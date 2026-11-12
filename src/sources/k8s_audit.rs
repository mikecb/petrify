//! Kubernetes API server audit log -> [`Workload`].
//!
//! Reads the requests that create or change pods and the controllers that
//! make pods (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs and so
//! on), and keeps the parts of their pod specs that admission policy cares
//! about.
//!
//! Two things about the audit policy that produced the log matter:
//!
//! - The object must be in the event, so these resources need the `Request`
//!   level or above. `Metadata` events say that a pod was created but not
//!   what was in it.
//! - Admission policy sees an object after mutating webhooks have changed
//!   it. Only the `RequestResponse` level records that final object; a
//!   `Request`-level event shows the pod as it was sent, without, say, the
//!   sidecar a service mesh injects.

use std::io::{self, BufRead};

use serde_json::Value;

use crate::events::{Notes, PodSpec, Workload};
use crate::sources::{json_documents, text};

pub fn sniff(head: &str) -> bool {
    head.contains("audit.k8s.io/")
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(Workload),
) -> io::Result<()> {
    for document in &json_documents(reader, notes)? {
        events(document, notes, emit);
    }
    Ok(())
}

fn events(document: &Value, notes: &mut Notes, emit: &mut dyn FnMut(Workload)) {
    if let Some(items) = document.as_array() {
        items.iter().for_each(|item| events(item, notes, emit));
    } else if let Some(items) = document.get("items") {
        events(items, notes, emit); // an EventList
    } else if document.get("auditID").is_some() {
        event(document, notes, emit);
    }
}

/// Where the pod spec sits in each kind of workload, by resource name.
fn pod_spec_path(resource: &str) -> Option<(&'static str, &'static [&'static str])> {
    const TEMPLATE: &[&str] = &["spec", "template", "spec"];
    Some(match resource {
        "pods" => ("Pod", &["spec"]),
        "deployments" => ("Deployment", TEMPLATE),
        "statefulsets" => ("StatefulSet", TEMPLATE),
        "daemonsets" => ("DaemonSet", TEMPLATE),
        "replicasets" => ("ReplicaSet", TEMPLATE),
        "replicationcontrollers" => ("ReplicationController", TEMPLATE),
        "jobs" => ("Job", TEMPLATE),
        "cronjobs" => (
            "CronJob",
            &["spec", "jobTemplate", "spec", "template", "spec"],
        ),
        _ => return None,
    })
}

fn event(event: &Value, notes: &mut Notes, emit: &mut dyn FnMut(Workload)) {
    // A request is logged at several stages; the last one has the outcome.
    if text(event, "stage").is_some_and(|stage| stage != "ResponseComplete") {
        return;
    }
    let verb = text(event, "verb").unwrap_or("");
    if !matches!(verb, "create" | "update" | "patch") {
        return;
    }
    // A server-side dry run goes through admission but deploys nothing.
    if text(event, "requestURI").is_some_and(|uri| uri.contains("dryRun=")) {
        return;
    }
    let target = event.get("objectRef").unwrap_or(&Value::Null);
    let (Some(resource), Some(namespace)) = (text(target, "resource"), text(target, "namespace"))
    else {
        return;
    };
    let Some((kind, path)) = pod_spec_path(resource) else {
        return;
    };
    // Status, scale, logs and the like are not the workload's definition.
    if !matches!(
        text(target, "subresource"),
        None | Some("ephemeralcontainers")
    ) {
        return;
    }

    let code = event
        .get("responseStatus")
        .and_then(|status| status.get("code"));
    let admitted = code.and_then(Value::as_u64).is_none_or(|code| code < 400);
    let spec_of = |key: &str| {
        let object = event.get(key)?;
        path.iter().try_fold(object, |value, step| value.get(step))
    };
    // The response is the object as stored, after mutating admission; a
    // patch request is only the patch.
    let stored = spec_of("responseObject").filter(|_| admitted);
    let sent = spec_of("requestObject").filter(|_| verb != "patch");
    let workload = |pod: PodSpec| Workload {
        subject: namespace.to_string(),
        kind: kind.to_string(),
        admitted,
        pod,
    };
    let Some(spec) = stored.or(sent) else {
        if admitted {
            notes.add(
                "skipped a workload request logged without its object; \
                 the audit policy must log these at the Request level or above",
            );
        } else {
            emit(workload(PodSpec::default())); // refused, whatever it asked for
        }
        return;
    };
    if admitted && stored.is_none() {
        notes.add(
            "read a workload as it was requested, not as it was stored: containers added by \
             a mutating webhook (a service mesh sidecar) are missing unless the audit policy \
             logs at the RequestResponse level",
        );
    }
    emit(workload(pod(spec)));
}

fn pod(spec: &Value) -> PodSpec {
    let list = |value: &Value, key: &str| -> Vec<Value> {
        value
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let flag = |value: &Value, key: &str| value.get(key).and_then(Value::as_bool) == Some(true);
    let mut pod = PodSpec {
        service_account: text(spec, "serviceAccountName")
            .or_else(|| text(spec, "serviceAccount"))
            .unwrap_or("default")
            .to_string(),
        host_network: flag(spec, "hostNetwork"),
        host_pid: flag(spec, "hostPID"),
        host_ipc: flag(spec, "hostIPC"),
        ..PodSpec::default()
    };
    for key in ["containers", "initContainers", "ephemeralContainers"] {
        for container in list(spec, key) {
            pod.images.extend(text(&container, "image").map(repository));
            let security = container.get("securityContext").unwrap_or(&Value::Null);
            pod.privileged |= flag(security, "privileged");
            let capabilities = security.get("capabilities").unwrap_or(&Value::Null);
            for capability in list(capabilities, "add") {
                pod.capabilities
                    .extend(capability.as_str().map(String::from));
            }
        }
    }
    for volume in list(spec, "volumes") {
        let host_path = volume.get("hostPath").and_then(|host| text(host, "path"));
        pod.host_paths.extend(host_path.map(String::from));
    }
    pod
}

/// An image reference without its tag or digest: the part that stays the
/// same from one deploy to the next.
pub(crate) fn repository(image: &str) -> String {
    let image = image.split('@').next().unwrap_or(image);
    // A colon after the last slash starts a tag; before it, a registry port.
    match image.rfind(':') {
        Some(colon) if !image[colon..].contains('/') => image[..colon].to_string(),
        _ => image.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse_text(text: &str) -> (Vec<Workload>, Notes) {
        let (mut found, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), &mut notes, &mut |workload| {
            found.push(workload)
        })
        .unwrap();
        (found, notes)
    }

    fn event(verb: &str, resource: &str, object: Value) -> Value {
        json!({
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "level": "Request",
            "auditID": "a-1",
            "stage": "ResponseComplete",
            "verb": verb,
            "objectRef": {"resource": resource, "namespace": "orders", "name": "x"},
            "responseStatus": {"code": 201},
            "requestObject": object,
        })
    }

    fn pod_spec() -> Value {
        json!({
            "serviceAccountName": "orders-api",
            "hostNetwork": true,
            "initContainers": [{"name": "init", "image": "busybox:1.36"}],
            "containers": [{
                "name": "api",
                "image": "registry.example.com:5000/shop/orders-api:v1.2.3@sha256:abcd",
                "securityContext": {
                    "privileged": true,
                    "capabilities": {"add": ["NET_BIND_SERVICE"], "drop": ["ALL"]},
                },
            }],
            "volumes": [
                {"name": "logs", "hostPath": {"path": "/var/log"}},
                {"name": "tmp", "emptyDir": {}},
            ],
        })
    }

    #[test]
    fn image_references_lose_tag_and_digest() {
        assert_eq!(repository("nginx"), "nginx");
        assert_eq!(repository("nginx:1.27"), "nginx");
        assert_eq!(repository("ghcr.io/org/app@sha256:abcd"), "ghcr.io/org/app");
        assert_eq!(repository("localhost:5000/app"), "localhost:5000/app");
        assert_eq!(
            repository("localhost:5000/app:dev@sha256:ab"),
            "localhost:5000/app"
        );
    }

    #[test]
    fn pod_specs_are_found_in_every_kind_of_workload() {
        let log = [
            event("create", "pods", json!({"kind": "Pod", "spec": pod_spec()})),
            event(
                "update",
                "deployments",
                json!({"spec": {"template": {"spec": pod_spec()}}}),
            ),
            event(
                "create",
                "cronjobs",
                json!({"spec": {"jobTemplate": {"spec": {"template": {"spec": pod_spec()}}}}}),
            ),
        ]
        .map(|event| event.to_string())
        .join("\n");
        assert!(sniff(&log));
        let (found, _) = parse_text(&log);
        let kinds: Vec<&str> = found.iter().map(|w| w.kind.as_str()).collect();
        assert_eq!(kinds, ["Pod", "Deployment", "CronJob"]);
        for workload in &found {
            assert_eq!(workload.subject, "orders");
            assert!(workload.admitted);
            assert_eq!(
                workload.pod,
                PodSpec {
                    images: vec![
                        "registry.example.com:5000/shop/orders-api".to_string(),
                        "busybox".to_string(),
                    ],
                    service_account: "orders-api".to_string(),
                    privileged: true,
                    host_network: true,
                    host_pid: false,
                    host_ipc: false,
                    capabilities: vec!["NET_BIND_SERVICE".to_string()],
                    host_paths: vec!["/var/log".to_string()],
                }
            );
        }
    }

    #[test]
    fn the_stored_object_is_preferred_to_the_request() {
        let sent = json!({"spec": {"containers": [{"image": "app:1"}]}});
        let stored = json!({"spec": {
            "serviceAccountName": "default",
            "containers": [{"image": "app:1"}, {"image": "istio/proxyv2:1.23"}],
        }});
        let mut both = event("create", "pods", sent.clone());
        both["responseObject"] = stored.clone();
        let mut patch = event("patch", "pods", json!({"metadata": {"labels": {"a": "b"}}}));
        patch["responseObject"] = stored;
        let bare_patch = event("patch", "pods", json!({"spec": {"containers": []}}));
        let log = json!({"kind": "EventList", "items": [both, patch, bare_patch, event("create", "pods", sent)]});

        let (found, notes) = parse_text(&log.to_string());
        let images: Vec<usize> = found.iter().map(|w| w.pod.images.len()).collect();
        assert_eq!(images, [2, 2, 1]);
        let notes: Vec<(&str, u64)> = notes.iter().collect();
        assert_eq!(notes.len(), 2);
        assert!(notes[0].0.contains("without its object") && notes[0].1 == 1);
        assert!(notes[1].0.contains("as it was requested") && notes[1].1 == 1);
    }

    #[test]
    fn rejected_requests_and_other_events_are_told_apart() {
        let pod = json!({"spec": {"containers": [{"image": "app:1"}]}});
        let mut rejected = event("create", "pods", pod.clone());
        rejected["responseStatus"] = json!({"code": 403});
        rejected["responseObject"] = json!({"kind": "Status", "code": 403});
        let mut early = event("create", "pods", pod.clone());
        early["stage"] = json!("RequestReceived");
        let mut status = event("update", "pods", pod.clone());
        status["objectRef"]["subresource"] = json!("status");
        let mut metadata = event("create", "pods", Value::Null);
        metadata["level"] = json!("Metadata");
        let mut cluster = event("create", "pods", pod.clone());
        cluster["objectRef"] = json!({"resource": "pods"});
        let mut dry_run = event("create", "pods", pod.clone());
        dry_run["requestURI"] = json!("/api/v1/namespaces/orders/pods?dryRun=All");
        let mut refused_patch = event("patch", "deployments", json!({"spec": {}}));
        refused_patch["responseStatus"] = json!({"code": 422});
        let log = json!([
            rejected,
            early,
            status,
            metadata,
            cluster,
            dry_run,
            refused_patch,
            event("get", "pods", Value::Null),
            event("create", "configmaps", json!({"data": {}})),
        ]);
        let (found, notes) = parse_text(&log.to_string());
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|workload| !workload.admitted));
        assert_eq!(found[0].pod.images, ["app"]);
        assert_eq!(
            (found[1].kind.as_str(), &found[1].pod),
            ("Deployment", &PodSpec::default())
        );
        assert_eq!(notes.len(), 1); // the Metadata-level create
    }
}
