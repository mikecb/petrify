//! Workload behaviour -> Kubernetes ValidatingAdmissionPolicy.
//!
//! The output is a `List` holding a `ValidatingAdmissionPolicy` and the
//! `ValidatingAdmissionPolicyBinding` that applies it to the namespace, for
//! `kubectl apply -f`. Both are built into the API server (GA in Kubernetes
//! 1.30), so nothing has to be installed for them to take effect.
//!
//! The policy checks pods, and also the controllers that create pods, so
//! that a Deployment asking for something the policy forbids is refused
//! when it is applied rather than failing quietly when its pods are made.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::Behavior;
use crate::events::{Error, Result};
use crate::prefix::generalize;

pub const POLICY_NAME: &str = "validating admission policy";

const API_VERSION: &str = "admissionregistration.k8s.io/v1";
/// The label every namespace carries with its own name.
const NAMESPACE_LABEL: &str = "kubernetes.io/metadata.name";

/// What the API server does with a request that fails the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Action {
    /// Refuse the request
    Deny,
    /// Admit it, with a warning to the client
    Warn,
    /// Admit it, and record the failure in the audit log
    Audit,
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Action::Deny => "Deny",
            Action::Warn => "Warn",
            Action::Audit => "Audit",
        }
    }
}

/// The pod spec of whatever is being admitted. Only one branch is ever
/// evaluated, so each kind is read where it keeps its pods.
const POD_SPEC: &str = "object.kind == 'Pod' ? object.spec : \
     (object.kind == 'CronJob' ? object.spec.jobTemplate.spec.template.spec : \
     object.spec.template.spec)";

/// A policy and binding that admit only what was observed, and notes about
/// them. `max_images` is how many image repositories to list before
/// summarising them by registry path.
pub fn policy(
    behavior: &Behavior,
    actions: &[Action],
    max_images: usize,
) -> Result<(Value, Vec<String>)> {
    if behavior.images.is_empty() {
        return Err(Error(
            "no admitted workload in the log shows what its pods run".to_string(),
        ));
    }
    let actions: BTreeSet<Action> = if actions.is_empty() {
        [Action::Deny].into()
    } else {
        actions.iter().copied().collect()
    };
    if actions.contains(&Action::Deny) && actions.contains(&Action::Warn) {
        return Err(Error(
            "--validation-action: Kubernetes does not accept deny and warn together".to_string(),
        ));
    }

    let mut notes = Vec::new();
    let mut validations = vec![images(behavior, max_images, &mut notes)];
    validations.push(check(
        format!(
            "variables.spec.?serviceAccountName.orValue('default') in {}",
            strings(behavior.service_accounts.keys())
        ),
        "service account was not observed",
    ));

    if behavior.privileged == 0 {
        validations.push(check(
            each_container("!c.?securityContext.?privileged.orValue(false)"),
            "privileged containers were not observed",
        ));
    } else {
        notes.push("privileged containers were observed and stay allowed".to_string());
    }
    for (field, seen) in [
        ("hostNetwork", behavior.host_network),
        ("hostPID", behavior.host_pid),
        ("hostIPC", behavior.host_ipc),
    ] {
        if seen == 0 {
            validations.push(check(
                format!("!variables.spec.?{field}.orValue(false)"),
                &format!("{field} was not observed"),
            ));
        } else {
            notes.push(format!("{field} was observed and stays allowed"));
        }
    }
    validations.push(check(
        each_container(&format!(
            "c.?securityContext.?capabilities.?add.orValue([]).all(a, a in {})",
            strings(behavior.capabilities.keys())
        )),
        "added capability was not observed",
    ));
    validations.push(check(
        format!(
            "variables.spec.?volumes.orValue([]).all(v, !has(v.hostPath) || v.hostPath.path in {})",
            strings(behavior.host_paths.keys())
        ),
        "hostPath volume was not observed",
    ));

    let name = match behavior.namespaces.as_slice() {
        [only] => format!("petrify-{only}"),
        _ => "petrify-workloads".to_string(),
    };
    let rule = |group: &str, resources: &[&str]| {
        json!({
            "apiGroups": [group],
            "apiVersions": ["v1"],
            "operations": ["CREATE", "UPDATE"],
            "resources": resources,
        })
    };
    let policy = json!({
        "apiVersion": API_VERSION,
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [
                rule("", &["pods", "pods/ephemeralcontainers", "replicationcontrollers"]),
                rule("apps", &["deployments", "statefulsets", "daemonsets", "replicasets"]),
                rule("batch", &["jobs", "cronjobs"]),
            ]},
            // Let an object that predates the policy be cleaned up.
            "matchConditions": [{
                "name": "not-being-deleted",
                "expression": "!has(object.metadata.deletionTimestamp)",
            }],
            "variables": [
                {"name": "spec", "expression": POD_SPEC},
            ],
            "validations": validations,
        },
    });
    let binding = json!({
        "apiVersion": API_VERSION,
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": name},
        "spec": {
            "policyName": name,
            "validationActions": actions.iter().map(|action| action.name()).collect::<Vec<_>>(),
            "matchResources": {"namespaceSelector": {"matchExpressions": [{
                "key": NAMESPACE_LABEL,
                "operator": "In",
                "values": behavior.namespaces,
            }]}},
        },
    });
    let document = json!({"apiVersion": "v1", "kind": "List", "items": [policy, binding]});
    Ok((document, notes))
}

fn check(expression: String, message: &str) -> Value {
    json!({"expression": expression, "message": format!("petrify: {message}")})
}

/// `predicate`, written about a container `c`, required of every container
/// in the pod. The three lists are checked one by one because ephemeral
/// containers are a different type from the rest, and the API server
/// type-checks the expression against each kind the policy matches.
fn each_container(predicate: &str) -> String {
    format!(
        "variables.spec.containers.all(c, {predicate}) && \
         variables.spec.?initContainers.orValue([]).all(c, {predicate}) && \
         variables.spec.?ephemeralContainers.orValue([]).all(c, {predicate})"
    )
}

/// A CEL list of string literals. JSON's string escapes are valid in CEL.
fn strings<'a>(items: impl IntoIterator<Item = &'a String>) -> String {
    let items: Vec<&String> = items.into_iter().collect();
    serde_json::to_string(&items).expect("strings serialize")
}

/// Every container's image must be one of the observed repositories, at any
/// tag or digest, or sit under one of the paths they were summarised into.
fn images(behavior: &Behavior, max_images: usize, notes: &mut Vec<String>) -> Value {
    let observed: BTreeSet<String> = behavior.images.keys().cloned().collect();
    let (prefixes, exact): (Vec<String>, Vec<String>) = generalize(&observed, max_images)
        .into_iter()
        .partition(|image| image.ends_with("/*"));
    let prefixes: Vec<String> = prefixes
        .iter()
        .map(|prefix| prefix.trim_end_matches('*').to_string())
        .collect();

    if !prefixes.is_empty() {
        notes.push(format!(
            "{} image repositories exceed --max-images {max_images}: any image under {} is allowed",
            observed.len(),
            prefixes.join(", "),
        ));
    }

    let mut allowed = Vec::new();
    if !exact.is_empty() {
        allowed.push(format!(
            "{}.exists(r, c.image == r || c.image.startsWith(r + ':') || c.image.startsWith(r + '@'))",
            strings(&exact)
        ));
    }
    if !prefixes.is_empty() {
        allowed.push(format!(
            "{}.exists(p, c.image.startsWith(p))",
            strings(&prefixes)
        ));
    }
    check(
        each_container(&allowed.join(" || ")),
        "image was not observed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{PodSpec, Workload};
    use crate::workloads::testing::{behavior, workload};

    fn expressions(document: &Value) -> Vec<&str> {
        document["items"][0]["spec"]["validations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|validation| validation["expression"].as_str().unwrap())
            .collect()
    }

    fn messages(document: &Value) -> Vec<&str> {
        document["items"][0]["spec"]["validations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|validation| validation["message"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn an_unprivileged_workload_gets_every_restriction() {
        let seen = behavior([workload("Deployment", &["registry.example.com/shop/api"])]);
        let (document, notes) = policy(&seen, &[], 20).unwrap();
        assert!(notes.is_empty());
        assert_eq!(
            messages(&document),
            [
                "petrify: image was not observed",
                "petrify: service account was not observed",
                "petrify: privileged containers were not observed",
                "petrify: hostNetwork was not observed",
                "petrify: hostPID was not observed",
                "petrify: hostIPC was not observed",
                "petrify: added capability was not observed",
                "petrify: hostPath volume was not observed",
            ]
        );
        let found = expressions(&document);
        let image = "[\"registry.example.com/shop/api\"].exists(r, c.image == r || \
                     c.image.startsWith(r + ':') || c.image.startsWith(r + '@'))";
        assert_eq!(
            found[0],
            format!(
                "variables.spec.containers.all(c, {image}) && \
                 variables.spec.?initContainers.orValue([]).all(c, {image}) && \
                 variables.spec.?ephemeralContainers.orValue([]).all(c, {image})"
            )
        );
        assert_eq!(
            found[1],
            "variables.spec.?serviceAccountName.orValue('default') in [\"default\"]"
        );
        assert_eq!(found[3], "!variables.spec.?hostNetwork.orValue(false)");
        assert!(found[6].contains(".?add.orValue([]).all(a, a in [])"));
        assert!(found[7].ends_with("!has(v.hostPath) || v.hostPath.path in [])"));
    }

    #[test]
    fn the_binding_applies_the_policy_to_the_namespace() {
        let seen = behavior([workload("Pod", &["app"])]);
        let (document, _) = policy(&seen, &[], 20).unwrap();
        assert_eq!(document["kind"], "List");
        let policy_object = &document["items"][0];
        assert_eq!(policy_object["kind"], "ValidatingAdmissionPolicy");
        assert_eq!(policy_object["metadata"]["name"], "petrify-orders");
        assert_eq!(
            policy_object["spec"]["matchConstraints"]["resourceRules"][1],
            json!({
                "apiGroups": ["apps"],
                "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"],
                "resources": ["deployments", "statefulsets", "daemonsets", "replicasets"],
            })
        );
        assert_eq!(
            document["items"][1],
            json!({
                "apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": "petrify-orders"},
                "spec": {
                    "policyName": "petrify-orders",
                    "validationActions": ["Deny"],
                    "matchResources": {"namespaceSelector": {"matchExpressions": [{
                        "key": "kubernetes.io/metadata.name",
                        "operator": "In",
                        "values": ["orders"],
                    }]}},
                },
            })
        );
    }

    #[test]
    fn what_was_observed_stays_allowed_and_is_noted() {
        let agent = Workload {
            pod: PodSpec {
                privileged: true,
                host_pid: true,
                capabilities: vec!["NET_ADMIN".to_string(), "SYS_PTRACE".to_string()],
                host_paths: vec!["/var/log".to_string()],
                service_account: "agent".to_string(),
                ..workload("DaemonSet", &["agent"]).pod
            },
            ..workload("DaemonSet", &[])
        };
        let (document, notes) = policy(&behavior([agent]), &[], 20).unwrap();
        assert_eq!(
            notes,
            [
                "privileged containers were observed and stay allowed",
                "hostPID was observed and stays allowed",
            ]
        );
        assert_eq!(
            messages(&document),
            [
                "petrify: image was not observed",
                "petrify: service account was not observed",
                "petrify: hostNetwork was not observed",
                "petrify: hostIPC was not observed",
                "petrify: added capability was not observed",
                "petrify: hostPath volume was not observed",
            ]
        );
        let found = expressions(&document);
        assert!(found[1].ends_with("in [\"agent\"]"));
        assert!(found[4].contains("a in [\"NET_ADMIN\",\"SYS_PTRACE\"]"));
        assert!(found[5].ends_with("v.hostPath.path in [\"/var/log\"])"));
    }

    #[test]
    fn many_images_are_summarised_by_registry_path() {
        let images: Vec<String> = (0..30).map(|n| format!("ghcr.io/shop/svc-{n}")).collect();
        let mut names: Vec<&str> = images.iter().map(String::as_str).collect();
        names.push("busybox");
        let seen = behavior([workload("Deployment", &names)]);

        let (document, _) = policy(&seen, &[], 40).unwrap();
        assert!(!expressions(&document)[0].contains("exists(p,"));

        let (document, notes) = policy(&seen, &[], 20).unwrap();
        assert_eq!(
            notes,
            [
                "31 image repositories exceed --max-images 20: any image under ghcr.io/shop/ is allowed"
            ]
        );
        let image = expressions(&document)[0];
        assert!(image.contains("[\"busybox\"].exists(r, c.image == r"));
        assert!(image.contains(" || [\"ghcr.io/shop/\"].exists(p, c.image.startsWith(p))"));
    }

    #[test]
    fn actions_choose_between_enforcing_and_watching() {
        let seen = behavior([workload("Pod", &["app"])]);
        let actions_of = |actions: &[Action]| {
            policy(&seen, actions, 20)
                .map(|(document, _)| document["items"][1]["spec"]["validationActions"].clone())
        };
        assert_eq!(actions_of(&[]).unwrap(), json!(["Deny"]));
        assert_eq!(
            actions_of(&[Action::Audit, Action::Warn, Action::Audit]).unwrap(),
            json!(["Warn", "Audit"])
        );
        assert!(
            actions_of(&[Action::Deny, Action::Warn])
                .unwrap_err()
                .0
                .contains("together")
        );
    }

    #[test]
    fn several_namespaces_share_one_policy() {
        let mut seen = behavior([workload("Pod", &["app"])]);
        seen.namespaces = vec!["billing".to_string(), "orders".to_string()];
        let (document, _) = policy(&seen, &[], 20).unwrap();
        assert_eq!(
            document["items"][0]["metadata"]["name"],
            "petrify-workloads"
        );
        let selector = &document["items"][1]["spec"]["matchResources"]["namespaceSelector"];
        assert_eq!(
            selector["matchExpressions"][0]["values"],
            json!(["billing", "orders"])
        );
    }

    #[test]
    fn nothing_observed_is_an_error_not_an_empty_policy() {
        let refused = Workload {
            admitted: false,
            ..workload("Pod", &["app"])
        };
        assert!(
            policy(&behavior([refused]), &[], 20)
                .unwrap_err()
                .0
                .contains("no admitted")
        );
    }
}
