//! API behaviour -> Kubernetes RBAC roles and bindings.
//!
//! The output is a `List` for `kubectl apply -f`: a `Role` and `RoleBinding`
//! in each namespace the subject worked in, and a `ClusterRole` and
//! `ClusterRoleBinding` for whatever it did across the cluster.
//!
//! RBAC can restrict some verbs to named objects (`resourceNames`). That is
//! worth doing for a secret or a lease, whose name is the same tomorrow, and
//! wrong for a pod, whose name is made up on every deploy. A resource is
//! pinned to the names observed unless there are too many of them or any of
//! them looks generated.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::Behavior;

pub const POLICY_NAME: &str = "RBAC roles";

const API_VERSION: &str = "rbac.authorization.k8s.io/v1";
const RBAC_GROUP: &str = "rbac.authorization.k8s.io";
/// How the action of a request outside the resource model is written.
const NON_RESOURCE: &str = "nonresource";
/// The characters the API server draws a generated name's suffix from.
const GENERATED_ALPHABET: &str = "bcdfghjklmnpqrstvwxz2456789";

/// What was done to one kind of resource in one scope.
#[derive(Debug, Default)]
struct Use {
    /// Verbs used on the collection, or on an object RBAC cannot name.
    unnamed: BTreeSet<String>,
    /// Verbs used on named objects.
    named: BTreeSet<String>,
    names: BTreeSet<String>,
}

/// (API group, resource) -> use. The core group is the empty string.
type Uses = BTreeMap<(String, String), Use>;

/// Roles and bindings granting the observed requests, and notes about them.
/// `max_names` is how many object names a rule may list before it applies to
/// every object of that resource.
pub fn policy(behavior: &Behavior, include_denied: bool, max_names: usize) -> (Value, Vec<String>) {
    // None is the cluster scope: cluster-wide resources, and namespaced ones
    // listed or watched across every namespace.
    let mut scopes: BTreeMap<Option<String>, Uses> = BTreeMap::new();
    let mut urls: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (action, resources) in behavior.granted(include_denied) {
        let Some((target, verb)) = action.rsplit_once(':') else {
            continue;
        };
        let Some((group, resource)) = target.split_once('/') else {
            continue;
        };
        if group == NON_RESOURCE {
            for path in resources {
                urls.entry(path).or_default().insert(verb.to_string());
            }
            continue;
        }
        let group = if group == "core" { "" } else { group };
        for object in &resources {
            let (namespace, name) = object.split_once('/').unwrap_or(("*", object));
            let scope = (namespace != "*").then(|| namespace.to_string());
            let used = scopes
                .entry(scope)
                .or_default()
                .entry((group.to_string(), resource.to_string()))
                .or_default();
            // A name does not exist yet when its creation is authorised.
            if name == "*" || verb == "create" {
                used.unnamed.insert(verb.to_string());
            } else {
                used.named.insert(verb.to_string());
                used.names.insert(name.to_string());
            }
        }
    }

    let name = match behavior.subjects.as_slice() {
        [only] => format!("petrify-{}", slug(only)),
        _ => "petrify-subjects".to_string(),
    };
    let subjects: Vec<Value> = behavior.subjects.iter().map(|user| subject(user)).collect();
    let binding = |kind: &str, namespace: Option<&str>| {
        let mut metadata = json!({ "name": name });
        if let Some(namespace) = namespace {
            metadata["namespace"] = json!(namespace);
        }
        json!({
            "apiVersion": API_VERSION,
            "kind": format!("{kind}Binding"),
            "metadata": metadata,
            "subjects": subjects,
            "roleRef": {"apiGroup": RBAC_GROUP, "kind": kind, "name": name},
        })
    };

    let mut notes = Vec::new();
    let mut items = Vec::new();
    for (scope, uses) in &scopes {
        let scope = scope.as_deref();
        let mut rules = rules(uses, max_names);
        if scope.is_none() {
            rules.extend(url_rules(&urls));
        }
        let kind = if scope.is_some() {
            "Role"
        } else {
            "ClusterRole"
        };
        let mut metadata = json!({ "name": name });
        if let Some(namespace) = scope {
            metadata["namespace"] = json!(namespace);
        }
        items.push(json!({
            "apiVersion": API_VERSION,
            "kind": kind,
            "metadata": metadata,
            "rules": rules,
        }));
        items.push(binding(kind, scope));
        if let Some(note) = secrets_note(uses, scope, max_names) {
            notes.push(note);
        }
    }
    if !scopes.contains_key(&None) && !urls.is_empty() {
        items.insert(
            0,
            json!({
                "apiVersion": API_VERSION,
                "kind": "ClusterRole",
                "metadata": {"name": name},
                "rules": url_rules(&urls),
            }),
        );
        items.insert(1, binding("ClusterRole", None));
    }
    let document = json!({"apiVersion": "v1", "kind": "List", "items": items});
    (document, notes)
}

/// Whether a resource's observed names go into `resourceNames`.
fn pinned(used: &Use, max_names: usize) -> bool {
    !used.names.is_empty()
        && used.names.len() <= max_names
        && !used.names.iter().any(|name| generated(name))
}

/// The rules for one scope: one per resource pinned to names, and one per
/// API group and set of verbs for everything else.
fn rules(uses: &Uses, max_names: usize) -> Vec<Value> {
    let mut rules = Vec::new();
    // (group, verbs) -> resources
    let mut open: BTreeMap<(&str, BTreeSet<&str>), Vec<&str>> = BTreeMap::new();
    for ((group, resource), used) in uses {
        let mut verbs: BTreeSet<&str> = used.unnamed.iter().map(String::as_str).collect();
        if pinned(used, max_names) {
            rules.push(json!({
                "apiGroups": [group],
                "resources": [resource],
                "resourceNames": used.names,
                "verbs": used.named,
            }));
        } else {
            verbs.extend(used.named.iter().map(String::as_str));
        }
        if !verbs.is_empty() {
            open.entry((group.as_str(), verbs))
                .or_default()
                .push(resource.as_str());
        }
    }
    for ((group, verbs), resources) in open {
        rules.push(json!({"apiGroups": [group], "resources": resources, "verbs": verbs}));
    }
    rules
}

/// Rules for paths outside the resource model, grouped by verbs.
fn url_rules(urls: &BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
    let mut by_verbs: BTreeMap<&BTreeSet<String>, Vec<&str>> = BTreeMap::new();
    for (path, verbs) in urls {
        by_verbs.entry(verbs).or_default().push(path);
    }
    by_verbs
        .into_iter()
        .map(|(verbs, paths)| json!({"nonResourceURLs": paths, "verbs": verbs}))
        .collect()
}

/// Reading secrets without naming them is reading all of them, which is
/// worth saying out loud.
fn secrets_note(uses: &Uses, scope: Option<&str>, max_names: usize) -> Option<String> {
    let used = uses.get(&(String::new(), "secrets".to_string()))?;
    let reads = |verbs: &BTreeSet<String>| {
        verbs
            .iter()
            .any(|verb| matches!(verb.as_str(), "get" | "list" | "watch"))
    };
    let every = reads(&used.unnamed) || (reads(&used.named) && !pinned(used, max_names));
    every.then(|| {
        format!(
            "can read every secret {}: it listed or watched them, or read too many to name",
            scope.map_or("in the cluster".to_string(), |namespace| format!(
                "in {namespace}"
            )),
        )
    })
}

/// Whether a name ends in a suffix a controller made up: the five random
/// characters of `generateName` (a ReplicaSet's or Job's pods), the hash a
/// Deployment gives its ReplicaSets, or the timestamp a CronJob gives its
/// Jobs.
fn generated(name: &str) -> bool {
    let Some((stem, suffix)) = name.rsplit_once('-') else {
        return false;
    };
    let random = matches!(suffix.len(), 5 | 8..=10)
        && suffix.chars().all(|c| GENERATED_ALPHABET.contains(c));
    let timestamp = suffix.len() >= 8 && suffix.chars().all(|c| c.is_ascii_digit());
    !stem.is_empty() && (random || timestamp)
}

/// A binding subject for a user name as the audit log gives it.
fn subject(user: &str) -> Value {
    let account = user.strip_prefix("system:serviceaccount:");
    match account.and_then(|account| account.split_once(':')) {
        Some((namespace, name)) => {
            json!({"kind": "ServiceAccount", "name": name, "namespace": namespace})
        }
        None => json!({"kind": "User", "name": user, "apiGroup": RBAC_GROUP}),
    }
}

/// A user name as part of an object name: lower-case letters, digits and
/// single dashes.
fn slug(user: &str) -> String {
    let user = user.strip_prefix("system:serviceaccount:").unwrap_or(user);
    let mut out = String::new();
    for c in user.chars().take(200) {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::testing::{behavior, call};
    use crate::events::Provider::Kubernetes;

    const SA: &str = "system:serviceaccount:orders:orders-api";

    fn observed(calls: &[(&str, &str)]) -> Behavior {
        let mut seen = behavior(
            Kubernetes,
            calls
                .iter()
                .map(|(action, object)| call(action, object, false)),
        );
        seen.subjects = vec![SA.to_string()];
        seen
    }

    fn item<'a>(document: &'a Value, kind: &str, namespace: Option<&str>) -> &'a Value {
        let items = document["items"].as_array().unwrap();
        let found = items.iter().find(|item| {
            item["kind"] == kind
                && item["metadata"].get("namespace") == namespace.map(|n| json!(n)).as_ref()
        });
        found.unwrap_or_else(|| panic!("no {kind} in {namespace:?}"))
    }

    #[test]
    fn a_namespace_gets_a_role_and_a_binding() {
        let seen = observed(&[
            ("core/configmaps:get", "orders/app-config"),
            ("core/pods:list", "orders/*"),
            ("core/pods:watch", "orders/*"),
            ("apps/deployments:patch", "orders/orders-api"),
        ]);
        let (document, notes) = policy(&seen, false, 10);
        assert!(notes.is_empty());
        assert_eq!(document["items"].as_array().unwrap().len(), 2);
        assert_eq!(
            item(&document, "Role", Some("orders")),
            &json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {"name": "petrify-orders-orders-api", "namespace": "orders"},
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["configmaps"],
                        "resourceNames": ["app-config"],
                        "verbs": ["get"],
                    },
                    {
                        "apiGroups": ["apps"],
                        "resources": ["deployments"],
                        "resourceNames": ["orders-api"],
                        "verbs": ["patch"],
                    },
                    {"apiGroups": [""], "resources": ["pods"], "verbs": ["list", "watch"]},
                ],
            })
        );
        assert_eq!(
            item(&document, "RoleBinding", Some("orders")),
            &json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": "petrify-orders-orders-api", "namespace": "orders"},
                "subjects": [
                    {"kind": "ServiceAccount", "name": "orders-api", "namespace": "orders"},
                ],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "petrify-orders-orders-api",
                },
            })
        );
    }

    #[test]
    fn cluster_wide_requests_get_a_cluster_role() {
        let seen = observed(&[
            ("core/nodes:get", "*/node-1"),
            ("core/pods:list", "*/*"),
            ("core/pods/log:get", "orders/toolbox"),
            ("nonresource/url:get", "/healthz"),
            ("nonresource/url:get", "/version"),
        ]);
        let (document, _) = policy(&seen, false, 10);
        assert_eq!(
            item(&document, "ClusterRole", None)["rules"],
            json!([
                {"apiGroups": [""], "resources": ["nodes"], "resourceNames": ["node-1"], "verbs": ["get"]},
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]},
                {"nonResourceURLs": ["/healthz", "/version"], "verbs": ["get"]},
            ])
        );
        assert_eq!(
            item(&document, "ClusterRoleBinding", None)["roleRef"]["kind"],
            "ClusterRole"
        );
        assert_eq!(
            item(&document, "Role", Some("orders"))["rules"],
            json!([{
                "apiGroups": [""],
                "resources": ["pods/log"],
                "resourceNames": ["toolbox"],
                "verbs": ["get"],
            }])
        );

        // Paths alone still need a ClusterRole to hang on.
        let (document, _) = policy(&observed(&[("nonresource/url:get", "/healthz")]), false, 10);
        assert_eq!(document["items"][0]["kind"], "ClusterRole");
        assert_eq!(document["items"][1]["kind"], "ClusterRoleBinding");
    }

    #[test]
    fn generated_or_numerous_names_are_not_pinned() {
        let seen = observed(&[
            ("core/pods:delete", "orders/orders-api-6db5cd7869-prn64"),
            ("core/pods:get", "orders/orders-api-6db5cd7869-q6bfv"),
            ("core/configmaps:get", "orders/a"),
            ("core/configmaps:get", "orders/b"),
            ("core/configmaps:get", "orders/c"),
            ("core/services:create", "orders/web"),
            ("core/services:get", "orders/web"),
        ]);
        let (document, _) = policy(&seen, false, 2);
        assert_eq!(
            item(&document, "Role", Some("orders"))["rules"],
            json!([
                {"apiGroups": [""], "resources": ["services"], "resourceNames": ["web"], "verbs": ["get"]},
                {"apiGroups": [""], "resources": ["services"], "verbs": ["create"]},
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["delete", "get"]},
                {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]},
            ])
        );
    }

    #[test]
    fn resources_with_the_same_verbs_share_a_rule() {
        let seen = observed(&[
            ("core/pods:list", "orders/*"),
            ("core/services:list", "orders/*"),
            ("apps/deployments:list", "orders/*"),
        ]);
        let (document, _) = policy(&seen, false, 10);
        assert_eq!(
            item(&document, "Role", Some("orders"))["rules"],
            json!([
                {"apiGroups": [""], "resources": ["pods", "services"], "verbs": ["list"]},
                {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["list"]},
            ])
        );
    }

    #[test]
    fn generated_names_are_recognised() {
        assert!(generated("orders-api-6db5cd7869-prn64"));
        assert!(generated("report-28871234-x7k2m"));
        assert!(generated("orders-api-6db5cd7869")); // a Deployment's ReplicaSet
        assert!(generated("report-28871234")); // a CronJob's Job
        assert!(!generated("release-2024"));
        assert!(!generated("orders-api"));
        assert!(!generated("app-nginx")); // vowels are never generated
        assert!(!generated("prn64"));
        assert!(!generated("kube-root-ca.crt"));
    }

    #[test]
    fn reading_every_secret_is_called_out() {
        let named = observed(&[("core/secrets:get", "orders/db-password")]);
        assert!(policy(&named, false, 10).1.is_empty());

        let listed = observed(&[("core/secrets:list", "orders/*")]);
        let (_, notes) = policy(&listed, false, 10);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].starts_with("can read every secret in orders"));

        let many = observed(&[
            ("core/secrets:get", "orders/a"),
            ("core/secrets:get", "orders/b"),
        ]);
        assert_eq!(policy(&many, false, 1).1.len(), 1);
        let everywhere = observed(&[("core/secrets:watch", "*/*")]);
        assert!(policy(&everywhere, false, 10).1[0].contains("in the cluster"));
    }

    #[test]
    fn denied_requests_are_granted_only_on_request() {
        let mut seen = behavior(
            Kubernetes,
            [
                call("core/pods:list", "orders/*", false),
                call("core/secrets:list", "orders/*", true),
            ],
        );
        seen.subjects = vec!["alice@example.com".to_string(), SA.to_string()];
        let (document, notes) = policy(&seen, false, 10);
        let role = item(&document, "Role", Some("orders"));
        assert_eq!(role["rules"].as_array().unwrap().len(), 1);
        assert_eq!(role["metadata"]["name"], "petrify-subjects");
        assert!(notes.is_empty());
        assert_eq!(
            item(&document, "RoleBinding", Some("orders"))["subjects"],
            json!([
                {"kind": "User", "name": "alice@example.com", "apiGroup": "rbac.authorization.k8s.io"},
                {"kind": "ServiceAccount", "name": "orders-api", "namespace": "orders"},
            ])
        );

        let (document, notes) = policy(&seen, true, 10);
        assert_eq!(
            item(&document, "Role", Some("orders"))["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            item(&document, "Role", Some("orders"))["rules"][0]["resources"],
            json!(["pods", "secrets"])
        );
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn object_names_are_made_from_user_names() {
        assert_eq!(slug(SA), "orders-orders-api");
        assert_eq!(slug("alice@example.com"), "alice-example-com");
        assert_eq!(slug("system:kube-scheduler"), "system-kube-scheduler");
        assert_eq!(slug("--Odd__Name--"), "odd-name");
    }
}
