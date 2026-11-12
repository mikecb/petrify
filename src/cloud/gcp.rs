//! Cloud API behaviour -> Google Cloud IAM custom role.
//!
//! The output is a role definition for `gcloud iam roles create --file`. A
//! Google Cloud role is only a list of permissions: where it applies is
//! decided by where it is bound, so the resources seen in the log are not
//! part of the role.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::{Behavior, truncated};
use crate::text::plural;

pub const POLICY_NAME: &str = "GCP custom role";

/// Bytes in a role title.
const TITLE_LIMIT: usize = 100;
/// Characters in a role description.
const DESCRIPTION_LIMIT: usize = 256;
/// Prefix of the Kubernetes API verbs in GKE audit logs.
const KUBERNETES: &str = "io.k8s.";

/// A custom role granting the observed permissions, and notes about it.
pub fn policy(behavior: &Behavior, include_denied: bool) -> (Value, Vec<String>) {
    let mut grants = behavior.granted(include_denied);
    // GKE's audit log lists Kubernetes API verbs beside IAM permissions.
    // Those are granted by Kubernetes RBAC and are not valid in a role.
    let before = grants.len();
    grants.retain(|permission, _| !permission.starts_with(KUBERNETES));
    let kubernetes = before - grants.len();
    let who = behavior.subjects.join(", ");
    let title = match behavior.subjects.as_slice() {
        [only] if only.len() + 9 <= TITLE_LIMIT => format!("petrify: {only}"),
        _ => "petrify".to_string(),
    };
    let description = format!("Permissions observed in audit logs for {who}");
    let document = json!({
        "title": title,
        "description": truncated(&description, DESCRIPTION_LIMIT),
        "stage": "GA",
        "includedPermissions": grants.keys().collect::<Vec<_>>(),
    });

    let resources: BTreeSet<&String> = grants
        .values()
        .flatten()
        .filter(|resource| *resource != "*")
        .collect();
    let mut notes = Vec::new();
    if kubernetes > 0 {
        notes.push(format!(
            "{} left out: `io.k8s.*` entries are granted by Kubernetes RBAC, not by an IAM role",
            plural(kubernetes as u64, "Kubernetes permission"),
        ));
    }
    if !resources.is_empty() {
        notes.push(format!(
            "a role does not say where it applies: bind it on the {} `show` lists \
             rather than on the whole project",
            plural(resources.len() as u64, "resource"),
        ));
    }
    (document, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::testing::{behavior, call};
    use crate::events::Provider::Gcp;

    #[test]
    fn role_lists_each_permission_once() {
        let seen = behavior(
            Gcp,
            [
                call(
                    "storage.objects.get",
                    "projects/_/buckets/b/objects/x",
                    false,
                ),
                call(
                    "storage.objects.get",
                    "projects/_/buckets/b/objects/y",
                    false,
                ),
                call("pubsub.topics.publish", "projects/p/topics/t", false),
                call(
                    "storage.objects.delete",
                    "projects/_/buckets/b/objects/x",
                    true,
                ),
            ],
        );
        let (document, notes) = policy(&seen, false);
        assert_eq!(
            document,
            json!({
                "title": "petrify: app",
                "description": "Permissions observed in audit logs for app",
                "stage": "GA",
                "includedPermissions": ["pubsub.topics.publish", "storage.objects.get"],
            })
        );
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("bind it on the 3 resources"));

        let (document, _) = policy(&seen, true);
        assert_eq!(document["includedPermissions"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn kubernetes_verbs_are_not_iam_permissions() {
        let seen = behavior(
            Gcp,
            [
                call(
                    "container.clusters.get",
                    "projects/p/zones/z/clusters/c",
                    false,
                ),
                call(
                    "io.k8s.core.v1.pods.delete",
                    "core/v1/namespaces/n/pods/x",
                    false,
                ),
                call("io.k8s.core.v1.nodes.list", "core/v1/nodes", false),
            ],
        );
        let (document, notes) = policy(&seen, false);
        assert_eq!(
            document["includedPermissions"],
            json!(["container.clusters.get"])
        );
        assert!(notes[0].starts_with("2 Kubernetes permissions left out"));
        assert!(notes[1].contains("bind it on the 1 resource "));
    }

    #[test]
    fn title_and_description_stay_within_limits() {
        let mut seen = behavior(Gcp, [call("storage.buckets.list", "*", false)]);
        seen.subjects = vec![format!(
            "{}@example.iam.gserviceaccount.com",
            "a".repeat(300)
        )];
        let (document, notes) = policy(&seen, false);
        assert_eq!(document["title"], "petrify");
        assert_eq!(document["description"].as_str().unwrap().len(), 256);
        assert!(notes.is_empty()); // nothing but "*" to bind on
    }
}
