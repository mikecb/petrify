//! Cloud API behaviour -> AWS IAM policy.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::Behavior;
use crate::text::{commas, plural};

pub const POLICY_NAME: &str = "IAM policy";

/// Characters in a managed policy, not counting whitespace.
const MANAGED_POLICY_LIMIT: usize = 6144;

/// An IAM policy document granting the observed calls, and notes about it.
pub fn policy(
    behavior: &Behavior,
    include_denied: bool,
    max_resources: usize,
) -> (Value, Vec<String>) {
    let mut notes = Vec::new();
    let grants = behavior.granted(include_denied);

    // Actions that share a resource list share a statement.
    let mut statements: BTreeMap<Vec<String>, Vec<&str>> = BTreeMap::new();
    for (action, resources) in &grants {
        let scoped = generalize(resources, max_resources);
        if scoped.len() > max_resources {
            notes.push(format!(
                "{action} touched {} resources that cannot be summarised by prefix",
                scoped.len()
            ));
        }
        statements.entry(scoped).or_default().push(action);
    }
    let unscoped = statements
        .get(["*".to_string()].as_slice())
        .map_or(0, Vec::len);

    let mut statements: Vec<(Vec<&str>, Vec<String>)> = statements
        .into_iter()
        .map(|(resources, actions)| (actions, resources))
        .collect();
    statements.sort();
    let document = json!({
        "Version": "2012-10-17",
        "Statement": statements
            .iter()
            .map(|(actions, resources)| json!({
                "Effect": "Allow",
                "Action": scalar(actions),
                "Resource": scalar(resources),
            }))
            .collect::<Vec<_>>(),
    });

    let size = document.to_string().len();
    if size > MANAGED_POLICY_LIMIT {
        notes.push(format!(
            "policy is {} characters; managed policies are limited to {}. \
             Lower --max-resources or split it",
            commas(size as u64),
            commas(MANAGED_POLICY_LIMIT as u64),
        ));
    }
    if unscoped > 0 {
        notes.push(format!(
            "{} granted on \"*\" because the log does not name a resource \
             (list and describe calls often have none); review them by hand",
            plural(unscoped as u64, "action"),
        ));
    }
    (document, notes)
}

/// IAM accepts a bare string where a list would have one element.
fn scalar<S: AsRef<str>>(values: &[S]) -> Value {
    match values {
        [only] => json!(only.as_ref()),
        many => json!(many.iter().map(AsRef::as_ref).collect::<Vec<&str>>()),
    }
}

/// Shrink a resource list to at most `limit` entries by replacing the
/// deepest path segments with wildcards, deepest first.
///
/// An application that wrote a thousand objects under `uploads/2024/` was not
/// granted those thousand keys; it was granted the prefix. Resources without
/// a path (a queue, a function) are never merged, so the result can still
/// exceed the limit.
pub fn generalize(resources: &BTreeSet<String>, limit: usize) -> Vec<String> {
    if resources.contains("*") {
        return vec!["*".to_string()];
    }
    let mut paths: BTreeSet<Vec<&str>> = prune(
        resources
            .iter()
            .map(|resource| resource.split('/').collect())
            .collect(),
    );
    while paths.len() > limit {
        let depth = paths.iter().map(Vec::len).max().unwrap_or(0);
        if depth < 2 {
            break; // nothing left with a path to shorten
        }
        let widened: BTreeSet<Vec<&str>> = paths
            .iter()
            .map(|path| {
                let mut path = path.clone();
                if path.len() == depth && path[depth - 1] != "*" {
                    path[depth - 1] = "*"; // a/b/c -> a/b/*
                } else if path.len() == depth && depth > 2 {
                    path.truncate(depth - 2); // a/b/* -> a/*, but never a/* -> *
                    path.push("*");
                }
                path
            })
            .collect();
        if widened == paths {
            break;
        }
        paths = prune(widened);
    }
    let mut out: Vec<String> = paths.iter().map(|path| path.join("/")).collect();
    out.sort();
    out
}

/// Drop paths already covered by a wildcard elsewhere in the set.
fn prune(paths: BTreeSet<Vec<&str>>) -> BTreeSet<Vec<&str>> {
    let wildcards: BTreeSet<Vec<&str>> = paths
        .iter()
        .filter(|path| path.last() == Some(&"*"))
        .map(|path| path[..path.len() - 1].to_vec())
        .collect();
    paths
        .into_iter()
        .filter(|path| {
            // A wildcard is not covered by its own prefix.
            let own = usize::from(path.last() == Some(&"*"));
            !(1..path.len() - own).any(|n| wildcards.contains(&path[..n]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::testing::{behavior, call};
    use crate::events::Provider::Aws;

    fn set(items: impl IntoIterator<Item = String>) -> BTreeSet<String> {
        items.into_iter().collect()
    }

    #[test]
    fn denied_calls_are_reported_but_not_granted() {
        let seen = behavior(
            Aws,
            [
                call("s3:GetObject", "arn:aws:s3:::b/k", false),
                call("s3:PutObject", "arn:aws:s3:::b/k", true),
                call("ec2:RunInstances", "*", true),
            ],
        );
        let (document, _) = policy(&seen, false, 10);
        assert_eq!(
            document["Statement"],
            json!([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/k"}])
        );

        let (document, notes) = policy(&seen, true, 10);
        assert_eq!(
            document["Statement"],
            json!([
                {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::b/k",
                },
            ])
        );
        assert!(
            notes
                .iter()
                .any(|note| note.starts_with("1 action granted on \"*\""))
        );
    }

    #[test]
    fn generalize_collapses_deepest_paths_first() {
        let mut keys = set((0..50).map(|n| format!("arn:aws:s3:::b/up/2026/{n}.jpg")));
        keys.insert("arn:aws:s3:::b/config.json".to_string());
        assert_eq!(
            generalize(&keys, 10),
            ["arn:aws:s3:::b/config.json", "arn:aws:s3:::b/up/2026/*"]
        );
    }

    #[test]
    fn generalize_keeps_going_up_but_never_past_the_bucket() {
        let keys = set((0..50).map(|n| format!("arn:aws:s3:::b/tenant-{n}/data/file")));
        assert_eq!(generalize(&keys, 10), ["arn:aws:s3:::b/*"]);
        let buckets = set([
            "arn:aws:s3:::a/*".to_string(),
            "arn:aws:s3:::b/*".to_string(),
        ]);
        assert_eq!(
            generalize(&buckets, 1),
            ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"]
        );
    }

    #[test]
    fn generalize_leaves_pathless_resources_alone() {
        let queues = set((0..5).map(|n| format!("arn:aws:sqs:us-east-1:1:q{n}")));
        assert_eq!(
            generalize(&queues, 2),
            queues.iter().cloned().collect::<Vec<_>>()
        );
        let any = set(["*".to_string(), "arn:aws:s3:::b".to_string()]);
        assert_eq!(generalize(&any, 10), ["*"]);
        let covered = set([
            "arn:aws:s3:::b/*".to_string(),
            "arn:aws:s3:::b/k".to_string(),
        ]);
        assert_eq!(generalize(&covered, 10), ["arn:aws:s3:::b/*"]);
    }

    #[test]
    fn oversized_policy_is_flagged() {
        let calls = (0..120).map(|n| {
            let queue = format!("arn:aws:sqs:eu-west-1:111122223333:a-rather-long-queue-name-{n}");
            call("sqs:SendMessage", &queue, false)
        });
        let (_, notes) = policy(&behavior(Aws, calls), false, 10);
        assert!(
            notes
                .iter()
                .any(|note| note.contains("managed policies are limited"))
        );
        assert!(
            notes
                .iter()
                .any(|note| note.contains("cannot be summarised"))
        );
    }
}
