//! Cloud API behaviour -> AWS IAM policy.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::Behavior;
use crate::prefix::generalize;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::testing::{behavior, call};
    use crate::events::Provider::Aws;

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
