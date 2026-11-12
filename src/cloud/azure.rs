//! Cloud API behaviour -> Azure custom role.
//!
//! The output is a role definition for
//! `az role definition create --role-definition`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{Behavior, truncated};

pub const POLICY_NAME: &str = "Azure custom role";

/// Recommended maximum lengths; the hard limits are higher.
const NAME_LIMIT: usize = 256;
const DESCRIPTION_LIMIT: usize = 512;

/// A custom role granting the observed actions, assignable where they were
/// observed, and notes about it. `max_scopes` is how many resource groups to
/// list before falling back to their subscriptions.
pub fn policy(behavior: &Behavior, max_scopes: usize) -> (Value, Vec<String>) {
    let grants = behavior.granted(false);
    let who = behavior.subjects.join(", ");
    let scopes = assignable_scopes(grants.values().flatten().map(String::as_str), max_scopes);
    let document = json!({
        "Name": truncated(&format!("petrify: {who}"), NAME_LIMIT),
        "IsCustom": true,
        "Description": truncated(
            &format!("Actions observed in the Activity Log for {who}"),
            DESCRIPTION_LIMIT,
        ),
        "Actions": actions(grants.keys().copied()),
        "NotActions": [],
        "AssignableScopes": scopes,
    });

    let mut notes = vec![
        "the Activity Log records writes, deletes and actions, but not reads or data-plane \
         operations: add the read and data actions the application needs by hand"
            .to_string(),
    ];
    if scopes.is_empty() {
        notes.push(
            "no subscription could be read from the log; fill in AssignableScopes".to_string(),
        );
    }
    (document, notes)
}

/// Action strings are case-insensitive and exports change their case, so
/// keep one spelling of each, preferring one in mixed case.
fn actions<'a>(seen: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut by_name: BTreeMap<String, &str> = BTreeMap::new();
    for action in seen {
        let mixed = |text: &str| {
            text.chars().any(char::is_uppercase) && text.chars().any(char::is_lowercase)
        };
        let kept = by_name.entry(action.to_lowercase()).or_insert(action);
        if mixed(action) && !mixed(kept) {
            *kept = action;
        }
    }
    by_name.into_values().collect()
}

/// Where the role may be assigned: the resource groups the actions touched,
/// or their subscriptions when a scope has no resource group or there are
/// more than `limit` of them.
fn assignable_scopes<'a>(scopes: impl Iterator<Item = &'a str>, limit: usize) -> Vec<String> {
    // subscription -> lower-cased resource group -> the name as first seen
    let mut groups: BTreeMap<String, BTreeMap<String, &str>> = BTreeMap::new();
    let mut whole: BTreeSet<String> = BTreeSet::new();
    for scope in scopes {
        let segments: Vec<&str> = scope.split('/').collect();
        let after = |name: &str| {
            let index = segments.iter().position(|s| s.eq_ignore_ascii_case(name))?;
            segments.get(index + 1).copied().filter(|s| !s.is_empty())
        };
        let Some(subscription) = after("subscriptions").map(str::to_lowercase) else {
            continue;
        };
        match after("resourceGroups") {
            Some(group) => {
                let groups = groups.entry(subscription).or_default();
                groups.entry(group.to_lowercase()).or_insert(group);
            }
            None => {
                whole.insert(subscription);
            }
        }
    }
    let listed: usize = groups
        .iter()
        .filter(|(subscription, _)| !whole.contains(*subscription))
        .map(|(_, groups)| groups.len())
        .sum();
    let collapse = listed + whole.len() > limit;

    let mut out = BTreeSet::new();
    for (subscription, groups) in &groups {
        if collapse || whole.contains(subscription) {
            out.insert(format!("/subscriptions/{subscription}"));
        } else {
            out.extend(
                groups
                    .values()
                    .map(|group| format!("/subscriptions/{subscription}/resourceGroups/{group}")),
            );
        }
    }
    out.extend(
        whole
            .iter()
            .map(|subscription| format!("/subscriptions/{subscription}")),
    );
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::testing::{behavior, call};
    use crate::events::Provider::Azure;

    const SUB: &str = "/subscriptions/AAAA1111-0000-0000-0000-000000000000";

    #[test]
    fn role_lists_actions_and_where_they_were_used() {
        let vm = format!("{SUB}/resourceGroups/web/providers/Microsoft.Compute/virtualMachines/a");
        let disk = format!("{SUB}/resourcegroups/WEB/providers/Microsoft.Compute/disks/d");
        let seen = behavior(
            Azure,
            [
                call(
                    "Microsoft.Compute/virtualMachines/restart/action",
                    &vm,
                    false,
                ),
                call(
                    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTART/ACTION",
                    &vm,
                    false,
                ),
                call("Microsoft.Compute/disks/write", &disk, false),
            ],
        );
        let (document, notes) = policy(&seen, 10);
        assert_eq!(
            document,
            json!({
                "Name": "petrify: app",
                "IsCustom": true,
                "Description": "Actions observed in the Activity Log for app",
                "Actions": [
                    "Microsoft.Compute/disks/write",
                    "Microsoft.Compute/virtualMachines/restart/action",
                ],
                "NotActions": [],
                "AssignableScopes": [
                    "/subscriptions/aaaa1111-0000-0000-0000-000000000000/resourceGroups/web",
                ],
            })
        );
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("not reads"));
    }

    #[test]
    fn scopes_fall_back_to_the_subscription() {
        let group = |name: &str| format!("{SUB}/resourceGroups/{name}/providers/X/y/z");
        let groups: Vec<String> = (0..5).map(|n| group(&format!("rg{n}"))).collect();
        let scopes = |limit| assignable_scopes(groups.iter().map(String::as_str), limit);
        assert_eq!(scopes(5).len(), 5);
        assert_eq!(
            scopes(4),
            ["/subscriptions/aaaa1111-0000-0000-0000-000000000000"]
        );

        // A subscription-level action makes its resource groups redundant.
        let mixed = [group("rg0"), SUB.to_string()];
        assert_eq!(
            assignable_scopes(mixed.iter().map(String::as_str), 10),
            ["/subscriptions/aaaa1111-0000-0000-0000-000000000000"]
        );
    }

    #[test]
    fn missing_scopes_are_admitted() {
        let seen = behavior(Azure, [call("Microsoft.Compute/disks/write", "*", false)]);
        let (document, notes) = policy(&seen, 10);
        assert_eq!(document["AssignableScopes"], json!([]));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("fill in AssignableScopes"))
        );
    }
}
