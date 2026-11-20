//! API behaviour, and the role or policy that grants exactly it.
//!
//! What an identity did is modelled the same way for every platform: which
//! permissions it exercised, on what, and whether it was refused. [`aws`],
//! [`gcp`], [`azure`] and [`kubernetes`] each turn that into their own kind
//! of document. Permission names are not translated between platforms, so a
//! log from one only ever leads to that one's policy.

pub mod aws;
pub mod azure;
pub mod gcp;
pub mod kubernetes;

use std::collections::{BTreeMap, BTreeSet};

use crate::events::{ApiCall, Provider};
use crate::text::{commas, plural, top};

pub const SUBJECT: &str = "principal";

/// Permission -> how often each resource was touched.
type Uses = BTreeMap<String, BTreeMap<String, u64>>;
/// (permission, whether it was refused) -> number of calls. Kept apart from
/// the resources because one call can touch several.
type Calls = BTreeMap<(String, bool), u64>;

#[derive(Debug)]
pub struct Behavior {
    pub provider: Provider,
    /// Whose behaviour this is.
    pub subjects: Vec<String>,
    pub allowed: Uses,
    pub denied: Uses,
    calls: Calls,
}

impl Behavior {
    /// Each permission to grant with the resources it was used on: what was
    /// allowed, plus what was refused when `include_denied`.
    pub fn granted(&self, include_denied: bool) -> BTreeMap<&str, BTreeSet<String>> {
        let mut grants: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        let denied = include_denied.then_some(&self.denied);
        for (action, resources) in self.allowed.iter().chain(denied.into_iter().flatten()) {
            grants
                .entry(action)
                .or_default()
                .extend(resources.keys().cloned());
        }
        grants
    }
}

impl Provider {
    /// The service a permission belongs to: `s3` in `s3:GetObject`, `storage`
    /// in `storage.objects.get`, `Microsoft.Storage` in
    /// `Microsoft.Storage/storageAccounts/write`, and the API group `apps`
    /// in `apps/deployments:patch`.
    fn service_of(self, action: &str) -> &str {
        let separator = match self {
            Provider::Aws => ':',
            Provider::Gcp => '.',
            Provider::Azure | Provider::Kubernetes => '/',
        };
        action.split(separator).next().unwrap_or(action)
    }
}

#[derive(Debug)]
pub struct Collector {
    provider: Provider,
    /// subject -> (allowed, denied, calls)
    seen: BTreeMap<String, (Uses, Uses, Calls)>,
    events: BTreeMap<String, u64>,
}

impl Collector {
    pub fn new(provider: Provider) -> Collector {
        Collector {
            provider,
            seen: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }

    pub fn add(&mut self, event: ApiCall) {
        *self.events.entry(event.subject.clone()).or_default() += 1;
        let (allowed, denied, calls) = self.seen.entry(event.subject).or_default();
        *calls
            .entry((event.action.clone(), event.denied))
            .or_default() += 1;
        let uses = if event.denied { denied } else { allowed };
        let resources = uses.entry(event.action).or_default();
        for resource in event.resources {
            *resources.entry(resource).or_default() += 1;
        }
    }

    /// Subjects seen, with how many events each produced.
    pub fn subjects(&self) -> &BTreeMap<String, u64> {
        &self.events
    }

    /// The combined behaviour of the chosen subjects.
    pub fn behavior(&self, subjects: &[String]) -> Behavior {
        let mut merged = Behavior {
            provider: self.provider,
            subjects: subjects.to_vec(),
            allowed: Uses::new(),
            denied: Uses::new(),
            calls: Calls::new(),
        };
        let chosen = subjects.iter().filter_map(|subject| self.seen.get(subject));
        for (allowed, denied, calls) in chosen {
            for (key, count) in calls {
                *merged.calls.entry(key.clone()).or_default() += count;
            }
            for (from, into) in [(allowed, &mut merged.allowed), (denied, &mut merged.denied)] {
                for (action, resources) in from {
                    let target = into.entry(action.clone()).or_default();
                    for (resource, count) in resources {
                        *target.entry(resource.clone()).or_default() += count;
                    }
                }
            }
        }
        merged
    }
}

pub fn describe(behavior: &Behavior) -> String {
    let services: BTreeSet<&str> = behavior
        .allowed
        .keys()
        .map(|action| behavior.provider.service_of(action))
        .collect();
    let mut lines = vec![format!(
        "API calls: {} across {}",
        plural(behavior.allowed.len() as u64, "action"),
        plural(services.len() as u64, "service"),
    )];
    lines.extend(table(&behavior.allowed, &behavior.calls, false));
    if !behavior.denied.is_empty() {
        lines.push(String::new());
        lines.push("Denied (left out of the policy unless --include-denied):".to_string());
        lines.extend(table(&behavior.denied, &behavior.calls, true));
    }
    lines.join("\n")
}

fn table(uses: &Uses, calls: &Calls, denied: bool) -> Vec<String> {
    let width = uses.keys().map(String::len).max().unwrap_or(0);
    uses.iter()
        .map(|(action, resources)| {
            let count = calls.get(&(action.clone(), denied)).copied().unwrap_or(0);
            let calls = commas(count);
            format!("  {action:<width$}  {calls:>7}  {}", top(resources, 3))
        })
        .collect()
}

/// `text` cut to at most `limit` bytes, on a character boundary.
fn truncated(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Call builders shared by this module's tests and the dialects'.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub fn call(action: &str, resource: &str, denied: bool) -> ApiCall {
        ApiCall {
            subject: "app".to_string(),
            action: action.to_string(),
            resources: vec![resource.to_string()],
            denied,
        }
    }

    /// The behaviour of subject "app" after these calls.
    pub fn behavior(provider: Provider, calls: impl IntoIterator<Item = ApiCall>) -> Behavior {
        let mut collector = Collector::new(provider);
        calls.into_iter().for_each(|call| collector.add(call));
        collector.behavior(&["app".to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{behavior, call};
    use super::*;

    #[test]
    fn subjects_are_kept_apart_until_chosen() {
        let mut collector = Collector::new(Provider::Aws);
        collector.add(call("s3:GetObject", "arn:aws:s3:::b/k", false));
        collector.add(ApiCall {
            subject: "other".into(),
            ..call("sqs:SendMessage", "*", false)
        });
        assert_eq!(collector.subjects().len(), 2);
        assert_eq!(collector.behavior(&["app".to_string()]).allowed.len(), 1);
        let both = collector.behavior(&["app".to_string(), "other".to_string()]);
        assert_eq!(both.allowed.len(), 2);
        assert_eq!(both.subjects, ["app", "other"]);
    }

    #[test]
    fn describe_counts_services_in_each_clouds_vocabulary() {
        let aws = behavior(
            Provider::Aws,
            [
                call("s3:GetObject", "*", false),
                call("s3:PutObject", "*", true),
            ],
        );
        let text = describe(&aws);
        assert!(text.starts_with("API calls: 1 action across 1 service\n"));
        assert!(text.contains("left out"));

        let gcp = behavior(
            Provider::Gcp,
            [
                call("storage.objects.get", "*", false),
                call("storage.objects.list", "*", false),
                call("pubsub.topics.publish", "*", false),
            ],
        );
        assert!(describe(&gcp).starts_with("API calls: 3 actions across 2 services\n"));

        let azure = behavior(
            Provider::Azure,
            [
                call("Microsoft.Storage/storageAccounts/write", "*", false),
                call(
                    "Microsoft.Storage/storageAccounts/listKeys/action",
                    "*",
                    false,
                ),
            ],
        );
        assert!(describe(&azure).starts_with("API calls: 2 actions across 1 service\n"));
    }

    #[test]
    fn calls_are_counted_once_however_many_resources_they_touch() {
        let attach = ApiCall {
            resources: vec!["volume/v".to_string(), "instance/i".to_string()],
            ..call("ec2:AttachVolume", "", false)
        };
        let seen = behavior(Provider::Aws, [attach.clone(), attach]);
        let text = describe(&seen);
        assert!(
            text.contains("ec2:AttachVolume        2  instance/i (2), volume/v (2)"),
            "{text}"
        );
    }

    #[test]
    fn granting_denied_calls_is_opt_in() {
        let seen = behavior(
            Provider::Aws,
            [
                call("s3:GetObject", "a", false),
                call("s3:GetObject", "b", true),
                call("s3:PutObject", "b", true),
            ],
        );
        assert_eq!(seen.granted(false).len(), 1);
        assert_eq!(seen.granted(false)["s3:GetObject"].len(), 1);
        assert_eq!(seen.granted(true).len(), 2);
        assert_eq!(seen.granted(true)["s3:GetObject"].len(), 2);
    }

    #[test]
    fn truncation_respects_character_boundaries() {
        assert_eq!(truncated("abc", 10), "abc");
        assert_eq!(truncated("abcdef", 3), "abc");
        assert_eq!(truncated("aé", 2), "a");
    }
}
