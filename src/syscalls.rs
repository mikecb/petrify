//! Syscall behaviour -> seccomp profile (the OCI JSON format understood by
//! Docker, Podman, containerd and Kubernetes).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::events::{Arch, Detail, Error, Result, Syscall};
use crate::text::{commas, plural, ranked};

pub const POLICY_NAME: &str = "seccomp profile";
pub const SUBJECT: &str = "program";

const DETAIL_ROWS: usize = 8;

/// What happens to a syscall the profile does not list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DefaultAction {
    ScmpActErrno,
    ScmpActKillProcess,
    ScmpActKill,
    ScmpActTrap,
    ScmpActLog,
}

impl DefaultAction {
    fn name(self) -> &'static str {
        match self {
            DefaultAction::ScmpActErrno => "SCMP_ACT_ERRNO",
            DefaultAction::ScmpActKillProcess => "SCMP_ACT_KILL_PROCESS",
            DefaultAction::ScmpActKill => "SCMP_ACT_KILL",
            DefaultAction::ScmpActTrap => "SCMP_ACT_TRAP",
            DefaultAction::ScmpActLog => "SCMP_ACT_LOG",
        }
    }
}

impl Arch {
    fn seccomp_name(self) -> &'static str {
        match self {
            Arch::X86_64 => "SCMP_ARCH_X86_64",
            Arch::Aarch64 => "SCMP_ARCH_AARCH64",
        }
    }

    /// The architecture petrify itself was built for.
    fn host() -> Option<Arch> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Arch::X86_64),
            "aarch64" => Some(Arch::Aarch64),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Behavior {
    pub calls: BTreeMap<String, u64>,
    pub details: BTreeMap<Detail, BTreeMap<String, u64>>,
    pub archs: BTreeSet<Arch>,
}

#[derive(Debug, Default)]
pub struct Collector {
    seen: BTreeMap<String, Behavior>,
    events: BTreeMap<String, u64>,
}

impl Collector {
    pub fn add(&mut self, event: Syscall) {
        *self.events.entry(event.subject.clone()).or_default() += 1;
        let seen = self.seen.entry(event.subject).or_default();
        *seen.calls.entry(event.name).or_default() += 1;
        seen.archs.extend(event.arch);
        if let Some((kind, value)) = event.detail {
            *seen
                .details
                .entry(kind)
                .or_default()
                .entry(value)
                .or_default() += 1;
        }
    }

    /// Subjects seen, with how many events each produced.
    pub fn subjects(&self) -> &BTreeMap<String, u64> {
        &self.events
    }

    /// The combined behaviour of the chosen subjects.
    pub fn behavior(&self, subjects: &[String]) -> Behavior {
        let mut merged = Behavior::default();
        for seen in subjects.iter().filter_map(|subject| self.seen.get(subject)) {
            for (name, count) in &seen.calls {
                *merged.calls.entry(name.clone()).or_default() += count;
            }
            merged.archs.extend(&seen.archs);
            for (kind, values) in &seen.details {
                let target = merged.details.entry(*kind).or_default();
                for (value, count) in values {
                    *target.entry(value.clone()).or_default() += count;
                }
            }
        }
        merged
    }
}

pub fn describe(behavior: &Behavior) -> String {
    let mut lines = vec![format!(
        "Syscalls: {}, {} distinct",
        plural(behavior.calls.values().sum(), "call"),
        behavior.calls.len()
    )];
    for (kind, values) in &behavior.details {
        let title = match kind {
            Detail::Exec => "Executes",
            Detail::Connect => "Connects to",
            Detail::Bind => "Listens on",
            Detail::Write => "Opens for writing",
            Detail::Read => "Opens for reading",
        };
        lines.push(String::new());
        lines.push(format!("{title}:"));
        let values = ranked(values);
        lines.extend(
            values
                .iter()
                .take(DETAIL_ROWS)
                .map(|(value, _)| format!("  {value}")),
        );
        if values.len() > DETAIL_ROWS {
            lines.push(format!(
                "  ... and {} more",
                commas((values.len() - DETAIL_ROWS) as u64)
            ));
        }
    }
    lines.push(String::new());
    lines.push("Calls:".to_string());
    let width = behavior.calls.keys().map(String::len).max().unwrap_or(0);
    for (name, count) in ranked(&behavior.calls) {
        lines.push(format!("  {name:<width$}  {:>9}", commas(count)));
    }
    lines.join("\n")
}

/// A seccomp profile allowing the observed syscalls plus `allow`, and notes
/// about it. `arch` overrides whatever the log recorded.
pub fn policy(
    behavior: &Behavior,
    default_action: DefaultAction,
    arch: Option<Arch>,
    allow: &[String],
) -> Result<(Value, Vec<String>)> {
    policy_on(Arch::host(), behavior, default_action, arch, allow)
}

fn policy_on(
    host: Option<Arch>,
    behavior: &Behavior,
    default_action: DefaultAction,
    arch: Option<Arch>,
    allow: &[String],
) -> Result<(Value, Vec<String>)> {
    let mut notes = Vec::new();
    let mut archs: BTreeSet<Arch> =
        arch.map_or_else(|| behavior.archs.clone(), |arch| [arch].into());
    if archs.is_empty() {
        let host = host.ok_or_else(|| {
            Error("cannot tell which architecture the trace is from; pass --arch".to_string())
        })?;
        notes.push(format!(
            "the trace does not record an architecture; assuming {host} (--arch)"
        ));
        archs.insert(host);
    }

    let names: BTreeSet<&str> = behavior
        .calls
        .keys()
        .chain(allow)
        .map(String::as_str)
        .filter(|n| !n.is_empty())
        .collect();
    let mut document = json!({ "defaultAction": default_action.name() });
    if default_action == DefaultAction::ScmpActErrno {
        document["defaultErrnoRet"] = json!(1); // EPERM
    }
    document["architectures"] = json!(archs.iter().map(|a| a.seccomp_name()).collect::<Vec<_>>());
    document["syscalls"] = json!([{ "names": names, "action": "SCMP_ACT_ALLOW" }]);
    Ok((document, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn behavior(names: &[&str], arch: Option<Arch>) -> Behavior {
        let mut collector = Collector::default();
        for name in names {
            let subject = "app".to_string();
            collector.add(Syscall {
                subject,
                name: name.to_string(),
                arch,
                detail: None,
            });
        }
        collector.behavior(&["app".to_string()])
    }

    #[test]
    fn profile_allows_exactly_what_was_seen() {
        let seen = behavior(&["read", "write", "read"], None);
        let (document, notes) = policy(
            &seen,
            DefaultAction::ScmpActErrno,
            Some(Arch::Aarch64),
            &["futex".to_string()],
        )
        .unwrap();
        assert_eq!(
            document,
            json!({
                "defaultAction": "SCMP_ACT_ERRNO",
                "defaultErrnoRet": 1,
                "architectures": ["SCMP_ARCH_AARCH64"],
                "syscalls": [{"names": ["futex", "read", "write"], "action": "SCMP_ACT_ALLOW"}],
            })
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn architecture_comes_from_the_log_when_it_has_one() {
        let seen = behavior(&["read"], Some(Arch::Aarch64));
        let (document, notes) =
            policy_on(None, &seen, DefaultAction::ScmpActLog, None, &[]).unwrap();
        assert_eq!(document["architectures"], json!(["SCMP_ARCH_AARCH64"]));
        assert_eq!(document["defaultAction"], "SCMP_ACT_LOG");
        assert!(document.get("defaultErrnoRet").is_none());
        assert!(notes.is_empty());
    }

    #[test]
    fn a_guessed_architecture_is_admitted() {
        let seen = behavior(&["read"], None);
        let errno = DefaultAction::ScmpActErrno;
        let (document, notes) = policy_on(Some(Arch::Aarch64), &seen, errno, None, &[]).unwrap();
        assert_eq!(document["architectures"], json!(["SCMP_ARCH_AARCH64"]));
        assert!(notes[0].contains("assuming aarch64"));
        assert!(
            policy_on(None, &seen, errno, None, &[])
                .unwrap_err()
                .0
                .contains("--arch")
        );
    }

    #[test]
    fn describe_lists_details_before_calls() {
        let mut collector = Collector::default();
        for (name, detail) in [
            ("openat", Some((Detail::Read, "/etc/app.conf"))),
            ("connect", Some((Detail::Connect, "10.0.2.10:5432"))),
            ("execve", Some((Detail::Exec, "/bin/app"))),
            ("read", None),
        ] {
            collector.add(Syscall {
                subject: "app".to_string(),
                name: name.to_string(),
                arch: None,
                detail: detail.map(|(kind, value)| (kind, value.to_string())),
            });
        }
        let text = describe(&collector.behavior(&["app".to_string()]));
        let position = |needle: &str| text.find(needle).unwrap();
        assert!(text.starts_with("Syscalls: 4 calls, 4 distinct"));
        assert!(position("Executes:") < position("Connects to:"));
        assert!(position("Connects to:") < position("Opens for reading:"));
        assert!(position("Opens for reading:") < position("Calls:"));
    }
}
