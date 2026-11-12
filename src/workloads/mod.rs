//! What ran in a Kubernetes namespace, and the admission policy that admits
//! exactly that.
//!
//! The behaviour here is not what a program did but what was deployed: which
//! images, under which service accounts, with which privileges. The subject
//! is the namespace.

pub mod admission;

use std::collections::BTreeMap;

use crate::events::Workload;
use crate::text::{commas, plural, ranked};

pub const SUBJECT: &str = "namespace";

type Counter = BTreeMap<String, u64>;

#[derive(Debug, Default, Clone)]
pub struct Behavior {
    pub namespaces: Vec<String>,
    /// Admitted requests, by kind of workload.
    pub admitted: Counter,
    /// Requests the API server refused.
    pub rejected: u64,
    /// Image repositories, without tag or digest.
    pub images: Counter,
    pub service_accounts: Counter,
    pub capabilities: Counter,
    pub host_paths: Counter,
    /// How many admitted workloads had a privileged container, and so on.
    pub privileged: u64,
    pub host_network: u64,
    pub host_pid: u64,
    pub host_ipc: u64,
}

impl Behavior {
    fn add(&mut self, event: Workload) {
        if !event.admitted {
            self.rejected += 1;
            return;
        }
        let count = |counter: &mut Counter, name: String| *counter.entry(name).or_default() += 1;
        count(&mut self.admitted, event.kind);
        count(&mut self.service_accounts, event.pod.service_account);
        // Each name counts once per workload, however many containers use it.
        for (counter, mut names) in [
            (&mut self.images, event.pod.images),
            (&mut self.capabilities, event.pod.capabilities),
            (&mut self.host_paths, event.pod.host_paths),
        ] {
            names.sort();
            names.dedup();
            names.into_iter().for_each(|name| count(counter, name));
        }
        self.privileged += u64::from(event.pod.privileged);
        self.host_network += u64::from(event.pod.host_network);
        self.host_pid += u64::from(event.pod.host_pid);
        self.host_ipc += u64::from(event.pod.host_ipc);
    }

    fn merge(&mut self, other: &Behavior) {
        for (into, from) in [
            (&mut self.admitted, &other.admitted),
            (&mut self.images, &other.images),
            (&mut self.service_accounts, &other.service_accounts),
            (&mut self.capabilities, &other.capabilities),
            (&mut self.host_paths, &other.host_paths),
        ] {
            for (name, count) in from {
                *into.entry(name.clone()).or_default() += count;
            }
        }
        self.rejected += other.rejected;
        self.privileged += other.privileged;
        self.host_network += other.host_network;
        self.host_pid += other.host_pid;
        self.host_ipc += other.host_ipc;
    }

    /// The host namespaces pods were seen to share, with how often.
    fn host_namespaces(&self) -> Vec<(&'static str, u64)> {
        [
            ("hostNetwork", self.host_network),
            ("hostPID", self.host_pid),
            ("hostIPC", self.host_ipc),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .collect()
    }
}

#[derive(Debug, Default)]
pub struct Collector {
    seen: BTreeMap<String, Behavior>,
    events: BTreeMap<String, u64>,
}

impl Collector {
    pub fn add(&mut self, event: Workload) {
        *self.events.entry(event.subject.clone()).or_default() += 1;
        self.seen
            .entry(event.subject.clone())
            .or_default()
            .add(event);
    }

    /// Namespaces seen, with how many workload requests each had.
    pub fn subjects(&self) -> &BTreeMap<String, u64> {
        &self.events
    }

    /// The combined behaviour of the chosen namespaces.
    pub fn behavior(&self, subjects: &[String]) -> Behavior {
        let mut merged = Behavior {
            namespaces: subjects.to_vec(),
            ..Behavior::default()
        };
        for seen in subjects.iter().filter_map(|subject| self.seen.get(subject)) {
            merged.merge(seen);
        }
        merged
    }
}

pub fn describe(behavior: &Behavior) -> String {
    let kinds: Vec<String> = ranked(&behavior.admitted)
        .iter()
        .map(|(kind, count)| plural(*count, kind))
        .collect();
    let mut summary = format!(
        "Workloads: {} admitted",
        commas(behavior.admitted.values().sum())
    );
    if !kinds.is_empty() {
        summary.push_str(&format!(" ({})", kinds.join(", ")));
    }
    if behavior.rejected > 0 {
        summary.push_str(&format!(
            ", {} rejected by the API server",
            commas(behavior.rejected)
        ));
    }

    let mut lines = vec![summary];
    let list = |counter: &Counter| -> Vec<String> {
        ranked(counter)
            .iter()
            .map(|(name, count)| format!("  {name}  ({})", commas(*count)))
            .collect()
    };
    for (title, counter) in [
        ("Images", &behavior.images),
        ("Service accounts", &behavior.service_accounts),
        ("Added capabilities", &behavior.capabilities),
        ("hostPath volumes", &behavior.host_paths),
    ] {
        lines.push(String::new());
        if counter.is_empty() {
            lines.push(format!("{title}: none"));
        } else {
            lines.push(format!("{title}:"));
            lines.extend(list(counter));
        }
    }
    lines.push(String::new());
    lines.push(match behavior.privileged {
        0 => "Privileged containers: none".to_string(),
        count => format!("Privileged containers: in {}", plural(count, "workload")),
    });
    let shared: Vec<String> = behavior
        .host_namespaces()
        .iter()
        .map(|(name, count)| format!("{name} ({})", commas(*count)))
        .collect();
    lines.push(format!(
        "Host namespaces: {}",
        if shared.is_empty() {
            "none".to_string()
        } else {
            shared.join(", ")
        }
    ));
    lines.join("\n")
}

/// Workload builders shared by this module's tests and the policy's.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::events::PodSpec;

    pub fn workload(kind: &str, images: &[&str]) -> Workload {
        Workload {
            subject: "orders".to_string(),
            kind: kind.to_string(),
            admitted: true,
            pod: PodSpec {
                images: images.iter().map(|image| image.to_string()).collect(),
                service_account: "default".to_string(),
                ..PodSpec::default()
            },
        }
    }

    /// The behaviour of namespace "orders" after these workloads.
    pub fn behavior(workloads: impl IntoIterator<Item = Workload>) -> Behavior {
        let mut collector = Collector::default();
        workloads
            .into_iter()
            .for_each(|workload| collector.add(workload));
        collector.behavior(&["orders".to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{behavior, workload};
    use super::*;
    use crate::events::PodSpec;

    #[test]
    fn namespaces_are_kept_apart_until_chosen() {
        let mut collector = Collector::default();
        collector.add(workload("Pod", &["app"]));
        collector.add(Workload {
            subject: "billing".to_string(),
            ..workload("Pod", &["ledger"])
        });
        assert_eq!(collector.subjects().len(), 2);
        assert_eq!(collector.behavior(&["orders".to_string()]).images.len(), 1);
        let both = collector.behavior(&["billing".to_string(), "orders".to_string()]);
        assert_eq!(both.images.len(), 2);
        assert_eq!(both.namespaces, ["billing", "orders"]);
    }

    #[test]
    fn describe_reports_what_was_and_was_not_seen() {
        let risky = Workload {
            pod: PodSpec {
                privileged: true,
                host_network: true,
                capabilities: vec!["NET_ADMIN".to_string()],
                host_paths: vec!["/var/log".to_string()],
                ..workload("DaemonSet", &["agent", "agent"]).pod
            },
            ..workload("DaemonSet", &[])
        };
        let refused = Workload {
            admitted: false,
            ..workload("Pod", &["miner"])
        };
        let seen = behavior([
            workload("Deployment", &["app", "sidecar"]),
            workload("Deployment", &["app"]),
            risky,
            refused,
        ]);
        let text = describe(&seen);
        assert!(text.starts_with(
            "Workloads: 3 admitted (2 Deployments, 1 DaemonSet), 1 rejected by the API server\n"
        ));
        assert!(text.contains("Images:\n  app  (2)\n  agent  (1)\n  sidecar  (1)\n"));
        assert!(!text.contains("miner"));
        assert!(text.contains("Added capabilities:\n  NET_ADMIN  (1)\n"));
        assert!(text.contains("hostPath volumes:\n  /var/log  (1)\n"));
        assert!(text.contains("Privileged containers: in 1 workload\n"));
        assert!(text.ends_with("Host namespaces: hostNetwork (1)"));

        let plain = describe(&behavior([workload("Pod", &["app"])]));
        assert!(plain.contains("Added capabilities: none\n"));
        assert!(plain.contains("Privileged containers: none\nHost namespaces: none"));
    }
}
