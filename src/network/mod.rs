//! Network behaviour, and the firewall rules that allow exactly it.
//!
//! The behaviour model here is the same for every cloud; [`aws`], [`gcp`] and
//! [`azure`] each write its rules in their own dialect.
//!
//! Flow records are mostly unidirectional and say nothing about who called whom,
//! but a stateful firewall rule needs exactly that: it allows the *opening*
//! of a conversation, and replies come for free. Most of this module is
//! working out, for each pair of flow records, which end was the server.

pub mod aws;
pub mod azure;
mod cidr;
pub mod gcp;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use cidr::collapse;
pub use cidr::{Net, summarize};

use crate::events::{Error, Flow, Result};
use crate::text::{commas, plural, ranked, top};

pub const SUBJECT: &str = "interface";

/// Start of the Linux default ephemeral port range.
const EPHEMERAL: u16 = 32768;
const REJECTED_ROWS: usize = 10;

// -- behaviour ---------------------------------------------------------------

/// (IP protocol, port); the port is `None` for protocols without ports.
pub type Service = (u8, Option<u16>);
type Peers = BTreeMap<IpAddr, u64>;

#[derive(Debug, Default)]
pub struct Behavior {
    pub local: Vec<Net>,
    pub ingress: BTreeMap<Service, Peers>,
    pub egress: BTreeMap<Service, Peers>,
    pub rejected: BTreeMap<String, u64>,
    /// Conversations where the server side could not be told apart.
    pub ambiguous: u64,
    /// Flows with no local endpoint.
    pub transit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    proto: u8,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    accepted: bool,
}

#[derive(Debug, Clone, Copy)]
struct Seen {
    count: u64,
    start: f64,
    initiator: Option<bool>,
}

impl Seen {
    const NONE: Seen = Seen {
        count: 0,
        start: f64::INFINITY,
        initiator: None,
    };

    fn merge(&mut self, count: u64, start: f64, initiator: Option<bool>) {
        self.count += count;
        self.start = self.start.min(start);
        self.initiator = self.initiator.or(initiator);
    }
}

/// One direction of a conversation: who sent, and what was seen of it.
type Record = (FlowKey, Seen);

/// The opening of a conversation: `client` connected to `server` on `port`.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Opening {
    client: IpAddr,
    server: IpAddr,
    port: u16,
}

fn ported(proto: u8) -> bool {
    matches!(proto, 6 | 17 | 132)
}

#[derive(Debug, Default)]
pub struct Collector {
    seen: BTreeMap<String, BTreeMap<FlowKey, Seen>>,
    /// Addresses the log itself attributed to each subject.
    known_local: BTreeMap<String, BTreeSet<IpAddr>>,
    events: BTreeMap<String, u64>,
}

impl Collector {
    pub fn add(&mut self, event: Flow) {
        *self.events.entry(event.subject.clone()).or_default() += 1;
        let ports = ported(event.proto);
        let key = FlowKey {
            proto: event.proto,
            src: event.src,
            sport: if ports { event.sport } else { 0 },
            dst: event.dst,
            dport: if ports { event.dport } else { 0 },
            accepted: event.accepted,
        };
        if let Some(local) = event.local {
            self.known_local
                .entry(event.subject.clone())
                .or_default()
                .insert(local);
        }
        self.seen
            .entry(event.subject)
            .or_default()
            .entry(key)
            .or_insert(Seen::NONE)
            .merge(1, event.start, event.initiator);
    }

    /// Subjects seen, with how many events each produced.
    pub fn subjects(&self) -> &BTreeMap<String, u64> {
        &self.events
    }

    /// The combined behaviour of the chosen subjects. `local` names the
    /// application's own addresses; when empty they are the ones the log
    /// attributed to each subject, or failing that, inferred.
    pub fn behavior(&self, subjects: &[String], local: &[String]) -> Result<Behavior> {
        let mut nets = Vec::new();
        for range in local {
            let net = Net::parse(range)
                .ok_or_else(|| Error(format!("--local: {range:?} is not an address or CIDR")))?;
            nets.push(net);
        }
        if nets.is_empty() {
            for subject in subjects {
                match self.known_local.get(subject) {
                    Some(known) => nets.extend(known.iter().map(|address| Net::host(*address))),
                    None => nets.push(Net::host(self.infer_local(subject)?)),
                }
            }
        }
        let nets = collapse(nets);
        let is_local = |address: IpAddr| nets.iter().any(|net| net.contains(address));
        let mut behavior = Behavior {
            local: nets.clone(),
            ..Behavior::default()
        };

        let mut flows: BTreeMap<FlowKey, Seen> = BTreeMap::new();
        for seen in subjects.iter().filter_map(|subject| self.seen.get(subject)) {
            for (key, seen) in seen {
                flows.entry(*key).or_insert(Seen::NONE).merge(
                    seen.count,
                    seen.start,
                    seen.initiator,
                );
            }
        }

        // Pair each flow with the one going the other way.
        type Endpoint = (IpAddr, u16);
        let mut conversations: BTreeMap<(u8, Endpoint, Endpoint), Vec<Record>> = BTreeMap::new();
        for (key, seen) in flows {
            if !key.accepted {
                let port = if ported(key.proto) {
                    format!(":{}", key.dport)
                } else {
                    String::new()
                };
                let what = format!(
                    "{} {} -> {}{port}",
                    protocol_name(key.proto),
                    key.src,
                    key.dst
                );
                *behavior.rejected.entry(what).or_default() += seen.count;
            } else if !(is_local(key.src) || is_local(key.dst)) {
                behavior.transit += seen.count;
            } else {
                let (a, b) = ((key.src, key.sport), (key.dst, key.dport));
                let pair = (key.proto, a.min(b), a.max(b));
                conversations.entry(pair).or_default().push((key, seen));
            }
        }

        for ((proto, ..), records) in &conversations {
            let (openings, sure) = openings(*proto, records);
            if !sure {
                behavior.ambiguous += 1;
            }
            let count: u64 = records.iter().map(|(_, seen)| seen.count).sum();
            for opening in openings {
                let service = (*proto, ported(*proto).then_some(opening.port));
                if is_local(opening.server) {
                    let peers = behavior.ingress.entry(service).or_default();
                    *peers.entry(opening.client).or_default() += count;
                }
                if is_local(opening.client) {
                    let peers = behavior.egress.entry(service).or_default();
                    *peers.entry(opening.server).or_default() += count;
                }
            }
        }
        Ok(behavior)
    }

    /// An interface's own address is the one present in every record
    /// captured on it.
    fn infer_local(&self, subject: &str) -> Result<IpAddr> {
        let mut common: Option<BTreeSet<IpAddr>> = None;
        for key in self.seen.get(subject).into_iter().flat_map(BTreeMap::keys) {
            let ends = BTreeSet::from([key.src, key.dst]);
            common = Some(match common {
                None => ends,
                Some(common) => &common & &ends,
            });
        }
        let common = common.unwrap_or_default();
        let why = match common.len() {
            1 => return Ok(common.into_iter().next().expect("one element")),
            0 => "no one address appears in every record",
            _ => "the log holds a single conversation",
        };
        Err(Error(format!(
            "cannot tell which address belongs to {subject:?} ({why}); \
             name the application's side with --local CIDR"
        )))
    }
}

/// Who opened this conversation, and whether that is a confident answer.
/// An unsure answer lists both directions, which over-allows rather than
/// breaking the application.
fn openings(proto: u8, records: &[Record]) -> (Vec<Opening>, bool) {
    // "The sender of this record opened" and "the receiver opened".
    let forward = |(key, _): &Record| Opening {
        client: key.src,
        server: key.dst,
        port: key.dport,
    };
    let backward = |(key, _): &Record| Opening {
        client: key.dst,
        server: key.src,
        port: key.sport,
    };

    // 1. The log says so (TCP SYN vs SYN-ACK).
    for record in records {
        if let Some(initiator) = record.1.initiator {
            return (
                vec![if initiator {
                    forward(record)
                } else {
                    backward(record)
                }],
                true,
            );
        }
    }

    let first = &records[0];
    if ported(proto) {
        // 2. A well-known or registered port talking to an ephemeral one.
        let (to, from) = (port_class(first.0.dport), port_class(first.0.sport));
        if to != from {
            return (
                vec![if to < from {
                    forward(first)
                } else {
                    backward(first)
                }],
                true,
            );
        }
    }
    // 3. One-way traffic: the receiver is the service.
    let Some(second) = records.get(1) else {
        return (vec![forward(first)], true);
    };
    // 4. Whoever spoke first. Second-granularity timestamps often tie.
    if first.1.start != second.1.start {
        let earlier = if first.1.start < second.1.start {
            first
        } else {
            second
        };
        return (vec![forward(earlier)], true);
    }
    (vec![forward(first), forward(second)], false)
}

fn port_class(port: u16) -> u8 {
    match port {
        0..1024 => 0,
        1024..EPHEMERAL => 1,
        _ => 2,
    }
}

fn protocol_name(proto: u8) -> String {
    match proto {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        58 => "icmpv6".to_string(),
        other => other.to_string(),
    }
}

fn service_name((proto, port): Service) -> String {
    match port {
        Some(port) => format!("{}/{port}", protocol_name(proto)),
        None => protocol_name(proto),
    }
}

// -- output ------------------------------------------------------------------

fn nets(list: &[Net]) -> String {
    list.iter()
        .map(Net::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn describe(behavior: &Behavior) -> String {
    let mut lines = vec![format!("Network behaviour of {}", nets(&behavior.local))];
    for (title, rules) in [
        ("Accepts connections on", &behavior.ingress),
        ("Opens connections to", &behavior.egress),
    ] {
        lines.push(String::new());
        lines.push(format!("{title}:"));
        let width = rules
            .keys()
            .map(|service| service_name(*service).len())
            .max()
            .unwrap_or(0);
        for (service, peers) in rules {
            let name = service_name(*service);
            let count = plural(peers.len() as u64, "peer");
            let peers: BTreeMap<String, u64> = peers
                .iter()
                .map(|(peer, count)| (peer.to_string(), *count))
                .collect();
            lines.push(format!("  {name:<width$}  {count:>9}  {}", top(&peers, 3)));
        }
        if rules.is_empty() {
            lines.push("  (nothing)".to_string());
        }
    }
    if !behavior.rejected.is_empty() {
        lines.push(String::new());
        lines.push("Rejected by the rules in force (never added to the policy):".to_string());
        let rejected = ranked(&behavior.rejected);
        for (what, count) in rejected.iter().take(REJECTED_ROWS) {
            lines.push(format!("  {what}  ({})", commas(*count)));
        }
        if rejected.len() > REJECTED_ROWS {
            let more = commas((rejected.len() - REJECTED_ROWS) as u64);
            lines.push(format!("  ... and {more} more"));
        }
    }
    if behavior.ambiguous > 0 {
        lines.push(String::new());
        lines.push(ambiguity_note(behavior.ambiguous));
    }
    lines.join("\n")
}

fn ambiguity_note(count: u64) -> String {
    format!(
        "{} had no clear server side and {} allowed in both directions",
        plural(count, "conversation"),
        if count == 1 { "is" } else { "are" },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        }
    }
}

/// One rule the behaviour calls for, before any cloud's dialect: `service`
/// may be opened by (ingress) or to (egress) the peers in `ranges`.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub direction: Direction,
    pub service: Service,
    pub ranges: Vec<Net>,
}

/// The rules that allow the behaviour, ingress first, with each rule's peers
/// summarised into at most `max_peers` ranges per address family; and notes
/// about what that cost in precision.
pub fn rules(behavior: &Behavior, max_peers: usize) -> (Vec<Rule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut notes = Vec::new();
    for (direction, services) in [
        (Direction::Ingress, &behavior.ingress),
        (Direction::Egress, &behavior.egress),
    ] {
        for (service, peers) in services {
            let ranges = summarize(peers.keys().copied(), max_peers);
            if ranges.iter().any(|net| net.prefix == 0) {
                notes.push(format!(
                    "{} {} is open to the world: {} could not be summarised \
                     into {max_peers} ranges",
                    direction.name(),
                    service_name(*service),
                    plural(peers.len() as u64, "peer"),
                ));
            }
            rules.push(Rule {
                direction,
                service: *service,
                ranges,
            });
        }
    }
    if behavior.ambiguous > 0 {
        notes.push(ambiguity_note(behavior.ambiguous));
    }
    (rules, notes)
}

/// Flow builders shared by this module's tests and the dialects'.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub const ME: &str = "10.0.1.5";

    pub fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    pub fn tcp(src: &str, sport: u16, dst: &str, dport: u16) -> Flow {
        Flow {
            subject: "eni-1".to_string(),
            proto: 6,
            src: ip(src),
            sport,
            dst: ip(dst),
            dport,
            accepted: true,
            start: 0.0,
            initiator: None,
            local: None,
        }
    }

    pub fn observe(flows: impl IntoIterator<Item = Flow>, local: &[&str]) -> Result<Behavior> {
        let mut collector = Collector::default();
        flows.into_iter().for_each(|flow| collector.add(flow));
        let local: Vec<String> = local.iter().map(|range| range.to_string()).collect();
        collector.behavior(&["eni-1".to_string()], &local)
    }

    /// The behaviour of some flows on one interface whose address is [`ME`].
    pub fn behavior(flows: impl IntoIterator<Item = Flow>) -> Behavior {
        observe(flows, &[ME]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::testing::{ME, observe, tcp};

    /// Behaviour with the interface's own address left to be inferred.
    fn behavior(flows: impl IntoIterator<Item = Flow>) -> Behavior {
        observe(flows, &[]).unwrap()
    }

    /// "tcp/443 a,b" style summary of one direction's services.
    fn services(found: &BTreeMap<Service, Peers>) -> Vec<String> {
        found
            .iter()
            .map(|(service, peers)| {
                let peers: Vec<String> = peers.keys().map(IpAddr::to_string).collect();
                format!("{} {}", service_name(*service), peers.join(","))
            })
            .collect()
    }

    #[test]
    fn well_known_port_marks_the_server() {
        let seen = behavior([
            tcp("203.0.113.7", 51000, ME, 443),
            tcp(ME, 443, "203.0.113.7", 51000),
            tcp(ME, 48000, "10.0.2.10", 5432),
            tcp("10.0.2.10", 5432, ME, 48000),
        ]);
        assert_eq!(services(&seen.ingress), ["tcp/443 203.0.113.7"]);
        assert_eq!(services(&seen.egress), ["tcp/5432 10.0.2.10"]);
        assert_eq!(nets(&seen.local), "10.0.1.5/32");
    }

    #[test]
    fn reply_only_capture_does_not_invert_the_rule() {
        let seen = behavior([
            tcp(ME, 443, "203.0.113.7", 51000),
            tcp(ME, 443, "203.0.113.8", 51001),
        ]);
        assert_eq!(services(&seen.ingress), ["tcp/443 203.0.113.7,203.0.113.8"]);
        assert!(seen.egress.is_empty());
    }

    #[test]
    fn syn_flags_beat_port_numbers() {
        // A service on an ephemeral port, called from a low source port.
        let seen = behavior([
            Flow {
                initiator: Some(true),
                ..tcp("10.0.2.10", 900, ME, 40000)
            },
            Flow {
                initiator: Some(false),
                ..tcp(ME, 40000, "10.0.2.10", 900)
            },
            tcp(ME, 40001, "10.0.2.11", 900),
        ]);
        assert_eq!(services(&seen.ingress), ["tcp/40000 10.0.2.10"]);
        assert_eq!(services(&seen.egress), ["tcp/900 10.0.2.11"]);
    }

    #[test]
    fn earlier_record_opens_when_ports_do_not_decide() {
        let seen = behavior([
            Flow {
                start: 100.0,
                ..tcp(ME, 45000, "10.0.2.10", 50000)
            },
            Flow {
                start: 101.0,
                ..tcp("10.0.2.10", 50000, ME, 45000)
            },
            tcp("10.0.2.20", 20000, ME, 20001),
        ]);
        assert_eq!(services(&seen.egress), ["tcp/50000 10.0.2.10"]);
        assert_eq!(services(&seen.ingress), ["tcp/20001 10.0.2.20"]);
        assert_eq!(seen.ambiguous, 0);
    }

    #[test]
    fn undecidable_conversation_is_allowed_both_ways_and_flagged() {
        let seen = behavior([
            tcp(ME, 45000, "10.0.2.10", 50000),
            tcp("10.0.2.10", 50000, ME, 45000),
            tcp(ME, 50000, "10.0.2.99", 443), // pins down which address is local
        ]);
        assert_eq!(
            services(&seen.egress),
            ["tcp/443 10.0.2.99", "tcp/50000 10.0.2.10"]
        );
        assert_eq!(services(&seen.ingress), ["tcp/45000 10.0.2.10"]);
        assert_eq!(seen.ambiguous, 1);
        let (_, notes) = rules(&seen, 8);
        assert!(notes.iter().any(|note| note.contains("both directions")));
        assert!(describe(&seen).contains("both directions"));
    }

    #[test]
    fn icmp_has_no_ports() {
        let ping = |src: &str, dst: &str, start: f64| Flow {
            proto: 1,
            start,
            ..tcp(src, 8, dst, 0)
        };
        let seen = behavior([
            ping(ME, "10.0.2.99", 5.0),
            ping("10.0.2.99", ME, 6.0),
            tcp(ME, 50000, "10.0.2.98", 443),
        ]);
        assert_eq!(
            services(&seen.egress),
            ["icmp 10.0.2.99", "tcp/443 10.0.2.98"]
        );
        assert!(seen.ingress.is_empty());
    }

    #[test]
    fn rejected_flows_are_shown_but_never_allowed() {
        let seen = behavior([
            Flow {
                accepted: false,
                ..tcp("192.0.2.66", 55001, ME, 22)
            },
            tcp("203.0.113.7", 51000, ME, 443),
            tcp("203.0.113.8", 51000, ME, 443),
        ]);
        assert_eq!(services(&seen.ingress), ["tcp/443 203.0.113.7,203.0.113.8"]);
        assert!(describe(&seen).contains("tcp 192.0.2.66 -> 10.0.1.5:22  (1)"));
    }

    #[test]
    fn local_address_must_be_inferable_or_given() {
        let one_conversation = || {
            [
                tcp("203.0.113.7", 51000, ME, 443),
                tcp(ME, 443, "203.0.113.7", 51000),
            ]
        };
        let error = |result: Result<Behavior>| result.unwrap_err().0;
        assert!(error(observe(one_conversation(), &[])).contains("single conversation"));
        let strangers = [
            tcp("10.0.0.1", 1, "10.0.0.2", 2),
            tcp("10.0.0.3", 3, "10.0.0.4", 4),
        ];
        assert!(error(observe(strangers, &[])).contains("--local"));
        assert!(error(observe(one_conversation(), &["not-a-cidr"])).contains("--local"));

        let seen = observe(one_conversation(), &["10.0.1.77/24"]).unwrap();
        assert_eq!(services(&seen.ingress), ["tcp/443 203.0.113.7"]);
        assert_eq!(nets(&seen.local), "10.0.1.0/24");
    }

    #[test]
    fn wide_local_range_sees_both_ends_and_ignores_transit() {
        let flows = [
            tcp("10.0.1.5", 48000, "10.0.1.9", 5432),
            tcp("172.16.0.1", 48000, "172.16.0.2", 80),
        ];
        let seen = observe(flows, &["10.0.1.0/24"]).unwrap();
        assert_eq!(services(&seen.ingress), ["tcp/5432 10.0.1.5"]);
        assert_eq!(services(&seen.egress), ["tcp/5432 10.0.1.9"]);
        assert_eq!(seen.transit, 1);
    }
}
