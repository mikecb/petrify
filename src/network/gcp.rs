//! Network behaviour -> Google Cloud VPC firewall rules.
//!
//! The output is a list of `Firewall` resources as the Compute Engine API
//! takes them. They name no network and no target, because the flows cannot
//! say which instances the rules are for: add `network` and `targetTags` or
//! `targetServiceAccounts` before creating them.

use serde_json::{Value, json};

use super::{Behavior, Direction, Rule, Service, nets, rules};

pub const POLICY_NAME: &str = "GCP firewall rules";

const ALLOW_PRIORITY: u32 = 1000;
/// Just ahead of the implied allow-all-egress rule at 65535.
const DENY_PRIORITY: u32 = 65534;

/// Firewall rules allowing the observed traffic and denying other egress,
/// and notes about them.
pub fn policy(behavior: &Behavior, max_peers: usize) -> (Value, Vec<String>) {
    let (rules, mut notes) = rules(behavior, max_peers);
    let description = format!("petrify: observed traffic of {}", nets(&behavior.local));

    let mut firewalls: Vec<Value> = Vec::new();
    for rule in &rules {
        // One rule cannot mix IPv4 and IPv6 ranges.
        for v6 in [false, true] {
            let ranges: Vec<String> = rule
                .ranges
                .iter()
                .filter(|net| net.v6 == v6)
                .map(|net| net.to_string())
                .collect();
            if !ranges.is_empty() {
                firewalls.push(allow(rule, v6, ranges, &description));
            }
        }
    }
    // Ingress is denied unless allowed, but egress is allowed unless denied.
    for (suffix, everywhere) in [("", "0.0.0.0/0"), ("-v6", "::/0")] {
        firewalls.push(json!({
            "name": format!("petrify-egress-deny-all{suffix}"),
            "description": description,
            "direction": "EGRESS",
            "priority": DENY_PRIORITY,
            "denied": [{"IPProtocol": "all"}],
            "destinationRanges": [everywhere],
        }));
    }
    notes.push(
        "the rules name no network or target and would apply to every instance on the \
         default network: set `network` and `targetTags` or `targetServiceAccounts` first"
            .to_string(),
    );
    (Value::Array(firewalls), notes)
}

fn allow(rule: &Rule, v6: bool, ranges: Vec<String>, description: &str) -> Value {
    let (protocol, port) = protocol_and_port(rule.service);
    let (direction, ranges_key) = match rule.direction {
        Direction::Ingress => ("INGRESS", "sourceRanges"),
        Direction::Egress => ("EGRESS", "destinationRanges"),
    };
    let mut allowed = json!({ "IPProtocol": protocol });
    if let Some(port) = port {
        allowed["ports"] = json!([port.to_string()]);
    }
    let name = format!(
        "petrify-{}-{protocol}{}{}",
        rule.direction.name(),
        port.map(|port| format!("-{port}")).unwrap_or_default(),
        if v6 { "-v6" } else { "" },
    );
    json!({
        "name": name,
        "description": description,
        "direction": direction,
        "priority": ALLOW_PRIORITY,
        "allowed": [allowed],
        ranges_key: ranges,
    })
}

/// The protocol as the API names it: a few well-known names, else the
/// number. Ports apply to TCP, UDP and SCTP only.
fn protocol_and_port((proto, port): Service) -> (String, Option<u16>) {
    let name = match proto {
        1 => "icmp",
        4 => "ipip",
        6 => "tcp",
        17 => "udp",
        50 => "esp",
        51 => "ah",
        132 => "sctp",
        other => return (other.to_string(), None),
    };
    (name.to_string(), port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Flow;
    use crate::network::testing::{ME, behavior, tcp};

    #[test]
    fn rules_allow_what_was_seen_and_deny_other_egress() {
        let ping = Flow {
            proto: 1,
            ..tcp(ME, 0, "10.0.2.99", 0)
        };
        let seen = behavior([
            tcp("203.0.113.7", 51000, ME, 443),
            tcp(ME, 48000, "10.0.2.10", 5432),
            ping,
        ]);
        let (document, notes) = policy(&seen, 8);
        let description = "petrify: observed traffic of 10.0.1.5/32";
        assert_eq!(
            document,
            json!([
                {
                    "name": "petrify-ingress-tcp-443",
                    "description": description,
                    "direction": "INGRESS",
                    "priority": 1000,
                    "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
                    "sourceRanges": ["203.0.113.7/32"],
                },
                {
                    "name": "petrify-egress-icmp",
                    "description": description,
                    "direction": "EGRESS",
                    "priority": 1000,
                    "allowed": [{"IPProtocol": "icmp"}],
                    "destinationRanges": ["10.0.2.99/32"],
                },
                {
                    "name": "petrify-egress-tcp-5432",
                    "description": description,
                    "direction": "EGRESS",
                    "priority": 1000,
                    "allowed": [{"IPProtocol": "tcp", "ports": ["5432"]}],
                    "destinationRanges": ["10.0.2.10/32"],
                },
                {
                    "name": "petrify-egress-deny-all",
                    "description": description,
                    "direction": "EGRESS",
                    "priority": 65534,
                    "denied": [{"IPProtocol": "all"}],
                    "destinationRanges": ["0.0.0.0/0"],
                },
                {
                    "name": "petrify-egress-deny-all-v6",
                    "description": description,
                    "direction": "EGRESS",
                    "priority": 65534,
                    "denied": [{"IPProtocol": "all"}],
                    "destinationRanges": ["::/0"],
                },
            ])
        );
        assert!(notes.iter().any(|note| note.contains("targetTags")));
    }

    #[test]
    fn address_families_get_separate_rules() {
        let seen = behavior([
            tcp("203.0.113.7", 51000, ME, 443),
            tcp("2001:db8::7", 51000, ME, 443),
        ]);
        let (document, _) = policy(&seen, 8);
        let names: Vec<&str> = document
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|rule| rule["name"].as_str())
            .collect();
        assert_eq!(
            names[..2],
            ["petrify-ingress-tcp-443", "petrify-ingress-tcp-443-v6"]
        );
        assert_eq!(document[1]["sourceRanges"], json!(["2001:db8::7/128"]));
    }

    #[test]
    fn unnamed_protocols_are_numbers_without_ports() {
        assert_eq!(protocol_and_port((58, None)), ("58".to_string(), None));
        assert_eq!(
            protocol_and_port((17, Some(53))),
            ("udp".to_string(), Some(53))
        );
    }
}
