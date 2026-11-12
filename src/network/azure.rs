//! Network behaviour -> Azure network security group rules.
//!
//! The output is a list of security rules in the shape of an ARM template's
//! `securityRules`: a name and `properties`.

use serde_json::{Value, json};

use super::{Behavior, Direction, Rule, nets, protocol_name, rules};

pub const POLICY_NAME: &str = "Azure NSG rules";

const FIRST_PRIORITY: u32 = 100;
/// The lowest priority a rule can be given. It still comes before the
/// default rules (65000 and up), which allow all traffic inside the virtual
/// network and all outbound traffic to the internet.
const LAST_PRIORITY: u32 = 4096;
/// Characters in a rule description.
const DESCRIPTION_LIMIT: usize = 140;

/// Security rules allowing the observed traffic and denying the rest, and
/// notes about them.
pub fn policy(behavior: &Behavior, max_peers: usize) -> (Value, Vec<String>) {
    let (rules, mut notes) = rules(behavior, max_peers);
    let mut description = format!("petrify: observed traffic of {}", nets(&behavior.local));
    description.truncate(DESCRIPTION_LIMIT); // the text is ASCII

    let mut security_rules: Vec<Value> = Vec::new();
    for direction in [Direction::Ingress, Direction::Egress] {
        let mut allows: Vec<(String, &Rule, Vec<String>)> = Vec::new();
        for rule in rules.iter().filter(|rule| rule.direction == direction) {
            let Some(protocol) = protocol(rule.service.0) else {
                notes.push(format!(
                    "{} {} is left out: a security rule cannot name IP protocol {}",
                    direction.name(),
                    protocol_name(rule.service.0),
                    rule.service.0,
                ));
                continue;
            };
            // Kept apart, since the docs do not say a rule may mix families.
            for v6 in [false, true] {
                let ranges: Vec<String> = rule
                    .ranges
                    .iter()
                    .filter(|net| net.v6 == v6)
                    .map(|net| net.to_string())
                    .collect();
                if !ranges.is_empty() {
                    let port = rule
                        .service
                        .1
                        .map(|port| format!("-{port}"))
                        .unwrap_or_default();
                    let family = if v6 { "-v6" } else { "" };
                    let name = format!(
                        "petrify-{}-{}{port}{family}",
                        way(direction).0,
                        protocol.to_lowercase()
                    );
                    allows.push((name, rule, ranges));
                }
            }
        }

        // Priorities are unique per direction; leave gaps while they fit.
        let room = (LAST_PRIORITY - FIRST_PRIORITY) as usize;
        let step = if allows.len() * 10 <= room { 10 } else { 1 };
        if allows.len() > room {
            notes.push(format!(
                "{} {} rules do not fit the priorities a security group has; lower --max-peers",
                allows.len(),
                direction.name()
            ));
        }
        for (index, (name, rule, ranges)) in allows.into_iter().enumerate() {
            let priority = FIRST_PRIORITY + (index * step) as u32;
            let port = rule
                .service
                .1
                .map_or("*".to_string(), |port| port.to_string());
            // The peers are the source of inbound traffic and the destination
            // of outbound; the other end is whatever the group is attached to.
            let (peers, own) = match direction {
                Direction::Ingress => ("sourceAddressPrefixes", "destinationAddressPrefix"),
                Direction::Egress => ("destinationAddressPrefixes", "sourceAddressPrefix"),
            };
            security_rules.push(json!({
                "name": name,
                "properties": {
                    "description": description,
                    "priority": priority,
                    "direction": way(direction).1,
                    "access": "Allow",
                    "protocol": protocol(rule.service.0),
                    "sourcePortRange": "*",
                    "destinationPortRange": port,
                    peers: ranges,
                    own: "*",
                },
            }));
        }
        security_rules.push(json!({
            "name": format!("petrify-{}-deny-all", way(direction).0),
            "properties": {
                "description": description,
                "priority": LAST_PRIORITY,
                "direction": way(direction).1,
                "access": "Deny",
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "*",
                "destinationAddressPrefix": "*",
            },
        }));
    }
    (Value::Array(security_rules), notes)
}

/// A direction as rule names and as the API spell it.
fn way(direction: Direction) -> (&'static str, &'static str) {
    match direction {
        Direction::Ingress => ("in", "Inbound"),
        Direction::Egress => ("out", "Outbound"),
    }
}

/// The protocols a security rule can name.
fn protocol(proto: u8) -> Option<&'static str> {
    match proto {
        1 => Some("Icmp"),
        6 => Some("Tcp"),
        17 => Some("Udp"),
        50 => Some("Esp"),
        51 => Some("Ah"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Flow;
    use crate::network::testing::{ME, behavior, tcp};

    #[test]
    fn rules_allow_what_was_seen_and_deny_the_rest() {
        let seen = behavior([
            tcp("203.0.113.7", 51000, ME, 443),
            tcp("203.0.113.9", 51000, ME, 8443),
            tcp(ME, 48000, "10.0.2.10", 5432),
        ]);
        let (document, notes) = policy(&seen, 8);
        let description = "petrify: observed traffic of 10.0.1.5/32";
        assert_eq!(
            document,
            json!([
                {
                    "name": "petrify-in-tcp-443",
                    "properties": {
                        "description": description,
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "443",
                        "sourceAddressPrefixes": ["203.0.113.7/32"],
                        "destinationAddressPrefix": "*",
                    },
                },
                {
                    "name": "petrify-in-tcp-8443",
                    "properties": {
                        "description": description,
                        "priority": 110,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "8443",
                        "sourceAddressPrefixes": ["203.0.113.9/32"],
                        "destinationAddressPrefix": "*",
                    },
                },
                {
                    "name": "petrify-in-deny-all",
                    "properties": {
                        "description": description,
                        "priority": 4096,
                        "direction": "Inbound",
                        "access": "Deny",
                        "protocol": "*",
                        "sourcePortRange": "*",
                        "destinationPortRange": "*",
                        "sourceAddressPrefix": "*",
                        "destinationAddressPrefix": "*",
                    },
                },
                {
                    "name": "petrify-out-tcp-5432",
                    "properties": {
                        "description": description,
                        "priority": 100,
                        "direction": "Outbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "5432",
                        "destinationAddressPrefixes": ["10.0.2.10/32"],
                        "sourceAddressPrefix": "*",
                    },
                },
                {
                    "name": "petrify-out-deny-all",
                    "properties": {
                        "description": description,
                        "priority": 4096,
                        "direction": "Outbound",
                        "access": "Deny",
                        "protocol": "*",
                        "sourcePortRange": "*",
                        "destinationPortRange": "*",
                        "sourceAddressPrefix": "*",
                        "destinationAddressPrefix": "*",
                    },
                },
            ])
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn portless_and_unsupported_protocols() {
        let other = |proto: u8, peer: &str| Flow {
            proto,
            ..tcp(ME, 0, peer, 0)
        };
        let seen = behavior([other(1, "10.0.2.99"), other(47, "10.0.2.98")]);
        let (document, notes) = policy(&seen, 8);
        let icmp = &document[1]["properties"];
        assert_eq!(document[1]["name"], "petrify-out-icmp");
        assert_eq!(icmp["protocol"], "Icmp");
        assert_eq!(icmp["destinationPortRange"], "*");
        assert_eq!(document.as_array().unwrap().len(), 3); // icmp and two denies
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("egress 47 is left out"));
    }

    #[test]
    fn priorities_tighten_when_there_are_many_rules() {
        let flows = (0..450u16).map(|n| tcp(ME, 40000, "10.0.2.10", 1000 + n));
        let (document, _) = policy(&behavior(flows), 8);
        let rules = document.as_array().unwrap();
        // inbound deny, 450 outbound allows, outbound deny
        assert_eq!(rules.len(), 452);
        assert_eq!(rules[1]["properties"]["priority"], 100);
        assert_eq!(rules[450]["properties"]["priority"], 549);
        assert_eq!(rules[451]["properties"]["priority"], 4096);
    }
}
