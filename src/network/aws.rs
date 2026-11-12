//! Network behaviour -> AWS security group rules.

use serde_json::{Value, json};

use super::{Behavior, Direction, Net, Service, nets, protocol_name, rules};

pub const POLICY_NAME: &str = "security group";

/// AWS default quota, per direction.
const RULES_PER_GROUP: usize = 60;

/// Security group rules in the shape `aws ec2 describe-security-groups`
/// prints and `authorize-security-group-*` accepts, and notes about them.
pub fn policy(behavior: &Behavior, max_peers: usize) -> (Value, Vec<String>) {
    let (rules, mut notes) = rules(behavior, max_peers);
    let mut description = format!("petrify: observed traffic of {}", nets(&behavior.local));
    description.truncate(255); // the API's limit; the text is ASCII
    let mut document = json!({ "Description": description });

    for (key, direction) in [
        ("IpPermissions", Direction::Ingress),
        ("IpPermissionsEgress", Direction::Egress),
    ] {
        let rules = rules.iter().filter(|rule| rule.direction == direction);
        let permissions: Vec<Value> = rules
            .clone()
            .map(|rule| permission(rule.service, &rule.ranges))
            .collect();
        let total: usize = rules.map(|rule| rule.ranges.len()).sum();
        if total > RULES_PER_GROUP {
            notes.push(format!(
                "{total} {} rules exceed the default quota of {RULES_PER_GROUP} \
                 per security group; lower --max-peers",
                direction.name()
            ));
        }
        document[key] = Value::Array(permissions);
    }
    (document, notes)
}

fn permission((proto, port): Service, ranges: &[Net]) -> Value {
    let mut permission = json!({ "IpProtocol": protocol_name(proto) });
    // -1 means every ICMP type; other portless protocols take no port fields.
    if let Some(port) = port
        .map(i32::from)
        .or(matches!(proto, 1 | 58).then_some(-1))
    {
        permission["FromPort"] = json!(port);
        permission["ToPort"] = json!(port);
    }
    let cidrs = |v6: bool, key: &str| -> Vec<Value> {
        ranges
            .iter()
            .filter(|net| net.v6 == v6)
            .map(|net| json!({ key: net.to_string() }))
            .collect()
    };
    let (v4, v6) = (cidrs(false, "CidrIp"), cidrs(true, "CidrIpv6"));
    if !v4.is_empty() {
        permission["IpRanges"] = Value::Array(v4);
    }
    if !v6.is_empty() {
        permission["Ipv6Ranges"] = Value::Array(v6);
    }
    permission
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Flow;
    use crate::network::testing::{ME, behavior, tcp};

    #[test]
    fn icmp_takes_the_all_types_port() {
        let ping = Flow {
            proto: 1,
            ..tcp(ME, 0, "10.0.2.99", 0)
        };
        let (document, _) = policy(&behavior([ping, tcp(ME, 50000, "10.0.2.98", 443)]), 8);
        assert_eq!(
            document["IpPermissionsEgress"][0],
            json!({
                "IpProtocol": "icmp",
                "FromPort": -1,
                "ToPort": -1,
                "IpRanges": [{"CidrIp": "10.0.2.99/32"}],
            })
        );
        assert_eq!(document["IpPermissions"], json!([]));
    }

    #[test]
    fn world_open_rules_and_quota_are_flagged() {
        let calls = |range: std::ops::Range<u32>| {
            range
                .map(|n| tcp(ME, 40000 + n as u16, &format!("{n}.1.1.1"), 443))
                .collect::<Vec<_>>()
        };
        let (document, notes) = policy(&behavior(calls(11..60)), 4);
        assert_eq!(
            document["IpPermissionsEgress"],
            json!([{
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }])
        );
        assert!(notes.iter().any(|note| note.contains("open to the world")));

        let (_, notes) = policy(&behavior(calls(11..111)), 200);
        assert!(notes.iter().any(|note| note.contains("quota")));
    }
}
