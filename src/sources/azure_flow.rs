//! Azure Network Watcher flow logs -> [`Flow`].
//!
//! Reads virtual network flow logs and the older network security group
//! flow logs (versions 1 and 2), which Azure retires in September 2027.
//! Both keep their records as comma-separated "flow tuples":
//!
//! ```text
//! NSG:   time,src,dst,sport,dport,T|U,I|O,A|D[,B|C|E,counters...]
//! VNet:  time,src,dst,sport,dport,<protocol number>,I|O,B|C|E|D,encryption,counters...
//! ```
//!
//! A tuple describes a whole connection, with counters for each direction,
//! and in every documented sample its source is the end that opened it. The
//! documentation does not state that as a rule; this module relies on it.
//! The direction (`I`nbound or `O`utbound) says which end is the monitored
//! interface, and the interface's MAC address is the subject.

use std::io::{self, BufRead};

use serde_json::Value;

use crate::events::{Flow, Notes};
use crate::sources::{json_documents, text};

pub fn sniff(head: &str) -> bool {
    head.contains("\"flowTuples\"")
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(Flow),
) -> io::Result<()> {
    for document in &json_documents(reader, notes)? {
        walk(document, None, notes, emit);
    }
    Ok(())
}

/// Find every `flowTuples` list, wherever the format version nests it,
/// remembering the nearest MAC address above it.
fn walk(value: &Value, mac: Option<&str>, notes: &mut Notes, emit: &mut dyn FnMut(Flow)) {
    match value {
        Value::Array(items) => items.iter().for_each(|item| walk(item, mac, notes, emit)),
        Value::Object(map) => {
            let mac = text(value, "mac")
                .or_else(|| text(value, "macAddress"))
                .or(mac);
            for (key, inner) in map {
                let tuples = inner.as_array().filter(|_| key == "flowTuples");
                match tuples {
                    Some(tuples) => {
                        for tuple in tuples.iter().filter_map(Value::as_str) {
                            match flow(tuple, mac) {
                                Some(flow) => emit(flow),
                                None => notes.add("skipped a flow tuple that could not be read"),
                            }
                        }
                    }
                    None => walk(inner, mac, notes, emit),
                }
            }
        }
        _ => {}
    }
}

fn flow(tuple: &str, mac: Option<&str>) -> Option<Flow> {
    let fields: Vec<&str> = tuple.split(',').collect();
    let [
        time,
        src,
        dst,
        sport,
        dport,
        protocol,
        direction,
        verdict,
        ..,
    ] = fields[..]
    else {
        return None;
    };
    let (src, dst) = (src.parse().ok()?, dst.parse().ok()?);
    Some(Flow {
        subject: mac.unwrap_or("all flows").to_string(),
        proto: match protocol {
            "T" => 6,
            "U" => 17,
            number => number.parse().ok()?,
        },
        src,
        sport: sport.parse().ok()?,
        dst,
        dport: dport.parse().ok()?,
        // "D" is the denied decision of an NSG tuple and the deny state of
        // a VNet tuple; both sit in this position.
        accepted: verdict != "D",
        start: time.parse().ok()?,
        initiator: Some(true),
        local: match direction {
            "I" => Some(dst),
            "O" => Some(src),
            _ => None,
        },
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse_text(text: &str) -> (Vec<Flow>, Notes) {
        let (mut flows, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), &mut notes, &mut |flow| {
            flows.push(flow)
        })
        .unwrap();
        (flows, notes)
    }

    /// (subject, src, dport, proto, accepted, local) of each flow.
    fn summary(flows: &[Flow]) -> Vec<(&str, String, u16, u8, bool, String)> {
        flows
            .iter()
            .map(|f| {
                let local = f.local.unwrap().to_string();
                (
                    f.subject.as_str(),
                    f.src.to_string(),
                    f.dport,
                    f.proto,
                    f.accepted,
                    local,
                )
            })
            .collect()
    }

    #[test]
    fn reads_virtual_network_flow_logs() {
        let log = json!({"records": [{
            "flowLogVersion": 4,
            "macAddress": "112233445566",
            "category": "FlowLogFlowEvent",
            "flowRecords": {"flows": [{
                "aclID": "a",
                "flowGroups": [
                    {"rule": "DefaultRule_AllowInternetOutBound", "flowTuples": [
                        "1663146003599,10.0.0.6,192.0.2.180,23956,443,6,O,B,NX,0,0,0,0",
                        "1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,3,767,2,1580",
                    ]},
                    {"rule": "BlockHighRiskTCPPortsFromInternet", "flowTuples": [
                        "1663145998065,101.33.218.153,10.0.0.6,55188,22,6,I,D,NX,0,0,0,0",
                        "1663146005503,10.0.0.6,10.0.0.9,40000,53,17,O,B,NX,0,0,0,0,822134362,10.26.252.5,4890",
                    ]},
                ],
            }]},
        }]});
        assert!(sniff(&log.to_string()));
        let (flows, notes) = parse_text(&log.to_string());
        let (mac, me) = ("112233445566", "10.0.0.6".to_string());
        assert_eq!(
            summary(&flows),
            [
                (mac, me.clone(), 443, 6, true, me.clone()),
                (mac, me.clone(), 443, 6, true, me.clone()),
                (mac, "101.33.218.153".to_string(), 22, 6, false, me.clone()),
                (mac, me.clone(), 53, 17, true, me),
            ]
        );
        assert!(flows.iter().all(|f| f.initiator == Some(true)));
        assert!(notes.is_empty());
    }

    #[test]
    fn reads_security_group_flow_logs() {
        let log = json!({"records": [{
            "category": "NetworkSecurityGroupFlowEvent",
            "properties": {"Version": 2, "flows": [
                {"rule": "DefaultRule_DenyAllInBound", "flows": [{
                    "mac": "000D3AF87856",
                    "flowTuples": ["1542110402,192.0.2.190,10.5.16.4,28746,443,U,I,D,B,,,,"],
                }]},
                {"rule": "DefaultRule_AllowInternetOutBound", "flows": [{
                    "mac": "000D3AF87856",
                    "flowTuples": [
                        "1542110377,10.5.16.4,203.0.113.118,59831,443,T,O,A,B,,,,",
                        "1542110379,10.5.16.4,203.0.113.117,59932,443,T,O,A,E,1,66,1,66",
                    ],
                }]},
            ]},
        }, {
            // Version 1 has no flow state; some exports nest "records" again.
            "records": [{"properties": {"Version": 1, "flows": [{"flows": [{
                "mac": "000D3AF8801A",
                "flowTuples": ["1487282370,192.0.2.17,10.1.0.4,61771,3389,T,I,A", "garbage"],
            }]}]}}],
        }]});
        let (flows, notes) = parse_text(&log.to_string());
        let me = "10.5.16.4".to_string();
        assert_eq!(
            summary(&flows),
            [
                (
                    "000D3AF87856",
                    "192.0.2.190".to_string(),
                    443,
                    17,
                    false,
                    me.clone()
                ),
                ("000D3AF87856", me.clone(), 443, 6, true, me.clone()),
                ("000D3AF87856", me.clone(), 443, 6, true, me),
                (
                    "000D3AF8801A",
                    "192.0.2.17".to_string(),
                    3389,
                    6,
                    true,
                    "10.1.0.4".to_string()
                ),
            ]
        );
        assert_eq!(notes.len(), 1);
    }
}
