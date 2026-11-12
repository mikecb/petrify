//! Google Cloud VPC Flow Logs -> [`Flow`].
//!
//! Each record is reported by one end of the flow (`reporter` is `SRC` or
//! `DEST`), which is how the log says whose flow it is: the subject is the
//! reporting VM and its address is the local one. Like AWS flow logs, the
//! two directions of a connection are separate records and nothing says who
//! opened it.
//!
//! Nothing marks a flow as denied either. Inbound packets a firewall rule
//! denies are not logged at all, but outbound packets are sampled before
//! egress rules apply, so a refused outbound attempt looks like any other
//! flow and ends up allowed by the generated rules.
//!
//! Reads the same shapes as the audit log source: a JSON array, JSON Lines,
//! or BigQuery rows.

use std::io::{self, BufRead};
use std::net::IpAddr;

use serde_json::Value;

use crate::events::{Flow, Notes};
use crate::sources::{json_documents, text, timestamp};

pub fn sniff(head: &str) -> bool {
    head.contains("vpc_flows") || (head.contains("\"reporter\"") && head.contains("\"connection\""))
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(Flow),
) -> io::Result<()> {
    for document in &json_documents(reader, notes)? {
        entries(document, notes, emit);
    }
    Ok(())
}

fn entries(document: &Value, notes: &mut Notes, emit: &mut dyn FnMut(Flow)) {
    if let Some(items) = document.as_array() {
        items.iter().for_each(|item| entries(item, notes, emit));
        return;
    }
    let payload = document.get("jsonPayload").unwrap_or(document);
    match flow(payload) {
        Some(flow) => emit(flow),
        None => notes.add("skipped a log entry that is not a flow record"),
    }
}

fn flow(payload: &Value) -> Option<Flow> {
    let connection = payload.get("connection")?;
    let src: IpAddr = text(connection, "src_ip")?.parse().ok()?;
    let dst: IpAddr = text(connection, "dest_ip")?.parse().ok()?;

    // "SRC" and "DEST" for VMs; gateways report as "SRC_GATEWAY" and so on.
    let reporter = text(payload, "reporter").unwrap_or("");
    let (local, instance) = if reporter.starts_with("SRC") {
        (Some(src), "src_instance")
    } else if reporter.starts_with("DEST") {
        (Some(dst), "dest_instance")
    } else {
        (None, "")
    };
    let vm = payload.get(instance).and_then(|vm| text(vm, "vm_name"));
    let subject = match (vm, local) {
        (Some(vm), _) => vm.to_string(),
        (None, Some(address)) => address.to_string(),
        (None, None) => "all flows".to_string(),
    };
    Some(Flow {
        subject,
        proto: number(connection.get("protocol")?)?,
        src,
        sport: connection.get("src_port").and_then(number).unwrap_or(0),
        dst,
        dport: connection.get("dest_port").and_then(number).unwrap_or(0),
        accepted: true,
        start: text(payload, "start_time")
            .and_then(timestamp)
            .unwrap_or(0.0),
        initiator: None,
        local,
    })
}

/// Numbers arrive as JSON numbers or, for 64-bit fields and from some
/// exports, as strings.
fn number<T: TryFrom<u64> + std::str::FromStr>(value: &Value) -> Option<T> {
    match value {
        Value::String(text) => text.parse().ok(),
        other => T::try_from(other.as_u64()?).ok(),
    }
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

    fn record(reporter: &str, src: (&str, u16), dst: (&str, u16), vm: Value) -> Value {
        let mut payload = json!({
            "connection": {
                "src_ip": src.0, "src_port": src.1,
                "dest_ip": dst.0, "dest_port": dst.1,
                "protocol": 6,
            },
            "reporter": reporter,
            "start_time": "2019-06-14T03:45:37.186193305Z",
            "bytes_sent": "1776",
        });
        let side = if reporter == "SRC" {
            "src_instance"
        } else {
            "dest_instance"
        };
        payload[side] = vm;
        json!({
            "logName": "projects/p/logs/compute.googleapis.com%2Fvpc_flows",
            "resource": {"type": "gce_subnetwork"},
            "jsonPayload": payload,
        })
    }

    #[test]
    fn the_reporter_is_the_subject_and_the_local_end() {
        let web = json!({"vm_name": "web", "zone": "us-east1-b"});
        let log = json!([
            record(
                "DEST",
                ("203.0.113.7", 51000),
                ("10.0.1.5", 443),
                web.clone()
            ),
            record("SRC", ("10.0.1.5", 443), ("203.0.113.7", 51000), web),
            record("SRC", ("10.0.9.9", 40000), ("10.0.2.10", 5432), Value::Null),
        ]);
        assert!(sniff(&log.to_string()));
        let (flows, notes) = parse_text(&log.to_string());
        let seen: Vec<(&str, String, u16, u16)> = flows
            .iter()
            .map(|f| {
                (
                    f.subject.as_str(),
                    f.local.unwrap().to_string(),
                    f.sport,
                    f.dport,
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("web", "10.0.1.5".to_string(), 51000, 443),
                ("web", "10.0.1.5".to_string(), 443, 51000),
                ("10.0.9.9", "10.0.9.9".to_string(), 40000, 5432),
            ]
        );
        assert!(
            flows
                .iter()
                .all(|f| f.accepted && f.proto == 6 && f.initiator.is_none())
        );
        assert!(flows[0].start > 1_560_000_000.0);
        assert!(notes.is_empty());
    }

    #[test]
    fn numbers_may_be_strings_and_other_entries_are_skipped() {
        let row = json!({
            "connection": {
                "src_ip": "10.0.1.5", "src_port": "40000",
                "dest_ip": "10.0.2.10", "dest_port": "53",
                "protocol": "17",
            },
            "reporter": "SRC",
        });
        let other = json!({"jsonPayload": {"message": "not a flow"}});
        let (flows, notes) = parse_text(&format!("{row}\n{other}\n"));
        assert_eq!(flows.len(), 1);
        assert_eq!(
            (flows[0].proto, flows[0].sport, flows[0].dport),
            (17, 40000, 53)
        );
        assert_eq!(notes.len(), 1);
    }
}
