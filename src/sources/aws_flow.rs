//! AWS VPC Flow Logs -> [`Flow`].
//!
//! Three ways of knowing which field is which, in this order:
//!
//! 1. A header line naming the fields, which is how flow logs delivered to
//!    S3 start.
//! 2. Field names given by the user (`--fields`), for a custom format that
//!    reached CloudWatch Logs or anywhere else without its header.
//! 3. AWS's own order. The default format is the first fourteen fields of
//!    it, and a log configured with "all fields" continues in the same
//!    order through each later version's additions.

use std::io::{self, BufRead};

use crate::events::{Flow, Notes};
use crate::inputs::for_each_line;

/// Every field in the order AWS documents and emits them. The default
/// (version 2) format is the first [`DEFAULT_COUNT`].
const STANDARD_FIELDS: [&str; 40] = [
    // version 2
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
    // version 3
    "vpc-id",
    "subnet-id",
    "instance-id",
    "tcp-flags",
    "type",
    "pkt-srcaddr",
    "pkt-dstaddr",
    // version 4
    "region",
    "az-id",
    "sublocation-type",
    "sublocation-id",
    // version 5
    "pkt-src-aws-service",
    "pkt-dst-aws-service",
    "flow-direction",
    "traffic-path",
    // version 7
    "ecs-cluster-arn",
    "ecs-cluster-name",
    "ecs-container-instance-arn",
    "ecs-container-instance-id",
    "ecs-container-id",
    "ecs-second-container-id",
    "ecs-service-name",
    "ecs-task-definition-arn",
    "ecs-task-arn",
    "ecs-task-id",
    // version 8
    "reject-reason",
];
const DEFAULT_COUNT: usize = 14;
const REQUIRED: [&str; 5] = ["srcaddr", "dstaddr", "srcport", "dstport", "protocol"];

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

fn is_header(tokens: &[&str]) -> bool {
    REQUIRED.iter().all(|field| tokens.contains(field))
}

/// Where a record in AWS's own field order starts within a line. Exports
/// from CloudWatch Logs put a timestamp or two in front of each record.
fn standard_start(tokens: &[&str]) -> Option<usize> {
    (0..=2).find(|&start| {
        let Some(record) = tokens.get(start..start + DEFAULT_COUNT) else {
            return false;
        };
        let version = record[0];
        version.len() <= 2
            && version.bytes().all(|b| b.is_ascii_digit())
            && matches!(record[12], "ACCEPT" | "REJECT" | "-")
            && matches!(record[13], "OK" | "NODATA" | "SKIPDATA")
    })
}

pub fn sniff(head: &str) -> bool {
    let Some(first) = head.lines().find(|line| !line.trim().is_empty()) else {
        return false;
    };
    let tokens: Vec<&str> = first.split_whitespace().collect();
    is_header(&tokens) || standard_start(&tokens).is_some()
}

/// Field names as the user gave them: separated by spaces or commas, with or
/// without the `${...}` of the flow log's format string.
pub fn field_names(given: &[String]) -> Result<Vec<String>, String> {
    let names: Vec<String> = given
        .iter()
        .flat_map(|part| part.split([' ', ',']))
        .map(|name| {
            name.trim_start_matches("${")
                .trim_end_matches('}')
                .to_string()
        })
        .filter(|name| !name.is_empty())
        .collect();
    let named: Vec<&str> = names.iter().map(String::as_str).collect();
    if is_header(&named) {
        Ok(names)
    } else {
        Err(format!(
            "--fields must name at least: {}",
            REQUIRED.join(", ")
        ))
    }
}

/// Read flow records. `fields` names the fields of a custom format that has
/// no header line; leave it empty otherwise.
pub fn parse(
    reader: &mut dyn BufRead,
    fields: &[String],
    notes: &mut Notes,
    emit: &mut dyn FnMut(Flow),
) -> io::Result<()> {
    // The fields of a header line or of --fields, once either is known.
    let mut named: Option<Vec<String>> = (!fields.is_empty()).then(|| fields.to_vec());
    for_each_line(reader, |line| {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            return;
        }
        if is_header(&tokens) {
            named = Some(tokens.iter().map(|t| t.to_string()).collect());
            return;
        }
        let (names, values): (Vec<&str>, &[&str]) = match &named {
            Some(names) if names.len() == tokens.len() => {
                (names.iter().map(String::as_str).collect(), &tokens)
            }
            Some(_) => {
                notes.add("skipped a flow record with an unexpected number of fields");
                return;
            }
            None => match standard_start(&tokens) {
                Some(start) => (STANDARD_FIELDS.to_vec(), &tokens[start..]),
                None => {
                    notes.add(
                        "skipped a flow record that is not in AWS's field order; \
                         name a custom format's fields with --fields",
                    );
                    return;
                }
            },
        };
        let field = |name: &str| {
            let index = names.iter().position(|field| *field == name)?;
            values.get(index).copied()
        };
        if field("log-status").unwrap_or("OK") != "OK" {
            return; // NODATA and SKIPDATA records describe no traffic
        }
        match flow(&field) {
            Some(flow) => emit(flow),
            None => notes.add("skipped an unreadable flow record"),
        }
    })
}

fn flow<'a>(field: &dyn Fn(&str) -> Option<&'a str>) -> Option<Flow> {
    let proto: u8 = field("protocol")?.parse().ok()?;
    let start = match field("start") {
        None | Some("-") => 0.0,
        Some(start) => start.parse().ok()?,
    };
    let (src, dst) = (
        field("srcaddr")?.parse().ok()?,
        field("dstaddr")?.parse().ok()?,
    );
    Some(Flow {
        subject: match field("interface-id") {
            None | Some("-") => "all flows".to_string(),
            Some(interface) => interface.to_string(),
        },
        proto,
        src,
        sport: field("srcport")?.parse().ok()?,
        dst,
        dport: field("dstport")?.parse().ok()?,
        accepted: field("action").unwrap_or("ACCEPT") == "ACCEPT",
        start,
        initiator: initiator(proto, field("tcp-flags")),
        // A record is captured on its way into or out of the interface,
        // which says which end the interface is.
        local: match field("flow-direction") {
            Some("ingress") => Some(dst),
            Some("egress") => Some(src),
            _ => None,
        },
    })
}

/// Flow logs record SYN (2) for the side that opened a TCP connection and
/// SYN-ACK (18) for the side that answered; bare ACKs are never recorded, so
/// the two cannot be confused. Later aggregation windows of a long-lived
/// connection carry neither.
fn initiator(proto: u8, flags: Option<&str>) -> Option<bool> {
    if proto != 6 {
        return None;
    }
    let flags: u8 = flags?.parse().ok()?;
    match flags & (SYN | ACK) {
        SYN => Some(true),
        bits if bits == SYN | ACK => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_with(text: &str, fields: &[String]) -> (Vec<Flow>, Notes) {
        let (mut flows, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), fields, &mut notes, &mut |flow| {
            flows.push(flow)
        })
        .unwrap();
        (flows, notes)
    }

    fn parse_text(text: &str) -> (Vec<Flow>, Notes) {
        parse_with(text, &[])
    }

    #[test]
    fn default_format_and_noise() {
        let text = "\
2 1111 eni-1 203.0.113.7 10.0.1.5 51734 443 6 12 4800 1730462400 1730462460 ACCEPT OK
2 1111 eni-1 192.0.2.6 10.0.1.5 51734 22 6 1 40 1730462400 1730462460 REJECT OK
2 1111 eni-1 - - - - - - - 1730462460 1730462520 - NODATA
2026-11-01T00:00:00Z 2 1111 eni-1 10.0.1.5 10.0.2.9 4000 53 17 1 40 1 2 ACCEPT OK
2 1111 eni-1 not-an-ip 10.0.1.5 1 2 6 1 40 1 2 ACCEPT OK
garbage line
";
        assert!(sniff(text));
        let (flows, notes) = parse_text(text);
        let seen: Vec<(String, u16, u8, bool)> = flows
            .iter()
            .map(|f| (f.src.to_string(), f.dport, f.proto, f.accepted))
            .collect();
        assert_eq!(
            seen,
            [
                ("203.0.113.7".to_string(), 443, 6, true),
                ("192.0.2.6".to_string(), 22, 6, false),
                ("10.0.1.5".to_string(), 53, 17, true),
            ]
        );
        assert_eq!(flows[0].subject, "eni-1");
        assert_eq!(flows[0].start, 1730462400.0);
        assert!(
            flows
                .iter()
                .all(|f| f.local.is_none() && f.initiator.is_none())
        );
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn custom_format_with_tcp_flags() {
        let text = "\
interface-id srcaddr dstaddr srcport dstport protocol tcp-flags action
eni-1 10.0.2.10 10.0.1.5 900 40000 6 2 ACCEPT
eni-1 10.0.1.5 10.0.2.10 40000 900 6 19 ACCEPT
eni-1 10.0.1.5 10.0.2.10 40000 900 6 1 ACCEPT
eni-1 10.0.1.5 10.0.2.10 40000 900 17 - ACCEPT
eni-1 10.0.1.5 10.0.2.10 40000 900
";
        assert!(sniff(text));
        let (flows, notes) = parse_text(text);
        let initiators: Vec<Option<bool>> = flows.iter().map(|f| f.initiator).collect();
        assert_eq!(initiators, [Some(true), Some(false), None, None]);
        assert_eq!(notes.len(), 1); // the short record
    }

    #[test]
    fn all_fields_in_aws_order_need_no_header() {
        // Version 5 with every field, then version 8 from a task with no
        // interface of its own, then a record with a timestamp in front.
        let text = "\
5 1111 eni-1 203.0.113.7 10.0.1.5 51734 443 6 12 4800 1730462400 1730462460 ACCEPT OK vpc-1 subnet-1 i-1 2 IPv4 203.0.113.7 10.0.1.5 us-east-1 use1-az5 - - - - ingress 1
5 1111 eni-1 10.0.1.5 203.0.113.7 443 51734 6 10 9100 1730462400 1730462460 ACCEPT OK vpc-1 subnet-1 i-1 18 IPv4 10.0.1.5 203.0.113.7 us-east-1 use1-az5 - - - - egress 1
8 1111 - 10.0.1.9 10.0.2.10 48000 5432 6 4 400 1730462400 1730462460 ACCEPT OK - - - - - - - - - - - - - egress - arn:aws:ecs:us-east-1:1111:cluster/c c arn:i i c1 - svc arn:td arn:task t1 -
1730462460000 5 1111 eni-1 10.0.1.5 10.0.0.2 39001 53 17 1 70 1730462400 1730462460 ACCEPT OK vpc-1 subnet-1 i-1 0 IPv4 10.0.1.5 10.0.0.2 us-east-1 use1-az5 - - - - egress 1
";
        assert!(sniff(text));
        let (flows, notes) = parse_text(text);
        assert!(notes.is_empty());
        let seen: Vec<(&str, u16, Option<bool>, String)> = flows
            .iter()
            .map(|f| {
                (
                    f.subject.as_str(),
                    f.dport,
                    f.initiator,
                    f.local.unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("eni-1", 443, Some(true), "10.0.1.5".to_string()),
                ("eni-1", 51734, Some(false), "10.0.1.5".to_string()),
                ("all flows", 5432, None, "10.0.1.9".to_string()),
                ("eni-1", 53, None, "10.0.1.5".to_string()),
            ]
        );
    }

    #[test]
    fn a_custom_order_without_a_header_needs_its_fields_named() {
        let text = "\
3 vpc-1 eni-1 IPv4 203.0.113.7 10.0.1.5 43416 5001 6 ACCEPT 2 OK
3 vpc-1 eni-1 - - - - - - - - NODATA
";
        assert!(!sniff(text));
        let (flows, notes) = parse_text(text);
        assert!(flows.is_empty());
        let notes: Vec<(&str, u64)> = notes.iter().collect();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].0.contains("--fields") && notes[0].1 == 2);

        let format = "${version} ${vpc-id} ${interface-id} ${type} ${srcaddr} ${dstaddr} \
                      ${srcport} ${dstport} ${protocol} ${action} ${tcp-flags} ${log-status}";
        let fields = field_names(&[format.to_string()]).unwrap();
        assert_eq!(fields.len(), 12);
        let (flows, notes) = parse_with(text, &fields);
        assert!(notes.is_empty());
        assert_eq!(flows.len(), 1);
        assert_eq!((flows[0].subject.as_str(), flows[0].dport), ("eni-1", 5001));
        assert_eq!(flows[0].initiator, Some(true));

        assert_eq!(
            field_names(&["srcaddr,dstaddr".to_string()]).unwrap_err(),
            "--fields must name at least: srcaddr, dstaddr, srcport, dstport, protocol"
        );
    }
}
