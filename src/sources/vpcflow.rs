//! AWS VPC Flow Logs -> [`Flow`].
//!
//! Handles the default (version 2) format and any custom format that starts
//! with a header line naming its fields, which is how flow logs delivered to
//! S3 look.

use std::io::{self, BufRead};

use crate::events::{Flow, Notes};
use crate::inputs::for_each_line;

const DEFAULT_FIELDS: [&str; 14] = [
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
];
const REQUIRED: [&str; 5] = ["srcaddr", "dstaddr", "srcport", "dstport", "protocol"];

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

fn is_header(tokens: &[&str]) -> bool {
    REQUIRED.iter().all(|field| tokens.contains(field))
}

pub fn sniff(head: &str) -> bool {
    let Some(first) = head.lines().find(|line| !line.trim().is_empty()) else {
        return false;
    };
    let tokens: Vec<&str> = first.split_whitespace().collect();
    is_header(&tokens)
        || (tokens.len() >= DEFAULT_FIELDS.len()
            && matches!(tokens[tokens.len() - 2], "ACCEPT" | "REJECT" | "-")
            && matches!(tokens[tokens.len() - 1], "OK" | "NODATA" | "SKIPDATA"))
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(Flow),
) -> io::Result<()> {
    let mut fields: Vec<String> = DEFAULT_FIELDS.iter().map(|f| f.to_string()).collect();
    let mut headed = false;
    for_each_line(reader, |line| {
        let mut tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            return;
        }
        if is_header(&tokens) {
            fields = tokens.iter().map(|t| t.to_string()).collect();
            headed = true;
            return;
        }
        if !headed && tokens.len() > fields.len() {
            // CloudWatch Logs exports prefix each record with a timestamp.
            tokens.drain(..tokens.len() - fields.len());
        }
        if tokens.len() != fields.len() {
            notes.add("skipped a flow record with an unexpected number of fields");
            return;
        }
        let field = |name: &str| {
            fields
                .iter()
                .position(|f| f == name)
                .map(|index| tokens[index])
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
    Some(Flow {
        subject: field("interface-id").unwrap_or("all flows").to_string(),
        proto,
        src: field("srcaddr")?.parse().ok()?,
        sport: field("srcport")?.parse().ok()?,
        dst: field("dstaddr")?.parse().ok()?,
        dport: field("dstport")?.parse().ok()?,
        accepted: field("action").unwrap_or("ACCEPT") == "ACCEPT",
        start,
        initiator: initiator(proto, field("tcp-flags")),
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

    fn parse_text(text: &str) -> (Vec<Flow>, Notes) {
        let (mut flows, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), &mut notes, &mut |flow| {
            flows.push(flow)
        })
        .unwrap();
        (flows, notes)
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
";
        assert!(sniff(text));
        let (flows, notes) = parse_text(text);
        let initiators: Vec<Option<bool>> = flows.iter().map(|f| f.initiator).collect();
        assert_eq!(initiators, [Some(true), Some(false), None, None]);
        assert!(notes.is_empty());
    }
}
