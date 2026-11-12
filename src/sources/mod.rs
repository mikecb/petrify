//! Log sources. Each module turns one log format into normalised events.
//!
//! A source module provides `sniff(head) -> bool` (does this text look like
//! my format?) and `parse(reader, notes, emit)`, which calls `emit` for each
//! event and reports lines it had to skip through `notes`.
//!
//! Adding a format means adding a module, a [`Format`] variant, and an arm
//! in `Collector::feed` (see `cli.rs`).

pub mod auditd;
pub mod aws_flow;
pub mod azure_activity;
pub mod azure_flow;
pub mod cloudtrail;
pub mod gcp_audit;
pub mod gcp_flow;
pub mod netflow;
pub mod strace;

use std::io::{self, BufRead};

use serde_json::Value;

use crate::events::{Notes, Provider};

/// The behaviour model a format's events feed, and so the policies it can
/// lead to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// API calls, in one cloud's permission vocabulary.
    Api(Provider),
    Network,
    Syscall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Format {
    Cloudtrail,
    #[value(alias = "vpcflow")]
    AwsFlow,
    GcpAudit,
    GcpFlow,
    AzureActivity,
    AzureFlow,
    Netflow,
    Strace,
    Auditd,
}

impl Format {
    /// Sniffed in this order, most distinctive format first.
    const ALL: [Format; 9] = [
        Format::Cloudtrail,
        Format::GcpAudit,
        Format::GcpFlow,
        Format::AzureFlow,
        Format::AzureActivity,
        Format::Auditd,
        Format::AwsFlow,
        Format::Netflow,
        Format::Strace,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Format::Cloudtrail => "cloudtrail",
            Format::AwsFlow => "aws-flow",
            Format::GcpAudit => "gcp-audit",
            Format::GcpFlow => "gcp-flow",
            Format::AzureActivity => "azure-activity",
            Format::AzureFlow => "azure-flow",
            Format::Netflow => "netflow",
            Format::Strace => "strace",
            Format::Auditd => "auditd",
        }
    }

    pub fn kind(self) -> Kind {
        match self {
            Format::Cloudtrail => Kind::Api(Provider::Aws),
            Format::GcpAudit => Kind::Api(Provider::Gcp),
            Format::AzureActivity => Kind::Api(Provider::Azure),
            Format::AwsFlow | Format::GcpFlow | Format::AzureFlow | Format::Netflow => {
                Kind::Network
            }
            Format::Auditd | Format::Strace => Kind::Syscall,
        }
    }

    fn sniff(self, head: &str) -> bool {
        match self {
            Format::Cloudtrail => cloudtrail::sniff(head),
            Format::AwsFlow => aws_flow::sniff(head),
            Format::GcpAudit => gcp_audit::sniff(head),
            Format::GcpFlow => gcp_flow::sniff(head),
            Format::AzureActivity => azure_activity::sniff(head),
            Format::AzureFlow => azure_flow::sniff(head),
            Format::Netflow => netflow::sniff(head),
            Format::Strace => strace::sniff(head),
            Format::Auditd => auditd::sniff(head),
        }
    }

    /// The first format whose sniffer accepts this text.
    pub fn detect(head: &str) -> Option<Format> {
        Format::ALL.into_iter().find(|format| format.sniff(head))
    }
}

/// The JSON documents in a log: the whole text if it is one document, else
/// one per line (JSON Lines, as log sinks and exports to storage write).
pub(crate) fn json_documents(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
) -> io::Result<Vec<Value>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    if let Ok(document) = serde_json::from_str::<Value>(&text) {
        return Ok(vec![document]);
    }
    let mut documents = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<Value>(line) {
            Ok(document) => documents.push(document),
            Err(_) => notes.add("skipped a line that is not valid JSON"),
        }
    }
    Ok(documents)
}

/// A non-empty string field of a JSON object.
pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Seconds since the epoch, from a number or `YYYY-MM-DD HH:MM:SS[.fff]`
/// (with a space or `T`, and an optional `Z`). Only used to order flows, so
/// time zones do not matter.
pub(crate) fn timestamp(text: &str) -> Option<f64> {
    if let Ok(number) = text.parse::<f64>() {
        return Some(number);
    }
    let (date, time) = text.split_once([' ', 'T'])?;
    let mut date = date.split('-').map(|part| part.parse::<i64>().ok());
    let (year, month, day) = (date.next()??, date.next()??, date.next()??);
    let mut time = time
        .trim_end_matches('Z')
        .split(':')
        .map(|part| part.parse::<f64>().ok());
    let (hour, minute, second) = (
        time.next()??,
        time.next()??,
        time.next().flatten().unwrap_or(0.0),
    );

    // Days since 1970-01-01 (Howard Hinnant's days_from_civil).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days as f64 * 86_400.0 + hour * 3600.0 + minute * 60.0 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn each_fixture_is_detected_as_its_own_format() {
        for (name, format) in [
            ("cloudtrail.json", Format::Cloudtrail),
            ("aws-flow.log", Format::AwsFlow),
            ("gcp-audit.json", Format::GcpAudit),
            ("gcp-flow.jsonl", Format::GcpFlow),
            ("azure-activity.json", Format::AzureActivity),
            ("azure-flow.json", Format::AzureFlow),
            ("azure-nsg-flow.json", Format::AzureFlow),
            ("netflow.csv", Format::Netflow),
            ("strace.log", Format::Strace),
            ("audit.log", Format::Auditd),
        ] {
            assert_eq!(Format::detect(&fixture(name)), Some(format), "{name}");
        }
        assert_eq!(Format::detect("hello world\n"), None);
        assert_eq!(Format::detect("a,b,c\n1,2,3\n"), None);
        assert_eq!(Format::detect("{\"some\": \"json\"}\n"), None);
    }

    #[test]
    fn json_documents_reads_one_document_or_one_per_line() {
        let read = |text: &str| {
            let mut notes = Notes::default();
            let documents = json_documents(&mut text.as_bytes(), &mut notes).unwrap();
            (documents.len(), notes.len())
        };
        assert_eq!(read("[{\"a\": 1},\n {\"a\": 2}]"), (1, 0));
        assert_eq!(read("{\"a\": 1}\n{\"a\": 2}\n\nnot json\n"), (2, 1));
    }

    #[test]
    fn timestamps_order_correctly() {
        assert_eq!(timestamp("1970-01-01 00:00:00"), Some(0.0));
        assert_eq!(timestamp("2026-11-01T12:00:00Z"), Some(1_793_534_400.0));
        assert_eq!(timestamp("2026-11-01 12:00:00.250"), Some(1_793_534_400.25));
        assert!(timestamp("2019-06-14T03:45:37.186193305Z") < timestamp("2019-06-14T03:45:37.3Z"));
        assert!(timestamp("2024-02-29 00:00:00") < timestamp("2024-03-01 00:00:00"));
        assert_eq!(timestamp("yesterday"), None);
    }
}
