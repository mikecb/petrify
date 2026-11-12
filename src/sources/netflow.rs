//! Generic flow CSV -> [`Flow`].
//!
//! Any CSV with a header row naming source/destination address and port and
//! the protocol works: `nfdump -o csv`, SiLK and Zeek exports, a spreadsheet.
//! Column names are matched loosely against the aliases below.

use std::io::{self, BufRead};

use csv::{ReaderBuilder, StringRecord};

use crate::events::{Flow, Notes};

const SRC: &[&str] = &[
    "sa",
    "src",
    "srcaddr",
    "src_addr",
    "srcip",
    "src_ip",
    "source",
    "ipv4_src_addr",
];
const DST: &[&str] = &[
    "da",
    "dst",
    "dstaddr",
    "dst_addr",
    "dstip",
    "dst_ip",
    "destination",
    "ipv4_dst_addr",
];
const SPORT: &[&str] = &["sp", "sport", "srcport", "src_port", "l4_src_port"];
const DPORT: &[&str] = &["dp", "dport", "dstport", "dst_port", "l4_dst_port"];
const PROTO: &[&str] = &["pr", "proto", "protocol"];
const START: &[&str] = &["ts", "start", "first", "start_time", "timestamp"];
const ACTION: &[&str] = &["action"];

/// Where each field lives in a row.
struct Columns {
    src: usize,
    dst: usize,
    dport: usize,
    proto: usize,
    sport: Option<usize>,
    start: Option<usize>,
    action: Option<usize>,
}

impl Columns {
    fn find(header: &StringRecord) -> Option<Columns> {
        let names: Vec<String> = header
            .iter()
            .map(|h| h.trim().to_lowercase().replace(['-', ' '], "_"))
            .collect();
        let column = |aliases: &[&str]| {
            aliases
                .iter()
                .find_map(|alias| names.iter().position(|name| name == alias))
        };
        Some(Columns {
            src: column(SRC)?,
            dst: column(DST)?,
            dport: column(DPORT)?,
            proto: column(PROTO)?,
            sport: column(SPORT),
            start: column(START),
            action: column(ACTION),
        })
    }
}

fn rows(reader: impl io::Read) -> csv::Reader<impl io::Read> {
    ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(reader)
}

pub fn sniff(head: &str) -> bool {
    let first = head
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let header = rows(first.as_bytes()).records().next();
    first.contains(',') && matches!(header, Some(Ok(header)) if Columns::find(&header).is_some())
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(Flow),
) -> io::Result<()> {
    let mut columns = None;
    for row in rows(reader).records() {
        let row = match row {
            Ok(row) => row,
            Err(error) => match error.into_kind() {
                csv::ErrorKind::Io(error) => return Err(error),
                _ => {
                    notes.add("skipped a CSV row that could not be read");
                    continue;
                }
            },
        };
        let Some(columns) = &columns else {
            columns = Columns::find(&row);
            if columns.is_none() {
                notes.add("CSV header does not name source, destination, port and protocol");
                return Ok(());
            }
            continue;
        };
        match flow(&row, columns) {
            Some(flow) => emit(flow),
            // nfdump ends its CSV with a summary block; that lands here too.
            None => notes.add("skipped a CSV row that is not a flow record"),
        }
    }
    Ok(())
}

fn flow(row: &StringRecord, columns: &Columns) -> Option<Flow> {
    let cell = |index: usize| row.get(index).map(str::trim);
    let proto = protocol(cell(columns.proto)?)?;
    let ported = matches!(proto, 6 | 17 | 132);
    // Some exporters print ports as floats, or pack ICMP type.code into them.
    let port = |index: Option<usize>| -> Option<u16> {
        match index.and_then(cell) {
            Some(text) if ported && !text.is_empty() => Some(text.parse::<f64>().ok()? as u16),
            _ => Some(0),
        }
    };
    let action = columns
        .action
        .and_then(cell)
        .unwrap_or("ACCEPT")
        .to_uppercase();
    Some(Flow {
        subject: "all flows".to_string(),
        proto,
        src: cell(columns.src)?.parse().ok()?,
        sport: port(columns.sport)?,
        dst: cell(columns.dst)?.parse().ok()?,
        dport: port(Some(columns.dport))?,
        accepted: !matches!(action.as_str(), "REJECT" | "DENY" | "DROP"),
        start: columns
            .start
            .and_then(cell)
            .and_then(timestamp)
            .unwrap_or(0.0),
        initiator: None,
    })
}

fn protocol(text: &str) -> Option<u8> {
    Some(match text.to_lowercase().as_str() {
        "icmp" => 1,
        "tcp" => 6,
        "udp" => 17,
        "gre" => 47,
        "esp" => 50,
        "icmp6" | "icmpv6" | "ipv6-icmp" => 58,
        "sctp" => 132,
        number => number.parse().ok()?,
    })
}

/// Seconds since the epoch, from a number or `YYYY-MM-DD HH:MM:SS[.fff]`.
/// Only used to order flows, so time zones do not matter.
fn timestamp(text: &str) -> Option<f64> {
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

    fn parse_text(text: &str) -> (Vec<Flow>, Notes) {
        let (mut flows, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), &mut notes, &mut |flow| {
            flows.push(flow)
        })
        .unwrap();
        (flows, notes)
    }

    #[test]
    fn columns_are_matched_by_alias() {
        let text = "\
Src IP,Dst IP,Src Port,Dst Port,Protocol,Timestamp
192.168.1.50,93.184.216.34,40222,443,6,1730462400.5
192.168.1.50,192.168.1.1,0,3.1,icmp,2026-11-01 12:00:00
total,,,,,
";
        assert!(sniff(text));
        let (flows, notes) = parse_text(text);
        let seen: Vec<(u8, u16)> = flows.iter().map(|f| (f.proto, f.dport)).collect();
        assert_eq!(seen, [(6, 443), (1, 0)]);
        assert!(flows[1].start > flows[0].start);
        assert_eq!(notes.len(), 1);
        assert!(!sniff("a,b,c\n1,2,3\n"));
    }

    #[test]
    fn timestamps_order_correctly() {
        assert_eq!(timestamp("1970-01-01 00:00:00"), Some(0.0));
        assert_eq!(timestamp("2026-11-01T12:00:00Z"), Some(1_793_534_400.0));
        assert_eq!(timestamp("2026-11-01 12:00:00.250"), Some(1_793_534_400.25));
        assert!(timestamp("2024-02-29 00:00:00") < timestamp("2024-03-01 00:00:00"));
        assert_eq!(timestamp("yesterday"), None);
    }
}
