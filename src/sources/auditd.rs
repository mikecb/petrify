//! Linux audit records -> [`Syscall`].
//!
//! Reads `type=SYSCALL` records (audit rules) and `type=SECCOMP` records
//! (what a seccomp profile with `SCMP_ACT_LOG`, or a blocking one, writes).
//! The second is what makes the tighten-run-repeat loop work: feed the audit
//! log from a trial run back in alongside the original trace.
//!
//! Works on `/var/log/audit/audit.log` in raw or enriched form, `ausearch -i`
//! output, and the `audit: type=1326 ...` lines found in dmesg and the
//! journal.

use std::collections::HashMap;
use std::io::{self, BufRead};
use std::sync::LazyLock;

use regex::Regex;

use crate::events::{Arch, Notes, Syscall};
use crate::inputs::for_each_line;
use crate::syscall_tables;

static RECORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btype=(SYSCALL|SECCOMP|1300|1326)\b").unwrap());
static FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(\w+)=("[^"]*"|\S+)"#).unwrap());
static ANY_RECORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\btype=\w+ .*audit\(").unwrap());

pub fn sniff(head: &str) -> bool {
    ANY_RECORD.is_match(head)
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(Syscall),
) -> io::Result<()> {
    let mut from_kernel_log = false;
    for_each_line(reader, |line| {
        let Some(record) = RECORD.captures(line) else {
            return; // PATH, CWD, PROCTITLE and friends
        };
        // Only the kernel log prints the record type as a number.
        from_kernel_log |= record[1].starts_with(|c: char| c.is_ascii_digit());

        // Enriched logs append interpreted copies of fields in upper case
        // (SYSCALL=openat) after a group separator; keys stay case-sensitive
        // so both forms coexist.
        let line = line.replace('\x1d', " ");
        let fields: HashMap<&str, &str> = FIELD
            .captures_iter(&line)
            .map(|field| {
                let (_, [key, value]) = field.extract();
                (key, value.trim_matches('"'))
            })
            .collect();

        let arch = fields
            .get("ARCH")
            .or(fields.get("arch"))
            .and_then(|arch| architecture(arch));
        let Some(raw) = fields.get("SYSCALL").or(fields.get("syscall")) else {
            return;
        };
        let name = match raw.parse::<u32>() {
            Err(_) => raw.to_string(),
            Ok(number) => match arch.and_then(|arch| syscall_tables::name(arch, number)) {
                Some(name) => name.to_string(),
                None => {
                    notes.add(format!(
                        "cannot name syscall {number} on arch {}; \
                         use an enriched audit log or `ausearch -i`",
                        fields.get("arch").unwrap_or(&"unknown"),
                    ));
                    return;
                }
            },
        };
        let subject = fields
            .get("exe")
            .or(fields.get("comm"))
            .unwrap_or(&"unknown");
        emit(Syscall {
            subject: subject.to_string(),
            name,
            arch,
            detail: None,
        });
    })?;
    if from_kernel_log {
        notes.add(
            "these audit records come from the kernel log, which keeps about 10 per 5 seconds \
             when auditd is not running; expect gaps, and repeat the run or start auditd",
        );
    }
    Ok(())
}

/// `arch=` as the kernel prints it (an AUDIT_ARCH_* constant in hex) or as
/// `ausearch -i` interprets it.
fn architecture(text: &str) -> Option<Arch> {
    match text.to_lowercase().as_str() {
        "c000003e" | "x86_64" => Some(Arch::X86_64),
        "c00000b7" | "aarch64" => Some(Arch::Aarch64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_text(text: &str) -> (Vec<Syscall>, Notes) {
        let (mut calls, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), &mut notes, &mut |call| {
            calls.push(call)
        })
        .unwrap();
        (calls, notes)
    }

    fn record(kind: &str, arch: &str, number: u32) -> String {
        format!(
            "type={kind} msg=audit(1730462400.1:1): arch={arch} syscall={number} \
             comm=\"app\" exe=\"/bin/app\"\n"
        )
    }

    #[test]
    fn numbers_are_named_per_architecture() {
        let text = record("SECCOMP", "c000003e", 41)
            + &record("SYSCALL", "c00000b7", 198)
            + &record("PATH", "c000003e", 1);
        assert!(sniff(&text));
        let (calls, notes) = parse_text(&text);
        let seen: Vec<(&str, Option<Arch>)> = calls
            .iter()
            .map(|call| (call.name.as_str(), call.arch))
            .collect();
        assert_eq!(
            seen,
            [
                ("socket", Some(Arch::X86_64)),
                ("socket", Some(Arch::Aarch64))
            ]
        );
        assert_eq!(calls[0].subject, "/bin/app");
        assert!(notes.is_empty());
    }

    #[test]
    fn enriched_and_interpreted_names_win() {
        let enriched = record("SYSCALL", "c000003e", 2).trim_end().to_string()
            + "\x1dARCH=x86_64 SYSCALL=open\n";
        let interpreted = "type=SYSCALL msg=audit(11/01/2026 12:00:00.1:2) : arch=x86_64 \
                           syscall=execve exe=/bin/app\n";
        let (calls, _) = parse_text(&(enriched + interpreted));
        let names: Vec<&str> = calls.iter().map(|call| call.name.as_str()).collect();
        assert_eq!(names, ["open", "execve"]);
        assert_eq!(calls[1].arch, Some(Arch::X86_64));
    }

    #[test]
    fn unknown_numbers_are_reported_not_guessed() {
        let text = record("SECCOMP", "c000003e", 99999) + &record("SECCOMP", "40000003", 5);
        let (calls, notes) = parse_text(&text);
        assert!(calls.is_empty());
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn kernel_log_records_parse_and_warn_about_rate_limiting() {
        // As printed by `journalctl -k` on a host without auditd.
        let line = "audit: type=1326 audit(1794507387.228:216): auid=4294967295 uid=0 gid=0 \
                    ses=4294967295 subj=runc pid=62077 comm=\"runc:[2:INIT]\" exe=\"/runc\" sig=0 \
                    arch=c000003e syscall=72 compat=0 ip=0x40f98e code=0x7ffc0000\n";
        assert!(sniff(line));
        let (calls, notes) = parse_text(&line.repeat(3));
        assert_eq!(calls.len(), 3);
        assert!(
            calls
                .iter()
                .all(|call| call.name == "fcntl" && call.subject == "/runc")
        );
        let notes: Vec<(&str, u64)> = notes.iter().collect();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].0.contains("auditd is not running"));
    }
}
