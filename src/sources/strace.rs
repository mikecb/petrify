//! strace output -> [`Syscall`].
//!
//! Understands the prefixes strace adds for `-f` (pid) and `-t`/`-tt`/`-ttt`/
//! `-r` (timestamps), and the split `<unfinished ...>` / `<... resumed>`
//! lines that appear when threads interleave.

use std::io::{self, BufRead};
use std::sync::LazyLock;

use regex::Regex;

use crate::events::{Detail, Notes, Syscall};
use crate::inputs::for_each_line;

const PREFIX: &str = r"^\s*(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:\d[\d:.]*\s+)?";

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
}

static CALL: LazyLock<Regex> =
    LazyLock::new(|| regex(&format!(r"{PREFIX}([a-z_][a-z0-9_]*)\((.*)$")));
/// Lines that are part of a trace without starting a syscall.
static NOISE: LazyLock<Regex> = LazyLock::new(|| {
    regex(&format!(
        r"{PREFIX}(?:<\.\.\. \w+ resumed>|\+\+\+ |--- |\) +=|strace: )"
    ))
});
static RESULT: LazyLock<Regex> = LazyLock::new(|| regex(r"\)\s+= |<unfinished \.\.\.>"));
static FAILED: LazyLock<Regex> = LazyLock::new(|| regex(r"\)\s+= -1 E\w+"));
static QUOTED: LazyLock<Regex> = LazyLock::new(|| regex(r#""((?:[^"\\]|\\.)*)""#));
static INET: LazyLock<Regex> =
    LazyLock::new(|| regex(r#"sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)"#));
static INET6: LazyLock<Regex> =
    LazyLock::new(|| regex(r#"sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)""#));
static UNIX: LazyLock<Regex> = LazyLock::new(|| regex(r#"sun_path=@?"([^"]+)""#));

pub fn sniff(head: &str) -> bool {
    let lines: Vec<&str> = head
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(20)
        .collect();
    let hits = lines
        .iter()
        .filter(|line| CALL.is_match(line) && RESULT.is_match(line))
        .count();
    hits > 0 && hits >= lines.len() / 2
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(Syscall),
) -> io::Result<()> {
    // The trace is named after the program it started with, so it lines up
    // with the `exe=` of audit records for the same program.
    let mut subject: Option<String> = None;
    for_each_line(reader, |line| {
        let Some(call) = CALL.captures(line) else {
            if !line.trim().is_empty() && !NOISE.is_match(line) {
                notes.add("skipped a line that does not look like strace output");
            }
            return;
        };
        let (name, rest) = (&call[1], &call[2]);
        if name.starts_with("syscall_") {
            notes.add(format!(
                "strace could not name {name}; add it with --allow if it is needed"
            ));
            return;
        }
        // A failed call was still attempted, so it counts; its arguments
        // just say nothing about what the program really touches.
        let detail = if FAILED.is_match(rest) {
            None
        } else {
            detail(name, rest)
        };
        if let (None, Some((Detail::Exec, path))) = (&subject, &detail) {
            subject = Some(path.clone());
        }
        emit(Syscall {
            subject: subject.clone().unwrap_or_else(|| "strace".to_string()),
            name: name.to_string(),
            arch: None,
            detail,
        });
    })
}

fn detail(name: &str, rest: &str) -> Option<(Detail, String)> {
    let first_string = || QUOTED.captures(rest).map(|found| found[1].to_string());
    match name {
        "execve" | "execveat" => Some((Detail::Exec, first_string()?)),
        "open" | "openat" | "openat2" | "creat" => {
            let writes = name == "creat"
                || ["O_WRONLY", "O_RDWR", "O_CREAT"]
                    .iter()
                    .any(|flag| rest.contains(flag));
            Some((
                if writes { Detail::Write } else { Detail::Read },
                first_string()?,
            ))
        }
        "connect" | "bind" => {
            let kind = if name == "bind" {
                Detail::Bind
            } else {
                Detail::Connect
            };
            let address = if let Some(v4) = INET.captures(rest) {
                format!("{}:{}", &v4[2], &v4[1])
            } else if let Some(v6) = INET6.captures(rest) {
                format!("[{}]:{}", &v6[2], &v6[1])
            } else {
                format!("unix:{}", &UNIX.captures(rest)?[1])
            };
            Some((kind, address))
        }
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

    fn names(calls: &[Syscall]) -> Vec<&str> {
        calls.iter().map(|call| call.name.as_str()).collect()
    }

    #[test]
    fn prefixes_and_split_lines() {
        let text = r#"execve("/bin/app", ["app"], 0x7ffd /* 3 vars */) = 0
[pid  4022] 12:00:01.123456 read(3,  <unfinished ...>
[pid  4021] 12:00:01.123460 futex(0x7f, FUTEX_WAIT, 0, NULL) = 0
[pid  4022] 12:00:01.123470 <... read resumed>"x", 1) = 1
4021 1730462400.000001 pread64(3, "", 10, 0) = 0
     0.000042 rt_sigreturn({mask=[]}) = 0
--- SIGCHLD {si_signo=SIGCHLD} ---
+++ exited with 0 +++
"#;
        assert!(sniff(text));
        let (calls, notes) = parse_text(text);
        assert_eq!(
            names(&calls),
            ["execve", "read", "futex", "pread64", "rt_sigreturn"]
        );
        assert!(notes.is_empty());
        assert!(calls.iter().all(|call| call.subject == "/bin/app"));
    }

    #[test]
    fn details_skip_failed_calls() {
        let text = r#"execve("/nope/app", ["app"], 0x7ffd) = -1 ENOENT (No such file or directory)
execve("/bin/app", ["app"], 0x7ffd) = 0
openat(AT_FDCWD, "/etc/app.conf", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/etc/absent", O_RDONLY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/var/lib/app/db", O_RDWR|O_CREAT, 0600) = 4
bind(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = 0
connect(6, {sa_family=AF_UNIX, sun_path="/run/app.sock"}, 110) = 0
"#;
        let (calls, _) = parse_text(text);
        let details: Vec<Option<(Detail, &str)>> = calls
            .iter()
            .map(|call| {
                call.detail
                    .as_ref()
                    .map(|(kind, value)| (*kind, value.as_str()))
            })
            .collect();
        assert_eq!(
            details,
            [
                None,
                Some((Detail::Exec, "/bin/app")),
                Some((Detail::Read, "/etc/app.conf")),
                None,
                Some((Detail::Write, "/var/lib/app/db")),
                Some((Detail::Bind, "0.0.0.0:8080")),
                Some((Detail::Connect, "[2001:db8::1]:443")),
                Some((Detail::Connect, "unix:/run/app.sock")),
            ]
        );
        assert_eq!(calls[0].name, "execve");
        assert_eq!(calls[0].subject, "strace");
        assert_eq!(calls[7].subject, "/bin/app");
    }

    #[test]
    fn unreadable_lines_are_reported() {
        let (calls, notes) = parse_text("read(3, \"\", 1) = 0\nsyscall_0x1c8(0x1) = 0\nwhat?\n");
        assert_eq!(names(&calls), ["read"]);
        assert_eq!(notes.len(), 2);
    }
}
