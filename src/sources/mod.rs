//! Log sources. Each module turns one log format into normalised events.
//!
//! A source module provides `sniff(head) -> bool` (does this text look like
//! my format?) and `parse(reader, notes, emit)`, which calls `emit` for each
//! event and reports lines it had to skip through `notes`.
//!
//! Adding a format means adding a module, a [`Format`] variant, and an arm
//! in `Collector::feed` (see `cli.rs`).

pub mod auditd;
pub mod cloudtrail;
pub mod netflow;
pub mod strace;
pub mod vpcflow;

/// The behaviour model a format's events feed, and so the policy it leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Api,
    Network,
    Syscall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Format {
    Cloudtrail,
    Auditd,
    Vpcflow,
    Netflow,
    Strace,
}

impl Format {
    /// Sniffed in this order, most distinctive format first.
    const ALL: [Format; 5] = [
        Format::Cloudtrail,
        Format::Auditd,
        Format::Vpcflow,
        Format::Netflow,
        Format::Strace,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Format::Cloudtrail => "cloudtrail",
            Format::Auditd => "auditd",
            Format::Vpcflow => "vpcflow",
            Format::Netflow => "netflow",
            Format::Strace => "strace",
        }
    }

    pub fn kind(self) -> Kind {
        match self {
            Format::Cloudtrail => Kind::Api,
            Format::Vpcflow | Format::Netflow => Kind::Network,
            Format::Auditd | Format::Strace => Kind::Syscall,
        }
    }

    fn sniff(self, head: &str) -> bool {
        match self {
            Format::Cloudtrail => cloudtrail::sniff(head),
            Format::Auditd => auditd::sniff(head),
            Format::Vpcflow => vpcflow::sniff(head),
            Format::Netflow => netflow::sniff(head),
            Format::Strace => strace::sniff(head),
        }
    }

    /// The first format whose sniffer accepts this text.
    pub fn detect(head: &str) -> Option<Format> {
        Format::ALL.into_iter().find(|format| format.sniff(head))
    }
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
        assert_eq!(
            Format::detect(&fixture("cloudtrail.json")),
            Some(Format::Cloudtrail)
        );
        assert_eq!(Format::detect(&fixture("audit.log")), Some(Format::Auditd));
        assert_eq!(
            Format::detect(&fixture("vpcflow.log")),
            Some(Format::Vpcflow)
        );
        assert_eq!(
            Format::detect(&fixture("netflow.csv")),
            Some(Format::Netflow)
        );
        assert_eq!(Format::detect(&fixture("strace.log")), Some(Format::Strace));
        assert_eq!(Format::detect("hello world\n"), None);
        assert_eq!(Format::detect("a,b,c\n1,2,3\n"), None);
    }
}
