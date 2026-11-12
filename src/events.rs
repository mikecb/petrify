//! The normalised events every log source is reduced to.
//!
//! Each event carries a `subject`: whoever did the thing (an IAM principal, a
//! network interface, an executable). A policy only makes sense for one
//! subject at a time, so the CLI makes the user choose when a log has several.

use std::fmt;
use std::net::IpAddr;

/// A problem the user can fix; shown as a message, never a panic.
#[derive(Debug)]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error(error.to_string())
    }
}

/// The cloud whose permission vocabulary an API call is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Provider {
    Aws,
    Gcp,
    Azure,
}

/// One cloud API call, already translated to the provider's permission
/// vocabulary.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiCall {
    pub subject: String,
    /// The permission exercised, as the provider's policies name it:
    /// `s3:GetObject`, `storage.objects.get`,
    /// `Microsoft.Storage/storageAccounts/write`.
    pub action: String,
    /// What the call touched (ARNs, resource names, scopes), or `["*"]`
    /// when the log does not say.
    pub resources: Vec<String>,
    pub denied: bool,
}

/// One unidirectional flow record.
#[derive(Debug, Clone, PartialEq)]
pub struct Flow {
    pub subject: String,
    /// IP protocol number.
    pub proto: u8,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub accepted: bool,
    /// When the flow began. Only ever compared with other flows of one log.
    pub start: f64,
    /// `Some(true)` when the log knows `src` opened the conversation,
    /// `Some(false)` when it knows `src` is answering, `None` otherwise.
    pub initiator: Option<bool>,
    /// The end of the flow that is the subject's own address, when the log
    /// says which it is. Otherwise it is inferred from the subject's flows.
    pub local: Option<IpAddr>,
}

/// One system call.
#[derive(Debug, Clone, PartialEq)]
pub struct Syscall {
    pub subject: String,
    pub name: String,
    pub arch: Option<Arch>,
    /// What the call acted on, when the source decoded its arguments.
    pub detail: Option<(Detail, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Arch {
    #[value(name = "x86_64")]
    X86_64,
    #[value(name = "aarch64")]
    Aarch64,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        })
    }
}

/// Kinds of syscall detail, in the order `show` lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Detail {
    Exec,
    Connect,
    Bind,
    Write,
    Read,
}

/// Things worth telling the user that are not errors: skipped lines, guesses
/// made, limits exceeded. Sources report here instead of failing, so one
/// malformed record does not abandon a multi-gigabyte log. Repeats are
/// counted rather than repeated.
#[derive(Debug, Default)]
pub struct Notes(Vec<(String, u64)>);

impl Notes {
    pub fn add(&mut self, note: impl AsRef<str>) {
        let note = note.as_ref();
        match self.0.iter_mut().find(|(seen, _)| seen == note) {
            Some((_, count)) => *count += 1,
            None => self.0.push((note.to_string(), 1)),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> {
        self.0.iter().map(|(note, count)| (note.as_str(), *count))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
