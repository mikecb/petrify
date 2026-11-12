//! Command line: read logs, pick a subject, then describe or constrain it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;

use crate::events::{Arch, Error, Notes, Provider, Result};
use crate::inputs::expand;
use crate::sources::{
    Format, Kind, auditd, aws_flow, azure_activity, azure_flow, cloudtrail, gcp_audit, gcp_flow,
    netflow, strace,
};
use crate::syscalls::DefaultAction;
use crate::text::{commas, plural};
use crate::{cloud, network, syscalls};

#[derive(Parser)]
#[command(
    name = "petrify",
    version,
    about = "Turn what an application was observed doing into a policy that lets it do nothing else.",
    after_help = "Cloud audit logs (CloudTrail, GCP audit logs, the Azure Activity Log) become \
                  an IAM policy or role; flow logs become firewall rules; strace or audit logs \
                  become a seccomp profile. The format is detected."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Summarise the observed behaviour
    Show(Common),
    /// Write a policy allowing only the observed behaviour
    Generate(Generate),
}

#[derive(Args)]
struct Common {
    /// Log file or directory (gzip is fine); - for stdin
    #[arg(required = true, value_name = "LOG")]
    logs: Vec<String>,

    /// Log format, when detection gets it wrong
    #[arg(short, long, value_enum)]
    format: Option<Format>,

    /// Whose behaviour to use: a principal, an interface or VM, or an
    /// executable (substring, or a glob such as '*'; repeatable)
    #[arg(short, long, value_name = "PATTERN")]
    subject: Vec<String>,

    /// Flow logs: address range of the application itself, when it cannot be
    /// inferred (repeatable)
    #[arg(long, value_name = "CIDR")]
    local: Vec<String>,
}

#[derive(Args)]
struct Generate {
    #[command(flatten)]
    common: Common,

    /// Write here instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Policy to write, when it should not follow from the log: flow logs
    /// from one cloud can become another cloud's firewall rules
    #[arg(short, long, value_enum)]
    policy: Option<Policy>,

    /// Also grant calls that were denied while the log was recorded
    #[arg(long, help_heading = "IAM policies and roles (audit logs)")]
    include_denied: bool,

    /// Summarise resources by path prefix (AWS) or resource groups by
    /// subscription (Azure) beyond N
    #[arg(long, value_name = "N", default_value_t = 10, value_parser = at_least_one,
          help_heading = "IAM policies and roles (audit logs)")]
    max_resources: usize,

    /// Widen peer addresses into at most N CIDR ranges per rule
    #[arg(long, value_name = "N", default_value_t = 8, value_parser = at_least_one,
          help_heading = "Firewall rules (flow logs)")]
    max_peers: usize,

    /// What happens to unlisted syscalls; SCMP_ACT_LOG gives a dry run
    #[arg(
        long,
        value_enum,
        default_value = "SCMP_ACT_ERRNO",
        help_heading = "Seccomp profile (strace, audit)"
    )]
    default_action: DefaultAction,

    /// Architecture of the traced program
    #[arg(long, value_enum, help_heading = "Seccomp profile (strace, audit)")]
    arch: Option<Arch>,

    /// Extra syscalls to allow, such as those the container runtime needs
    #[arg(
        long,
        value_name = "SYSCALL[,...]",
        value_delimiter = ',',
        help_heading = "Seccomp profile (strace, audit)"
    )]
    allow: Vec<String>,
}

/// The documents petrify can write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Policy {
    AwsIam,
    GcpRole,
    AzureRole,
    AwsSecurityGroup,
    GcpFirewall,
    AzureNsg,
    Seccomp,
}

impl Policy {
    /// The policy a log leads to when none is asked for.
    fn default_for(format: Format) -> Policy {
        match format {
            Format::Cloudtrail => Policy::AwsIam,
            Format::GcpAudit => Policy::GcpRole,
            Format::AzureActivity => Policy::AzureRole,
            // A flow CSV has no cloud of its own; AWS was here first.
            Format::AwsFlow | Format::Netflow => Policy::AwsSecurityGroup,
            Format::GcpFlow => Policy::GcpFirewall,
            Format::AzureFlow => Policy::AzureNsg,
            Format::Strace | Format::Auditd => Policy::Seccomp,
        }
    }

    /// The kind of behaviour this policy is written from.
    fn kind(self) -> Kind {
        match self {
            Policy::AwsIam => Kind::Api(Provider::Aws),
            Policy::GcpRole => Kind::Api(Provider::Gcp),
            Policy::AzureRole => Kind::Api(Provider::Azure),
            Policy::AwsSecurityGroup | Policy::GcpFirewall | Policy::AzureNsg => Kind::Network,
            Policy::Seccomp => Kind::Syscall,
        }
    }

    /// What to call the document in messages.
    fn label(self) -> &'static str {
        match self {
            Policy::AwsIam => cloud::aws::POLICY_NAME,
            Policy::GcpRole => cloud::gcp::POLICY_NAME,
            Policy::AzureRole => cloud::azure::POLICY_NAME,
            Policy::AwsSecurityGroup => network::aws::POLICY_NAME,
            Policy::GcpFirewall => network::gcp::POLICY_NAME,
            Policy::AzureNsg => network::azure::POLICY_NAME,
            Policy::Seccomp => syscalls::POLICY_NAME,
        }
    }

    /// The name used on the command line.
    fn name(self) -> String {
        let value = self.to_possible_value().expect("no skipped variants");
        value.get_name().to_string()
    }
}

fn at_least_one(text: &str) -> std::result::Result<usize, String> {
    match text.parse() {
        Ok(number) if number >= 1 => Ok(number),
        _ => Err("must be a whole number, at least 1".to_string()),
    }
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut notes = Notes::default();
    let result = run(&cli.command, &mut notes);

    let mut stderr = io::stderr().lock();
    let code = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(stderr, "petrify: {error}");
            ExitCode::FAILURE
        }
    };
    for (note, count) in notes.iter() {
        let times = if count > 1 {
            format!(" (x{})", commas(count))
        } else {
            String::new()
        };
        let _ = writeln!(stderr, "petrify: note: {note}{times}");
    }
    code
}

fn run(command: &Command, notes: &mut Notes) -> Result<()> {
    let common = match command {
        Command::Show(common) => common,
        Command::Generate(generate) => &generate.common,
    };
    let (collector, first, formats) = collect(common, notes)?;
    let subjects = collector.subjects();
    if subjects.is_empty() {
        return Err(Error(
            "the log contains no events petrify can use".to_string(),
        ));
    }
    let noun = collector.subject_noun();

    let Some(chosen) = choose(subjects, &common.subject)? else {
        let listing = subject_table(subjects, noun);
        if matches!(command, Command::Generate(_)) {
            return Err(Error(format!(
                "a policy constrains one {noun}, and the log has several. \
                 Pick one with --subject (substring or glob; '*' for all):\n{listing}"
            )));
        }
        let count = plural(subjects.len() as u64, noun);
        return print(&format!(
            "The log covers {count}. Pick one with --subject:\n{listing}\n"
        ));
    };

    let events = plural(
        chosen
            .iter()
            .filter_map(|subject| subjects.get(subject))
            .sum(),
        "event",
    );
    let who = match chosen.as_slice() {
        [only] => only.clone(),
        many => plural(many.len() as u64, noun),
    };
    match command {
        Command::Show(_) => {
            let formats: Vec<&str> = formats.iter().map(|format| format.name()).collect();
            let description = collector.describe(&chosen, common)?;
            print(&format!(
                "{who}  ({events}, {})\n\n{description}\n",
                formats.join("/")
            ))
        }
        Command::Generate(options) => {
            let policy = options.policy.unwrap_or(Policy::default_for(first));
            let (document, warnings) = collector.policy(policy, &chosen, options)?;
            warnings.iter().for_each(|warning| notes.add(warning));
            let text = serde_json::to_string_pretty(&document).expect("JSON value") + "\n";
            let policy = policy.label();
            match &options.output {
                Some(path) => {
                    std::fs::write(path, text)
                        .map_err(|error| Error(format!("{}: {error}", path.display())))?;
                    eprintln!(
                        "petrify: wrote {policy} to {} for {who} from {events}",
                        path.display()
                    );
                }
                None => {
                    print(&text)?;
                    eprintln!("petrify: wrote {policy} for {who} from {events}");
                }
            }
            Ok(())
        }
    }
}

/// Write to stdout; a reader that stops early (`| head`) is not an error.
fn print(text: &str) -> Result<()> {
    match io::stdout().lock().write_all(text.as_bytes()) {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error.into()),
        _ => Ok(()),
    }
}

/// The behaviour model for one kind of log, holding everything seen so far.
enum Collector {
    Api(cloud::Collector),
    Network(network::Collector),
    Syscall(syscalls::Collector),
}

impl Collector {
    fn new(kind: Kind) -> Collector {
        match kind {
            Kind::Api(provider) => Collector::Api(cloud::Collector::new(provider)),
            Kind::Network => Collector::Network(Default::default()),
            Kind::Syscall => Collector::Syscall(Default::default()),
        }
    }

    fn kind(&self) -> Kind {
        match self {
            Collector::Api(c) => Kind::Api(c.provider()),
            Collector::Network(_) => Kind::Network,
            Collector::Syscall(_) => Kind::Syscall,
        }
    }

    /// Parse one input into this collector. The caller has checked that
    /// `format` produces this collector's kind of event.
    fn feed(
        &mut self,
        format: Format,
        reader: &mut dyn BufRead,
        notes: &mut Notes,
    ) -> io::Result<()> {
        match (self, format) {
            (Collector::Api(c), Format::Cloudtrail) => {
                cloudtrail::parse(reader, notes, &mut |event| c.add(event))
            }
            (Collector::Api(c), Format::GcpAudit) => {
                gcp_audit::parse(reader, notes, &mut |event| c.add(event))
            }
            (Collector::Api(c), Format::AzureActivity) => {
                azure_activity::parse(reader, notes, &mut |event| c.add(event))
            }
            (Collector::Network(c), Format::AwsFlow) => {
                aws_flow::parse(reader, notes, &mut |event| c.add(event))
            }
            (Collector::Network(c), Format::GcpFlow) => {
                gcp_flow::parse(reader, notes, &mut |event| c.add(event))
            }
            (Collector::Network(c), Format::AzureFlow) => {
                azure_flow::parse(reader, notes, &mut |event| c.add(event))
            }
            (Collector::Network(c), Format::Netflow) => {
                netflow::parse(reader, notes, &mut |event| c.add(event))
            }
            (Collector::Syscall(c), Format::Strace) => {
                strace::parse(reader, notes, &mut |event| c.add(event))
            }
            (Collector::Syscall(c), Format::Auditd) => {
                auditd::parse(reader, notes, &mut |event| c.add(event))
            }
            _ => unreachable!("format and collector kinds are matched before parsing"),
        }
    }

    fn subjects(&self) -> &BTreeMap<String, u64> {
        match self {
            Collector::Api(c) => c.subjects(),
            Collector::Network(c) => c.subjects(),
            Collector::Syscall(c) => c.subjects(),
        }
    }

    /// What a subject is called for this kind of log.
    fn subject_noun(&self) -> &'static str {
        match self {
            Collector::Api(_) => cloud::SUBJECT,
            Collector::Network(_) => network::SUBJECT,
            Collector::Syscall(_) => syscalls::SUBJECT,
        }
    }

    fn describe(&self, subjects: &[String], options: &Common) -> Result<String> {
        Ok(match self {
            Collector::Api(c) => cloud::describe(&c.behavior(subjects)),
            Collector::Network(c) => network::describe(&c.behavior(subjects, &options.local)?),
            Collector::Syscall(c) => syscalls::describe(&c.behavior(subjects)),
        })
    }

    fn policy(
        &self,
        policy: Policy,
        subjects: &[String],
        options: &Generate,
    ) -> Result<(Value, Vec<String>)> {
        if policy.kind() != self.kind() {
            let fitting: Vec<String> = Policy::value_variants()
                .iter()
                .filter(|candidate| candidate.kind() == self.kind())
                .map(|candidate| candidate.name())
                .collect();
            return Err(Error(format!(
                "--policy {} cannot be written from this log, which leads to: {}",
                policy.name(),
                fitting.join(", ")
            )));
        }
        match self {
            Collector::Api(c) => {
                let behavior = c.behavior(subjects);
                Ok(match policy {
                    Policy::GcpRole => cloud::gcp::policy(&behavior, options.include_denied),
                    Policy::AzureRole => cloud::azure::policy(&behavior, options.max_resources),
                    _ => {
                        cloud::aws::policy(&behavior, options.include_denied, options.max_resources)
                    }
                })
            }
            Collector::Network(c) => {
                let behavior = c.behavior(subjects, &options.common.local)?;
                Ok(match policy {
                    Policy::GcpFirewall => network::gcp::policy(&behavior, options.max_peers),
                    Policy::AzureNsg => network::azure::policy(&behavior, options.max_peers),
                    _ => network::aws::policy(&behavior, options.max_peers),
                })
            }
            Collector::Syscall(c) => syscalls::policy(
                &c.behavior(subjects),
                options.default_action,
                options.arch,
                &options.allow,
            ),
        }
    }
}

/// Parse every input into one collector. Inputs may mix formats (an strace
/// capture plus an audit log) but not kinds of behaviour. Also returns the
/// first format read, which decides the default policy, and all of them.
fn collect(options: &Common, notes: &mut Notes) -> Result<(Collector, Format, BTreeSet<Format>)> {
    let mut collector: Option<(Format, Collector)> = None;
    let mut formats = BTreeSet::new();
    for input in expand(&options.logs)? {
        let named = |error: io::Error| Error(format!("{}: {error}", input.name));
        let detected = match options.format {
            Some(format) => Some(format),
            None => Format::detect(&input.head().map_err(named)?),
        };
        let Some(format) = detected else {
            notes.add(format!(
                "{}: unrecognised format, skipped (see --format)",
                input.name
            ));
            continue;
        };
        let (first, collector) =
            collector.get_or_insert_with(|| (format, Collector::new(format.kind())));
        if first.kind() != format.kind() {
            return Err(Error(format!(
                "{} is a {} log, which cannot be combined with the {} log before it; \
                 run petrify once per kind of log",
                input.name,
                format.name(),
                first.name(),
            )));
        }
        formats.insert(format);
        collector
            .feed(format, &mut *input.open().map_err(named)?, notes)
            .map_err(named)?;
    }
    match collector {
        Some((first, collector)) => Ok((collector, first, formats)),
        None => Err(Error("no readable logs given".to_string())),
    }
}

/// The subjects the patterns select; `None` when the user has to decide.
fn choose(subjects: &BTreeMap<String, u64>, patterns: &[String]) -> Result<Option<Vec<String>>> {
    if patterns.is_empty() {
        let only = (subjects.len() == 1).then(|| subjects.keys().cloned().collect());
        return Ok(only);
    }
    let mut chosen = BTreeSet::new();
    for pattern in patterns {
        let matched: Vec<&String> = subjects
            .keys()
            .filter(|subject| matches(pattern, subject))
            .collect();
        if matched.is_empty() {
            return Err(Error(format!(
                "--subject {pattern:?} matches nothing. Seen:\n{}",
                subject_table(subjects, "subject")
            )));
        }
        chosen.extend(matched.into_iter().cloned());
    }
    Ok(Some(chosen.into_iter().collect()))
}

/// A pattern with `*` or `?` is a glob over the whole subject; anything else
/// matches as a substring, so `-s orders-api` finds the role's full ARN.
fn matches(pattern: &str, subject: &str) -> bool {
    if !pattern.contains(['*', '?']) {
        return subject.contains(pattern);
    }
    fn glob(pattern: &[char], text: &[char]) -> bool {
        match (pattern.split_first(), text.split_first()) {
            (None, None) => true,
            (Some((&'*', rest)), _) => {
                glob(rest, text) || (!text.is_empty() && glob(pattern, &text[1..]))
            }
            (Some((&'?', rest)), Some((_, tail))) => glob(rest, tail),
            (Some((p, rest)), Some((t, tail))) => p == t && glob(rest, tail),
            _ => false,
        }
    }
    let (pattern, subject): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), subject.chars().collect());
    glob(&pattern, &subject)
}

/// Subjects with their event counts, busiest first.
fn subject_table(subjects: &BTreeMap<String, u64>, noun: &str) -> String {
    let mut rows: Vec<(&String, &u64)> = subjects.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let mut lines = vec![format!("  {:>9}  {noun}", "events")];
    lines.extend(
        rows.iter()
            .map(|(subject, count)| format!("  {:>9}  {subject}", commas(**count))),
    );
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_patterns_are_substrings_unless_they_glob() {
        let role = "arn:aws:iam::111122223333:role/orders-api";
        assert!(matches("orders-api", role));
        assert!(matches("*", role));
        assert!(matches("arn:*:role/orders-*", role));
        assert!(matches("*role/orders-ap?", role));
        assert!(!matches("orders-*", role)); // a glob covers the whole subject
        assert!(!matches("billing", role));
        assert!(matches("*", ""));
    }

    #[test]
    fn choosing_needs_a_pattern_only_when_there_are_several() {
        let one = BTreeMap::from([("a".to_string(), 1)]);
        let two = BTreeMap::from([("app".to_string(), 1), ("runc".to_string(), 2)]);
        let pick = |patterns: &[&str]| {
            let patterns: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
            choose(&two, &patterns)
        };
        assert_eq!(choose(&one, &[]).unwrap(), Some(vec!["a".to_string()]));
        assert_eq!(pick(&[]).unwrap(), None);
        assert_eq!(pick(&["run"]).unwrap(), Some(vec!["runc".to_string()]));
        assert_eq!(pick(&["app", "runc", "app"]).unwrap().unwrap().len(), 2);
        assert_eq!(pick(&["*"]).unwrap().unwrap().len(), 2);
        assert!(
            pick(&["app", "nobody"])
                .unwrap_err()
                .0
                .contains("\"nobody\" matches nothing")
        );
    }
}
