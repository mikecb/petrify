//! End-to-end tests: run the built binary against the fixture logs.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A fresh directory for one test's files.
fn scratch(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

fn finish(output: Output) -> Run {
    Run {
        code: output.status.code().unwrap(),
        out: String::from_utf8(output.stdout).unwrap(),
        err: String::from_utf8(output.stderr).unwrap(),
    }
}

fn petrify(args: &[&str]) -> Run {
    finish(
        Command::new(env!("CARGO_BIN_EXE_petrify"))
            .args(args)
            .output()
            .unwrap(),
    )
}

fn json_of(run: &Run) -> Value {
    assert_eq!(run.code, 0, "{}", run.err);
    serde_json::from_str(&run.out).unwrap()
}

#[test]
fn show_lists_subjects_when_there_are_several() {
    let run = petrify(&["show", &fixture("cloudtrail.json")]);
    assert_eq!(run.code, 0);
    assert!(run.out.starts_with("The log covers 2 principals."));
    assert!(run.out.contains("role/orders-api") && run.out.contains("user/alice"));
}

#[test]
fn generate_refuses_to_blend_subjects() {
    let run = petrify(&["generate", &fixture("cloudtrail.json")]);
    assert_eq!((run.code, run.out.as_str()), (1, ""));
    assert!(run.err.contains("--subject") && run.err.contains("role/orders-api"));
}

#[test]
fn generate_iam_policy() {
    let run = petrify(&["generate", &fixture("cloudtrail.json"), "-s", "orders-api"]);
    let document = json_of(&run);
    assert_eq!(document["Version"], "2012-10-17");

    let resource_of = |wanted: &str| {
        let statements = document["Statement"].as_array().unwrap();
        let found = statements
            .iter()
            .find(|statement| match &statement["Action"] {
                Value::String(action) => action == wanted,
                actions => actions.as_array().unwrap().contains(&json!(wanted)),
            });
        found.map(|statement| statement["Resource"].clone())
    };
    assert_eq!(
        resource_of("s3:GetObject"),
        Some(json!([
            "arn:aws:s3:::orders-data/config/app.json",
            "arn:aws:s3:::orders-data/exports/latest.csv",
            "arn:aws:s3:::orders-data/invoices/2026/*",
        ]))
    );
    assert_eq!(
        resource_of("dynamodb:Query"),
        Some(json!([
            "arn:aws:dynamodb:us-east-1:111122223333:table/Orders",
            "arn:aws:dynamodb:us-east-1:111122223333:table/Orders/index/by-customer",
        ]))
    );
    assert_eq!(
        resource_of("sts:AssumeRole"),
        Some(json!("arn:aws:iam::444455556666:role/partner-read"))
    );
    assert_eq!(resource_of("ec2:DescribeInstances"), Some(json!("*")));
    assert_eq!(resource_of("cloudwatch:PutMetricData"), Some(json!("*")));
    assert_eq!(resource_of("s3:DeleteObject"), None); // was denied
    assert_eq!(resource_of("s3:ListAllMyBuckets"), None); // another principal
    assert!(
        run.err
            .contains("wrote IAM policy for arn:aws:iam::111122223333:role/orders-api")
    );
    assert!(run.err.contains("note: 2 actions granted on \"*\""));
}

#[test]
fn iam_options_change_the_policy() {
    let log = fixture("cloudtrail.json");
    let run = petrify(&["generate", &log, "-s", "orders-api", "--include-denied"]);
    assert!(run.out.contains("s3:DeleteObject"));
    let run = petrify(&["generate", &log, "-s", "orders-api", "--max-resources", "1"]);
    assert!(run.out.contains("\"arn:aws:s3:::orders-data/*\""));
    let run = petrify(&["generate", &log, "-s", "orders-api", "--max-resources", "0"]);
    assert_eq!(run.code, 2);
}

#[test]
fn subject_patterns_select_and_must_match() {
    let log = fixture("cloudtrail.json");
    let run = petrify(&["generate", &log, "-s", "*"]);
    assert!(run.code == 0 && run.out.contains("s3:ListAllMyBuckets"));
    assert!(run.err.contains("for 2 principals"));
    let run = petrify(&["generate", &log, "-s", "nobody"]);
    assert!(run.code == 1 && run.err.contains("matches nothing"));

    let run = petrify(&[
        "generate",
        &fixture("audit.log"),
        "-s",
        "orders",
        "-s",
        "sshd",
    ]);
    assert_eq!(
        json_of(&run)["syscalls"][0]["names"],
        json!(["accept4", "openat", "socket"])
    );
    assert_eq!(
        json_of(&run)["architectures"],
        json!(["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"])
    );
}

#[test]
fn generate_security_group() {
    let run = petrify(&["generate", &fixture("vpcflow.log"), "--subject", "eni-0aaa"]);
    assert_eq!(
        json_of(&run),
        json!({
            "Description": "petrify: observed traffic of 10.0.1.5/32",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "198.51.100.20/32"}, {"CidrIp": "203.0.113.7/32"}],
            }],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "icmp",
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpRanges": [{"CidrIp": "10.0.2.99/32"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [{"CidrIp": "10.0.2.10/32"}],
                },
                {
                    "IpProtocol": "udp",
                    "FromPort": 53,
                    "ToPort": 53,
                    "IpRanges": [{"CidrIp": "10.0.0.2/32"}],
                },
            ],
        })
    );
}

#[test]
fn show_network() {
    let run = petrify(&["show", &fixture("vpcflow.log"), "-s", "eni-0aaa"]);
    assert_eq!(run.code, 0);
    assert!(
        run.out
            .starts_with("eni-0aaa  (13 events, vpcflow)\n\nNetwork behaviour of 10.0.1.5/32")
    );
    assert!(
        run.out
            .contains("tcp/443    2 peers  198.51.100.20 (2), 203.0.113.7 (2)")
    );
    assert!(run.out.contains("tcp 192.0.2.66 -> 10.0.1.5:22  (1)"));

    let run = petrify(&["show", &fixture("netflow.csv")]);
    assert_eq!(run.code, 0);
    assert!(run.out.contains("tcp/22") && run.out.contains("tcp/8443"));
    assert!(run.out.contains("192.168.1.50/32"));
    assert!(run.err.contains("not a flow record (x3)"));

    let run = petrify(&["show", &fixture("netflow.csv"), "--local", "192.168.1.0/24"]);
    assert!(run.out.contains("Network behaviour of 192.168.1.0/24"));
}

#[test]
fn show_syscalls() {
    let run = petrify(&["show", &fixture("strace.log")]);
    assert_eq!(run.code, 0);
    assert!(
        run.out
            .starts_with("/usr/local/bin/orders  (16 events, strace)\n\nSyscalls: 16 calls")
    );
    for expected in [
        "Executes:\n  /usr/local/bin/orders\n",
        "Connects to:\n  10.0.2.10:5432\n",
        "Listens on:\n  0.0.0.0:8080\n",
        "Opens for writing:\n  /var/log/orders.log\n",
        "Opens for reading:\n  /etc/ld.so.cache\n",
    ] {
        assert!(
            run.out.contains(expected),
            "missing {expected:?} in:\n{}",
            run.out
        );
    }
}

#[test]
fn trace_and_audit_log_combine_into_one_profile() {
    let target = scratch("combine").join("profile.json");
    let run = petrify(&[
        "generate",
        &fixture("strace.log"),
        &fixture("audit.log"),
        "-s",
        "/usr/local/bin/orders",
        "--allow",
        "futex,epoll_wait",
        "--allow",
        "nanosleep",
        "--arch",
        "x86_64",
        "-o",
        target.to_str().unwrap(),
    ]);
    assert_eq!((run.code, run.out.as_str()), (0, ""));
    let profile: Value = serde_json::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
    assert_eq!(
        profile,
        json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [{
                "names": [
                    "accept4", "bind", "brk", "clone3", "close", "connect", "epoll_wait",
                    "execve", "exit", "exit_group", "futex", "listen", "nanosleep", "openat",
                    "read", "socket", "write",
                ],
                "action": "SCMP_ACT_ALLOW",
            }],
        })
    );
    assert!(run.err.contains("cannot name syscall 99999"));
    assert!(run.err.contains("from 19 events"));
}

#[test]
fn seccomp_dry_run_profile_logs_instead_of_blocking() {
    let run = petrify(&[
        "generate",
        &fixture("strace.log"),
        "--default-action",
        "SCMP_ACT_LOG",
        "--arch",
        "aarch64",
    ]);
    let profile = json_of(&run);
    assert_eq!(profile["defaultAction"], "SCMP_ACT_LOG");
    assert_eq!(profile["architectures"], json!(["SCMP_ARCH_AARCH64"]));
    assert!(profile.get("defaultErrnoRet").is_none());
}

#[test]
fn kinds_of_log_do_not_mix() {
    let run = petrify(&["show", &fixture("strace.log"), &fixture("vpcflow.log")]);
    assert_eq!(run.code, 1);
    assert!(run.err.contains("cannot be combined"));
}

#[test]
fn directories_gzip_and_unknown_files() {
    let root = scratch("directories").join("AWSLogs");
    let logs = root.join("2026");
    std::fs::create_dir_all(&logs).unwrap();
    let gz = std::fs::File::create(logs.join("a.json.gz")).unwrap();
    let mut gz = flate2::write::GzEncoder::new(gz, flate2::Compression::default());
    gz.write_all(&std::fs::read(fixture("cloudtrail.json")).unwrap())
        .unwrap();
    gz.finish().unwrap();
    std::fs::write(logs.join("notes.txt"), "nothing to see\n").unwrap();
    std::fs::write(root.join(".hidden"), "{").unwrap();

    let run = petrify(&["show", root.to_str().unwrap(), "-s", "alice"]);
    assert_eq!(run.code, 0, "{}", run.err);
    assert!(run.out.contains("s3:ListAllMyBuckets"));
    assert!(run.err.contains("notes.txt: unrecognised format"));
    assert!(!run.err.contains(".hidden"));
}

#[test]
fn reads_stdin() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_petrify"))
        .args(["show", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = std::fs::read(fixture("strace.log")).unwrap();
    child.stdin.take().unwrap().write_all(&log).unwrap();
    let run = finish(child.wait_with_output().unwrap());
    assert_eq!(run.code, 0);
    assert!(run.out.contains("10.0.2.10:5432"));
}

#[test]
fn format_can_be_forced() {
    let dir = scratch("forced");
    let odd = dir.join("flows.txt");
    // A custom flow log whose header was lost: undetectable, and unreadable
    // as the default format, but not a crash.
    std::fs::write(&odd, "eni-1 10.0.0.1 10.0.0.2 1 2 6\n").unwrap();
    let run = petrify(&["show", odd.to_str().unwrap()]);
    assert!(run.code == 1 && run.err.contains("unrecognised format"));
    let run = petrify(&["show", "--format", "vpcflow", odd.to_str().unwrap()]);
    assert!(run.code == 1 && run.err.contains("no events"));
    assert!(run.err.contains("unexpected number of fields"));
}

#[test]
fn errors_are_messages_not_panics() {
    let dir = scratch("errors");
    let run = petrify(&["show", dir.join("missing.log").to_str().unwrap()]);
    assert!(run.code == 1 && run.err.contains("no such file"));

    let empty = dir.join("empty.json");
    std::fs::write(&empty, r#"{"Records": []}"#).unwrap();
    let run = petrify(&["show", "--format", "cloudtrail", empty.to_str().unwrap()]);
    assert!(run.code == 1 && run.err.contains("no events"));

    let run = petrify(&[
        "show",
        &fixture("vpcflow.log"),
        "-s",
        "eni-0aaa",
        "--local",
        "nope",
    ]);
    assert!(run.code == 1 && run.err.contains("--local"));

    assert_eq!(petrify(&["generate"]).code, 2);
    assert_eq!(petrify(&["--version"]).out, "petrify 0.1.0\n");
}
