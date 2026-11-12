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
    let run = petrify(&[
        "generate",
        &fixture("aws-flow.log"),
        "--subject",
        "eni-0aaa",
    ]);
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
    let run = petrify(&["show", &fixture("aws-flow.log"), "-s", "eni-0aaa"]);
    assert_eq!(run.code, 0);
    assert!(
        run.out
            .starts_with("eni-0aaa  (13 events, aws-flow)\n\nNetwork behaviour of 10.0.1.5/32")
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
fn gcp_audit_log_becomes_a_custom_role() {
    let log = fixture("gcp-audit.json");
    let run = petrify(&["show", &log, "-s", "orders-api"]);
    assert!(run.out.starts_with(
        "orders-api@shop-prod.iam.gserviceaccount.com  (10 events, gcp-audit)\n\n\
         API calls: 7 actions across 5 services"
    ));
    assert!(run.out.contains("Denied (left out"));

    let run = petrify(&["generate", &log, "-s", "orders-api"]);
    assert_eq!(
        json_of(&run),
        json!({
            "title": "petrify: orders-api@shop-prod.iam.gserviceaccount.com",
            "description":
                "Permissions observed in audit logs for orders-api@shop-prod.iam.gserviceaccount.com",
            "stage": "GA",
            "includedPermissions": [
                "bigquery.jobs.create",
                "cloudsql.instances.connect",
                "pubsub.topics.publish",
                "secretmanager.versions.access",
                "storage.objects.create",
                "storage.objects.get",
                "storage.objects.list",
            ],
        })
    );
    assert!(run.err.contains("wrote GCP custom role"));
    assert!(run.err.contains("bind it on the 9 resources"));

    let run = petrify(&["generate", &log, "-s", "orders-api", "--include-denied"]);
    assert!(run.out.contains("storage.objects.delete"));
}

#[test]
fn gcp_flow_log_becomes_firewall_rules() {
    let log = fixture("gcp-flow.jsonl");
    let run = petrify(&["show", &log]);
    assert!(run.out.contains("orders-api") && run.out.contains("orders-db"));

    // The reporting VM's address is known, so even the database's single
    // conversation needs no --local.
    let run = petrify(&["show", &log, "-s", "orders-db"]);
    assert!(run.out.contains("Network behaviour of 10.128.0.9/32"));
    assert!(run.out.contains("tcp/5432     1 peer  10.128.0.5 (2)"));

    let run = petrify(&["generate", &log, "-s", "orders-api"]);
    let rules = json_of(&run);
    let names: Vec<&str> = rules
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "petrify-ingress-tcp-443",
            "petrify-egress-icmp",
            "petrify-egress-tcp-443",
            "petrify-egress-tcp-5432",
            "petrify-egress-deny-all",
            "petrify-egress-deny-all-v6",
        ]
    );
    assert_eq!(
        rules[0]["sourceRanges"],
        json!(["198.51.100.20/32", "203.0.113.7/32"])
    );
    assert_eq!(
        rules[3]["allowed"],
        json!([{"IPProtocol": "tcp", "ports": ["5432"]}])
    );
    assert_eq!(rules[3]["destinationRanges"], json!(["10.128.0.9/32"]));
    assert!(
        run.err
            .contains("wrote GCP firewall rules for orders-api from 9 events")
    );
    assert!(run.err.contains("targetTags"));
}

#[test]
fn azure_activity_log_becomes_a_custom_role() {
    let log = fixture("azure-activity.json");
    let run = petrify(&["show", &log, "-s", "deployer"]);
    assert!(run.out.starts_with(
        "orders-api-deployer  (10 events, azure-activity)\n\n\
         API calls: 4 actions across 4 services"
    ));

    let run = petrify(&["generate", &log, "-s", "deployer"]);
    let subscription = "/subscriptions/aaaa1111-2222-3333-4444-555555555555";
    assert_eq!(
        json_of(&run),
        json!({
            "Name": "petrify: orders-api-deployer",
            "IsCustom": true,
            "Description": "Actions observed in the Activity Log for orders-api-deployer",
            "Actions": [
                "Microsoft.Compute/virtualMachines/restart/action",
                "Microsoft.KeyVault/vaults/secrets/write",
                "Microsoft.Network/networkSecurityGroups/securityRules/write",
                "Microsoft.Storage/storageAccounts/listKeys/action",
            ],
            "NotActions": [],
            "AssignableScopes": [
                format!("{subscription}/resourceGroups/orders"),
                format!("{subscription}/resourceGroups/shared"),
            ],
        })
    );
    assert!(run.err.contains("wrote Azure custom role"));
    assert!(run.err.contains("but not reads or data-plane operations"));

    let run = petrify(&["generate", &log, "-s", "deployer", "--max-resources", "1"]);
    assert_eq!(json_of(&run)["AssignableScopes"], json!([subscription]));
}

#[test]
fn azure_flow_logs_become_nsg_rules() {
    let log = fixture("azure-flow.json");
    let run = petrify(&["show", &log, "-s", "AABB"]);
    assert!(
        run.out.starts_with(
            "00224800AABB  (11 events, azure-flow)\n\nNetwork behaviour of 10.1.0.4/32"
        )
    );
    assert!(
        run.out
            .contains("tcp/8080    2 peers  10.1.2.7 (2), 10.1.2.8 (1)")
    );
    assert!(run.out.contains("tcp 192.0.2.66 -> 10.1.0.4:22  (1)"));

    let run = petrify(&["generate", &log, "-s", "AABB"]);
    let rules = json_of(&run);
    let summary: Vec<(&str, i64, &str, &str)> = rules
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| {
            let properties = &rule["properties"];
            (
                rule["name"].as_str().unwrap(),
                properties["priority"].as_i64().unwrap(),
                properties["access"].as_str().unwrap(),
                properties["destinationPortRange"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("petrify-in-tcp-8080", 100, "Allow", "8080"),
            ("petrify-in-deny-all", 4096, "Deny", "*"),
            ("petrify-out-tcp-443", 100, "Allow", "443"),
            ("petrify-out-tcp-1433", 110, "Allow", "1433"),
            ("petrify-out-udp-53", 120, "Allow", "53"),
            ("petrify-out-deny-all", 4096, "Deny", "*"),
        ]
    );
    assert_eq!(
        rules[2]["properties"]["destinationAddressPrefixes"],
        json!(["198.51.100.84/32", "203.0.113.17/32"])
    );
    assert!(run.err.contains("wrote Azure NSG rules"));

    // The older NSG flow log format.
    let run = petrify(&["show", &fixture("azure-nsg-flow.json")]);
    assert!(run.out.starts_with("000D3AF87856  (5 events, azure-flow)"));
    assert!(run.out.contains("udp 192.0.2.190 -> 10.5.16.4:443  (1)"));
}

#[test]
fn flows_from_one_cloud_can_become_another_clouds_rules() {
    let log = fixture("aws-flow.log");
    let run = petrify(&[
        "generate",
        &log,
        "-s",
        "eni-0aaa",
        "--policy",
        "gcp-firewall",
    ]);
    assert_eq!(json_of(&run)[0]["name"], "petrify-ingress-tcp-443");
    let run = petrify(&["generate", &log, "-s", "eni-0aaa", "-p", "azure-nsg"]);
    assert_eq!(json_of(&run)[0]["name"], "petrify-in-tcp-443");
    let run = petrify(&[
        "generate",
        &fixture("netflow.csv"),
        "-p",
        "aws-security-group",
    ]);
    assert!(json_of(&run).get("IpPermissions").is_some());

    // Permissions are not translated between clouds, or into firewall rules.
    let run = petrify(&["generate", &log, "-s", "eni-0aaa", "--policy", "gcp-role"]);
    assert_eq!(run.code, 1);
    assert!(run.err.contains(
        "--policy gcp-role cannot be written from this log, \
         which leads to: aws-security-group, gcp-firewall, azure-nsg"
    ));
    let run = petrify(&[
        "generate",
        &fixture("gcp-audit.json"),
        "-s",
        "alice",
        "-p",
        "aws-iam",
    ]);
    assert!(run.code == 1 && run.err.contains("which leads to: gcp-role"));
}

#[test]
fn clouds_do_not_mix() {
    let run = petrify(&[
        "show",
        &fixture("cloudtrail.json"),
        &fixture("gcp-audit.json"),
    ]);
    assert_eq!(run.code, 1);
    assert!(
        run.err
            .contains("is a gcp-audit log, which cannot be combined with the cloudtrail")
    );
}

#[test]
fn kubernetes_audit_log_becomes_an_admission_policy() {
    // The fixture is a trimmed audit log from a real API server.
    let log = fixture("k8s-audit.log");
    let run = petrify(&["show", &log]);
    assert!(run.out.starts_with("The log covers 3 namespaces."));

    let run = petrify(&["show", &log, "-s", "orders"]);
    assert!(run.out.starts_with(
        "orders  (7 events, k8s-audit)\n\n\
         Workloads: 6 admitted (3 Pods, 1 CronJob, 1 Deployment, 1 ReplicaSet), \
         1 rejected by the API server\n"
    ));
    for expected in [
        "Images:\n  registry.example.com/shop/orders-api  (4)\n",
        "  busybox  (1)\n",
        "Service accounts:\n  orders-api  (4)\n  default  (2)\n",
        "Added capabilities:\n  NET_BIND_SERVICE  (4)\n",
        "hostPath volumes: none\n",
        "Privileged containers: none\nHost namespaces: none\n",
    ] {
        assert!(
            run.out.contains(expected),
            "missing {expected:?} in:\n{}",
            run.out
        );
    }

    let run = petrify(&["generate", &log, "-s", "orders"]);
    let list = json_of(&run);
    assert_eq!(list["kind"], "List");
    let (policy, binding) = (&list["items"][0], &list["items"][1]);
    assert_eq!(policy["kind"], "ValidatingAdmissionPolicy");
    assert_eq!(policy["metadata"]["name"], "petrify-orders");
    let validations = policy["spec"]["validations"].as_array().unwrap();
    assert_eq!(validations.len(), 8);
    let images = validations[0]["expression"].as_str().unwrap();
    assert!(images.contains(
        "[\"busybox\",\"registry.example.com/shop/orders-api\",\
         \"registry.example.com/shop/orders-migrate\",\"registry.example.com/shop/report\"]"
    ));
    assert!(
        validations[1]["expression"]
            .as_str()
            .unwrap()
            .ends_with("in [\"default\",\"orders-api\"]")
    );
    assert_eq!(binding["spec"]["policyName"], "petrify-orders");
    assert_eq!(binding["spec"]["validationActions"], json!(["Deny"]));
    assert!(
        run.err
            .contains("wrote validating admission policy for orders from 7 events")
    );
    assert!(!run.err.contains("note:"));
}

#[test]
fn admission_policy_options() {
    let log = fixture("k8s-audit.log");
    let run = petrify(&[
        "generate",
        &log,
        "-s",
        "orders",
        "--validation-action",
        "warn,audit",
    ]);
    assert_eq!(
        json_of(&run)["items"][1]["spec"]["validationActions"],
        json!(["Warn", "Audit"])
    );
    let run = petrify(&[
        "generate",
        &log,
        "-s",
        "orders",
        "--validation-action",
        "deny,warn",
    ]);
    assert!(run.code == 1 && run.err.contains("together"));

    let run = petrify(&["generate", &log, "-s", "orders", "--max-images", "1"]);
    let images = json_of(&run)["items"][0]["spec"]["validations"][0]["expression"].clone();
    assert!(
        images
            .as_str()
            .unwrap()
            .contains("[\"registry.example.com/shop/\"].exists(p,")
    );
    assert!(
        run.err
            .contains("any image under registry.example.com/shop/ is allowed")
    );

    // What a namespace was seen to need stays allowed, and is said.
    let run = petrify(&["generate", &log, "-s", "monitoring"]);
    assert_eq!(
        json_of(&run)["items"][0]["spec"]["validations"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert!(
        run.err
            .contains("privileged containers were observed and stay allowed")
    );
    assert!(run.err.contains("hostPID was observed and stays allowed"));

    let run = petrify(&["generate", &log, "-s", "orders", "-s", "monitoring"]);
    assert_eq!(
        json_of(&run)["items"][0]["metadata"]["name"],
        "petrify-workloads"
    );
    let run = petrify(&["generate", &log, "-s", "orders", "--policy", "seccomp"]);
    assert!(run.code == 1 && run.err.contains("which leads to: k8s-admission"));
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
    let run = petrify(&["show", &fixture("strace.log"), &fixture("aws-flow.log")]);
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
    for name in ["aws-flow", "vpcflow"] {
        // "vpcflow" is what 0.1 called the AWS format.
        let run = petrify(&["show", "--format", name, odd.to_str().unwrap()]);
        assert!(run.code == 1 && run.err.contains("no events"));
        assert!(run.err.contains("unexpected number of fields"));
    }
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
        &fixture("aws-flow.log"),
        "-s",
        "eni-0aaa",
        "--local",
        "nope",
    ]);
    assert!(run.code == 1 && run.err.contains("--local"));

    assert_eq!(petrify(&["generate"]).code, 2);
    let version = format!("petrify {}\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(petrify(&["--version"]).out, version);
}
