# petrify

Point petrify at a log of what an application did, and it writes a policy that
lets the application do that and nothing else.

| Log                                   | Shows                          | Policy written        |
| ------------------------------------- | ------------------------------ | --------------------- |
| AWS CloudTrail                        | API calls and their resources  | IAM policy            |
| VPC Flow Logs, or any flow CSV        | who connects to whom           | security group rules  |
| `strace` output, Linux audit records  | system calls                   | seccomp profile       |

```console
$ petrify show cloudtrail/ --subject orders-api
arn:aws:iam::111122223333:role/orders-api  (30 events, cloudtrail)

API calls: 13 actions across 9 services
  dynamodb:Query        2  arn:aws:dynamodb:us-east-1:111122223333:table/Orders (1), ...
  s3:GetObject         16  arn:aws:s3:::orders-data/config/app.json (1), ... +13 more
  ...
Denied (left out of the policy unless --include-denied):
  s3:DeleteObject       1  arn:aws:s3:::orders-data/exports/old.csv (1)

$ petrify generate cloudtrail/ --subject orders-api -o policy.json
petrify: wrote IAM policy to policy.json for arn:aws:iam::111122223333:role/orders-api from 30 events
```

## Status

Version 0.1. The seccomp path has been run end to end against a real container
runtime. The IAM and security group paths are tested only against fixture
logs so far: read what they generate before applying it. [ROADMAP.md](ROADMAP.md)
has what comes next.

## Build

Needs a recent stable Rust toolchain (developed on 1.99 and 1.100) and a C
linker (`build-essential` on Debian and Ubuntu).

```sh
cargo build --release      # binary at target/release/petrify
cargo test
```

## Use

```
petrify show     LOG...   summarise the observed behaviour
petrify generate LOG...   write the policy (stdout, or -o FILE)
```

`LOG` is a file, a directory (walked recursively, the way CloudTrail and flow
logs land in S3), or `-` for stdin. Gzip is read transparently and the format
is detected; `--format` overrides it.

**One subject at a time.** A log usually covers several actors, and a policy
that blends them is too broad for each. petrify calls the actor the *subject*:
the IAM principal, the network interface, or the executable. With several in a
log, `show` lists them and `generate` refuses until you pick with `--subject`
(a substring, or a glob such as `'*'`; repeatable).

Notes about guesses and gaps go to stderr, so stdout is always just the policy.

### IAM policy from CloudTrail

```sh
petrify generate AWSLogs/ -s my-role -o policy.json
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY \
    --policy-document file://policy.json
```

- All sessions of a role are one subject, named by the role's ARN.
- CloudTrail event names are translated to IAM actions where they differ
  (`ListObjectsV2` is `s3:ListBucket`, `Invoke` is `lambda:InvokeFunction`).
- Resources come from the event when it names them, and from request
  parameters for S3, DynamoDB, SQS, SNS, Lambda, Secrets Manager, SSM, KMS,
  CloudWatch Logs and STS. Everything else is granted on `*` and noted.
- An action that touched more than `--max-resources` resources (default 10)
  has its deepest path segments replaced by wildcards until it fits:
  a thousand keys under `uploads/2026/` become `uploads/2026/*`.
- Calls that were denied while the log was recorded are shown but not granted,
  unless `--include-denied`.

### Security group from flow logs

```sh
petrify generate flowlogs/ -s eni-0abc123 -o sg.json
aws ec2 authorize-security-group-ingress --group-id sg-... \
    --ip-permissions "$(jq -c .IpPermissions sg.json)"
aws ec2 authorize-security-group-egress --group-id sg-... \
    --ip-permissions "$(jq -c .IpPermissionsEgress sg.json)"
```

A new security group allows all egress; revoke that rule or the egress rules
above constrain nothing.

Flow records do not say who opened a connection, and a stateful rule needs to
know. petrify decides, per conversation, in this order:

1. TCP flags, when the log has them (custom format with `tcp-flags`).
2. Port numbers: a port below the ephemeral range is the server.
3. Traffic seen in one direction only: the receiver is the server.
4. Whichever side sent first.

If none of these settles it, both directions are allowed and a note says so.

- The application's own address is inferred as the one present in every record
  of the interface. When that fails (a one-conversation log, a CSV from a
  router), pass `--local CIDR`.
- Peers are listed exactly until a rule has more than `--max-peers` (default
  8); then prefixes widen step by step. Private addresses never widen past
  their private range. A rule that ends up at `0.0.0.0/0` is noted.
- Rejected flows are shown and never allowed.
- Supported: the default flow log format, custom formats that start with a
  header line (as delivered to S3), and CSV with a header naming source,
  destination, ports and protocol (`nfdump -o csv` and similar).

### Seccomp profile from strace or audit records

```sh
strace -f -o app.trace ./app
petrify generate app.trace -o seccomp.json
docker run --security-opt seccomp=seccomp.json ...
```

The profile is the OCI JSON format used by Docker, Podman, containerd and
Kubernetes (`seccompProfile.type: Localhost`). It lists syscall names; it does
not filter on arguments.

**A trace taken outside the container is not enough to start the container.**
The runtime installs the filter and then keeps working (dropping privileges,
closing descriptors, `execve`) under it. Measured on runc 1.5.1 with the
`hello-world` image: the program makes 5 syscalls; runc needs 26 more.

Close the gap by letting the kernel report what is missing:

```sh
# 1. Dry run: unlisted syscalls are logged instead of refused.
petrify generate app.trace --default-action SCMP_ACT_LOG -o dry-run.json
docker run --security-opt seccomp=dry-run.json ...

# 2. Feed the audit records back in. '*' because they are attributed to the
#    runtime's executable as well as the application's.
journalctl -k | grep type=1326 > audit.log     # or /var/log/audit/audit.log
petrify generate app.trace audit.log -s '*' --default-action SCMP_ACT_LOG -o dry-run.json

# 3. Repeat until a run logs nothing new, then drop --default-action.
```

Without auditd running, the kernel log keeps only about 10 audit records per
5 seconds, so expect several rounds (petrify says when it sees such a log);
running auditd avoids that limit. `--allow name,name` adds syscalls by hand.

Audit records carry only a syscall number unless the log is enriched; petrify
names them from built-in tables for x86_64 and aarch64.

## Limits

petrify reports what the log shows. Whether that is everything the application
needs is for you to judge.

- **Unexercised behaviour is denied.** The monthly job, the error path and the
  failover that did not happen during the recording are not in the policy.
  Record for long enough, then roll out gradually: `SCMP_ACT_LOG` for seccomp;
  for IAM and security groups, apply to one instance and run petrify on the
  new logs, where denied calls and rejected flows show up by name.
- **CloudTrail omits things.** Data events (S3 objects, Lambda invokes,
  DynamoDB items) appear only if the trail records them. Permissions that are
  checked without an API call of their own, `iam:PassRole` above all, never
  appear. The event-to-action mapping is maintained by hand and incomplete.
- **No conditions.** IAM policies carry no `Condition` blocks, security groups
  reference CIDR ranges rather than other groups, and seccomp rules do not
  inspect arguments.
- **AWS only** for the cloud and network policies, for now.

[ROADMAP.md](ROADMAP.md) lists which of these are meant to change.

## Layout

```
src/sources/    one module per log format -> normalised events
src/cloud.rs    API calls   -> IAM policy
src/network.rs  flows       -> security group
src/syscalls.rs syscalls    -> seccomp profile
src/cli.rs      argument parsing, subject selection, output
tests/          end-to-end tests against tests/fixtures/
```

A new log format is a module in `src/sources/` with `sniff` and `parse`, a
`Format` variant, and one arm in `Collector::feed`. A new policy for an
existing kind of behaviour (say, Kubernetes NetworkPolicy from flows) is a
second `policy` function beside the first.

`src/syscall_tables.rs` is generated from kernel headers by
`scripts/gen_syscall_tables.py` (needs `linux-libc-dev` and `cpp`).
