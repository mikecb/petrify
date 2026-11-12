# Roadmap

Where petrify is, and where it could go next. The order within each section is
roughly the order of value; nothing here is scheduled.

## Today (0.1)

| Log                                  | Policy               | Tested against                          |
| ------------------------------------ | -------------------- | --------------------------------------- |
| AWS CloudTrail                       | IAM policy           | hand-written fixtures only              |
| VPC Flow Logs, flow CSV              | security group rules | hand-written fixtures only              |
| `strace`, audit / kernel-log records | seccomp profile      | a real container under Docker and runc  |

The seccomp path has run end to end. The two AWS paths have not yet met a real
log or a real AWS account, which is the first thing to fix.

Pull requests are checked on Linux and macOS, and a version tag publishes
binaries for both once the same checks pass.

## 1. Trust what exists

Before adding breadth, make the three current policies ones you can apply
without reading them line by line.

- **Run against real logs.** A real CloudTrail trail and real flow logs from a
  known application, with the generated policy applied and the application
  exercised. Turn what breaks into fixtures.
- **IAM actions from the source of truth.** Replace the hand-written
  event-to-action tables with data generated from the AWS Service
  Authorization Reference, the way the syscall tables are generated from
  kernel headers. That also tells petrify which actions exist, which support
  resource-level scoping (so `*` is right, not a gap), and which dependent
  actions a call needs.
- **Flag what a log cannot show.** When the behaviour implies a permission
  CloudTrail never records (`iam:PassRole` for `RunInstances` or
  `CreateFunction`, `kms:Decrypt` behind an encrypted bucket), say so.
- **Flow logs without a header.** A `--fields` option for custom formats
  delivered to CloudWatch Logs, which carry no header line.
- **Seccomp with auditd.** Confirm the dry-run loop converges in one round
  when auditd is running, and test against crun and containerd.
- **Large logs.** CloudTrail files are read whole; stream them. Measure memory
  on a day of flow logs from a busy interface.

## 2. Compare, not just generate

Most applications already have a policy. The useful question is often "what
can I remove?", and answering it needs no new log format.

- **`petrify diff POLICY LOG`.** Given the policy in force and the log, list
  what is granted but never used, and what was used but is not granted.
- **Saved behaviour.** Write the observed behaviour to a file and merge
  several (`petrify merge`), so a policy can be built from last month plus
  this week without keeping every raw log.
- **Time and frequency.** `--since` / `--until`, and marking behaviour seen
  only once or only long ago, which is where both mistakes and attacks hide.

## 3. More policies from behaviour already collected

Each of these is a second `policy` function over an existing behaviour model.

- **Terraform output** for the IAM policy and the security group, since that
  is how most of them are applied.
- **Kubernetes NetworkPolicy** and **nftables** rules from flows.
- **systemd hardening** from a trace: `SystemCallFilter=`, `IPAddressAllow=`,
  `ReadWritePaths=`, `RestrictAddressFamilies=`.
- **AppArmor and Landlock** from the files, executables and sockets a trace
  shows. `show` already extracts these from strace output; they are not yet
  turned into policy.

## 4. Tighter policies

- **Seccomp argument filters**: socket families, `clone` flags, `ioctl`
  requests, instead of allowing a syscall outright.
- **IAM conditions** where the log supports them: `aws:SourceVpc`, encryption
  context, required tags.
- **Security groups that reference** other security groups and AWS prefix
  lists rather than CIDR ranges. The second fixes the commonest reason a rule
  widens to `0.0.0.0/0`: an AWS service with many addresses.
- **Port ranges**, for peers that speak on many adjacent ports.

## 5. macOS: Santa rules

[Santa](https://github.com/northpolesec/santa) decides which binaries may run
on a Mac. In Monitor mode it logs every execution and blocks nothing; in
Lockdown mode it runs only what a rule allows. Getting from the first to the
second is the same step petrify takes everywhere else: read what ran, write
the rules that allow exactly that.

This is a fourth kind of behaviour (executions) beside API calls, flows and
syscalls, so it needs a new behaviour model as well as a source and a policy.

- **Source: Santa's event log** from a Monitor-mode fleet. Each execution
  record carries the binary's path and hash and its signing identity. The
  subject is the machine or the user.
- **Policy: Santa allow rules**, as a configuration profile's static rules and
  as input for a sync server. Prefer the broadest identity that is still
  specific to the vendor: a Team ID or Signing ID rule survives the next
  software update, a binary hash rule does not. Fall back to hashes only for
  unsigned binaries, and list those separately for review.
- **Show what Lockdown would break.** Executions that no generated rule
  covers, and anything Santa already blocked while the log was recorded.
- **Second source: `eslogger`**, which records the same execution events from
  Endpoint Security on a Mac that does not run Santa yet.
- **Later: file access policies.** Santa can also restrict which processes
  read or write given paths; its file access log could feed those rules the
  same way.

To be checked first: the exact fields of each Santa log format (text,
JSON, protobuf) across versions, and that the build runs on macOS at all.
Nothing has been tested there yet.

## 6. More logs

- **Network**: Zeek `conn.log` and conntrack, which record who opened a
  connection and so need no guessing; Cilium Hubble flows.
- **Syscalls**: eBPF tracers (Tetragon, Tracee, Falco), `perf trace`, and
  `strace -c` summaries. These can trace a container from its first
  instruction, which removes the dry-run loop.
- **Cloud**: Kubernetes audit logs to RBAC roles; GCP Cloud Audit Logs and
  Azure Activity Logs to their IAM; reading CloudTrail Lake, Athena and
  CloudWatch Logs directly rather than from exported files.

## Not planned

- **Enforcement or a long-running agent.** petrify reads logs and writes
  files. Applying the policy, and collecting the logs, belong to tools that
  already do those well.
- **Guessing beyond the evidence.** No "applications like this usually also
  need" additions. If it was not observed, it is not granted, and the notes
  say where the log could not see.
