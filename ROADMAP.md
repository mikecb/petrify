# Roadmap

Where petrify is, and where it could go next. The order within each section is
roughly the order of value; nothing here is scheduled.

## Today (0.5)

| Log                                  | Policy                   | Tested against                         |
| ------------------------------------ | ------------------------ | -------------------------------------- |
| AWS CloudTrail                       | IAM policy               | fixtures; public samples read, incl. a real account |
| Google Cloud Audit Logs              | IAM custom role          | fixtures; public samples read          |
| Azure Activity Log                   | custom role              | fixtures; public samples read, incl. a real tenant |
| AWS VPC Flow Logs, flow CSV          | security group rules     | fixtures; public samples read          |
| Google Cloud VPC Flow Logs           | VPC firewall rules       | fixtures; public samples read          |
| Azure VNet and NSG flow logs         | NSG security rules       | fixtures; public samples read          |
| Kubernetes API server audit log      | ValidatingAdmissionPolicy | a real API server (k3s, Kubernetes 1.34) |
| Kubernetes API server audit log      | RBAC roles and bindings  | a real API server (k3s, Kubernetes 1.34) |
| `strace`, audit / kernel-log records | seccomp profile          | a real container under Docker and runc |

The seccomp and Kubernetes paths have run end to end. The cloud paths read
public sample logs correctly, but no policy they generate has been applied to
a real account, which is the first thing to fix.

Pull requests are checked on Linux and macOS, and a version tag publishes
binaries for both once the same checks pass.

## 1. Trust what exists

Before adding more breadth, make the current policies ones you can apply
without reading them line by line.

- **Apply a generated policy in each cloud.** Reading public sample logs
  found and fixed format bugs, but nobody has yet attached a generated policy
  to a known application and exercised it. For Google Cloud and Azure this
  also means running the commands the README gives for applying the output.
- **Scope more AWS calls.** IAM, EC2 and RDS are now scoped from AWS's
  reference, which took a real administrator's CloudTrail from 197 of 240
  actions on `*` to 117, most of the rest being calls that cannot be limited.
  Next: the same for the other services petrify sees, and for the few
  actions that take too many resource types to list (`ec2:CreateTags`,
  `ec2:RunInstances`), where the request does say which ones are involved.
- **Summarise names as well as paths.** Twenty secrets called
  `retrieve-secret-0` to `-19` stay twenty resources, because summarising
  only understands `/`.
- **Split a policy that is too large.** The same administrator's policy is
  29,651 characters against a limit of 6,144, more than before because
  scoped resources take more room than `*`. petrify says so and stops.
- **IAM actions from the source of truth.** The AWS Service Authorization
  Reference is now generated into the code for three services, to say which
  resource types an action supports. Use it for the rest: replace the
  hand-written event-to-action tables, check that every action petrify
  writes exists, and add the dependent actions a call needs. Sample logs show the cost of not having it: event
  names such as `ssm:OpenControlChannel`, `bedrock:Converse` and
  `s3:GetStorageLensDashboardDataInternal` pass straight through, and are
  not what IAM calls those permissions.
- **Flag what a log cannot show.** When the behaviour implies a permission
  CloudTrail never records (`iam:PassRole` for `RunInstances` or
  `CreateFunction`, `kms:Decrypt` behind an encrypted bucket), say so.
- **Azure reads and data actions.** A role built from the Activity Log has
  neither. Read the resource logs that do record them (storage, Key Vault),
  and fill `DataActions`.
- **Google Cloud bindings.** Write the role bindings, with IAM Conditions on
  resource names, that scope a custom role to the resources the log shows,
  instead of leaving that to a note.
- **Confirm the Azure flow tuple reading.** petrify takes a tuple's source to
  be the end that opened the connection, as the documented samples show but
  the documentation does not say.
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

- **Terraform output** for every cloud's roles and firewall rules, since that
  is how most of them are applied, and it would replace the shell loops the
  README needs for Google Cloud and Azure today.
- **Kubernetes NetworkPolicy** and **nftables** rules from flows.
- **Kyverno and Gatekeeper** output for the admission behaviour, for clusters
  that already standardise on one of them.
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
- **Rules that reference what the peer is**, not its address: other security
  groups and AWS prefix lists, Google Cloud tags and service accounts, Azure
  service tags and application security groups. That fixes the commonest
  reason a rule widens to `0.0.0.0/0`: a cloud service with many addresses.
- **Port ranges**, for peers that speak on many adjacent ports.

- **Kubernetes admission that requires as well as restricts.** Where every
  observed pod ran as non-root, with a read-only root filesystem, without
  privilege escalation or with all capabilities dropped, keep it that way.
  Then more of the pod spec: volume types, host ports, sysctls, user and
  group IDs, seccomp and AppArmor profiles.
- **Image digests**: allow only the digests observed, for namespaces that
  deploy by digest.

- **RBAC for groups and aggregated roles.** Bind a group when every member
  behaves alike, and say when an existing ClusterRole already fits.

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
- **Cloud**: Google Cloud firewall rule logs, which say what was denied, as
  its flow logs cannot; reading CloudTrail Lake, Athena, CloudWatch Logs,
  Cloud Logging and Azure Monitor directly rather than from exported files.
- **Kubernetes**: admission dry-run results. An audit log records which
  requests would have failed a policy in warn or audit mode; `show` could
  list exactly those.

## Not planned

- **Enforcement or a long-running agent.** petrify reads logs and writes
  files. Applying the policy, and collecting the logs, belong to tools that
  already do those well.
- **Guessing beyond the evidence.** No "applications like this usually also
  need" additions. If it was not observed, it is not granted, and the notes
  say where the log could not see.
