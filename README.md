# petrify

Point petrify at a log of what an application did, and it writes a policy that
lets the application do that and nothing else.

| Log                                                   | Shows                         | Policy written                                              |
| ----------------------------------------------------- | ----------------------------- | ----------------------------------------------------------- |
| AWS CloudTrail                                        | API calls and their resources | IAM policy                                                  |
| Google Cloud Audit Logs                               | permissions checked           | IAM custom role                                             |
| Azure Activity Log                                    | Resource Manager operations   | custom role                                                 |
| Flow logs from AWS, Google Cloud or Azure; flow CSVs  | who connects to whom          | security group, VPC firewall rules, or NSG rules            |
| Kubernetes API server audit log                       | what was deployed             | ValidatingAdmissionPolicy                                   |
| `strace` output, Linux audit records                  | system calls                  | seccomp profile                                             |

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

Version 0.3. How far each path has been tested:

- **Seccomp**: run end to end against a real container runtime.
- **Kubernetes admission**: run end to end against a real API server (k3s,
  Kubernetes 1.34): a policy generated from its audit log was applied and
  then tried with requests it should admit and refuse.
- **AWS** (IAM policy, security group): fixture logs only.
- **Google Cloud and Azure**: fixture logs only. Their formats were checked
  against the vendors' documentation, published API definitions and public
  sample logs, but petrify has not read a log from a real account, and the
  commands below that apply its output are untested.

Read what it generates before applying it. [ROADMAP.md](ROADMAP.md) has what
comes next.

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
the principal, the network interface or VM, the namespace, or the executable. With several in
a log, `show` lists them and `generate` refuses until you pick with `--subject`
(a substring, or a glob such as `'*'`; repeatable).

Notes about guesses and gaps go to stderr, so stdout is always just the policy.

### Permissions from cloud audit logs

Each cloud's audit log leads to that cloud's policy; permission names are not
translated between clouds. Common to all three:

- Calls that were denied while the log was recorded are shown but not granted,
  unless `--include-denied`.
- The policy grants what was *used*. Compare it with what the identity has now
  to see what can go.

#### AWS: CloudTrail to an IAM policy

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

#### Google Cloud: audit logs to a custom role

```sh
gcloud logging read 'logName:"cloudaudit.googleapis.com"' \
    --project=shop-prod --freshness=30d --format=json > audit.json
petrify generate audit.json -s orders-api@ -o role.json
gcloud iam roles create ordersApi --project=shop-prod --file=role.json
```

- An audit log entry lists the permissions that were checked and whether each
  was granted, so nothing is translated: the role's `includedPermissions` are
  the ones the log recorded.
- A role is only a list of permissions. Where it applies is decided by where
  you bind it, so bind it on the resources `show` lists, not project-wide.
- Also reads the JSON Lines a log sink writes to Cloud Storage, and rows
  exported from BigQuery.
- Data Access audit logs are off by default for most services. Without them
  the log shows configuration changes but few of an application's reads and
  writes, and the role will be too small.
- GKE audit logs also list Kubernetes API verbs (`io.k8s.*`). Kubernetes
  RBAC grants those, so they are left out of the role and noted.
- Some permissions cannot be put in a custom role; `gcloud` rejects those.

#### Azure: Activity Log to a custom role

```sh
az monitor activity-log list --offset 30d --max-events 100000 > activity.json
petrify generate activity.json -s orders-api-deployer -o role.json
az role definition create --role-definition @role.json
```

(`--max-events` defaults to 50.)

The Activity Log is a narrower record than the other two, and a role built
from it is a starting point, not a finished role:

- It records writes, deletes and actions. **Reads are not recorded**, so the
  role has none: add the `*/read` actions the application needs.
- It covers the control plane only. Reading a blob or a secret is a data
  action, logged by the resource itself, and is not in the role.
- A request refused for lack of permission produces no record, so nothing is
  ever shown as denied.

`AssignableScopes` lists the resource groups the actions touched, or their
subscriptions when there are more than `--max-resources` of them. Also reads
the Activity Log as exported to Event Hubs or a storage account.

### Firewall rules from flow logs

```sh
petrify generate flowlogs/ -s eni-0abc123 -o sg.json
```

The traffic model is the same for every cloud, and so is most of the work:
deciding who opened each connection, and how exactly to name the peers.

**Who opened the connection.** A stateful rule allows the opening of a
conversation; replies come for free. Azure flow logs record connections, so
they say. AWS and Google Cloud flow logs record each direction separately,
and petrify decides, per conversation, in this order:

1. TCP flags, when the log has them (AWS custom format with `tcp-flags`).
2. Port numbers: a port below the ephemeral range is the server.
3. Traffic seen in one direction only: the receiver is the server.
4. Whichever side sent first.

If none of these settles it, both directions are allowed and a note says so.

**Whose traffic it is.** Google Cloud and Azure logs say which end is the
monitored VM or interface. For AWS, the interface's address is inferred as
the one present in every record. When that fails (a one-conversation log, a
CSV from a router), pass `--local CIDR`.

**Naming the peers.** Peers are listed exactly until a rule has more than
`--max-peers` (default 8); then prefixes widen step by step. Private addresses
never widen past their private range. A rule that ends up at `0.0.0.0/0` is
noted. Rejected flows are shown and never allowed.

The rules are written in the dialect of the cloud the log came from. `--policy`
overrides that, so a flow CSV or one cloud's flow log can become another
cloud's rules: `--policy gcp-firewall`, `azure-nsg` or `aws-security-group`.

#### AWS: security group

```sh
aws ec2 authorize-security-group-ingress --group-id sg-... \
    --ip-permissions "$(jq -c .IpPermissions sg.json)"
aws ec2 authorize-security-group-egress --group-id sg-... \
    --ip-permissions "$(jq -c .IpPermissionsEgress sg.json)"
```

A new security group allows all egress; revoke that rule or the egress rules
above constrain nothing. Reads the default flow log format and custom formats
that start with a header line (as delivered to S3).

#### Google Cloud: VPC firewall rules

```sh
gcloud logging read 'log_id("compute.googleapis.com/vpc_flows")' \
    --project=shop-prod --freshness=7d --format=json > flows.json
petrify generate flows.json -s orders-api -o firewall.json
```

The output is a list of `Firewall` resources for the Compute Engine API.

- The subject is the VM that reported the flow.
- The rules name no network and no target, because the flows cannot say which
  instances they are for. As written they would apply to every instance on
  the default network. Add `network` and `targetTags` or
  `targetServiceAccounts` to each before creating them:

  ```sh
  jq -c '.[] | .network = "projects/shop-prod/global/networks/prod"
             | .targetTags = ["orders-api"]' firewall.json |
  while read -r rule; do
    curl -sS -X POST -d "$rule" -H "Content-Type: application/json" \
      -H "Authorization: Bearer $(gcloud auth print-access-token)" \
      "https://compute.googleapis.com/compute/v1/projects/shop-prod/global/firewalls"
  done
  ```

- Google Cloud allows all egress unless a rule denies it, so the list ends
  with deny-all egress rules at priority 65534. Allow rules already on the
  network at a higher priority still apply.
- VPC Flow Logs do not mark denied traffic. Inbound packets a rule denied are
  simply absent, but outbound packets are logged before egress rules apply,
  so an outbound attempt that was refused looks like any other flow and is
  allowed by the generated rules. Check the egress rules against what the
  application should reach.

#### Azure: network security group rules

```sh
petrify generate PT1H.json -s 00224800AABB -o nsg.json
```

The output is a list of security rules, each a `name` and `properties` as in
an ARM template's `securityRules`.

```sh
NSG=/subscriptions/.../resourceGroups/orders/providers/Microsoft.Network/networkSecurityGroups/orders
jq -c '.[]' nsg.json | while read -r rule; do
  az rest --method put --body "$(jq -c '{properties}' <<<"$rule")" \
    --url "https://management.azure.com$NSG/securityRules/$(jq -r .name <<<"$rule")?api-version=2023-09-01"
done
```

- Reads virtual network flow logs and the older NSG flow logs (versions 1 and
  2). The subject is the interface's MAC address.
- Each direction ends with a deny-all rule at priority 4096. That overrides
  the default rules that allow all traffic within the virtual network and all
  outbound traffic to the internet, which is the point, but check that what
  the platform itself needs was in the recording (load balancer health
  probes from 168.63.129.16, for one).
- A security rule can only name TCP, UDP, ICMP, ESP and AH; other protocols
  are left out and noted.

#### Other flow sources

CSV with a header naming source, destination, ports and protocol (`nfdump -o
csv` and similar) is read as flows with no cloud of its own: the default
output is an AWS security group, and `--policy` picks another.

### Admission policy from a Kubernetes audit log

```sh
petrify show audit.log                       # lists the namespaces
petrify generate audit.log -s orders -o policy.json
kubectl apply -f policy.json
```

The subject is a namespace. The output is a `ValidatingAdmissionPolicy` and
the binding that applies it to that namespace. Both are built into the API
server (Kubernetes 1.30 and later), so there is nothing to install. From then
on, a pod in that namespace is admitted only if:

- every container's **image** comes from a repository that was observed, at
  any tag or digest (beyond `--max-images` repositories, default 20, they are
  summarised by registry path);
- its **service account** was observed;
- it has no **privileged** container, **host namespace** (`hostNetwork`,
  `hostPID`, `hostIPC`), added **capability** or **hostPath** volume beyond
  the ones observed. Whatever was observed stays allowed, and a note says so.

The policy checks pods, including ephemeral debug containers, and also
Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs and CronJobs, so a
Deployment asking for an image the policy forbids is refused when it is
applied, not when its pods quietly fail to appear.

**The audit policy has to record the objects.** Events at the `Metadata` level
say that a pod was created but not what was in it. Use `RequestResponse`,
which records each object as stored, after mutating webhooks have added to it;
`Request` works too, but shows pods as they were sent, without, say, a service
mesh's sidecar, and petrify notes when that is all it had.

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods", "pods/ephemeralcontainers", "replicationcontrollers"]
      - group: "apps"
        resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
      - group: "batch"
        resources: ["jobs", "cronjobs"]
  - level: Metadata
```

**Dry run first.** A policy built from a short recording will refuse the
workload nobody deployed that week.

```sh
# 1. Violations are admitted, with a warning to the client and an annotation
#    in the audit log (validation.policy.admission.k8s.io/validation_failure).
petrify generate audit.log -s orders --validation-action warn,audit -o policy.json
kubectl apply -f policy.json

# 2. Whatever was admitted is in the audit log now. Read the longer log.
petrify generate audit.log -s orders --validation-action warn,audit -o policy.json

# 3. When the warnings stop, drop --validation-action to enforce.
```

What it does not do:

- **It restricts; it does not require.** Nothing here insists on
  `runAsNonRoot`, a read-only root filesystem or dropped capabilities. Pod
  Security Admission does that, and the two work together: Pod Security says
  what no pod may do, petrify says which images and identities this namespace
  runs.
- It does not check image signatures or pin digests, and of the volume types
  only `hostPath` is restricted.
- Server-side dry runs in the log are ignored, since they deployed nothing.
- Objects that are being deleted are exempt, so that something which predates
  the policy can still be cleaned up. Any other change to such an object is
  refused until it conforms.

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
  Record for long enough, then roll out gradually: `SCMP_ACT_LOG` for seccomp
  and `--validation-action warn,audit` for Kubernetes; for IAM and firewall
  rules, apply to one instance and run petrify on the new logs, where denied
  calls and rejected flows show up by name.
- **Audit logs omit things.**
  - CloudTrail records data events (S3 objects, Lambda invokes, DynamoDB
    items) only if the trail is set to, and never records permissions that
    are checked without an API call of their own, `iam:PassRole` above all.
    Its event-to-action mapping here is maintained by hand and incomplete.
  - Google Cloud records most reads and writes of data only where Data Access
    audit logs are enabled.
  - The Azure Activity Log records no reads and no data-plane operations at
    all.
- **No conditions.** IAM policies carry no `Condition` blocks, Google Cloud
  roles come without the bindings that scope them, firewall rules reference
  address ranges rather than tags, groups or service accounts, and seccomp
  rules do not inspect arguments.
- **Azure flow tuples are read as connections.** In every documented sample
  the tuple's source is the end that opened the connection, and petrify
  relies on that, but the documentation does not state it as a rule.

[ROADMAP.md](ROADMAP.md) lists which of these are meant to change.

## Layout

```
src/sources/    one module per log format -> normalised events
src/cloud/      API calls -> IAM policy (aws), custom role (gcp, azure)
src/network/    flows     -> security group (aws), firewall rules (gcp), NSG rules (azure)
src/workloads/  workloads -> Kubernetes ValidatingAdmissionPolicy
src/syscalls.rs syscalls  -> seccomp profile
src/cli.rs      argument parsing, subject and policy selection, output
tests/          end-to-end tests against tests/fixtures/
```

A new log format is a module in `src/sources/` with `sniff` and `parse`, a
`Format` variant, and one arm in `Collector::feed`. A new policy for an
existing kind of behaviour (say, Kubernetes NetworkPolicy from flows) is a
module beside the others in `src/cloud/` or `src/network/` and a `Policy`
variant.

`src/syscall_tables.rs` is generated from kernel headers by
`scripts/gen_syscall_tables.py` (needs `linux-libc-dev` and `cpp`).

## Releasing

Every pull request runs formatting, clippy and the tests on Linux and macOS.

To release, raise `version` in `Cargo.toml` in a pull request (`cargo build`
updates `Cargo.lock` to match), merge it, and push a tag `vX.Y.Z` on main. The
Release workflow publishes only if the tag matches that version and is on
main, the same checks pass on the tagged commit, and each binary builds and
runs. It attaches static Linux binaries (x86_64, aarch64), macOS binaries
(Apple silicon, Intel) and their SHA-256 checksums.

A pull request that changes the release workflow runs the builds as a dry
run, without publishing.

## License

MIT. See [LICENSE](LICENSE).
