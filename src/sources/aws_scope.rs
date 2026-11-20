//! Scoping an AWS call to the resources its request named, for the services
//! covered by the generated [`aws_reference`](super::aws_reference).
//!
//! An IAM action can only be limited to the resource types it supports, and
//! a call can involve several of them: attaching a volume needs both the
//! volume and the instance. So the rule here is, for each resource type the
//! action supports:
//!
//! - the ARNs of the resources of that type the request named, or
//! - if it named none, every resource of that type (`vpc/*`).
//!
//! That never grants less than the call needed, as far as the reference
//! knows, and it pins down whatever the log does show. An action that
//! supports no resource type, or whose request names nothing of use, is left
//! to the caller to grant on `*`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::aws_reference::{self, MANY, Service};
use super::text;

/// Where a call was made, for filling in ARNs.
pub(crate) struct Place<'a> {
    pub partition: &'a str,
    pub region: &'a str,
    pub account: &'a str,
}

/// EC2 resource IDs start with a prefix that says what they are. Longer
/// prefixes first, where one begins with another.
const EC2_IDS: [(&str, &str); 28] = [
    ("tgw-attach-", "transit-gateway-attachment"),
    ("tgw-rtb-", "transit-gateway-route-table"),
    ("tgw-", "transit-gateway"),
    ("eipalloc-", "elastic-ip"),
    ("subnet-", "subnet"),
    ("snap-", "snapshot"),
    ("vpce-", "vpc-endpoint"),
    ("eigw-", "egress-only-internet-gateway"),
    ("dopt-", "dhcp-options"),
    ("vpc-", "vpc"),
    ("vol-", "volume"),
    ("ami-", "image"),
    ("eni-", "network-interface"),
    ("rtb-", "route-table"),
    ("igw-", "internet-gateway"),
    ("nat-", "natgateway"),
    ("acl-", "network-acl"),
    ("pcx-", "vpc-peering-connection"),
    ("vgw-", "vpn-gateway"),
    ("cgw-", "customer-gateway"),
    ("vpn-", "vpn-connection"),
    ("sgr-", "security-group-rule"),
    ("sg-", "security-group"),
    ("fl-", "vpc-flow-log"),
    ("lt-", "launch-template"),
    ("pl-", "prefix-list"),
    ("cr-", "capacity-reservation"),
    ("i-", "instance"),
];

/// IAM request parameters that name a resource, and its type.
const IAM_PARAMETERS: [(&str, &str); 10] = [
    ("roleName", "role"),
    ("userName", "user"),
    ("groupName", "group"),
    ("instanceProfileName", "instance-profile"),
    ("policyArn", "policy"),
    ("policyName", "policy"),
    ("virtualMFADeviceName", "mfa"),
    ("serverCertificateName", "server-certificate"),
    ("sAMLProviderArn", "saml-provider"),
    ("openIDConnectProviderArn", "oidc-provider"),
];

/// How RDS request parameters that name a resource end, lower-cased, and
/// its type. Parameters come with prefixes (`source...`, `final...`), and
/// longer endings come first where one ends with another.
const RDS_PARAMETERS: [(&str, &str); 10] = [
    ("dbclustersnapshotidentifier", "cluster-snapshot"),
    ("dbsnapshotidentifier", "snapshot"),
    ("globalclusteridentifier", "global-cluster"),
    ("dbclusteridentifier", "cluster"),
    ("dbinstanceidentifier", "db"),
    ("dbsubnetgroupname", "subgrp"),
    ("dbclusterparametergroupname", "cluster-pg"),
    ("dbparametergroupname", "pg"),
    ("optiongroupname", "og"),
    ("dbsecuritygroupname", "secgrp"),
];

/// The resources to grant `service:action` on for one call, or `None` when
/// the reference or the request has nothing to narrow it with. `caller` is
/// the ARN of the IAM user who made the call, if it was one.
pub(crate) fn resources(
    service: &str,
    action: &str,
    params: &Value,
    caller: Option<&str>,
    place: &Place,
) -> Option<Vec<String>> {
    let reference = aws_reference::service(service)?;
    let types = lookup(reference.actions, action)?;
    if types.is_empty() || types == MANY {
        return None;
    }

    let mut named: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut name = |kind: &'static str, value: &str| {
        // Something the action cannot be limited to is context, not a target.
        if !types.contains(&kind) {
            return;
        }
        let arns = named.entry(kind).or_default();
        if value.starts_with("arn:") {
            arns.insert(value.to_string());
        } else if let Some(format) = lookup(reference.arns, kind) {
            arns.extend(fill(format, place, value));
        }
    };
    match service {
        "iam" => iam(params, caller, types, &mut name),
        "ec2" => ec2(params, &mut name),
        "rds" => rds(params, reference, &mut name),
        _ => {}
    }
    if named.is_empty() {
        return None;
    }

    let mut out = Vec::new();
    for kind in types {
        match named.get(kind) {
            Some(arns) => out.extend(arns.iter().cloned()),
            None => out.extend(lookup(reference.arns, kind).map(|format| any(format, place))),
        }
    }
    Some(out)
}

fn lookup<T: Copy>(table: &[(&str, T)], key: &str) -> Option<T> {
    let index = table.binary_search_by_key(&key, |(name, _)| name).ok()?;
    Some(table[index].1)
}

fn iam(
    params: &Value,
    caller: Option<&str>,
    types: &[&str],
    name: &mut dyn FnMut(&'static str, &str),
) {
    for (parameter, kind) in IAM_PARAMETERS {
        if let Some(value) = text(params, parameter) {
            name(kind, value);
        }
    }
    // Calls about a user that name no user are about the caller: GetUser,
    // CreateAccessKey, ListMFADevices and the like.
    if types.contains(&"user")
        && text(params, "userName").is_none()
        && let Some(caller) = caller
    {
        name("user", caller);
    }
    // A virtual MFA device's serial number is its ARN.
    if let Some(serial) = text(params, "serialNumber").filter(|serial| serial.starts_with("arn:")) {
        name("mfa", serial);
    }
}

/// EC2 requests nest their targets differently for every action, but an ID
/// is recognisable wherever it sits.
fn ec2(params: &Value, name: &mut dyn FnMut(&'static str, &str)) {
    match params {
        Value::String(value) => {
            let known = EC2_IDS.iter().find(|(prefix, _)| {
                value.strip_prefix(prefix).is_some_and(|rest| {
                    rest.len() >= 8 && rest.bytes().all(|b| b.is_ascii_hexdigit())
                })
            });
            if let Some((_, kind)) = known {
                name(kind, value);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| ec2(item, name)),
        Value::Object(map) => {
            for (key, value) in map {
                match value.as_str() {
                    Some(key_pair) if key == "keyName" => name("key-pair", key_pair),
                    _ => ec2(value, name),
                }
            }
        }
        _ => {}
    }
}

fn rds(params: &Value, reference: &Service, name: &mut dyn FnMut(&'static str, &str)) {
    let Some(map) = params.as_object() else {
        return;
    };
    for (key, value) in map {
        let Some(value) = value.as_str().filter(|value| !value.is_empty()) else {
            continue;
        };
        let key = key.to_lowercase();
        if value.starts_with("arn:") {
            // An identifier given as an ARN, or `resourceName`, which always
            // is one: the ARN itself says what it names.
            let kind = reference
                .arns
                .iter()
                .find(|(_, format)| same_kind(format, value));
            if let Some((kind, _)) = kind {
                name(kind, value);
            }
        } else if let Some((_, kind)) = RDS_PARAMETERS.iter().find(|(end, _)| key.ends_with(end)) {
            // RDS stores identifiers in lower case, whatever case was sent.
            name(kind, &value.to_lowercase());
        }
    }
}

/// Whether an RDS ARN is of the type an ARN format describes: both have the
/// type as the sixth colon-separated field (`...:db:name`).
fn same_kind(format: &str, arn: &str) -> bool {
    let kind = |text: &str| text.split(':').nth(5).map(str::to_string);
    kind(format).is_some() && kind(format) == kind(arn)
}

/// An ARN format with its placeholders filled in.
fn fill_with(format: &str, place: &Place, value: &str) -> String {
    let mut out = String::new();
    let mut rest = format;
    let mut used = false;
    while let Some(start) = rest.find("${") {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        out.push_str(&rest[..start]);
        out.push_str(match &rest[start + 2..start + end] {
            "Partition" => place.partition,
            "Region" => place.region,
            "Account" => place.account,
            // The first other placeholder is the resource's name or ID.
            // A format with more than one is a sub-resource; take them all.
            _ if !used => {
                used = true;
                value
            }
            _ => "*",
        });
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}

/// The ARNs for a resource called `value`. IAM names can sit under a path
/// (`role/service-role/name`) that the request does not give, so a name
/// without one is allowed with any path or none.
fn fill(format: &str, place: &Place, value: &str) -> Vec<String> {
    let exact = fill_with(format, place, value);
    if format.ends_with("WithPath}") && !value.contains('/') {
        vec![fill_with(format, place, &format!("*/{value}")), exact]
    } else {
        vec![exact]
    }
}

/// The ARN pattern for every resource of a type.
fn any(format: &str, place: &Place) -> String {
    fill_with(format, place, "*")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PLACE: Place = Place {
        partition: "aws",
        region: "eu-west-1",
        account: "111122223333",
    };

    fn scoped(service: &str, action: &str, params: Value) -> Option<Vec<String>> {
        resources(service, action, &params, None, &PLACE)
    }

    fn arns(found: Option<Vec<String>>) -> Vec<String> {
        found.expect("the call should be scoped")
    }

    #[test]
    fn every_mapped_type_is_one_the_reference_knows() {
        let known = |service: &str, kind: &str| {
            lookup(aws_reference::service(service).unwrap().arns, kind).is_some()
        };
        for (_, kind) in EC2_IDS {
            assert!(known("ec2", kind), "ec2 {kind}");
        }
        assert!(known("ec2", "key-pair"));
        for (_, kind) in IAM_PARAMETERS {
            assert!(known("iam", kind), "iam {kind}");
        }
        for (_, kind) in RDS_PARAMETERS {
            assert!(known("rds", kind), "rds {kind}");
        }
    }

    #[test]
    fn iam_names_are_allowed_under_any_path() {
        assert_eq!(
            arns(scoped("iam", "GetRole", json!({"roleName": "app"}))),
            [
                "arn:aws:iam::111122223333:role/*/app",
                "arn:aws:iam::111122223333:role/app"
            ]
        );
        assert_eq!(
            arns(scoped(
                "iam",
                "DeletePolicy",
                json!({"policyArn": "arn:aws:iam::1:policy/p"})
            )),
            ["arn:aws:iam::1:policy/p"]
        );
    }

    #[test]
    fn what_an_action_cannot_be_limited_to_is_not_a_resource() {
        // Attaching a policy is authorised against the role; the policy is
        // a condition key, not a resource.
        let attach = json!({"roleName": "app", "policyArn": "arn:aws:iam::aws:policy/Admin"});
        assert_eq!(
            arns(scoped("iam", "AttachRolePolicy", attach)),
            [
                "arn:aws:iam::111122223333:role/*/app",
                "arn:aws:iam::111122223333:role/app"
            ]
        );
        // An inline policy's name is not a managed policy.
        let put = json!({"roleName": "app", "policyName": "inline"});
        assert_eq!(arns(scoped("iam", "PutRolePolicy", put)).len(), 2);
        // Nothing to limit these to at all.
        assert_eq!(scoped("iam", "ListRoles", json!({})), None);
        assert_eq!(
            scoped(
                "ec2",
                "DescribeInstances",
                json!({"instancesSet": {"items": [{"instanceId": "i-0123456789abcdef0"}]}})
            ),
            None
        );
        assert_eq!(
            scoped(
                "ec2",
                "CreateTags",
                json!({"resourcesSet": {"items": [{"resourceId": "vpc-0123456789abcdef0"}]}})
            ),
            None
        );
        assert_eq!(
            scoped("iam", "NotAnAction", json!({"roleName": "app"})),
            None
        );
        assert_eq!(scoped("sqs", "SendMessage", json!({})), None);
    }

    #[test]
    fn a_call_about_no_named_user_is_about_the_caller() {
        let me = "arn:aws:iam::111122223333:user/alice";
        let own = |params: Value| resources("iam", "GetUser", &params, Some(me), &PLACE);
        assert_eq!(arns(own(json!({}))), [me]);
        assert_eq!(arns(own(Value::Null)), [me]);
        assert_eq!(
            arns(own(json!({"userName": "bob"}))),
            [
                "arn:aws:iam::111122223333:user/*/bob",
                "arn:aws:iam::111122223333:user/bob"
            ]
        );
        // A role has no user of its own to fall back on.
        assert_eq!(scoped("iam", "GetUser", json!({})), None);
    }

    #[test]
    fn ec2_ids_are_found_wherever_the_request_puts_them() {
        let terminate = json!({"instancesSet": {"items": [
            {"instanceId": "i-05c30218156bcc246"}, {"instanceId": "i-0aaaaaaaaaaaaaaaa"},
        ]}});
        assert_eq!(
            arns(scoped("ec2", "TerminateInstances", terminate)),
            [
                "arn:aws:ec2:eu-west-1:111122223333:instance/i-05c30218156bcc246",
                "arn:aws:ec2:eu-west-1:111122223333:instance/i-0aaaaaaaaaaaaaaaa",
            ]
        );
        let nat = json!({"DeleteNatGatewayRequest": {"NatGatewayId": "nat-0dd264ee104155137"}});
        assert_eq!(
            arns(scoped("ec2", "DeleteNatGateway", nat)),
            ["arn:aws:ec2:eu-west-1:111122223333:natgateway/nat-0dd264ee104155137"]
        );
        // Snapshots and images have no account in their ARN.
        let snapshot = json!({"snapshotId": "snap-083d3b857c13988bc"});
        assert_eq!(
            arns(scoped("ec2", "ModifySnapshotAttribute", snapshot)),
            ["arn:aws:ec2:eu-west-1::snapshot/snap-083d3b857c13988bc"]
        );
        let key = json!({"keyName": "deploy"});
        assert_eq!(
            arns(scoped("ec2", "DeleteKeyPair", key)),
            ["arn:aws:ec2:eu-west-1:111122223333:key-pair/deploy"]
        );
    }

    #[test]
    fn types_the_request_does_not_name_are_allowed_whole() {
        // Both ends of an attachment are needed, and both are named.
        let attach =
            json!({"volumeId": "vol-0123456789abcdef0", "instanceId": "i-0123456789abcdef0"});
        assert_eq!(
            arns(scoped("ec2", "AttachVolume", attach)),
            [
                "arn:aws:ec2:eu-west-1:111122223333:instance/i-0123456789abcdef0",
                "arn:aws:ec2:eu-west-1:111122223333:volume/vol-0123456789abcdef0",
            ]
        );
        // A new subnet has no ID yet; the VPC it goes in does.
        let create = json!({"vpcId": "vpc-07b33857c7ad1c027", "cidrBlock": "10.0.2.0/24"});
        assert_eq!(
            arns(scoped("ec2", "CreateSubnet", create)),
            [
                "arn:aws:ec2::111122223333:ipam-pool/*",
                "arn:aws:ec2:eu-west-1:111122223333:subnet/*",
                "arn:aws:ec2:eu-west-1:111122223333:vpc/vpc-07b33857c7ad1c027",
            ]
        );
        // Naming nothing leaves nothing to narrow with.
        assert_eq!(
            scoped("ec2", "CreateVpc", json!({"cidrBlock": "10.0.0.0/16"})),
            None
        );
        // An ID-shaped string that is not one is ignored.
        assert_eq!(
            scoped("ec2", "DeleteVpc", json!({"vpcId": "vpc-default"})),
            None
        );
    }

    #[test]
    fn rds_identifiers_become_lower_case_arns() {
        let delete = json!({
            "dBInstanceIdentifier": "Orders-DB",
            "finalDBSnapshotIdentifier": "orders-final",
            "skipFinalSnapshot": false,
        });
        // The final snapshot is named too, but deleting an instance cannot
        // be limited to a snapshot, so it is left out.
        assert_eq!(
            arns(scoped("rds", "DeleteDBInstance", delete)),
            ["arn:aws:rds:eu-west-1:111122223333:db:orders-db"]
        );
        let share = json!({"dBSnapshotIdentifier": "exfiltration", "attributeName": "restore"});
        assert_eq!(
            arns(scoped("rds", "ModifyDBSnapshotAttribute", share)),
            ["arn:aws:rds:eu-west-1:111122223333:snapshot:exfiltration"]
        );
        // A cluster snapshot is not an instance snapshot.
        let cluster = json!({"dBClusterSnapshotIdentifier": "weekly"});
        assert_eq!(
            arns(scoped("rds", "DeleteDBClusterSnapshot", cluster)),
            ["arn:aws:rds:eu-west-1:111122223333:cluster-snapshot:weekly"]
        );
    }

    #[test]
    fn an_rds_arn_says_what_it_names() {
        // An identifier given as an ARN (a snapshot shared from another
        // account) is used as it is, under the type the ARN names.
        let shared = "arn:aws:rds:us-east-1:444455556666:snapshot:shared";
        let copy = json!({
            "sourceDBSnapshotIdentifier": shared,
            "targetDBSnapshotIdentifier": "Copy",
        });
        assert_eq!(
            arns(scoped("rds", "CopyDBSnapshot", copy)),
            ["arn:aws:rds:eu-west-1:111122223333:snapshot:copy", shared]
        );
        // Tagging takes any of two dozen types: too many to list.
        let tags = json!({"resourceName": "arn:aws:rds:us-east-1:111122223333:subgrp:shared"});
        assert_eq!(scoped("rds", "ListTagsForResource", tags), None);
    }
}
