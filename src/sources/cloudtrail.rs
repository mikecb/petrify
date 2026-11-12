//! AWS CloudTrail -> [`ApiCall`].
//!
//! CloudTrail records what was *called*; IAM policies are written in terms of
//! what is *authorised*. The two vocabularies mostly agree, and this module
//! holds the places where they do not. Everything here is best effort:
//! validate the result with `aws accessanalyzer validate-policy` before
//! relying on it.

use std::io::{self, BufRead};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::events::{ApiCall, Notes};
use crate::sources::{json_documents, text};

pub fn sniff(head: &str) -> bool {
    head.contains("\"eventSource\"") || head.contains("\"CloudTrailEvent\"")
}

/// Accepts every shape CloudTrail events are commonly found in: an S3
/// delivery file (`{"Records": [...]}`), `aws cloudtrail lookup-events`
/// output, EventBridge envelopes, a bare list, or one JSON object per line.
pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(ApiCall),
) -> io::Result<()> {
    let documents = json_documents(reader, notes)?;
    for document in &documents {
        unwrap(document, notes, emit);
    }
    Ok(())
}

fn unwrap(document: &Value, notes: &mut Notes, emit: &mut dyn FnMut(ApiCall)) {
    match document {
        Value::Array(items) => items.iter().for_each(|item| unwrap(item, notes, emit)),
        Value::Object(map) => {
            if map.contains_key("eventSource") && map.contains_key("eventName") {
                calls(document, emit);
            } else if let Some(inner) = map.get("CloudTrailEvent") {
                match inner.as_str().map(serde_json::from_str::<Value>) {
                    Some(Ok(event)) => unwrap(&event, notes, emit),
                    _ => notes.add("skipped an unparseable CloudTrailEvent"),
                }
            } else {
                for key in ["Records", "Events", "detail"] {
                    if let Some(inner) = map.get(key) {
                        unwrap(inner, notes, emit);
                    }
                }
            }
        }
        _ => {}
    }
}

// -- record -> calls ---------------------------------------------------------

static DENIED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)AccessDenied|Unauthorized|AuthorizationError|Forbidden").unwrap()
});
/// Lambda event names carry the API version: `GetFunction20150331v2`.
static LAMBDA_VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d{8}(v\d+)?$").unwrap());
static ASSUMED_ROLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^arn:([^:]+):sts::(\d*):assumed-role/([^/]+)/").unwrap());
static AWS_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.amazonaws\.com(\.cn)?$").unwrap());
static SQS_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^https?://sqs\.([^.]+)\.[^/]+/(\d+)/([^/?]+)").unwrap());
static KMS_KEY_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(mrk-)?[0-9a-f-]{32,36}$").unwrap());

fn calls(record: &Value, emit: &mut dyn FnMut(ApiCall)) {
    if text(record, "eventType").unwrap_or("AwsApiCall") != "AwsApiCall" {
        return; // service-side events and console sign-ins need no IAM action
    }
    let identity = record.get("userIdentity").unwrap_or(&Value::Null);
    let (Some(subject), Some(source), Some(name)) = (
        subject(identity),
        text(record, "eventSource"),
        text(record, "eventName"),
    ) else {
        return;
    };
    if source.starts_with("signin.") {
        return;
    }

    let service = service(source);
    let params = record.get("requestParameters").unwrap_or(&Value::Null);
    let context = Context::new(record, identity);
    let denied = text(record, "errorCode").is_some_and(|code| DENIED.is_match(code));
    let mut call = |action: String, resources: Vec<String>| {
        emit(ApiCall {
            subject: subject.clone(),
            action: format!("{service}:{action}"),
            resources,
            denied,
        })
    };

    if service == "s3" {
        s3_calls(name, params, &context, &mut call);
        return;
    }
    let action = if service == "lambda" {
        let bare = LAMBDA_VERSION.replace(name, "");
        match bare.as_ref() {
            "Invoke" | "InvokeAsync" | "InvokeWithResponseStream" => "InvokeFunction".to_string(),
            other => other.to_string(),
        }
    } else {
        name.to_string()
    };
    call(action, resources(record, &service, params, &context));
}

/// The durable identity behind a call: the role, not the session.
fn subject(identity: &Value) -> Option<String> {
    let kind = text(identity, "type");
    if kind == Some("AWSService") {
        return None;
    }
    let arn = text(identity, "arn");
    if kind == Some("AssumedRole") {
        let issuer = identity
            .get("sessionContext")
            .and_then(|c| c.get("sessionIssuer"));
        if let Some(role) = issuer.and_then(|issuer| text(issuer, "arn")) {
            return Some(role.to_string());
        }
        if let Some(found) = arn.and_then(|arn| ASSUMED_ROLE.captures(arn)) {
            return Some(format!(
                "arn:{}:iam::{}:role/{}",
                &found[1], &found[2], &found[3]
            ));
        }
    }
    Some(
        arn.or(text(identity, "principalId"))
            .or(kind)
            .unwrap_or("unknown")
            .to_string(),
    )
}

/// `eventSource` host -> IAM service prefix. Usually the last DNS label
/// before `.amazonaws.com`; the exceptions are listed.
fn service(source: &str) -> String {
    let host = AWS_HOST.replace(source, "");
    match host.as_ref() {
        "monitoring" => "cloudwatch",
        "email" => "ses",
        "tagging" => "tag",
        "cloudcontrolapi" => "cloudformation",
        other => other.rsplit('.').next().unwrap_or(other),
    }
    .to_string()
}

/// What is needed to build an ARN from a bare resource name.
struct Context {
    partition: &'static str,
    region: String,
    account: String,
}

impl Context {
    fn new(record: &Value, identity: &Value) -> Context {
        let region = text(record, "awsRegion").unwrap_or("*").to_string();
        let account = text(record, "recipientAccountId")
            .or(text(identity, "accountId"))
            .unwrap_or("*")
            .to_string();
        let partition = if region.starts_with("cn-") {
            "aws-cn"
        } else if region.starts_with("us-gov-") {
            "aws-us-gov"
        } else {
            "aws"
        };
        Context {
            partition,
            region,
            account,
        }
    }

    fn arn(&self, service: &str, resource: &str) -> String {
        format!(
            "arn:{}:{service}:{}:{}:{resource}",
            self.partition, self.region, self.account
        )
    }

    /// `value` if it already is an ARN, else an ARN built around it.
    fn named(&self, service: &str, prefix: &str, value: Option<&str>) -> Option<String> {
        let value = value?;
        Some(if value.starts_with("arn:") {
            value.to_string()
        } else {
            self.arn(service, &format!("{prefix}{value}"))
        })
    }
}

// -- S3 ----------------------------------------------------------------------

/// S3 is the service where API names and IAM actions disagree most.
fn s3_action(name: &str) -> &str {
    match name {
        "ListObjects" | "ListObjectsV2" | "HeadBucket" => "ListBucket",
        "ListObjectVersions" => "ListBucketVersions",
        "ListBuckets" => "ListAllMyBuckets",
        "HeadObject" | "SelectObjectContent" => "GetObject",
        "DeleteObjects" => "DeleteObject",
        "CopyObject"
        | "CreateMultipartUpload"
        | "UploadPart"
        | "UploadPartCopy"
        | "CompleteMultipartUpload" => "PutObject",
        "ListMultipartUploads" => "ListBucketMultipartUploads",
        "ListParts" => "ListMultipartUploadParts",
        "GetBucketCors" => "GetBucketCORS",
        "PutBucketCors" | "DeleteBucketCors" => "PutBucketCORS",
        "GetBucketLifecycle" | "GetBucketLifecycleConfiguration" => "GetLifecycleConfiguration",
        "PutBucketLifecycle" | "PutBucketLifecycleConfiguration" | "DeleteBucketLifecycle" => {
            "PutLifecycleConfiguration"
        }
        "GetBucketEncryption" => "GetEncryptionConfiguration",
        "PutBucketEncryption" | "DeleteBucketEncryption" => "PutEncryptionConfiguration",
        "GetBucketReplication" => "GetReplicationConfiguration",
        "PutBucketReplication" | "DeleteBucketReplication" => "PutReplicationConfiguration",
        "GetBucketAccelerateConfiguration" => "GetAccelerateConfiguration",
        "PutBucketAccelerateConfiguration" => "PutAccelerateConfiguration",
        "GetBucketInventoryConfiguration" => "GetInventoryConfiguration",
        "GetBucketMetricsConfiguration" => "GetMetricsConfiguration",
        "GetBucketAnalyticsConfiguration" => "GetAnalyticsConfiguration",
        "GetBucketIntelligentTieringConfiguration" => "GetIntelligentTieringConfiguration",
        "GetBucketNotificationConfiguration" => "GetBucketNotification",
        "PutBucketNotificationConfiguration" => "PutBucketNotification",
        "GetPublicAccessBlock" => "GetBucketPublicAccessBlock",
        "PutPublicAccessBlock" | "DeletePublicAccessBlock" => "PutBucketPublicAccessBlock",
        "GetObjectLockConfiguration" => "GetBucketObjectLockConfiguration",
        "PutObjectLockConfiguration" => "PutBucketObjectLockConfiguration",
        "DeleteBucketTagging" => "PutBucketTagging",
        same => same,
    }
}

/// Reading or deleting a specific object version is a separate permission.
fn s3_versioned(action: &str) -> &str {
    match action {
        "GetObject" => "GetObjectVersion",
        "DeleteObject" => "DeleteObjectVersion",
        "GetObjectAcl" => "GetObjectVersionAcl",
        "PutObjectAcl" => "PutObjectVersionAcl",
        "GetObjectTagging" => "GetObjectVersionTagging",
        "PutObjectTagging" => "PutObjectVersionTagging",
        "DeleteObjectTagging" => "DeleteObjectVersionTagging",
        same => same,
    }
}

fn s3_calls(
    name: &str,
    params: &Value,
    context: &Context,
    call: &mut dyn FnMut(String, Vec<String>),
) {
    let mut action = s3_action(name);
    if text(params, "versionId").is_some() {
        action = s3_versioned(action);
    }
    let resource = s3_resource(
        action,
        text(params, "bucketName"),
        text(params, "key"),
        context,
    );
    call(action.to_string(), vec![resource]);

    if matches!(name, "CopyObject" | "UploadPartCopy") {
        // The copy source is read with the caller's own s3:GetObject.
        let source = percent_decode(text(params, "x-amz-copy-source").unwrap_or(""));
        let source = source.trim_start_matches('/');
        if let Some((bucket, key)) = source.split_once('/') {
            let key = key.split('?').next().filter(|key| !key.is_empty());
            if !bucket.is_empty() && key.is_some() {
                let resource = s3_resource("GetObject", Some(bucket), key, context);
                call("GetObject".to_string(), vec![resource]);
            }
        }
    }
}

fn s3_resource(action: &str, bucket: Option<&str>, key: Option<&str>, context: &Context) -> String {
    let Some(bucket) = bucket else {
        return "*".to_string();
    };
    let arn = format!("arn:{}:s3:::{bucket}", context.partition);
    let object_level = (action.contains("Object") && !action.contains("Bucket"))
        || matches!(action, "AbortMultipartUpload" | "ListMultipartUploadParts");
    if object_level {
        format!("{arn}/{}", key.unwrap_or("*"))
    } else {
        arn
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes
            .get(index + 1..index + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok());
        match (
            bytes[index],
            hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()),
        ) {
            (b'%', Some(byte)) => {
                out.push(byte);
                index += 3;
            }
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// -- everything else ---------------------------------------------------------

fn resources(record: &Value, service: &str, params: &Value, context: &Context) -> Vec<String> {
    // `resources[].ARN` entries that belong to a different service than the
    // call are context (a KMS key on an S3 write), not the thing authorised.
    // STS is the exception: it authorises against IAM roles.
    let mut found: Vec<String> = Vec::new();
    for entry in record
        .get("resources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(arn) = text(entry, "ARN") else {
            continue;
        };
        let fields: Vec<&str> = arn.splitn(6, ':').collect();
        if fields.len() == 6 && (fields[2] == service || (service == "sts" && fields[2] == "iam")) {
            found.push(arn.to_string());
        }
    }
    if found.is_empty() {
        found = derive(service, params, context);
    }
    if let (true, Some(index)) = (service == "dynamodb", text(params, "indexName")) {
        // Querying an index is authorised against the index, which
        // CloudTrail's `resources` list does not mention.
        let tables: Vec<String> = found
            .iter()
            .filter(|arn| !arn.contains("/index/"))
            .cloned()
            .collect();
        found.extend(tables.iter().map(|arn| format!("{arn}/index/{index}")));
    }
    let mut unique: Vec<String> = Vec::with_capacity(found.len());
    for arn in found {
        if !unique.contains(&arn) {
            unique.push(arn);
        }
    }
    if unique.is_empty() {
        unique.push("*".to_string());
    }
    unique
}

/// Build ARNs from request parameters, for the services where the mapping
/// is simple and stable.
fn derive(service: &str, params: &Value, context: &Context) -> Vec<String> {
    let one = |arn: Option<String>| arn.into_iter().collect::<Vec<_>>();
    match service {
        "dynamodb" => one(context.named("dynamodb", "table/", text(params, "tableName"))),
        "sns" => {
            let topic = text(params, "topicArn").or(text(params, "targetArn"));
            one(context.named("sns", "", topic))
        }
        "lambda" => one(context.named("lambda", "function:", text(params, "functionName"))),
        "sqs" => {
            // https://sqs.<region>.amazonaws.com/<account>/<queue>
            let url = text(params, "queueUrl").and_then(|url| SQS_URL.captures(url));
            one(url.map(|u| {
                format!(
                    "arn:{}:sqs:{}:{}:{}",
                    context.partition, &u[1], &u[2], &u[3]
                )
            }))
        }
        "secretsmanager" => one(text(params, "secretId").map(|secret| {
            if secret.starts_with("arn:") {
                secret.to_string()
            } else {
                // Secrets Manager appends a random suffix to every ARN.
                context.arn("secretsmanager", &format!("secret:{secret}-??????"))
            }
        })),
        "ssm" => {
            let mut names: Vec<String> = Vec::new();
            for name in params
                .get("names")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                names.extend(name.as_str().map(String::from));
            }
            names.extend(text(params, "name").map(String::from));
            names.extend(text(params, "path").map(|p| format!("{}/*", p.trim_end_matches('/'))));
            names
                .iter()
                .filter_map(|name| {
                    let bare = if name.starts_with("arn:") {
                        name
                    } else {
                        name.trim_start_matches('/')
                    };
                    context.named("ssm", "parameter/", Some(bare))
                })
                .collect()
        }
        "kms" => one(text(params, "keyId").and_then(|key| {
            if key.starts_with("arn:") && key.contains(":key/") {
                Some(key.to_string())
            } else if KMS_KEY_ID.is_match(key) {
                Some(context.arn("kms", &format!("key/{key}")))
            } else {
                None // aliases are not a resource KMS authorises against
            }
        })),
        "logs" => one(text(params, "logGroupName")
            .map(|group| context.arn("logs", &format!("log-group:{group}:*")))),
        "sts" => one(text(params, "roleArn").map(String::from)),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn event(source: &str, name: &str, params: Value) -> Value {
        json!({
            "eventSource": source,
            "eventName": name,
            "awsRegion": "eu-west-1",
            "recipientAccountId": "111122223333",
            "requestParameters": params,
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/app"},
        })
    }

    fn with(mut event: Value, key: &str, value: Value) -> Value {
        event[key] = value;
        event
    }

    fn parse_text(text: &str) -> (Vec<ApiCall>, Notes) {
        let (mut found, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), &mut notes, &mut |call| {
            found.push(call)
        })
        .unwrap();
        (found, notes)
    }

    /// (service:Action, resources) for each call the events produce.
    fn calls(events: Value) -> Vec<(String, Vec<String>)> {
        let (found, _) = parse_text(&json!({ "Records": events }).to_string());
        found.into_iter().map(|c| (c.action, c.resources)).collect()
    }

    fn expect(action: &str, resources: &[&str]) -> (String, Vec<String>) {
        (
            action.to_string(),
            resources.iter().map(|r| r.to_string()).collect(),
        )
    }

    #[test]
    fn s3_api_names_become_iam_actions() {
        let found = calls(json!([
            event(
                "s3.amazonaws.com",
                "ListObjectsV2",
                json!({"bucketName": "b"})
            ),
            event(
                "s3.amazonaws.com",
                "HeadObject",
                json!({"bucketName": "b", "key": "k"})
            ),
            event(
                "s3.amazonaws.com",
                "DeleteObjects",
                json!({"bucketName": "b"})
            ),
            event("s3.amazonaws.com", "ListBuckets", Value::Null),
        ]));
        assert_eq!(
            found,
            [
                expect("s3:ListBucket", &["arn:aws:s3:::b"]),
                expect("s3:GetObject", &["arn:aws:s3:::b/k"]),
                expect("s3:DeleteObject", &["arn:aws:s3:::b/*"]),
                expect("s3:ListAllMyBuckets", &["*"]),
            ]
        );
    }

    #[test]
    fn s3_versions_and_copies_need_extra_permissions() {
        let found = calls(json!([
            event(
                "s3.amazonaws.com",
                "GetObject",
                json!({"bucketName": "b", "key": "k", "versionId": "v1"})
            ),
            event(
                "s3.amazonaws.com",
                "CopyObject",
                json!({
                    "bucketName": "dst",
                    "key": "k",
                    "x-amz-copy-source": "/src/a%20b.txt?versionId=3"
                })
            ),
        ]));
        assert_eq!(
            found,
            [
                expect("s3:GetObjectVersion", &["arn:aws:s3:::b/k"]),
                expect("s3:PutObject", &["arn:aws:s3:::dst/k"]),
                expect("s3:GetObject", &["arn:aws:s3:::src/a b.txt"]),
            ]
        );
    }

    #[test]
    fn lambda_event_names_lose_their_api_version() {
        let function = "arn:aws:lambda:eu-west-1:111122223333:function:f";
        let found = calls(json!([
            event(
                "lambda.amazonaws.com",
                "Invoke",
                json!({"functionName": "f"})
            ),
            event(
                "lambda.amazonaws.com",
                "UpdateFunctionCode20150331v2",
                json!({"functionName": "f"})
            ),
        ]));
        assert_eq!(
            found,
            [
                expect("lambda:InvokeFunction", &[function]),
                expect("lambda:UpdateFunctionCode", &[function]),
            ]
        );
    }

    #[test]
    fn service_prefix_can_differ_from_event_source() {
        let found = calls(json!([
            event("monitoring.amazonaws.com", "PutMetricData", Value::Null),
            event("email.amazonaws.com", "SendEmail", Value::Null),
            event(
                "runtime.sagemaker.amazonaws.com",
                "InvokeEndpoint",
                Value::Null
            ),
        ]));
        let actions: Vec<&str> = found.iter().map(|(action, _)| action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "cloudwatch:PutMetricData",
                "ses:SendEmail",
                "sagemaker:InvokeEndpoint"
            ]
        );
    }

    #[test]
    fn resources_of_another_service_are_context_not_targets() {
        let get = with(
            event(
                "dynamodb.amazonaws.com",
                "GetItem",
                json!({"tableName": "T"}),
            ),
            "resources",
            json!([
                {"ARN": "arn:aws:kms:eu-west-1:111122223333:key/abc"},
                {"ARN": "arn:aws:dynamodb:eu-west-1:111122223333:table/T"},
            ]),
        );
        let assume = with(
            event("sts.amazonaws.com", "AssumeRole", Value::Null),
            "resources",
            json!([{"ARN": "arn:aws:iam::444455556666:role/partner"}]),
        );
        assert_eq!(
            calls(json!([get, assume])),
            [
                expect(
                    "dynamodb:GetItem",
                    &["arn:aws:dynamodb:eu-west-1:111122223333:table/T"]
                ),
                expect(
                    "sts:AssumeRole",
                    &["arn:aws:iam::444455556666:role/partner"]
                ),
            ]
        );
    }

    #[test]
    fn resources_are_derived_from_request_parameters() {
        let found = calls(json!([
            event(
                "dynamodb.amazonaws.com",
                "Query",
                json!({"tableName": "T", "indexName": "by-date"})
            ),
            event(
                "secretsmanager.amazonaws.com",
                "GetSecretValue",
                json!({"secretId": "app/db"})
            ),
            event(
                "ssm.amazonaws.com",
                "GetParameters",
                json!({"names": ["/app/a", "app/b"]})
            ),
            event(
                "ssm.amazonaws.com",
                "GetParametersByPath",
                json!({"path": "/app/"})
            ),
            event(
                "logs.amazonaws.com",
                "PutLogEvents",
                json!({"logGroupName": "/app/web"})
            ),
            event(
                "kms.amazonaws.com",
                "Decrypt",
                json!({"keyId": "alias/app"})
            ),
        ]));
        let arn = |tail: &str| format!("eu-west-1:111122223333:{tail}");
        assert_eq!(
            found,
            [
                expect(
                    "dynamodb:Query",
                    &[
                        &format!("arn:aws:dynamodb:{}", arn("table/T")),
                        &format!("arn:aws:dynamodb:{}", arn("table/T/index/by-date")),
                    ]
                ),
                expect(
                    "secretsmanager:GetSecretValue",
                    &[&format!(
                        "arn:aws:secretsmanager:{}",
                        arn("secret:app/db-??????")
                    )]
                ),
                expect(
                    "ssm:GetParameters",
                    &[
                        &format!("arn:aws:ssm:{}", arn("parameter/app/a")),
                        &format!("arn:aws:ssm:{}", arn("parameter/app/b")),
                    ]
                ),
                expect(
                    "ssm:GetParametersByPath",
                    &[&format!("arn:aws:ssm:{}", arn("parameter/app/*"))]
                ),
                expect(
                    "logs:PutLogEvents",
                    &[&format!("arn:aws:logs:{}", arn("log-group:/app/web:*"))]
                ),
                expect("kms:Decrypt", &["*"]),
            ]
        );
    }

    #[test]
    fn partition_follows_region() {
        let china = with(
            event(
                "sqs.amazonaws.com",
                "SendMessage",
                json!({"queueUrl": "https://sqs.cn-north-1.amazonaws.com.cn/111122223333/q"}),
            ),
            "awsRegion",
            json!("cn-north-1"),
        );
        assert_eq!(
            calls(json!([china])),
            [expect(
                "sqs:SendMessage",
                &["arn:aws-cn:sqs:cn-north-1:111122223333:q"]
            )]
        );
    }

    #[test]
    fn sessions_of_a_role_are_one_subject() {
        let session = |name: &str| {
            with(
                event("sqs.amazonaws.com", "ListQueues", Value::Null),
                "userIdentity",
                json!({
                    "type": "AssumedRole",
                    "arn": format!("arn:aws:sts::111122223333:assumed-role/app/{name}"),
                }),
            )
        };
        let (found, _) = parse_text(&json!([session("i-1"), session("i-2")]).to_string());
        assert_eq!(found.len(), 2);
        assert!(
            found
                .iter()
                .all(|c| c.subject == "arn:aws:iam::111122223333:role/app")
        );
    }

    #[test]
    fn denial_is_recognised_but_other_errors_are_not() {
        let failed = |code: &str| {
            with(
                event("ec2.amazonaws.com", "RunInstances", Value::Null),
                "errorCode",
                json!(code),
            )
        };
        let (found, _) = parse_text(
            &json!([
                failed("AccessDenied"),
                failed("Client.UnauthorizedOperation"),
                failed("InvalidParameterValue"),
            ])
            .to_string(),
        );
        assert_eq!(
            found.iter().map(|c| c.denied).collect::<Vec<_>>(),
            [true, true, false]
        );
    }

    #[test]
    fn events_that_need_no_permission_are_ignored() {
        let found = calls(json!([
            with(
                event("kms.amazonaws.com", "Decrypt", Value::Null),
                "userIdentity",
                json!({"type": "AWSService"})
            ),
            with(
                event("signin.amazonaws.com", "ConsoleLogin", Value::Null),
                "eventType",
                json!("AwsConsoleSignIn")
            ),
            with(
                event("ec2.amazonaws.com", "TerminateInstances", Value::Null),
                "eventType",
                json!("AwsServiceEvent")
            ),
        ]));
        assert_eq!(found, []);
    }

    #[test]
    fn reads_json_lines_and_lookup_events_output() {
        let inner = event("sqs.amazonaws.com", "ListQueues", Value::Null);
        let lookup = json!({"Events": [{"EventName": "x", "CloudTrailEvent": inner.to_string()}]});
        assert_eq!(parse_text(&lookup.to_string()).0.len(), 1);

        let lines = format!("{inner}\nnot json\n{}\n", json!({ "detail": inner }));
        let (found, notes) = parse_text(&lines);
        assert_eq!((found.len(), notes.len()), (2, 1));
    }
}
