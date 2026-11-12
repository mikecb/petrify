//! Google Cloud Audit Logs -> [`ApiCall`].
//!
//! An audit log entry already lists the IAM permissions that were checked
//! and whether each was granted (`protoPayload.authorizationInfo`), so
//! nothing has to be translated: the permissions go into the role as they
//! are.
//!
//! Reads `gcloud logging read --format=json` output (a JSON array), the JSON
//! Lines a log sink writes to Cloud Storage, and rows exported from BigQuery,
//! where the payload is called `protopayload_auditlog`.

use std::io::{self, BufRead};

use serde_json::Value;

use crate::events::{ApiCall, Notes};
use crate::sources::{json_documents, text};

pub fn sniff(head: &str) -> bool {
    head.contains("cloudaudit.googleapis.com")
        || head.contains("google.cloud.audit.AuditLog")
        || head.contains("protopayload_auditlog")
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(ApiCall),
) -> io::Result<()> {
    for document in &json_documents(reader, notes)? {
        entries(document, emit);
    }
    Ok(())
}

fn entries(document: &Value, emit: &mut dyn FnMut(ApiCall)) {
    if let Some(items) = document.as_array() {
        items.iter().for_each(|item| entries(item, emit));
    } else if let Some(payload) = document
        .get("protoPayload")
        .or_else(|| document.get("protopayload_auditlog"))
    {
        calls(payload, emit);
    }
}

fn calls(payload: &Value, emit: &mut dyn FnMut(ApiCall)) {
    let identity = payload.get("authenticationInfo").unwrap_or(&Value::Null);
    // The email is redacted in some entries, and absent for identities from
    // outside Google, which are named by `principalSubject` instead.
    let subject = text(identity, "principalEmail")
        .or_else(|| text(identity, "principalSubject"))
        .unwrap_or("unknown");

    let checks = payload.get("authorizationInfo").and_then(Value::as_array);
    for check in checks.into_iter().flatten() {
        let Some(permission) = text(check, "permission") else {
            continue;
        };
        let attributes = check.get("resourceAttributes").unwrap_or(&Value::Null);
        let resource = text(check, "resource")
            .or_else(|| text(attributes, "name"))
            .or_else(|| text(payload, "resourceName"))
            .unwrap_or("*");
        emit(ApiCall {
            subject: subject.to_string(),
            action: permission.to_string(),
            resources: vec![resource.to_string()],
            // `granted` is left out of the JSON altogether when it is false.
            denied: check.get("granted").and_then(Value::as_bool) != Some(true),
        });
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse_text(text: &str) -> (Vec<ApiCall>, Notes) {
        let (mut found, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), &mut notes, &mut |call| {
            found.push(call)
        })
        .unwrap();
        (found, notes)
    }

    fn entry(principal: Value, checks: Value) -> Value {
        json!({
            "logName": "projects/p/logs/cloudaudit.googleapis.com%2Fdata_access",
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": principal,
                "authorizationInfo": checks,
                "methodName": "storage.objects.get",
                "resourceName": "projects/_/buckets/b/objects/fallback",
            },
        })
    }

    fn app() -> Value {
        json!({"principalEmail": "app@p.iam.gserviceaccount.com"})
    }

    #[test]
    fn each_permission_check_is_a_call() {
        let log = json!([entry(
            app(),
            json!([
                {
                    "resource": "projects/_/buckets/b/objects/o",
                    "permission": "storage.objects.get",
                    "granted": true,
                },
                {
                    "permission": "storage.objects.list",
                    "granted": true,
                    "resourceAttributes": {"name": "projects/_/buckets/b"},
                },
                {"permission": "storage.objects.delete"},
                {"permission": "storage.buckets.update", "granted": false},
                {"granted": true},
            ]),
        )]);
        assert!(sniff(&log.to_string()));
        let (found, notes) = parse_text(&log.to_string());
        let seen: Vec<(&str, &str, bool)> = found
            .iter()
            .map(|c| (c.action.as_str(), c.resources[0].as_str(), c.denied))
            .collect();
        assert_eq!(
            seen,
            [
                (
                    "storage.objects.get",
                    "projects/_/buckets/b/objects/o",
                    false
                ),
                ("storage.objects.list", "projects/_/buckets/b", false),
                (
                    "storage.objects.delete",
                    "projects/_/buckets/b/objects/fallback",
                    true
                ),
                (
                    "storage.buckets.update",
                    "projects/_/buckets/b/objects/fallback",
                    true
                ),
            ]
        );
        assert!(
            found
                .iter()
                .all(|c| c.subject == "app@p.iam.gserviceaccount.com")
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn principals_without_an_email_are_still_named() {
        let check = json!([{"permission": "storage.buckets.list", "granted": true}]);
        let federated = json!({"principalSubject": "principal://iam.googleapis.com/x/subject/y"});
        let log = json!([entry(federated, check.clone()), entry(json!({}), check)]);
        let (found, _) = parse_text(&log.to_string());
        let subjects: Vec<&str> = found.iter().map(|c| c.subject.as_str()).collect();
        assert_eq!(
            subjects,
            ["principal://iam.googleapis.com/x/subject/y", "unknown"]
        );
    }

    #[test]
    fn reads_json_lines_and_bigquery_rows() {
        let check = json!([{"permission": "storage.buckets.list", "granted": true}]);
        let sink = entry(app(), check.clone());
        let row = json!({
            "logName": "projects/p/logs/cloudaudit_googleapis_com_activity",
            "protopayload_auditlog": {"authenticationInfo": app(), "authorizationInfo": check},
        });
        let system = json!({"protoPayload": {"methodName": "compute.instances.preempted"}});
        let lines = format!("{sink}\n{row}\n{system}\n{{broken\n");
        let (found, notes) = parse_text(&lines);
        assert_eq!((found.len(), notes.len()), (2, 1));
    }
}
