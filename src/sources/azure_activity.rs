//! Azure Activity Log -> [`ApiCall`].
//!
//! Each record names the Resource Manager operation that was authorised
//! (`authorization.action`) and the scope it applied to.
//!
//! Know what this log leaves out before relying on a role built from it:
//!
//! - It records writes, deletes and actions. Reads are not recorded.
//! - It covers the control plane only. Reading a blob or a secret is a data
//!   action and appears in the resource's own logs, not here.
//! - A request refused for lack of permission produces no record, so there
//!   is nothing to report as denied.
//!
//! Reads `az monitor activity-log list` output, the `{"records": [...]}`
//! documents sent to Event Hubs, and the JSON Lines written to a storage
//! account.

use std::io::{self, BufRead};

use serde_json::Value;

use crate::events::{ApiCall, Notes};
use crate::sources::{json_documents, text};

const UPN: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";
const OBJECT_ID: &str = "http://schemas.microsoft.com/identity/claims/objectidentifier";

/// Categories of event that are not operations someone was authorised for.
const NOT_OPERATIONS: [&str; 7] = [
    "servicehealth",
    "resourcehealth",
    "alert",
    "autoscale",
    "recommendation",
    "security",
    "policy",
];

pub fn sniff(head: &str) -> bool {
    head.contains("\"operationName\"") && head.contains("\"authorization\"")
}

pub fn parse(
    reader: &mut dyn BufRead,
    notes: &mut Notes,
    emit: &mut dyn FnMut(ApiCall),
) -> io::Result<()> {
    for document in &json_documents(reader, notes)? {
        records(document, emit);
    }
    Ok(())
}

fn records(document: &Value, emit: &mut dyn FnMut(ApiCall)) {
    if let Some(items) = document.as_array() {
        items.iter().for_each(|item| records(item, emit));
    } else if document.get("operationName").is_some() {
        emit_call(document, emit);
    } else {
        // Event Hubs wraps records in "records"; the REST API in "value".
        for key in ["records", "value"] {
            if let Some(inner) = document.get(key) {
                records(inner, emit);
            }
        }
    }
}

/// A field that is a plain string in exported records and a
/// `{"value": ..., "localizedValue": ...}` object from the API.
fn plain<'a>(record: &'a Value, key: &str) -> Option<&'a str> {
    let field = record.get(key)?;
    field
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| text(field, "value"))
}

fn emit_call(record: &Value, emit: &mut dyn FnMut(ApiCall)) {
    let category = plain(record, "category").unwrap_or("").to_lowercase();
    if NOT_OPERATIONS.contains(&category.replace(' ', "").as_str()) {
        return;
    }
    // Exports nest the caller's details under "identity".
    let identity = record.get("identity").unwrap_or(record);
    let authorization = identity.get("authorization").unwrap_or(&Value::Null);
    let Some(action) = text(authorization, "action")
        .or_else(|| plain(record, "operationName"))
        .filter(|action| action.contains('/'))
    else {
        return;
    };
    let scope = text(authorization, "scope")
        .or_else(|| text(record, "resourceId"))
        .unwrap_or("*");

    let claims = identity.get("claims").unwrap_or(&Value::Null);
    let evidence = authorization.get("evidence").unwrap_or(&Value::Null);
    let subject = text(record, "caller")
        .or_else(|| text(claims, UPN))
        .or_else(|| text(claims, "appid"))
        .or_else(|| text(claims, OBJECT_ID))
        .or_else(|| text(evidence, "principalId"))
        .unwrap_or("unknown");

    emit(ApiCall {
        subject: subject.trim().to_string(),
        action: action.to_string(),
        resources: vec![scope.to_string()],
        denied: false,
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SCOPE: &str = "/subscriptions/s1/resourceGroups/web/providers/Microsoft.Network/networkSecurityGroups/nsg";

    fn parse_text(text: &str) -> Vec<ApiCall> {
        let (mut found, mut notes) = (Vec::new(), Notes::default());
        parse(&mut text.as_bytes(), &mut notes, &mut |call| {
            found.push(call)
        })
        .unwrap();
        found
    }

    fn summary(calls: &[ApiCall]) -> Vec<(&str, &str, &str)> {
        calls
            .iter()
            .map(|c| {
                (
                    c.subject.as_str(),
                    c.action.as_str(),
                    c.resources[0].as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn reads_the_api_and_cli_shape() {
        let event = |category: &str, status: &str| {
            json!({
                "authorization": {
                    "action": "Microsoft.Network/networkSecurityGroups/write",
                    "scope": SCOPE,
                },
                "caller": "rob@contoso.com",
                "category": {"value": category, "localizedValue": category},
                "operationName": {
                    "value": "Microsoft.Network/networkSecurityGroups/write",
                    "localizedValue": "Create or Update Network Security Group",
                },
                "resourceId": SCOPE,
                "status": {"value": status, "localizedValue": status},
            })
        };
        let log = json!([
            event("Administrative", "Started"),
            event("Administrative", "Succeeded"),
            event("ServiceHealth", "Active"),
        ]);
        assert!(sniff(&log.to_string()));
        let found = parse_text(&log.to_string());
        let write = (
            "rob@contoso.com",
            "Microsoft.Network/networkSecurityGroups/write",
            SCOPE,
        );
        assert_eq!(summary(&found), [write, write]);
        assert!(found.iter().all(|c| !c.denied));
    }

    #[test]
    fn reads_the_exported_shape() {
        let record = |claims: Value| {
            json!({
                "time": "2019-01-21T22:14:26.9792776Z",
                "resourceId": SCOPE.to_uppercase(),
                "operationName": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
                "category": "Write",
                "resultType": "Success",
                "identity": {
                    "authorization": {
                        "scope": SCOPE,
                        "action": "Microsoft.Network/networkSecurityGroups/write",
                        "evidence": {"principalId": "p-1"},
                    },
                    "claims": claims,
                },
            })
        };
        let user = record(json!({UPN: "admin@contoso.com", "appid": "app-1"}));
        let service = record(json!({"appid": "app-1", OBJECT_ID: "obj-1"}));
        let nobody = record(json!({}));
        let action = "Microsoft.Network/networkSecurityGroups/write";

        // Event Hubs: one document with "records".
        let hub = json!({ "records": [user, service] });
        assert!(sniff(&hub.to_string()));
        assert_eq!(
            summary(&parse_text(&hub.to_string())),
            [
                ("admin@contoso.com", action, SCOPE),
                ("app-1", action, SCOPE)
            ]
        );
        // Storage: one record per line.
        let lines = format!("{nobody}\n{nobody}\n");
        assert_eq!(summary(&parse_text(&lines)), [("p-1", action, SCOPE); 2]);
    }

    #[test]
    fn falls_back_to_the_operation_name_and_resource() {
        let bare = json!([{
            "operationName": "Microsoft.Compute/virtualMachines/restart/action",
            "resourceId": "/subscriptions/s1/resourceGroups/web/providers/Microsoft.Compute/virtualMachines/a",
            "category": "Administrative",
        }, {
            "operationName": "FlowLogFlowEvent",
            "category": "FlowLogFlowEvent",
        }]);
        let found = parse_text(&bare.to_string());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject, "unknown");
        assert_eq!(
            found[0].action,
            "Microsoft.Compute/virtualMachines/restart/action"
        );
    }
}
