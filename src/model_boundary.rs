//! Last-mile filtering of a complete model request received over a local pipe.
use crate::{Error, Result, redaction::Policy, vault::Vault};
use serde_json::{Value, json};

pub const PROTOCOL: &str = "sanctum-native-v1";

pub fn filter(envelope: &Value, policy: Policy, vault: &Vault) -> Result<Value> {
    let session = envelope
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or(Error("model_session_required"))?;
    let mut body = envelope
        .get("body")
        .filter(|v| v.is_object())
        .cloned()
        .ok_or(Error("model_body_required"))?;
    if body
        .get("background")
        .is_some_and(|v| !v.is_null() && v != false)
        || ["previous_response_id", "conversation"]
            .iter()
            .any(|k| body.get(*k).is_some_and(|v| !v.is_null()))
    {
        return Err(Error("native_stateless_requests_only"));
    }
    if let Some(tools) = body.get("tools") {
        inspect_tools(tools)?;
    }
    body["store"] = Value::Bool(false);
    let safe = vault.transact(session, policy, |engine| {
        let mut opaque = Vec::new();
        if let Some(items) = body.get_mut("input").and_then(Value::as_array_mut) {
            for (index, item) in items.iter_mut().enumerate() {
                if item["type"] == "reasoning"
                    && let Some(cipher) = item.get("encrypted_content").filter(|v| !v.is_null())
                {
                    let cipher = cipher.as_str().ok_or(Error("unknown_provider_opaque"))?;
                    if !engine.known_provider_opaque(cipher) {
                        return Err(Error("unknown_provider_opaque"));
                    }
                    opaque.push((index, cipher.to_owned()));
                    item.as_object_mut()
                        .ok_or(Error("invalid_reasoning"))?
                        .remove("encrypted_content");
                }
            }
        }
        if let Some(input) = body.get("input") {
            inspect_input(input, 0)?;
        }
        engine.reserve(&body)?;
        let first = engine.value(&body)?;
        let mut safe = engine.value(&first)?;
        for (index, cipher) in opaque {
            safe["input"][index]["encrypted_content"] = Value::String(cipher);
        }
        Ok(safe)
    })?;
    Ok(json!({"protocol":PROTOCOL,"session_id":session,"body":safe}))
}
pub fn record_provider(envelope: &Value, policy: Policy, vault: &Vault) -> Result<Value> {
    let session = envelope["session_id"]
        .as_str()
        .ok_or(Error("model_session_required"))?;
    let item = &envelope["item"];
    if item["type"] != "reasoning" {
        return Err(Error("provider_reasoning_required"));
    }
    let cipher = item["encrypted_content"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= crate::MAX_EVENT)
        .ok_or(Error("invalid_provider_opaque"))?;
    vault.transact(session, policy, |engine| {
        engine.remember_provider_opaque(cipher)
    })?;
    Ok(json!({"protocol":PROTOCOL,"session_id":session,"recorded":true}))
}
fn inspect_input(value: &Value, depth: usize) -> Result<()> {
    if depth > 64 {
        return Err(Error("nesting_limit"));
    }
    match value {
        Value::Object(map) => {
            let kind = map.get("type").and_then(Value::as_str);
            if kind == Some("tool_search_output") && map.get("execution") != Some(&json!("client"))
            {
                return Err(Error("native_hosted_tools_disabled"));
            }
            if matches!(kind, Some("additional_tools" | "tool_search_output")) {
                inspect_tools(map.get("tools").ok_or(Error("invalid_model_tools"))?)?;
                return Ok(());
            }
            if map.get("type").and_then(Value::as_str).is_some_and(|t| {
                [
                    "input_image",
                    "input_file",
                    "input_audio",
                    "image",
                    "file",
                    "audio",
                    "video",
                ]
                .contains(&t)
            }) || [
                "file_data",
                "file_id",
                "file_url",
                "image_url",
                "input_audio",
                "encrypted_content",
            ]
            .iter()
            .any(|k| map.get(*k).is_some_and(|v| !v.is_null()))
            {
                return Err(Error("native_opaque_context_disabled"));
            }
            for item in map.values() {
                inspect_input(item, depth + 1)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                inspect_input(item, depth + 1)?;
            }
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
    Ok(())
}
fn inspect_tools(value: &Value) -> Result<()> {
    for tool in value.as_array().ok_or(Error("invalid_model_tools"))? {
        match tool["type"].as_str() {
            Some("function" | "custom") => {}
            Some("tool_search") if tool["execution"] == "client" => {}
            Some("namespace") => {
                inspect_tools(tool.get("tools").ok_or(Error("invalid_model_tools"))?)?
            }
            _ => return Err(Error("native_hosted_tools_disabled")),
        }
    }
    Ok(())
}
