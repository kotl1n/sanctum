use serde_json::Value;
use sha2::{Digest, Sha256};

const PUBLIC_LARK: [&str; 3] = [
    "8eead048e20069c17fcd0b6fe5ee9ed29364868723f8e08889de146a2b4b7a8e",
    "d6367f4826ed608c424b0a308f3d6163527df63c22513d089b91863552f8bfeb",
    "2c1d2069867f720f53f5c8e08100287d56c0b4818e2921067de5c6614fb7ca5e",
];

pub(crate) fn is_public(format: &Value) -> bool {
    format["type"] == "grammar"
        && format["syntax"] == "lark"
        && format["definition"].as_str().is_some_and(|definition| {
            let digest = format!("{:x}", Sha256::digest(definition.as_bytes()));
            PUBLIC_LARK.contains(&digest.as_str())
        })
}

pub(crate) fn remember(value: &Value, path: &str, formats: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            let tool_container = path.is_empty()
                || matches!(
                    value["type"].as_str(),
                    Some("namespace" | "additional_tools")
                )
                || (value["type"] == "tool_search_output" && value["execution"] == "client");
            if tool_container && let Some(tools) = value["tools"].as_array() {
                for (index, tool) in tools.iter().enumerate() {
                    if tool["type"] == "custom" && tool["format"]["type"] == "grammar" {
                        formats.push((format!("{path}/tools/{index}"), tool["format"].clone()));
                    }
                }
            }
            for (key, item) in map {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                remember(item, &format!("{path}/{escaped}"), formats);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                remember(item, &format!("{path}/{index}"), formats);
            }
        }
        _ => {}
    }
}

pub(crate) fn remove_changed(body: &mut Value, formats: Vec<(String, Value)>) {
    let mut removed = false;

    for (path, original) in formats.into_iter().rev() {
        if body
            .pointer(&path)
            .is_some_and(|tool| tool["format"] != original)
            && let Some((parent, index)) = path.rsplit_once('/')
            && let Ok(index) = index.parse::<usize>()
            && let Some(tools) = body.pointer_mut(parent).and_then(Value::as_array_mut)
        {
            tools.remove(index);
            removed = true;
        }
    }
    if removed && body.get("tool_choice").is_some() {
        body["tool_choice"] = Value::String("auto".into());
    }
}
