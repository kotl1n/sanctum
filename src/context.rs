use crate::{Error, Result, rewrite::Rewriter};
use serde_json::{Value, json};

pub fn rewrite(body: &Value, session: &str, rewriter: &Rewriter) -> Result<Value> {
    let mut safe = body.clone();
    let map = safe.as_object_mut().ok_or(Error("model_body_required"))?;

    map.remove("previous_response_id");
    map.remove("conversation");
    if map.contains_key("input") || map.contains_key("store") {
        map.insert("store".into(), json!(false));
    }
    sanitize_history(&mut safe, session, rewriter)?;
    sanitize(&mut safe);
    let mut grammars = Vec::new();
    crate::tool_grammar::remember(&safe, "", &mut grammars);
    mask_data(&mut safe, |data| rewriter.try_mask(session, data))?;
    crate::tool_grammar::remove_changed(&mut safe, grammars);
    Ok(safe)
}

pub(crate) fn mask_data(
    body: &mut Value,
    mask: impl FnOnce(&Value) -> Result<Value>,
) -> Result<()> {
    let mut paths = Vec::new();
    let mut texts = Vec::new();
    collect(
        body,
        "",
        "",
        crate::context_paths::Place::Request,
        &mut paths,
        &mut texts,
    );
    let masked = mask(&Value::Array(texts))?;
    let values = masked.as_array().ok_or(Error("invalid_masked_context"))?;
    if values.len() != paths.len() {
        return Err(Error("invalid_masked_context"));
    }
    for (target, value) in paths.iter().zip(values) {
        let Target::Data { path, wrapped } = target else {
            let Target::SchemaName(original) = target else {
                unreachable!()
            };
            if original != value {
                return Err(Error("private_schema_identifier"));
            }
            continue;
        };
        let replacement = if *wrapped {
            let map = value
                .as_object()
                .filter(|m| m.len() == 1)
                .ok_or(Error("invalid_masked_context"))?;
            map.values().next().ok_or(Error("invalid_masked_context"))?
        } else {
            value
        };
        *body
            .pointer_mut(path)
            .ok_or(Error("invalid_masked_context"))? = replacement.clone();
    }
    Ok(())
}

pub(crate) fn has_omitted_history(before: &Value, after: &Value) -> bool {
    let omitted = |old: &Value, new: &Value| {
        old.as_array()
            .zip(new.as_array())
            .is_some_and(|(old, new)| {
                old.iter().any(|item| {
                    crate::opaque::kind(item).is_some_and(|k| k != "reasoning")
                        && !new.iter().any(|safe| safe == item)
                })
            })
    };
    omitted(&before["input"], &after["input"])
        || before["traces"]
            .as_array()
            .zip(after["traces"].as_array())
            .is_some_and(|(old, new)| {
                old.iter()
                    .zip(new)
                    .any(|(old, new)| omitted(&old["items"], &new["items"]))
            })
}

fn sanitize_history(body: &mut Value, session: &str, rewriter: &Rewriter) -> Result<()> {
    if let Some(items) = body.get_mut("input").and_then(Value::as_array_mut) {
        items.retain_mut(|item| {
            let Some(kind) = crate::opaque::kind(item) else {
                return true;
            };
            if kind == "context_compaction" && item["encrypted_content"].is_null() {
                return true;
            }
            if rewriter.known_provider_item(session, item) {
                return true;
            }
            if kind == "reasoning" {
                return false;
            }
            *item = json!({"role":"user","content":crate::opaque::HISTORY_UNAVAILABLE});
            true
        });
    }
    if let Some(traces) = body.get_mut("traces").and_then(Value::as_array_mut) {
        for trace in traces {
            if !trace.is_object() {
                return Err(Error("invalid_context_trace"));
            }
            let mut wrapper = json!({"input":trace.get("items").cloned().unwrap_or(json!([]))});
            sanitize_history(&mut wrapper, session, rewriter)?;
            trace["items"] = wrapper["input"].take();
        }
    }
    Ok(())
}

fn sanitize(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                sanitize(item);
            }
        }
        Value::Object(map) => {
            if matches!(
                map.get("type").and_then(Value::as_str),
                Some(
                    "input_image"
                        | "input_file"
                        | "input_audio"
                        | "image"
                        | "file"
                        | "audio"
                        | "video"
                )
            ) {
                *value = json!({"type":"input_text","text":crate::rewrite::ATTACHMENT});
                return;
            }
            if let Some(tools) = map.get_mut("tools").and_then(Value::as_array_mut) {
                tools.retain(|t| {
                    matches!(
                        t["type"].as_str(),
                        Some("function" | "custom" | "namespace")
                    ) || (t["type"] == "tool_search" && t["execution"] == "client")
                });
            }
            for item in map.values_mut() {
                sanitize(item);
            }
        }
        _ => {}
    }
}

enum Target {
    Data { path: String, wrapped: bool },
    SchemaName(Value),
}

fn collect(
    value: &Value,
    path: &str,
    field: &str,
    place: crate::context_paths::Place,
    paths: &mut Vec<Target>,
    texts: &mut Vec<Value>,
) {
    use crate::context_paths::{self, Field, Place};
    match value {
        Value::Bool(_) if matches!(place, Place::Schema) => {}
        Value::Array(items) if context_paths::list(place) => {
            for (index, item) in items.iter().enumerate() {
                collect(
                    item,
                    &format!("{path}/{index}"),
                    "",
                    context_paths::array_child(place),
                    paths,
                    texts,
                );
            }
        }
        Value::Object(map) if context_paths::object(place, value) => {
            for (key, item) in map {
                let identifier = if matches!(place, Place::SchemaMap) {
                    Some(json!(key))
                } else if matches!(place, Place::Schema)
                    && matches!(key.as_str(), "required" | "$ref" | "$dynamicRef")
                {
                    Some(item.clone())
                } else {
                    None
                };
                if let Some(identifier) = identifier {
                    paths.push(Target::SchemaName(identifier.clone()));
                    texts.push(identifier);
                }
                if let Field::Walk(next) = context_paths::field(place, value, key, item) {
                    let escaped = key.replace('~', "~0").replace('/', "~1");
                    collect(item, &format!("{path}/{escaped}"), key, next, paths, texts);
                }
            }
        }
        _ => {
            let wrapped = !field.is_empty() && !matches!(place, Place::Schema);
            paths.push(Target::Data {
                path: path.into(),
                wrapped,
            });
            texts.push(if wrapped {
                json!({field:value})
            } else {
                value.clone()
            });
        }
    }
}
