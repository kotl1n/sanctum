use crate::{
    Error, MAX_EVENT, Result, json,
    redaction::{Redactor, token_matches},
};
use serde_json::{Map, Value, json as value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const BLOCKED_TYPES: &[&str] = &[
    "input_image",
    "input_file",
    "input_audio",
    "image",
    "file",
    "audio",
    "video",
];
const BLOCKED_FIELDS: &[&str] = &[
    "image_url",
    "file_data",
    "file_id",
    "file_url",
    "audio",
    "input_audio",
    "video",
    "mcp_servers",
];

pub struct Session {
    pub redactor: Redactor,
    opaque: HashSet<[u8; 32]>,
}
impl Session {
    pub fn new(redactor: Redactor) -> Self {
        Self {
            redactor,
            opaque: HashSet::new(),
        }
    }
    pub fn remember_opaque(&mut self, data: &Value) -> Result<()> {
        match data {
            Value::Object(map) => {
                for (key, item) in map {
                    if key == "encrypted_content" {
                        if let Some(text) = item.as_str() {
                            let hash = Sha256::digest(text.as_bytes()).into();
                            if !self.opaque.contains(&hash) && self.opaque.len() >= 10_000 {
                                return Err(Error("opaque_capacity"));
                            }
                            self.opaque.insert(hash);
                        }
                    } else {
                        self.remember_opaque(item)?;
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.remember_opaque(item)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub fn request(&mut self, payload: &Value) -> Result<Value> {
        let object = payload.as_object().ok_or(Error("json_object_required"))?;
        if object
            .get("background")
            .is_some_and(|v| !v.is_null() && v != false)
            || ["previous_response_id", "conversation"]
                .iter()
                .any(|k| object.get(*k).is_some_and(|v| !v.is_null()))
        {
            return Err(Error("stateless_requests_only"));
        }
        if let Some(tools) = object.get("tools") {
            validate_tools(tools)?;
        }
        let mut result = payload.clone();
        let mut saved = HashMap::new();
        self.inspect(&mut result, &mut saved, 0)?;
        self.redactor.reserve(&result)?;
        let first = self.redactor.value(&result)?;
        let mut result = self.redactor.value(&first)?;
        put_back(&mut result, &saved)?;
        result
            .as_object_mut()
            .ok_or(Error("json_object_required"))?
            .insert("store".into(), Value::Bool(false));
        Ok(result)
    }
    fn inspect(
        &self,
        data: &mut Value,
        saved: &mut HashMap<String, String>,
        depth: usize,
    ) -> Result<()> {
        if depth > 64 {
            return Err(Error("nesting_limit"));
        }
        match data {
            Value::Object(map) => {
                if map
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|k| BLOCKED_TYPES.contains(&k))
                    || BLOCKED_FIELDS.iter().any(|k| map.contains_key(*k))
                {
                    return Err(Error("attachments_disabled"));
                }
                if map.get("type").and_then(Value::as_str) == Some("additional_tools") {
                    validate_tools(map.get("tools").ok_or(Error("invalid_tools"))?)?;
                }
                for (key, item) in map.iter_mut() {
                    if key == "encrypted_content" && !item.is_null() {
                        let text = item.as_str().ok_or(Error("unknown_opaque"))?;
                        let hash: [u8; 32] = Sha256::digest(text.as_bytes()).into();
                        if !self.opaque.contains(&hash) {
                            return Err(Error("unknown_opaque"));
                        }
                        let marker = format!("__SANCTUM_OPAQUE_{}__", saved.len());
                        saved.insert(marker.clone(), text.into());
                        *item = Value::String(marker);
                    } else {
                        self.inspect(item, saved, depth + 1)?;
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.inspect(item, saved, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn restore_value(&self, data: &Value, code: bool, depth: usize) -> Result<Value> {
        if depth > 64 {
            return Err(Error("nesting_limit"));
        }
        match data {
            Value::String(text) => {
                for token in token_matches(text) {
                    match self.redactor.original(token) {
                        Some(original) => {
                            if code && !safe_code_literal(original) {
                                return Err(Error("unsafe_code_interpolation"));
                            }
                        }
                        None if self.redactor.literal_token(token) => {}
                        None => return Err(Error("unknown_placeholder")),
                    }
                }
                Ok(Value::String(self.redactor.restore(text)))
            }
            Value::Object(map) => {
                let mut result = Map::new();
                for (key, item) in map {
                    let restored_key = self
                        .restore_value(&Value::String(key.clone()), code, depth + 1)?
                        .as_str()
                        .ok_or(Error("invalid_arguments"))?
                        .to_owned();
                    if result.contains_key(&restored_key) {
                        return Err(Error("argument_key_collision"));
                    }
                    let code_field = [
                        "cmd",
                        "command",
                        "code",
                        "chars",
                        "script",
                        "source",
                        "expression",
                    ]
                    .contains(&key.to_lowercase().as_str());
                    result.insert(
                        restored_key,
                        self.restore_value(item, code || code_field, depth + 1)?,
                    );
                }
                Ok(Value::Object(result))
            }
            Value::Array(items) => items
                .iter()
                .map(|item| self.restore_value(item, code, depth + 1))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array),
            _ => Ok(data.clone()),
        }
    }
    pub fn arguments(&self, arguments: &str, name: &str) -> Result<String> {
        let parsed = json::parse(arguments.as_bytes()).map_err(|_| Error("invalid_arguments"))?;
        let name = name.to_lowercase();
        let code = [
            "exec",
            "shell",
            "bash",
            "terminal",
            "write_stdin",
            "python",
            "javascript",
            "evaluate",
        ]
        .iter()
        .any(|s| name.contains(s));
        serde_json::to_string(&self.restore_value(&parsed, code, 0)?)
            .map_err(|_| Error("invalid_arguments"))
    }
    pub fn item(&self, item: &Value) -> Result<Value> {
        let mut result = item.clone();
        match item.get("type").and_then(Value::as_str) {
            Some("function_call") => {
                let args = item
                    .get("arguments")
                    .and_then(Value::as_str)
                    .ok_or(Error("invalid_arguments"))?;
                if !args.is_empty() {
                    result["arguments"] =
                        Value::String(self.arguments(
                            args,
                            item.get("name").and_then(Value::as_str).unwrap_or(""),
                        )?);
                }
            }
            Some("custom_tool_call") => {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(Error("invalid_tool"))?;
                let input = item
                    .get("input")
                    .and_then(Value::as_str)
                    .ok_or(Error("invalid_tool"))?;
                if !["exec", "apply_patch"].contains(&name) && token_matches(input).next().is_some()
                {
                    return Err(Error("unsupported_custom_tool"));
                }
                result["input"] =
                    self.restore_value(&Value::String(input.into()), name == "exec", 0)?;
            }
            _ => {}
        }
        Ok(result)
    }
    pub fn response(&mut self, payload: &Value) -> Result<Value> {
        self.remember_opaque(payload)?;
        let mut result = payload.clone();
        if let Some(output) = payload.get("output").and_then(Value::as_array) {
            result["output"] = Value::Array(
                output
                    .iter()
                    .map(|item| self.item(item))
                    .collect::<Result<_>>()?,
            );
        }
        Ok(result)
    }
}

fn safe_code_literal(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_./:@%+,=-".contains(&c))
}
fn validate_tools(tools: &Value) -> Result<()> {
    for tool in tools.as_array().ok_or(Error("invalid_tools"))? {
        match tool.get("type").and_then(Value::as_str) {
            Some("function" | "custom") => {}
            Some("namespace") => validate_tools(tool.get("tools").ok_or(Error("invalid_tools"))?)?,
            _ => return Err(Error("hosted_tools_disabled")),
        }
    }
    Ok(())
}
fn put_back(data: &mut Value, saved: &HashMap<String, String>) -> Result<()> {
    match data {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if key == "encrypted_content" && !item.is_null() {
                    *item = Value::String(
                        saved
                            .get(item.as_str().ok_or(Error("opaque_marker_changed"))?)
                            .ok_or(Error("opaque_marker_changed"))?
                            .clone(),
                    );
                } else {
                    put_back(item, saved)?;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                put_back(item, saved)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// One decoder per response, independent buffers for interleaved tool calls.
#[derive(Default)]
pub struct ResponseStream {
    names: HashMap<String, String>,
    pending: HashMap<String, String>,
    sequence: u64,
    line: Vec<u8>,
    lines: Vec<Vec<u8>>,
    frame_size: usize,
    terminal: bool,
}
impl ResponseStream {
    pub fn event(
        &mut self,
        session: &mut Session,
        data: &Value,
        restore: bool,
    ) -> Result<Vec<Value>> {
        session.remember_opaque(data)?;
        if !restore {
            return Ok(vec![data.clone()]);
        }
        let mut result = data.clone();
        let kind = data
            .get("type")
            .and_then(Value::as_str)
            .ok_or(Error("invalid_provider_event"))?;
        let mut output = Vec::new();
        match kind {
            "response.output_item.added" => {
                let item = data.get("item").ok_or(Error("invalid_provider_event"))?;
                if let (Some(id), Some(name)) = (
                    item.get("id").and_then(Value::as_str),
                    item.get("name").and_then(Value::as_str),
                ) {
                    self.names.insert(id.into(), name.into());
                }
                result["item"] = session.item(item)?;
            }
            "response.function_call_arguments.delta" | "response.custom_tool_call_input.delta" => {
                let id = data
                    .get("item_id")
                    .and_then(Value::as_str)
                    .ok_or(Error("invalid_provider_event"))?;
                let delta = data
                    .get("delta")
                    .and_then(Value::as_str)
                    .ok_or(Error("invalid_provider_event"))?;
                let pending = self.pending.entry(id.into()).or_default();
                if pending.len() + delta.len() > MAX_EVENT {
                    return Err(Error("tool_argument_limit"));
                }
                pending.push_str(delta);
                result["delta"] = Value::String(String::new());
            }
            "response.function_call_arguments.done" | "response.custom_tool_call_input.done" => {
                let id = data
                    .get("item_id")
                    .and_then(Value::as_str)
                    .ok_or(Error("invalid_provider_event"))?;
                let field = if kind.contains("function_call") {
                    "arguments"
                } else {
                    "input"
                };
                let complete = data
                    .get(field)
                    .and_then(Value::as_str)
                    .or_else(|| self.pending.get(id).map(String::as_str))
                    .ok_or(Error("invalid_provider_event"))?;
                let name = self
                    .names
                    .get(id)
                    .map(String::as_str)
                    .or_else(|| data.get("name").and_then(Value::as_str))
                    .ok_or(Error("unknown_tool"))?;
                let restored = if field == "arguments" {
                    Value::String(session.arguments(complete, name)?)
                } else {
                    session.item(&value!({"type":"custom_tool_call","name":name,"input":complete}))?["input"].clone()
                };
                result[field] = restored.clone();
                let mut delta = result.clone();
                let map = delta
                    .as_object_mut()
                    .ok_or(Error("invalid_provider_event"))?;
                map.remove(field);
                map.remove("name");
                map.insert(
                    "type".into(),
                    Value::String(format!("{}.delta", kind.trim_end_matches(".done"))),
                );
                map.insert("delta".into(), restored);
                output.push(delta);
                self.pending.remove(id);
            }
            "response.output_item.done" => {
                result["item"] =
                    session.item(data.get("item").ok_or(Error("invalid_provider_event"))?)?;
            }
            _ => {
                if let Some(response) = data.get("response").filter(|v| v.is_object()) {
                    result["response"] = session.response(response)?;
                }
            }
        }
        output.push(result);
        for event in &mut output {
            if event.get("sequence_number").is_some() {
                event["sequence_number"] = self.sequence.into();
                self.sequence += 1;
            }
        }
        Ok(output)
    }
    pub fn feed(
        &mut self,
        session: &mut Session,
        chunk: &[u8],
        restore: bool,
    ) -> Result<Vec<Vec<u8>>> {
        let mut frames = Vec::new();
        for &byte in chunk {
            self.frame_size += 1;
            if self.frame_size > MAX_EVENT {
                return Err(Error("provider_event_limit"));
            }
            if byte != b'\n' {
                self.line.push(byte);
                continue;
            }
            let mut line = std::mem::take(&mut self.line);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if !line.is_empty() {
                self.lines.push(line);
                continue;
            }
            let lines = std::mem::take(&mut self.lines);
            self.frame_size = 0;
            let data: Vec<u8> = lines
                .iter()
                .filter_map(|l| l.strip_prefix(b"data:"))
                .map(|l| l.strip_prefix(b" ").unwrap_or(l))
                .collect::<Vec<_>>()
                .join(&b'\n');
            if data.is_empty() || data == b"[DONE]" {
                frames.push(b": keepalive\n\n".to_vec());
                continue;
            }
            let payload = json::parse(&data).map_err(|_| Error("invalid_provider_event"))?;
            let kind = payload
                .get("type")
                .and_then(Value::as_str)
                .ok_or(Error("invalid_provider_event"))?;
            if [
                "response.completed",
                "response.failed",
                "response.incomplete",
                "error",
            ]
            .contains(&kind)
            {
                self.terminal = true;
            }
            for event in self.event(session, &payload, restore)? {
                let kind = event
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or(Error("invalid_provider_event"))?;
                if !kind
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                {
                    return Err(Error("invalid_provider_event"));
                }
                let mut wire = format!("event: {kind}\ndata: ").into_bytes();
                wire.extend(json::encode(&event)?);
                wire.extend(b"\n\n");
                frames.push(wire);
            }
        }
        Ok(frames)
    }
    pub fn finish(&self) -> Result<()> {
        if !self.line.is_empty()
            || !self.lines.is_empty()
            || !self.pending.is_empty()
            || !self.terminal
        {
            return Err(Error("incomplete_provider_stream"));
        }
        Ok(())
    }
}
