use crate::{
    Error, MAX_BODY, Result, json,
    redaction::{Policy, Redactor},
};
use serde_json::Value;

pub const PLUGIN_VERSION: &str = crate::VERSION;

#[derive(Debug, PartialEq, Eq)]
pub struct Findings(pub Vec<(&'static str, usize)>);
impl Findings {
    pub fn blocked(&self) -> bool {
        !self.0.is_empty()
    }
}
pub fn inspect(prompt: &str, policy: Policy) -> Result<Findings> {
    if prompt.len() > MAX_BODY {
        return Err(Error("prompt_size_limit"));
    }
    let mut redactor = Redactor::new(policy)?;
    let source = Value::String(prompt.to_owned());
    redactor.reserve(&source)?;

    let first = redactor.value(&source)?;
    let _ = redactor.value(&first)?;
    Ok(Findings(redactor.finding_counts()))
}
pub fn inspect_hook(bytes: &[u8], policy: Policy) -> Result<Findings> {
    if bytes.len() > MAX_BODY {
        return Err(Error("hook_input_limit"));
    }
    let payload = json::parse(bytes)?;
    if payload.get("hook_event_name").and_then(Value::as_str) != Some("UserPromptSubmit") {
        return Err(Error("unexpected_hook_event"));
    }
    let prompt = payload
        .get("prompt")
        .and_then(Value::as_str)
        .ok_or(Error("prompt_required"))?;
    inspect(prompt, policy)
}

pub fn decision(_result: Result<Findings>) -> Option<Value> {
    None
}
