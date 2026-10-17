//! Synchronous UserPromptSubmit decision. No network, sockets or persistence.
use crate::{
    Error, MAX_BODY, Result, json,
    redaction::{Policy, Redactor},
};
use serde_json::{Value, json as value};

pub const PLUGIN_VERSION: &str = "0.1.0";
pub const INSPECTION_FAILURE: &str = "Sanctum: отправка остановлена — не удалось проверить промпт. Проверьте работу плагина и его политику. Исходный текст не включён в сообщение об ошибке.";

#[derive(Debug, PartialEq, Eq)]
pub struct Findings(pub Vec<(&'static str, usize)>);
impl Findings {
    pub fn blocked(&self) -> bool {
        !self.0.is_empty()
    }
    pub fn reason(&self) -> String {
        let counts = self
            .0
            .iter()
            .map(|(kind, count)| format!("{kind}: {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Sanctum: отправка остановлена. Найдены возможные чувствительные данные ({counts}; количество разных значений). Удалите или замените их и отправьте сообщение снова. Сами значения не включены в предупреждение."
        )
    }
}
pub fn inspect(prompt: &str, policy: Policy) -> Result<Findings> {
    if prompt.len() > MAX_BODY {
        return Err(Error("prompt_size_limit"));
    }
    let mut redactor = Redactor::new(policy)?;
    let source = Value::String(prompt.to_owned());
    redactor.reserve(&source)?;
    // Also inspect a prompt consisting of serialized JSON as structured data.
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
/// Empty stdout permits processing; a JSON block decision rejects this prompt.
pub fn decision(result: Result<Findings>) -> Option<Value> {
    match result {
        Ok(findings) if !findings.blocked() => None,
        Ok(findings) => Some(value!({"decision":"block","reason":findings.reason()})),
        Err(_) => Some(value!({"decision":"block","reason":INSPECTION_FAILURE})),
    }
}
