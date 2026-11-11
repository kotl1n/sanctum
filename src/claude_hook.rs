//! Обработчик событий Claude Code: маскирование без прокси и сетевого порта.
//!
//! Модель видит только псевдонимы. Запросы с приватными данными блокируются
//! с замаскированной копией, вывод инструментов заменяется через
//! `updatedToolOutput`. Исходные значения не попадают в ответы обработчика,
//! которые Claude Code сохраняет в журнал сеанса: команды Bash восстанавливает
//! и выполняет `run-command`, а файлы после Write и Edit восстанавливаются на месте.
use crate::{
    Error, Result, protocol::Session, redaction::Policy, redaction::Redactor, rewrite::OMITTED,
    vault::Vault,
};
use serde_json::{Value, json as value};
use std::path::PathBuf;

/// Инструменты, которые выполняются на устройстве и получают исходные значения.
/// Сетевые инструменты, MCP и субагенты продолжают видеть псевдонимы.
pub const LOCAL_TOOLS: &[&str] = &[
    "Bash",
    "PowerShell",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "Grep",
    "Glob",
    "LS",
];
const FILE_TOOLS: &[(&str, &str)] = &[
    ("Write", "file_path"),
    ("Edit", "file_path"),
    ("MultiEdit", "file_path"),
    ("NotebookEdit", "notebook_path"),
];

const CONTEXT: &str = "Sanctum privacy guard is active. Values like [EMAIL-1], [IP-2], [KEY-1] or [SECRET-3] are local pseudonyms for private data. Use them verbatim in local tool calls (Bash, Read, Write, Edit, Grep, Glob): Sanctum restores the real values on this device and masks tool output again. Files you read show pseudonyms while the file on disk keeps real values, so an Edit old_string must not contain pseudonyms: anchor it on neighbouring text, or use Write or Bash. Do not try to guess, reconstruct or ask for the original values, and do not pass pseudonyms to network tools expecting them to resolve.";

/// Как запустить `run-command` с тем же состоянием и политикой.
pub struct Runner {
    pub executable: PathBuf,
    pub policy: Option<PathBuf>,
    pub state_directory: Option<PathBuf>,
}
impl Runner {
    fn command(&self, session: &str, command: &str, timeout_ms: u64) -> String {
        let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
        let hex = |text: &str| -> String { text.bytes().map(|c| format!("{c:02x}")).collect() };
        let mut line = format!(
            "{} run-command --session {} --command-hex {} --timeout-ms {timeout_ms}",
            quote(&self.executable.to_string_lossy()),
            quote(session),
            hex(command)
        );
        for (flag, path) in [
            ("--policy", &self.policy),
            ("--state-directory", &self.state_directory),
        ] {
            if let Some(path) = path {
                line.push_str(&format!(" {flag} {}", quote(&path.to_string_lossy())));
            }
        }
        line
    }
}

pub fn handle(
    event: &Value,
    policy: Policy,
    vault: &Vault,
    runner: &Runner,
) -> Result<Option<Value>> {
    let session = event["session_id"]
        .as_str()
        .ok_or(Error("session_id_required"))?;
    match event["hook_event_name"].as_str() {
        Some("SessionStart") => Ok(Some(
            value!({"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":CONTEXT}}),
        )),
        Some("UserPromptSubmit") => {
            Ok(masked_prompt(event, policy, vault)?.map(|masked| blocked_prompt(Some(&masked))))
        }
        Some("PreToolUse") => {
            let name = event["tool_name"]
                .as_str()
                .ok_or(Error("tool_name_required"))?;
            let input = event
                .get("tool_input")
                .ok_or(Error("tool_input_required"))?;
            if !LOCAL_TOOLS.contains(&name)
                || FILE_TOOLS.iter().any(|(tool, _)| *tool == name)
                || !has_tokens(input)
                || !vault.exists(session)?
            {
                return Ok(None);
            }
            let restored = vault.transact(session, policy.clone(), |engine| {
                let session = Session::new(Redactor::from_snapshot(policy, &engine.snapshot())?);
                crate::json::parse(session.arguments(&input.to_string(), name)?.as_bytes())
            })?;
            if &restored == input {
                return Ok(None);
            }
            let updated = match (name, input["command"].as_str()) {
                ("Bash", Some(command)) if !cfg!(windows) => {
                    let timeout = if input["run_in_background"] == true {
                        24 * 3600 * 1000
                    } else {
                        input["timeout"].as_u64().unwrap_or(120_000)
                    };
                    let mut wrapped = input.clone();
                    wrapped["command"] = runner.command(session, command, timeout).into();
                    wrapped
                }
                _ => restored,
            };
            Ok(Some(
                value!({"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":updated}}),
            ))
        }
        Some("PostToolUse") => {
            let response = event
                .get("tool_response")
                .ok_or(Error("tool_response_required"))?;
            let name = event["tool_name"].as_str().unwrap_or("");
            if let Some((_, field)) = FILE_TOOLS.iter().find(|(tool, _)| *tool == name)
                && has_tokens(&event["tool_input"])
                && let Some(path) = event["tool_input"][field].as_str()
            {
                restore_file(vault, session, policy.clone(), path)?;
            }
            let masked = conform(response, &vault.mask(session, policy, response)?, None);
            if &masked == response {
                return Ok(None);
            }
            Ok(Some(updated_output(masked)))
        }
        _ => Ok(None),
    }
}

fn has_tokens(value: &Value) -> bool {
    crate::redaction::token_matches(&value.to_string())
        .next()
        .is_some()
}

/// Заменяет известные псевдонимы в записанном файле исходными значениями.
/// В блокнотах значения экранируются как строки JSON.
fn restore_file(vault: &Vault, session: &str, policy: Policy, path: &str) -> Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Error("file_read_failed")),
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(());
    };
    let json = path.ends_with(".ipynb");
    let restored = vault.transact(session, policy, |engine| {
        let mut result = String::with_capacity(text.len());
        let mut cursor = 0;
        for token in crate::redaction::token_matches(text) {
            let Some(original) = engine.original(token) else {
                continue;
            };
            let start = token.as_ptr() as usize - text.as_ptr() as usize;
            result.push_str(&text[cursor..start]);
            if json {
                let encoded = serde_json::to_string(original).map_err(|_| Error("invalid_json"))?;
                result.push_str(&encoded[1..encoded.len() - 1]);
            } else {
                result.push_str(original);
            }
            cursor = start + token.len();
        }
        result.push_str(&text[cursor..]);
        Ok(result)
    })?;
    if restored != text {
        std::fs::write(path, restored).map_err(|_| Error("file_write_failed"))?;
    }
    Ok(())
}

/// Ответ при сбое: ничего исходного не должно дойти до модели.
pub fn failure(event: Option<&Value>) -> Value {
    let reason = "Sanctum: действие заблокировано из-за ошибки локальной проверки или восстановления данных. Исходные значения скрыты.";
    match event.and_then(|e| e["hook_event_name"].as_str()) {
        Some("UserPromptSubmit") => blocked_prompt(None),
        Some("PreToolUse") => {
            value!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":reason}})
        }
        Some("PostToolUse") => {
            let response = event.map(|e| &e["tool_response"]).unwrap_or(&Value::Null);
            updated_output(omit(response))
        }
        _ => value!({"decision":"block","reason":reason}),
    }
}

fn updated_output(output: Value) -> Value {
    value!({"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":output}})
}

/// Замаскированный запрос, если в нём есть приватные данные.
///
/// Claude Code не позволяет хуку изменить текст запроса, поэтому оригинал
/// блокируется, а копию передаёт модели второй, фоновый обработчик с
/// `asyncRewake`: его вывод при коде 2 приходит модели вместо запроса.
pub fn masked_prompt(event: &Value, policy: Policy, vault: &Vault) -> Result<Option<String>> {
    if event["hook_event_name"] != "UserPromptSubmit" {
        return Ok(None);
    }
    let session = event["session_id"]
        .as_str()
        .ok_or(Error("session_id_required"))?;
    let prompt = event["prompt"].as_str().ok_or(Error("prompt_required"))?;
    let masked = vault.mask(session, policy, &Value::String(prompt.into()))?;
    let masked = masked.as_str().ok_or(Error("invalid_output"))?;
    Ok((masked != prompt).then(|| masked.to_owned()))
}

fn blocked_prompt(masked: Option<&str>) -> Value {
    let reason = match masked {
        Some(masked) => format!(
            "Sanctum: приватные данные заменены псевдонимами, модель получает замаскированную копию запроса.\n\n{masked}"
        ),
        None => "Sanctum: запрос не отправлен модели из-за ошибки локальной проверки. Исходный текст скрыт.".into(),
    };
    value!({"decision":"block","reason":reason,
        "hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}})
}

/// Возвращает замаскированное значение в форме исходного: Claude Code
/// отклоняет `updatedToolOutput` другой формы и тогда передаёт модели оригинал.
/// Числа и флаги, ставшие псевдонимами, заменяются нейтральными значениями,
/// данные изображений не меняются.
fn conform(original: &Value, masked: &Value, field: Option<&str>) -> Value {
    if field == Some("base64") {
        return original.clone();
    }
    match (original, masked) {
        (Value::Object(left), Value::Object(right)) if left.len() == right.len() => Value::Object(
            left.iter()
                .zip(right.iter())
                .map(|((key, a), (safe_key, b))| (safe_key.clone(), conform(a, b, Some(key))))
                .collect(),
        ),
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => Value::Array(
            left.iter()
                .zip(right)
                .map(|(a, b)| conform(a, b, field))
                .collect(),
        ),
        (Value::String(_), Value::String(_)) => masked.clone(),
        (a, b) if a == b => b.clone(),
        _ => omit(original),
    }
}

fn omit(original: &Value) -> Value {
    match original {
        Value::String(_) => Value::String(OMITTED.into()),
        Value::Number(_) => value!(0),
        Value::Bool(_) => Value::Bool(false),
        Value::Array(items) => Value::Array(items.iter().map(omit).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), omit(item)))
                .collect(),
        ),
        Value::Null => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conform_keeps_shape() {
        let original = value!({"stdout":"a@b.example","code":4111111111111111u64,"ok":true,"file":{"base64":"QUJD"}});
        let masked =
            value!({"stdout":"[EMAIL-1]","code":"[CARD-1]","ok":true,"file":{"base64":"[KEY-1]"}});
        assert_eq!(
            conform(&original, &masked, None),
            value!({"stdout":"[EMAIL-1]","code":0,"ok":true,"file":{"base64":"QUJD"}})
        );
    }

    #[test]
    fn failure_hides_output() {
        let event =
            value!({"hook_event_name":"PostToolUse","tool_response":{"stdout":"secret","n":3}});
        assert_eq!(
            failure(Some(&event))["hookSpecificOutput"]["updatedToolOutput"],
            value!({"stdout":OMITTED,"n":0})
        );
    }
}
