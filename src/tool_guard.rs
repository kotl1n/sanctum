//! Local tool boundary. Inputs are restored only for explicitly supported tools.
use crate::{Error, Result, json, protocol::Session, redaction::Policy, vault::Vault};
use serde_json::{Value, json as value};

pub fn handle(event: &Value, policy: Policy, vault: &Vault) -> Result<Option<Value>> {
    handle_with_policy_path(event, policy, vault, None)
}
pub fn handle_with_policy_path(
    event: &Value,
    policy: Policy,
    vault: &Vault,
    policy_path: Option<&std::path::Path>,
) -> Result<Option<Value>> {
    let session = event["session_id"]
        .as_str()
        .ok_or(Error("session_id_required"))?;
    match event["hook_event_name"].as_str() {
        Some("UserPromptSubmit") => {
            let text = event["prompt"].as_str().ok_or(Error("prompt_required"))?;
            let safe = vault.mask(session, policy, &Value::String(text.into()))?;
            // The bridge has already rewritten prompts. Direct clients retain
            // a blocking guard instead of passing unsanitized prompts through.
            if safe.as_str() == Some(text) {
                Ok(None)
            } else {
                Ok(Some(
                    value!({"decision":"block","reason":"Sanctum: отправка остановлена. Этот клиент передал исходный текст. Используйте запуск Sanctum без порта для автоматических замен."}),
                ))
            }
        }
        Some("PreToolUse") => {
            let name = event["tool_name"]
                .as_str()
                .ok_or(Error("tool_name_required"))?;
            let input = event
                .get("tool_input")
                .ok_or(Error("tool_input_required"))?;
            if !vault.exists(session)? {
                return Err(Error("protected_session_required"));
            }
            let supported = [
                "Bash",
                "bash",
                "exec",
                "exec_command",
                "shell_command",
                "shell",
                "apply_patch",
                "read_file",
                "list_directory",
                "grep_files",
                "glob_files",
            ];
            if ["update_plan", "request_user_input"].contains(&name) {
                return Ok(None);
            }
            let encoded = json::encode(input)?;
            if !supported.contains(&name) {
                // Even an unknown tool without placeholders can return opaque
                // content. This mode supports local text tools only.
                return Err(Error("unsupported_tool_in_private_mode"));
            }
            if ["Bash", "bash", "exec_command", "shell_command", "shell"].contains(&name) {
                let command_field = if input.get("command").is_some() {
                    "command"
                } else {
                    "cmd"
                };
                let command = input[command_field]
                    .as_str()
                    .ok_or(Error("command_required"))?;
                let executable = std::env::var_os("SANCTUM_GUARD_EXECUTABLE")
                    .map(std::path::PathBuf::from)
                    .map(Ok)
                    .unwrap_or_else(|| {
                        std::env::current_exe().map_err(|_| Error("binary_location_failed"))
                    })?;
                let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
                let hex: String = command
                    .as_bytes()
                    .iter()
                    .map(|c| format!("{c:02x}"))
                    .collect();
                let mut replacement = input.clone();
                let policy_arg = policy_path
                    .map(|p| format!(" --policy {}", quote(&p.to_string_lossy())))
                    .unwrap_or_default();
                let shell_arg = input
                    .get("shell")
                    .and_then(Value::as_str)
                    .map(|s| format!(" --shell {}", quote(s)))
                    .unwrap_or_default();
                let login_arg = if input.get("login") == Some(&Value::Bool(true)) {
                    " --login"
                } else {
                    ""
                };
                let cwd = input
                    .get("workdir")
                    .or_else(|| input.get("cwd"))
                    .and_then(Value::as_str);
                let cwd_arg = cwd
                    .map(|s| {
                        format!(
                            " --cwd-hex {}",
                            s.as_bytes()
                                .iter()
                                .map(|c| format!("{c:02x}"))
                                .collect::<String>()
                        )
                    })
                    .unwrap_or_default();
                if let Some(object) = replacement.as_object_mut() {
                    object.remove("workdir");
                    object.remove("cwd");
                }
                replacement[command_field] = Value::String(format!(
                    "{} run-command --session {} --command-hex {}{}{}{}{}",
                    quote(&executable.to_string_lossy()),
                    quote(session),
                    hex,
                    policy_arg,
                    shell_arg,
                    login_arg,
                    cwd_arg
                ));
                return Ok(Some(
                    value!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":replacement}}),
                ));
            }
            let restored = vault.transact(session, policy.clone(), |engine| {
                let session = Session::new(crate::redaction::Redactor::from_snapshot(
                    policy,
                    &engine.snapshot(),
                )?);
                let text = std::str::from_utf8(&encoded).map_err(|_| Error("invalid_arguments"))?;
                json::parse(session.arguments(text, name)?.as_bytes())
            })?;
            if &restored == input {
                Ok(None)
            } else {
                Ok(Some(
                    value!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":restored}}),
                ))
            }
        }
        Some("PostToolUse") => {
            if !vault.exists(session)? {
                return Err(Error("protected_session_required"));
            }
            let response = event
                .get("tool_response")
                .ok_or(Error("tool_response_required"))?;
            let safe = vault.mask(session, policy, response)?;
            if &safe == response {
                return Ok(None);
            }
            // continue:false can still expose the original to a running code
            // script. A blocking result rejects that promise with safe text.
            let feedback =
                serde_json::to_string(&safe).map_err(|_| Error("output_encode_failed"))?;
            Ok(Some(value!({"decision":"block","reason":feedback})))
        }
        _ => Err(Error("unexpected_hook_event")),
    }
}
pub fn failure(event: Option<&Value>) -> Value {
    let reason = "Sanctum: действие остановлено — локальная проверка или восстановление данных не выполнены. Исходные значения скрыты.";
    let _ = event;
    value!({"decision":"block","reason":reason})
}
