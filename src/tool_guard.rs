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
    if std::env::var_os("SANCTUM_CONTEXT_PROTECTION").is_some_and(|v| v == "1") {
        return context_hook(event, session, policy, vault);
    }
    match event["hook_event_name"].as_str() {
        Some("UserPromptSubmit") => Ok(None),
        Some("PreToolUse") => {
            if cfg!(windows) {
                return Err(Error("windows_context_backend_required"));
            }
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

            let feedback =
                serde_json::to_string(&safe).map_err(|_| Error("output_encode_failed"))?;
            Ok(Some(value!({"decision":"block","reason":feedback})))
        }
        _ => Err(Error("unexpected_hook_event")),
    }
}

pub fn context_hook(
    event: &Value,
    session: &str,
    policy: Policy,
    vault: &Vault,
) -> Result<Option<Value>> {
    if event["hook_event_name"] != "PreToolUse" {
        return Ok(None);
    }
    let name = event["tool_name"].as_str().unwrap_or("");
    let local = [
        "Bash",
        "bash",
        "exec",
        "exec_command",
        "shell_command",
        "shell",
        "write_stdin",
        "apply_patch",
        "read_file",
        "list_directory",
        "grep_files",
        "glob_files",
    ];

    if !local.contains(&name) {
        return Ok(None);
    }
    let Some(input) = event.get("tool_input") else {
        return Ok(None);
    };
    if crate::redaction::token_matches(&input.to_string())
        .next()
        .is_none()
    {
        return Ok(None);
    }
    let restored = vault.transact(session, policy.clone(), |engine| {
        let session = Session::new(crate::redaction::Redactor::from_snapshot(
            policy,
            &engine.snapshot(),
        )?);
        crate::local_arguments::restore(&session, input, name)
    })?;
    if restored == *input {
        return Ok(None);
    }

    Ok(Some(
        value!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":restored}}),
    ))
}
pub fn failure(event: Option<&Value>) -> Value {
    let reason = "Sanctum: действие заблокировано из-за ошибки локальной проверки или восстановления данных. Исходные значения скрыты.";
    let _ = event;
    value!({"decision":"block","reason":reason})
}
