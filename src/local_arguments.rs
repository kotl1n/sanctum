use crate::{Error, Result, protocol::Session};
use serde_json::Value;

pub fn restore(session: &Session, input: &Value, name: &str) -> Result<Value> {
    let mut result = input.clone();
    let Some(map) = result.as_object_mut() else {
        return Err(Error("local_arguments_object_required"));
    };

    if map.get("environment_id").is_some_and(|v| !v.is_null()) {
        return Ok(result);
    }
    let fields: &[(&str, bool)] = match name {
        "Bash" | "bash" | "exec_command" | "shell_command" => &[
            ("cmd", true),
            ("command", true),
            ("workdir", false),
            ("cwd", false),
        ],
        "shell" => &[("command", true), ("workdir", false), ("cwd", false)],
        "write_stdin" => &[("chars", true)],
        "read_file" => &[("path", false), ("file_path", false), ("file", false)],
        "list_directory" | "glob_files" => &[("path", false), ("pattern", false)],
        "grep_files" => &[("path", false), ("pattern", false), ("include", false)],

        "exec" => {
            return crate::json::parse(session.arguments(&input.to_string(), name)?.as_bytes());
        }
        "apply_patch" => &[("command", false), ("patch", false), ("input", false)],
        _ => return Ok(result),
    };
    for &(field, code) in fields {
        let Some(value) = map.get_mut(field) else {
            continue;
        };
        let Some(text) = value.as_str() else { continue };

        let encoded = serde_json::to_string(text).map_err(|_| Error("invalid_arguments"))?;
        let restored: Value = if name == "apply_patch" {
            Value::String(crate::patch_arguments::restore(session, text)?)
        } else {
            crate::json::parse(
                session
                    .arguments(&encoded, if code { "exec" } else { "data" })?
                    .as_bytes(),
            )?
        };
        if restored.as_str().is_some_and(|s| s.contains('\0')) {
            return Err(Error("local_argument_nul"));
        }
        *value = restored;
    }
    Ok(result)
}
