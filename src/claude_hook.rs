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
    let session = &scope(event)?;
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
        Some("MessageDisplay") => {
            let delta = event["delta"].as_str().unwrap_or("");
            if !has_tokens(&Value::String(delta.into())) || !vault.exists(session)? {
                return Ok(None);
            }
            let style = DisplayStyle::current();
            let shown =
                vault.transact(session, policy, |engine| Ok(display(engine, delta, style)))?;
            if shown == delta {
                return Ok(None);
            }
            Ok(Some(
                value!({"hookSpecificOutput":{"hookEventName":"MessageDisplay","displayContent":shown}}),
            ))
        }
        _ => Ok(None),
    }
}

/// Как выделить восстановленное значение на экране, чтобы было видно,
/// что модель получила вместо него псевдоним.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayStyle {
    /// Тёмно-серый цвет ANSI для терминала.
    Ansi,
    /// Серая формула LaTeX для интерфейсов, которые показывают markdown с
    /// формулами, но не HTML (десктопное приложение Claude).
    Latex,
    /// Значение без оформления.
    Plain,
}
impl DisplayStyle {
    pub fn current() -> Self {
        match std::env::var("SANCTUM_DISPLAY_STYLE").as_deref() {
            Ok("ansi") => Self::Ansi,
            Ok("latex") => Self::Latex,
            Ok("plain") => Self::Plain,
            _ if std::env::var("CLAUDE_CODE_ENTRYPOINT").as_deref() == Ok("cli") => Self::Ansi,
            _ => Self::Latex,
        }
    }
}

/// Заменяет известные псевдонимы исходными значениями только для показа.
/// Внутри блоков и фрагментов кода формулы не работают, поэтому там значение
/// вставляется без оформления.
pub fn display(engine: &Redactor, text: &str, style: DisplayStyle) -> String {
    let mut result = String::with_capacity(text.len());
    let mut fenced = false;
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with("```") || line.trim_start().starts_with("~~~") {
            fenced = !fenced;
            result.push_str(line);
            continue;
        }
        let mut cursor = 0;
        for token in crate::redaction::token_matches(line) {
            let Some(original) = engine.original(token) else {
                continue;
            };
            let start = token.as_ptr() as usize - line.as_ptr() as usize;
            let inline_code = line[..start].matches('`').count() % 2 == 1;
            result.push_str(&line[cursor..start]);
            result.push_str(&match style {
                DisplayStyle::Ansi => format!("\x1b[90m{original}\x1b[39m"),
                DisplayStyle::Latex if !fenced && !inline_code => gray_latex(original),
                _ => original.to_owned(),
            });
            cursor = start + token.len();
        }
        result.push_str(&line[cursor..]);
    }
    result
}

/// Предел длины формулы, которую десктопное приложение ещё распознаёт.
const FORMULA_LIMIT: usize = 60;

/// Записывает значение серыми формулами LaTeX так, как их распознаёт
/// десктопное приложение: исходник каждой формулы не длиннее
/// [`FORMULA_LIMIT`], в нём нет буквального `@`, а формулы разделены
/// невидимым U+2060, чтобы `$$` не превратилось в выносную формулу.
/// Перед `:` и `.` и внутри лигатур вроде `--` начинается новый `\text{}`,
/// чтобы в исходнике не было ссылок и значение показалось без изменений.
fn gray_latex(text: &str) -> String {
    const OPEN: &str = "\\color{gray}{";
    let mut formulas = Vec::new();
    let mut body = String::new();
    let mut in_text = false;
    let mut previous = None;
    let close = |body: &mut String, in_text: &mut bool| {
        if *in_text {
            body.push('}');
            *in_text = false;
        }
    };
    for c in text.chars() {
        let (snippet, text_mode, command) = match c {
            '\\' => ("\\textbackslash".to_owned(), true, true),
            '^' => ("\\textasciicircum".to_owned(), true, true),
            '~' => ("\\textasciitilde".to_owned(), true, true),
            '@' => ("\\char64".to_owned(), false, false),
            '{' | '}' | '$' | '&' | '%' | '#' | '_' => (format!("\\{c}"), true, false),
            _ => (c.to_string(), true, false),
        };
        let opening = if text_mode && !in_text {
            "\\text{".len()
        } else {
            0
        };
        if !body.is_empty() && OPEN.len() + body.len() + opening + snippet.len() + 2 > FORMULA_LIMIT
        {
            close(&mut body, &mut in_text);
            formulas.push(std::mem::take(&mut body));
        }
        if !text_mode
            || matches!(c, ':' | '.')
            || matches!(c, '-' | '\'' | '`') && previous == Some(c)
        {
            close(&mut body, &mut in_text);
        }
        if text_mode && !in_text {
            body.push_str("\\text{");
            in_text = true;
        }
        body.push_str(&snippet);
        if command {
            close(&mut body, &mut in_text);
        }
        previous = Some(c);
    }
    close(&mut body, &mut in_text);
    if !body.is_empty() {
        formulas.push(body);
    }
    formulas
        .iter()
        .map(|body| format!("${OPEN}{body}}}$"))
        .collect::<Vec<_>>()
        .join("\u{2060}")
}

/// Соответствия общие для проекта: Claude Code выдаёт новый `session_id` при
/// возобновлении, форке и `/clear`, а псевдонимы в истории должны продолжать
/// восстанавливаться. Без каталога проекта используется сеанс.
fn scope(event: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};
    let project = std::env::var("CLAUDE_PROJECT_DIR")
        .ok()
        .filter(|path| !path.is_empty())
        .or_else(|| event["cwd"].as_str().map(str::to_owned));
    match project {
        Some(path) => Ok(format!(
            "claude-project-{:x}",
            Sha256::digest(path.as_bytes())
        )),
        None => event["session_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or(Error("session_id_required")),
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

/// Замаскированный запрос, если в нём или в упомянутых через `@` файлах есть
/// приватные данные.
///
/// Claude Code не позволяет хуку изменить текст запроса, поэтому оригинал
/// блокируется, а копию передаёт модели второй, фоновый обработчик с
/// `asyncRewake`: его вывод при коде 2 приходит модели вместо запроса.
/// Упомянутые файлы Claude Code прикладывает сам, мимо хуков инструментов;
/// при блокировке они не прикладываются, а модель получает просьбу прочитать
/// их инструментом Read, вывод которого маскируется.
pub fn masked_prompt(event: &Value, policy: Policy, vault: &Vault) -> Result<Option<String>> {
    if event["hook_event_name"] != "UserPromptSubmit" {
        return Ok(None);
    }
    let session = &scope(event)?;
    let prompt = event["prompt"].as_str().ok_or(Error("prompt_required"))?;
    let directory = event["cwd"]
        .as_str()
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CLAUDE_PROJECT_DIR").map(PathBuf::from));
    let mut private = Vec::new();
    for mention in mentions(prompt) {
        if let Some(path) = mentioned_file(&mention, directory.as_deref())
            && private_file(vault, session, policy.clone(), &path)?
        {
            private.push(mention);
        }
    }
    let mut text = prompt.to_owned();
    if !private.is_empty() {
        text.push_str(&format!(
            "\n\n[Sanctum: these files mentioned with @ were not attached because they contain private data: {}. Read them with the Read tool; their contents will be masked.]",
            private.join(", ")
        ));
    }
    let masked = vault.mask(session, policy, &Value::String(text))?;
    let masked = masked.as_str().ok_or(Error("invalid_output"))?;
    Ok((masked != prompt).then(|| masked.to_owned()))
}

/// Упоминания файлов так, как их находит Claude Code: `@"путь"` и `@путь` в
/// начале слова, без концевой пунктуации.
fn mentions(prompt: &str) -> Vec<String> {
    const DELIMITERS: &[char] = &['\u{3002}', '\u{3001}', '\u{FF1F}', '\u{FF01}'];
    let delimiter = |c: char| c.is_whitespace() || DELIMITERS.contains(&c);
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let mut found = Vec::new();
    let mut previous = None;
    for (index, c) in prompt.char_indices() {
        if c == '@'
            && previous.is_none_or(delimiter)
            && let Some(rest) = prompt[index + 1..].strip_prefix('"')
            && let Some(end) = rest.find('"')
            && end > 0
        {
            found.push(rest[..end].to_owned());
        }
        previous = Some(c);
    }
    for token in prompt.split(delimiter).filter(|t| !t.is_empty()) {
        let mut start = None;
        let mut before = None;
        for (index, c) in token.char_indices() {
            if c == '@' && (index == 0 || before.is_some_and(|b| DELIMITERS.contains(&b))) {
                start = Some(index + 1);
                break;
            }
            before = Some(c);
        }
        let Some(start) = start else { continue };
        let rest = &token[start..];
        if rest.starts_with('"') {
            continue;
        }
        let chars: Vec<char> = rest.chars().collect();
        let mut end = chars.len();
        while end >= 1 && word(chars.get(end - 1).copied()) == word(chars.get(end).copied()) {
            end -= 1;
        }
        if end >= 1 {
            found.push(chars[..end].iter().collect());
        }
    }
    found.sort();
    found.dedup();
    found
}

fn mentioned_file(mention: &str, directory: Option<&std::path::Path>) -> Option<PathBuf> {
    let path = mention.split('#').next().filter(|p| !p.is_empty())?;
    let path = match path.strip_prefix("~/") {
        Some(rest) => crate::platform::home().ok()?.join(rest),
        None => PathBuf::from(path),
    };
    let path = if path.is_absolute() {
        path
    } else {
        directory?.join(path)
    };
    path.is_file().then_some(path)
}

/// Есть ли в текстовом файле приватные данные. Слишком большой файл считается
/// приватным: проверить его целиком нельзя. Двоичные файлы, включая
/// изображения, не проверяются.
fn private_file(
    vault: &Vault,
    session: &str,
    policy: Policy,
    path: &std::path::Path,
) -> Result<bool> {
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(false);
    };
    if metadata.len() > crate::MAX_BODY as u64 / 2 {
        return Ok(true);
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(false);
    };
    let content = Value::String(text);
    Ok(vault.mask(session, policy, &content)? != content)
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
    fn gray_latex_keeps_value_literal_and_short() {
        assert_eq!(
            gray_latex(r"a--b_c$"),
            r"$\color{gray}{\text{a-}\text{-b\_c\$}}$"
        );
        assert_eq!(
            gray_latex(r"d\e"),
            r"$\color{gray}{\text{d\textbackslash}\text{e}}$"
        );
        assert_eq!(
            gray_latex("x@y-z.example"),
            r"$\color{gray}{\text{x}\char64\text{y-z}\text{.example}}$"
        );
        let long = gray_latex(&"Zq9".repeat(30));
        let formulas: Vec<&str> = long.split('\u{2060}').collect();
        assert!(formulas.len() > 1);
        assert!(formulas.iter().all(|f| f.len() - 2 <= FORMULA_LIMIT));
        let shown: String = formulas
            .iter()
            .map(|f| {
                f.trim_start_matches(r"$\color{gray}{\text{")
                    .trim_end_matches("}}$")
            })
            .collect();
        assert_eq!(shown, "Zq9".repeat(30));
    }

    #[test]
    fn mentions_follow_claude_code_syntax() {
        assert_eq!(
            mentions(r#"see @src/a.rs#L1-5, @"my dir/b.txt" and @c.md). (@d.md) mail a@b.example"#),
            vec!["c.md", "my dir/b.txt", "src/a.rs#L1-5"]
        );
        assert!(mentions("no mentions, a@b.example").is_empty());
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
