use crate::{
    MAX_BODY,
    redaction::{Policy, Redactor},
    vault::Vault,
};
use serde_json::{Value, json};
use std::{collections::HashMap, path::Path, sync::Mutex};

pub const OMITTED: &str = "[SANCTUM-REDACTED: content could not be masked]";
pub const ATTACHMENT: &str = "[SANCTUM-ATTACHMENT: non-text attachment omitted]";

pub fn app_server_args(args: &[std::ffi::OsString]) -> Option<&[std::ffi::OsString]> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let text = arg.to_string_lossy();
        if matches!(text.as_ref(), "-c" | "--config" | "--enable" | "--disable") {
            args.get(index + 1)?;
            index += 2;
        } else if ["--config=", "--enable=", "--disable="]
            .iter()
            .any(|prefix| text.starts_with(prefix))
            || (text.starts_with("-c") && text.len() > 2)
        {
            index += 1;
        } else {
            return (arg == "app-server").then_some(&args[index..]);
        }
    }
    None
}

pub struct Rewriter {
    vault: Option<Vault>,
    policy: Policy,
    policy_available: bool,
    memory: Mutex<HashMap<String, Redactor>>,
    pending: HashMap<String, String>,
}
impl Rewriter {
    pub fn new(vault: Option<Vault>, policy: Policy) -> Self {
        Self {
            vault,
            policy,
            policy_available: true,
            memory: Mutex::new(HashMap::new()),
            pending: HashMap::new(),
        }
    }
    pub fn with_unavailable_policy(mut self) -> Self {
        self.policy_available = false;
        self
    }
    pub fn known_provider_opaque(&self, session: &str, cipher: &str) -> bool {
        self.vault.as_ref().is_some_and(|vault| {
            vault
                .transact(session, self.policy.clone(), |engine| {
                    Ok(engine.known_provider_opaque(cipher))
                })
                .unwrap_or(false)
        })
    }
    pub fn known_provider_item(&self, session: &str, item: &Value) -> bool {
        let Some(kind) = crate::opaque::kind(item) else {
            return false;
        };
        let Some(cipher) = item["encrypted_content"].as_str() else {
            return false;
        };
        self.known_provider_opaque(session, &crate::opaque::key(kind, cipher))
            || (kind == "reasoning" && self.known_provider_opaque(session, cipher))
    }
    pub fn approve_provider_request(&self, session: &str, request: &str) -> crate::Result<()> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(crate::Error("persistent_vault_required"))?;
        if request.is_empty() || request.len() > 128 {
            return Err(crate::Error("invalid_provider_request"));
        }
        vault.transact(session, self.policy.clone(), |engine| {
            engine.remember_provider_opaque(&format!("sanctum-request-v1:{request}"))
        })
    }

    pub fn mask(&self, session: &str, texts: &Value) -> Value {
        self.try_mask(session, texts)
            .unwrap_or_else(|_| omit_strings(texts))
    }

    pub fn try_mask(&self, session: &str, texts: &Value) -> crate::Result<Value> {
        if !self.policy_available {
            return Err(crate::Error("rewrite_policy_unavailable"));
        }
        if let Some(vault) = &self.vault {
            return vault.transact(session, self.policy.clone(), |engine| {
                engine.reserve(texts)?;
                let once = engine.value(texts)?;
                engine.value(&once)
            });
        }

        let operation = || -> crate::Result<Value> {
            let mut memory = self
                .memory
                .lock()
                .map_err(|_| crate::Error("rewrite_state_failed"))?;
            if !memory.contains_key(session) {
                if memory.len() >= 128 {
                    return Err(crate::Error("rewrite_session_capacity"));
                }
                memory.insert(session.into(), Redactor::new(self.policy.clone())?);
            }
            let engine = memory
                .get_mut(session)
                .ok_or(crate::Error("rewrite_state_failed"))?;
            engine.reserve(texts)?;
            let once = engine.value(texts)?;
            engine.value(&once)
        };
        operation()
    }
    pub fn incoming(&mut self, message: &Value, active: bool) -> Value {
        if !active {
            return message.clone();
        }
        let mut safe = message.clone();
        match message["method"].as_str() {
            Some("thread/start") => {
                let session = format!(
                    "rewrite-{}",
                    crate::setup::random_key().unwrap_or_else(|_| "temporary".into())
                );
                let instructions: serde_json::Map<String, Value> =
                    ["baseInstructions", "developerInstructions"]
                        .into_iter()
                        .filter_map(|key| {
                            message["params"]
                                .get(key)
                                .filter(|v| !v.is_null())
                                .map(|v| (key.into(), v.clone()))
                        })
                        .collect();
                let masked = self.mask(&session, &Value::Object(instructions));
                if let Some(params) = safe.get_mut("params").and_then(Value::as_object_mut)
                    && let Some(fields) = masked.as_object()
                {
                    for (key, value) in fields {
                        params.insert(key.clone(), value.clone());
                    }
                }
                if self.pending.len() >= 128 {
                    self.pending.clear();
                }
                self.pending.insert(message["id"].to_string(), session);
            }
            Some("turn/start" | "turn/steer") => {
                let session = message["params"]["threadId"]
                    .as_str()
                    .unwrap_or("rewrite-unidentified");
                if let Some(input) = safe
                    .get_mut("params")
                    .and_then(|p| p.get_mut("input"))
                    .and_then(Value::as_array_mut)
                {
                    for item in input.iter_mut() {
                        match item["type"].as_str() {
                            Some("text") => {
                                if let Some(obj) = item.as_object_mut() {
                                    obj.remove("text_elements");
                                    obj.remove("textElements");
                                }
                            }
                            Some("mention" | "skill") => {
                                *item = json!({"type":"text", "text":attachment_text(item)});
                            }
                            _ => {
                                *item = json!({"type":"text", "text":ATTACHMENT});
                            }
                        }
                    }
                    let texts = Value::Array(
                        input
                            .iter()
                            .map(|i| i.get("text").cloned().unwrap_or(json!(OMITTED)))
                            .collect(),
                    );
                    let masked = self.mask(session, &texts);
                    if let Some(texts) = masked.as_array() {
                        for (item, text) in input.iter_mut().zip(texts) {
                            item["text"] = text.clone();
                        }
                    }
                }
            }
            _ => {}
        }
        safe
    }
    pub fn outgoing(&mut self, message: &Value) {
        if message.get("method").is_some() {
            return;
        }
        let Some(source) = self.pending.remove(&message["id"].to_string()) else {
            return;
        };
        if let Some(thread) = message["result"]["thread"]["id"].as_str() {
            if let Some(vault) = &self.vault {
                let _ = vault.copy_session(&source, thread, self.policy.clone());
                let _ = vault.forget(&source);
            }
            if let Ok(mut memory) = self.memory.lock()
                && let Some(engine) = memory.remove(&source)
            {
                memory.insert(thread.into(), engine);
            }
        }
    }
}
fn omit_strings(value: &Value) -> Value {
    match value {
        Value::String(_) => json!(OMITTED),
        Value::Array(items) => Value::Array(items.iter().map(omit_strings).collect()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(k, v)| (k.clone(), omit_strings(v)))
                .collect(),
        ),
        _ => value.clone(),
    }
}
fn attachment_text(item: &Value) -> String {
    let read = || -> Option<String> {
        let path = Path::new(item["path"].as_str()?);
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !path.is_absolute()
            || !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.len() > MAX_BODY as u64
        {
            return None;
        }
        use std::io::Read;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        std::fs::File::open(path)
            .ok()?
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > MAX_BODY {
            return None;
        }
        let text = std::str::from_utf8(&bytes).ok()?;
        if text.contains('\0') {
            return None;
        }
        Some(text.into())
    };
    read().unwrap_or_else(|| ATTACHMENT.into())
}

pub async fn run(executable: &Path, args: &[std::ffi::OsString]) -> crate::Result<i32> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let policy_path = std::env::var_os("SANCTUM_GUARD_POLICY").map(std::path::PathBuf::from);
    let policy = crate::setup::load_policy(policy_path.as_deref());
    let valid_policy = policy.is_ok();
    let vault = Vault::default_directory().and_then(Vault::new).ok();
    let mut rewriter = Rewriter::new(vault, policy.unwrap_or_default());
    if !valid_policy {
        rewriter = rewriter.with_unavailable_policy();
    }
    let mut backend = tokio::process::Command::new(executable);
    backend.args(args);
    if std::env::var_os("SANCTUM_CONTEXT_PROTECTION").is_some_and(|v| v == "1") {
        if std::env::var_os("SANCTUM_VERIFY_COMPATIBILITY").is_some_and(|v| v == "1") {
            let checker = std::env::current_exe()
                .map_err(|_| crate::Error("binary_location_failed"))?
                .parent()
                .ok_or(crate::Error("binary_location_failed"))?
                .join("../ui/manage_backend.py");
            let checked = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::process::Command::new("python3")
                    .arg(checker)
                    .arg("check")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .status(),
            )
            .await;
            if !matches!(checked, Ok(Ok(status)) if status.success()) {
                return Err(crate::Error("desktop_compatibility_changed"));
            }
        }
        let proof = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::process::Command::new(executable)
                .arg("--sanctum-context-protocol")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| crate::Error("context_backend_probe_failed"))?
        .map_err(|_| crate::Error("context_backend_probe_failed"))?;
        if !proof.status.success() || proof.stdout != b"sanctum-context-v2\n" {
            return Err(crate::Error("verified_context_backend_required"));
        }
        let helper = std::env::current_exe()
            .map_err(|_| crate::Error("binary_location_failed"))?
            .with_file_name(crate::platform::executable("sanctum-guard"));
        backend
            .env("SANCTUM_NATIVE_HELPER", helper)
            .env("SANCTUM_NATIVE_REQUIRED", "1");
        backend.arg("-c").arg("web_search=\"disabled\"");
    } else {
        backend
            .env_remove("SANCTUM_NATIVE_REQUIRED")
            .env_remove("SANCTUM_NATIVE_HELPER");
    }
    let mut child = backend
        .env_remove("CODEX_CLI_PATH")
        .env("SANCTUM_PORTLESS_ACTIVE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| crate::Error("backend_start_failed"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or(crate::Error("backend_pipe_failed"))?;
    let mut stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or(crate::Error("backend_pipe_failed"))?,
    )
    .lines();
    let mut client = BufReader::new(tokio::io::stdin()).lines();
    let mut output = tokio::io::stdout();
    loop {
        tokio::select! {
            incoming = client.next_line() => {
                let Some(line) = incoming.map_err(|_| crate::Error("rpc_read_failed"))? else { break; };
                let transformed = match serde_json::from_str::<Value>(&line) {
                    Ok(message) => rewriter.incoming(&message, crate::settings::try_active().unwrap_or(true)).to_string(),
                    Err(_) => line,
                };
                stdin.write_all(transformed.as_bytes()).await.map_err(|_| crate::Error("backend_pipe_failed"))?;
                stdin.write_all(b"\n").await.map_err(|_| crate::Error("backend_pipe_failed"))?;
                stdin.flush().await.map_err(|_| crate::Error("backend_pipe_failed"))?;
            }
            outgoing = stdout.next_line() => {
                let Some(line) = outgoing.map_err(|_| crate::Error("backend_read_failed"))? else { break; };
                if let Ok(message) = serde_json::from_str::<Value>(&line) { rewriter.outgoing(&message); }
                output.write_all(line.as_bytes()).await.map_err(|_| crate::Error("rpc_write_failed"))?;
                output.write_all(b"\n").await.map_err(|_| crate::Error("rpc_write_failed"))?;
                output.flush().await.map_err(|_| crate::Error("rpc_write_failed"))?;
            }
        }
    }
    let _ = child.start_kill();
    Ok(child
        .wait()
        .await
        .map_err(|_| crate::Error("backend_wait_failed"))?
        .code()
        .unwrap_or(0))
}
