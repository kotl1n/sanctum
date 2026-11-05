use crate::{Error, MAX_BODY, Result, json, redaction::Policy, vault::Vault};
use serde_json::{Value, json as value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

fn key(id: &Value) -> Result<String> {
    if !id.is_string() && !id.is_number() {
        return Err(Error("rpc_id_required"));
    }
    Ok(id.to_string())
}
pub struct Filter {
    pub vault: Arc<Vault>,
    policy: Policy,
    pending: Mutex<HashMap<String, String>>,
    callbacks: Mutex<HashMap<String, String>>,
    cwds: Mutex<HashMap<String, PathBuf>>,
    native_boundary: bool,
}
impl Filter {
    pub fn new(vault: Arc<Vault>, policy: Policy) -> Self {
        Self {
            vault,
            policy,
            pending: Mutex::new(HashMap::new()),
            callbacks: Mutex::new(HashMap::new()),
            cwds: Mutex::new(HashMap::new()),
            native_boundary: false,
        }
    }
    pub fn incoming(&self, message: &Value) -> Result<Value> {
        if message.get("method").is_none() && message.get("id").is_some() {
            let session = self
                .callbacks
                .lock()
                .map_err(|_| Error("bridge_state_failed"))?
                .remove(&key(&message["id"])?)
                .ok_or(Error("unknown_backend_request"))?;

            if session.is_empty() {
                return Ok(message.clone());
            }
            let mut result = message.clone();
            if let Some(data) = result.get_mut("result") {
                *data = self.vault.mask(&session, self.policy.clone(), data)?;
            }
            if result.get("error").is_some() {
                result["error"] = value!({"code":-32010,"message":"Client response error; details omitted by Sanctum."});
            }
            return Ok(result);
        }
        let method = message["method"].as_str().ok_or(Error("invalid_rpc"))?;
        let mut result = message.clone();
        match method {
            "initialize" => {
                result["params"]["capabilities"]["experimentalApi"] = Value::Bool(true);
            }
            "thread/start" => {
                let id = key(&message["id"])?;
                let session = format!("start-{}", crate::setup::random_key()?);
                let params = result["params"]
                    .as_object_mut()
                    .ok_or(Error("invalid_rpc_params"))?;

                let instructions: serde_json::Map<String, Value> =
                    ["baseInstructions", "developerInstructions"]
                        .into_iter()
                        .filter_map(|field| {
                            params
                                .get(field)
                                .filter(|v| !v.is_null())
                                .map(|v| (field.into(), v.clone()))
                        })
                        .collect();
                let safe =
                    self.vault
                        .mask(&session, self.policy.clone(), &Value::Object(instructions))?;
                for (field, text) in safe.as_object().ok_or(Error("invalid_instructions"))? {
                    params.insert(field.clone(), text.clone());
                }
                if let Some(cwd) = params.get("cwd").and_then(Value::as_str) {
                    self.preflight(Path::new(cwd))?;
                }
                self.vault
                    .transact(&session, self.policy.clone(), |_| Ok(()))?;
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| Error("bridge_state_failed"))?;
                if pending.len() >= 128 {
                    return Err(Error("bridge_capacity"));
                }
                pending.insert(id, session);
            }
            "turn/start" | "turn/steer" => {
                let session = message["params"]["threadId"]
                    .as_str()
                    .ok_or(Error("thread_id_required"))?;
                if !self.vault.exists(session)? {
                    return Err(Error("protected_session_required"));
                }
                let cwd = message["params"]["cwd"]
                    .as_str()
                    .map(PathBuf::from)
                    .or_else(|| self.cwds.lock().ok()?.get(session).cloned())
                    .ok_or(Error("protected_cwd_required"))?;
                self.preflight(&cwd)?;
                let input = result["params"]["input"]
                    .as_array_mut()
                    .ok_or(Error("input_required"))?;
                for item in input.iter_mut() {
                    match item["type"].as_str() {
                        Some("text") => {
                            let text = item["text"].as_str().ok_or(Error("text_required"))?;
                            let _ = text;

                            if let Some(obj) = item.as_object_mut() {
                                obj.remove("text_elements");
                                obj.remove("textElements");
                            }
                        }
                        Some("mention" | "skill") => {
                            let path = item["path"]
                                .as_str()
                                .ok_or(Error("attachment_path_required"))?;
                            let path = Path::new(path);
                            if !path.is_absolute() {
                                return Err(Error("absolute_attachment_path_required"));
                            }
                            let metadata = std::fs::symlink_metadata(path)
                                .map_err(|_| Error("attachment_unavailable"))?;
                            if !metadata.is_file()
                                || metadata.file_type().is_symlink()
                                || metadata.len() > MAX_BODY as u64
                            {
                                return Err(Error("text_attachment_required"));
                            }
                            use std::io::Read;
                            let mut bytes = zeroize::Zeroizing::new(Vec::new());
                            std::fs::File::open(path)
                                .map_err(|_| Error("attachment_unavailable"))?
                                .take((MAX_BODY + 1) as u64)
                                .read_to_end(&mut bytes)
                                .map_err(|_| Error("attachment_read_failed"))?;
                            if bytes.len() > MAX_BODY {
                                return Err(Error("attachment_size_limit"));
                            }
                            let text = std::str::from_utf8(&bytes)
                                .map_err(|_| Error("binary_attachment_disabled"))?;
                            if text.contains('\0') {
                                return Err(Error("binary_attachment_disabled"));
                            }
                            let source =
                                format!("Local text attachment {}:\n{}", path.display(), text);
                            *item = value!({"type":"text","text":source});
                        }
                        _ => return Err(Error("opaque_attachments_disabled")),
                    }
                }
                let texts = Value::Array(input.iter().map(|item| item["text"].clone()).collect());
                let safe = self.vault.mask(session, self.policy.clone(), &texts)?;
                for (item, text) in input
                    .iter_mut()
                    .zip(safe.as_array().ok_or(Error("invalid_texts"))?)
                {
                    item["text"] = text.clone();
                }
                if result["params"]
                    .get("toolOutput")
                    .is_some_and(|v| !v.is_null())
                {
                    return Err(Error("external_tool_output_disabled"));
                }
            }
            "thread/resume" | "thread/fork" => {
                let session = message["params"]["threadId"]
                    .as_str()
                    .ok_or(Error("thread_id_required"))?;
                if !self.vault.exists(session)? {
                    return Err(Error("unprotected_history_disabled"));
                }
                if method == "thread/fork" {
                    self.pending
                        .lock()
                        .map_err(|_| Error("bridge_state_failed"))?
                        .insert(key(&message["id"])?, session.into());
                }
                if message["params"]
                    .get("history")
                    .is_some_and(|v| !v.is_null())
                {
                    return Err(Error("external_history_disabled"));
                }
            }
            "review/start" | "thread/compact/start" => {
                return Err(Error("unsupported_model_context"));
            }
            name if name.starts_with("thread/realtime/") => {
                return Err(Error("opaque_audio_disabled"));
            }
            name if name.starts_with("turn/") && name != "turn/interrupt" => {
                return Err(Error("unsupported_turn_method"));
            }
            _ => {}
        }
        Ok(result)
    }
    pub fn outgoing(&self, message: &Value) -> Result<()> {
        if let (Some(thread), Some(cwd)) = (
            message["result"]["thread"]["id"].as_str(),
            message["result"]["thread"]["cwd"].as_str(),
        ) {
            self.cwds
                .lock()
                .map_err(|_| Error("bridge_state_failed"))?
                .insert(thread.into(), PathBuf::from(cwd));
        }
        let Some(id) = message.get("id") else {
            return Ok(());
        };
        if message.get("method").is_some() {
            if message["method"] == "account/chatgptAuthTokens/refresh" {
                self.callbacks
                    .lock()
                    .map_err(|_| Error("bridge_state_failed"))?
                    .insert(key(id)?, String::new());
                return Ok(());
            }
            if let Some(session) = message["params"]["threadId"].as_str() {
                let mut callbacks = self
                    .callbacks
                    .lock()
                    .map_err(|_| Error("bridge_state_failed"))?;
                if callbacks.len() >= 128 {
                    return Err(Error("bridge_capacity"));
                }
                callbacks.insert(key(id)?, session.into());
            }
            return Ok(());
        }
        let source = self
            .pending
            .lock()
            .map_err(|_| Error("bridge_state_failed"))?
            .remove(&key(id)?);
        if let Some(source) = source {
            if let Some(thread) = message["result"]["thread"]["id"].as_str() {
                self.vault
                    .copy_session(&source, thread, self.policy.clone())?;
            }
            if source.starts_with("start-") {
                self.vault.forget(&source)?;
            }
        }
        Ok(())
    }
    fn preflight(&self, cwd: &Path) -> Result<()> {
        if self.native_boundary {
            return Ok(());
        }

        let mut paths = Vec::new();
        let home = std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| crate::platform::home().ok().map(|s| s.join(".codex")));
        if let Some(home) = home {
            paths.push(home.join("AGENTS.md"));
            paths.push(home.join("AGENTS.override.md"));
        }
        for parent in cwd.ancestors() {
            paths.push(parent.join("AGENTS.md"));
            paths.push(parent.join("AGENTS.override.md"));
        }
        for path in paths {
            match std::fs::read(&path) {
                Ok(raw) => {
                    if raw.len() > MAX_BODY {
                        return Err(Error("implicit_context_size_limit"));
                    }
                    let text = std::str::from_utf8(&raw)
                        .map_err(|_| Error("implicit_context_utf8_required"))?;
                    if crate::prompt_guard::inspect(text, self.policy.clone())?.blocked() {
                        return Err(Error("sensitive_implicit_instructions"));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error("implicit_context_unavailable")),
            }
        }
        Ok(())
    }
}
pub fn rejection(message: &Value) -> Value {
    value!({"id":message.get("id").cloned().unwrap_or(Value::Null),"error":{"code":-32010,"message":"Sanctum blocked this request: unsupported context, sensitive startup instructions, expired vault, or local inspection failure. Original content omitted."}})
}
pub fn verify_hooks(result: &Value) -> Result<()> {
    for event in ["userPromptSubmit", "preToolUse", "postToolUse"] {
        let found = result["data"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|row| row["hooks"].as_array().into_iter().flatten())
            .any(|h| {
                h["pluginId"] == "sanctum-portless@sanctum-portless-dev"
                    && h["eventName"] == event
                    && h["enabled"] == true
                    && h["trustStatus"] == "trusted"
            });
        if !found {
            return Err(Error("trusted_privacy_hooks_required"));
        }
    }
    Ok(())
}
async fn record(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Option<Value>> {
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    let n = reader
        .take((MAX_BODY + 1) as u64)
        .read_until(b'\n', &mut raw)
        .await
        .map_err(|_| Error("rpc_read_failed"))?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_BODY {
        return Err(Error("rpc_size_limit"));
    }
    Ok(Some(json::parse(&raw)?))
}
pub async fn run(
    executable: &Path,
    args: &[std::ffi::OsString],
    state: PathBuf,
    policy: Policy,
) -> Result<i32> {
    let mut filter = Filter::new(Arc::new(Vault::new(state.clone())?), policy);
    if std::env::var_os("SANCTUM_NATIVE_REQUIRED").is_some() {
        let proof = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Command::new(executable)
                .arg("--sanctum-native-protocol")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| Error("native_boundary_probe_failed"))?
        .map_err(|_| Error("native_boundary_probe_failed"))?;
        if !proof.status.success()
            || proof.stdout != b"sanctum-native-v1\n"
            || std::env::var_os("SANCTUM_NATIVE_HELPER").is_none()
        {
            return Err(Error("verified_native_backend_required"));
        }
        filter.native_boundary = true;
    }
    let filter = Arc::new(filter);
    for (index, arg) in args.iter().enumerate() {
        if arg == "--code-mode-host" || arg.to_string_lossy().starts_with("--code-mode-host=") {
            return Err(Error("local_code_mode_host_required"));
        }
        if arg == "--listen" && args.get(index + 1).is_none_or(|value| value != "stdio://") {
            return Err(Error("stdio_transport_required"));
        }
        if arg.to_string_lossy().starts_with("--listen=") && arg != "--listen=stdio://" {
            return Err(Error("stdio_transport_required"));
        }
    }
    let mut backend = Command::new(executable);
    backend.args(args);
    if filter.native_boundary {
        backend.arg("-c").arg("web_search=\"disabled\"");
    }
    let mut child = backend
        .env("SANCTUM_STATE_DIR", state)
        .env("SANCTUM_PORTLESS_ACTIVE", "1")
        .env("CODEX_CLI_PATH", executable)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Error("backend_start_failed"))?;
    let backend_in = Arc::new(tokio::sync::Mutex::new(
        child.stdin.take().ok_or(Error("backend_pipe_failed"))?,
    ));
    let mut backend_out = BufReader::new(child.stdout.take().ok_or(Error("backend_pipe_failed"))?);
    let mut client_in = BufReader::new(tokio::io::stdin());
    let client_out = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let private_requests: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<Value>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let private_responses = private_requests.clone();
    let incoming_backend = backend_in.clone();
    let writer = client_out.clone();
    let incoming = filter.clone();
    let mut input = tokio::spawn(async move {
        while let Some(message) = record(&mut client_in).await? {
            if message["method"] == "thread/start"
                || message["method"] == "thread/resume"
                || message["method"] == "thread/fork"
                || message["method"] == "turn/start"
                || message["method"] == "turn/steer"
            {
                let id = format!("__sanctum_{}", crate::setup::random_key()?);
                let (send, receive) = tokio::sync::oneshot::channel();
                private_requests
                    .lock()
                    .map_err(|_| Error("bridge_state_failed"))?
                    .insert(id.clone(), send);
                let cwds = message["params"]["cwd"]
                    .as_str()
                    .map(|s| vec![s.to_owned()])
                    .unwrap_or_else(|| {
                        vec![
                            std::env::current_dir()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .into_owned(),
                        ]
                    });
                {
                    let mut backend = incoming_backend.lock().await;
                    backend
                        .write_all(&json::encode(
                            &value!({"id":id,"method":"hooks/list","params":{"cwds":cwds}}),
                        )?)
                        .await
                        .map_err(|_| Error("backend_pipe_failed"))?;
                    backend
                        .write_all(b"\n")
                        .await
                        .map_err(|_| Error("backend_pipe_failed"))?;
                    backend
                        .flush()
                        .await
                        .map_err(|_| Error("backend_pipe_failed"))?;
                }
                let hook_list =
                    tokio::time::timeout(std::time::Duration::from_secs(15), receive).await;
                let trusted = match hook_list {
                    Ok(Ok(response)) => verify_hooks(&response["result"]).is_ok(),
                    _ => false,
                };
                if !trusted {
                    private_requests
                        .lock()
                        .map_err(|_| Error("bridge_state_failed"))?
                        .remove(&id);
                    let mut output = writer.lock().await;
                    output
                        .write_all(&json::encode(&rejection(&message))?)
                        .await
                        .map_err(|_| Error("rpc_write_failed"))?;
                    output
                        .write_all(b"\n")
                        .await
                        .map_err(|_| Error("rpc_write_failed"))?;
                    output
                        .flush()
                        .await
                        .map_err(|_| Error("rpc_write_failed"))?;
                    continue;
                }
            }
            match incoming.incoming(&message) {
                Ok(safe) => {
                    let mut backend_in = incoming_backend.lock().await;
                    backend_in
                        .write_all(&json::encode(&safe)?)
                        .await
                        .map_err(|_| Error("backend_pipe_failed"))?;
                    backend_in
                        .write_all(b"\n")
                        .await
                        .map_err(|_| Error("backend_pipe_failed"))?;
                    backend_in
                        .flush()
                        .await
                        .map_err(|_| Error("backend_pipe_failed"))?;
                }
                Err(_) => {
                    let mut output = writer.lock().await;
                    output
                        .write_all(&json::encode(&rejection(&message))?)
                        .await
                        .map_err(|_| Error("rpc_write_failed"))?;
                    output
                        .write_all(b"\n")
                        .await
                        .map_err(|_| Error("rpc_write_failed"))?;
                    output
                        .flush()
                        .await
                        .map_err(|_| Error("rpc_write_failed"))?;
                }
            }
        }
        Ok::<(), Error>(())
    });
    let output = async {
        while let Some(message) = record(&mut backend_out).await? {
            let private = message
                .get("id")
                .and_then(Value::as_str)
                .and_then(|id| private_responses.lock().ok()?.remove(id));
            if let Some(send) = private {
                let _ = send.send(message);
                continue;
            }
            filter.outgoing(&message)?;
            let mut output = client_out.lock().await;
            output
                .write_all(&json::encode(&message)?)
                .await
                .map_err(|_| Error("rpc_write_failed"))?;
            output
                .write_all(b"\n")
                .await
                .map_err(|_| Error("rpc_write_failed"))?;
            output
                .flush()
                .await
                .map_err(|_| Error("rpc_write_failed"))?;
        }
        Ok::<(), Error>(())
    };
    tokio::pin!(output);
    let result = tokio::select! {
        result=&mut output=>result,
        result=&mut input=>result.map_err(|_|Error("bridge_task_failed"))?,
    };
    input.abort();
    let _ = child.start_kill();
    let _ = child.wait().await;
    result?;
    Ok(0)
}
