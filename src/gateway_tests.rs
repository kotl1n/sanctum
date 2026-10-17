use super::*;
use crate::demo::{LocalServer, start_local};
use std::sync::atomic::{AtomicU16, Ordering};

struct StubState {
    requests: Mutex<Vec<(Value, HeaderMap, String)>>,
    reply: Mutex<Value>,
    status: AtomicU16,
}
async fn stub(State(state): State<Arc<StubState>>, request: Request) -> Response {
    let path = request.uri().to_string();
    let headers = request.headers().clone();
    let bytes = to_bytes(request.into_body(), MAX_BODY).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        json::parse(&bytes).unwrap()
    };
    state.requests.lock().await.push((body, headers, path));
    let status = StatusCode::from_u16(state.status.load(Ordering::Relaxed)).unwrap();
    let mut response = (status, axum::Json(state.reply.lock().await.clone())).into_response();
    if status.is_redirection() {
        response.headers_mut().insert(
            "location",
            HeaderValue::from_static("https://example.invalid/must-not-receive-auth"),
        );
    }
    response
}
struct Harness {
    _provider: LocalServer,
    _gateway: LocalServer,
    state: Arc<StubState>,
    key: String,
    client: reqwest::Client,
    base: String,
}
impl Harness {
    async fn new(restore: bool, max_sessions: usize) -> Self {
        let state = Arc::new(StubState {
            requests: Mutex::new(Vec::new()),
            reply: Mutex::new(value!({"output":[]})),
            status: AtomicU16::new(200),
        });
        let provider = start_local(Router::new().fallback(stub).with_state(state.clone()))
            .await
            .unwrap();
        let key = crate::setup::random_key().unwrap();
        let mut settings = Settings::new(key.clone(), Mode::Chatgpt, Policy::default(), restore)
            .unwrap()
            .loopback_fixture(provider.address)
            .unwrap();
        settings.max_sessions = max_sessions;
        let gateway = start_local(router(settings).unwrap()).await.unwrap();
        let base = format!("http://{}", gateway.address);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        Self {
            _provider: provider,
            _gateway: gateway,
            state,
            key,
            client,
            base,
        }
    }
    fn request(&self) -> reqwest::RequestBuilder {
        self.request_for("synthetic-session-1")
    }
    fn request_for(&self, session_id: &str) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}/backend-api/codex/responses", self.base))
            .header("X-Sanctum-Key", &self.key)
            .bearer_auth("synthetic-upstream-credential")
            .header("session_id", session_id)
    }
    async fn send(&self, payload: Value) -> reqwest::Response {
        self.request().json(&payload).send().await.unwrap()
    }
}

#[tokio::test]
async fn actual_http_body_is_masked_and_only_required_headers_leave() {
    let h = Harness::new(true, 128).await;
    let response = h.request().header("cookie", "synthetic-cookie").header("x-extra", "synthetic-extra").header("chatgpt-account-id", "synthetic-account")
        .json(&value!({"input":["11.111.111.11 demo@example.com password=synthetic-password", "synthetic-password"]})).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let requests = h.state.requests.lock().await;
    let (body, headers, path) = &requests[0];
    for secret in ["11.111.111.11", "demo@example.com", "synthetic-password"] {
        assert!(!body.to_string().contains(secret));
    }
    assert_eq!(path, "/backend-api/codex/responses");
    assert_eq!(
        headers["authorization"],
        "Bearer synthetic-upstream-credential"
    );
    assert_eq!(headers["chatgpt-account-id"], "synthetic-account");
    for name in ["cookie", "x-extra", "x-sanctum-key"] {
        assert!(!headers.contains_key(name));
    }
    assert_eq!(body["store"], false);
}
#[tokio::test]
async fn gateway_and_provider_credentials_in_body_are_always_masked() {
    let h = Harness::new(true, 128).await;
    assert_eq!(
        h.send(value!({"input":[h.key,"synthetic-upstream-credential"]}))
            .await
            .status(),
        200
    );
    let requests = h.state.requests.lock().await;
    assert!(!requests[0].0.to_string().contains(&h.key));
    assert!(
        !requests[0]
            .0
            .to_string()
            .contains("synthetic-upstream-credential")
    );
}
#[tokio::test]
async fn auth_origin_and_duplicate_auth_are_rejected_before_upstream() {
    let h = Harness::new(true, 128).await;
    assert_eq!(
        h.client
            .post(format!("{}/backend-api/codex/responses", h.base))
            .header("X-Sanctum-Key", "wrong")
            .json(&value!({"input":"hello"}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        h.request()
            .header("X-Sanctum-Key", "wrong")
            .json(&value!({"input":"hello"}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        h.request()
            .header("origin", "https://example.invalid")
            .json(&value!({"input":"hello"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        h.request()
            .header("authorization", "Bearer other")
            .json(&value!({"input":"hello"}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert!(h.state.requests.lock().await.is_empty());
}
#[tokio::test]
async fn unsupported_routes_queries_and_encoding_do_not_contact_upstream() {
    let h = Harness::new(true, 128).await;
    for path in [
        "/v1/files",
        "/responses",
        "/backend-api/codex/responses?token=secret",
        "/backend-api/codex/models?client_version=1&secret=value",
    ] {
        let response = h
            .client
            .post(format!("{}{path}", h.base))
            .header("X-Sanctum-Key", &h.key)
            .json(&value!({"input":"hi"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "{path}");
    }
    assert_eq!(
        h.request()
            .header("content-encoding", "gzip")
            .json(&value!({"input":"hi"}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert!(h.state.requests.lock().await.is_empty());
}
#[tokio::test]
async fn malformed_json_missing_session_and_attachments_do_not_contact_upstream() {
    let h = Harness::new(true, 128).await;
    for raw in [
        "{broken",
        "[]",
        "{\"input\":NaN}",
        "{\"input\":1,\"input\":2}",
    ] {
        assert_eq!(
            h.request()
                .header("content-type", "application/json")
                .body(raw)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    assert_eq!(
        h.request_for("demo@example.com")
            .json(&value!({"input":"hello"}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        h.send(value!({"input":[{"type":"input_image","image_url":"data:secret"}]}))
            .await
            .status(),
        400
    );
    assert!(h.state.requests.lock().await.is_empty());
}
#[tokio::test]
async fn upstream_errors_and_redirects_never_echo_or_follow() {
    let h = Harness::new(true, 128).await;
    *h.state.reply.lock().await = value!({"error":"synthetic-upstream-credential secret-echo"});
    for status in [401, 429, 503, 307] {
        h.state.status.store(status, Ordering::Relaxed);
        let response = h.send(value!({"input":"hello"})).await;
        assert_eq!(
            response.status().as_u16(),
            if status == 307 { 502 } else { status }
        );
        let text = response.text().await.unwrap();
        assert!(!text.contains("secret-echo"));
        assert!(!text.contains("synthetic-upstream-credential"));
    }
    assert_eq!(h.state.requests.lock().await.len(), 4);
}
#[tokio::test]
async fn tool_restoration_uses_the_correct_session_vault() {
    let h = Harness::new(true, 128).await;
    assert_eq!(
        h.send(value!({"input":"11.111.111.11"})).await.status(),
        200
    );
    assert_eq!(
        h.request_for("synthetic-session-2")
            .json(&value!({"input":"22.222.222.22"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    *h.state.reply.lock().await = value!({"output":[{"type":"function_call","name":"connect","arguments":"{\"host\":\"[IP-1]\"}"}]});
    for (id, original) in [
        ("synthetic-session-1", "11.111.111.11"),
        ("synthetic-session-2", "22.222.222.22"),
    ] {
        let response: Value = h
            .request_for(id)
            .json(&value!({"input":"hello"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let arguments = json::parse(
            response["output"][0]["arguments"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(arguments["host"], original);
    }
}
#[tokio::test]
async fn session_limit_does_not_silently_evict_existing_vaults() {
    let h = Harness::new(true, 1).await;
    assert_eq!(
        h.send(value!({"input":"11.111.111.11"})).await.status(),
        200
    );
    assert_eq!(
        h.request_for("synthetic-session-2")
            .json(&value!({"input":"22.222.222.22"}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(h.send(value!({"input":"[IP-1]"})).await.status(), 200);
}
#[tokio::test]
async fn no_restore_mode_and_authenticated_health() {
    let h = Harness::new(false, 128).await;
    *h.state.reply.lock().await = value!({"output":[{"type":"function_call","name":"connect","arguments":"{\"host\":\"[IP-1]\"}"}]});
    let response: Value = h
        .send(value!({"input":"11.111.111.11"}))
        .await
        .json()
        .await
        .unwrap();
    assert!(
        response["output"][0]["arguments"]
            .as_str()
            .unwrap()
            .contains("[IP-1]")
    );
    assert_eq!(
        h.client
            .get(format!("{}/health", h.base))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let health: Value = h
        .client
        .get(format!("{}/health", h.base))
        .header("X-Sanctum-Key", &h.key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["implementation"], "rust");
    assert_eq!(health["restore_tools"], false);
}
#[tokio::test]
async fn network_demo_executes_and_remasks_real_tool_output() {
    crate::demo::run().await.unwrap();
}

#[tokio::test]
#[ignore = "requires installed Codex CLI; model is fake, but client may make background service requests"]
async fn codex_transport() {
    let (provider, received) = crate::demo::fake_provider(Mode::Openai).await.unwrap();
    let key = crate::setup::random_key().unwrap();
    let settings = Settings::new(key.clone(), Mode::Openai, Policy::default(), true)
        .unwrap()
        .loopback_fixture(provider.address)
        .unwrap();
    let gateway = start_local(router(settings).unwrap()).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut command = tokio::process::Command::new("codex");
    command
        .env("CODEX_HOME", directory.path())
        .env("SANCTUM_RUST_TEST_KEY", "synthetic-provider-key")
        .current_dir(directory.path())
        .args([
            "exec",
            "--ignore-user-config",
            "--skip-git-repo-check",
            "--ephemeral",
            "--json",
            "-s",
            "read-only",
        ])
        .kill_on_drop(true);
    for (key_name, value) in [
        ("model_provider", "\"sanctum_rust_test\"".into()),
        (
            "model_providers.sanctum_rust_test.name",
            "\"Sanctum Rust fixture\"".into(),
        ),
        (
            "model_providers.sanctum_rust_test.base_url",
            format!("\"http://{}/v1\"", gateway.address),
        ),
        (
            "model_providers.sanctum_rust_test.env_key",
            "\"SANCTUM_RUST_TEST_KEY\"".into(),
        ),
        (
            "model_providers.sanctum_rust_test.http_headers",
            format!("{{\"X-Sanctum-Key\"=\"{key}\"}}"),
        ),
        (
            "model_providers.sanctum_rust_test.supports_websockets",
            "false".into(),
        ),
        ("web_search", "\"disabled\"".into()),
        ("check_for_update_on_startup", "false".into()),
        ("otel.exporter", "\"none\"".into()),
    ] {
        command.args(["-c", &format!("{key_name}={value}")]);
    }
    command.arg("Print synthetic address 11.111.111.11 once using a local command, then finish.");
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "Codex failed; diagnostics omitted");
    let requests = received.lock().await;
    assert_eq!(requests.len(), 2);
    assert!(
        !requests
            .iter()
            .any(|r| r.to_string().contains("11.111.111.11"))
    );
    let tool_outputs: Vec<&Value> = requests[1]["input"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| {
            item["type"] == "custom_tool_call_output" || item["type"] == "function_call_output"
        })
        .collect();
    let tool_wire = serde_json::to_string(&tool_outputs).unwrap();
    assert!(tool_wire.contains("SANCTUM_ORIGINAL_OK:"));
    assert!(tool_wire.contains("[IP-1]"));
    assert!(!tool_wire.contains("SANCTUM_ORIGINAL_MISSING"));
    println!(
        "PASS: actual Codex CLI -> Rust gateway -> fake model -> native tool execution -> masked follow-up."
    );
}
