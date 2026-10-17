//! Integration of the packaged plugin with a real CLI and a fake model.
//! Run explicitly; Codex may make its own background service requests.
use axum::{Router, body::Bytes, extract::State, response::IntoResponse, routing::post};
use serde_json::{Value, json};
use std::{net::Ipv4Addr, path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::{net::TcpListener, process::Command, sync::Mutex};

async fn model(State(received): State<Arc<Mutex<Vec<Value>>>>, body: Bytes) -> impl IntoResponse {
    received
        .lock()
        .await
        .push(serde_json::from_slice(&body).unwrap());
    let item = json!({"type":"message","id":"msg_guard_fixture","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Clean prompt accepted.","annotations":[]}]});
    let events = [
        json!({"type":"response.created","response":{"id":"resp_guard_fixture","status":"in_progress","output":[]},"sequence_number":0}),
        json!({"type":"response.output_item.added","output_index":0,"item":item,"sequence_number":1}),
        json!({"type":"response.output_item.done","output_index":0,"item":item,"sequence_number":2}),
        json!({"type":"response.completed","response":{"id":"resp_guard_fixture","object":"response","status":"completed","output":[item],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}},"sequence_number":3}),
    ];
    (
        [("content-type", "text/event-stream")],
        events
            .iter()
            .map(|event| format!("data: {event}\n\n"))
            .collect::<String>(),
    )
}
async fn command(mut command: Command) -> std::process::Output {
    command.kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("CLI timed out")
        .expect("CLI did not start")
}
async fn install(home: &Path, package: &Path) {
    for args in [
        vec![
            "plugin",
            "marketplace",
            "add",
            package.to_str().unwrap(),
            "--json",
        ],
        vec![
            "plugin",
            "add",
            "sanctum-prompt-guard@sanctum-guard-dev",
            "--json",
        ],
    ] {
        let mut cli = Command::new("codex");
        cli.env("CODEX_HOME", home).current_dir(home).args(args);
        assert!(
            command(cli).await.status.success(),
            "Plugin installation failed; diagnostics omitted"
        );
    }
}
// The disposable profile trusts only the hash of the exact artifact verified by
// each test. No trust-bypass flag and no changes to the user's real profile.
async fn trust_vetted_test_hook(home: &Path) {
    let mut child = Command::new("codex")
        .args(["app-server", "--stdio"])
        .env("CODEX_HOME", home)
        .current_dir(home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    async fn send(stdin: &mut tokio::process::ChildStdin, request: Value) {
        stdin
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        stdin.flush().await.unwrap();
    }
    async fn next(lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(15), lines.next_line())
            .await
            .expect("App-server timeout")
            .unwrap()
            .expect("App-server EOF");
        serde_json::from_str(&line).unwrap()
    }
    send(&mut stdin, json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"sanctum-guard-fixture","version":"0.1.0"},"capabilities":{"experimentalApi":true}}})).await;
    loop {
        if next(&mut lines).await["id"] == 1 {
            break;
        }
    }
    send(&mut stdin, json!({"method":"initialized","params":{}})).await;
    send(
        &mut stdin,
        json!({"id":2,"method":"hooks/list","params":{"cwds":[home]}}),
    )
    .await;
    loop {
        let response = next(&mut lines).await;
        if response["id"] == 2 {
            let hook = response["result"]["data"][0]["hooks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|h| h["pluginId"] == "sanctum-prompt-guard@sanctum-guard-dev")
                .unwrap();
            assert_eq!(hook["eventName"], "userPromptSubmit");
            assert_eq!(hook["enabled"], true);
            let key = serde_json::to_string(hook["key"].as_str().unwrap()).unwrap();
            let hash = serde_json::to_string(hook["currentHash"].as_str().unwrap()).unwrap();
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(home.join("config.toml"))
                .unwrap();
            std::io::Write::write_all(
                &mut file,
                format!("\n[hooks.state.{key}]\nenabled = true\ntrusted_hash = {hash}\n")
                    .as_bytes(),
            )
            .unwrap();
            break;
        }
    }
    child.start_kill().unwrap();
    let _ = child.wait().await;
}
#[tokio::test]
#[ignore = "requires installed Codex CLI; model is fake, runtime can make background requests"]
async fn packaged_submit_hook_blocks_before_model_request() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("codex");
    std::fs::create_dir(&home).unwrap();
    let package = directory.path().join("package");
    let mut pack = Command::new(env!("CARGO_BIN_EXE_sanctum-guard"));
    pack.args(["package", "--output", package.to_str().unwrap()]);
    assert!(command(pack).await.status.success());
    install(&home, &package).await;
    let installed = home.join("plugins/cache/sanctum-guard-dev/sanctum-prompt-guard/0.1.0");
    // Vet the exact installed definition and executable before trusting this
    // one test artifact in the disposable profile.
    assert_eq!(
        std::fs::read(installed.join("bin/sanctum-guard")).unwrap(),
        std::fs::read(env!("CARGO_BIN_EXE_sanctum-guard")).unwrap()
    );
    assert_eq!(
        std::fs::read(installed.join("hooks/hooks.json")).unwrap(),
        std::fs::read(package.join("plugin/hooks/hooks.json")).unwrap()
    );
    trust_vetted_test_hook(&home).await;

    let received = Arc::new(Mutex::new(Vec::<Value>::new()));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/responses", post(model))
        .with_state(received.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    for (prompt, blocked, expected_total) in [
        ("Explain ownership in Rust", false, 1),
        ("Check server 11.111.111.11", true, 1),
        ("Contact demo@example.com", true, 1),
        ("password=synthetic-only", true, 1),
        ("Explain borrowing in Rust", false, 2),
    ] {
        let mut cli = Command::new("codex");
        cli.env("CODEX_HOME", &home)
            .env("SANCTUM_GUARD_TEST_KEY", "synthetic-provider-key")
            .env_remove("SANCTUM_GUARD_POLICY")
            .current_dir(&home)
            .args([
                "exec",
                "--ephemeral",
                "--skip-git-repo-check",
                "--json",
                "-s",
                "read-only",
            ]);
        // Use the persisted exact hash, as the ordinary hook trust flow does.
        for (key, setting) in [
            ("model_provider", "\"guard_fixture\"".into()),
            (
                "model_providers.guard_fixture.name",
                "\"Guard fake model\"".into(),
            ),
            (
                "model_providers.guard_fixture.base_url",
                format!("\"http://{address}/v1\""),
            ),
            (
                "model_providers.guard_fixture.env_key",
                "\"SANCTUM_GUARD_TEST_KEY\"".into(),
            ),
            (
                "model_providers.guard_fixture.supports_websockets",
                "false".into(),
            ),
            ("web_search", "\"disabled\"".into()),
            ("check_for_update_on_startup", "false".into()),
            ("otel.exporter", "\"none\"".into()),
        ] {
            cli.args(["-c", &format!("{key}={setting}")]);
        }
        cli.arg(prompt);
        let output = command(cli).await;
        let messages = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if blocked {
            assert!(
                output.status.success()
                    && messages.contains("\"type\":\"turn.completed\"")
                    && messages.contains("\"input_tokens\":0"),
                "Blocked turn did not complete without model usage; diagnostics omitted"
            );
        } else {
            assert!(
                output.status.success(),
                "Clean prompt failed; diagnostics omitted"
            );
            assert!(
                messages.contains("Clean prompt accepted."),
                "Clean model reply missing"
            );
        }
        assert_eq!(
            received.lock().await.len(),
            expected_total,
            "Unexpected model request count"
        );
    }
    for request in received.lock().await.iter() {
        let wire = request.to_string();
        for secret in ["11.111.111.11", "demo@example.com", "synthetic-only"] {
            assert!(!wire.contains(secret));
        }
    }
    server.abort();
    println!(
        "PASS: clean prompts reached fake model; IP/email/password prompts blocked by the installed plugin, with zero extra model calls. No Sanctum gateway used."
    );
}

#[tokio::test]
#[ignore = "requires installed Codex app-server; synthetic test in a temporary profile"]
async fn app_server_reports_blocked_hook_and_safe_warning() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("codex");
    std::fs::create_dir(&home).unwrap();
    let package = directory.path().join("package");
    let mut pack = Command::new(env!("CARGO_BIN_EXE_sanctum-guard"));
    pack.args(["package", "--output", package.to_str().unwrap()]);
    assert!(command(pack).await.status.success());
    install(&home, &package).await;
    let installed = home.join("plugins/cache/sanctum-guard-dev/sanctum-prompt-guard/0.1.0");
    assert_eq!(
        std::fs::read(installed.join("bin/sanctum-guard")).unwrap(),
        std::fs::read(env!("CARGO_BIN_EXE_sanctum-guard")).unwrap()
    );
    assert_eq!(
        std::fs::read(installed.join("hooks/hooks.json")).unwrap(),
        std::fs::read(package.join("plugin/hooks/hooks.json")).unwrap()
    );
    trust_vetted_test_hook(&home).await;

    let received = Arc::new(Mutex::new(Vec::<Value>::new()));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/responses", post(model))
        .with_state(received.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut child = Command::new("codex");
    // Only the vetted hook in this disposable profile is used by this test.
    child
        .args(["app-server", "--stdio"])
        .env("CODEX_HOME", &home)
        .env("SANCTUM_GUARD_TEST_KEY", "synthetic-provider-key")
        .env_remove("SANCTUM_GUARD_POLICY")
        .current_dir(&home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    for (key, setting) in [
        ("model_provider", "\"guard_fixture\"".into()),
        (
            "model_providers.guard_fixture.name",
            "\"Guard fake model\"".into(),
        ),
        (
            "model_providers.guard_fixture.base_url",
            format!("\"http://{address}/v1\""),
        ),
        (
            "model_providers.guard_fixture.env_key",
            "\"SANCTUM_GUARD_TEST_KEY\"".into(),
        ),
        (
            "model_providers.guard_fixture.supports_websockets",
            "false".into(),
        ),
        ("web_search", "\"disabled\"".into()),
        ("check_for_update_on_startup", "false".into()),
        ("otel.exporter", "\"none\"".into()),
    ] {
        child.args(["-c", &format!("{key}={setting}")]);
    }
    let mut child = child.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    async fn send(stdin: &mut tokio::process::ChildStdin, request: Value) {
        stdin
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        stdin.flush().await.unwrap();
    }
    async fn next(lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(15), lines.next_line())
            .await
            .expect("App-server timeout")
            .unwrap()
            .expect("App-server EOF");
        serde_json::from_str(&line).unwrap()
    }
    send(&mut stdin, json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"sanctum-guard-fixture","version":"0.1.0"},"capabilities":{"experimentalApi":true}}})).await;
    loop {
        if next(&mut lines).await["id"] == 1 {
            break;
        }
    }
    send(&mut stdin, json!({"method":"initialized","params":{}})).await;
    send(
        &mut stdin,
        json!({"id":2,"method":"hooks/list","params":{"cwds":[home]}}),
    )
    .await;
    loop {
        let response = next(&mut lines).await;
        if response["id"] == 2 {
            let hooks = response["result"]["data"][0]["hooks"]
                .as_array()
                .expect("Hook list missing");
            assert!(hooks.iter().any(|h| h["eventName"] == "userPromptSubmit"
                && h["pluginId"] == "sanctum-prompt-guard@sanctum-guard-dev"
                && h["enabled"] == true
                && h["trustStatus"] == "trusted"));
            break;
        }
    }
    send(&mut stdin, json!({"id":3,"method":"thread/start","params":{"cwd":home,"ephemeral":true,"approvalPolicy":"never","sandbox":"read-only"}})).await;
    let thread_id = loop {
        let response = next(&mut lines).await;
        if response["id"] == 3 {
            break response["result"]["thread"]["id"]
                .as_str()
                .expect("Test thread missing")
                .to_owned();
        }
    };
    send(&mut stdin, json!({"id":4,"method":"turn/start","params":{"threadId":thread_id,"input":[{"type":"text","text":"Check synthetic server 11.111.111.11"}]}})).await;
    let mut hook_blocked = false;
    let mut notification_methods = Vec::new();
    let mut hook_notifications = Vec::new();
    loop {
        let notification = next(&mut lines).await;
        if let Some(method) = notification["method"].as_str() {
            notification_methods.push(method.to_owned());
            if method.contains("hook") {
                hook_notifications.push(notification.clone());
            }
        }
        if notification["method"] == "hook/completed" {
            let run = &notification["params"]["run"];
            if run["eventName"] == "userPromptSubmit" {
                assert_eq!(run["status"], "blocked");
                let entries = run["entries"].to_string();
                assert!(entries.contains("Sanctum: отправка остановлена"));
                assert!(entries.contains("IP: 1"));
                assert!(!entries.contains("11.111.111.11"));
                hook_blocked = true;
            }
        }
        if notification["method"] == "turn/completed" {
            break;
        }
    }
    assert!(
        hook_blocked,
        "No blocked-hook event from app-server. Methods: {notification_methods:?}; hooks: {hook_notifications:?}"
    );
    assert!(
        received.lock().await.is_empty(),
        "Blocked prompt reached fake model"
    );
    child.start_kill().unwrap();
    let _ = child.wait().await;
    server.abort();
    println!(
        "PASS: Codex app-server discovered the installed hook, reported blocked status and a safe category-only warning; no model request was made."
    );
}
