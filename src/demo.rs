//! All values and both servers in this demo are synthetic and local.
use crate::{
    Error, Result,
    gateway::{self, Mode, Settings},
    json,
    redaction::Policy,
};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::{Value, json as value};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};

pub(crate) struct LocalServer {
    pub address: SocketAddr,
    task: JoinHandle<()>,
}
impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(crate) async fn start_local(router: Router) -> Result<LocalServer> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| Error("fixture_bind_failed"))?;
    let address = listener
        .local_addr()
        .map_err(|_| Error("fixture_bind_failed"))?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(LocalServer { address, task })
}
pub(crate) type Received = Arc<Mutex<Vec<Value>>>;
pub(crate) async fn fake_provider(mode: Mode) -> Result<(LocalServer, Received)> {
    let received = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route(&format!("{}/responses", mode.prefix()), post(provider))
        .with_state(received.clone());
    Ok((start_local(router).await?, received))
}
async fn provider(State(received): State<Received>, body: Bytes) -> Response {
    let Ok(request) = json::parse(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let code_mode = request
        .get("input")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|x| x["type"] == "additional_tools"));
    let mut requests = received.lock().await;
    requests.push(request.clone());
    let number = requests.len();
    let item = if number == 1 && code_mode {
        value!({"type":"custom_tool_call","id":"ctc_synthetic_1","call_id":"call_synthetic_1","name":"exec","namespace":"functions","input":"const r = await tools.exec_command({cmd: \"printf '%s' '[IP-1]'\"}); text(r.output.trim() === [\"11\",\"111\",\"111\",\"11\"].join(\".\") ? \"SANCTUM_ORIGINAL_OK:\" + r.output : \"SANCTUM_ORIGINAL_MISSING\");","status":"completed"})
    } else if number == 1 {
        value!({"type":"function_call","id":"fc_synthetic_1","call_id":"call_synthetic_1","name":"exec_command","arguments":"{\"cmd\":\"printf '%s' '[IP-1]'\"}","status":"completed"})
    } else {
        value!({"type":"message","id":"msg_synthetic_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Synthetic local tool returned [IP-1].","annotations":[]}]})
    };
    let response = value!({"id":format!("resp_synthetic_{number}"),"object":"response","status":"completed","model":request.get("model"),"output":[item.clone()],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}});
    let mut added = item.clone();
    let field = if code_mode { "input" } else { "arguments" };
    if number == 1 {
        added[field] = Value::String(String::new());
    }
    let mut events = vec![
        value!({"type":"response.created","response":{"id":format!("resp_synthetic_{number}"),"status":"in_progress","output":[]}}),
        value!({"type":"response.output_item.added","output_index":0,"item":added}),
    ];
    if number == 1 {
        let complete = item[field].as_str().unwrap_or("");
        let stem = if code_mode {
            "response.custom_tool_call_input"
        } else {
            "response.function_call_arguments"
        };
        // Every byte is an independent tool delta. This exercises restoration
        // even when placeholder syntax and JSON escapes cross event boundaries.
        for character in complete.chars() {
            events.push(value!({"type":format!("{stem}.delta"),"item_id":item["id"],"output_index":0,"delta":character.to_string()}));
        }
        let mut done =
            value!({"type":format!("{stem}.done"),"item_id":item["id"],"output_index":0});
        done[field] = Value::String(complete.into());
        events.push(done);
    }
    events.extend([
        value!({"type":"response.output_item.done","output_index":0,"item":item}),
        value!({"type":"response.completed","response":response}),
    ]);
    let mut wire = String::new();
    for (index, mut event) in events.into_iter().enumerate() {
        event["sequence_number"] = index.into();
        wire.push_str(&format!(
            "event: {}\ndata: {event}\n\n",
            event["type"].as_str().unwrap_or("message")
        ));
    }
    ([("content-type", "text/event-stream")], wire).into_response()
}

pub async fn run() -> Result<()> {
    let mode = Mode::Chatgpt;
    let (provider, received) = fake_provider(mode).await?;
    let key = crate::setup::random_key()?;
    let settings = Settings::new(key.clone(), mode, Policy::default(), true)?
        .loopback_fixture(provider.address)?;
    let gateway = start_local(gateway::router(settings)?).await?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| Error("demo_client_failed"))?;
    let send = |payload: Value| {
        client
            .post(format!(
                "http://{}{}/responses",
                gateway.address,
                mode.prefix()
            ))
            .header("X-Sanctum-Key", &key)
            .bearer_auth("synthetic-demo-credential")
            .header("session_id", "synthetic-demo-session")
            .json(&payload)
            .send()
    };
    let original = "Server 11.111.111.11, email demo@example.com, password=demo-secret-value";
    let response = send(value!({"model":"synthetic-model","stream":true,"input":original}))
        .await
        .map_err(|_| Error("demo_request_failed"))?;
    if !response.status().is_success() {
        return Err(Error("demo_request_rejected"));
    }
    let wire = response
        .text()
        .await
        .map_err(|_| Error("demo_read_failed"))?;
    let events = wire
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|data| json::parse(data.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    let call = events
        .iter()
        .find(|e| e["type"] == "response.output_item.done")
        .ok_or(Error("demo_tool_missing"))?;
    let args = json::parse(
        call["item"]["arguments"]
            .as_str()
            .ok_or(Error("demo_tool_missing"))?
            .as_bytes(),
    )?;
    let command = args["cmd"].as_str().ok_or(Error("demo_tool_missing"))?;
    if command != "printf '%s' '11.111.111.11'" {
        return Err(Error("demo_restoration_failed"));
    }
    // Execute only the exact synthetic argv, never arbitrary shell text.
    let output = tokio::process::Command::new("printf")
        .args(["%s", "11.111.111.11"])
        .output()
        .await
        .map_err(|_| Error("demo_command_failed"))?;
    if !output.status.success() {
        return Err(Error("demo_command_failed"));
    }
    let output = String::from_utf8(output.stdout).map_err(|_| Error("demo_command_failed"))?;
    let response = send(value!({"model":"synthetic-model","stream":true,"input":[{"type":"function_call_output","call_id":"call_synthetic_1","output":output}]})).await.map_err(|_| Error("demo_followup_failed"))?;
    let _ = response
        .bytes()
        .await
        .map_err(|_| Error("demo_followup_failed"))?;
    let requests = received.lock().await;
    if requests.len() != 2
        || requests.iter().any(|r| {
            ["11.111.111.11", "demo@example.com", "demo-secret-value"]
                .iter()
                .any(|secret| r.to_string().contains(secret))
        })
    {
        return Err(Error("demo_privacy_check_failed"));
    }
    println!("OFFLINE RUST DEMO — synthetic data, fake provider, no OpenAI request");
    println!("1. Provider received: {}", requests[0]["input"]);
    println!("2. Local tool executed: {command}");
    println!("3. Local tool returned: {output}");
    println!(
        "4. Follow-up provider received: {}",
        requests[1]["input"][0]["output"]
    );
    println!("PASS: originals stayed local; native Rust gateway restored streamed tool arguments.");
    Ok(())
}
