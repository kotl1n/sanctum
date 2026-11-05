use crate::{
    Error, MAX_BODY, Result, VERSION, json,
    protocol::{ResponseStream, Session},
    redaction::{Policy, Redactor},
};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json as value};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore, mpsc},
};
use tokio_stream::wrappers::ReceiverStream;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Default, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Chatgpt,
    Openai,
}
impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Chatgpt => "chatgpt",
            Self::Openai => "openai",
        }
    }
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Chatgpt => "/backend-api/codex",
            Self::Openai => "/v1",
        }
    }
    fn upstream(self) -> &'static str {
        match self {
            Self::Chatgpt => "https://chatgpt.com/backend-api/codex",
            Self::Openai => "https://api.openai.com/v1",
        }
    }
}

pub struct Settings {
    key: Zeroizing<String>,
    pub mode: Mode,
    pub policy: Policy,
    pub restore_tools: bool,
    pub max_sessions: usize,
}
impl Settings {
    pub fn new(key: String, mode: Mode, policy: Policy, restore_tools: bool) -> Result<Self> {
        policy.validate()?;
        if key.len() < 24 || key.len() > 256 || !key.is_ascii() {
            return Err(Error("invalid_local_key"));
        }
        Ok(Self {
            key: Zeroizing::new(key),
            mode,
            policy,
            restore_tools,
            max_sessions: 128,
        })
    }
}
struct App {
    settings: Settings,
    client: reqwest::Client,
    sessions: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
    permits: Arc<Semaphore>,
}
impl App {
    async fn session(&self, id: &str) -> Result<Arc<Mutex<Session>>> {
        if !valid_session_id(id) {
            return Err(Error("session_id_required"));
        }
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get(id) {
            return Ok(session.clone());
        }
        if sessions.len() >= self.settings.max_sessions {
            return Err(Error("session_capacity"));
        }
        let mut redactor = Redactor::new(self.settings.policy.clone())?;
        redactor.add_literal(&self.settings.key)?;
        let session = Arc::new(Mutex::new(Session::new(redactor)));
        sessions.insert(id.into(), session.clone());
        Ok(session)
    }
}

pub fn router(settings: Settings) -> Result<Router> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(120))
        .build()
        .map_err(|_| Error("http_client_init"))?;
    let state = Arc::new(App {
        settings,
        client,
        sessions: Mutex::new(HashMap::new()),
        permits: Arc::new(Semaphore::new(64)),
    });
    Ok(Router::new().fallback(handle).with_state(state))
}
pub async fn serve(listener: TcpListener, settings: Settings) -> Result<()> {
    if listener
        .local_addr()
        .map_err(|_| Error("listener_error"))?
        .ip()
        != IpAddr::V4(Ipv4Addr::LOCALHOST)
    {
        return Err(Error("loopback_bind_required"));
    }
    axum::serve(listener, router(settings)?)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|_| Error("server_error"))
}

struct Rejected(StatusCode, &'static str);
impl From<Error> for Rejected {
    fn from(error: Error) -> Self {
        Self(StatusCode::BAD_REQUEST, error.0)
    }
}
fn error_response(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, axum::Json(value!({"error":{"type":"sanctum_error","code":code,"message":"Sanctum blocked or could not complete this request. Content and credentials omitted."}}))).into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("connection", HeaderValue::from_static("close"));
    response
}
async fn handle(State(app): State<Arc<App>>, request: Request) -> Response {
    match process(app, request).await {
        Ok(response) => response,
        Err(Rejected(status, code)) => error_response(status, code),
    }
}
fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(Error("duplicate_header"));
    }
    first
        .map(|v| v.to_str().map_err(|_| Error("invalid_header")))
        .transpose()
}
pub fn valid_session_id(id: &str) -> bool {
    (8..=128).contains(&id.len())
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn forward_headers(headers: &HeaderMap) -> Result<HeaderMap> {
    let auth = one_header(headers, "authorization")?
        .filter(|s| s.starts_with("Bearer ") && s.len() > 7 && s.len() <= 16_384)
        .ok_or(Error("provider_auth_required"))?;
    let mut result = HeaderMap::new();
    let mut auth = HeaderValue::from_str(auth).map_err(|_| Error("invalid_auth"))?;
    auth.set_sensitive(true);
    result.insert("authorization", auth);
    result.insert(
        "accept",
        HeaderValue::from_static("text/event-stream, application/json"),
    );
    result.insert("accept-encoding", HeaderValue::from_static("identity"));
    result.insert("user-agent", HeaderValue::from_static("sanctum-rust/0.2"));
    for name in ["chatgpt-account-id", "openai-beta", "originator", "version"] {
        if let Some(value) = one_header(headers, name)? {
            if value.len() > 512 || !value.bytes().all(|c| (32..=126).contains(&c)) {
                return Err(Error("invalid_routing_header"));
            }
            result.insert(
                name,
                HeaderValue::from_str(value).map_err(|_| Error("invalid_routing_header"))?,
            );
        }
    }
    if let Some(id) = one_header(headers, "session_id")? {
        if !valid_session_id(id) {
            return Err(Error("invalid_session_header"));
        }
        result.insert(
            "session_id",
            HeaderValue::from_str(id).map_err(|_| Error("invalid_session_header"))?,
        );
    }
    Ok(result)
}
fn route(request: &Request, mode: Mode) -> Result<&str> {
    if request.uri().scheme().is_some() || request.uri().authority().is_some() {
        return Err(Error("unsupported_route"));
    }
    let path = request.uri().path();
    let suffix = path
        .strip_prefix(mode.prefix())
        .ok_or(Error("unsupported_route"))?;
    if !["/responses", "/responses/compact", "/models"].contains(&suffix) {
        return Err(Error("unsupported_route"));
    }
    if let Some(query) = request.uri().query() {
        let version = query
            .strip_prefix("client_version=")
            .ok_or(Error("unsupported_query"))?;
        if suffix != "/models"
            || version.is_empty()
            || version.len() > 64
            || !version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err(Error("unsupported_query"));
        }
    }
    let full = request
        .uri()
        .path_and_query()
        .ok_or(Error("unsupported_route"))?
        .as_str();
    full.strip_prefix(mode.prefix())
        .ok_or(Error("unsupported_route"))
}

async fn process(app: Arc<App>, request: Request) -> std::result::Result<Response, Rejected> {
    let headers = request.headers();
    let supplied = one_header(headers, "x-sanctum-key")?.unwrap_or("");
    if !bool::from(supplied.as_bytes().ct_eq(app.settings.key.as_bytes())) {
        return Err(Rejected(StatusCode::UNAUTHORIZED, "local_auth_required"));
    }
    if headers.contains_key("origin") {
        return Err(Rejected(StatusCode::FORBIDDEN, "browser_requests_disabled"));
    }
    let permit = app
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| Rejected(StatusCode::TOO_MANY_REQUESTS, "local_concurrency_limit"))?;
    if request.method() == Method::GET && request.uri() == "/health" {
        let mut response = axum::Json(value!({"service":"sanctum","implementation":"rust","version":VERSION,"mode":app.settings.mode.label(),"text_only":true,"restore_tools":app.settings.restore_tools})).into_response();
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        return Ok(response);
    }
    let suffix = route(&request, app.settings.mode)?.to_owned();
    let method = request.method().clone();
    if !((method == Method::GET && suffix.starts_with("/models"))
        || (method == Method::POST
            && ["/responses", "/responses/compact"].contains(&suffix.as_str())))
    {
        return Err(Rejected(
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported_method",
        ));
    }
    let mut outgoing_headers = forward_headers(headers)?;
    let mut session_guard = None;
    let mut outgoing_body = None;
    if method == Method::POST {
        if headers.contains_key("transfer-encoding")
            || one_header(headers, "content-encoding")?.is_some_and(|v| v != "identity")
        {
            return Err(Error("unsupported_encoding").into());
        }
        let length: usize = one_header(headers, "content-length")?
            .ok_or(Error("content_length_required"))?
            .parse()
            .map_err(|_| Error("invalid_content_length"))?;
        if length == 0 || length > MAX_BODY {
            return Err(Rejected(StatusCode::PAYLOAD_TOO_LARGE, "payload_limit"));
        }
        if one_header(headers, "content-type")?
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            != Some("application/json")
        {
            return Err(Rejected(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "json_required",
            ));
        }
        let header_id = one_header(headers, "session_id")?
            .or(one_header(headers, "x-sanctum-session")?)
            .map(str::to_owned);
        let raw = tokio::time::timeout(
            Duration::from_secs(30),
            to_bytes(request.into_body(), MAX_BODY),
        )
        .await
        .map_err(|_| Error("request_timeout"))?
        .map_err(|_| Error("invalid_request_body"))?;
        if raw.len() != length {
            return Err(Error("body_length_mismatch").into());
        }
        let payload = json::parse(&raw)?;
        let id = header_id
            .as_deref()
            .or_else(|| payload.get("prompt_cache_key").and_then(Value::as_str))
            .ok_or(Error("session_id_required"))?;
        let session = app.session(id).await?;
        let mut guard = tokio::time::timeout(Duration::from_secs(120), session.lock_owned())
            .await
            .map_err(|_| Error("session_busy"))?;
        let bearer = outgoing_headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(Error("provider_auth_required"))?;
        guard.redactor.add_literal(bearer)?;
        outgoing_body = Some(json::encode(&guard.request(&payload)?)?);
        session_guard = Some(guard);
        outgoing_headers.insert("content-type", HeaderValue::from_static("application/json"));
    }
    let upstream = app.settings.mode.upstream();
    let mut builder = app
        .client
        .request(method, format!("{upstream}{suffix}"))
        .headers(outgoing_headers);
    if let Some(body) = outgoing_body {
        builder = builder.body(body);
    }
    let response = builder
        .send()
        .await
        .map_err(|_| Rejected(StatusCode::BAD_GATEWAY, "upstream_unavailable"))?;
    let status = response.status();
    if !status.is_success() {
        let status = if status.is_client_error() || status.is_server_error() {
            status
        } else {
            StatusCode::BAD_GATEWAY
        };
        return Err(Rejected(status, "upstream_http_error"));
    }
    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|v| v != "identity")
    {
        return Err(Rejected(
            StatusCode::BAD_GATEWAY,
            "upstream_encoding_rejected",
        ));
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .unwrap_or("")
        .trim();
    if content_type == "text/event-stream" {
        let mut guard =
            session_guard.ok_or(Rejected(StatusCode::BAD_GATEWAY, "unexpected_stream"))?;
        let (sender, receiver) = mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(4);
        let restore = app.settings.restore_tools;
        tokio::spawn(async move {
            let _permit = permit;
            let mut upstream = response.bytes_stream();
            let mut decoder = ResponseStream::default();
            let outcome: Result<()> = async {
                loop {
                    let next = tokio::select! {
                        _ = sender.closed() => return Ok(()),
                        chunk = tokio::time::timeout(Duration::from_secs(120), upstream.next()) => chunk.map_err(|_| Error("upstream_timeout"))?,
                    };
                    let Some(chunk) = next else { break; };
                    let chunk = chunk.map_err(|_| Error("upstream_stream_failed"))?;
                    for frame in decoder.feed(&mut guard, &chunk, restore)? {
                        if sender.send(Ok(Bytes::from(frame))).await.is_err() { return Ok(()); }
                    }
                }
                decoder.finish()
            }.await;
            if outcome.is_err() {
                let event = b"event: error\ndata: {\"type\":\"error\",\"code\":\"sanctum_stream_rejected\",\"message\":\"Sanctum stopped this stream; content omitted.\"}\n\n";
                let _ = sender.send(Ok(Bytes::from_static(event))).await;
            }
        });
        return Ok(Response::builder()
            .status(status)
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-store")
            .body(Body::from_stream(ReceiverStream::new(receiver)))
            .map_err(|_| Error("response_build_failed"))?);
    }
    if content_type != "application/json" {
        return Err(Rejected(
            StatusCode::BAD_GATEWAY,
            "upstream_content_rejected",
        ));
    }
    let mut stream = response.bytes_stream();
    let mut raw = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Rejected(StatusCode::BAD_GATEWAY, "upstream_read_failed"))?;
        if raw.len() + chunk.len() > MAX_BODY {
            return Err(Rejected(StatusCode::BAD_GATEWAY, "upstream_payload_limit"));
        }
        raw.extend(chunk);
    }
    let payload = json::parse(&raw)
        .map_err(|_| Rejected(StatusCode::BAD_GATEWAY, "upstream_json_rejected"))?;
    if !payload.is_object() {
        return Err(Rejected(StatusCode::BAD_GATEWAY, "upstream_json_rejected"));
    }
    let payload = if let Some(mut guard) = session_guard {
        guard.remember_opaque(&payload)?;
        if app.settings.restore_tools {
            guard.response(&payload)?
        } else {
            payload
        }
    } else {
        payload
    };
    let mut response = (status, axum::Json(payload)).into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    Ok(response)
}
