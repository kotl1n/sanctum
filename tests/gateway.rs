use sanctum::{
    gateway::{self, Mode, Settings},
    redaction::Policy,
};
use serde_json::json;
use std::time::Duration;

const KEY: &str = "synthetic-local-key-at-least-24-characters";
struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server() -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router =
        gateway::router(Settings::new(KEY.into(), Mode::Openai, Policy::default(), true).unwrap())
            .unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Server { url, task }
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn health_requires_local_auth_and_rejects_browser_origin() {
    let server = server().await;
    let client = client();
    let url = format!("{}/health", server.url);
    assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
    let response = client
        .get(&url)
        .header("x-sanctum-key", KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = response.text().await.unwrap();
    assert!(body.contains("sanctum"));
    assert!(!body.contains(KEY));
    assert_eq!(
        client
            .get(&url)
            .header("x-sanctum-key", KEY)
            .header("origin", "https://example.invalid")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(&url)
            .header("x-sanctum-key", KEY)
            .header("x-sanctum-key", KEY)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
}

#[tokio::test]
async fn invalid_requests_are_rejected_locally_without_echoing_content() {
    let server = server().await;
    let client = client();
    for (path, body, session) in [
        (
            "/unsupported",
            json!({"input":"synthetic-private-value"}),
            false,
        ),
        (
            "/v1/responses?unexpected=1",
            json!({"input":"synthetic-private-value"}),
            false,
        ),
        (
            "/v1/responses",
            json!({"input":"synthetic-private-value"}),
            false,
        ),
        (
            "/v1/responses",
            json!({"input":[{"type":"input_image","image_url":"synthetic-private-value"}]}),
            true,
        ),
    ] {
        let mut request = client
            .post(format!("{}{path}", server.url))
            .header("x-sanctum-key", KEY)
            .bearer_auth("synthetic-provider-credential")
            .json(&body);
        if session {
            request = request.header("session_id", "test-session");
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 400, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = response.text().await.unwrap();
        for private in [
            KEY,
            "synthetic-private-value",
            "synthetic-provider-credential",
        ] {
            assert!(!body.contains(private));
        }
    }
}
