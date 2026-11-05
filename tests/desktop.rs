mod support;
use sanctum::{
    context, local_arguments, model_boundary, preview,
    protocol::Session,
    redaction::{Policy, Redactor},
    rewrite::{ATTACHMENT, OMITTED, Rewriter},
    settings::Settings,
    vault::Vault,
};
use serde_json::json;

#[test]
fn context_masks_content_without_breaking_request_controls_or_schema() {
    let rewriter = Rewriter::new(None, Policy::default());
    let schema = json!({"type":"object","properties":{"count":{"type":"integer","minimum":0}},"required":["count"],"additionalProperties":false});
    let body = json!({"model":"test-model","stream":true,"max_output_tokens":256,
        "instructions":"Contact demo@example.com","input":[{"role":"user","content":"host 192.0.2.10"}],
        "previous_response_id":"old","conversation":"old","store":true,
        "tools":[{"type":"function","name":"local_read","parameters":schema.clone()}]});
    let safe = context::rewrite(&body, "chat", &rewriter).unwrap();
    assert_eq!(safe["model"], "test-model");
    assert_eq!(safe["stream"], true);
    assert_eq!(safe["max_output_tokens"], 256);
    assert_eq!(safe["store"], false);
    assert!(safe.get("previous_response_id").is_none());
    assert!(safe.get("conversation").is_none());
    assert_eq!(safe["tools"][0]["parameters"], schema);
    assert!(!safe.to_string().contains("demo@example.com"));
    assert!(!safe.to_string().contains("192.0.2.10"));
}

#[test]
fn unsupported_attachments_and_hosted_tools_are_removed() {
    let rewriter = Rewriter::new(None, Policy::default());
    let safe = context::rewrite(
        &json!({"input":[{"role":"user","content":[
        {"type":"input_image","image_url":"private-attachment"}]}],
        "tools":[{"type":"web_search"},{"type":"function","name":"read"}]}),
        "chat",
        &rewriter,
    )
    .unwrap();
    assert_eq!(safe["input"][0]["content"][0]["text"], ATTACHMENT);
    assert_eq!(safe["tools"].as_array().unwrap().len(), 1);
    assert!(!safe.to_string().contains("private-attachment"));
}

#[test]
fn unavailable_policy_omits_context_and_compaction_keeps_its_shape() {
    let rewriter = Rewriter::new(None, Policy::default()).with_unavailable_policy();
    for (kind, field) in [
        ("responses", "input"),
        ("compact", "input"),
        ("memory", "raw_memories"),
        ("trace", "traces"),
    ] {
        let mut body = json!({"model":"test-model","instructions":"private-context"});
        body[field] = json!(["private-context"]);
        let result = model_boundary::rewrite(
            &json!({"session_id":"chat","request_kind":kind,"body":body}),
            true,
            &rewriter,
        )
        .unwrap();
        assert_eq!(result["boundary_status"], "context_omitted");
        assert!(!result.to_string().contains("private-context"));
        assert_eq!(result["body"]["model"], "test-model");
        if kind == "compact" {
            assert!(result["body"].get("store").is_none());
        }
        if matches!(field, "raw_memories" | "traces") {
            assert_eq!(result["body"][field], json!([]));
        } else {
            assert!(result.to_string().contains(OMITTED));
        }
    }
}

#[test]
fn disabled_boundary_preserves_the_body() {
    let body = json!({"input":"demo@example.com","store":true});
    let rewriter = Rewriter::new(None, Policy::default());
    let safe = model_boundary::rewrite(&json!({"session_id":"chat","body":body}), false, &rewriter)
        .unwrap();
    assert_eq!(safe["body"], body);
    assert_eq!(safe["boundary_status"], "disabled");
}

#[test]
fn malformed_turn_params_do_not_crash_the_adapter() {
    let mut rewriter = Rewriter::new(None, Policy::default());
    for params in [json!(null), json!("invalid"), json!(42), json!([])] {
        let request = json!({"method":"turn/start","params":params});
        assert_eq!(rewriter.incoming(&request, true), request);
    }
}

#[test]
fn opaque_compaction_replay_is_bound_to_request_and_session() {
    let temp = support::TempDir::new();
    let directory = temp.path().join("private");
    let rewriter = Rewriter::new(
        Some(Vault::new(directory.clone()).unwrap()),
        Policy::default(),
    );
    let vault = Vault::new(directory).unwrap();
    let item = json!({"type":"context_compaction","encrypted_content":"opaque-fixture"});
    let record = json!({"session_id":"chat","request_id":"request-1","item":item});
    assert!(model_boundary::record_provider(&record, Policy::default(), &vault).is_err());
    rewriter
        .approve_provider_request("chat", "request-1")
        .unwrap();
    model_boundary::record_provider(&record, Policy::default(), &vault).unwrap();
    let body = json!({"input":[item]});
    assert_eq!(
        context::rewrite(&body, "chat", &rewriter).unwrap()["input"][0],
        item
    );
    let other = context::rewrite(&body, "other", &rewriter).unwrap();
    assert!(!other.to_string().contains("opaque-fixture"));
}

#[test]
fn preview_spans_use_utf16_offsets_and_do_not_need_persistent_storage() {
    let text = "🔒 demo@example.com";
    let preview = preview::inspect(text, Ok(Policy::default()), true);
    assert_eq!(preview["status"], "ready");
    assert_eq!(preview["persisted"], false);
    assert_eq!(
        preview["spans_utf16"],
        json!([[3, text.encode_utf16().count()]])
    );
    assert!(
        !preview["masked_text"]
            .as_str()
            .unwrap()
            .contains("demo@example.com")
    );
}

#[test]
fn encrypted_state_survives_reopen_and_rejects_tampering() {
    let temp = support::TempDir::new();
    let directory = temp.path().join("private");
    let vault = Vault::new(directory.clone()).unwrap();
    let masked = vault
        .mask("chat", Policy::default(), &json!("demo@example.com"))
        .unwrap();
    let reopened = Vault::new(directory.clone()).unwrap();
    reopened
        .transact("chat", Policy::default(), |engine| {
            assert_eq!(engine.restore(masked.as_str().unwrap()), "demo@example.com");
            Ok(())
        })
        .unwrap();
    let path = std::fs::read_dir(&directory)
        .unwrap()
        .map(|p| p.unwrap().path())
        .find(|p| p.extension().is_some_and(|ext| ext == "vault"))
        .unwrap();
    let mut raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(b"demo@example.com".len())
            .any(|w| w == b"demo@example.com")
    );
    let last = raw.len() - 1;
    raw[last] ^= 1;
    std::fs::write(path, raw).unwrap();
    assert!(
        reopened
            .mask("chat", Policy::default(), &json!("clean"))
            .is_err()
    );
    reopened.forget("chat").unwrap();
    assert!(!reopened.exists("chat").unwrap());
}

#[test]
fn local_arguments_restore_paths_and_stdin_but_preserve_remote_environment() {
    let mut engine = Redactor::new(Policy::default()).unwrap();
    engine.text("192.0.2.10").unwrap();
    let session = Session::new(engine);
    assert_eq!(
        local_arguments::restore(&session, &json!({"path":"/tmp/[IP-1]"}), "read_file").unwrap()["path"],
        "/tmp/192.0.2.10"
    );
    assert_eq!(
        local_arguments::restore(&session, &json!({"chars":"ping [IP-1]\n"}), "write_stdin")
            .unwrap()["chars"],
        "ping 192.0.2.10\n"
    );
    let remote = json!({"cmd":"ping [IP-1]","environment_id":"remote"});
    assert_eq!(
        local_arguments::restore(&session, &remote, "exec_command").unwrap(),
        remote
    );
    assert!(local_arguments::restore(&session, &json!({"path":"[IP-99]"}), "read_file").is_err());
}

#[test]
fn settings_roundtrip_and_corruption_are_explicit() {
    let temp = support::TempDir::new();
    let path = temp.path().join("settings.json");
    Settings { enabled: false }.save(&path).unwrap();
    assert!(!Settings::load(&path).unwrap().active());
    std::fs::write(&path, b"{broken").unwrap();
    assert!(Settings::load(&path).is_err());
    std::fs::write(&path, br#"{"enabled":true,"unexpected":true}"#).unwrap();
    assert!(Settings::load(&path).is_err());
}
