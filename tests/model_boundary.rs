mod support;
use sanctum::{model_boundary, redaction::Policy, vault::Vault};
use serde_json::{Value, json};

fn vault() -> (support::TempDir, Vault) {
    let temp = support::TempDir::new();
    let vault = Vault::new(temp.path().join("private")).unwrap();
    (temp, vault)
}

#[test]
fn complete_context_including_instructions_and_tool_metadata_is_masked() {
    let (_temp, vault) = vault();
    let request = json!({"session_id":"chat","body":{"model":"synthetic-model","instructions":"AGENTS: 192.0.2.123 native-startup-only","input":[{"role":"user","content":"Connect 11.111.111.11"},{"role":"developer","content":"password=native-startup-only"}],"tools":[{"type":"function","name":"local_read","description":"Contact skill-contact@example.com","parameters":{"type":"object","properties":{"file_id":{"type":"string"}}}}]}});
    let result = model_boundary::filter(&request, Policy::default(), &vault).unwrap();
    assert_eq!(result["protocol"], model_boundary::PROTOCOL);
    assert_eq!(result["body"]["store"], false);
    let wire = result.to_string();
    for raw in [
        "192.0.2.123",
        "11.111.111.11",
        "native-startup-only",
        "skill-contact@example.com",
    ] {
        assert!(!wire.contains(raw));
    }
    assert!(wire.contains("[EMAIL-1]"));
}
#[test]
fn provider_reasoning_replay_is_exact_and_bound_to_the_registered_session() {
    let (_temp, vault) = vault();
    let cipher = "opaque-provider-fixture";
    let request = json!({"session_id":"chat","body":{"include":["reasoning.encrypted_content"],"input":[{"type":"reasoning","encrypted_content":cipher},{"role":"user","content":"clean"}]}});
    assert!(model_boundary::filter(&request, Policy::default(), &vault).is_err());
    model_boundary::record_provider(
        &json!({"session_id":"chat","item":{"type":"reasoning","encrypted_content":cipher}}),
        Policy::default(),
        &vault,
    )
    .unwrap();
    let result = model_boundary::filter(&request, Policy::default(), &vault).unwrap();
    assert_eq!(
        result["body"]["include"],
        json!(["reasoning.encrypted_content"])
    );
    assert_eq!(result["body"]["input"][0]["encrypted_content"], cipher);
    let mut other = request.clone();
    other["session_id"] = json!("other-chat");
    assert!(model_boundary::filter(&other, Policy::default(), &vault).is_err());
}
#[test]
fn real_opaque_inputs_are_blocked_but_tool_schema_metadata_is_text() {
    let (_temp, vault) = vault();
    for item in [
        json!({"type":"input_image","image_url":"opaque"}),
        json!({"type":"input_file","file_id":"opaque"}),
        json!({"type":"message","encrypted_content":"opaque"}),
    ] {
        assert!(
            model_boundary::filter(
                &json!({"session_id":"chat","body":{"input":[item]}}),
                Policy::default(),
                &vault
            )
            .is_err()
        );
    }
    let metadata = json!({"type":"additional_tools","tools":[{"type":"function","name":"local_read","parameters":{"type":"object","properties":{"file_id":{"type":"string"}}}}]});
    assert!(
        model_boundary::filter(
            &json!({"session_id":"chat","body":{"input":[metadata]}}),
            Policy::default(),
            &vault
        )
        .is_ok()
    );
}
#[test]
fn server_side_continuation_and_hosted_tools_cannot_bypass_the_boundary() {
    let (_temp, vault) = vault();
    for body in [
        json!({"previous_response_id":"other"}),
        json!({"conversation":"other"}),
        json!({"background":true}),
        json!({"tools":[{"type":"web_search"}]}),
        json!({"tools":[{"type":"tool_search","execution":"server"}]}),
    ] {
        assert!(
            model_boundary::filter(
                &json!({"session_id":"chat","body":body}),
                Policy::default(),
                &vault
            )
            .is_err()
        );
    }
}
#[test]
fn client_tool_discovery_metadata_is_filtered_without_executing_hosted_tools() {
    let (_temp, vault) = vault();
    let request = json!({"session_id":"chat","body":{"tools":[{"type":"tool_search","execution":"client","description":"Contact discovery@example.com"}],"input":[{"type":"tool_search_output","execution":"client","tools":[{"type":"function","name":"read","description":"Read 192.0.2.10","parameters":{"properties":{"file_id":{"type":"string"}}}}]}]}});
    let safe = model_boundary::filter(&request, Policy::default(), &vault)
        .unwrap()
        .to_string();
    assert!(!safe.contains("discovery@example.com"));
    assert!(!safe.contains("192.0.2.10"));
}
#[test]
fn native_filter_shares_existing_prompt_aliases_and_persists_new_startup_aliases() {
    let (_temp, vault) = vault();
    vault
        .mask("chat", Policy::default(), &json!("11.111.111.11"))
        .unwrap();
    let safe = model_boundary::filter(
        &json!({"session_id":"chat","body":{"instructions":"192.0.2.123","input":"[IP-1]"}}),
        Policy::default(),
        &vault,
    )
    .unwrap();
    assert_eq!(safe["body"]["instructions"], "[IP-2]");
    vault
        .transact("chat", Policy::default(), |engine| {
            assert_eq!(engine.restore("[IP-1] [IP-2]"), "11.111.111.11 192.0.2.123");
            Ok(())
        })
        .unwrap();
}
#[test]
fn invalid_envelopes_never_emit_uninspected_content() {
    let (_temp, vault) = vault();
    for envelope in [
        Value::Null,
        json!({"body":{}}),
        json!({"session_id":"chat","body":"raw"}),
    ] {
        assert!(model_boundary::filter(&envelope, Policy::default(), &vault).is_err());
    }
}
