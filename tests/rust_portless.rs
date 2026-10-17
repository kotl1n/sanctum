use sanctum::{
    bridge::Filter,
    redaction::{Policy, Redactor},
    tool_guard,
    vault::Vault,
};
use serde_json::{Value, json};
use std::sync::Arc;

fn vault() -> (tempfile::TempDir, Vault) {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::new(temp.path().join("private")).unwrap();
    (temp, vault)
}
#[test]
fn extended_entities_and_context_preserve_roundtrips() {
    for (original, token) in [
        ("Call +7 (999) 123-45-67", "[PHONE-1]"),
        ("Card 4111 1111 1111 1111", "[CARD-1]"),
        ("Go to api.payments.internal", "[DOMAIN-1]"),
        ("паспорт: 1234 567890", "[DOCUMENT-1]"),
        ("ФИО=\"Иван Иванов\"", "[PERSON-1]"),
    ] {
        let mut engine = Redactor::new(Policy::default()).unwrap();
        let safe = engine.text(original).unwrap();
        assert!(safe.contains(token), "{safe}");
        assert_eq!(engine.restore(&safe), original);
    }
    let mut engine = Redactor::new(Policy::default()).unwrap();
    assert_eq!(
        engine
            .text("4111 1111 1111 1112 build 123456 Иван")
            .unwrap(),
        "4111 1111 1111 1112 build 123456 Иван"
    );
}
#[test]
fn configured_names_domains_regex_and_structured_documents() {
    let mut policy = Policy::default();
    policy.personal_names = vec!["Иван Иванов".into()];
    policy.internal_domains = vec!["company.example".into()];
    policy.patterns = vec![r"EMP-[0-9]{5}".into()];
    let mut engine = Redactor::new(policy).unwrap();
    let safe=engine.value(&json!({"phone":"89991234567","passport":"1234 567890","full_name":"Анна Примерова","nested":"Иван Иванов https://db.company.example EMP-12345"})).unwrap().to_string();
    for raw in [
        "89991234567",
        "1234 567890",
        "Анна Примерова",
        "Иван Иванов",
        "db.company.example",
        "EMP-12345",
    ] {
        assert!(!safe.contains(raw));
    }
    assert!(safe.contains("[DOMAIN-1]"));
    let mut invalid = Policy::default();
    invalid.patterns = vec![".*".into()];
    assert!(Redactor::new(invalid).is_err());
}
#[test]
fn encrypted_vault_persists_without_plaintext_and_is_session_bound() {
    let (temp, vault) = vault();
    let safe = vault
        .mask(
            "session-one",
            Policy::default(),
            &json!("11.111.111.11 demo@example.com"),
        )
        .unwrap();
    assert_eq!(safe, "[IP-1] [EMAIL-1]");
    let reopened = Vault::new(temp.path().join("private")).unwrap();
    assert_eq!(
        reopened
            .mask("session-one", Policy::default(), &json!("11.111.111.11"))
            .unwrap(),
        "[IP-1]"
    );
    assert_eq!(
        reopened
            .mask("session-two", Policy::default(), &json!("22.222.222.22"))
            .unwrap(),
        "[IP-1]"
    );
    reopened
        .transact("session-one", Policy::default(), |engine| {
            assert_eq!(engine.restore("[IP-1]"), "11.111.111.11");
            Ok(())
        })
        .unwrap();
    for file in std::fs::read_dir(temp.path().join("private")).unwrap() {
        let bytes = std::fs::read(file.unwrap().path()).unwrap();
        for raw in ["11.111.111.11", "demo@example.com", "22.222.222.22"] {
            assert!(!bytes.windows(raw.len()).any(|s| s == raw.as_bytes()));
        }
    }
    reopened.forget("session-one").unwrap();
    assert!(!reopened.exists("session-one").unwrap());
}
#[test]
fn corruption_and_cross_session_ciphertext_fail_closed() {
    let (temp, vault) = vault();
    vault
        .mask("one", Policy::default(), &json!("11.111.111.11"))
        .unwrap();
    vault
        .mask("two", Policy::default(), &json!("22.222.222.22"))
        .unwrap();
    let files: Vec<_> = std::fs::read_dir(temp.path().join("private"))
        .unwrap()
        .map(|x| x.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "vault"))
        .collect();
    std::fs::copy(&files[0], &files[1]).unwrap();
    let failures = ["one", "two"]
        .into_iter()
        .filter(|id| vault.mask(id, Policy::default(), &json!("clean")).is_err())
        .count();
    assert_eq!(failures, 1);
    for path in files {
        let mut data = std::fs::read(&path).unwrap();
        let n = data.len();
        data[n - 1] ^= 1;
        std::fs::write(path, data).unwrap();
    }
    assert!(
        vault
            .mask("one", Policy::default(), &json!("clean"))
            .is_err()
    );
}
#[test]
fn snapshot_preserves_reserved_literals_and_new_indices() {
    let mut engine = Redactor::new(Policy::default()).unwrap();
    assert_eq!(
        engine.text("[IP-1] 11.111.111.11").unwrap(),
        "[IP-1] [IP-2]"
    );
    let mut restored = Redactor::from_snapshot(Policy::default(), &engine.snapshot()).unwrap();
    assert!(restored.literal_token("[IP-1]"));
    assert_eq!(
        restored.text("11.111.111.11 22.222.222.22").unwrap(),
        "[IP-2] [IP-3]"
    );
}
#[test]
fn hooks_restore_local_arguments_and_remask_new_output_entities() {
    let (_temp, vault) = vault();
    vault
        .mask("chat", Policy::default(), &json!("11.111.111.11"))
        .unwrap();
    let pre = json!({"session_id":"chat","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf '%s' '[IP-1]'"}});
    let decision = tool_guard::handle(&pre, Policy::default(), &vault)
        .unwrap()
        .unwrap();
    assert!(
        decision["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap()
            .contains("run-command")
    );
    assert!(!decision.to_string().contains("11.111.111.11"));
    let post = json!({"session_id":"chat","hook_event_name":"PostToolUse","tool_response":{"output":"11.111.111.11 demo@example.com"}});
    let safe = tool_guard::handle(&post, Policy::default(), &vault)
        .unwrap()
        .unwrap();
    assert_eq!(safe["decision"], "block");
    assert!(safe.to_string().contains("[EMAIL-1]"));
    assert!(!safe.to_string().contains("11.111.111.11"));
    let remote = json!({"session_id":"chat","hook_event_name":"PreToolUse","tool_name":"mcp_remote_send","tool_input":{"value":"[IP-1]"}});
    assert!(tool_guard::handle(&remote, Policy::default(), &vault).is_err());
}
#[test]
fn shell_injection_and_unknown_aliases_are_not_restored() {
    let (_temp, vault) = vault();
    vault
        .mask(
            "chat",
            Policy::default(),
            &json!("password='a; touch /tmp/unsafe'"),
        )
        .unwrap();
    for token in ["[SECRET-1]", "[IP-999]"] {
        let pre = json!({"session_id":"chat","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":format!("echo {token}")}});
        let encoded = pre["tool_input"]["command"]
            .as_str()
            .unwrap()
            .bytes()
            .map(|c| format!("{c:02x}"))
            .collect::<String>();
        assert!(sanctum::local_command::run(&vault, "chat", Policy::default(), &encoded).is_err());
    }
}
#[test]
fn bridge_masks_before_backend_and_rejects_opaque_or_unprotected_history() {
    let (temp, vault) = vault();
    let filter = Filter::new(Arc::new(vault), Policy::default());
    filter
        .incoming(&json!({"id":1,"method":"thread/start","params":{"cwd":temp.path()}}))
        .unwrap();
    filter
        .outgoing(&json!({"id":1,"result":{"thread":{"id":"thread-test","cwd":temp.path()}}}))
        .unwrap();
    let safe=filter.incoming(&json!({"id":2,"method":"turn/start","params":{"threadId":"thread-test","input":[{"type":"text","text":"11.111.111.11"}]}})).unwrap();
    assert_eq!(safe["params"]["input"][0]["text"], "[IP-1]");
    for item in [
        json!({"type":"localImage","path":"/private/photo.png"}),
        json!({"type":"file","file_data":"opaque"}),
    ] {
        assert!(filter.incoming(&json!({"id":3,"method":"turn/start","params":{"threadId":"thread-test","input":[item]}})).is_err());
    }
    assert!(
        filter
            .incoming(&json!({"id":4,"method":"thread/resume","params":{"threadId":"old-chat"}}))
            .is_err()
    );
}
#[test]
fn bridge_never_silently_passes_sensitive_implicit_instructions() {
    let (temp, vault) = vault();
    std::fs::write(temp.path().join("AGENTS.md"), "Server 11.111.111.11").unwrap();
    let filter = Filter::new(Arc::new(vault), Policy::default());
    assert!(
        filter
            .incoming(&json!({"id":1,"method":"thread/start","params":{"cwd":temp.path()}}))
            .is_err()
    );
}
#[cfg(unix)]
#[test]
fn private_paths_and_locking_prevent_insecure_storage_or_lost_updates() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (temp, vault) = vault();
    std::fs::set_permissions(
        temp.path().join("private"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(Vault::new(temp.path().join("private")).is_err());
    std::fs::set_permissions(
        temp.path().join("private"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    symlink(temp.path().join("private"), temp.path().join("link")).unwrap();
    assert!(Vault::new(temp.path().join("link")).is_err());
    let vault = Arc::new(vault);
    let workers: Vec<_> = (1..=8)
        .map(|i| {
            let vault = vault.clone();
            std::thread::spawn(move || {
                vault
                    .mask("shared", Policy::default(), &json!(format!("192.0.2.{i}")))
                    .unwrap()
            })
        })
        .collect();
    let values: Vec<Value> = workers.into_iter().map(|t| t.join().unwrap()).collect();
    let unique: std::collections::HashSet<_> = values.iter().map(Value::to_string).collect();
    assert_eq!(unique.len(), 8);
}

#[test]
fn bridge_requires_all_three_trusted_hooks() {
    let mut hooks:Vec<_>=["userPromptSubmit","preToolUse","postToolUse"].iter().map(|e|json!({"eventName":e,"pluginId":"sanctum-portless@sanctum-portless-dev","enabled":true,"trustStatus":"trusted"})).collect();
    assert!(sanctum::bridge::verify_hooks(&json!({"data":[{"hooks":hooks}]})).is_ok());
    hooks[1]["trustStatus"] = json!("untrusted");
    assert!(sanctum::bridge::verify_hooks(&json!({"data":[{"hooks":hooks}]})).is_err());
    assert!(sanctum::bridge::verify_hooks(&json!({"data":[]})).is_err());
}

#[test]
fn expired_state_cannot_silently_reassign_old_tokens() {
    let (temp, vault) = vault();
    vault
        .mask("expired", Policy::default(), &json!("11.111.111.11"))
        .unwrap();
    let vault = Vault::new(temp.path().join("private"))
        .unwrap()
        .with_ttl(1)
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1050));
    assert_eq!(
        vault
            .mask("expired", Policy::default(), &json!("22.222.222.22"))
            .unwrap_err()
            .0,
        "vault_expired"
    );
}

#[test]
fn tool_question_answers_are_masked_but_account_routing_is_preserved() {
    let (_temp, vault) = vault();
    vault
        .mask("chat", Policy::default(), &json!("clean"))
        .unwrap();
    let filter = Filter::new(Arc::new(vault), Policy::default());
    filter
        .outgoing(
            &json!({"id":42,"method":"item/tool/requestUserInput","params":{"threadId":"chat"}}),
        )
        .unwrap();
    let answer = filter
        .incoming(&json!({"id":42,"result":{"answer":"demo@example.com"}}))
        .unwrap();
    assert_eq!(answer["result"]["answer"], "[EMAIL-1]");
    filter
        .outgoing(&json!({"id":43,"method":"account/chatgptAuthTokens/refresh","params":{}}))
        .unwrap();
    let routing = json!({"id":43,"result":{"accessToken":"synthetic-routing-only"}});
    assert_eq!(filter.incoming(&routing).unwrap(), routing);
    assert!(
        filter
            .incoming(&json!({"id":99,"result":{"answer":"unknown"}}))
            .is_err()
    );
}

#[test]
fn separate_prompt_parts_share_one_two_pass_inspection() {
    let (temp, vault) = vault();
    let filter = Filter::new(Arc::new(vault), Policy::default());
    let start=filter.incoming(&json!({"id":1,"method":"thread/start","params":{"cwd":temp.path(),"baseInstructions":"fixture-only","developerInstructions":"password=fixture-only"}})).unwrap();
    assert!(!start.to_string().contains("fixture-only"));
    filter
        .outgoing(&json!({"id":1,"result":{"thread":{"id":"chat","cwd":temp.path()}}}))
        .unwrap();
    let turn=filter.incoming(&json!({"id":2,"method":"turn/start","params":{"threadId":"chat","input":[{"type":"text","text":"another-value"},{"type":"text","text":"password=another-value"}]}})).unwrap();
    assert!(!turn.to_string().contains("another-value"));
}

#[test]
fn adapter_does_not_silently_bypass_privacy_for_daemon_transport() {
    for command in ["daemon", "proxy"] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_sanctum-codex"))
            .env("SANCTUM_REAL_CODEX", "/usr/bin/false")
            .args(["app-server", command])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("stdio_transport_required"));
    }
}
#[test]
fn adapter_rejects_a_remote_code_host_before_starting_backend() {
    let temp = tempfile::tempdir().unwrap();
    for args in [
        vec!["--code-mode-host", "https://example.invalid"],
        vec!["--code-mode-host=https://example.invalid"],
    ] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_sanctum-codex"))
            .env("SANCTUM_REAL_CODEX", "/usr/bin/false")
            .env("SANCTUM_STATE_DIR", temp.path().join("private"))
            .env_remove("SANCTUM_NATIVE_REQUIRED")
            .arg("app-server")
            .args(args)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("local_code_mode_host_required"));
    }
}
