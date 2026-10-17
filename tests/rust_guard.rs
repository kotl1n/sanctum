use sanctum::{Error, json, prompt_guard, redaction::Policy};
use serde_json::{Value, json as value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn invoke(args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sanctum-guard"))
        .args(args)
        .env_remove("SANCTUM_GUARD_POLICY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
fn event(prompt: &str) -> String {
    value!({"hook_event_name":"UserPromptSubmit","prompt":prompt,"session_id":"synthetic-session"})
        .to_string()
}

#[test]
fn clean_prompts_and_literal_placeholders_are_allowed() {
    for prompt in [
        "Explain ownership in Rust",
        "Use [IP-1] and [EMAIL-1] in this example",
        "Поясни этот алгоритм",
    ] {
        assert!(
            !prompt_guard::inspect(prompt, Policy::default())
                .unwrap()
                .blocked()
        );
        let result = invoke(&["check"], &event(prompt));
        assert!(result.status.success());
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }
}
#[test]
fn secrets_are_blocked_without_echoing_values() {
    for (prompt, secret, category) in [
        ("Check server 11.111.111.11", "11.111.111.11", "IP"),
        ("Contact demo@example.com.", "demo@example.com", "EMAIL"),
        (
            "password=synthetic-password",
            "synthetic-password",
            "SECRET",
        ),
        (
            "sk-proj-abcdefghijklmnopqrstuvwx",
            "sk-proj-abcdefghijklmnopqrstuvwx",
            "KEY",
        ),
        (
            "пароль='секрет с пробелами'",
            "секрет с пробелами",
            "SECRET",
        ),
    ] {
        let output = invoke(&["check"], &event(prompt));
        assert!(output.status.success());
        let decision = json::parse(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "block");
        assert!(decision["reason"].as_str().unwrap().contains(category));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}
#[test]
fn counts_are_distinct_values_not_placeholder_indices() {
    let findings = prompt_guard::inspect(
        "Example [IP-1]; real 11.111.111.11 and again 11.111.111.11",
        Policy::default(),
    )
    .unwrap();
    assert_eq!(findings.0, vec![("IP", 1)]);
}
#[test]
fn json_prompts_and_serialized_secrets_are_checked() {
    for prompt in [
        r#"{"password":"synthetic with spaces"}"#,
        r#"{"payload":"{\"token\":\"synthetic-nested\"}"}"#,
        r#"{"password":123456}"#,
    ] {
        assert!(
            prompt_guard::inspect(prompt, Policy::default())
                .unwrap()
                .blocked()
        );
    }
}
#[test]
fn malformed_hook_and_invalid_policy_block_without_hook_failure() {
    let directory = tempfile::tempdir().unwrap();
    let invalid = directory.path().join("invalid.json");
    std::fs::write(&invalid, r#"{"unknown":"synthetic-private-value"}"#).unwrap();
    for input in [
        "broken",
        "{}",
        r#"{"hook_event_name":"Other","prompt":"synthetic-private-value"}"#,
        r#"{"hook_event_name":"UserPromptSubmit","prompt":123}"#,
    ] {
        let output = invoke(&["check"], input);
        assert!(output.status.success());
        assert_eq!(json::parse(&output.stdout).unwrap()["decision"], "block");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-private-value"));
    }
    for path in [invalid, directory.path().join("missing.json")] {
        let output = invoke(
            &["check", "--policy", path.to_str().unwrap()],
            &event("clean prompt"),
        );
        assert!(output.status.success());
        assert_eq!(json::parse(&output.stdout).unwrap()["decision"], "block");
        assert!(output.stderr.is_empty());
    }
    assert!(
        prompt_guard::decision(Err(Error("private_diagnostic_must_not_be_echoed")))
            .unwrap()
            .to_string()
            .find("private_diagnostic")
            .is_none()
    );
}
#[test]
fn hook_metadata_is_not_treated_as_the_typed_prompt() {
    let event = value!({"hook_event_name":"UserPromptSubmit","prompt":"Explain this algorithm","cwd":"/private/demo@example.com","session_id":"synthetic-session"});
    assert!(
        !prompt_guard::inspect_hook(event.to_string().as_bytes(), Policy::default())
            .unwrap()
            .blocked()
    );
}
#[test]
fn known_company_secret_is_blocked_by_custom_policy() {
    let directory = tempfile::tempdir().unwrap();
    let policy = directory.path().join("policy.json");
    std::fs::write(&policy, r#"{"literals":["SYNTHETIC-COMPANY-INTERNAL"]}"#).unwrap();
    let output = invoke(
        &["check", "--policy", policy.to_str().unwrap()],
        &event("Inspect SYNTHETIC-COMPANY-INTERNAL"),
    );
    let decision = json::parse(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "block");
    assert!(decision["reason"].as_str().unwrap().contains("CUSTOM"));
    assert!(!decision.to_string().contains("SYNTHETIC-COMPANY-INTERNAL"));
}
#[test]
fn standalone_package_has_only_submit_hook_and_no_server_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let package = directory.path().join("guard");
    assert!(
        invoke(&["package", "--output", package.to_str().unwrap()], "")
            .status
            .success()
    );
    let hooks: Value =
        json::parse(&std::fs::read(package.join("plugin/hooks/hooks.json")).unwrap()).unwrap();
    assert!(!package.join("plugin/plugin.json").exists());
    assert!(package.join("plugin/.codex-plugin/plugin.json").is_file());
    let events = hooks["hooks"].as_object().unwrap();
    assert_eq!(events.keys().collect::<Vec<_>>(), vec!["UserPromptSubmit"]);
    let command = events["UserPromptSubmit"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(command.contains("/bin/sanctum-guard\" check"));
    for unwanted in ["python", " serve", "http://", "https://"] {
        assert!(!command.contains(unwanted));
    }
    assert!(!package.join("connection.json").exists());
    assert!(!package.join("codex.fragment.toml").exists());
    let binary = package.join("plugin/bin/sanctum-guard");
    let help = Command::new(binary).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("check"));
    assert!(!help.contains("  serve"));
    assert!(
        !invoke(&["package", "--output", package.to_str().unwrap()], "")
            .status
            .success()
    );
}
#[test]
fn guard_demo_runs_without_provider_or_codex_configuration() {
    let output = invoke(&["demo"], "");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("PASS:"));
    assert!(text.contains("\"decision\":\"allow\""));
    assert!(text.contains("\"decision\":\"block\""));
}
