mod support;
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

const EMAIL: &str = "demo.user@example.com";
const ADDRESS: &str = "11.111.111.11";

fn hook(state: &std::path::Path, event: Value) -> Option<Value> {
    let mut child = Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum-guard")))
        .args([
            "claude-hook",
            "--state-directory",
            state.join("private").to_str().unwrap(),
        ])
        .env("SANCTUM_SETTINGS_PATH", state.join("settings.json"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    (!text.trim().is_empty()).then(|| serde_json::from_str(&text).unwrap())
}

fn mask_output(state: &std::path::Path, stdout: &str) -> Value {
    let result = hook(
        state,
        json!({"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat x"},
            "tool_response":{"stdout":stdout,"stderr":"","interrupted":false,"isImage":false}}),
    )
    .unwrap();
    result["hookSpecificOutput"]["updatedToolOutput"].clone()
}

#[test]
fn prompt_with_private_data_is_blocked_with_masked_copy() {
    let temp = support::TempDir::new();
    let prompt = format!("write to {EMAIL}");
    let result = hook(
        temp.path(),
        json!({"session_id":"s","hook_event_name":"UserPromptSubmit","prompt":prompt}),
    )
    .unwrap();
    assert_eq!(result["decision"], "block");
    assert_eq!(result["hookSpecificOutput"]["suppressOriginalPrompt"], true);
    let reason = result["reason"].as_str().unwrap();
    assert!(reason.contains("write to [EMAIL-1]") && !reason.contains(EMAIL));
    let resent = json!({"session_id":"s","hook_event_name":"UserPromptSubmit","prompt":"write to [EMAIL-1]"});
    assert!(hook(temp.path(), resent).is_none());
}

#[test]
fn tool_output_is_masked_in_the_same_shape() {
    let temp = support::TempDir::new();
    let output = mask_output(temp.path(), &format!("{EMAIL} {ADDRESS}"));
    assert_eq!(
        output,
        json!({"stdout":"[EMAIL-1] [IP-1]","stderr":"","interrupted":false,"isImage":false})
    );
    let clean = json!({"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{},
        "tool_response":{"stdout":"hello","stderr":""}});
    assert!(hook(temp.path(), clean).is_none());
}

#[test]
fn bash_runs_restored_command_without_exposing_values_to_the_hook_output() {
    let temp = support::TempDir::new();
    mask_output(temp.path(), EMAIL);
    let result = hook(
        temp.path(),
        json!({"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash",
            "tool_input":{"command":"printf '%s' [EMAIL-1] | wc -c","description":"count"}}),
    )
    .unwrap();
    let encoded = result.to_string();
    assert!(!encoded.contains(EMAIL));
    let input = &result["hookSpecificOutput"]["updatedInput"];
    assert_eq!(input["description"], "count");
    #[cfg(windows)]
    let shell = sanctum::claude_hook::git_bash().expect("Git Bash is required on Windows");
    #[cfg(not(windows))]
    let shell = std::path::PathBuf::from("/bin/sh");
    let run = Command::new(shell)
        .args(["-c", input["command"].as_str().unwrap()])
        .output()
        .unwrap();
    assert!(run.status.success());
    assert_eq!(
        String::from_utf8(run.stdout).unwrap().trim(),
        EMAIL.len().to_string()
    );
}

#[test]
fn written_files_receive_original_values_and_network_tools_keep_pseudonyms() {
    let temp = support::TempDir::new();
    mask_output(temp.path(), ADDRESS);
    let file = temp.path().join("config.txt");
    std::fs::write(&file, "host=[IP-1] other=[IP-9]\n").unwrap();
    let input = json!({"file_path":file,"content":"host=[IP-1] other=[IP-9]\n"});
    assert!(
        hook(
            temp.path(),
            json!({"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":input}),
        )
        .is_none()
    );
    hook(
        temp.path(),
        json!({"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":input,
            "tool_response":{"type":"create","filePath":file,"content":"host=[IP-1] other=[IP-9]\n"}}),
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("host={ADDRESS} other=[IP-9]\n")
    );
    let fetch = json!({"session_id":"s","hook_event_name":"PreToolUse","tool_name":"WebFetch",
        "tool_input":{"url":"https://example.com/?q=[IP-1]","prompt":"x"}});
    assert!(hook(temp.path(), fetch).is_none());
}

#[test]
fn forwarded_prompt_wakes_the_model_with_masked_text_only() {
    let temp = support::TempDir::new();
    let run = |prompt: &str| {
        let mut child = Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum-guard")))
            .args(["claude-hook", "--forward-prompt", "--state-directory"])
            .arg(temp.path().join("private"))
            .env("SANCTUM_SETTINGS_PATH", temp.path().join("settings.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let event = json!({"session_id":"s","hook_event_name":"UserPromptSubmit","prompt":prompt});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(event.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let output = run(&format!("owner={EMAIL}, host {ADDRESS}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "owner=[EMAIL-1], host [IP-1]"
    );
    let clean = run("hello");
    assert_eq!(clean.status.code(), Some(0));
    assert!(clean.stderr.is_empty());
}

#[test]
fn displayed_messages_show_original_values_marked_as_model_placeholders() {
    let temp = support::TempDir::new();
    mask_output(temp.path(), &format!("{EMAIL} {ADDRESS}"));
    let show = |style: &str, delta: &str| -> Option<String> {
        let mut child = Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum-guard")))
            .args(["claude-hook", "--state-directory"])
            .arg(temp.path().join("private"))
            .env("SANCTUM_SETTINGS_PATH", temp.path().join("settings.json"))
            .env("SANCTUM_DISPLAY_STYLE", style)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let event = json!({"session_id":"s","hook_event_name":"MessageDisplay","turn_id":"t",
            "message_id":"m","index":0,"final":true,"delta":delta});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(event.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        (!text.trim().is_empty()).then(|| {
            let value: Value = serde_json::from_str(&text).unwrap();
            value["hookSpecificOutput"]["displayContent"]
                .as_str()
                .unwrap()
                .to_owned()
        })
    };
    assert_eq!(
        show("ansi", "mail [EMAIL-1]\n").unwrap(),
        format!("mail \x1b[90m{EMAIL}\x1b[39m\n")
    );
    let latex = show("latex", "host [IP-1], `[IP-1]`\n```\n[IP-1]\n```\n").unwrap();
    assert_eq!(
        latex,
        format!(
            "host $\\color{{gray}}{{\\text{{11}}\\text{{.111}}\\text{{.111}}\\text{{.11}}}}$, `{ADDRESS}`\n```\n{ADDRESS}\n```\n"
        )
    );
    assert!(show("latex", "nothing [IP-7] here\n").is_none());
    assert!(show("latex", "plain text\n").is_none());
}

#[test]
fn resumed_sessions_in_the_same_project_share_pseudonyms() {
    let temp = support::TempDir::new();
    let first = hook(
        temp.path(),
        json!({"session_id":"before-resume","cwd":"/work/app","hook_event_name":"PostToolUse","tool_name":"Bash",
            "tool_input":{},"tool_response":{"stdout":EMAIL,"stderr":""}}),
    )
    .unwrap();
    assert_eq!(
        first["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        "[EMAIL-1]"
    );
    let shown = hook(
        temp.path(),
        json!({"session_id":"after-resume","cwd":"/work/app","hook_event_name":"MessageDisplay",
            "turn_id":"t","message_id":"m","index":0,"final":true,"delta":"[EMAIL-1]\n"}),
    )
    .unwrap();
    assert!(
        shown["hookSpecificOutput"]["displayContent"]
            .as_str()
            .unwrap()
            .contains(r"\text{demo}\text{.user}\char64")
    );
    let other_project = json!({"session_id":"after-resume","cwd":"/work/other","hook_event_name":"MessageDisplay",
        "turn_id":"t","message_id":"m","index":0,"final":true,"delta":"[EMAIL-1]\n"});
    assert!(hook(temp.path(), other_project).is_none());
}

#[test]
fn mentioned_files_with_private_data_are_not_attached() {
    let temp = support::TempDir::new();
    let project = temp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("secrets.env"), format!("ADMIN={EMAIL}\n")).unwrap();
    std::fs::write(project.join("notes.md"), "nothing private\n").unwrap();
    let event = |prompt: &str| json!({"session_id":"s","cwd":project,"hook_event_name":"UserPromptSubmit","prompt":prompt});
    let blocked = hook(temp.path(), event("check @secrets.env please")).unwrap();
    assert_eq!(blocked["decision"], "block");
    let reason = blocked["reason"].as_str().unwrap();
    assert!(reason.contains("check @secrets.env please"));
    assert!(reason.contains("not attached") && !reason.contains(EMAIL));
    assert!(hook(temp.path(), event("check @notes.md please")).is_none());
    assert!(hook(temp.path(), event("check @missing.env please")).is_none());
}

#[test]
fn claude_package_is_a_complete_local_marketplace() {
    let directory = support::TempDir::new();
    let output = directory.path().join("claude");
    let result = Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum-guard")))
        .args(["package-claude", "--output", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let read = |path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(output.join(path)).unwrap()).unwrap()
    };
    let marketplace = read(".claude-plugin/marketplace.json");
    assert_eq!(marketplace["plugins"][0]["name"], "sanctum-privacy");
    assert_eq!(marketplace["plugins"][0]["source"], "./plugin");
    assert_eq!(marketplace["plugins"][0]["version"], sanctum::VERSION);
    let manifest = read("plugin/.claude-plugin/plugin.json");
    assert_eq!(manifest["name"], "sanctum-privacy");
    assert_eq!(manifest["version"], sanctum::VERSION);
    let hooks = read("plugin/hooks/hooks.json");
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "MessageDisplay",
    ] {
        for hook in hooks["hooks"][event][0]["hooks"].as_array().unwrap() {
            assert!(
                hook["command"]
                    .as_str()
                    .unwrap()
                    .starts_with("\"${CLAUDE_PLUGIN_ROOT}/bin/sanctum-guard\" claude-hook")
            );
        }
    }
    assert!(
        hooks["hooks"]["UserPromptSubmit"][0]["hooks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hook| hook["asyncRewake"] == true)
    );
    let readme = std::fs::read_to_string(output.join("plugin/README.md")).unwrap();
    assert!(readme.contains("](docs/CLAUDE_CODE.md)"));
    assert!(output.join("plugin/docs/CLAUDE_CODE.md").is_file());
    assert!(output.join("plugin/.claude-plugin/icon.png").is_file());
    let binary = output
        .join("plugin/bin")
        .join(sanctum::platform::executable("sanctum-guard"));
    let version = Command::new(support::binary(binary.to_str().unwrap()))
        .arg("--version")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).contains(sanctum::VERSION));
}
