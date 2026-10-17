use sanctum::{json, setup};
use serde_json::json as value;
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn invoke(args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sanctum"))
        .args(args)
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
#[test]
fn native_cli_redact_restore_and_private_vault() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("test.vault.json");
    let original = "11.111.111.11 demo@example.com password=synthetic-password";
    let masked = invoke(&["redact", "--vault", path.to_str().unwrap()], original);
    assert!(masked.status.success());
    assert!(!String::from_utf8_lossy(&masked.stdout).contains("11.111.111.11"));
    let restored = invoke(
        &["restore", "--vault", path.to_str().unwrap()],
        std::str::from_utf8(&masked.stdout).unwrap(),
    );
    assert!(restored.status.success());
    assert_eq!(std::str::from_utf8(&restored.stdout).unwrap(), original);
    assert!(
        !invoke(&["redact", "--vault", path.to_str().unwrap()], "hello")
            .status
            .success()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
}
#[test]
fn native_hook_and_prompt_guard_never_echo_input() {
    let input =
        value!({"hook_event_name":"SessionStart","prompt":"synthetic-hidden-value"}).to_string();
    let start = invoke(&["session-start"], &input);
    assert!(start.status.success());
    assert!(!String::from_utf8_lossy(&start.stdout).contains("synthetic-hidden-value"));
    assert_eq!(
        json::parse(&start.stdout).unwrap()["hookSpecificOutput"]["hookEventName"],
        "SessionStart"
    );
    for input in [
        value!({"hook_event_name":"UserPromptSubmit","prompt":"password=synthetic-hidden-value"})
            .to_string(),
        "broken".into(),
    ] {
        let blocked = invoke(&["prompt-guard"], &input);
        assert!(blocked.status.success());
        assert_eq!(json::parse(&blocked.stdout).unwrap()["decision"], "block");
        assert!(!String::from_utf8_lossy(&blocked.stdout).contains("synthetic-hidden-value"));
    }
}
#[test]
fn setup_is_private_compatible_and_non_overwriting() {
    let directory = tempfile::tempdir().unwrap();
    let result = invoke(
        &["prepare", "--directory", directory.path().to_str().unwrap()],
        "",
    );
    assert!(result.status.success());
    let connection = setup::load_connection(&directory.path().join("connection.json")).unwrap();
    assert_eq!(connection.port, 47631);
    assert_eq!(connection.mode.label(), "chatgpt");
    assert!(!String::from_utf8_lossy(&result.stdout).contains(&connection.local_key));
    assert!(
        !invoke(
            &["prepare", "--directory", directory.path().to_str().unwrap()],
            ""
        )
        .status
        .success()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["connection.json", "codex.fragment.toml"] {
            assert_eq!(
                directory
                    .path()
                    .join(name)
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
#[test]
fn package_contains_executable_native_hook_and_no_python_dependency() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("native-package");
    assert!(
        invoke(&["package", "--output", output.to_str().unwrap()], "")
            .status
            .success()
    );
    let hook = std::fs::read_to_string(output.join("plugin/hooks/hooks.json")).unwrap();
    assert!(hook.contains("/bin/sanctum"));
    assert!(!hook.contains("python"));
    let binary = output.join("plugin/bin/sanctum");
    assert!(
        Command::new(binary)
            .arg("--version")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !invoke(&["package", "--output", output.to_str().unwrap()], "")
            .status
            .success()
    );
}
