mod support;
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn invoke(args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum")))
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
    let directory = support::TempDir::new();
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
fn engine_and_guard_report_the_public_release_version() {
    for binary in [
        env!("CARGO_BIN_EXE_sanctum"),
        env!("CARGO_BIN_EXE_sanctum-guard"),
    ] {
        let output = Command::new(support::binary(binary))
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success());
        let reported = String::from_utf8(output.stdout).unwrap();
        assert!(reported.trim_end().ends_with(env!("CARGO_PKG_VERSION")));
    }
    assert_eq!(sanctum::prompt_guard::PLUGIN_VERSION, sanctum::VERSION);
    assert!(
        sanctum::tool_guard::failure(None)["reason"]
            .as_str()
            .unwrap()
            .contains("заблокировано")
    );
}
#[test]
fn portless_package_contains_current_ui_assets_and_runnable_binaries() {
    let directory = support::TempDir::new();
    let output = directory.path().join("portless");
    let result = Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum-guard")))
        .args(["package-portless", "--output", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let ui = output.join("plugin/ui");
    assert_eq!(
        std::fs::read_to_string(ui.join("composer-host.cjs")).unwrap(),
        include_str!("../ui/composer-host.cjs")
    );
    assert_eq!(
        std::fs::read_to_string(ui.join("manage_backend.py")).unwrap(),
        include_str!("../scripts/manage_backend.py")
    );
    assert!(output.join("plugin/assets/cover.png").is_file());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("plugin/.codex-plugin/plugin.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["version"], sanctum::VERSION);
    assert!(
        manifest["interface"]["shortDescription"]
            .as_str()
            .unwrap()
            .contains("защита")
    );
    let hooks = std::fs::read_to_string(output.join("plugin/hooks/hooks.json")).unwrap();
    assert!(hooks.contains("локальная обработка данных"));
    assert_eq!(
        std::fs::read_to_string(ui.join("cli_text.py")).unwrap(),
        include_str!("../scripts/cli_text.py")
    );
    assert!(output.join(".agents/plugins/marketplace.json").is_file());
    assert!(
        Command::new(support::binary(output.join("plugin/bin/sanctum-guard")))
            .arg("--version")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[cfg(unix)]
#[test]
fn adapter_uses_saved_backend_route_after_switch_and_rejects_invalid_routes() {
    use std::os::unix::fs::PermissionsExt;
    let directory = support::TempDir::new();
    let backend = directory.path().join("selected-backend");
    std::fs::write(&backend, "#!/bin/sh\nprintf 'selected-backend\\n'\n").unwrap();
    std::fs::set_permissions(&backend, std::fs::Permissions::from_mode(0o755)).unwrap();
    let settings = directory.path().join("settings.json");
    std::fs::write(&settings, r#"{"enabled":false}"#).unwrap();
    let route = directory.path().join("backend.json");
    std::fs::write(
        &route,
        serde_json::json!({"mode":"context","path":backend}).to_string(),
    )
    .unwrap();
    let invoke = || {
        Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum-codex")))
            .env("SANCTUM_BACKEND_ROUTE", &route)
            .env("SANCTUM_REAL_CODEX", "/nonexistent-old-backend")
            .env("SANCTUM_SETTINGS_PATH", &settings)
            .output()
            .unwrap()
    };
    let result = invoke();
    assert!(result.status.success());
    assert_eq!(result.stdout, b"selected-backend\n");
    std::fs::write(&route, r#"{"mode":"context","path":"relative-backend"}"#).unwrap();
    let invalid = invoke();
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("relative-backend"));
}
