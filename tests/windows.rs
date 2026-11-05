#![cfg(windows)]
mod support;
use sanctum::{redaction::Policy, vault::Vault};
use serde_json::json;
use std::process::Command;

#[test]
fn concurrent_windows_vault_updates_keep_all_mappings() {
    let temp = support::TempDir::new();
    let directory = temp.path().join("private");
    let vault = Vault::new(directory.clone()).unwrap();
    let handles: Vec<_> = (1..=4)
        .map(|last| {
            let directory = directory.clone();
            std::thread::spawn(move || {
                let vault = Vault::new(directory).unwrap();
                let original = std::net::Ipv4Addr::new(192, 0, 2, last).to_string();
                let masked = vault
                    .mask("parallel", Policy::default(), &json!(original))
                    .unwrap();
                (original, masked)
            })
        })
        .collect();
    let values: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    vault
        .transact("parallel", Policy::default(), |engine| {
            for (original, masked) in &values {
                assert_eq!(engine.restore(masked.as_str().unwrap()), *original);
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn master_key_uses_dpapi_and_hardlinked_key_is_rejected() {
    let temp = support::TempDir::new();
    let directory = temp.path().join("private");
    let vault = Vault::new(directory.clone()).unwrap();
    vault
        .mask("fixture", Policy::default(), &json!("synthetic text"))
        .unwrap();
    let key = directory.join("master.key");
    assert!(std::fs::metadata(&key).unwrap().len() > 32);
    std::fs::hard_link(&key, directory.join("linked-key")).unwrap();
    assert!(
        vault
            .mask("fixture", Policy::default(), &json!("safe"))
            .is_err()
    );
}

#[test]
fn adapter_returns_exit_code_from_windows_backend() {
    let temp = support::TempDir::new();
    let shell = std::env::var_os("COMSPEC").unwrap();
    let settings = temp.path().join("settings.json");
    std::fs::write(&settings, br#"{"enabled":false}"#).unwrap();
    let result = Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum-codex")))
        .args(["/D", "/C", "exit 7"])
        .env("SANCTUM_REAL_CODEX", shell)
        .env_remove("SANCTUM_BACKEND_ROUTE")
        .env("SANCTUM_SETTINGS_PATH", settings)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(7));
}

#[test]
fn local_windows_command_restores_and_masks_utf8_output() {
    let temp = support::TempDir::new();
    let directory = temp.path().join("private");
    let vault = Vault::new(directory.clone()).unwrap();
    let original = std::net::Ipv4Addr::new(192, 0, 2, 37).to_string();
    let masked = vault
        .mask("fixture", Policy::default(), &json!(original))
        .unwrap();
    let file = temp
        .path()
        .join(format!("кириллица с пробелом {original}.txt"));
    std::fs::write(&file, format!("Привет, мир! {original}\r\n")).expect("write_utf8_fixture");
    let masked_path = file
        .to_string_lossy()
        .replace(&original, masked.as_str().unwrap());
    let line = format!("type \"{masked_path}\"");
    let encoded: String = line.bytes().map(|value| format!("{value:02x}")).collect();
    let result = Command::new(support::binary(env!("CARGO_BIN_EXE_sanctum-guard")))
        .args([
            "run-command",
            "--session",
            "fixture",
            "--command-hex",
            &encoded,
            "--shell",
        ])
        .arg(std::env::var_os("COMSPEC").unwrap())
        .env("SANCTUM_STATE_DIR", directory)
        .env_remove("SANCTUM_GUARD_POLICY")
        .output()
        .expect("run_windows_guard");
    assert!(
        result.status.success(),
        "status={:?}; stdout={:?}; stderr={:?}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("Привет, мир!"), "captured={output:?}");
    assert!(!output.contains(&original));
    assert!(output.contains(masked.as_str().unwrap()));
}

#[test]
fn windows_code_arguments_reject_environment_expansion_in_originals() {
    use sanctum::{protocol::Session, redaction::Redactor};
    let original = "synthetic%PATH%fixture";
    let mut policy = Policy::default();
    policy.literals.push(original.into());
    let mut engine = Redactor::new(policy).unwrap();
    let token = engine.text(original).unwrap();
    let session = Session::new(engine);
    assert!(
        session
            .arguments(&json!({"cmd":token}).to_string(), "exec")
            .is_err()
    );
    let data = session
        .arguments(&json!({"path":token}).to_string(), "read_file")
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&data).unwrap()["path"],
        original
    );
}
