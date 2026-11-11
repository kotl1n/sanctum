use crate::{Error, MAX_BODY, Result, json, redaction::Policy};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroize;

pub fn random_key() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error("os_random_unavailable"))?;
    let key = bytes.iter().map(|b| format!("{b:02x}")).collect();
    bytes.zeroize();
    Ok(key)
}
pub fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| Error("private_file_create_failed"))?;
    #[cfg(windows)]
    crate::windows::protect_path(path)?;
    file.write_all(bytes)
        .map_err(|_| Error("private_file_write_failed"))
}
fn read_file(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|_| Error("file_read_failed"))?;
    let mut bytes = Vec::new();
    file.take((MAX_BODY + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("file_read_failed"))?;
    if bytes.len() > MAX_BODY {
        return Err(Error("file_size_limit"));
    }
    Ok(bytes)
}
pub fn load_policy(path: Option<&Path>) -> Result<Policy> {
    let Some(path) = path else {
        return Ok(Policy::default());
    };
    let mut raw = read_file(path)?;
    let result = json::parse(&raw)
        .and_then(|v| serde_json::from_value::<Policy>(v).map_err(|_| Error("invalid_policy")));
    raw.zeroize();
    let policy = result?;
    policy.validate()?;
    Ok(policy)
}
pub fn package_claude(output: &Path) -> Result<()> {
    let executable = std::env::current_exe().map_err(|_| Error("binary_location_failed"))?;
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|_| Error("package_parent_failed"))?;
    }
    fs::create_dir(output).map_err(|_| Error("package_output_must_be_new"))?;
    let result = (|| {
        let plugin = output.join("plugin");
        for dir in [
            plugin.join(".claude-plugin"),
            plugin.join("hooks"),
            plugin.join("bin"),
            plugin.join("docs"),
            output.join(".claude-plugin"),
        ] {
            fs::create_dir_all(dir).map_err(|_| Error("package_directory_failed"))?;
        }
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../plugins/sanctum-privacy/.claude-plugin/plugin.json"
        ))
        .map_err(|_| Error("package_encode_failed"))?;
        let marketplace = serde_json::json!({"name":"sanctum-local","owner":{"name":"Sanctum"},
            "description":"Локальная сборка Sanctum: защита приватных данных в Claude Code без прокси.",
            "plugins":[{"name":"sanctum-privacy","source":"./plugin","description":manifest["description"],
                "version":crate::VERSION,"category":"security"}]});
        for (path, data) in [
            (
                plugin.join("hooks/hooks.json"),
                include_str!("../plugins/sanctum-privacy/hooks/hooks.json"),
            ),
            (
                plugin.join(".claude-plugin/plugin.json"),
                include_str!("../plugins/sanctum-privacy/.claude-plugin/plugin.json"),
            ),
            (
                plugin.join("README.md"),
                &include_str!("../plugins/sanctum-privacy/README.md")
                    .replace("../../docs/CLAUDE_CODE.md", "docs/CLAUDE_CODE.md"),
            ),
            (
                plugin.join("docs/CLAUDE_CODE.md"),
                include_str!("../docs/CLAUDE_CODE.md"),
            ),
        ] {
            fs::write(path, data).map_err(|_| Error("package_write_failed"))?;
        }
        fs::write(
            plugin.join(".claude-plugin/icon.png"),
            include_bytes!("../plugins/sanctum-privacy/.claude-plugin/icon.png"),
        )
        .map_err(|_| Error("package_write_failed"))?;
        for (path, data) in [
            (
                plugin.join("policy.json"),
                serde_json::json!({"literals":[],"max_entries":10000}),
            ),
            (output.join(".claude-plugin/marketplace.json"), marketplace),
        ] {
            fs::write(
                path,
                serde_json::to_vec_pretty(&data).map_err(|_| Error("package_encode_failed"))?,
            )
            .map_err(|_| Error("package_write_failed"))?;
        }
        let destination = plugin
            .join("bin")
            .join(crate::platform::executable("sanctum-guard"));
        fs::copy(executable, &destination).map_err(|_| Error("package_binary_copy_failed"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o755))
                .map_err(|_| Error("package_binary_mode_failed"))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}
pub fn package_portless(output: &Path) -> Result<()> {
    let executable = std::env::current_exe().map_err(|_| Error("binary_location_failed"))?;
    let adapter = executable
        .parent()
        .ok_or(Error("binary_location_failed"))?
        .join(crate::platform::executable("sanctum-codex"));
    if !adapter.is_file() {
        return Err(Error("build_sanctum_codex_first"));
    }
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|_| Error("package_parent_failed"))?;
    }
    fs::create_dir(output).map_err(|_| Error("package_output_must_be_new"))?;
    let result = (|| {
        let plugin = output.join("plugin");
        for dir in [
            plugin.join(".codex-plugin"),
            plugin.join("hooks"),
            plugin.join("bin"),
            output.join(".agents/plugins"),
        ] {
            fs::create_dir_all(dir).map_err(|_| Error("package_directory_failed"))?;
        }
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../plugins/sanctum-portless/.codex-plugin/plugin.json"
        ))
        .map_err(|_| Error("package_encode_failed"))?;
        let command = if cfg!(windows) {
            r#""%CODEX_PLUGIN_ROOT%/bin/sanctum-guard.exe" hook --policy "%CODEX_PLUGIN_ROOT%/policy.json""#
        } else {
            "\"${CLAUDE_PLUGIN_ROOT}/bin/sanctum-guard\" hook --policy \"${CLAUDE_PLUGIN_ROOT}/policy.json\""
        };
        let mut hooks = serde_json::Map::new();
        for event in ["UserPromptSubmit", "PreToolUse", "PostToolUse"] {
            hooks.insert(event.into(),serde_json::json!([{"hooks":[{"type":"command","command":command,"timeout":30,"statusMessage":"Sanctum: локальная обработка данных"}]}]));
        }
        let marketplace = serde_json::json!({"name":"sanctum-portless-dev","interface":{"displayName":"Sanctum: локальная защита"},"plugins":[{"name":"sanctum-portless","source":{"source":"local","path":"./plugin"},"policy":{"installation":"AVAILABLE","authentication":"ON_INSTALL"},"category":"Developer Tools"}]});
        for (path, data) in [
            (plugin.join(".codex-plugin/plugin.json"), manifest),
            (
                plugin.join("hooks/hooks.json"),
                serde_json::json!({"hooks":hooks}),
            ),
            (
                plugin.join("policy.json"),
                serde_json::json!({"literals":[],"max_entries":10000}),
            ),
            (output.join(".agents/plugins/marketplace.json"), marketplace),
        ] {
            fs::write(
                path,
                serde_json::to_vec_pretty(&data).map_err(|_| Error("package_encode_failed"))?,
            )
            .map_err(|_| Error("package_write_failed"))?;
        }
        for (source, name) in [(executable, "sanctum-guard"), (adapter, "sanctum-codex")] {
            let destination = plugin.join("bin").join(crate::platform::executable(name));
            fs::copy(source, &destination).map_err(|_| Error("package_binary_copy_failed"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(destination, fs::Permissions::from_mode(0o755))
                    .map_err(|_| Error("package_binary_mode_failed"))?;
            }
        }
        let ui = plugin.join("ui");
        fs::create_dir(&ui).map_err(|_| Error("package_directory_failed"))?;
        for (name, contents) in [
            ("composer.js", include_str!("../ui/composer.js")),
            ("cli_text.py", include_str!("../scripts/cli_text.py")),
            (
                "platform_support.py",
                include_str!("../scripts/platform_support.py"),
            ),
            (
                "manage_backend.py",
                include_str!("../scripts/manage_backend.py"),
            ),
            ("composer-host.cjs", include_str!("../ui/composer-host.cjs")),
        ] {
            fs::write(ui.join(name), contents).map_err(|_| Error("package_write_failed"))?;
        }
        let assets = plugin.join("assets");
        fs::create_dir(&assets).map_err(|_| Error("package_directory_failed"))?;
        for (name, contents) in [
            (
                "cover.png",
                include_bytes!("../plugins/sanctum-portless/assets/cover.png").as_slice(),
            ),
            (
                "cover.svg",
                include_bytes!("../plugins/sanctum-portless/assets/cover.svg").as_slice(),
            ),
            (
                "logo.svg",
                include_bytes!("../plugins/sanctum-portless/assets/logo.svg").as_slice(),
            ),
            (
                "composer-icon.svg",
                include_bytes!("../plugins/sanctum-portless/assets/composer-icon.svg").as_slice(),
            ),
        ] {
            fs::write(assets.join(name), contents).map_err(|_| Error("package_write_failed"))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}
