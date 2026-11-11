use crate::{Error, MAX_BODY, Result, gateway::Mode, json, redaction::Policy};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub local_key: String,
    pub port: u16,
    pub mode: Mode,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.local_key.zeroize();
    }
}

pub fn random_key() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error("os_random_unavailable"))?;
    let key = bytes.iter().map(|b| format!("{b:02x}")).collect();
    bytes.zeroize();
    Ok(key)
}
pub fn default_directory() -> Result<PathBuf> {
    Ok(crate::platform::home()?.join(".config/sanctum-rust"))
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
pub fn load_connection(path: &Path) -> Result<Connection> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)
            .map_err(|_| Error("connection_unavailable"))?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(Error("connection_must_be_private"));
        }
    }
    let mut raw = read_file(path)?;
    let result = json::parse(&raw).and_then(|v| {
        serde_json::from_value::<Connection>(v).map_err(|_| Error("invalid_connection"))
    });
    raw.zeroize();
    let connection = result?;
    if connection.port == 0 {
        return Err(Error("invalid_port"));
    }
    Ok(connection)
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
pub fn prepare(directory: &Path, port: u16, mode: Mode) -> Result<()> {
    if port == 0 {
        return Err(Error("invalid_port"));
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|_| Error("state_directory_failed"))?;
    let state = directory.join("connection.json");
    let config = directory.join("codex.fragment.toml");
    if state.symlink_metadata().is_ok() || config.symlink_metadata().is_ok() {
        return Err(Error("setup_already_exists"));
    }
    let connection = Connection {
        local_key: random_key()?,
        port,
        mode,
    };
    let auth = match mode {
        Mode::Chatgpt => "requires_openai_auth = true",
        Mode::Openai => "env_key = \"OPENAI_API_KEY\"",
    };
    let mut fragment = format!(
        "# Экспериментальный провайдер Sanctum Rust. Содержит ЛОКАЛЬНЫЙ ключ; храните приватно.\nmodel_provider = \"sanctum_rust\"\nweb_search = \"disabled\"\n\n[model_providers.sanctum_rust]\nname = \"Sanctum Rust: локальный шлюз\"\nbase_url = \"http://127.0.0.1:{port}{}\"\nwire_api = \"responses\"\n{auth}\nsupports_websockets = false\nhttp_headers = {{ \"X-Sanctum-Key\" = \"{}\" }}\n",
        mode.prefix(),
        connection.local_key
    );
    let mut serialized =
        serde_json::to_vec_pretty(&connection).map_err(|_| Error("connection_encode_failed"))?;
    let result = (|| {
        private_write(&state, &serialized)?;
        if let Err(error) = private_write(&config, fragment.as_bytes()) {
            let _ = fs::remove_file(&state);
            return Err(error);
        }
        Ok(())
    })();
    serialized.zeroize();
    fragment.zeroize();
    result
}

pub fn package(output: &Path) -> Result<()> {
    let executable = std::env::current_exe().map_err(|_| Error("binary_location_failed"))?;
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
        for (path, contents) in [
            (
                plugin.join("plugin.json"),
                include_str!("../plugins/sanctum-rust/plugin.json"),
            ),
            (
                plugin.join(".codex-plugin/plugin.json"),
                include_str!("../plugins/sanctum-rust/.codex-plugin/plugin.json"),
            ),
            (
                plugin.join("hooks/hooks.json"),
                include_str!("../plugins/sanctum-rust/hooks/hooks.json"),
            ),
            (
                output.join(".agents/plugins/marketplace.json"),
                "{\"name\":\"sanctum-rust-dev\",\"interface\":{\"displayName\":\"Sanctum Rust\"},\"plugins\":[{\"name\":\"sanctum-rust\",\"source\":{\"source\":\"local\",\"path\":\"./plugin\"},\"policy\":{\"installation\":\"AVAILABLE\",\"authentication\":\"ON_INSTALL\"},\"category\":\"Developer Tools\"}]}\n",
            ),
        ] {
            fs::write(path, contents).map_err(|_| Error("package_write_failed"))?;
        }
        #[cfg(windows)]
        {
            let hooks = serde_json::json!({"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":r#""%CODEX_PLUGIN_ROOT%/bin/sanctum.exe" session-start"#,"timeout":5}]}]}});
            fs::write(
                plugin.join("hooks/hooks.json"),
                serde_json::to_vec_pretty(&hooks).map_err(|_| Error("package_encode_failed"))?,
            )
            .map_err(|_| Error("package_write_failed"))?;
        }
        let binary = plugin
            .join("bin")
            .join(crate::platform::executable("sanctum"));
        fs::copy(executable, &binary).map_err(|_| Error("package_binary_copy_failed"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(binary, fs::Permissions::from_mode(0o755))
                .map_err(|_| Error("package_binary_mode_failed"))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

pub fn package_prompt_guard(output: &Path) -> Result<()> {
    let executable = std::env::current_exe().map_err(|_| Error("binary_location_failed"))?;
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
        for (path, contents) in [
            (
                plugin.join(".codex-plugin/plugin.json"),
                include_str!("../plugins/sanctum-prompt-guard/.codex-plugin/plugin.json"),
            ),
            (
                plugin.join("hooks/hooks.json"),
                include_str!("../plugins/sanctum-prompt-guard/hooks/hooks.json"),
            ),
            (
                plugin.join("policy.json"),
                include_str!("../plugins/sanctum-prompt-guard/policy.json"),
            ),
            (
                output.join(".agents/plugins/marketplace.json"),
                "{\"name\":\"sanctum-guard-dev\",\"interface\":{\"displayName\":\"Sanctum: совместимость без защиты\"},\"plugins\":[{\"name\":\"sanctum-prompt-guard\",\"source\":{\"source\":\"local\",\"path\":\"./plugin\"},\"policy\":{\"installation\":\"AVAILABLE\",\"authentication\":\"ON_INSTALL\"},\"category\":\"Developer Tools\"}]}\n",
            ),
        ] {
            fs::write(path, contents).map_err(|_| Error("package_write_failed"))?;
        }
        let binary = plugin
            .join("bin")
            .join(crate::platform::executable("sanctum-guard"));
        fs::copy(executable, &binary).map_err(|_| Error("package_binary_copy_failed"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(binary, fs::Permissions::from_mode(0o755))
                .map_err(|_| Error("package_binary_mode_failed"))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
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
            output.join(".claude-plugin"),
        ] {
            fs::create_dir_all(dir).map_err(|_| Error("package_directory_failed"))?;
        }
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../plugins/sanctum-claude/.claude-plugin/plugin.json"
        ))
        .map_err(|_| Error("package_encode_failed"))?;
        let marketplace = serde_json::json!({"name":"sanctum-local","owner":{"name":"Sanctum"},
            "plugins":[{"name":"sanctum-claude","source":"./plugin","description":manifest["description"],
                "version":crate::VERSION,"category":"security"}]});
        for (path, data) in [
            (
                plugin.join("hooks/hooks.json"),
                include_str!("../plugins/sanctum-claude/hooks/hooks.json"),
            ),
            (
                plugin.join(".claude-plugin/plugin.json"),
                include_str!("../plugins/sanctum-claude/.claude-plugin/plugin.json"),
            ),
        ] {
            fs::write(path, data).map_err(|_| Error("package_write_failed"))?;
        }
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
