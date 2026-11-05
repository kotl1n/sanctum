use sanctum::{Error, Result};
use std::{ffi::OsString, path::PathBuf};

fn backend_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("SANCTUM_BACKEND_ROUTE") {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| Error("backend_route_unavailable"))?
            .take(256_001)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("backend_route_unavailable"))?;
        if bytes.len() > 256_000 {
            return Err(Error("backend_route_invalid"));
        }
        let route = sanctum::json::parse(&bytes)?;
        if route["mode"] != "context" {
            return Err(Error("backend_route_invalid"));
        }
        return route["path"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .ok_or(Error("backend_route_invalid"));
    }
    std::env::var_os("SANCTUM_REAL_CODEX")
        .map(PathBuf::from)
        .ok_or(Error("real_codex_path_required"))
}

async fn run() -> Result<i32> {
    let executable = backend_path()?;
    if !executable.is_absolute()
        || std::fs::canonicalize(&executable).ok() == std::env::current_exe().ok()
    {
        return Err(Error("invalid_codex_path"));
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if !sanctum::settings::try_active()? {
        return passthrough(executable, args);
    }
    if let Some(server_args) = sanctum::rewrite::app_server_args(&args) {
        if server_args.iter().any(|s| s == "daemon" || s == "proxy") {
            return Err(Error("stdio_transport_required"));
        }
        for (index, arg) in server_args.iter().enumerate() {
            let text = arg.to_string_lossy();
            if (arg == "--listen"
                && server_args
                    .get(index + 1)
                    .is_none_or(|v| v != "stdio://" && v != "stdio"))
                || (text.starts_with("--listen=")
                    && text != "--listen=stdio://"
                    && text != "--listen=stdio")
            {
                return Err(Error("stdio_transport_required"));
            }
        }
        if server_args.iter().any(|s| {
            s == "--code-mode-host" || s.to_string_lossy().starts_with("--code-mode-host=")
        }) {
            return Err(Error("local_code_mode_host_required"));
        }
        if server_args.iter().any(|s| {
            s == "generate-ts" || s == "generate-json-schema" || s == "--help" || s == "-h"
        }) {
            let status = tokio::process::Command::new(executable)
                .args(args)
                .status()
                .await
                .map_err(|_| Error("backend_start_failed"))?;
            return Ok(status.code().unwrap_or(1));
        }
        sanctum::rewrite::run(&executable, &args).await
    } else {
        passthrough(executable, args)
    }
}
fn passthrough(executable: PathBuf, args: Vec<OsString>) -> Result<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let _ = std::process::Command::new(executable)
            .args(args)
            .env_remove("CODEX_CLI_PATH")
            .env_remove("SANCTUM_NATIVE_REQUIRED")
            .env_remove("SANCTUM_NATIVE_HELPER")
            .env_remove("SANCTUM_PORTLESS_ACTIVE")
            .env_remove("SANCTUM_CONTEXT_PROTECTION")
            .exec();
        Err(Error("backend_start_failed"))
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(executable)
            .args(args)
            .env_remove("CODEX_CLI_PATH")
            .env_remove("SANCTUM_NATIVE_REQUIRED")
            .env_remove("SANCTUM_NATIVE_HELPER")
            .env_remove("SANCTUM_PORTLESS_ACTIVE")
            .env_remove("SANCTUM_CONTEXT_PROTECTION")
            .status()
            .map_err(|_| Error("backend_start_failed"))?;
        Ok(status.code().unwrap_or(1))
    }
}
#[tokio::main]
async fn main() {
    match run().await {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Sanctum: {}. Содержимое скрыто.", error.0);
            std::process::exit(1);
        }
    }
}
