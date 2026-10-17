//! Executable selected by CODEX_CLI_PATH. Only app-server stdio is filtered.
use sanctum::{Error, Result, setup, vault::Vault};
use std::{ffi::OsString, path::PathBuf};

async fn run() -> Result<i32> {
    let executable = std::env::var_os("SANCTUM_REAL_CODEX")
        .map(PathBuf::from)
        .ok_or(Error("real_codex_path_required"))?;
    if !executable.is_absolute()
        || std::fs::canonicalize(&executable).ok() == std::env::current_exe().ok()
    {
        return Err(Error("invalid_codex_path"));
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|s| s == "app-server") {
        if args.iter().any(|s| s == "daemon" || s == "proxy") {
            return Err(Error("stdio_transport_required"));
        }
        if args.iter().any(|s| {
            s == "generate-ts" || s == "generate-json-schema" || s == "--help" || s == "-h"
        }) {
            let status = tokio::process::Command::new(executable)
                .args(args)
                .status()
                .await
                .map_err(|_| Error("backend_start_failed"))?;
            return Ok(status.code().unwrap_or(1));
        }
        let policy = std::env::var_os("SANCTUM_GUARD_POLICY").map(PathBuf::from);
        sanctum::bridge::run(
            &executable,
            &args,
            Vault::default_directory()?,
            setup::load_policy(policy.as_deref())?,
        )
        .await
    } else {
        // Native code-mode helpers, --version and other CLI invocations retain
        // their original pipes. Interactive CLI prompts are NOT protected here.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let _ = std::process::Command::new(executable)
                .args(args)
                .env_remove("CODEX_CLI_PATH")
                .exec();
            Err(Error("backend_start_failed"))
        }
        #[cfg(not(unix))]
        {
            Err(Error("portless_platform_unsupported"))
        }
    }
}
#[tokio::main]
async fn main() {
    match run().await {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Sanctum: {}. Content omitted.", error.0);
            std::process::exit(1);
        }
    }
}
