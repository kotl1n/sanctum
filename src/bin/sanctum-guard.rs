use clap::{Parser, Subcommand};
use sanctum::{Error, MAX_BODY, Result, json, prompt_guard, setup};
use serde_json::json as value;
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name="sanctum-guard", version=prompt_guard::PLUGIN_VERSION, about="Local Codex prompt check at submit time. No server or model-provider changes.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Filter a complete native model request over stdin/stdout. No listener.
    ModelRequest,
    /// Record a reasoning block observed directly in a provider response.
    ProviderItem,
    /// Read a UserPromptSubmit JSON event from stdin; return a blocking decision if needed.
    Check {
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Package this native checker as a standalone Codex plugin.
    Package {
        #[arg(long, default_value = "dist/sanctum-prompt-guard")]
        output: PathBuf,
    },
    /// Inspect only hardcoded synthetic examples locally, without Codex or networking.
    Demo,
    /// Portless tool hooks (used by the separate enhanced plugin).
    Hook {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        state_directory: Option<PathBuf>,
    },
    /// Mask stdin and save encrypted per-session correspondences locally.
    Mask {
        #[arg(long)]
        session: String,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        state_directory: Option<PathBuf>,
    },
    /// Delete the encrypted mapping for one session.
    Forget {
        #[arg(long)]
        session: String,
        #[arg(long)]
        state_directory: Option<PathBuf>,
    },
    /// Package the portless stdio adapter and tool hooks together.
    /// Internal local shell runner; returns only masked stdout/stderr.
    #[command(name = "run-command")]
    RunLocal {
        #[arg(long)]
        session: String,
        #[arg(long)]
        command_hex: String,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        shell: Option<String>,
        #[arg(long)]
        login: bool,
        #[arg(long)]
        cwd_hex: Option<String>,
    },
    PackagePortless {
        #[arg(long, default_value = "dist/sanctum-portless")]
        output: PathBuf,
    },
}
fn input() -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    io::stdin()
        .take((MAX_BODY + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("stdin_read_failed"))?;
    if bytes.len() > MAX_BODY {
        return Err(Error("hook_input_limit"));
    }
    Ok(bytes)
}
fn print_json(value: &serde_json::Value) -> Result<()> {
    let encoded = json::encode(value)?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&encoded)
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|_| Error("stdout_write_failed"))
}
fn run(command: Command) -> Result<()> {
    match command {
        Command::ModelRequest | Command::ProviderItem => {
            let raw = input()?;
            let envelope = json::parse(&raw)?;
            let path = std::env::var_os("SANCTUM_GUARD_POLICY").map(PathBuf::from);
            let policy = setup::load_policy(path.as_deref())?;
            let vault = sanctum::vault::Vault::new(sanctum::vault::Vault::default_directory()?)?;
            let result = match command {
                Command::ModelRequest => sanctum::model_boundary::filter(&envelope, policy, &vault),
                Command::ProviderItem => {
                    sanctum::model_boundary::record_provider(&envelope, policy, &vault)
                }
                _ => unreachable!(),
            }?;
            print_json(&result)?;
        }
        Command::RunLocal {
            session,
            command_hex,
            policy,
            shell,
            login,
            cwd_hex,
        } => {
            let policy = std::env::var_os("SANCTUM_GUARD_POLICY")
                .map(PathBuf::from)
                .or(policy);
            let vault = sanctum::vault::Vault::new(sanctum::vault::Vault::default_directory()?)?;
            let code = sanctum::local_command::run_with_options(
                &vault,
                &session,
                setup::load_policy(policy.as_deref())?,
                &command_hex,
                shell.as_deref(),
                login,
                cwd_hex.as_deref(),
            )?;
            std::process::exit(code);
        }
        Command::Hook {
            policy,
            state_directory,
        } => {
            let raw = input();
            let event = raw.as_ref().ok().and_then(|s| json::parse(s).ok());
            let operation = || -> Result<Option<serde_json::Value>> {
                let event = event.as_ref().ok_or(Error("invalid_hook"))?;
                let path = std::env::var_os("SANCTUM_GUARD_POLICY")
                    .map(PathBuf::from)
                    .or(policy);
                let policy = setup::load_policy(path.as_deref())?;
                if std::env::var_os("SANCTUM_PORTLESS_ACTIVE").as_deref()
                    != Some(std::ffi::OsStr::new("1"))
                {
                    if event["hook_event_name"] == "UserPromptSubmit" {
                        return Ok(prompt_guard::decision(prompt_guard::inspect_hook(
                            raw.as_ref().map_err(|_| Error("invalid_hook"))?,
                            policy,
                        )));
                    }
                    return Ok(None);
                }
                let vault = sanctum::vault::Vault::new(
                    state_directory
                        .map(Ok)
                        .unwrap_or_else(sanctum::vault::Vault::default_directory)?,
                )?;
                sanctum::tool_guard::handle_with_policy_path(event, policy, &vault, path.as_deref())
            };
            match operation() {
                Ok(Some(value)) => print_json(&value)?,
                Ok(None) => {}
                Err(_) => print_json(&sanctum::tool_guard::failure(event.as_ref()))?,
            }
        }
        Command::Mask {
            session,
            policy,
            state_directory,
        } => {
            let vault = sanctum::vault::Vault::new(
                state_directory
                    .map(Ok)
                    .unwrap_or_else(sanctum::vault::Vault::default_directory)?,
            )?;
            let raw = input()?;
            let text = std::str::from_utf8(&raw).map_err(|_| Error("utf8_required"))?;
            let safe = vault.mask(
                &session,
                setup::load_policy(policy.as_deref())?,
                &serde_json::Value::String(text.into()),
            )?;
            io::stdout()
                .write_all(safe.as_str().ok_or(Error("text_required"))?.as_bytes())
                .map_err(|_| Error("stdout_write_failed"))?;
        }
        Command::Forget {
            session,
            state_directory,
        } => {
            sanctum::vault::Vault::new(
                state_directory
                    .map(Ok)
                    .unwrap_or_else(sanctum::vault::Vault::default_directory)?,
            )?
            .forget(&session)?;
            println!("Session mapping deleted locally.");
        }
        Command::PackagePortless { output } => {
            setup::package_portless(&output)?;
            println!("Portless package created in {}", output.display());
        }
        Command::Check { policy } => {
            // Any inspection failure is a successful hook invocation returning
            // decision:block, not an exit-1 hook failure the runtime may ignore.
            let inspect = || -> Result<prompt_guard::Findings> {
                let path = std::env::var_os("SANCTUM_GUARD_POLICY")
                    .map(PathBuf::from)
                    .or(policy);
                let policy = setup::load_policy(path.as_deref())?;
                prompt_guard::inspect_hook(&input()?, policy)
            };
            if let Some(decision) = prompt_guard::decision(inspect()) {
                print_json(&decision)?;
            }
        }
        Command::Package { output } => {
            setup::package_prompt_guard(&output)?;
            println!("Standalone prompt guard created in {}", output.display());
        }
        Command::Demo => {
            for (name, prompt) in [
                ("clean", "Explain ownership in Rust"),
                ("ip", "Check server 11.111.111.11"),
                ("email", "Contact demo@example.com"),
                ("password", "password=synthetic-only"),
            ] {
                let findings = prompt_guard::inspect(prompt, Default::default())?;
                print_json(
                    &value!({"example":name,"decision":if findings.blocked() {"block"} else {"allow"},"types":findings.0.iter().map(|(kind, _)| kind).collect::<Vec<_>>()}),
                )?;
            }
            println!(
                "PASS: standalone local checks; no server, provider credential or Codex process used."
            );
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run(Cli::parse().command) {
        eprintln!("Sanctum Guard: {}. Input and credentials omitted.", error.0);
        std::process::exit(1);
    }
}
