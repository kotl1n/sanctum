use clap::{Parser, Subcommand};
use sanctum::{
    Error, MAX_BODY, Result,
    gateway::{Mode, Settings},
    json,
    redaction::{Redactor, restore_mapping},
    setup,
};
use serde_json::{Value, json as value};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "sanctum",
    version,
    about = "Local text privacy gateway and native Codex companion"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Read stdin and mask locally. A vault is saved only if explicitly requested.
    Redact {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Restore stdin locally using an explicitly saved PLAINTEXT vault.
    Restore {
        #[arg(long)]
        vault: PathBuf,
    },
    /// Create private connection files without editing Codex settings.
    Prepare {
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(long, default_value_t = 47631)]
        port: u16,
        #[arg(long, value_enum, default_value_t = Mode::Chatgpt)]
        mode: Mode,
    },
    /// Serve on 127.0.0.1. No remote bind or arbitrary upstream option exists.
    Serve {
        #[arg(long)]
        connection: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        no_restore_tools: bool,
    },
    /// Package this binary with plugin manifests, native hook and local marketplace.
    Package {
        #[arg(long, default_value = "dist/sanctum-rust")]
        output: PathBuf,
    },
    /// Fully offline synthetic gateway, tool execution and follow-up demonstration.
    Demo,
    /// Native SessionStart hook, used by the plugin.
    SessionStart,
    /// Optional blocking UserPromptSubmit hook; not enabled by the plugin.
    PromptGuard {
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}
fn stdin_text() -> Result<String> {
    let mut buffer = Vec::new();
    io::stdin()
        .take((MAX_BODY + 1) as u64)
        .read_to_end(&mut buffer)
        .map_err(|_| Error("stdin_read_failed"))?;
    if buffer.len() > MAX_BODY {
        return Err(Error("input_size_limit"));
    }
    String::from_utf8(buffer).map_err(|_| Error("utf8_required"))
}
fn print_json(data: &Value) -> Result<()> {
    let encoded = json::encode(data)?;
    let mut output = io::stdout().lock();
    output
        .write_all(&encoded)
        .and_then(|_| output.write_all(b"\n"))
        .map_err(|_| Error("stdout_write_failed"))
}
async fn run(command: Command) -> Result<()> {
    match command {
        Command::Redact { policy, vault } => {
            let mut engine = Redactor::new(setup::load_policy(policy.as_deref())?)?;
            let mut text = stdin_text()?;
            let first = engine.text(&text)?;
            let safe = engine.text(&first)?;
            text.zeroize();
            if let Some(path) = vault {
                let mut encoded = json::encode(&engine.export())?;
                let result = setup::private_write(&path, &encoded);
                encoded.zeroize();
                result?;
            }
            io::stdout()
                .write_all(safe.as_bytes())
                .map_err(|_| Error("stdout_write_failed"))?;
        }
        Command::Restore { vault } => {
            let mut raw = std::fs::read(vault).map_err(|_| Error("vault_read_failed"))?;
            if raw.len() > MAX_BODY {
                raw.zeroize();
                return Err(Error("vault_size_limit"));
            }
            let parsed = json::parse(&raw);
            raw.zeroize();
            let restored = restore_mapping(&stdin_text()?, &parsed?)?;
            io::stdout()
                .write_all(restored.as_bytes())
                .map_err(|_| Error("stdout_write_failed"))?;
        }
        Command::Prepare {
            directory,
            port,
            mode,
        } => {
            let directory = directory.map(Ok).unwrap_or_else(setup::default_directory)?;
            setup::prepare(&directory, port, mode)?;
            println!(
                "Created private connection files in {}. Codex settings have not been changed.",
                directory.display()
            );
        }
        Command::Serve {
            connection,
            policy,
            no_restore_tools,
        } => {
            let path = connection
                .map(Ok)
                .unwrap_or_else(|| setup::default_directory().map(|p| p.join("connection.json")))?;
            let connection = setup::load_connection(&path)?;
            let settings = Settings::new(
                connection.local_key.clone(),
                connection.mode,
                setup::load_policy(policy.as_deref())?,
                !no_restore_tools,
            )?;
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, connection.port))
                    .await
                    .map_err(|_| Error("loopback_bind_failed"))?;
            println!(
                "Sanctum Rust listening on 127.0.0.1:{}; mode={}; text-only; tool restoration={}",
                connection.port,
                connection.mode.label(),
                !no_restore_tools
            );
            sanctum::gateway::serve(listener, settings).await?;
        }
        Command::Package { output } => {
            setup::package(&output)?;
            println!("Native plugin package created in {}", output.display());
        }
        Command::Demo => sanctum::demo::run().await?,
        Command::SessionStart => {
            // Consume input without ever emitting it as context or diagnostics.
            let mut input = stdin_text()?;
            input.zeroize();
            print_json(
                &value!({"systemMessage":"Sanctum Rust companion loaded. Protection requires a separately configured and verified local gateway.","hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"If the Sanctum gateway is active, identifiers such as [IP-1], [EMAIL-1], and [SECRET-1] are local privacy placeholders. Preserve them exactly in tool arguments. The gateway restores supported local tool arguments. Do not guess originals, encode placeholders, or read Sanctum connection files, vaults or process memory. Use structured local tool arguments for complex secrets. Text-only mode rejects attachments and hosted tools. Companion installation does not prove traffic is routed through the gateway."}}),
            )?;
        }
        Command::PromptGuard { policy } => {
            let inspect = || -> Result<bool> {
                let payload = json::parse(stdin_text()?.as_bytes())?;
                if payload["hook_event_name"] != "UserPromptSubmit" {
                    return Err(Error("unexpected_hook"));
                }
                let prompt = payload["prompt"].as_str().ok_or(Error("prompt_required"))?;
                let mut engine = Redactor::new(setup::load_policy(policy.as_deref())?)?;
                engine.text(prompt)?;
                Ok(engine.has_secrets())
            };
            match inspect() {
                Ok(false) => {}
                Ok(true) => print_json(
                    &value!({"decision":"block","reason":"Sanctum detected sensitive text. Configure the local gateway or sanitize locally; original content omitted."}),
                )?,
                Err(_) => print_json(
                    &value!({"decision":"block","reason":"Sanctum could not inspect this prompt. Request blocked; content omitted."}),
                )?,
            }
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse().command).await {
        eprintln!("Sanctum: {}. Input and credentials omitted.", error.0);
        std::process::exit(1);
    }
}
