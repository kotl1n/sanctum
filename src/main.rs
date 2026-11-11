use clap::{Parser, Subcommand};
use sanctum::{
    Error, MAX_BODY, Result, json,
    redaction::{Redactor, restore_mapping},
    setup,
};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "sanctum",
    version,
    about = "Обратимое маскирование приватных данных в тексте"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Заменить приватные данные псевдонимами
    Redact {
        #[arg(long, help = "Файл политики распознавания")]
        policy: Option<PathBuf>,
        #[arg(long, help = "Локальный файл незашифрованных соответствий JSON")]
        vault: Option<PathBuf>,
    },

    /// Восстановить значения из локального файла соответствий
    Restore {
        #[arg(long, help = "Локальный файл незашифрованных соответствий JSON")]
        vault: PathBuf,
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
fn run(command: Command) -> Result<()> {
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
    }
    Ok(())
}
fn main() {
    if let Err(error) = run(sanctum::cli::parse::<Cli>().command) {
        eprintln!(
            "Sanctum: {}. Входные данные и учётные данные скрыты.",
            error.0
        );
        std::process::exit(1);
    }
}
