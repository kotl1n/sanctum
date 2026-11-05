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
    about = "Локальный шлюз защиты текста и нативный компаньон Codex"
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

    /// Создать файлы подключения экспериментального HTTP-шлюза
    Prepare {
        #[arg(long, help = "Каталог файлов подключения")]
        directory: Option<PathBuf>,
        #[arg(long, default_value_t = 47631, help = "Локальный TCP-порт")]
        port: u16,
        #[arg(long, value_enum, default_value_t = Mode::Chatgpt, help = "Режим авторизации шлюза")]
        mode: Mode,
    },

    /// Запустить экспериментальный локальный HTTP-шлюз
    Serve {
        #[arg(long, help = "Приватный файл подключения")]
        connection: Option<PathBuf>,
        #[arg(long, help = "Файл политики распознавания")]
        policy: Option<PathBuf>,
        #[arg(long, help = "Отключить восстановление аргументов инструментов")]
        no_restore_tools: bool,
    },

    /// Создать пакет Rust-компаньона
    Package {
        #[arg(
            long,
            default_value = "dist/sanctum-rust",
            help = "Новый каталог для пакета"
        )]
        output: PathBuf,
    },

    /// Обработать начало сеанса Rust-компаньона
    SessionStart,
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
                "Приватные файлы подключения созданы в {}. Настройки Codex не изменены.",
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
                "Sanctum Rust: локальный адрес 127.0.0.1:{}; режим={}; только текст; восстановление аргументов={}",
                connection.port,
                connection.mode.label(),
                !no_restore_tools
            );
            sanctum::gateway::serve(listener, settings).await?;
        }
        Command::Package { output } => {
            setup::package(&output)?;
            println!("Пакет нативного плагина создан в {}", output.display());
        }
        Command::SessionStart => {
            let mut input = stdin_text()?;
            input.zeroize();
            print_json(
                &value!({"systemMessage":"Компаньон Sanctum Rust загружен. Для защиты требуется отдельно настроенный и проверенный локальный шлюз.","hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"If the Sanctum gateway is active, identifiers such as [IP-1], [EMAIL-1], and [SECRET-1] are local privacy placeholders. Preserve them exactly in tool arguments. The gateway restores supported local tool arguments. Do not guess originals, encode placeholders, or read Sanctum connection files, vaults or process memory. Use structured local tool arguments for complex secrets. Text-only mode rejects attachments and hosted tools. Companion installation does not prove traffic is routed through the gateway."}}),
            )?;
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(error) = run(sanctum::cli::parse::<Cli>().command).await {
        eprintln!(
            "Sanctum: {}. Входные данные и учётные данные скрыты.",
            error.0
        );
        std::process::exit(1);
    }
}
