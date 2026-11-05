use clap::{Parser, Subcommand};
use sanctum::{Error, MAX_BODY, Result, json, prompt_guard, setup};
use serde_json::json as value;
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name="sanctum-guard", version=prompt_guard::PLUGIN_VERSION, about="Локальное маскирование текста, настройки и обработчики событий без сетевого порта.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Проверить текст без сохранения соответствий
    Preview {
        #[arg(long, help = "Файл политики распознавания")]
        policy: Option<PathBuf>,
    },

    /// Просмотреть или изменить настройки защиты
    Settings {
        #[arg(long, help = "Включить или выключить защиту: true или false")]
        enabled: Option<bool>,
        #[arg(long, help = "Файл настроек")]
        file: Option<PathBuf>,
    },

    /// Обработать запрос нативной серверной части к модели
    ModelRequest,

    /// Сохранить элемент ответа для воспроизведения истории
    ProviderItem,

    /// Создать устаревший пакет совместимости без защиты
    Package {
        #[arg(
            long,
            default_value = "dist/sanctum-prompt-guard",
            help = "Новый каталог для пакета"
        )]
        output: PathBuf,
    },

    /// Обработать событие локального инструмента
    Hook {
        #[arg(long, help = "Файл политики распознавания")]
        policy: Option<PathBuf>,
        #[arg(long, help = "Каталог зашифрованного состояния")]
        state_directory: Option<PathBuf>,
    },

    /// Замаскировать текст в указанном сеансе
    Mask {
        #[arg(long, help = "Идентификатор сеанса")]
        session: String,
        #[arg(long, help = "Файл политики распознавания")]
        policy: Option<PathBuf>,
        #[arg(long, help = "Каталог зашифрованного состояния")]
        state_directory: Option<PathBuf>,
    },

    /// Удалить локальные соответствия сеанса
    Forget {
        #[arg(long, help = "Идентификатор сеанса")]
        session: String,
        #[arg(long, help = "Каталог зашифрованного состояния")]
        state_directory: Option<PathBuf>,
    },

    #[command(name = "run-command")]
    /// Выполнить локальную команду с восстановлением аргументов
    RunLocal {
        #[arg(long, help = "Идентификатор сеанса")]
        session: String,
        #[arg(long, help = "Команда в формате hex")]
        command_hex: String,
        #[arg(long, help = "Файл политики распознавания")]
        policy: Option<PathBuf>,
        #[arg(long, help = "Путь к командной оболочке")]
        shell: Option<String>,
        #[arg(long, help = "Запустить оболочку в режиме входа")]
        login: bool,
        #[arg(long, help = "Рабочий каталог в формате hex")]
        cwd_hex: Option<String>,
    },
    /// Создать пакет интеграции Desktop
    PackagePortless {
        #[arg(
            long,
            default_value = "dist/sanctum-portless",
            help = "Новый каталог для пакета"
        )]
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
        Command::Preview { policy } => {
            let raw = input()?;
            let text = std::str::from_utf8(&raw).map_err(|_| Error("utf8_required"))?;
            let path = std::env::var_os("SANCTUM_GUARD_POLICY")
                .map(PathBuf::from)
                .or(policy);
            print_json(&sanctum::preview::inspect(
                text,
                setup::load_policy(path.as_deref()),
                sanctum::settings::active(),
            ))?;
        }
        Command::Settings { enabled, file } => {
            let path = file.map(Ok).unwrap_or_else(sanctum::settings::path)?;
            let mut settings = sanctum::settings::Settings::load(&path)
                .unwrap_or(sanctum::settings::Settings { enabled: false });
            if let Some(value) = enabled {
                settings.enabled = value;
            }
            if enabled.is_some() {
                settings.save(&path)?;
            }
            print_json(
                &value!({"enabled":settings.enabled,"active":settings.active(),
                    "mode":if std::env::var_os("SANCTUM_CONTEXT_PROTECTION").is_some_and(|v|v=="1") {"context"} else {"rewrite"}}),
            )?;
        }
        Command::ModelRequest | Command::ProviderItem => {
            let raw = input()?;
            let envelope = json::parse(&raw)?;
            let active = sanctum::settings::try_active().unwrap_or(true);
            if !active || matches!(command, Command::ProviderItem) {
                if matches!(command, Command::ProviderItem) {
                    let mut recorded = false;
                    if active && envelope["request_id"].as_str().is_some() {
                        let path = std::env::var_os("SANCTUM_GUARD_POLICY").map(PathBuf::from);
                        if let (Ok(policy), Ok(vault)) = (
                            setup::load_policy(path.as_deref()),
                            sanctum::vault::Vault::default_directory()
                                .and_then(sanctum::vault::Vault::new),
                        ) {
                            recorded =
                                sanctum::model_boundary::record_provider(&envelope, policy, &vault)
                                    .is_ok();
                        }
                    }
                    print_json(
                        &value!({"protocol":sanctum::model_boundary::PROTOCOL,"session_id":envelope["session_id"],"recorded":recorded}),
                    )?;
                } else {
                    let rewriter = sanctum::rewrite::Rewriter::new(None, Default::default());
                    print_json(&sanctum::model_boundary::rewrite(
                        &envelope, false, &rewriter,
                    )?)?;
                }
                return Ok(());
            }
            let path = std::env::var_os("SANCTUM_GUARD_POLICY").map(PathBuf::from);
            let policy = setup::load_policy(path.as_deref());
            let valid = policy.is_ok();
            let vault = sanctum::vault::Vault::default_directory()
                .and_then(sanctum::vault::Vault::new)
                .ok();
            let storage_available = vault.is_some();
            let mut rewriter = sanctum::rewrite::Rewriter::new(vault, policy.unwrap_or_default());
            if !valid || !storage_available {
                rewriter = rewriter.with_unavailable_policy();
            }
            let result = sanctum::model_boundary::rewrite(&envelope, true, &rewriter)?;
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

            if !sanctum::settings::active()
                || !event.as_ref().is_some_and(|e| {
                    matches!(
                        e["hook_event_name"].as_str(),
                        Some("PreToolUse" | "PostToolUse")
                    )
                })
            {
                return Ok(());
            }
            let operation = || -> Result<Option<serde_json::Value>> {
                let event = event.as_ref().ok_or(Error("invalid_hook"))?;
                let path = std::env::var_os("SANCTUM_GUARD_POLICY")
                    .map(PathBuf::from)
                    .or(policy);
                let policy = setup::load_policy(path.as_deref())?;
                if std::env::var_os("SANCTUM_PORTLESS_ACTIVE").as_deref()
                    != Some(std::ffi::OsStr::new("1"))
                {
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
            println!("Соответствия сеанса удалены с устройства.");
        }
        Command::PackagePortless { output } => {
            setup::package_portless(&output)?;
            println!("Пакет интеграции Desktop создан в {}", output.display());
        }
        Command::Package { output } => {
            setup::package_prompt_guard(&output)?;
            println!("Пакет совместимости создан в {}", output.display());
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run(sanctum::cli::parse::<Cli>().command) {
        eprintln!(
            "Sanctum Guard: {}. Входные данные и учётные данные скрыты.",
            error.0
        );
        std::process::exit(1);
    }
}
