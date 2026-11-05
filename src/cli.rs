//! Русская справка CLI. Имена команд и параметры совместимы с внешними инструментами.

use clap::{Command, Parser, error::ErrorKind};

fn localized(command: Command) -> Command {
    let mut command = command
        .subcommand_help_heading("Команды")
        .subcommand_value_name("КОМАНДА")
        .help_template("{about-with-newline}\nИспользование: {usage}\n\n{all-args}");
    command.build();
    command
        .mut_args(|arg| {
            let arg = match arg.get_id().as_str() {
                "help" => arg.help("Показать справку"),
                "version" => arg.help("Показать версию"),
                _ => arg,
            };
            arg.help_heading("Параметры")
        })
        .mut_subcommands(|command| {
            if command.get_name() == "help" {
                command.about("Показать справку по команде")
            } else {
                localized(command)
            }
        })
}

fn help_text(text: &str) -> String {
    text.replace("[OPTIONS]", "[ПАРАМЕТРЫ]")
        .replace("[COMMAND]", "[КОМАНДА]")
        .replace("[default:", "[по умолчанию:")
        .replace("[possible values:", "[допустимые значения:")
}

pub fn parse<T: Parser>() -> T {
    let command = localized(T::command());
    let name = command.get_name().to_owned();
    let matches = command.try_get_matches().unwrap_or_else(|error| {
        match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                print!("{}", help_text(&error.to_string()));
                std::process::exit(0);
            }
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                eprint!("{}", help_text(&error.to_string()));
            }
            _ => {
                eprintln!("Ошибка в аргументах. Справка: {name} --help.");
            }
        }
        std::process::exit(2);
    });
    T::from_arg_matches(&matches).unwrap_or_else(|_| {
        eprintln!("Ошибка в аргументах. Справка: {name} --help.");
        std::process::exit(2);
    })
}
