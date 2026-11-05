# Windows x64

Поддержка Windows добавлена как экспериментальная. Движок, шифрованное хранилище, установщик, запускатель и средства сборки учитывают особенности Windows. Полный сеанс Desktop требует отдельной проверки конкретной официальной Windows-сборки. Профиль Linux для неё не подходит. Реальная интеграция Codex Desktop и задания MSVC в GitHub Actions ещё не проверены; результаты нативного прогона Windows GNU и Wine учитываются отдельно.

## Что изменено

- Исполняемые файлы имеют расширение `.exe`; домашний каталог определяется через `USERPROFILE`.
- Ключ хранилища дополнительно защищён DPAPI текущего пользователя. DACL ограничивает доступ владельцем и SYSTEM. Junction, reparse points и жёсткие ссылки на файлы хранилища отклоняются.
- Блокировки установщика используют Windows API через `msvcrt`. Права и синхронизация файлов учитывают различия ОС; установка, удаление и откат сохраняют журнал транзакций.
- Запускатель состоит из `.cmd` и PowerShell-файла с UTF-8 BOM. Пути с пробелами, кириллицей и апострофами передаются как данные. Системная политика PowerShell не изменяется: параметры действуют только на процесс запускателя.
- Адаптер передаёт код завершения дочернего процесса. Локальные команды поддерживают PowerShell, pwsh и cmd; дерево процессов ограничивается Windows Job Object.
- Вывод локальных инструментов должен быть UTF-8. Для PowerShell эта кодировка задаётся при запуске; программы с OEM-выводом через cmd требуют собственной настройки кодировки. Некорректный UTF-8 отклоняется.
- Значения с расширением переменных оболочки не восстанавливаются в исходный код. Для сложных значений используйте структурированные аргументы локальных инструментов.

Не переносите хранилище и ключ между Linux и Windows. На Windows ключ привязан DPAPI к учётной записи и её системному профилю. Не удаляйте рабочее хранилище ради обновления: для миграции пока нет автоматического инструмента.

## Сборка движка

Нужны Windows 10/11 x64, Rust 1.88+, Python 3.11+ и Git. Для MSVC установите C++ Build Tools, для теста запускателя — Node.js 22+. В PowerShell:

```powershell
cargo test --locked --all-targets --jobs 2
python -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/composer-host.test.cjs
python scripts/build_release.py --jobs 2
```

В `target/release/` появятся `sanctum.exe`, `sanctum-guard.exe` и `sanctum-codex.exe`. Это ещё не готовая интеграция Desktop: ей нужны закреплённая нативная серверная часть и профиль компонентов Windows.

## Профиль Desktop и полный комплект

Нужны настоящие файлы официальной Windows-сборки Desktop: исполняемый файл приложения, `app.asar`, Node, Codex и code-mode-host. Используйте физические файлы пакета, а не системные псевдонимы запуска приложений. Относительные пути задавайте с разделителем `/`.

Сначала создайте отпечаток. Значения ниже — пример структуры, а не утверждение о расположении файлов вашей сборки:

```powershell
$desktopRoot = 'C:/DesktopPackage'
python scripts/desktop_profile.py --desktop-root $desktopRoot --desktop-version ВЕРСИЯ `
  --app 'ChatGPT.exe' --archive 'resources/app.asar' --node 'resources/node.exe' `
  --codex 'resources/codex.exe' --code-mode-host 'resources/codex-code-mode-host.exe' `
  --output target/windows-candidate.json
```

Проверьте происхождение пакета, его версию, состав и соответствие Codex закреплённой версии 0.159.0. После этой проверки повторите команду с `--reviewed` и новым выходным файлом `target/windows-profile.json`. Этот флаг подтверждает проверку компонентов, но не успешность настоящего сеанса Desktop. Автоматически доверять произвольной установленной сборке нельзя.

```powershell
python scripts/build_native_backend.py --profile target/windows-profile.json `
  --code-mode-host "$desktopRoot/resources/codex-code-mode-host.exe" `
  --output dist/sanctum-context-backend-windows
python scripts/package_release.py --profile target/windows-profile.json `
  --backend dist/sanctum-context-backend-windows --output dist/sanctum-windows
python dist/sanctum-windows/install.py install --bundle dist/sanctum-windows --desktop-root $desktopRoot
python dist/sanctum-windows/install.py install --bundle dist/sanctum-windows --desktop-root $desktopRoot --apply
```

Сборке upstream нужны Rust 1.95+ и его собственные инструменты сборки для Windows. Упаковщик проверяет патч, коммит, протокол, контрольные суммы и соответствующие исходники. Он не подменяет Linux-сборку Windows-именами и не загружает непроверенную серверную часть.

Установите `plugin/` из комплекта средствами Desktop, проверьте и разрешите хуки. Затем выполните `check` и `enable --apply` установленным `ui/manage_backend.py`. Запускайте приложение через `%USERPROFILE%/.local/bin/sanctum-desktop.cmd`. После обновления полностью перезапустите Desktop. Удаление и откат выполняются командами установщика из README.

До объявления стабильной поддержки выполните все ручные сценарии из [проверки релиза](RELEASE.md): настоящий запрос с синтетическими данными, подсветку, восстановление аргументов, сжатие истории, перезапуск, удаление и откат. Проверенного готового профиля настоящей Windows-сборки в репозитории пока нет.

## Проверка на настоящей Windows

В VirtualBox на Windows 11 Enterprise Eval 10.0.26300.9457 пройдены 56 тестов Rust из исполняемых файлов Windows GNU, 22 теста Python, 5 тестов Node и проверка синтаксиса JavaScript. Отдельно проверены системный PowerShell по умолчанию, вывод UTF-8, кириллица, пробелы, апостроф и псевдоним в рабочем каталоге и имени файла, а также передача кода завершения 7.

Полная сборка и запуск закреплённой нативной серверной части на Windows и реальная интеграция Codex Desktop остаются непроверенными. Этот прогон не подтверждает MSVC или результаты GitHub Actions.

## Проверки через Docker

На Linux с Docker:

```sh
python3 scripts/test_windows_docker.py
```

Скрипт передаёт в контейнер только текущие архивируемые исходники, включая незакоммиченные изменения. Домашний каталог, Git-история, аккаунты, локальные ключи и хранилища не монтируются. Контейнер содержит Rust 1.88, MinGW, актуальный Wine из официального WineHQ-репозитория, Windows Python и Windows Git; локаль UTF-8 позволяет проверять кириллические пути. В нём выполняются Clippy для Windows, Windows `.exe` тестов Rust, тесты установщика/упаковки под Windows Python и оптимизированная сборка движка. Для отдельного демона поддерживаются `--docker`, `--host` и `--network`; готовый образ можно выбрать через `--image` и повторно использовать с `--skip-build`.

Wine проверяет Windows API в Linux, а не настоящее ядро Windows, Defender, MSVC или графический сеанс Desktop. Для проверки на Windows добавлены задания в [GitHub Actions](../.github/workflows/windows.yml): тесты движка и установщика, релизная сборка Sanctum и `cargo check` закреплённого нативного патча. Последнее не заменяет полную сборку нативной серверной части. Результат этих заданий появится только после запуска CI на GitHub; графический сеанс Desktop проверяется вручную.

Обычный Linux-контейнер Docker также не проверяет macOS. Для настоящих проверок macOS нужен Mac либо macOS-runner в CI; контейнер с QEMU был бы виртуальной машиной и не заменял бы проверку на поддерживаемом Apple-оборудовании. Поддержка macOS в этой работе не добавлялась.
