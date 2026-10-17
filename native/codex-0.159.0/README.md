# Локальная сборка Codex для Sanctum

Upstream: OpenAI Codex `rust-v0.159.0`, commit
`687a119f0fcaace47e1f1abcc77cec6c813fd6da`.

Обычный плагин не получает окончательный запрос модели. Этот небольшой патч
добавляет проверку в HTTP-клиент backend **до сжатия и подписи** запроса.
Проверка вызывает `sanctum-guard model-request` через stdin/stdout, без
TCP/UDP-listener. Путь helper должен быть абсолютным. Если включён
`SANCTUM_NATIVE_REQUIRED`, отсутствие helper или любая ошибка проверки блокирует
отправку. Ограничения: 8 MiB, 15 секунд на вызов.

Режим активируется только переменными `SANCTUM_NATIVE_REQUIRED=1` и
`SANCTUM_NATIVE_HELPER=/absolute/path/to/sanctum-guard`. Stdio-адаптер проверяет
приватный протокол `--sanctum-native-protocol` перед запуском. WebSocket отключается
ответом 426 внутри клиента; обычный fallback Codex использует проверяемый HTTP.
HTTP trace с телом запроса отключён в этом режиме.

Полное JSON-тело фильтруется вместе: AGENTS.md, системные/пользовательские
инструкции, текстовая история, описания инструментов и навыков. Это позволяет
узнать секрет по подписи в одной части и скрыть повтор в другой. Изображения,
файловые идентификаторы, server-side continuation и hosted tools блокируются.
Зашифрованный reasoning разрешён лишь как точный повтор блока ответа провайдера,
зарегистрированного в этом же чате до продолжения агента. В локальной таблице
хранится только хеш такого блока.

## Сборка по закреплённым исходникам

```bash
python3 scripts/build_native_backend.py
```

Нужны Git, Cargo/Rust и системные зависимости upstream. Неизменённый официальный
`codex-code-mode-host` версии 0.159.0 берётся из установленного Desktop; его SHA-256
закреплён в manifest.json. Другой путь можно задать через `--code-mode-host`.
Сборка host из исходников здесь упирается в отсутствующий upstream V8-архив;
никакая библиотека другой версии вместо него не подставляется.
Upstream задаёт Rust 1.95; здесь используется установленный Rust
1.98. Для него в `codex-chatgpt` повышен `recursion_limit` до 256.
`Cargo.lock` нормализует только версии собственных workspace-пакетов с 0.0.0 на
0.159.0; версии сторонних библиотек сохранены. `just bazel-lock-update` не дал
изменений MODULE.bazel.lock.

Скрипт проверяет commit, контрольную сумму патча и содержимое каждого изменённого
файла. Неожиданные изменения останавливают сборку; reset/clean не выполняются.
Исходники находятся в игнорируемом `target/codex-native/source`, результат — в
новом `dist/sanctum-native-backend`. Системный Codex не заменяется.
Получается dev-сборка без debug info и incremental compilation; копии бинарников
обрабатываются `strip`. Это не официальный дистрибутив OpenAI.

## Проверка

```bash
# Из upstream/codex-rs, с доступными just и cargo-nextest:
just test -p codex-http-client -p codex-api -p codex-cli -p codex-chatgpt
just fix -p codex-http-client -p codex-api -p codex-cli -p codex-chatgpt
just fmt

# Из корня Sanctum, после cargo build --locked --bins:
python3 scripts/check_portless.py --native-boundary \
  --codex ./dist/sanctum-native-backend/codex
```

Проверка с имитацией модели не использует пользовательскую авторизацию. Она
проверяет prompt → модель → локальная команда → модель, неявный контекст,
возврат reasoning, fallback HTTP и отказ при недоступном фильтре.

## Пределы

Это фильтр текстового контекста Responses API, а не DLP всего приложения.
Телеметрия, загрузка плагинов, удалённые MCP/коннекторы и прочие сетевые каналы
требуют отдельного контроля. Детекторы эвристические. Патч не создаёт изоляцию от
агента, которому уже предоставлен доступ к локальным оригиналам.
Совместимость с новыми версиями Desktop/backend нужно проверять отдельно.
