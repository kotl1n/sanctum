# Sanctum

[Русская версия](README.ru.md)

Local protection for text data in Codex Desktop. Sanctum replaces detected private values with pseudonyms, keeps the mappings on your device and restores the values for supported local tools.

**Version 1.0.0.** The engine and all plugins share one version. Linux x86-64 has a pinned Desktop build. Windows x64 support is experimental: see the [Windows guide](docs/WINDOWS.md). Full integration requires a verified profile of the specific Windows build. Verification status and limitations: [release verification](docs/RELEASE.md).

## How it works

- `sanctum-guard` handles preview, masking, settings and argument restoration.
- `sanctum-codex` connects Desktop to the backend over standard input and output (stdio).
- A native patch filters model requests, including instructions, tool descriptions and history. Protecting the whole context requires this backend and launching the app through Sanctum.
- Session mappings are stored encrypted. On Windows the key is additionally protected with the current user's DPAPI. The key stays on the same device; encryption does not protect against a process that can read the key. State expires after 24 hours without a successful update.
- Input field highlighting uses a local debug channel without a TCP port. It shows what was detected and does not by itself confirm that the request was filtered safely.

Detectors recognize IP addresses, email addresses, known credential formats, password fields and other structured private data. Rules cover Russian and English. An arbitrary secret may go unnoticed, and false positives are possible. Add your own policy for project-specific values. In protected mode, attachments and remote tools are restricted or excluded. If masking fails, the affected context is replaced with an omission notice.

## Building and testing

Requires Rust 1.88+, Python 3.11+, Node.js 22+ and Git. The commands below are for Linux x86-64. Windows commands and experimental limitations are in the [Windows guide](docs/WINDOWS.md). Downloading the pinned upstream sources requires network access.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --jobs 2 -- -D warnings
cargo test --locked --all-targets --jobs 2
python3 -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/composer-host.test.cjs
python3 scripts/build_release.py --jobs 2
```

The builder replaces personal build paths and checks that none remain in the executables. Python is used for installation and packaging; the core runs in Rust.

Tests and the required build, install and management scripts are kept in the repository and the source archive for reproducible release verification. The installed plugin does not run tests.

## Trying it without Desktop

On Linux, run `target/release/sanctum-guard preview` and pipe sample text to standard input. On Windows, use `target/release/sanctum-guard.exe preview` after building. Preview does not store mappings. For reversible masking, use `sanctum redact --vault PATH` and `sanctum restore --vault PATH` (`sanctum.exe` on Windows), also with standard input.

The CLI `--vault` file holds **unencrypted mappings as JSON**. It is created with `0600` permissions on Unix and a private DACL on Windows. This is a separate mechanism, not the encrypted Desktop store. Keep the file local and delete it after use. Do not commit vaults, keys, account settings or policies containing secrets to Git.

Policies support the `literals`, `patterns`, `internal_domains`, `personal_names` and `max_entries` fields. Example: [examples/policy.json](examples/policy.json). Use `--policy`, or the `SANCTUM_GUARD_POLICY` variable for Desktop.

## Building the Desktop bundle

The native integration is pinned to Codex **0.159.0**. The commit, context protocol and checksums are listed in the [manifest](native/codex-0.159.0-context/manifest.json). The upstream version and protocol identifier are independent of the Sanctum version. The following commands use the pinned Linux x86-64 profile; Windows first needs a separate [profile of the real Desktop build](docs/WINDOWS.md).

```sh
python3 scripts/build_native_backend.py --prepare-only
python3 scripts/build_native_backend.py --jobs 2 --code-mode-host /path/to/official/codex-code-mode-host
python3 scripts/package_release.py --backend dist/sanctum-context-backend --output dist/sanctum-1.0.0
```

Building upstream also requires Rust 1.95+, C/C++ tools, CMake, pkg-config and OpenSSL headers. The official code-mode helper must match the checksum in the manifest. A full build takes much longer than building Sanctum alone.

To verify packaging, installation, masking, restoration, native app-server initialization and removal in a temporary home directory, replace the last command with:

```sh
python3 tests/smoke_bundle.py --backend dist/sanctum-context-backend --output dist/sanctum-1.0.0-check
```

The output directory must be new. The check sends no request to the model and does not change your Desktop profile. Installed Desktop components must match the compatibility profile.

The bundle includes executables, licenses, Sanctum and pinned upstream sources, the native patch and `SHA256SUMS`. Checksums confirm integrity, not the publisher's identity. `native/desktop-compatibility.json` is a template for Desktop **26.928.20755**. Plugin, UI and backend checksums are generated for each build. After a Desktop update, a compatibility check and a new profile are needed.

## Installing and enabling

The paths and commands below are for Linux. For Windows, follow the [separate guide](docs/WINDOWS.md). Unpack the verified bundle. Review the plan first, then apply it:

```sh
python3 dist/sanctum-1.0.0/install.py install --bundle dist/sanctum-1.0.0
python3 dist/sanctum-1.0.0/install.py install --bundle dist/sanctum-1.0.0 --apply
```

The installer creates `~/.local/bin/sanctum-desktop` and a separate Desktop shortcut. Protection stays off. The installer does not register the plugin or grant trust to hooks. Install the bundle's `plugin/` directory through your Desktop build's local plugin mechanism, then review and allow the hooks. `.agents/plugins/marketplace.json` is created inside the bundle during packaging; the source repository is not meant to be installed as a ready plugin. Changing the definitions requires a new trust review.

Check compatibility and enable protection:

```sh
python3 ~/.codex/plugins/cache/sanctum-portless-dev/sanctum-portless/1.0.0/ui/manage_backend.py check
python3 ~/.codex/plugins/cache/sanctum-portless-dev/sanctum-portless/1.0.0/ui/manage_backend.py enable --apply
```

Use `disable --apply` to turn it off. After installing or switching the backend, fully restart Desktop through Sanctum. Before upgrading, disable protection with the current installation's manager. Installer 1.0.0 uses a separate plugin version directory and keeps a transaction history for recovery.

## Removal and rollback

Linux example; on Windows, run the same `install.py` with `python` from your bundle directory.

```sh
python3 dist/sanctum-1.0.0/install.py uninstall
python3 dist/sanctum-1.0.0/install.py uninstall --apply
python3 dist/sanctum-1.0.0/install.py rollback --transaction transaction-EXAMPLE.json
```

An applied operation returns the transaction name. Interrupted transactions are recovered on the next installer run. Modified settings and policies are kept on removal; modified program files cause a conflict and are not overwritten. Encrypted session state also stays on the device. Use `sanctum-guard forget` to delete session mappings. Installation and removal do not change account settings.

## Claude Code

The `sanctum-privacy` plugin works in Claude Code through hooks only, without a proxy or network port. The model receives pseudonyms instead of private data in prompts and tool output, while local tools work with the original values. Build it with `sanctum-guard package-claude --output dist/sanctum-privacy`, then run `/plugin marketplace add` and `/plugin install sanctum-privacy@sanctum-local`. Details and limitations (in Russian): [Sanctum for Claude Code](docs/CLAUDE_CODE.md).

## Other components

The `sanctum` executable only provides the `redact` and `restore` commands for masking text from standard input (see "Trying it without Desktop"). Sanctum opens no network ports: the Desktop integration is `sanctum-portless` with the verified native backend, and the Claude Code integration is the `sanctum-privacy` plugin.

## Language and license

User-facing descriptions, help and messages in Sanctum are in Russian; the remaining documentation in `docs/` is in Russian as well. Command names, JSON fields, error codes, protocol identifiers and model instructions keep their original names for compatibility. License texts are kept untranslated.

Copyright (C) 2026 Sanctum contributors. Sanctum is distributed under the [GNU GPL version 3, that version only](LICENSE), without warranty. When distributing a derivative work you must keep the copyright notices and provide the corresponding sources under GPLv3. Selling copies is allowed; distributing a closed derivative work is not.

Upstream and third-party code keeps its own licenses. See [NOTICE](NOTICE) and the original upstream license and notice files in the `native` directory.
