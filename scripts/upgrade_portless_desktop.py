#!/usr/bin/env python3
"""Upgrade this user's existing Sanctum launcher; leave Codex settings intact."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic(path, data, mode):
    fd, temporary = tempfile.mkstemp(prefix=".sanctum-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def legacy_guard_plan(new_binary, package, user_dir=None):
    """Verify the optional older prompt-only plugin before changing anything."""
    user_dir = Path.home() if user_dir is None else user_dir
    installed = user_dir / ".codex/plugins/cache/sanctum-guard-dev/sanctum-prompt-guard/0.1.0"
    if not installed.exists():
        return []
    source = package.resolve() / "plugin"
    for relative in ("hooks/hooks.json", ".codex-plugin/plugin.json"):
        if (installed / relative).read_bytes() != (source / relative).read_bytes():
            raise SystemExit("Legacy plugin definition differs; left untouched")
    targets = [installed / "bin/sanctum-guard", source / "bin/sanctum-guard"]
    expected = sha(new_binary)
    if sha(targets[0]) not in (sha(targets[1]), expected):
        raise SystemExit("Legacy binary differs from its package; left untouched")
    return [path for path in targets if sha(path) != expected]


def refresh_legacy_guard(new_binary, targets, backup):
    """Keep the trusted check hook and policies, replacing only its executable."""
    entries = []
    for index, path in enumerate(targets):
        saved = backup / f"legacy-guard-{index}"
        shutil.copy2(path, saved)
        entries.append({"path": str(path), "backup": str(saved), "previous_sha256": sha(saved),
                        "sha256": sha(new_binary)})
    atomic(backup / "legacy-receipt.json", json.dumps(entries, indent=2).encode(), 0o600)
    changed = []
    try:
        for entry in entries:
            atomic(Path(entry["path"]), new_binary.read_bytes(), 0o755)
            changed.append(entry)
    except BaseException:
        for entry in reversed(changed):
            atomic(Path(entry["path"]), Path(entry["backup"]).read_bytes(), 0o755)
        raise
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--previous-package", type=Path, required=True)
    parser.add_argument("--backend", type=Path, default=ROOT / "dist/sanctum-native-backend")
    parser.add_argument("--refresh-previous-source", action="store_true", help="Also update binaries/README in the registered local marketplace source")
    parser.add_argument("--legacy-package", type=Path, default=ROOT / "dist/sanctum-prompt-guard",
                        help="Known source of the optional older prompt-only guard")
    args = parser.parse_args()
    user_dir = Path.home()
    plugin = user_dir / ".codex/plugins/cache/sanctum-portless-dev/sanctum-portless/0.1.0"
    launcher = user_dir / ".local/bin/sanctum-desktop"
    source = args.package.resolve() / "plugin"
    previous = args.previous_package.resolve() / "plugin"
    backend = args.backend.resolve()
    legacy_targets = legacy_guard_plan(source / "bin/sanctum-guard", args.legacy_package, user_dir)
    # Refuse to replace a plugin/launcher that was independently changed.
    for relative in ("hooks/hooks.json", ".codex-plugin/plugin.json"):
        if (plugin / relative).read_bytes() != (source / relative).read_bytes():
            raise SystemExit("Installed plugin definition differs; left untouched")
    for name in ("sanctum-guard", "sanctum-codex"):
        if sha(plugin / "bin" / name) != sha(previous / "bin" / name):
            raise SystemExit("Installed binaries differ from previous package; left untouched")
    text = launcher.read_text()
    if "# Sanctum Portless: independent launch; no TCP listener." not in text:
        raise SystemExit("Existing launcher is not the known Sanctum launcher")
    manifest = json.loads((backend / "manifest.json").read_text())
    info = json.loads((backend / "build-info.json").read_text())
    if sha(backend / "native.patch") != manifest["patch_sha256"] or any(
        sha(backend / name) != info["binaries"][name] for name in ("codex", "codex-code-mode-host")
    ) or sha(backend / "codex-code-mode-host") != manifest["code_mode_host_sha256"]:
        raise SystemExit("Native artifact checksum mismatch")
    probe = subprocess.check_output([str(backend / "codex"), "--sanctum-native-protocol"], timeout=5)
    if probe != b"sanctum-native-v1\n" or not (backend / "codex-code-mode-host").is_file():
        raise SystemExit("Native backend verification failed")
    destination = user_dir / ".local/lib/sanctum" / ("codex-0.159.0-native-" + manifest["patch_sha256"][:12])
    if destination.exists():
        raise SystemExit("Native install directory already exists; left untouched")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup = user_dir / ".codex/backups" / ("sanctum-native-" + stamp)
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(backup, 0o700)
    for name in ("sanctum-guard", "sanctum-codex"):
        shutil.copy2(plugin / "bin" / name, backup / name)
    shutil.copy2(launcher, backup / "sanctum-desktop")
    if args.refresh_previous_source:
        shutil.copy2(previous.parent / "README.txt", backup / "marketplace-README.txt")
    print("Backup prepared:", backup, flush=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(backend, destination)
    for name in ("sanctum-guard", "sanctum-codex"):
        atomic(plugin / "bin" / name, (source / "bin" / name).read_bytes(), 0o755)
    if args.refresh_previous_source:
        for name in ("sanctum-guard", "sanctum-codex"):
            atomic(previous / "bin" / name, (source / "bin" / name).read_bytes(), 0o755)
        atomic(previous.parent / "README.txt", (source.parent / "README.txt").read_bytes(), 0o644)
    legacy_entries = refresh_legacy_guard(source / "bin/sanctum-guard", legacy_targets, backup)
    exports = {
        "SANCTUM_REAL_CODEX": str(destination / "codex"),
        "CODEX_CLI_PATH": str(plugin / "bin/sanctum-codex"),
        "SANCTUM_STATE_DIR": str(user_dir / ".local/state/sanctum-portless"),
        "SANCTUM_GUARD_POLICY": str(user_dir / ".config/sanctum-portless/policy.json"),
        "SANCTUM_NATIVE_REQUIRED": "1",
        "SANCTUM_NATIVE_HELPER": str(plugin / "bin/sanctum-guard"),
    }
    script = "#!/bin/sh\n# Sanctum Portless: independent launch; no TCP listener.\n"
    script += "".join(f"export {name}={shlex.quote(value)}\n" for name, value in exports.items())
    script += 'exec /usr/bin/chatgpt "$@"\n'
    atomic(launcher, script.encode(), 0o755)
    receipt = {"backend": str(destination), "backup": str(backup), "legacy_guard": legacy_entries,
               "refreshed_marketplace_source": str(previous.parent) if args.refresh_previous_source else None,
               "binaries": {name: sha(plugin / "bin" / name) for name in ("sanctum-guard", "sanctum-codex")}}
    atomic(backup / "receipt.json", json.dumps(receipt, indent=2).encode(), 0o600)
    print("Updated launcher:", launcher)
    print("Native backend:", destination)
    print("Rollback backup:", backup)


if __name__ == "__main__":
    main()
