#!/usr/bin/env python3

from cli_text import ArgumentParser, print_result
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from platform_support import (WINDOWS, PLATFORM, executable, reparse, relative_path,
                              private_temp, desktop_root)

class Invalid(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise Invalid(reason)

def sha(path):
    require(path.is_file() and not reparse(path), "file_missing_or_symlink")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def unique_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "duplicate_json_field")
    return result

def load(path):
    require(path.is_file() and not reparse(path) and path.stat().st_size <= 256_000, "metadata_unavailable")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)

def settings(home):
    result = load(home / ".config/sanctum-portless/settings.json")
    require(isinstance(result, dict), "invalid_settings")
    result.pop("force_disabled", None)
    require(set(result) <= {"enabled"}, "invalid_settings")
    require(all(isinstance(value, bool) for value in result.values()), "invalid_settings")
    return result

def backend(home, profile, ident):
    record = profile["backends"][ident]
    base = home / ".local/lib/sanctum"
    directory = base / ("codex-0.159.0-context-" + ident[:12])
    require(not reparse(directory) and directory.resolve().is_relative_to(home.resolve()), "backend_location_invalid")
    require(directory.resolve().parent == base.resolve(), "backend_location_invalid")
    manifest = load(directory / "manifest.json")
    build = load(directory / "build-info.json")
    require(manifest["commit"] == build["commit"] == profile["commit"], "backend_commit_mismatch")
    require(manifest["patch_sha256"] == sha(directory / "native.patch") == ident, "backend_patch_mismatch")
    for name in (executable("codex"), executable("codex-code-mode-host")):
        require(sha(directory / name) == build["binaries"][name] == record["binaries"][name], "backend_binary_mismatch")
    require(manifest["code_mode_host_sha256"] == record["binaries"][executable("codex-code-mode-host")], "backend_host_mismatch")
    return directory

def plugin_files(directory, profile):
    for name in (executable("sanctum-guard"), executable("sanctum-codex")):
        require(sha(directory / "bin" / name) == profile["plugin"][name], "plugin_binary_mismatch")
    for name, digest in profile["ui"].items():
        require(Path(name).name == name, "invalid_profile")
        require(sha(directory / "ui" / name) == digest, "plugin_ui_mismatch")

def check(home, profile, system_root=None):
    reasons = []
    try:
        settings(home)
        require(profile.get('supported', {}).get('platform', PLATFORM) == PLATFORM, 'platform_mismatch')
        if WINDOWS:
            require(profile.get('desktop') and profile.get('launch'), 'windows_profile_required')
            require(profile['supported'].get('reviewed') is True, 'windows_profile_not_reviewed')
            require(all(profile['launch'].get(key) in profile['desktop'] for key in ('app', 'node', 'codex', 'code_mode_host', 'archive')), 'windows_profile_required')
        system_root = system_root if system_root is not None else desktop_root(home, profile)
        for name, digest in profile["desktop"].items():
            relative = relative_path(name)
            require(not relative.is_absolute() and ".." not in relative.parts, "invalid_profile")
            require(sha(system_root / relative) == digest, "desktop_changed")
        plugin_files(home / ".codex/plugins/cache/sanctum-portless-dev/sanctum-portless/1.0.0", profile)
        route = load(home / ".config/sanctum-portless/backend.json")
        matches = [ident for ident, row in profile["backends"].items() if row["binaries"][executable("codex")] == route.get("sha256")]
        require(len(matches) == 1, "backend_not_approved")
        ident = matches[0]
        if profile.get("supported", {}).get("context_protocol") == "sanctum-context-v2":
            require("typed_compaction_replay" in profile["backends"][ident]["features"], "backend_protocol_unsupported")
        directory = backend(home, profile, ident)
        require(route.get("mode") == "context" and route.get("path") == str(directory / executable("codex")), "backend_route_mismatch")
        require(route.get("helper_sha256") == profile["backends"][ident]["binaries"][executable("codex-code-mode-host")], "backend_route_mismatch")
        return {"compatible": True, "reasons": [], "backend": ident[:12],
                "features": profile["backends"][ident]["features"]}
    except Invalid as error:
        reasons.append(str(error))
    except (OSError, ValueError, KeyError, TypeError):
        reasons.append("metadata_invalid")
    return {"compatible": False, "reasons": reasons}

def atomic(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".sanctum-route-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            private_temp(stream.fileno(), temporary, 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def set_enabled(home, profile, enabled, apply=False):
    state = settings(home)
    if enabled:
        require(check(home, profile)['compatible'], 'desktop_incompatible')
    result = {'status': 'plan', 'enabled': enabled, 'requires_restart': True}
    if apply:
        state['enabled'] = enabled
        atomic(home / '.config/sanctum-portless/settings.json',
               (json.dumps(state, indent=2) + '\n').encode())
        result['status'] = 'saved'
    return result

def rollback(home, profile, prefix, apply=False):
    require(len(prefix) >= 8, "backend_id_too_short")
    matches = [ident for ident in profile["backends"] if ident.startswith(prefix)]
    require(len(matches) == 1, "backend_id_unknown_or_ambiguous")
    ident = matches[0]
    directory = backend(home, profile, ident)
    result = {"status": "plan", "to": ident[:12], "would_enable": False,
              "features": profile["backends"][ident]["features"], "requires_restart": True}
    if not apply:
        return result
    state = settings(home)
    require(state.get("enabled") is False, "disable_before_rollback")
    route = home / ".config/sanctum-portless/backend.json"
    require(not route.is_symlink(), "route_symlink_rejected")
    previous = route.read_bytes() if route.exists() else None
    require(previous is None or len(previous) <= 256_000, "metadata_invalid")
    metadata = {"mode": "context", "path": str(directory / executable("codex")),
                "sha256": profile["backends"][ident]["binaries"][executable("codex")],
                "helper_sha256": profile["backends"][ident]["binaries"][executable("codex-code-mode-host")]}
    content = (json.dumps(metadata, indent=2) + "\n").encode()
    backups = home / ".codex/backups"
    require(not backups.is_symlink(), "backup_location_invalid")
    backups.mkdir(parents=True, exist_ok=True)
    saved = Path(tempfile.mkdtemp(prefix="sanctum-route-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-"), dir=backups))
    if previous is not None:
        atomic(saved / "previous.json", previous)
    atomic(saved / "receipt.json", (json.dumps({"previous_present": previous is not None,
        "old_sha256": hashlib.sha256(previous).hexdigest() if previous is not None else None,
        "new_sha256": hashlib.sha256(content).hexdigest(), "to": ident}) + "\n").encode())

    require(settings(home) == state, "settings_changed_during_rollback")
    require((route.read_bytes() if route.exists() else None) == previous, "route_changed_during_rollback")
    atomic(route, content)
    result["status"] = "staged"
    return result

def profile_path():
    local = Path(__file__).with_name("desktop-compatibility.json")
    return local if local.exists() else Path(__file__).resolve().parents[1] / "native/desktop-compatibility.json"

def main():
    parser = ArgumentParser(description="Проверка совместимости и управление защитой Desktop.")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("check", help="Проверить совместимость")
    sub.add_parser("list", help="Показать доступные серверные части")
    for action in ('enable', 'disable'):
        toggle = sub.add_parser(action, help="Включить защиту" if action == "enable" else "Отключить защиту")
        toggle.add_argument('--apply', action='store_true', help='Применить изменения вместо вывода плана')
    revert = sub.add_parser("rollback", help="Переключить серверную часть на сохранённую версию")
    revert.add_argument("--to", required=True, help="Префикс идентификатора серверной части")
    revert.add_argument("--apply", action="store_true", help="Применить изменения вместо вывода плана")
    args = parser.parse_args()
    try:
        profile = load(profile_path())
        require(profile.get("schema") == 1 and len(profile["backends"]) <= 32, "invalid_profile")
        home = Path.home().resolve()
        if args.action == "check":
            result = check(home, profile)
        elif args.action in ('enable', 'disable'):
            result = set_enabled(home, profile, args.action == 'enable', args.apply)
        elif args.action == "rollback":
            result = rollback(home, profile, args.to, args.apply)
        else:
            rows = []
            for ident, record in profile["backends"].items():
                try:
                    backend(home, profile, ident)
                    available = True
                except (Invalid, OSError, ValueError, KeyError):
                    available = False
                rows.append({"id": ident[:12], "features": record["features"], "available": available})
            result = {"backends": rows}
        print_result(result)
        return 2 if result.get("compatible") is False else 0
    except (Invalid, OSError, ValueError, KeyError, TypeError) as error:
        print_result({"status": "error", "reason": str(error) if isinstance(error, Invalid) else "metadata_invalid"})
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
