#!/usr/bin/env python3

from cli_text import ArgumentParser, print_result
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile

from manage_backend import Invalid, load, require, sha
from platform_support import (WINDOWS, PLATFORM, LAUNCHER, executable, file_mode,
                              reparse, relative_path, private_temp, sync_parent,
                              lock_file, protect, desktop_root as installed_desktop_root,
                              windows_launcher)

PLUGIN = Path('.codex/plugins/cache/sanctum-portless-dev/sanctum-portless/1.0.0')
CONFIG = Path('.config/sanctum-portless')
STATE = Path('.local/state/sanctum-installer')
USER_CONFIG = {CONFIG / 'settings.json', CONFIG / 'policy.json'}
REQUIRED_FILES = {
    'plugin/bin/' + executable('sanctum-guard'), 'plugin/bin/' + executable('sanctum-codex'),
    'plugin/.codex-plugin/plugin.json', 'plugin/hooks/hooks.json', 'plugin/policy.json',
    'plugin/ui/composer.js', 'plugin/ui/composer-host.cjs',
    'plugin/ui/manage_backend.py', 'plugin/ui/cli_text.py', 'plugin/ui/platform_support.py', 'plugin/ui/desktop-compatibility.json',
    'backend/' + executable('codex'), 'backend/' + executable('codex-code-mode-host'), 'backend/native.patch',
    'backend/manifest.json', 'backend/build-info.json',
}

def safe_path(home, relative):
    try:
        relative = relative_path(relative.as_posix() if isinstance(relative, Path) else relative)
    except ValueError:
        raise Invalid('invalid_path') from None
    path = home
    for part in relative.parts:
        path = path / part
        require(not reparse(path), 'symlink_rejected')
    return path

def atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.sanctum-install-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            private_temp(stream.fileno(), temp, mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if WINDOWS:
            os.chmod(temp, mode)
        os.replace(temp, path)
        sync_parent(path.parent)
    finally:
        Path(temp).unlink(missing_ok=True)

def snapshot(path):
    if not path.exists():
        return None
    require(path.is_file() and not reparse(path), 'regular_file_required')
    return {'sha256': sha(path), 'mode': file_mode(stat.S_IMODE(path.stat().st_mode))}

def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()

def same(path, expected):
    return snapshot(path) == expected

class Installer:
    def __init__(self, home):
        self.home = home.absolute()
        require(self.home.is_dir() and not reparse(self.home), 'home_required')
        self.state = safe_path(self.home, STATE)
        self.lock = None

    def __enter__(self):
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        protect(self.state) if WINDOWS else os.chmod(self.state, 0o700)
        lock_path = safe_path(self.home, STATE / 'lock')
        self.lock = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        lock_file(self.lock)
        pending = self.state / 'pending.json'
        if pending.exists():
            self.recover()
        return self

    def __exit__(self, *args):
        os.close(self.lock)

    def capture(self, path):
        saved = snapshot(path)
        if saved is not None:
            blob = self.state / "objects" / saved['sha256']
            if not blob.exists(): atomic(blob, path.read_bytes())
        return saved

    def blob(self, digest):
        path = safe_path(self.home, STATE / "objects" / digest)
        require(sha(path) == digest, "backup_hash_mismatch")
        return path.read_bytes()

    def restore(self, path, saved):
        if saved is None:
            path.unlink(missing_ok=True)
        else:
            atomic(path, self.blob(saved['sha256']), saved['mode'])

    def recover(self):
        journal = load(self.state / 'pending.json')

        for row in journal['files']:
            path = safe_path(self.home, row['path'])
            require(same(path, row['before']) or same(path, row['after']), 'recovery_conflict')
        for row in reversed(journal['files']):
            path = safe_path(self.home, row['path'])
            if not same(path, row['before']):
                self.restore(path, row['before'])
        (self.state / 'pending.json').unlink()

    def transact(self, changes):
        rows = []
        for relative, content, mode in changes:
            path = safe_path(self.home, relative)
            after = None if content is None else {'sha256': hashlib.sha256(content).hexdigest(), 'mode': file_mode(mode)}
            if after is not None:
                atomic(self.state / 'objects' / after['sha256'], content)
            before = self.capture(path)
            if before != after:
                rows.append({'path': Path(relative).as_posix(), 'before': before, 'after': after})
        require(len({r['path'] for r in rows}) == len(rows), 'duplicate_target')
        journal = {'schema': 1, 'files': rows}
        atomic(self.state / 'pending.json', encoded(journal))
        try:
            for row in rows:
                path = safe_path(self.home, row['path'])
                require(same(path, row['before']), 'concurrent_edit')
                self.restore(path, row['after'])
        except BaseException:
            self.recover()
            raise
        fd, name = tempfile.mkstemp(prefix='transaction-', suffix='.json', dir=self.state)
        os.close(fd)
        atomic(Path(name), encoded(journal))
        (self.state / 'pending.json').unlink()
        return Path(name).name

    def rollback(self, transaction):
        require(Path(transaction).name == transaction and transaction.startswith('transaction-'), 'invalid_transaction')
        journal = load(self.state / transaction)
        changes = []
        for row in reversed(journal['files']):
            require(same(safe_path(self.home, row['path']), row['after']), 'rollback_conflict')
            old = row['before']
            changes.append((Path(row['path']), self.blob(old['sha256']) if old else None, old['mode'] if old else 0o600))
        return self.transact(changes)

    def install(self, bundle, apply=False, desktop_root=None):
        profile = load(bundle / 'release.json')
        require(profile.get('schema') == 1, 'invalid_release')
        files = profile['files']
        require(isinstance(files, dict) and 1 <= len(files) <= 128, 'invalid_release')
        require(REQUIRED_FILES <= files.keys(), 'incomplete_release')
        compatibility = load(bundle / 'plugin/ui/desktop-compatibility.json')

        require(compatibility.get('supported', {}).get('platform', PLATFORM) == PLATFORM, 'platform_mismatch')
        if WINDOWS:
            require(compatibility.get('desktop') and compatibility.get('launch'), 'windows_profile_required')
            require(compatibility['supported'].get('reviewed') is True, 'windows_profile_not_reviewed')
            require(all(compatibility['launch'].get(key) in compatibility['desktop'] for key in ('app', 'node', 'codex', 'code_mode_host', 'archive')), 'windows_profile_required')
            desktop_root = desktop_root or installed_desktop_root(self.home, compatibility)
        else:
            desktop_root = Path('/')
        require(desktop_root.is_absolute(), 'desktop_root_required')
        for relative, digest in compatibility['desktop'].items():
            require(sha(desktop_root / relative_path(relative)) == digest, 'desktop_changed')
        ident = sha(bundle / 'backend/native.patch')
        destination = Path('.local/lib/sanctum') / ('codex-0.159.0-context-' + ident[:12])
        changes = []
        for relative, digest in files.items():
            source = safe_path(bundle.absolute(), relative)
            require(sha(source) == digest, 'release_hash_mismatch')
            parts = Path(relative).parts
            require(parts[0] in ('plugin', 'backend') and len(parts) > 1, 'invalid_release_path')
            target = (PLUGIN if parts[0] == 'plugin' else destination).joinpath(*parts[1:])
            changes.append((target, source.read_bytes(), 0o755 if (parts[0] == 'backend' and parts[-1] in (executable('codex'),executable('codex-code-mode-host'))) or parts[1] == 'bin' else 0o644))
        manifest = load(bundle / 'backend/manifest.json')
        build = load(bundle / 'backend/build-info.json')
        require(manifest['patch_sha256'] == ident and manifest['commit'] == build['commit'] == compatibility['commit'], 'backend_manifest_mismatch')
        approved = compatibility['backends'].get(ident)
        require(approved and all(sha(bundle / 'backend' / n) == approved['binaries'][n] == build['binaries'][n] for n in (executable('codex'),executable('codex-code-mode-host'))), 'backend_not_approved')
        settings = safe_path(self.home, CONFIG / 'settings.json')
        if settings.exists():
            state = load(settings)
            require(state.get('enabled') is False, 'disable_before_update')
        else:
            changes.append((CONFIG / 'settings.json', encoded({'enabled':False}), 0o600))
        policy = safe_path(self.home, CONFIG / 'policy.json')
        if not policy.exists():
            changes.append((CONFIG / 'policy.json', encoded({'literals':[], 'max_entries':10000}), 0o600))
        route = {'mode':'context', 'path':str(self.home / destination / executable('codex')), **{'sha256':approved['binaries'][executable('codex')], 'helper_sha256':approved['binaries'][executable('codex-code-mode-host')]}}
        changes.append((CONFIG / 'backend.json', encoded(route), 0o600))
        env = {'SANCTUM_REAL_CODEX':str(self.home / destination / executable('codex')), 'CODEX_CLI_PATH':str(self.home / PLUGIN / 'bin' / executable('sanctum-codex')),
               'SANCTUM_BACKEND_ROUTE':str(self.home / CONFIG / 'backend.json'),
               'SANCTUM_CONTEXT_PROTECTION':'1', 'SANCTUM_VERIFY_COMPATIBILITY':'1',
               'SANCTUM_STATE_DIR':str(self.home / '.local/state/sanctum-portless'),
               'SANCTUM_SETTINGS_PATH':str(self.home / CONFIG / 'settings.json'),
               'SANCTUM_GUARD_POLICY':str(self.home / CONFIG / 'policy.json')}
        if WINDOWS:
            changes.extend(windows_launcher(self.home, env, compatibility, desktop_root, settings, plugin=PLUGIN))
        else:
            launcher = '#!/bin/sh\n# Запускатель под управлением Sanctum\n'
            launcher += ''.join('export ' + key + '=' + shlex.quote(value) + '\n' for key,value in env.items())
            launcher += 'exec /usr/lib/chatgpt/resources/cua_node/bin/node ' + shlex.quote(str(self.home / PLUGIN / 'ui/composer-host.cjs'))
            launcher += ' --app /usr/bin/chatgpt --guard ' + shlex.quote(str(self.home / PLUGIN / 'bin/sanctum-guard')) + ' --settings ' + shlex.quote(str(settings)) + ' -- "$@"\n'
            changes.append((Path('.local/bin/sanctum-desktop'), launcher.encode(), 0o755))
            desktop = '[Desktop Entry]\nType=Application\nName=ChatGPT — Sanctum\nExec="' + str(self.home / '.local/bin/sanctum-desktop').replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$') + '" %U\nTerminal=false\n'
            changes.append((Path('.local/share/applications/sanctum-desktop.desktop'), desktop.encode(), 0o644))
        installed = self.state / 'installed.json'
        previous = load(installed) if installed.exists() else {'files':{}}
        originals = previous['files']
        for relative, _, _ in changes:
            if Path(relative).as_posix() not in originals:
                originals[Path(relative).as_posix()] = self.capture(safe_path(self.home, relative))

        expected = {r: v for r,v in previous.get('expected', {}).items()}
        for relative, content, mode in changes:
            if Path(relative).as_posix() in previous.get('expected', {}):
                require(same(safe_path(self.home, relative), previous['expected'][Path(relative).as_posix()]), 'installed_file_modified')
            expected[Path(relative).as_posix()] = {'sha256':hashlib.sha256(content).hexdigest(), 'mode':file_mode(mode)}
        changes.append((STATE / 'installed.json', encoded({'files':originals, 'expected':expected}), 0o600))
        result = {'status':'plan', 'files':len(changes), 'requires_restart':True, 'enabled':False}
        if apply:
            result.update(status='staged', transaction=self.transact(changes))
        return result

    def uninstall(self, apply=False):
        installed = load(self.state / 'installed.json')
        changes = []
        for relative, saved in installed['files'].items():
            unchanged = same(safe_path(self.home, relative), installed['expected'][relative])
            # Preserve edited user configuration, but refuse to overwrite
            # changes to installed programs.
            if Path(relative) in USER_CONFIG and not unchanged:
                continue
            require(unchanged, 'uninstall_conflict')
            changes.append((Path(relative), self.blob(saved['sha256']) if saved else None, saved['mode'] if saved else 0o600))
        changes.append((STATE / 'installed.json', None, 0o600))
        return {'status':'removed', 'transaction':self.transact(changes)} if apply else {'status':'plan', 'files':len(changes)}

def main():
    parser = ArgumentParser(description="Установка, удаление и откат Sanctum с журналом транзакций.")
    parser.add_argument('--home', type=Path, default=Path.home(), help='Домашний каталог установки')
    sub = parser.add_subparsers(dest='action', required=True)
    install = sub.add_parser('install', help='Установить комплект')
    install.add_argument('--bundle', type=Path, required=True, help='Каталог проверенного комплекта')
    install.add_argument('--desktop-root', type=Path, help='Каталог проверенной Windows-сборки Desktop')
    install.add_argument('--apply', action='store_true', help='Применить изменения; без этого флага выводится только план')
    uninstall = sub.add_parser('uninstall', help='Удалить установленный комплект')
    uninstall.add_argument('--apply', action='store_true', help='Применить изменения; без этого флага выводится только план')
    revert = sub.add_parser('rollback', help='Отменить применённую транзакцию')
    revert.add_argument('--transaction', required=True, help='Имя сохранённой транзакции')
    sub.add_parser('recover', help='Восстановить прерванные операции')
    args = parser.parse_args()
    try:
        with Installer(args.home) as installer:
            if args.action == 'install': result = installer.install(args.bundle.absolute(), args.apply, args.desktop_root)
            elif args.action == 'uninstall': result = installer.uninstall(args.apply)
            elif args.action == 'rollback': result = {'status':'restored', 'transaction':installer.rollback(args.transaction)}
            else: result = {'status':'recovered'}
        print_result(result)
        return 0
    except (Invalid, OSError, ValueError, KeyError, TypeError):
        print_result({'status':'error', 'reason':str(sys.exc_info()[1]) if isinstance(sys.exc_info()[1], Invalid) else 'installation_failed'})
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
