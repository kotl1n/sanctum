#!/usr/bin/env python3

from cli_text import ArgumentParser, print_result
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib
from build_release import ensure_no_personal_paths
from manage_backend import Invalid, load, require, sha, plugin_files
from platform_support import executable, reparse
from desktop_profile import build_profile, backend_manifest

ROOT = Path(__file__).resolve().parents[1]

def release_version():
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding="utf-8"))['package']['version']
    require(len(version.split('.')) == 3 and all(p.isdigit() for p in version.split('.')),
            'invalid_release_version')
    for path in (ROOT / 'plugins').rglob('plugin.json'):
        require(load(path)['version'] == version, 'plugin_version_mismatch')
    profile = load(ROOT / 'native/desktop-compatibility.json')
    require(profile['supported']['plugin_version'] == profile['supported']['sanctum_crate_version'] == version,
            'compatibility_version_mismatch')
    return version

def source_archive(root, output):
    # Explicit source roots keep local credentials, build outputs and Git
    # history out of the distributable while including uncommitted sources.
    roots = ('Cargo.toml', 'Cargo.lock', 'README.md', 'README.ru.md', 'CHANGELOG.md', 'LICENSE', 'NOTICE',
             '.gitignore', '.gitattributes', '.github', 'docs', 'examples', 'native', 'plugins',
             'scripts', 'src', 'tests', 'ui')
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root)
    with tarfile.open(output, 'w:gz') as archive:
        for name in sorted(set(names.split(b'\0')) - {b''}):
            relative = Path(os.fsdecode(name))
            if relative.parts[0] not in roots:
                continue
            path = root
            for part in relative.parts:
                path = path / part
                require(not reparse(path), 'source_symlink_rejected')
            if path.is_file():
                archive.add(path, arcname='sanctum/' + relative.as_posix(), recursive=False)

def package(backend, output, native_source=None, profile_path=None):
    profile = build_profile(profile_path)
    manifest = backend_manifest(profile)
    require(load(backend / 'manifest.json') == manifest, 'backend_manifest_mismatch')
    require(sha(backend / 'native.patch') == manifest['patch_sha256'], 'backend_patch_mismatch')
    build = load(backend / 'build-info.json')
    require(build['commit'] == manifest['commit'], 'backend_commit_mismatch')
    for name in (executable('codex'),executable('codex-code-mode-host')):
        require(sha(backend / name) == build['binaries'][name], 'backend_binary_mismatch')
        ensure_no_personal_paths(backend / name)
    require(sha(backend / executable('codex-code-mode-host')) == manifest['code_mode_host_sha256'], 'backend_host_mismatch')
    require(subprocess.check_output([str(backend / executable('codex')), '--sanctum-context-protocol'], timeout=5) == b'sanctum-context-v2\n', 'backend_protocol_mismatch')
    require((backend / 'LICENSE').is_file() and (backend / 'NOTICE').is_file(), 'backend_licenses_required')
    native_source = native_source or ROOT / 'target/codex-native/source'
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=native_source, text=True).strip() == manifest['commit'], 'backend_source_required')
    for name in (executable('sanctum-guard'),executable('sanctum-codex')):
        ensure_no_personal_paths(ROOT / 'target/release' / name)
    version = release_version()
    for binary_name in ('sanctum', 'sanctum-guard'):
        version_output = subprocess.check_output(
            [str(ROOT / 'target/release' / executable(binary_name)), '--version'], text=True)
        if version_output.strip().split()[-1] != version:
            raise ValueError('release_binary_version_mismatch')
    require(not output.exists(), 'output_must_be_new')

    subprocess.run([str(ROOT / 'target/release' / executable('sanctum-guard')), 'package-portless', '--output', str(output)], check=True)
    try:
        packaged_version = load(output / 'plugin/.codex-plugin/plugin.json')['version']
        if packaged_version != version:
            raise ValueError('packaged_plugin_version_mismatch')
        subprocess.run([str(ROOT / 'target/release' / executable('sanctum-guard')), 'package-claude', '--output', str(output / 'claude')], check=True)
        if load(output / 'claude/plugin/.claude-plugin/plugin.json')['version'] != version:
            raise ValueError('packaged_claude_plugin_version_mismatch')
        for name in ('LICENSE', 'NOTICE', 'README.md', 'README.ru.md', 'CHANGELOG.md'):
            shutil.copy2(ROOT / name, output / name)
        for name in ('docs', 'examples', 'native'):
            shutil.copytree(ROOT / name, output / name)
        for name, note in (('README.md', '> This is a binary bundle. To build from source, unpack '
                                         '`sanctum-source.tar.gz` and enter the `sanctum/` directory.'),
                           ('README.ru.md', '> Это исполняемый комплект. Для сборки из исходников распакуйте '
                                            '`sanctum-source.tar.gz` и перейдите в каталог `sanctum/`.')):
            readme = output / name
            readme.write_text(note + '\n\n' + readme.read_text(encoding="utf-8"), encoding="utf-8")
        source_archive(ROOT, output / 'sanctum-source.tar.gz')
        subprocess.run(['git', 'archive', '--format=tar.gz', '--prefix=codex/',
                        '--output=' + str(output / 'codex-upstream-source.tar.gz'), manifest['commit']],
                       cwd=native_source, check=True)

        for name in ('composer.js','composer-host.cjs'):
            shutil.copy2(ROOT / 'ui' / name, output / 'plugin/ui' / name)
        for name in ('manage_backend.py', 'cli_text.py', 'platform_support.py'):
            shutil.copy2(ROOT / 'scripts' / name, output / 'plugin/ui' / name)
        target = output / 'backend'
        target.mkdir()
        for name in (executable('codex'),executable('codex-code-mode-host'),'native.patch','manifest.json','build-info.json','LICENSE','NOTICE'):
            if (backend / name).is_file(): shutil.copy2(backend / name, target / name)
        for name in ('install.py','manage_backend.py','cli_text.py','platform_support.py'):
            shutil.copy2(ROOT / 'scripts' / name, output / name)
        profile['backends'] = {manifest['patch_sha256']:{'binaries':build['binaries'],
            'features':['context','local_workdir','stdin_aliases','multiline_patch','typed_compaction_replay']}}
        profile['plugin'] = {name:sha(output / 'plugin/bin' / name) for name in (executable('sanctum-guard'),executable('sanctum-codex'))}
        profile['ui'] = {p.name:sha(p) for p in sorted((output / 'plugin/ui').iterdir()) if p.is_file() and p.name != 'desktop-compatibility.json'}
        (output / 'plugin/ui/desktop-compatibility.json').write_text(json.dumps(profile, indent=2)+'\n', encoding="utf-8")
        (output / 'desktop-compatibility.json').write_text(json.dumps(profile, indent=2)+'\n', encoding="utf-8")
        plugin_files(output / 'plugin', profile)
        files = {p.relative_to(output).as_posix():sha(p) for base in (output / 'plugin', target) for p in sorted(base.rglob('*')) if p.is_file()}
        (output / 'release.json').write_text(json.dumps({'schema':1,'files':files}, indent=2)+'\n', encoding="utf-8")
    except BaseException:
        shutil.rmtree(output)
        raise
    sums = [sha(p) + '  ' + p.relative_to(output).as_posix() for p in sorted(output.rglob('*')) if p.is_file()]
    (output / 'SHA256SUMS').write_text('\n'.join(sums)+'\n', encoding="utf-8")
    return output

if __name__ == '__main__':
    parser = ArgumentParser(description="Упаковка проверенных исполняемых файлов и соответствующих исходников.")
    parser.add_argument('--backend', type=Path, required=True, help='Каталог закреплённой нативной серверной части')
    parser.add_argument('--output', type=Path, required=True, help='Новый каталог для комплекта')
    parser.add_argument('--native-source', type=Path, help='Закреплённый Git-каталог upstream для включения соответствующих исходников')
    parser.add_argument('--profile', type=Path, help='Проверенный профиль Windows Desktop')
    args = parser.parse_args()
    try:
        print('Комплект создан:', package(args.backend.resolve(), args.output.absolute(), args.native_source, args.profile))
    except (Invalid, OSError, ValueError, KeyError, TypeError) as error:
        print_result({'status': 'error', 'reason': str(error) if isinstance(error, Invalid) else 'packaging_failed'})
        raise SystemExit(1)
