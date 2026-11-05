"""Профили проверенных сборок Desktop; чужая ОС и непроверенные профили отклоняются."""

from pathlib import Path
import json
from cli_text import ArgumentParser
from manage_backend import load, require, sha
from platform_support import PLATFORM, WINDOWS, relative_path, reparse

ROOT = Path(__file__).resolve().parents[1]


def build_profile(path=None):
    require(path is not None or not WINDOWS, 'windows_profile_required')
    profile = load(path or ROOT / 'native/desktop-compatibility.json')
    reference = load(ROOT / 'native/desktop-compatibility.json')
    require(profile.get('schema') == 1, 'invalid_profile')
    for field in ('codex_version', 'context_protocol', 'plugin_version', 'sanctum_crate_version'):
        require(profile['supported'][field] == reference['supported'][field], 'compatibility_version_mismatch')
    require(profile['supported']['platform'] == PLATFORM, 'platform_mismatch')
    if WINDOWS:
        require(profile['supported'].get('reviewed') is True, 'windows_profile_not_reviewed')
        require(profile['desktop'] and profile.get('launch'), 'windows_profile_required')
        require(all(profile['launch'][key] in profile['desktop'] for key in ('app', 'node', 'codex', 'code_mode_host', 'archive')), 'invalid_profile')
    return profile


def backend_manifest(profile):
    manifest = load(ROOT / 'native/codex-0.159.0-context/manifest.json')
    if profile['supported']['platform'] == 'windows-x86_64':
        manifest['code_mode_host_sha256'] = profile['desktop'][profile['launch']['code_mode_host']]
        manifest['platform'] = 'windows-x86_64'
    return manifest


def main():
    parser = ArgumentParser(description='Создать отпечаток Windows Desktop. Контрольные суммы сами по себе не подтверждают совместимость.')
    parser.add_argument('--desktop-root', type=Path, required=True, help='Каталог официальной Windows-сборки Desktop')
    parser.add_argument('--desktop-version', required=True, help='Точная версия Desktop')
    parser.add_argument('--output', type=Path, required=True, help='Новый файл профиля')
    for key in ('app', 'node', 'codex', 'code-mode-host', 'archive'):
        parser.add_argument('--' + key, required=True, help='Относительный путь компонента внутри Desktop; разделитель /')
    parser.add_argument('--reviewed', action='store_true', help='Подтвердить источник, версию и состав официальной Windows-сборки перед тестовой установкой')
    args = parser.parse_args()
    profile = load(ROOT / 'native/desktop-compatibility.json')
    launch = {key:relative_path(getattr(args, key)).as_posix() for key in ('app', 'node', 'codex', 'code_mode_host', 'archive')}
    root = args.desktop_root.resolve(strict=True)
    for name in launch.values():
        path = root / name
        require(path.resolve().is_relative_to(root) and not reparse(path), 'invalid_component_path')
    profile.update(desktop={name:sha(root/name) for name in launch.values()}, launch=launch, plugin={}, ui={}, backends={})
    profile['supported'].update(platform='windows-x86_64', desktop_version=args.desktop_version, reviewed=args.reviewed)
    require(not args.output.exists(), 'output_must_be_new')
    args.output.write_text(json.dumps(profile, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print('Профиль создан. Проверка компонентов подтверждена; реальный сеанс Desktop требует отдельной проверки.' if args.reviewed else 'Отпечаток создан. Профиль пока не разрешён для релизной установки.')


if __name__ == '__main__':
    main()
