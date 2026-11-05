"""Проверка текущих исходников в Docker + Wine без монтирования домашнего каталога."""
from pathlib import Path
import subprocess
import tempfile
from cli_text import ArgumentParser
from package_release import source_archive

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--docker', default='docker', help='Путь к Docker CLI')
    parser.add_argument('--host', help='Адрес отдельного Docker-демона')
    parser.add_argument('--image', default='sanctum-windows-test', help='Имя образа для сборки и запуска')
    parser.add_argument('--skip-build', action='store_true', help='Использовать уже собранный образ')
    parser.add_argument('--network', default='default', help='Сеть контейнера; host для изолированного демона без моста')
    args = parser.parse_args()
    command = [args.docker] + (['--host', args.host] if args.host else [])
    if not args.skip_build:
        subprocess.run(command + ['build', '--network', args.network, '-t', args.image, str(ROOT/'tests/docker/windows')], check=True)
    (ROOT/'target').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='windows-source-', dir=ROOT/'target') as temporary:
        archive = Path(temporary)/'source.tar.gz'
        source_archive(ROOT, archive)
        with archive.open('rb') as stream:
            subprocess.run(command + ['run', '--rm', '-i', '--network', args.network, args.image,
                           'sh', '-c', 'tar -xzf - --strip-components=1 && sh tests/docker/windows/run.sh'], stdin=stream, check=True)


if __name__ == '__main__':
    main()
