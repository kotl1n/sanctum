#!/usr/bin/env python3

from cli_text import ArgumentParser
import mmap
import os
from pathlib import Path
import shlex
import subprocess
from platform_support import executable

ROOT = Path(__file__).resolve().parents[1]

def private_prefixes(source=ROOT):
    paths = {Path.home().resolve(), ROOT.resolve(), source.resolve()}
    for path in tuple(paths):

        if len(path.parts) > 2 and path.parts[1] in ('home', 'Users'):
            paths.add(Path(*path.parts[:3]))
    return sorted(paths, key=lambda p: len(str(p)))

def compiler_environment(source=ROOT, base=None):
    env = dict(os.environ if base is None else base)
    flags = env.get('CARGO_ENCODED_RUSTFLAGS')
    flags = flags.split('\x1f') if flags else shlex.split(env.get('RUSTFLAGS', ''))
    mappings = {path:'/build/user' for path in private_prefixes(source)}
    mappings[ROOT.resolve()] = '/src/sanctum'
    if source.resolve() != ROOT.resolve(): mappings[source.resolve()] = '/src/codex'
    flags += ['--remap-path-prefix=' + str(path) + '=' + target
              for path,target in sorted(mappings.items(), key=lambda item:len(str(item[0])))]
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)

    if os.name == 'nt':
        return env
    native_flags = ['-ffile-prefix-map=' + str(path) + '=' + target
                    for path,target in sorted(mappings.items(), key=lambda item:len(str(item[0])))]
    names = {'CFLAGS', 'CXXFLAGS'}
    names.update(name for name in env if any(name.startswith(kind + '_') or name.endswith('_' + kind)
                                            for kind in ('CFLAGS', 'CXXFLAGS')))
    for name in names:
        env[name] = shlex.join(shlex.split(env.get(name, '')) + native_flags)
    env['CC_SHELL_ESCAPED_FLAGS'] = '1'
    return env

def ensure_no_personal_paths(binary, source=ROOT):
    with binary.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for prefix in private_prefixes(source):

            if data.find(str(prefix).encode()) >= 0 or data.find(str(prefix).encode('utf-16-le')) >= 0:
                raise ValueError('personal_build_path_in_binary: ' + binary.name)

def main():
    parser = ArgumentParser(description="Релизная сборка Sanctum без персональных путей.")
    parser.add_argument('--jobs', type=int, default=2, help='Количество параллельных заданий сборки')
    parser.add_argument("--target", help="Целевая платформа Rust, например x86_64-pc-windows-gnu")
    args = parser.parse_args()
    if args.jobs < 1: parser.error('--jobs должен быть положительным числом')
    command = ['cargo','build','--release','--locked','--jobs',str(args.jobs)]
    if args.target:
        command += ['--target', args.target]
    subprocess.run(command, cwd=ROOT, env=compiler_environment(), check=True)
    directory = ROOT / 'target'
    if args.target:
        directory /= args.target
    directory /= 'release'
    for name in ('sanctum','sanctum-guard','sanctum-codex'):
        filename = name + '.exe' if args.target and 'windows' in args.target else executable(name)
        ensure_no_personal_paths(directory / filename)
    print('Релизные файлы собраны; персональные пути сборки отсутствуют.')

if __name__ == '__main__': main()
