"""Системные операции Linux/Windows. Формат путей в метаданных — POSIX."""

import ctypes
import os
from pathlib import Path, PureWindowsPath
import stat
import sys
import time

WINDOWS = os.name == 'nt'
PLATFORM = 'windows-x86_64' if WINDOWS else 'linux-x86_64'
if sys.platform not in ('linux', 'win32'):
    PLATFORM = 'unsupported'

CONFIG = Path('.config/sanctum-portless')
STATE = Path('.local/state/sanctum-installer')
PLUGIN = Path('.codex/plugins/cache/sanctum-portless-dev/sanctum-portless/1.0.0')
LAUNCHER = Path('.local/bin/sanctum-desktop.cmd' if WINDOWS else '.local/bin/sanctum-desktop')


def executable(name):
    return name + ('.exe' if WINDOWS else '')


def file_mode(mode):
    return (0o666 if mode & stat.S_IWRITE else 0o444) if WINDOWS else mode


def reparse(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def relative_path(value):
    path = Path(value)
    windows = PureWindowsPath(value)
    if path.anchor or windows.anchor or '..' in path.parts or '..' in windows.parts or not path.parts:
        raise ValueError('invalid_path')
    # ADS, drive-relative paths and alternate Windows separators are not release paths.
    if ':' in str(value) or '\\' in str(value):
        raise ValueError('invalid_path')
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {prefix + str(number) for prefix in ('COM', 'LPT') for number in range(1, 10)}
    for part in windows.parts:
        if part.endswith((' ', '.')) or part.split('.')[0].upper() in reserved:
            raise ValueError('invalid_path')
    return path


def protect(path):
    if not WINDOWS:
        return
    if reparse(path):
        raise OSError('private_path_reparse_point')
    from ctypes import wintypes
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    get_acl = advapi.GetSecurityDescriptorDacl
    get_acl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    get_acl.restype = wintypes.BOOL
    set_acl = advapi.SetNamedSecurityInfoW
    set_acl.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    set_acl.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not convert('D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)', 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, defaulted, acl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not get_acl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)) or not present.value or not acl.value:
            raise OSError('private_acl_failed')
        result = set_acl(str(path), 1, 0x80000004, None, None, acl, None)
        if result:
            raise ctypes.WinError(result)
    finally:
        kernel.LocalFree(descriptor)


def private_temp(fd, path, mode):
    if WINDOWS:
        protect(Path(path))
    else:
        os.fchmod(fd, mode)


def sync_parent(path):
    if not WINDOWS:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def lock_file(fd):
    if not WINDOWS:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    import msvcrt
    if os.fstat(fd).st_size == 0:
        os.write(fd, b'\0')
    deadline = time.monotonic() + 5
    while True:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise OSError('installer_busy') from None
            time.sleep(0.05)


def desktop_root(home, profile):
    if not WINDOWS:
        return Path('/')
    import json
    data = json.loads((home / CONFIG / 'desktop.json').read_text(encoding="utf-8"))
    path = Path(data['root'])
    if not path.is_absolute():
        raise ValueError('desktop_root_required')
    return path


def windows_launcher(home, env, profile, root, settings, plugin=PLUGIN):
    import json
    launch = profile['launch']
    if not all(launch[key] in profile['desktop'] for key in ('app', 'node')):
        raise ValueError('invalid_profile')
    def quoted(value):
        text = str(value)
        if any(char in text for char in '\r\n\0'):
            raise ValueError('invalid_launcher_path')
        return "'" + text.replace("'", "''") + "'"
    script = "$ErrorActionPreference = 'Stop'\r\n"
    script += ''.join('$env:' + key + ' = ' + quoted(value) + '\r\n' for key, value in env.items())
    args = [root / relative_path(launch['node']), home / plugin / 'ui/composer-host.cjs',
            '--app', root / relative_path(launch['app']), '--guard',
            home / plugin / 'bin' / 'sanctum-guard.exe', '--settings', settings, '--']
    script += 'try { & ' + ' '.join(quoted(value) for value in args) + ' @args; exit $LASTEXITCODE }\r\n'
    script += "catch { [Console]::Error.WriteLine('Sanctum: не удалось запустить Desktop.'); exit 1 }\r\n"
    command = '@echo off\r\n"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0sanctum-desktop.ps1" %*\r\nexit /b %errorlevel%\r\n'
    return [(Path('.local/bin/sanctum-desktop.cmd'), command.encode('ascii'), 0o755),
            (LAUNCHER.with_suffix('.ps1'), script.encode('utf-8-sig'), 0o600),
            (CONFIG / 'desktop.json', (json.dumps({'root':str(root)})+'\n').encode(), 0o600)]
