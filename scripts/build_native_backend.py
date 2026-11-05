#!/usr/bin/env python3

from cli_text import ArgumentParser
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_release import compiler_environment, ensure_no_personal_paths
from platform_support import executable, WINDOWS
from desktop_profile import build_profile, backend_manifest

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "native/codex-0.159.0-context"
REPOSITORY = "https://github.com/openai/codex.git"
COMMIT = "687a119f0fcaace47e1f1abcc77cec6c813fd6da"

def run(*args, cwd=None, capture=False, env=None):
    return subprocess.run(args, cwd=cwd, env=env, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = ArgumentParser(description="Сборка закреплённой нативной серверной части Codex для Sanctum.")
    parser.add_argument("--source", type=Path, default=ROOT / "target/codex-native/source", help="Каталог исходников upstream")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/sanctum-context-backend", help="Новый каталог для серверной части")
    parser.add_argument("--jobs", type=int, default=2, help="Количество параллельных заданий сборки")
    parser.add_argument("--code-mode-host", type=Path, default=Path("/usr/lib/chatgpt/resources/codex-code-mode-host"), help="Официальный неизменённый вспомогательный процесс 0.159.0; сумма закреплена в манифесте")
    parser.add_argument("--prepare-only", action="store_true", help="Подготовить и проверить исходники без компиляции")
    parser.add_argument("--profile", type=Path, help="Проверенный профиль Windows Desktop")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs должен быть положительным числом")
    source = args.source.resolve()
    patch = BUNDLE / "native.patch"
    if args.prepare_only and args.profile is None:
        manifest = json.loads((BUNDLE / "manifest.json").read_text(encoding="utf-8"))
    else:
        manifest = backend_manifest(build_profile(args.profile))
    if manifest["commit"] != COMMIT or digest(patch) != manifest["patch_sha256"]:
        raise SystemExit("Нарушена целостность нативного патча")
    if not source.exists():
        source.mkdir(parents=True)
        run("git", "init", "-q", str(source))
        run("git", "remote", "add", "origin", REPOSITORY, cwd=source)
    head = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=source,
                          capture_output=True, text=True)
    if head.returncode != 0:
        # A failed fetch leaves an initialized repository. Retry only that clean
        # state; never check out over unrelated work in a caller's source tree.
        if (not (source / ".git").is_dir()
                or any(p.name != ".git" for p in source.iterdir())
                or run("git", "remote", "get-url", "origin", cwd=source, capture=True).strip() != REPOSITORY):
            raise SystemExit("Неожиданный каталог исходников; файлы не изменены")
        run("git", "config", "core.autocrlf", "false", cwd=source)
        run("git", "config", "core.eol", "lf", cwd=source)
        run("git", "fetch", "--depth=1", "origin", COMMIT, cwd=source)
        run("git", "checkout", "--detach", "FETCH_HEAD", cwd=source)
    if run("git", "rev-parse", "HEAD", cwd=source, capture=True).strip() != COMMIT:
        raise SystemExit("Неожиданный коммит upstream; исходники не изменены")
    status = run("git", "status", "--porcelain", cwd=source, capture=True)
    if not status:
        run("git", "apply", "--check", str(patch), cwd=source)
        run("git", "apply", str(patch), cwd=source)
    changed = set(run("git", "diff", "--name-only", "HEAD", cwd=source, capture=True).splitlines())
    changed.update(run("git", "ls-files", "--others", "--exclude-standard", cwd=source, capture=True).splitlines())
    if changed != set(manifest["files"]):
        raise SystemExit("Неожиданные изменения исходников; файлы не сбрасывались и не перезаписывались")
    for relative, expected in manifest["files"].items():
        if digest(source / relative) != expected:
            raise SystemExit(f"Неожиданное содержимое исходников: {relative}")
    if args.prepare_only:
        print("Закреплённый патч проверен:", source)
        return
    host = args.code_mode_host.resolve()
    if not host.is_file() or digest(host) != manifest["code_mode_host_sha256"]:
        raise SystemExit("Укажите закреплённый официальный code-mode-host 0.159.0 через --code-mode-host")

    run("cargo", "build", "--locked", "-p", "codex-cli", "--bin", "codex",
        "--jobs", str(args.jobs), "--config", "profile.dev.debug=0",
        "--config", "profile.dev.incremental=false", "--config", "profile.dev.package.age.debug-assertions=false",
        "--config", "profile.dev.package.rust-embed.debug-assertions=false",
        cwd=source / "codex-rs", env=compiler_environment(source))
    ensure_no_personal_paths(source / "codex-rs/target/debug" / executable("codex"), source)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name in (executable("codex"), executable("codex-code-mode-host")):
        target = output / name
        shutil.copy2(host if name == executable("codex-code-mode-host") else source / "codex-rs/target/debug" / name, target)
        if name == executable("codex") and not WINDOWS and shutil.which("strip"):
            run("strip", "--strip-unneeded", str(target))
        os.chmod(target, 0o755)
    for name in ("LICENSE", "NOTICE"):
        if (source / name).is_file():
            shutil.copy2(source / name, output / name)
    shutil.copy2(patch, output / "native.patch")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    build_info = {"commit": COMMIT, "path_remapped": True, "profile": "dev; debug=0; incremental=false; age/rust-embed debug-assertions=false (embedded i18n); stripped",
                  "rustc": run("rustc", "--version", capture=True).strip(),
                  "binaries": {name: digest(output / name) for name in (executable("codex"), executable("codex-code-mode-host"))}}
    (output / "build-info.json").write_text(json.dumps(build_info, indent=2) + "\n", encoding="utf-8")
    print("Сборка готова:", output)
    run(str(output / executable("codex")), "--sanctum-context-protocol")

if __name__ == "__main__":
    main()
