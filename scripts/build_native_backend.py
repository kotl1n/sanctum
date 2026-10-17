#!/usr/bin/env python3
"""Build the pinned Sanctum Codex backend. Never replaces the system binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "native/codex-0.159.0"
REPOSITORY = "https://github.com/openai/codex.git"
COMMIT = "687a119f0fcaace47e1f1abcc77cec6c813fd6da"


def run(*args, cwd=None, capture=False):
    return subprocess.run(args, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "target/codex-native/source")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/sanctum-native-backend")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--code-mode-host", type=Path, default=Path("/usr/lib/chatgpt/resources/codex-code-mode-host"), help="Unmodified official 0.159.0 helper; checksum is pinned in manifest")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()
    patch = BUNDLE / "native.patch"
    manifest = json.loads((BUNDLE / "manifest.json").read_text())
    if manifest["commit"] != COMMIT or digest(patch) != manifest["patch_sha256"]:
        raise SystemExit("Native patch integrity mismatch")
    if not source.exists():
        source.mkdir(parents=True)
        run("git", "init", "-q", str(source))
        run("git", "remote", "add", "origin", REPOSITORY, cwd=source)
        run("git", "fetch", "--depth=1", "origin", COMMIT, cwd=source)
        run("git", "checkout", "--detach", "FETCH_HEAD", cwd=source)
    if run("git", "rev-parse", "HEAD", cwd=source, capture=True).strip() != COMMIT:
        raise SystemExit("Unexpected upstream commit; source left untouched")
    status = run("git", "status", "--porcelain", cwd=source, capture=True)
    if not status:
        run("git", "apply", "--check", str(patch), cwd=source)
        run("git", "apply", str(patch), cwd=source)
    changed = set(run("git", "diff", "--name-only", "HEAD", cwd=source, capture=True).splitlines())
    changed.update(run("git", "ls-files", "--others", "--exclude-standard", cwd=source, capture=True).splitlines())
    if changed != set(manifest["files"]):
        raise SystemExit("Unexpected source changes; no files were reset or overwritten")
    for relative, expected in manifest["files"].items():
        if digest(source / relative) != expected:
            raise SystemExit(f"Unexpected source content: {relative}")
    if args.prepare_only:
        print("Pinned patch verified:", source)
        return
    if args.jobs < 1:
        raise SystemExit("--jobs must be positive")
    host = args.code_mode_host.resolve()
    if not host.is_file() or digest(host) != manifest["code_mode_host_sha256"]:
        raise SystemExit("Provide the pinned official 0.159.0 code-mode-host via --code-mode-host")
    # Debug info and incremental compilation are disabled to keep this large
    # upstream workspace within desktop RAM/disk budgets. This is a dev build.
    run("cargo", "build", "--locked", "-p", "codex-cli", "--bin", "codex",
        "--jobs", str(args.jobs), "--config", "profile.dev.debug=0",
        "--config", "profile.dev.incremental=false", cwd=source / "codex-rs")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name in ("codex", "codex-code-mode-host"):
        target = output / name
        shutil.copy2(host if name == "codex-code-mode-host" else source / "codex-rs/target/debug" / name, target)
        if name == "codex" and shutil.which("strip"):
            run("strip", "--strip-unneeded", str(target))
        os.chmod(target, 0o755)
    for name in ("LICENSE", "NOTICE"):
        if (source / name).is_file():
            shutil.copy2(source / name, output / name)
    shutil.copy2(patch, output / "native.patch")
    shutil.copy2(BUNDLE / "manifest.json", output / "manifest.json")
    build_info = {"commit": COMMIT, "profile": "dev; debug=0; incremental=false; stripped",
                  "rustc": run("rustc", "--version", capture=True).strip(),
                  "binaries": {name: digest(output / name) for name in ("codex", "codex-code-mode-host")}}
    (output / "build-info.json").write_text(json.dumps(build_info, indent=2) + "\n")
    print("Built:", output)
    run(str(output / "codex"), "--sanctum-native-protocol")


if __name__ == "__main__":
    main()
