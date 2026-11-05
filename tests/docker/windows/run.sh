#!/bin/sh
set -eu
export PYTHONUTF8=1
XDG_RUNTIME_DIR=$(mktemp -d /tmp/sanctum-runtime.XXXXXX)
export XDG_RUNTIME_DIR
trap 'rm -rf "$XDG_RUNTIME_DIR"' 0
wine /opt/windows-python/python.exe --version
wine --version
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets --jobs 2 -- -D warnings
cargo test --locked --target x86_64-pc-windows-gnu --all-targets --jobs 2
wine /opt/windows-python/python.exe -m unittest discover -s tests -p 'test_*.py' -v

python3 scripts/build_release.py --target x86_64-pc-windows-gnu --jobs 2
wine target/x86_64-pc-windows-gnu/release/sanctum-guard.exe --version
