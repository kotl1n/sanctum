from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sys

from .gateway import Gateway, Settings
from .redaction import Policy, Redactor, RedactionError, restore_with_mapping


def private_write(path: Path, content: str):
    """Never overwrite existing files or follow symlinks."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(content)


def prepare(directory: Path, port: int, mode: str):
    if not 1 <= port <= 65535:
        raise RedactionError("Invalid port")
    directory = directory.expanduser().resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any((directory / name).exists() for name in ("connection.json", "codex.fragment.toml")):
        raise RedactionError("Setup already exists; refusing to replace credentials")
    key = secrets.token_urlsafe(32)
    state = {"local_key": key, "port": port, "mode": mode}
    prefix = "/backend-api/codex" if mode == "chatgpt" else "/v1"
    auth = 'requires_openai_auth = true' if mode == "chatgpt" else 'env_key = "OPENAI_API_KEY"'
    config = f'''# Experimental Sanctum connection. Merge keys, do not duplicate TOML tables.
# This contains a LOCAL gateway credential. Keep this file private.
model_provider = "sanctum"
web_search = "disabled"

[model_providers.sanctum]
name = "Sanctum local"
base_url = "http://127.0.0.1:{port}{prefix}"
wire_api = "responses"
{auth}
supports_websockets = false
http_headers = {{ "X-Sanctum-Key" = "{key}" }}
'''
    private_write(directory / "connection.json", json.dumps(state, indent=2) + "\n")
    private_write(directory / "codex.fragment.toml", config)
    print(f"Created private connection files in {directory}")
    print("Codex settings have NOT been changed. See README.md for activation and rollback.")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sanctum", description="Local text redaction for coding agents. Experimental Desktop adapter.")
    sub = parser.add_subparsers(dest="command", required=True)
    redact = sub.add_parser("redact", help="Read stdin; write sanitized text to stdout")
    redact.add_argument("--policy")
    redact.add_argument("--vault", type=Path, help="Explicitly save a PLAINTEXT local mapping, mode 0600")
    restore = sub.add_parser("restore", help="Locally restore stdin using an explicitly saved vault")
    restore.add_argument("--vault", type=Path, required=True)
    init = sub.add_parser("prepare", help="Generate private connection files; does not edit Codex settings")
    init.add_argument("--directory", type=Path, default=Path.home() / ".config/sanctum")
    init.add_argument("--port", type=int, default=47631)
    init.add_argument("--mode", choices=("chatgpt", "openai"), default="chatgpt")
    serve = sub.add_parser("serve", help="Run loopback gateway; credentials stay in process memory")
    serve.add_argument("--connection", type=Path, default=Path.home() / ".config/sanctum/connection.json")
    serve.add_argument("--policy")
    serve.add_argument("--no-restore-tools", action="store_true")
    sub.add_parser("demo", help="Run a fully offline gateway + tool + follow-up demonstration")
    args = parser.parse_args(argv)
    try:
        if args.command == "redact":
            redactor = Redactor(Policy.load(args.policy))
            text = sys.stdin.read()
            safe = redactor.text(redactor.text(text))
            if args.vault:
                private_write(args.vault, json.dumps(redactor.export(), ensure_ascii=False, indent=2) + "\n")
            sys.stdout.write(safe)
        elif args.command == "restore":
            mapping = json.loads(args.vault.read_text(encoding="utf-8"))
            sys.stdout.write(restore_with_mapping(sys.stdin.read(), mapping))
        elif args.command == "prepare":
            prepare(args.directory, args.port, args.mode)
        elif args.command == "demo":
            from .demo import run
            run()
        elif args.command == "serve":
            state = json.loads(args.connection.expanduser().read_text(encoding="utf-8"))
            port = state["port"]
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError()
            settings = Settings(local_key=state["local_key"], mode=state["mode"], policy=Policy.load(args.policy), restore_tools=not args.no_restore_tools)
            with Gateway(("127.0.0.1", port), settings) as server:
                print(f"Sanctum listening on 127.0.0.1:{port}; mode={settings.mode}; text-only; tool restoration={settings.restore_tools}", flush=True)
                server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Never interpolate exception strings: they can contain secrets or paths.
        print("Sanctum: operation failed; input and credentials omitted. Check configuration or input format.", file=sys.stderr)
        return 1
    return 0
