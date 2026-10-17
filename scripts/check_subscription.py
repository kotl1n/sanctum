#!/usr/bin/env python3
"""Opt-in real ChatGPT-subscription smoke using the installed Sanctum launcher.

Sends a tiny synthetic prompt. Never prints account identity, raw context or
backend diagnostics. Does not change auth/config or launch/restart Desktop.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import shlex
import tempfile
import time

from check_portless import RPC


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-subscription-request", action="store_true", required=True)
    args = parser.parse_args()
    assert args.run_subscription_request
    env = dict(os.environ)
    launcher = Path.home() / ".local/bin/sanctum-desktop"
    for line in launcher.read_text().splitlines():
        if line.startswith("export "):
            key, value = line[7:].split("=", 1)
            env[key] = shlex.split(value)[0]
    assert env.get("SANCTUM_NATIVE_REQUIRED") == "1"
    with tempfile.TemporaryDirectory(prefix="sanctum-subscription-smoke-") as tmp:
        workspace = Path(tmp) / "workspace"
        workspace.mkdir()
        (workspace / "AGENTS.md").write_text("Synthetic host 192.0.2.42. Do not use tools.\n")
        env["SANCTUM_STATE_DIR"] = str(Path(tmp) / "state")
        rpc = RPC([env["CODEX_CLI_PATH"], "app-server", "--stdio"], env, workspace)
        try:
            rpc.initialize()
            account = rpc.request("account/read", {"refreshToken": False})
            assert account.get("account", {}).get("type") == "chatgpt", "Subscription auth required"
            hooks = rpc.request("hooks/list", {"cwds": [str(workspace)]})
            owned = [h for row in hooks["data"] for h in row["hooks"]
                     if h.get("pluginId") in ("sanctum-portless@sanctum-portless-dev",
                                               "sanctum-prompt-guard@sanctum-guard-dev")]
            assert len(owned) == 4 and all(h.get("enabled") and h.get("trustStatus") == "trusted" for h in owned), "Trusted hooks required"
            started = rpc.request("thread/start", {"cwd": str(workspace), "ephemeral": True,
                "approvalPolicy": "untrusted", "sandbox": "read-only",
                "baseInstructions": "This is a synthetic privacy test. Do not use tools. Reply exactly OK."})
            assert started.get("modelProvider") == "openai"
            thread = started["thread"]["id"]
            turn = rpc.request("turn/start", {"threadId": thread, "effort": "low",
                "input": [{"type": "text", "text": "Ответь ровно OK. Инструменты не нужны."}]})["turn"]["id"]
            events = list(rpc.notifications)
            deadline = time.monotonic() + 90
            def finished():
                return next((e for e in events if e.get("method") == "turn/completed"
                             and e.get("params", {}).get("threadId") == thread
                             and e["params"].get("turn", {}).get("id") == turn), None)
            while not finished() and time.monotonic() < deadline:
                try:
                    events.append(rpc.next(timeout=5))
                except queue.Empty:
                    pass
            done = finished()
            assert done, "Synthetic turn timed out; diagnostics omitted"
            items = [e.get("params", {}).get("item", {}) for e in events
                     if e.get("method") == "item/completed" and e.get("params", {}).get("threadId") == thread
                     and e["params"].get("turnId") == turn]
            answers = [item.get("text", "").strip() for item in items if item.get("type") == "agentMessage"]
            usage = any(e.get("method") == "thread/tokenUsage/updated"
                        and e.get("params", {}).get("threadId") == thread for e in events)
            result = {"auth": "chatgpt", "provider": "openai", "trusted_hooks": len(owned),
                      "status": done["params"]["turn"]["status"], "answer_ok": answers == ["OK"],
                      "usage_event": usage, "tool_calls": any(i.get("type") in
                          ("commandExecution", "mcpToolCall", "dynamicToolCall") for i in items)}
            output = Path(__file__).resolve().parents[1] / "target/subscription-smoke-result.json"
            output.write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result))
            assert result["status"] == "completed" and result["answer_ok"] and usage and not result["tool_calls"]
        finally:
            rpc.close()


if __name__ == "__main__":
    main()
