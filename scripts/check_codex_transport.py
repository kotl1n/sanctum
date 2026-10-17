"""Exercise an installed Codex CLI against a fake model through Sanctum.

No real provider credentials are used. Codex itself may make background service
requests independently of its model provider; this test does not intercept them.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sanctum.demo import running
from sanctum.gateway import Gateway, Settings
from sanctum.protocol import dumps


def main():
    executable = shutil.which("codex")
    if not executable:
        raise RuntimeError("Codex CLI is not installed")
    received = []
    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append(request)
            number = len(received)
            if number == 1:
                item = {"type": "custom_tool_call", "id": "ctc_synthetic_1", "call_id": "call_synthetic_1", "name": "exec", "namespace": "functions", "input": 'const r = await tools.exec_command({cmd: "printf \'%s\' \'[IP-1]\'"}); text(r.output.trim() === ["11","111","111","11"].join(".") ? "SANCTUM_ORIGINAL_OK:" + r.output : "SANCTUM_ORIGINAL_MISSING");', "status": "completed"}
            else:
                item = {"type": "message", "id": "msg_synthetic_1", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "Sanctum client transport check complete.", "annotations": []}]}
            response = {"id": f"resp_synthetic_{number}", "object": "response", "status": "completed", "model": request.get("model"), "output": [item], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
            events = [{"type": "response.created", "response": {**response, "status": "in_progress", "output": []}}, {"type": "response.output_item.added", "output_index": 0, "item": {**item, "input": ""} if number == 1 else item}]
            if number == 1:
                events += [{"type": "response.custom_tool_call_input.delta", "item_id": item["id"], "output_index": 0, "delta": item["input"]}, {"type": "response.custom_tool_call_input.done", "item_id": item["id"], "output_index": 0, "input": item["input"]}]
            events += [{"type": "response.output_item.done", "output_index": 0, "item": item}, {"type": "response.completed", "response": response}]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for index, event in enumerate(events):
                event["sequence_number"] = index
                self.wfile.write(f"event: {event['type']}\ndata: {dumps(event)}\n\n".encode())
                self.wfile.flush()

    with tempfile.TemporaryDirectory(prefix="sanctum-client-") as directory, running(ThreadingHTTPServer(("127.0.0.1", 0), Provider)) as upstream:
        key = secrets.token_urlsafe(32)
        settings = Settings(local_key=key, mode="openai", test_upstream=f"http://127.0.0.1:{upstream.server_port}/v1")
        with running(Gateway(("127.0.0.1", 0), settings)) as gateway:
            # Separate Codex configuration/auth directory. No user auth file is
            # copied or read by this harness, and no user settings are changed.
            env = dict(os.environ)
            env.update({"CODEX_HOME": directory, "SANCTUM_TEST_PROVIDER_KEY": "synthetic-provider-key"})
            config = {
                "model_provider": '"sanctum_test"',
                "model_providers.sanctum_test.name": '"Sanctum transport test"',
                "model_providers.sanctum_test.base_url": f'"http://127.0.0.1:{gateway.server_port}/v1"',
                "model_providers.sanctum_test.env_key": '"SANCTUM_TEST_PROVIDER_KEY"',
                "model_providers.sanctum_test.http_headers": f'{{"X-Sanctum-Key"="{key}"}}',
                "model_providers.sanctum_test.supports_websockets": "false",
                "web_search": '"disabled"',
                "check_for_update_on_startup": "false",
                "otel.exporter": '"none"',
            }
            args = [executable, "exec", "--ignore-user-config", "--skip-git-repo-check", "--ephemeral", "--json", "-C", directory, "-s", "read-only"]
            for name, value in config.items():
                args.extend(("-c", f"{name}={value}"))
            args.append("Print synthetic address 11.111.111.11 once using a local command, then finish.")
            result = subprocess.run(args, env=env, input="", capture_output=True, text=True, timeout=30)
            if result.returncode or len(received) != 2:
                print(f"FAIL: client exit={result.returncode}, model requests={len(received)}; diagnostics omitted")
                return 1
            if any("11.111.111.11" in dumps(request) for request in received):
                print("FAIL: synthetic original reached model endpoint")
                return 1
            tool_outputs = [item for item in received[1].get("input", []) if isinstance(item, dict) and item.get("type") in {"function_call_output", "custom_tool_call_output"}]
            if not tool_outputs or "SANCTUM_ORIGINAL_OK:" not in dumps(tool_outputs) or "[IP-1]" not in dumps(tool_outputs) or "unsupported call" in result.stderr or "error" in dumps(tool_outputs).lower():
                print("FAIL: tool execution was not confirmed")
                print(dumps(tool_outputs))
                return 1
            print("PASS: actual Codex CLI -> Sanctum -> fake provider -> streamed code-mode tool -> masked result -> final response.")
            print("Subscription auth and Desktop transport remain unverified. Codex background network paths are outside this test.")
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
