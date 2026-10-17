"""Offline integration demonstration using synthetic data, no provider calls."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import shlex
import subprocess
import threading
import urllib.request

from .gateway import Gateway, Settings
from .protocol import dumps


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def run():
    received = []
    class FakeProvider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append(request)
            if len(received) == 1:
                item = {"type": "function_call", "id": "fc_demo", "call_id": "call_demo", "name": "exec_command", "arguments": ""}
                args = dumps({"cmd": "printf '%s' '[IP-1]'"})
                events = [{"type": "response.output_item.added", "output_index": 0, "item": item}]
                # Intentionally split the placeholder across stream events.
                events += [{"type": "response.function_call_arguments.delta", "item_id": "fc_demo", "output_index": 0, "delta": x} for x in (args[:23], args[23:26], args[26:])]
                events += [{"type": "response.function_call_arguments.done", "item_id": "fc_demo", "output_index": 0, "arguments": args}, {"type": "response.output_item.done", "output_index": 0, "item": {**item, "arguments": args}}, {"type": "response.completed", "response": {"id": "resp_demo", "output": [{**item, "arguments": args}]}}]
            else:
                events = [{"type": "response.completed", "response": {"id": "resp_final", "output": [{"type": "message", "content": [{"type": "output_text", "text": "Local tool returned [IP-1]."}]}]}}]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for index, event in enumerate(events):
                event["sequence_number"] = index
                self.wfile.write(f"event: {event['type']}\ndata: {dumps(event)}\n\n".encode())
                self.wfile.flush()

    with running(ThreadingHTTPServer(("127.0.0.1", 0), FakeProvider)) as upstream:
        key = secrets.token_urlsafe(32)
        settings = Settings(local_key=key, test_upstream=f"http://127.0.0.1:{upstream.server_port}/backend-api/codex")
        with running(Gateway(("127.0.0.1", 0), settings)) as gateway:
            url = f"http://127.0.0.1:{gateway.server_port}/backend-api/codex/responses"
            def send(payload):
                req = urllib.request.Request(url, data=dumps(payload).encode(), headers={"Content-Type": "application/json", "Authorization": "Bearer synthetic-demo-credential", "X-Sanctum-Key": key, "session_id": "synthetic-demo-session"})
                with urllib.request.urlopen(req, timeout=5) as response:
                    return [json.loads(line[6:]) for line in response.read().decode().splitlines() if line.startswith("data: ")]
            original = "Server 11.111.111.11, email demo@example.com, password=demo-secret-value"
            events = send({"model": "synthetic-model", "stream": True, "input": original})
            call = next(e["item"] for e in events if e["type"] == "response.output_item.done")
            command = json.loads(call["arguments"])["cmd"]
            argv = shlex.split(command)
            if argv != ["printf", "%s", "11.111.111.11"]:
                raise RuntimeError("Unexpected demo command")
            # Execute exactly this allowlisted, synthetic argv. No shell.
            output = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
            send({"model": "synthetic-model", "stream": True, "input": [{"type": "function_call_output", "call_id": "call_demo", "output": output}]})
            for request in received:
                wire = dumps(request)
                if any(secret in wire for secret in ("11.111.111.11", "demo@example.com", "demo-secret-value")):
                    raise RuntimeError("Demo detected a leak")
            print("OFFLINE DEMO — synthetic data, fake provider, no OpenAI request")
            print("1. Provider received:", received[0]["input"])
            print("2. Local tool executed:", command)
            print("3. Local tool returned:", output)
            print("4. Follow-up provider received:", received[1]["input"][0]["output"])
            print("PASS: originals stayed local across both requests; streamed tool arguments restored.")
