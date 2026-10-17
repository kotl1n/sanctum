#!/usr/bin/env python3
"""Real app-server + Sanctum stdio adapter; synthetic local model only.

The temporary fake MODEL listens on loopback for the test. Sanctum has no
listener. Nothing is installed in the user's profile and no paid model is used.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = "sanctum-portless@sanctum-portless-dev"


class RPC:
    def __init__(self, command, env, cwd):
        self.process = subprocess.Popen(command, env=env, cwd=cwd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, bufsize=1)
        self.messages = queue.Queue()
        def read():
            for line in self.process.stdout:
                self.messages.put(json.loads(line))
            self.messages.put(None)
        threading.Thread(target=read, daemon=True).start()
        self.next_id = 1
        self.notifications = []

    def next(self, timeout=40):
        message = self.messages.get(timeout=timeout)
        if message is None:
            raise RuntimeError("Backend EOF; raw diagnostics omitted")
        return message

    def request(self, method, params):
        ident = self.next_id
        self.next_id += 1
        self.process.stdin.write(json.dumps({"id": ident, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        while True:
            result = self.next()
            if result.get("id") == ident:
                if "error" in result:
                    raise RuntimeError(f"RPC rejected: {method}: {result['error'].get('message', 'error')}")
                return result["result"]
            self.notifications.append(result)

    def initialize(self):
        self.request("initialize", {"clientInfo": {"name": "sanctum-portless-fixture", "version": "0.1.0"},
                                    "capabilities": {"experimentalApi": True}})
        self.process.stdin.write('{"method":"initialized","params":{}}\n')
        self.process.stdin.flush()

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--native-boundary", action="store_true")
    args = parser.parse_args()
    real = Path(subprocess.check_output(["sh", "-c", 'command -v "$1"', "sh", args.codex], text=True).strip()).resolve()
    bindir = ROOT / "target" / ("release" if args.release else "debug")
    guard = bindir / "sanctum-guard"
    adapter = bindir / "sanctum-codex"
    requests = []
    class Model(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["content-length"])))
            requests.append(request)
            code_mode = any(item.get("type") == "additional_tools" for item in request.get("input", []) if isinstance(item, dict))
            if len(requests) == 1:
                if args.native_boundary:
                    assert code_mode, "Native fixture must exercise the local code-mode host"
                command = "printf '%s' '[IP-1]' > executed.txt; cat sample.txt; cat executed.txt"
                if args.native_boundary:
                    strings=[]
                    def collect(node):
                        if isinstance(node,str): strings.append(node)
                        elif isinstance(node,dict):
                            for value in node.values():collect(value)
                        elif isinstance(node,list):
                            for value in node:collect(value)
                    collect(request)
                    joined="\n".join(strings)
                    startup=re.search(r"NATIVE_STARTUP_HOST\s*=\s*(\[IP-[0-9]+\])",joined)
                    assert startup, "Startup instructions did not reach native filter as aliases"
                    assert "NATIVE_CONFIG_MARKER" in joined, "Config instructions not exercised"
                    assert "NATIVE_SKILL_MARKER" in joined, "Skill metadata not exercised"
                    command += "; printf '%s' '"+startup.group(1)+"' > startup-executed.txt; cat startup-executed.txt"
                if code_mode:
                    item = {"type": "custom_tool_call", "id": "ctc_private_fixture", "call_id": "call_private_fixture", "name": "exec", "namespace": "functions",
                            "input": "const r = await tools.exec_command({cmd: " + json.dumps(command) + "}); text(r);", "status": "completed"}
                else:
                    item = {"type": "function_call", "id": "fc_private_fixture", "call_id": "call_private_fixture", "name": "exec_command",
                            "arguments": json.dumps({"cmd": command}), "status": "completed"}
            else:
                item = {"type": "message", "id": "msg_private_fixture", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": "Private fixture complete.", "annotations": []}]}
            output=[item]
            if args.native_boundary and len(requests)==1:
                output.insert(0,{"type":"reasoning","id":"rs_native_fixture","summary":[{"type":"summary_text","text":"Summary [IP-1]"}],"encrypted_content":"opaque-provider-fixture"})
            response = {"id": f"resp_fixture_{len(requests)}", "object": "response", "status": "completed", "output": output,
                        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
            events = [{"type": "response.created", "response": {"id": response["id"], "status": "in_progress", "output": []}}]
            for index,entry in enumerate(output):
                events += [{"type":"response.output_item.added","output_index":index,"item":entry},
                           {"type":"response.output_item.done","output_index":index,"item":entry}]
            events.append({"type":"response.completed","response":response})
            wire = "".join("data: " + json.dumps(dict(event, sequence_number=i)) + "\n\n" for i, event in enumerate(events)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)
        def log_message(self, *unused):
            pass

    with tempfile.TemporaryDirectory(prefix="sanctum-portless-test-") as temporary:
        temp = Path(temporary)
        home = temp / "codex"
        home.mkdir()
        workspace = temp / "workspace"
        workspace.mkdir()
        state = temp / "state"
        state.mkdir(mode=0o700)
        package = temp / "package"
        env = dict(os.environ, CODEX_HOME=str(home), SANCTUM_STATE_DIR=str(state), SANCTUM_REAL_CODEX=str(real))
        env.pop("SANCTUM_GUARD_POLICY", None)
        env.pop("SANCTUM_NATIVE_REQUIRED",None)
        env.pop("SANCTUM_NATIVE_HELPER",None)
        if args.native_boundary:
            assert subprocess.check_output([str(real),"--sanctum-native-protocol"],text=True).strip()=="sanctum-native-v1"
            env["SANCTUM_NATIVE_REQUIRED"]="1"
            env["SANCTUM_NATIVE_HELPER"]=str(guard)
            subprocess.run(["git","init","-q",str(workspace)],check=True)
            (workspace/"AGENTS.md").write_text("NATIVE_STARTUP_HOST=192.0.2.123\npassword=native-startup-only\n")
            skill=workspace/".agents/skills/native-fixture"
            skill.mkdir(parents=True)
            (skill/"SKILL.md").write_text("---\nname: native-fixture\ndescription: NATIVE_SKILL_MARKER contact skill-contact@example.com\n---\nUse local tools.\n")
        subprocess.run([str(guard), "package-portless", "--output", str(package)], env=env, cwd=temp, check=True, stdout=subprocess.DEVNULL)
        for command in [[str(real), "plugin", "marketplace", "add", str(package), "--json"],
                        [str(real), "plugin", "add", PLUGIN, "--json"]]:
            subprocess.run(command, env=env, cwd=temp, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        installed = home / "plugins/cache/sanctum-portless-dev/sanctum-portless/0.1.0"
        for name in ["bin/sanctum-guard", "bin/sanctum-codex", "hooks/hooks.json"]:
            assert (installed / name).read_bytes() == (package / "plugin" / name).read_bytes()
        rpc = RPC([str(real), "app-server", "--stdio"], env, workspace)
        try:
            rpc.initialize()
            hooks = rpc.request("hooks/list", {"cwds": [str(workspace)]})
        finally:
            rpc.close()
        matching = [h for row in hooks["data"] for h in row["hooks"] if h.get("pluginId") == PLUGIN]
        untrusted = RPC([str(adapter), "app-server", "--stdio"], env, workspace)
        try:
            untrusted.initialize()
            try:
                untrusted.request("thread/start", {"cwd":str(workspace),"ephemeral":True})
                raise AssertionError("Untrusted hooks were accepted")
            except RuntimeError as error:
                assert "Sanctum blocked" in str(error)
        finally:
            untrusted.close()
        assert {h["eventName"] for h in matching} == {"userPromptSubmit", "preToolUse", "postToolUse"}
        with (home / "config.toml").open("a") as config:
            for hook in matching:
                config.write(f'\n[hooks.state.{json.dumps(hook["key"])}]\nenabled = true\ntrusted_hash = {json.dumps(hook["currentHash"])}\n')
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Model)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        config = {
            "model_provider": "private_fixture",
            "model_providers.private_fixture.name": "Synthetic private fixture",
            "model_providers.private_fixture.base_url": f"http://127.0.0.1:{server.server_port}/v1",
            "model_providers.private_fixture.requires_openai_auth": False,
            "model_providers.private_fixture.supports_websockets": args.native_boundary,
            "model_providers.private_fixture.request_max_retries": 0,
            "model_providers.private_fixture.stream_max_retries": 0,
            "web_search": "cached" if args.native_boundary else "disabled", "check_for_update_on_startup": False,
        }
        if args.native_boundary:
            config["developer_instructions"]="NATIVE_CONFIG_MARKER password=native-config-only"
        command = [str(adapter), "app-server", "--stdio"]
        for key, value in config.items():
            command += ["-c", key + "=" + json.dumps(value)]
        rpc = RPC(command, env, workspace)
        try:
            rpc.initialize()
            thread = rpc.request("thread/start", {"cwd": str(workspace), "ephemeral": True, "approvalPolicy": "never", "sandbox": "danger-full-access"})["thread"]["id"]
            (workspace / "sample.txt").write_text("demo@example.com password=fixture-only +7 (999) 123-45-67\n")
            attachment = workspace / "attachment.txt"
            attachment.write_text("Contact attachment@example.com")
            rpc.request("turn/start", {"threadId": thread, "input": [{"type": "text", "text": "Check synthetic host 11.111.111.11"}, {"type":"mention","name":"attachment.txt","path":str(attachment)}]})
            events = list(rpc.notifications)
            deadline = time.monotonic() + 60
            while not any(e.get("method") == "turn/completed" for e in events):
                assert time.monotonic() < deadline, "Turn timed out"
                events.append(rpc.next())
            hook_runs = [e.get("params", {}).get("run", {}) for e in events if e.get("method") == "hook/completed"]
            if not (workspace / "executed.txt").exists():
                # Synthetic fixture diagnostics only; never print user profiles.
                raise AssertionError("Tool did not execute. Synthetic hook runs: " + json.dumps(hook_runs, ensure_ascii=False))
            assert (workspace / "executed.txt").read_text() == "11.111.111.11", "Command did not receive original"
            assert len(requests) == 2, f"Expected prompt and tool follow-up, got {len(requests)}"
            if args.native_boundary:
                assert (workspace/"startup-executed.txt").read_text()=="192.0.2.123", "Native-only alias did not restore for local command"
                replay=[item for item in requests[-1]["input"] if isinstance(item,dict) and item.get("type")=="reasoning"]
                assert replay and replay[0].get("encrypted_content")=="opaque-provider-fixture", "Provider reasoning was not replayed exactly"
                for request in requests:
                    wire=json.dumps(request)
                    for original in ["192.0.2.123","native-startup-only","native-config-only","skill-contact@example.com"]:
                        assert original not in wire, "Implicit context original reached model"

            for index, request in enumerate(requests):
                wire = json.dumps(request, ensure_ascii=False)
                for original in ["11.111.111.11", "demo@example.com", "fixture-only", "+7 (999) 123-45-67", "attachment@example.com"]:
                    if original in wire:
                        def locate(node, path=""):
                            if isinstance(node, dict):
                                for key, val in node.items(): yield from locate(val, path+"/"+key)
                            elif isinstance(node,list):
                                for i,val in enumerate(node):yield from locate(val,path+"/"+str(i))
                            elif isinstance(node,str) and original in node: yield path
                        raise AssertionError(f"Synthetic entity {['11.111.111.11','demo@example.com','fixture-only','+7 (999) 123-45-67','attachment@example.com'].index(original)} reached fake model request {index}; fields: {list(locate(request))}")
            followup = json.dumps(requests[-1])
            for alias in ["[IP-1]", "[EMAIL-1]", "[SECRET-1]", "[PHONE-1]"]:
                assert alias in followup, f"Missing alias {alias} in follow-up"
            assert "[EMAIL-2]" in followup, "New file email did not receive a distinct stable alias"
            for rejected in [{"type":"localImage","path":str(attachment)}, {"type":"audio","url":"https://example.invalid/audio"}]:
                try:
                    rpc.request("turn/start", {"threadId":thread,"input":[rejected]})
                    raise AssertionError("Opaque attachment was accepted")
                except RuntimeError as error:
                    assert "Sanctum blocked" in str(error)
            assert len(requests)==2, "Rejected attachment reached model"
            if args.native_boundary:
                broken_env = dict(env, SANCTUM_NATIVE_HELPER=str(temp / "missing-filter"))
                broken = RPC(command, broken_env, workspace)
                try:
                    broken.initialize()
                    failed_thread = broken.request("thread/start", {"cwd":str(workspace),"ephemeral":True,"approvalPolicy":"never","sandbox":"danger-full-access"})["thread"]["id"]
                    broken.request("turn/start", {"threadId":failed_thread,"input":[{"type":"text","text":"Synthetic boundary failure fixture"}]})
                    failed_events = list(broken.notifications)
                    deadline = time.monotonic() + 60
                    while not any(e.get("method")=="turn/completed" for e in failed_events):
                        assert time.monotonic()<deadline, "Missing-helper test timed out"
                        failed_events.append(broken.next())
                    completed = next(e for e in failed_events if e.get("method")=="turn/completed")
                    assert completed["params"]["turn"]["status"]=="failed", "Missing filter did not fail the turn"
                    assert len(requests)==2, "Missing filter leaked an unfiltered request"
                finally:
                    broken.close()
            descriptor_dir=Path(f"/proc/{rpc.process.pid}/fd")
            if descriptor_dir.is_dir():
                sockets=[]
                for descriptor in descriptor_dir.iterdir():
                    try: sockets.append(os.readlink(descriptor))
                    except OSError: pass
                inodes = {s[8:-1] for s in sockets if s.startswith("socket:[")}
                for table in ["tcp", "tcp6", "udp", "udp6"]:
                    path = Path(f"/proc/{rpc.process.pid}/net/{table}")
                    if path.exists():
                        owned = [line for line in path.read_text().splitlines()[1:] if len(line.split())>9 and line.split()[9] in inodes]
                        assert not owned, "Adapter owns an Internet socket"
                # Tokio may own unnamed Unix socketpairs for its signal driver;
                # these have no listening TCP/UDP address or network port.
            print("PASS: native stdio adapter masked prompt; local command received original; file/tool output reached model as aliases; encrypted vault survived separate hook processes.")
            if args.native_boundary:
                print("PASS: AGENTS/config/skill metadata masked at native request boundary; native-only alias restored locally; encrypted provider reasoning replayed exactly; WebSocket route fell back to filtered HTTP.")
                print("PASS: missing native filter failed the turn without sending any model request.")
            print("Backend:", subprocess.check_output([str(real), "--version"], text=True).strip())
            print("Sanctum listeners: none. Temporary test model requests:", len(requests))
        finally:
            rpc.close()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
