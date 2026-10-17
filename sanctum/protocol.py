"""Text-only Responses transport policy and local tool argument restoration."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

from .redaction import Redactor, RedactionError, TOKEN

MAX_EVENT = 4 * 1024 * 1024
SHELL_TOOLS = {"shell", "shell_command", "exec_command", "write_stdin", "Bash", "bash", "terminal"}
SAFE_SHELL_VALUE = re.compile(r"[A-Za-z0-9_./:@%+,=-]+\Z")
BLOCKED_TYPES = {"input_image", "input_file", "input_audio", "image", "file", "audio", "video"}
BLOCKED_FIELDS = {"image_url", "file_data", "file_id", "file_url", "audio", "input_audio", "video", "mcp_servers"}


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


class Session:
    def __init__(self, redactor: Redactor):
        self.redactor = redactor
        self.opaque: set[str] = set()

    def remember_opaque(self, value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "encrypted_content" and isinstance(item, str):
                    if len(self.opaque) >= 10000:
                        raise RedactionError("Opaque replay capacity exceeded")
                    self.opaque.add(hashlib.sha256(item.encode()).hexdigest())
                else:
                    self.remember_opaque(item)
        elif isinstance(value, list):
            for item in value:
                self.remember_opaque(item)

    def request(self, payload: dict) -> dict:
        if payload.get("background") or payload.get("previous_response_id") or payload.get("conversation"):
            raise RedactionError("Only stateless text requests with replayed input are supported")
        # Remote/hosted tools can fetch content outside this gateway's inspection.
        def tools(items):
            if not isinstance(items, list):
                raise RedactionError("Invalid tools")
            for tool in items:
                if not isinstance(tool, dict):
                    raise RedactionError("Invalid tool")
                kind = tool.get("type")
                if kind == "namespace":
                    tools(tool.get("tools"))
                elif kind not in {"function", "custom"}:
                    raise RedactionError("Hosted tools are disabled in text-only mode")
        tools(payload.get("tools", []))
        saved: dict[str, str] = {}

        def inspect(value):
            if isinstance(value, dict):
                if value.get("type") in BLOCKED_TYPES or BLOCKED_FIELDS.intersection(value):
                    raise RedactionError("Attachments and remote content are disabled in text-only mode")
                if value.get("type") == "additional_tools":
                    tools(value.get("tools"))
                for key, item in value.items():
                    if key == "encrypted_content" and item is not None:
                        if not isinstance(item, str) or hashlib.sha256(item.encode()).hexdigest() not in self.opaque:
                            raise RedactionError("Unrecognized opaque content; request blocked")
                        # Keep provider-generated encrypted reasoning byte-identical.
                        marker = f"__SANCTUM_OPAQUE_{len(saved)}__"
                        saved[marker] = item
                        value[key] = marker
                    else:
                        inspect(item)
            elif isinstance(value, list):
                for item in value:
                    inspect(item)

        result = copy.deepcopy(payload)
        inspect(result)
        self.redactor.reserve(result)
        # First pass discovers labelled secrets across the entire request;
        # second pass also catches earlier unlabelled occurrences of them.
        result = self.redactor.value(self.redactor.value(result))

        def put_back(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "encrypted_content" and item is not None:
                        if not isinstance(item, str) or item not in saved:
                            raise RedactionError("Opaque replay marker changed during redaction")
                        value[key] = saved[item]
                    else:
                        put_back(item)
            elif isinstance(value, list):
                for item in value:
                    put_back(item)
        put_back(result)
        # Retention control applies to API mode too; ChatGPT requests already
        # use this value. Authentication is outside payload pseudonymization.
        result["store"] = False
        return result

    def _restore_value(self, value: Any, *, shell: bool = False) -> Any:
        if isinstance(value, str):
            originals = self.redactor.export()
            for match in TOKEN.finditer(value):
                original = originals.get(match.group())
                if original is None:
                    if self.redactor.is_literal_token(match.group()):
                        continue
                    raise RedactionError("Model returned an unknown placeholder")
                if shell and not SAFE_SHELL_VALUE.fullmatch(original):
                    raise RedactionError("Unsafe shell interpolation; use a structured local tool")
            return self.redactor.restore(value)
        if isinstance(value, list):
            return [self._restore_value(item, shell=shell) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                restored_key = self._restore_value(key, shell=shell)
                if restored_key in result:
                    raise RedactionError("Restored argument key collision")
                code_field = key.lower() in {"cmd", "command", "code", "chars", "script", "source", "expression"}
                result[restored_key] = self._restore_value(item, shell=shell or code_field)
            return result
        return value

    def arguments(self, arguments: str, name: str) -> str:
        try:
            value = json.loads(arguments)
        except (ValueError, RecursionError):
            raise RedactionError("Invalid function arguments from provider") from None
        # Code execution tools can execute shell/code indirectly. For all code
        # carrying tools, reject unsafe originals rather than guessing quoting.
        shell = name in SHELL_TOOLS or any(x in name.lower() for x in ("exec", "shell", "python", "javascript", "evaluate"))
        return dumps(self._restore_value(value, shell=shell))

    def item(self, item: dict) -> dict:
        result = copy.deepcopy(item)
        kind = result.get("type")
        if kind == "function_call":
            args = result.get("arguments", "")
            if args:
                result["arguments"] = self.arguments(args, result.get("name", ""))
        elif kind == "custom_tool_call":
            name = result.get("name")
            if name not in {"apply_patch", "exec"} and TOKEN.search(result.get("input", "")):
                raise RedactionError("Placeholder restoration is unsupported for this custom tool")
            result["input"] = self._restore_value(result.get("input", ""), shell=name == "exec")
        return result

    def response(self, payload: dict) -> dict:
        self.remember_opaque(payload)
        result = copy.deepcopy(payload)
        if isinstance(result.get("output"), list):
            result["output"] = [self.item(item) for item in result["output"]]
        return result


class ResponseStream:
    """Preserve text SSE. Buffer only tool argument deltas until valid JSON.

    Emit empty intermediate argument deltas, then the complete restored JSON
    delta at *.done. This handles tokens and JSON escapes split across packets.
    """

    def __init__(self, session: Session):
        self.session = session
        self.names: dict[str, str] = {}
        self.pending: dict[str, list[str]] = {}
        self.pending_sizes: dict[str, int] = {}
        self.sequence = 0

    def event(self, data: dict) -> list[dict]:
        self.session.remember_opaque(data)
        kind = data.get("type", "")
        result = copy.deepcopy(data)
        output = [result]
        if kind == "response.output_item.added":
            item = result.get("item", {})
            self.names[item.get("id", "")] = item.get("name", "")
            result["item"] = self.session.item(item)
        elif kind in {"response.function_call_arguments.delta", "response.custom_tool_call_input.delta"}:
            item_id = result["item_id"]
            delta = result.get("delta", "")
            self.pending_sizes[item_id] = self.pending_sizes.get(item_id, 0) + len(delta.encode())
            if self.pending_sizes[item_id] > MAX_EVENT:
                raise RedactionError("Tool argument stream exceeds local limit")
            self.pending.setdefault(item_id, []).append(delta)
            result["delta"] = ""
        elif kind in {"response.function_call_arguments.done", "response.custom_tool_call_input.done"}:
            item_id = result["item_id"]
            field = "arguments" if "function_call" in kind else "input"
            complete = result.get(field, "".join(self.pending.get(item_id, [])))
            name = self.names.get(item_id, result.get("name", ""))
            if field == "arguments":
                restored = self.session.arguments(complete, name)
            else:
                restored = self.session.item({"type": "custom_tool_call", "name": name, "input": complete})["input"]
            result[field] = restored
            delta = {k: v for k, v in result.items() if k not in {field, "name"}}
            delta["type"] = kind.removesuffix(".done") + ".delta"
            delta["delta"] = restored
            output = [delta, result]
            self.pending.pop(item_id, None)
            self.pending_sizes.pop(item_id, None)
        elif kind == "response.output_item.done":
            result["item"] = self.session.item(result["item"])
        elif isinstance(result.get("response"), dict):
            result["response"] = self.session.response(result["response"])
        for event in output:
            if "sequence_number" in event:
                event["sequence_number"] = self.sequence
                self.sequence += 1
        return output

    def frames(self, source):
        lines: list[bytes] = []
        size = 0
        terminal = False
        for line in source:
            size += len(line)
            if size > MAX_EVENT:
                raise RedactionError("Provider event exceeds local limit")
            if line.rstrip(b"\r\n"):
                lines.append(line.rstrip(b"\r\n"))
                continue
            if not lines:
                yield b": keepalive\n\n"
                size = 0
                continue
            data = b"\n".join(x[5:].lstrip(b" ") for x in lines if x.startswith(b"data:"))
            if not data or data == b"[DONE]":
                yield b"\n".join(lines) + b"\n\n"
            else:
                try:
                    payload = json.loads(data)
                    if not isinstance(payload, dict):
                        raise ValueError()
                except (ValueError, UnicodeError, RecursionError):
                    raise RedactionError("Invalid provider SSE event") from None
                if payload.get("type") in {"response.completed", "response.failed", "response.incomplete", "error"}:
                    terminal = True
                for event in self.event(payload):
                    # The JSON type is authoritative; event labels must match
                    # synthetic argument delta events as well.
                    event_type = event.get("type", "message")
                    yield f"event: {event_type}\ndata: {dumps(event)}\n\n".encode()
            lines, size = [], 0
        if lines or self.pending or not terminal:
            raise RedactionError("Incomplete provider stream")
