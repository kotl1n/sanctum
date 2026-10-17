"""Optional standalone blocking hook. Not enabled by the companion plugin.

UserPromptSubmit can reject a prompt, but cannot replace it with sanitized text.
Do not enable this guard when you expect transparent raw prompt redaction.
"""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sanctum.redaction import Policy, Redactor

try:
    data = json.loads(sys.stdin.read(8 * 1024 * 1024))
    if data.get("hook_event_name") != "UserPromptSubmit" or not isinstance(data.get("prompt"), str):
        raise ValueError()
    engine = Redactor(Policy.load(os.environ.get("SANCTUM_POLICY")))
    engine.text(data["prompt"])
    if engine.counts:
        print(json.dumps({"decision": "block", "reason": "Sanctum detected sensitive text. Configure the local gateway or sanitize locally before resubmitting. Original content omitted."}))
except Exception:
    print(json.dumps({"decision": "block", "reason": "Sanctum could not inspect this prompt. Request blocked; content omitted."}))
