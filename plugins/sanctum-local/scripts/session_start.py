"""Companion instructions only. This hook is not an interception boundary."""
import json

print(json.dumps({
    "systemMessage": "Sanctum companion loaded. Protection requires a separately configured and verified local gateway.",
    "hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": "If the Sanctum gateway is active, identifiers such as [IP-1], [EMAIL-1], and [SECRET-1] are local privacy placeholders. Preserve them exactly in tool arguments. Do not guess their originals, encode them, or try to read Sanctum connection files, process memory, or vault files. The local gateway restores supported tool arguments. Use structured arguments for secrets containing shell syntax. Text-only mode does not support attachments or hosted tools. Installing this companion does not establish that traffic is routed through Sanctum."
    }
}))
