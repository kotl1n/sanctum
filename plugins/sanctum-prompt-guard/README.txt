Sanctum Prompt Guard 0.1.0 — standalone native Linux plugin

Checks the typed prompt when you submit it. No local server or gateway is used.

Install this marketplace root:
  codex plugin marketplace add /absolute/path/to/this/folder
  codex plugin add sanctum-prompt-guard@sanctum-guard-dev

Restart the app and review/trust the UserPromptSubmit hook using Codex's normal
hook controls (/hooks in the CLI). Untrusted hooks are skipped by Codex.

Detected IPs, emails, recognized keys and labelled secrets cause a block.
The warning lists only categories and counts; it omits the original values.
Clean prompts are allowed. Fix the text manually and submit it again.
There is no in-composer highlighting or automatic replacement.

Optional: set SANCTUM_GUARD_POLICY to a private JSON policy file containing
{"literals":["your-known-secret"],"max_entries":10000} in the app environment.
The default policy.json contains no custom secrets. Native detectors stay active.

This covers typed prompts only, not later file reads, tool results, attachments,
other hooks, client transcripts, analytics, sync or arbitrary network traffic.
Not every kind of sensitive data can be detected. A missing, untrusted, disabled,
crashed or timed-out hook is subject to Codex runtime behaviour; this plugin
does not enforce runtime policy or prevent deliberate bypass.

No real credentials are included in this package. Built for Linux x86_64.
