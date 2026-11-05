"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { parseArgs } = require("node:util");

class Pipe {
  constructor(child) {
    this.child = child; this.next = 1; this.pending = new Map(); this.listeners = []; this.buffer = Buffer.alloc(0); this.closed = false;
    child.stdio[4].on("data", chunk => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      let end;
      while ((end = this.buffer.indexOf(0)) >= 0) {
        const raw = this.buffer.subarray(0, end); this.buffer = this.buffer.subarray(end + 1);
        let message; try { message = JSON.parse(raw.toString()); } catch { continue; }
        if (message.id && this.pending.has(message.id)) {
          const waiter = this.pending.get(message.id); this.pending.delete(message.id); clearTimeout(waiter.timer);
          if (message.error) waiter.reject(new Error("local_debug_command_failed")); else waiter.resolve(message.result || {});
        } else for (const listener of this.listeners) Promise.resolve(listener(message)).catch(() => {});
      }
    });
    const close = reason => {
      this.closed = true;
      for (const waiter of this.pending.values()) { clearTimeout(waiter.timer); waiter.reject(new Error(reason)); }
      this.pending.clear();
    };
    child.stdio[3].on("error", () => close("local_debug_pipe_failed"));
    child.stdio[4].on("error", () => close("local_debug_pipe_failed"));
    child.on("error", () => close("application_start_failed"));
    child.on("exit", () => close("application_exited"));
  }
  send(method, params = {}, sessionId) {
    if (this.closed) return Promise.reject(new Error("application_exited"));
    return new Promise((resolve, reject) => {
      const id = this.next++;
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error("local_debug_timeout")); }, 6000);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdio[3].write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + "\0");
    });
  }
}

function localJson(guard, args, text, env) {
  return new Promise(resolve => {
    const child = spawn(guard, args, { env, stdio: ["pipe", "pipe", "ignore"] });
    const chunks = []; let length = 0;
    const timer = setTimeout(() => child.kill(), 5000);
    child.on("error", () => { clearTimeout(timer); resolve(null); });
    child.stdout.on("data", chunk => { length += chunk.length; if (length <= 16 * 1024 * 1024) chunks.push(chunk); else child.kill(); });
    child.on("close", code => { clearTimeout(timer); if (code !== 0) return resolve(null); try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch { resolve(null); } });
    child.stdin.on("error", () => {}); child.stdin.end(text);
  });
}

function ownPage(info) {
  if (info.type !== "page") return false;
  try { const url = new URL(info.url); return url.protocol === "app:" && url.hostname === "-"; } catch { return false; }
}

function start(options) {
  const env = options.env || process.env;
  const child = spawn(options.app, ["--remote-debugging-pipe", ...(options.args || [])], {
    env, detached: Boolean(options.detached), stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"]
  });
  const pipe = new Pipe(child);
  const source = fs.readFileSync(options.source || path.join(__dirname, "composer.js"), "utf8");
  const sessions = new Map(), attached = new Set(), contexts = new Map(), revisions = new Map();
  const latest = new Map();
  let processing = false, stopped = false, configured = false;
  let settingsRevision = 0;
  async function evaluate(session, expression) {
    return pipe.send("Runtime.evaluate", { expression, returnByValue: true }, session);
  }
  async function attach(info) {
    if (!ownPage(info) || attached.has(info.targetId)) return;
    attached.add(info.targetId);
    try {
      const { sessionId } = await pipe.send("Target.attachToTarget", { targetId: info.targetId, flatten: true });
      sessions.set(sessionId, info.targetId);
      await pipe.send("Runtime.enable", {}, sessionId);
      await pipe.send("Page.enable", {}, sessionId);
      await pipe.send("Runtime.addBinding", { name: "__sanctumLocalInspect" }, sessionId);
      await pipe.send("Page.addScriptToEvaluateOnNewDocument", { source }, sessionId);
      await evaluate(sessionId, source);
      await evaluate(sessionId, `window.__sanctumComposer?.enabled(${configured})`);
    } catch { attached.delete(info.targetId); }
  }
  async function processLatest() {
    if (processing || stopped) return;
    processing = true;
    try {
      while (latest.size && !stopped) {
        const [jobKey, job] = latest.entries().next().value; latest.delete(jobKey);
        const result = await localJson(options.guard, ["preview"], job.text, env);
        const key = job.session + ":" + job.editor;
        if (revisions.get(key) !== job.revision) continue;
        const payload = { editor: job.editor, revision: job.revision,
          active: Boolean(result?.active && result?.status === "ready"), spans: result?.spans_utf16 || [] };
        await evaluate(job.session, `window.__sanctumComposer?.apply(${JSON.stringify(payload)})`).catch(() => {});
      }
    } finally { processing = false; }
  }
  pipe.listeners.push(async event => {
    if (event.method === "Target.targetCreated" || event.method === "Target.targetInfoChanged") return attach(event.params.targetInfo);
    if (event.method === "Runtime.executionContextCreated") {
      contexts.set(event.sessionId + ":" + event.params.context.id, event.params.context.origin === "app://-");
      return;
    }
    if (event.method === "Runtime.executionContextsCleared") {
      for (const key of contexts.keys()) if (key.startsWith(event.sessionId + ":")) contexts.delete(key);
      return;
    }
    if (event.method !== "Runtime.bindingCalled" || event.params.name !== "__sanctumLocalInspect"
        || !contexts.get(event.sessionId + ":" + event.params.executionContextId)) return;
    let value; try { value = JSON.parse(event.params.payload); } catch { return; }
    if (!Number.isInteger(value.editor) || !Number.isInteger(value.revision) || typeof value.text !== "string" || Buffer.byteLength(value.text) > 8 * 1024 * 1024) return;
    revisions.set(event.sessionId + ":" + value.editor, value.revision);
    if (latest.size >= 128) latest.clear();
    latest.set(event.sessionId + ":" + value.editor, { session: event.sessionId, ...value });
    processLatest().catch(() => {});
  });
  async function settings() {
    const revision = ++settingsRevision;
    const value = await localJson(options.guard, ["settings"], "", env);
    if (revision !== settingsRevision || stopped) return;
    configured = Boolean(value?.active);
    for (const session of sessions.keys()) await evaluate(session, `window.__sanctumComposer?.enabled(${configured})`).catch(() => {});
  }
  const ready = pipe.send("Target.setDiscoverTargets", { discover: true })
    .then(() => pipe.send("Target.getTargets"))
    .then(async result => { await settings(); for (const info of result.targetInfos || []) await attach(info); });
  ready.catch(() => {});
  const watch = options.settings || env.SANCTUM_SETTINGS_PATH;
  if (watch) fs.watchFile(watch, { interval: 700, persistent: false }, () => settings().catch(() => {}));
  function cleanup() { stopped = true; latest.clear(); if (watch) fs.unwatchFile(watch); }
  child.on("exit", cleanup);
  child.on("error", cleanup);
  return { child, pipe, sessions, ready, evaluate,
    diagnostics() { return { sessions:sessions.size, contexts:contexts.size, ownContexts:[...contexts.values()].filter(Boolean).length }; }, stop() {
    cleanup(); try { if (options.detached && process.platform !== "win32") process.kill(-child.pid, "SIGTERM"); else child.kill(); } catch {}
  }};
}

module.exports = { start, Pipe };
if (require.main === module) {
  try {
    const argv = process.argv.slice(2); const separator = argv.indexOf("--");
    const own = separator < 0 ? argv : argv.slice(0, separator); const args = separator < 0 ? [] : argv.slice(separator + 1);
    const { values } = parseArgs({ args: own, options: { app: { type: "string" }, guard: { type: "string" }, settings: { type: "string" } } });
    if (!values.app || !values.guard) throw new Error("arguments_required");
    const app = start({ ...values, args });
    process.on("SIGTERM", () => app.stop()); process.on("SIGINT", () => app.stop());
    app.child.on("error", () => { process.stderr.write("Sanctum: не удалось запустить приложение (application_start_failed)\n"); process.exitCode = 1; });
    app.child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
  } catch {
    process.stderr.write("Использование: composer-host.cjs --app ПУТЬ --guard ПУТЬ [--settings ПУТЬ] -- [аргументы приложения]\n");
    process.exitCode = 1;
  }
}
