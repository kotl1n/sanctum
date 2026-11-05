"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter, once } = require("node:events");
const { PassThrough } = require("node:stream");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { Pipe, start } = require("../ui/composer-host.cjs");

function fixture() {
  const child = new EventEmitter();
  child.stdio = [null, null, null, new PassThrough(), new PassThrough()];
  return { child, pipe: new Pipe(child) };
}

test("debug pipe handles fragmented and coalesced messages", async () => {
  const { child, pipe } = fixture();
  const notification = once(child.stdio[3], "data");
  const result = pipe.send("Runtime.evaluate", { expression: "1" }, "own-session");
  const [bytes] = await notification;
  assert.deepEqual(JSON.parse(bytes.toString().slice(0, -1)), {
    id: 1, method: "Runtime.evaluate", params: { expression: "1" }, sessionId: "own-session"
  });
  const seen = [];
  pipe.listeners.push(event => seen.push(event));
  child.stdio[4].write('{"id":1,"res');
  child.stdio[4].write('ult":{"value":42}}\0not-json\0{"method":"event"}\0');
  assert.deepEqual(await result, { value: 42 });
  assert.deepEqual(seen, [{ method: "event" }]);
  assert.equal(pipe.pending.size, 0);
});

test("protocol errors reject without returning provider detail", async () => {
  const { child, pipe } = fixture();
  const result = pipe.send("test");
  child.stdio[4].write('{"id":1,"error":{"message":"private detail"}}\0');
  await assert.rejects(result, { message: "local_debug_command_failed" });
  assert.equal(pipe.pending.size, 0);
});

test("application exit rejects pending and future calls", async () => {
  const { child, pipe } = fixture();
  const first = pipe.send("test");
  child.emit("exit", 1);
  await assert.rejects(first, { message: "application_exited" });
  await assert.rejects(pipe.send("test"), { message: "application_exited" });
  assert.equal(pipe.pending.size, 0);
});

test("spawn failure cleans up the pending debug connection", async () => {
  const app = start({ app: path.join(__dirname, "missing-application"), guard: "unused" });
  await assert.rejects(app.ready, { message: "application_start_failed" });
  assert.equal(app.pipe.pending.size, 0);
  app.stop();
});

test("launcher rejects incomplete and unknown options", () => {
  for (const args of [[], ["--app", "/tmp/app"], ["--unknown", "value"]]) {
    const result = spawnSync(process.execPath, [path.join(__dirname, "../ui/composer-host.cjs"), ...args], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /^Использование:/);
    assert.equal(result.stdout, "");
  }
});
