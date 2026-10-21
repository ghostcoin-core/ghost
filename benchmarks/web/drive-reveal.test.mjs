// Tests for drive-reveal.mjs against a fake DevTools server: a local HTTP
// server for /json/version and a minimal WebSocket stub that answers the
// protocol commands the driver sends and plays a page that runs one session.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const DRIVER = path.join(path.dirname(fileURLToPath(import.meta.url)), "drive-reveal.mjs");
const OWN_TAB = "driver-tab-1";
const USER_TAB = "user-tab-0";
const PAGE_SESSION = "page-session-1";
const WORKER_SESSION = "worker-session-1";

function readFrame(buf) {
  if (buf.length < 2) return null;
  const opcode = buf[0] & 0x0f;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f;
  let off = 2;
  if (len === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    off = 4;
  } else if (len === 127) {
    if (buf.length < 10) return null;
    len = Number(buf.readBigUInt64BE(2));
    off = 10;
  }
  const maskOff = off;
  if (masked) off += 4;
  if (buf.length < off + len) return null;
  const payload = Buffer.from(buf.subarray(off, off + len));
  if (masked) for (let i = 0; i < len; i += 1) payload[i] ^= buf[maskOff + (i % 4)];
  return { opcode, payload, size: off + len };
}

function frame(opcode, payload) {
  const len = payload.length;
  let head;
  if (len < 126) {
    head = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode;
    head[1] = 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, payload]);
}

// The fake browser: one tab of the user's already open, the tab the driver
// creates, and a page whose session finishes on the second poll after start.
function fakeBrowser() {
  const state = { messages: [], targets: new Set([USER_TAB]), closed: [], created: [] };
  let started = false;
  let pollsAfterStart = 0;
  let deviceClass = null;

  const record = () => ({
    device_class: deviceClass,
    session: 0,
    statement: "coin-reveal",
    run_index: 0,
    run_kind: "cold",
    proving_ms: 1234.5,
    verified: true,
    outcome: "completed",
  });

  function answer(msg, send) {
    const reply = (result) => send({ id: msg.id, sessionId: msg.sessionId, result });
    const p = msg.params ?? {};
    switch (msg.method) {
      case "Target.createTarget":
        state.targets.add(OWN_TAB);
        state.created.push(OWN_TAB);
        return reply({ targetId: OWN_TAB });
      case "Target.attachToTarget":
        return reply({ sessionId: PAGE_SESSION });
      case "Target.closeTarget":
        state.closed.push(p.targetId);
        state.targets.delete(p.targetId);
        return reply({ success: true });
      case "Target.setAutoAttach":
      case "Emulation.setCPUThrottlingRate":
      case "Network.enable":
      case "Network.emulateNetworkConditions":
      case "Page.enable":
      case "Runtime.runIfWaitingForDebugger":
        return reply({});
      case "Page.navigate":
        return reply({ frameId: "frame-1" });
      case "Runtime.evaluate": {
        const expr = p.expression;
        if (expr.startsWith("/*drive:probe*/")) {
          if (started) pollsAfterStart += 1;
          const done = started && pollsAfterStart >= 2;
          const value = JSON.stringify({ ready: true, status: done ? "session complete" : "running…", done, ok: done });
          return reply({ result: { type: "string", value } });
        }
        if (expr.startsWith("/*drive:start*/")) {
          started = true;
          deviceClass = JSON.parse(expr.slice(expr.lastIndexOf("})(") + 3, -1)).device;
          reply({ result: { type: "boolean", value: true } });
          // The page starts its prover worker, which Chrome attaches paused.
          return send({
            method: "Target.attachedToTarget",
            sessionId: PAGE_SESSION,
            params: {
              sessionId: WORKER_SESSION,
              targetInfo: { targetId: "worker-1", type: "worker", url: "reveal-worker.js" },
              waitingForDebugger: true,
            },
          });
        }
        if (expr.startsWith("/*drive:records*/")) {
          return reply({ result: { type: "string", value: JSON.stringify(record()) } });
        }
        return send({ id: msg.id, error: { code: -32000, message: "unexpected expression" } });
      }
      default:
        return send({ id: msg.id, sessionId: msg.sessionId, error: { code: -32601, message: `'${msg.method}' wasn't found` } });
    }
  }

  const sockets = new Set();
  const server = http.createServer((req, res) => {
    if (req.url === "/json/version") {
      const { port } = server.address();
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ Browser: "FakeChrome/1.0", webSocketDebuggerUrl: `ws://127.0.0.1:${port}/devtools/browser/fake` }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  server.on("upgrade", (req, socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    const accept = createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    const send = (obj) => socket.write(frame(1, Buffer.from(JSON.stringify(obj))));
    let buf = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (let f = readFrame(buf); f; f = readFrame(buf)) {
        buf = buf.subarray(f.size);
        if (f.opcode === 8) {
          socket.end(frame(8, Buffer.alloc(0)));
        } else if (f.opcode === 9) {
          socket.write(frame(10, f.payload));
        } else if (f.opcode === 1) {
          const msg = JSON.parse(f.payload.toString("utf8"));
          state.messages.push(msg);
          answer(msg, send);
        }
      }
    });
  });
  return {
    state,
    listen: () => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`))),
    stop: () => new Promise((resolve) => {
      for (const s of sockets) s.destroy();
      server.close(() => resolve());
    }),
  };
}

function run(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [DRIVER, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

let outDir;
before(async () => {
  outDir = await mkdtemp(path.join(os.tmpdir(), "drive-reveal-"));
});
after(async () => {
  await rm(outDir, { recursive: true, force: true });
});

async function driveOnce(mode, dir) {
  const fake = fakeBrowser();
  const endpoint = await fake.listen();
  try {
    const result = await run([
      "--devtools", endpoint,
      "--page", "http://localhost:8000/reveal.html",
      "--sessions", "1",
      "--mode", mode,
      "--warm", "0",
      "--rest", "0",
      "--poll-ms", "10",
      "--timeout", "30",
      "--out", dir,
    ]);
    return { ...result, state: fake.state };
  } finally {
    await fake.stop();
  }
}

test("--help prints usage and exits 0", async () => {
  const { code, stdout } = await run(["--help"]);
  assert.equal(code, 0);
  assert.match(stdout, /^Usage: node benchmarks\/web\/drive-reveal\.mjs/);
  assert.match(stdout, /--mode MODE/);
});

test("bad arguments exit non-zero with one line", async () => {
  for (const args of [
    ["--devtools", "http://127.0.0.1:9222", "--page", "http://localhost:8000/reveal.html", "--sessions", "1", "--mode", "tablet"],
    ["--devtools", "http://127.0.0.1:9222", "--page", "http://localhost:8000/reveal.html", "--sessions", "0", "--mode", "phone"],
    ["--page", "http://localhost:8000/reveal.html", "--sessions", "1", "--mode", "phone"],
    ["--bogus"],
  ]) {
    const { code, stdout, stderr } = await run(args);
    assert.notEqual(code, 0, args.join(" "));
    assert.equal(stdout, "");
    assert.equal(stderr.trimEnd().split("\n").length, 1, stderr);
    assert.match(stderr, /^drive-reveal: /);
  }
});

test("phone: opens its own tab, throttles 4x, collects one result and closes only its tab", async () => {
  const dir = path.join(outDir, "phone");
  const { code, stderr, state } = await driveOnce("phone", dir);
  assert.equal(code, 0, stderr);

  assert.deepEqual(state.created, [OWN_TAB]);
  assert.deepEqual(state.closed, [OWN_TAB]);
  assert.ok(state.targets.has(USER_TAB), "the user's tab is still open");
  const methods = state.messages.map((m) => m.method);
  assert.ok(!methods.some((m) => m.startsWith("Browser.")), `no browser-wide command: ${methods}`);
  assert.ok(methods.indexOf("Target.closeTarget") > methods.lastIndexOf("Runtime.evaluate"), "the tab is closed after the results are read");

  const throttles = state.messages.filter((m) => m.method === "Emulation.setCPUThrottlingRate");
  assert.deepEqual(
    throttles.map((m) => [m.sessionId, m.params.rate]),
    [[PAGE_SESSION, 4], [WORKER_SESSION, 4]],
  );
  const firstEvaluate = state.messages.findIndex((m) => m.method === "Runtime.evaluate");
  const navigate = state.messages.findIndex((m) => m.method === "Page.navigate");
  assert.ok(state.messages.indexOf(throttles[0]) < navigate && navigate < firstEvaluate, "throttled before the page loads");
  assert.equal(state.messages[navigate].params.url, "http://localhost:8000/reveal.html");
  assert.ok(state.messages.some((m) => m.method === "Runtime.runIfWaitingForDebugger" && m.sessionId === WORKER_SESSION), "the paused worker is resumed");

  const network = state.messages.find((m) => m.method === "Network.emulateNetworkConditions");
  assert.deepEqual(network.params, { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  assert.equal(network.sessionId, PAGE_SESSION);

  const start = state.messages.find((m) => m.method === "Runtime.evaluate" && m.params.expression.startsWith("/*drive:start*/"));
  assert.match(start.params.expression, /"device":"emulated-phone"/);
  assert.match(start.params.expression, /"session":0/);

  assert.deepEqual(await readdir(dir), ["emulated-phone-coin-reveal-session0.jsonl"]);
  const text = await readFile(path.join(dir, "emulated-phone-coin-reveal-session0.jsonl"), "utf8");
  assert.ok(text.endsWith("\n"));
  const lines = text.trimEnd().split("\n");
  assert.equal(lines.length, 1);
  const r = JSON.parse(lines[0]);
  assert.equal(r.device_class, "emulated-phone");
  assert.equal(r.session, 0);
  assert.equal(r.run_kind, "cold");
  assert.equal(r.proving_ms, 1234.5);
  assert.equal(r.outcome, "completed");
  assert.equal(r.cpu_throttling_rate_applied, 4);
  assert.equal(r.cpu_throttling_worker, true);
  assert.match(r.cpu_throttling, /^4x CPU throttling by DevTools Emulation\.setCPUThrottlingRate/);
  assert.match(r.network_conditions, /^none/);
  assert.match(r.driver, /drive-reveal\.mjs/);
});

test("desktop: no throttling (rate 1) and records for the Mac Studio", async () => {
  const dir = path.join(outDir, "desktop");
  const { code, stderr, state } = await driveOnce("desktop", dir);
  assert.equal(code, 0, stderr);
  const rates = state.messages.filter((m) => m.method === "Emulation.setCPUThrottlingRate").map((m) => m.params.rate);
  assert.deepEqual(rates, [1, 1]);
  assert.deepEqual(state.closed, [OWN_TAB]);
  const r = JSON.parse(await readFile(path.join(dir, "mac-studio-coin-reveal-session0.jsonl"), "utf8"));
  assert.equal(r.device_class, "mac-studio");
  assert.equal(r.cpu_throttling, "none");
  assert.equal(r.cpu_throttling_rate_applied, 1);
});
