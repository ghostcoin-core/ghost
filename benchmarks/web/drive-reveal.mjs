#!/usr/bin/env node
// Session driver for the real coin reveal benchmark (reveal.html), over the
// Chrome DevTools Protocol. It talks to a Chrome the operator started with
// --remote-debugging-port: it never launches a browser, and it closes only
// the tabs it opened itself. Each session runs in a fresh tab with Chrome's
// own CPU throttling (1x on the desktop, 4x for the emulated phone) and with
// network emulation cleared; the records the page produces are written as
// JSON lines, one file per session, in the format of
// docs/benchmarks/reveal-results/. Node 22 or later, no dependencies: the
// built-in fetch and WebSocket.

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const USAGE = `Usage: node benchmarks/web/drive-reveal.mjs --devtools URL --page URL --sessions N --mode desktop|phone [options]

Runs N sessions of the coin reveal benchmark, each in a fresh Chrome tab opened
over the DevTools protocol, and writes each session's records as JSON lines to
<out>/<device>-coin-reveal-session<n>.jsonl.

Required:
  --devtools URL     Chrome's DevTools endpoint: http://host:port of a Chrome
                     started with --remote-debugging-port, or its
                     ws://.../devtools/browser/... URL
  --page URL         the page to measure, e.g. http://localhost:8000/reveal.html
  --sessions N       number of sessions to run, one fresh tab each
  --mode MODE        desktop (Mac Studio, no CPU throttling) or phone
                     (emulated mid-range phone, Chrome CPU throttling 4x)

Options:
  --first-session K  number of the first session (default 0)
  --warm W           warm runs per session after the cold run (default 10)
  --commit SHA       repository commit written into every record (default unknown)
  --out DIR          directory for the record files (default .)
  --proofs           also write <device>-coin-reveal-session<n>.proofs for
                     ghost-reveal-verify
  --rest S           seconds of rest before every session after the first (default 180)
  --timeout S        seconds allowed for one session (default 1800)
  --poll-ms MS       how often the page is polled for its results (default 1000)
  -h, --help         print this help and exit

The driver never launches or closes the browser and never touches tabs it did
not open. Start Chrome yourself, for instance with a fresh profile:
  chrome --remote-debugging-port=9222 --user-data-dir=$(mktemp -d)`;

const MODES = {
  desktop: { deviceClass: "mac-studio", cpuRate: 1 },
  phone: { deviceClass: "emulated-phone", cpuRate: 4 },
};

// Nothing but the CPU is changed for the emulated phone (see
// docs/benchmarks/plan.md): network emulation is set to no latency and no
// throughput limit in both modes, so a leftover setting cannot slow the page.
const NETWORK_CONDITIONS = { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 };
const NETWORK_DESCRIPTION = "none: DevTools network emulation cleared (no latency, no throughput limit)";
const DRIVER = "benchmarks/web/drive-reveal.mjs over the Chrome DevTools Protocol; one fresh tab per session";

class UsageError extends Error {}

function positiveInt(name, text, min) {
  if (!/^\d+$/.test(text ?? "")) throw new UsageError(`--${name} must be a whole number, got ${JSON.stringify(text)}`);
  const n = Number(text);
  if (n < min) throw new UsageError(`--${name} must be at least ${min}, got ${n}`);
  return n;
}

function url(name, text, protocols) {
  let u;
  try {
    u = new URL(text);
  } catch {
    throw new UsageError(`--${name} is not a URL: ${JSON.stringify(text)}`);
  }
  if (!protocols.includes(u.protocol)) throw new UsageError(`--${name} must be a ${protocols.join(" or ")} URL, got ${u.protocol}`);
  return u.href;
}

export function parseOptions(argv) {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        devtools: { type: "string" },
        page: { type: "string" },
        sessions: { type: "string" },
        mode: { type: "string" },
        "first-session": { type: "string", default: "0" },
        warm: { type: "string", default: "10" },
        commit: { type: "string", default: "unknown" },
        out: { type: "string", default: "." },
        proofs: { type: "boolean", default: false },
        rest: { type: "string", default: "180" },
        timeout: { type: "string", default: "1800" },
        "poll-ms": { type: "string", default: "1000" },
        help: { type: "boolean", short: "h", default: false },
      },
    }));
  } catch (err) {
    throw new UsageError(err.message.split("\n")[0]);
  }
  if (values.help) return { help: true };
  for (const name of ["devtools", "page", "sessions", "mode"]) {
    if (values[name] === undefined) throw new UsageError(`--${name} is required (see --help)`);
  }
  if (!Object.hasOwn(MODES, values.mode)) throw new UsageError(`--mode must be desktop or phone, got ${JSON.stringify(values.mode)}`);
  return {
    help: false,
    devtools: url("devtools", values.devtools, ["http:", "https:", "ws:", "wss:"]),
    page: url("page", values.page, ["http:", "https:", "file:"]),
    sessions: positiveInt("sessions", values.sessions, 1),
    mode: values.mode,
    firstSession: positiveInt("first-session", values["first-session"], 0),
    warm: positiveInt("warm", values.warm, 0),
    commit: values.commit,
    out: values.out,
    proofs: values.proofs,
    restMs: positiveInt("rest", values.rest, 0) * 1000,
    timeoutMs: positiveInt("timeout", values.timeout, 1) * 1000,
    pollMs: positiveInt("poll-ms", values["poll-ms"], 1),
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A DevTools protocol connection to the browser target, with flattened
// sessions for the tabs and workers it attaches to.
class Cdp {
  static async connect(endpoint) {
    let wsUrl = endpoint;
    if (/^https?:/.test(endpoint)) {
      const res = await fetch(new URL("json/version", endpoint.endsWith("/") ? endpoint : `${endpoint}/`));
      if (!res.ok) throw new Error(`DevTools endpoint answered ${res.status} for /json/version`);
      wsUrl = (await res.json()).webSocketDebuggerUrl;
      if (!wsUrl) throw new Error("DevTools endpoint gave no webSocketDebuggerUrl");
    }
    if (typeof WebSocket !== "function") throw new Error("this Node has no built-in WebSocket: use Node 22 or later");
    const ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener("open", resolve, { once: true });
      ws.addEventListener("error", () => reject(new Error(`cannot connect to ${wsUrl}`)), { once: true });
    });
    return new Cdp(ws);
  }

  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Set();
    ws.addEventListener("message", (ev) => this.onMessage(ev.data));
    ws.addEventListener("close", () => {
      for (const { reject } of this.pending.values()) reject(new Error("DevTools connection closed"));
      this.pending.clear();
    });
  }

  onMessage(data) {
    const msg = JSON.parse(typeof data === "string" ? data : Buffer.from(data).toString("utf8"));
    if (msg.id !== undefined) {
      const waiter = this.pending.get(msg.id);
      if (!waiter) return;
      this.pending.delete(msg.id);
      if (msg.error) waiter.reject(new Error(`${waiter.method}: ${msg.error.message}`));
      else waiter.resolve(msg.result ?? {});
    } else {
      for (const listener of this.listeners) listener(msg);
    }
  }

  send(method, params = {}, sessionId = undefined) {
    const id = this.nextId++;
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.ws.send(JSON.stringify(msg));
    });
  }

  on(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  close() {
    this.ws.close();
  }
}

async function evaluate(cdp, sessionId, expression) {
  const { result, exceptionDetails } = await cdp.send(
    "Runtime.evaluate",
    { expression, returnByValue: true, awaitPromise: true },
    sessionId,
  );
  if (exceptionDetails) throw new Error(`page script failed: ${exceptionDetails.exception?.description ?? exceptionDetails.text}`);
  return result?.value;
}

// The page has finished its environment check once #env no longer reads
// "collecting…"; a session is over once #status carries the class "ok"
// (complete) or "warn" (refused or the worker stopped).
const PROBE = `/*drive:probe*/ JSON.stringify((() => {
  const env = document.getElementById("env");
  const status = document.getElementById("status");
  return {
    ready: document.readyState === "complete" && !!env && !!status && !env.textContent.startsWith("collecting"),
    status: status ? status.textContent : "",
    done: !!status && (status.className === "ok" || status.className === "warn"),
    ok: !!status && status.className === "ok",
  };
})())`;

function startExpression(settings) {
  return `/*drive:start*/ ((s) => {
  const set = (id, value) => {
    const el = document.getElementById(id);
    el.value = String(value);
    el.dispatchEvent(new Event("change"));
  };
  set("device", s.device);
  set("session", s.session);
  set("warm", s.warm);
  set("commit", s.commit);
  document.getElementById("newkey").checked = s.newKey;
  document.getElementById("run").click();
  return true;
})(${JSON.stringify(settings)})`;
}

const RECORDS = `/*drive:records*/ document.getElementById("records").textContent`;
const PROOFS = `/*drive:proofs*/ (self.revealProofLines || []).join("\\n")`;

async function waitFor(cdp, sessionId, test, opts, what) {
  const deadline = Date.now() + opts.timeoutMs;
  for (;;) {
    const state = JSON.parse(await evaluate(cdp, sessionId, PROBE));
    if (test(state)) return state;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what} (status: ${JSON.stringify(state.status)})`);
    await sleep(opts.pollMs);
  }
}

async function runSession(cdp, opts, session, log) {
  const mode = MODES[opts.mode];
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const workers = [];
  let stopListening = () => {};
  try {
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });

    // Workers the page starts (the prover runs in one) are attached paused,
    // given the same CPU throttling when Chrome accepts it there, and resumed.
    stopListening = cdp.on((msg) => {
      if (msg.method !== "Target.attachedToTarget" || msg.sessionId !== sessionId) return;
      const child = msg.params.sessionId;
      const type = msg.params.targetInfo?.type;
      const resume = () => cdp.send("Runtime.runIfWaitingForDebugger", {}, child).catch(() => {});
      if (type !== "worker") {
        resume();
        return;
      }
      const entry = cdp
        .send("Emulation.setCPUThrottlingRate", { rate: mode.cpuRate }, child)
        .then(() => true, () => false)
        .then(async (throttled) => {
          await resume();
          return throttled;
        });
      workers.push(entry);
    });
    await cdp.send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId);

    await cdp.send("Emulation.setCPUThrottlingRate", { rate: mode.cpuRate }, sessionId);
    await cdp.send("Network.enable", {}, sessionId);
    await cdp.send("Network.emulateNetworkConditions", NETWORK_CONDITIONS, sessionId);
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send("Page.navigate", { url: opts.page }, sessionId);
    await waitFor(cdp, sessionId, (s) => s.ready, opts, "the page to load");

    await evaluate(cdp, sessionId, startExpression({
      device: mode.deviceClass,
      session,
      warm: opts.warm,
      commit: opts.commit,
      newKey: session % 2 === 1,
    }));
    log(`session ${session}: running in tab ${targetId}`);
    const state = await waitFor(cdp, sessionId, (s) => s.done, opts, `session ${session} to finish`);

    const workerThrottled = (await Promise.all(workers)).some(Boolean);
    const text = (await evaluate(cdp, sessionId, RECORDS)) ?? "";
    const records = text.split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line));
    if (records.length === 0) throw new Error(`session ${session}: the page produced no records (status: ${JSON.stringify(state.status)})`);
    const lines = records.map((r) => JSON.stringify({
      ...r,
      cpu_throttling: mode.cpuRate === 1
        ? "none"
        : `${mode.cpuRate}x CPU throttling by DevTools Emulation.setCPUThrottlingRate on the tab` +
          (workerThrottled ? " and its worker" : "; Chrome did not accept it on the worker"),
      cpu_throttling_rate_applied: mode.cpuRate,
      cpu_throttling_worker: workerThrottled,
      network_conditions: NETWORK_DESCRIPTION,
      driver: DRIVER,
    }));

    await mkdir(opts.out, { recursive: true });
    const file = path.join(opts.out, `${mode.deviceClass}-coin-reveal-session${session}.jsonl`);
    await writeFile(file, lines.join("\n") + "\n");
    log(`session ${session}: ${state.status}, ${records.length} records in ${file}`);
    if (opts.proofs) {
      const proofs = (await evaluate(cdp, sessionId, PROOFS)) ?? "";
      const proofFile = path.join(opts.out, `${mode.deviceClass}-coin-reveal-session${session}.proofs`);
      await writeFile(proofFile, proofs ? proofs + "\n" : "");
    }
    return state.ok;
  } finally {
    stopListening();
    // Only the tab this session opened is closed.
    await cdp.send("Target.closeTarget", { targetId }).catch(() => {});
  }
}

export async function drive(opts, log = (line) => console.error(line)) {
  const cdp = await Cdp.connect(opts.devtools);
  let allOk = true;
  try {
    for (let i = 0; i < opts.sessions; i += 1) {
      const session = opts.firstSession + i;
      if (i > 0 && opts.restMs > 0) {
        log(`resting ${opts.restMs / 1000} s before session ${session}`);
        await sleep(opts.restMs);
      }
      if (!(await runSession(cdp, opts, session, log))) allOk = false;
    }
  } finally {
    cdp.close();
  }
  return allOk;
}

async function main() {
  let opts;
  try {
    opts = parseOptions(process.argv.slice(2));
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    console.error(`drive-reveal: ${err.message}`);
    process.exit(2);
  }
  if (opts.help) {
    console.log(USAGE);
    return;
  }
  try {
    const ok = await drive(opts);
    if (!ok) {
      console.error("drive-reveal: at least one session did not complete; its records were still written");
      process.exitCode = 1;
    }
  } catch (err) {
    console.error(`drive-reveal: ${err.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
