// The look for a Ghost node on this computer: probeLocalNode against an
// injected fetch (a Ghost node, a node of another kind, an HTTP 500, a
// JSON-RPC error, a thrown error and an answer that never comes), the
// visitor's system from the user agent, and the wiring of app.mjs on a
// stand-in page: a node found is the default endpoint with no setting
// written, no node shows the Run a node block in the Network panel, and a
// failed look shows nothing else. No browser, no build and no network.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { formatGhost, parseAddress, parseGhost } from "../src/chain.mjs";
import { WALLET_APPROVAL } from "../src/flow.mjs";
import { INSTALL_LINES, INSTALL_SITE, PROBE_BODY, PROBE_TIMEOUT_MS, probeLocalNode, systemOf } from "../src/local-node.mjs";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

const ENDPOINT = "http://127.0.0.1:8545";
const ENVELOPE = { jsonrpc: "2.0", id: 1, method: "rpc_modules", params: [] };

const UA = {
  macOS: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  Linux: "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
  Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
};

// A fetch that records each request and answers with `answer(url, init)`.
function stubFetch(answer) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return answer(url, init);
  };
  return { fetch, calls };
}

// A JSON answer of HTTP `status`.
function reply(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => (typeof body === "string" ? JSON.parse(body) : body),
  };
}

const GHOST_MODULES = { eth: "1.0", net: "1.0", web3: "1.0", ghost: "1.0", rpc: "1.0" };

// The one request: exactly the JSON-RPC envelope, no cookie, no cache, and no
// other field.
function assertProbeRequest(call) {
  assert.equal(call.url, ENDPOINT);
  const { init } = call;
  assert.deepEqual(Object.keys(init).sort(), ["body", "cache", "credentials", "headers", "method", "signal"]);
  assert.equal(init.method, "POST");
  assert.deepEqual(init.headers, { "content-type": "application/json" });
  assert.equal(init.credentials, "omit");
  assert.equal(init.cache, "no-store");
  assert.ok(init.signal instanceof AbortSignal);
  assert.equal(init.body, PROBE_BODY);
  assert.equal(init.body, JSON.stringify(ENVELOPE));
  assert.deepEqual(JSON.parse(init.body), ENVELOPE);
}

// --- probeLocalNode ---

test("a Ghost node, whose modules hold ghost, is found with one request of exactly the envelope", async () => {
  const { fetch, calls } = stubFetch(() => reply({ jsonrpc: "2.0", id: 1, result: GHOST_MODULES }));
  assert.equal(await probeLocalNode(fetch, ENDPOINT), true);
  assert.equal(calls.length, 1);
  assertProbeRequest(calls[0]);
});

test("a node without the ghost module is no node", async () => {
  for (const result of [{ eth: "1.0", net: "1.0", web3: "1.0" }, ["ghost"], "ghost", null, 1, { Ghost: "1.0" }]) {
    const { fetch, calls } = stubFetch(() => reply({ jsonrpc: "2.0", id: 1, result }));
    assert.equal(await probeLocalNode(fetch, ENDPOINT), false, JSON.stringify(result));
    assert.equal(calls.length, 1);
  }
});

test("an HTTP 500, a JSON-RPC error or an answer that is not JSON is no node", async () => {
  const answers = [
    () => reply({ jsonrpc: "2.0", id: 1, result: GHOST_MODULES }, 500),
    () => reply({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "the method rpc_modules does not exist" } }),
    () => reply({ jsonrpc: "2.0", id: 1, result: GHOST_MODULES, error: { code: -32000, message: "no" } }),
    () => reply("<html>not json"),
    () => null,
  ];
  for (const answer of answers) {
    const { fetch, calls } = stubFetch(answer);
    assert.equal(await probeLocalNode(fetch, ENDPOINT), false);
    assert.equal(calls.length, 1, "one request, no retry");
  }
});

test("a thrown error, as a refused connection or CORS gives, is no node and does not throw", async () => {
  const { fetch, calls } = stubFetch(() => {
    throw new TypeError("Failed to fetch");
  });
  assert.equal(await probeLocalNode(fetch, ENDPOINT), false);
  assert.equal(calls.length, 1, "one request, no retry");
  assert.equal(await probeLocalNode(() => Promise.reject(new Error("refused")), ENDPOINT), false);
});

test("an answer that never comes is no node once the time is up", async () => {
  assert.equal(PROBE_TIMEOUT_MS, 1500);
  let signal = null;
  // As a real fetch does, the request ends only when its signal aborts.
  const { fetch, calls } = stubFetch((url, init) => {
    signal = init.signal;
    return new Promise((resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason));
    });
  });
  const started = Date.now();
  assert.equal(await probeLocalNode(fetch, ENDPOINT), false);
  const took = Date.now() - started;
  assert.ok(signal.aborted, "the request was given up");
  assert.ok(took >= PROBE_TIMEOUT_MS - 50, `gave up after ${took} ms`);
  assert.ok(took < PROBE_TIMEOUT_MS + 1500, `gave up after ${took} ms`);
  assert.equal(calls.length, 1, "one request, no retry");
});

// --- The visitor's system ---

test("the system is macOS, Linux or Windows from the user agent, Linux by default", () => {
  assert.equal(systemOf(UA.macOS), "macOS");
  assert.equal(systemOf(UA.Linux), "Linux");
  assert.equal(systemOf(UA.Windows), "Windows");
  assert.equal(systemOf("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)"), "Linux");
  assert.equal(systemOf("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)"), "Linux");
  assert.equal(systemOf(""), "Linux");
  assert.equal(systemOf(undefined), "Linux");
});

test("the three install lines are fixed one-line commands from the install site", () => {
  assert.deepEqual(Object.keys(INSTALL_LINES).sort(), ["Linux", "Windows", "macOS"]);
  assert.equal(INSTALL_SITE, "https://get.ghostcoin.com");
  assert.equal(INSTALL_LINES.macOS, "curl -fsSL https://get.ghostcoin.com/install.sh | bash");
  assert.equal(INSTALL_LINES.Linux, "curl -fsSL https://get.ghostcoin.com/install.sh | bash");
  assert.equal(INSTALL_LINES.Windows, "irm https://get.ghostcoin.com/install.ps1 | iex");
  for (const line of Object.values(INSTALL_LINES)) assert.doesNotMatch(line, /\n/);
});

// --- The page ---

// Each id's opening tag, for its starting `hidden` and `data-` attributes.
const tags = new Map([...html.matchAll(/<[a-z]+\b[^>]*\bid="([^"]+)"[^>]*>/gi)].map((m) => [m[1], m[0]]));

// The markup of the element with `id`, its closing tag included.
function element(id) {
  const open = new RegExp(`<([a-z]+)\\b[^>]*\\bid="${id}"[^>]*>`, "i").exec(html);
  assert.ok(open, `index.html has an element with id ${id}`);
  const re = new RegExp(`<(/?)${open[1]}\\b[^>]*>`, "gi");
  re.lastIndex = open.index;
  let depth = 0;
  for (let m = re.exec(html); m; m = re.exec(html)) {
    depth += m[1] ? -1 : 1;
    if (depth === 0) return html.slice(open.index, m.index + m[0].length);
  }
  assert.fail(`the element with id ${id} is closed`);
}

class Element {
  constructor(tag, id = null) {
    this.tagName = tag;
    this.id = id;
    this.children = [];
    this.text = "";
    this.dataset = {};
    this.attributes = {};
    this.listeners = {};
    this.hidden = false;
    this.value = "";
    this.disabled = false;
    const classes = new Set();
    this.classList = {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
      toggle: (c, on = !classes.has(c)) => (on ? classes.add(c) : classes.delete(c), on),
    };
  }
  get textContent() {
    return this.text + this.children.map((c) => c.textContent).join("");
  }
  set textContent(value) {
    this.children = [];
    this.text = String(value);
  }
  get childElementCount() {
    return this.children.length;
  }
  get parentElement() {
    return (this.parent ??= new Element("div"));
  }
  replaceChildren(...children) {
    this.text = "";
    this.children = children;
  }
  append(...children) {
    this.children.push(...children);
  }
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }
  getAttribute(name) {
    return this.attributes[name] ?? null;
  }
  toggleAttribute(name, on) {
    if (on) this.attributes[name] = "";
    else delete this.attributes[name];
  }
  querySelectorAll(tag) {
    return this.children.flatMap((c) => [...(c.tagName === tag ? [c] : []), ...c.querySelectorAll(tag)]);
  }
  addEventListener(type, handler) {
    (this.listeners[type] ??= []).push(handler);
  }
  focus() {}
  fire(type) {
    for (const handler of this.listeners[type] ?? []) handler({ preventDefault() {}, key: undefined });
  }
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

// Starts app.mjs on a stand-in page, with the real probe over `fetch` and a
// stand-in flow that records any setting written. `endpoint` is the flow's
// endpoint at load.
function startPage({ fetch, userAgent = UA.Linux, endpoint = ENDPOINT }) {
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!tags.has(id)) return null;
      if (!elements.has(id)) {
        const el = new Element("x", id);
        el.hidden = /\shidden[\s>]/.test(tags.get(id));
        elements.set(id, el);
      }
      return elements.get(id);
    },
    createElement: (tag) => new Element(tag),
    querySelectorAll: () => [],
    addEventListener() {},
  };
  const copied = [];
  const settings = [];
  const flows = [];
  function createFlow(options) {
    flows.push(options);
    const state = {
      endpoint,
      commitEntry: "0x67686f7374000000000000000000000000000005",
      chainRefused: null,
      wallet: null,
      busy: null,
      progress: null,
      error: null,
      vanish: null,
      summon: null,
    };
    return {
      state,
      setEndpoint: (value) => settings.push(["endpoint", value]),
      setCommitEntry: (value) => settings.push(["commitEntry", value]),
      vanishCancel() {},
      summonClose() {},
    };
  }
  const navigator = { userAgent, clipboard: { writeText: async (text) => copied.push(text) } };

  const body = source.replace(/^import .*;$/gm, "");
  const names = ["document", "window", "navigator", "setInterval", "fetch", "formatGhost", "parseGhost", "parseAddress", "createFlow"];
  const more = ["normalKey", "wrongWords", "DEFAULT_COMMIT_ENTRY", "MAX_COMMIT_FEE", "WALLET_APPROVAL", "DEFAULT_ENDPOINT", "browserProver"];
  const rest = ["downloadKeyImage", "popupConnector", "createHeaderStore", "INSTALL_LINES", "INSTALL_SITE", "probeLocalNode", "systemOf"];
  new Function(...names, ...more, ...rest, body)(
    document,
    new Element("window"),
    navigator,
    () => 0,
    fetch,
    formatGhost,
    parseGhost,
    parseAddress,
    createFlow,
    (t) => t,
    () => [],
    "0x67686f7374000000000000000000000000000005",
    10n ** 16n,
    WALLET_APPROVAL,
    ENDPOINT,
    () => ({}),
    async () => {},
    () => assert.fail("no pop-up wallet"),
    () => null,
    INSTALL_LINES,
    INSTALL_SITE,
    probeLocalNode,
    systemOf,
  );
  const $ = (id) => document.getElementById(id);
  // Every element's visible state, for comparing the page before and after.
  const snapshot = () =>
    Object.fromEntries([...tags.keys()].map((id) => [id, { hidden: $(id).hidden, text: $(id).textContent, value: $(id).value }]));
  return { $, copied, settings, flows, snapshot };
}

// Runs `run` with the console watched; returns what was written to it.
async function watchConsole(run) {
  const said = [];
  const saved = {};
  for (const level of ["log", "info", "warn", "error", "debug"]) {
    saved[level] = console[level];
    console[level] = (...args) => said.push([level, ...args]);
  }
  try {
    await run();
  } finally {
    Object.assign(console, saved);
  }
  return said;
}

test("the Network panel holds the found line and the Run a node block, both hidden at first", () => {
  const network = element("network-panel");
  assert.ok(network.includes('id="local-node-found"'));
  assert.ok(network.includes('id="local-node-run"'));
  assert.match(tags.get("local-node-found"), /\bhidden\b/);
  assert.match(tags.get("local-node-run"), /\bhidden\b/);
  assert.match(element("local-node-found"), />Connected to your Ghost node</);
  const block = element("local-node-run");
  assert.match(block, /<h3>Run a node<\/h3>/);
  assert.match(element("local-node-line"), /^<code\b/);
  assert.equal([...block.matchAll(/<button\b/g)].length, 1, "one button");
  assert.match(element("local-node-copy"), />Copy</);
  assert.match(tags.get("local-node-site"), /rel="noopener noreferrer"/);
  assert.match(element("local-node-site"), />get\.ghostcoin\.com</);
  // Nowhere else on the page.
  assert.equal(html.split("Run a node").length, 2);
});

test("a stubbed Ghost node on 127.0.0.1:8545 is used as the default endpoint with no setting written", async () => {
  const { fetch, calls } = stubFetch(() => reply({ jsonrpc: "2.0", id: 1, result: GHOST_MODULES }));
  let page;
  const said = await watchConsole(async () => {
    page = startPage({ fetch });
    await settle();
    await settle();
  });
  const { $, settings, flows } = page;
  assert.equal(calls.length, 1, "one look");
  assertProbeRequest(calls[0]);
  assert.equal(flows[0].endpoint, ENDPOINT, "the flow uses the default endpoint");
  assert.equal($("endpoint").value, ENDPOINT);
  assert.deepEqual(settings, [], "no setting written");
  assert.equal($("local-node-found").hidden, false);
  assert.equal($("local-node-run").hidden, true);
  assert.equal($("error").textContent, "");
  assert.deepEqual(said, []);
});

test("no node: the Network panel shows Run a node, the visitor's line with its Copy button and the link", async () => {
  for (const system of ["macOS", "Linux", "Windows"]) {
    const { fetch, calls } = stubFetch(() => {
      throw new TypeError("Failed to fetch");
    });
    const page = startPage({ fetch, userAgent: UA[system] });
    await settle();
    await settle();
    const { $, copied, settings } = page;
    assert.equal(calls.length, 1, "one look");
    assert.equal($("local-node-run").hidden, false, system);
    assert.equal($("local-node-found").hidden, true);
    assert.equal($("local-node-line").textContent, INSTALL_LINES[system]);
    assert.equal($("local-node-system").textContent, system);
    assert.equal($("local-node-site").href, "https://get.ghostcoin.com");
    $("local-node-copy").fire("click");
    await settle();
    await settle();
    assert.deepEqual(copied, [INSTALL_LINES[system]]);
    assert.equal($("local-node-copy").textContent, "Copied");
    assert.deepEqual(settings, []);
  }
});

test("a failed look shows the Run a node block and nothing else: no error, no message, no second try", async () => {
  for (const fail of [
    () => {
      throw new TypeError("Failed to fetch");
    },
    () => reply({ error: "boom" }, 500),
    () => reply({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "no such method" } }),
    () => reply({ jsonrpc: "2.0", id: 1, result: { eth: "1.0" } }),
  ]) {
    let answer;
    const gate = new Promise((resolve) => (answer = resolve));
    const { fetch, calls } = stubFetch(async () => {
      await gate;
      return fail();
    });
    let page;
    let before;
    const said = await watchConsole(async () => {
      page = startPage({ fetch });
      await settle();
      before = page.snapshot();
      // Hidden until the look has failed.
      assert.equal(before["local-node-run"].hidden, true);
      assert.equal(before["local-node-found"].hidden, true);
      answer();
      for (let i = 0; i < 5; i++) await settle();
    });
    const after = page.snapshot();
    const changed = Object.keys(after).filter((id) => JSON.stringify(after[id]) !== JSON.stringify(before[id]));
    assert.deepEqual(changed, ["local-node-run"]);
    assert.equal(after["local-node-run"].hidden, false);
    assert.equal(page.$("error").textContent, "");
    assert.equal(page.$("progress").textContent, "");
    assert.deepEqual(said, [], "nothing on the console");
    assert.equal(calls.length, 1, "no second try");
  }
});

test("no look when the endpoint is not the default", async () => {
  const { fetch, calls } = stubFetch(() => reply({ jsonrpc: "2.0", id: 1, result: GHOST_MODULES }));
  const page = startPage({ fetch, endpoint: "http://192.0.2.7:8545" });
  await settle();
  await settle();
  assert.equal(calls.length, 0);
  assert.equal(page.$("local-node-found").hidden, true);
  assert.equal(page.$("local-node-run").hidden, true);
});

test("the look reaches the probe once, from page load, and nothing is stored", () => {
  assert.equal(source.match(/probeLocalNode\(/g).length, 1);
  assert.match(source, /probeLocalNode\(fetch, DEFAULT_ENDPOINT\)/);
  const probe = readFileSync(new URL("../src/local-node.mjs", import.meta.url), "utf8");
  for (const word of [["local", "Storage"].join(""), ["session", "Storage"].join(""), "document.cookie", "indexedDB", "setTimeout", "retry"]) {
    assert.ok(!probe.includes(word), word);
  }
});
