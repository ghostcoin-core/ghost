// The public test nodes, used when no Ghost node on this computer answers:
// the list and its chain check in rpc.mjs, the move to the next node when
// the one in use stops answering, the flow's choice of node, and app.mjs on
// a stand-in page with the real flow over an injected fetch. Every node here
// is a stand-in: no browser, no build and no network.
//
// (a) a local Ghost node answers: it is used and no public node is asked;
// (b) no local node: Spark is used, and a wallet's balance is read from it;
// (c) Spark names another chain, fails or never answers: the VM is used;
// (d) all fail: the Run a node block and the "network could not be read"
//     line, on the default endpoint;
// (e) the node in use failing mid-session moves to the next one, once;
// (f) a typed endpoint is never replaced.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { formatGhost, parseAddress, parseGhost } from "../src/chain.mjs";
import { WALLET_APPROVAL, createFlow } from "../src/flow.mjs";
import { NETWORKS, networkOf } from "../src/header.mjs";
import { INSTALL_LINES, INSTALL_SITE, probeLocalNode, systemOf } from "../src/local-node.mjs";
import {
  CHAIN_ID_BODY,
  DEFAULT_ENDPOINT,
  NODE_CHECK_MS,
  PUBLIC_CHAIN_ID,
  PUBLIC_ENDPOINTS,
  REQUEST_TIMEOUT_MS,
  RpcError,
  answersChain,
  createRpc,
  pickNode,
} from "../src/rpc.mjs";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

const [SPARK, VM] = PUBLIC_ENDPOINTS;
const LOCAL = "http://127.0.0.1:8545/";
const TYPED = "http://192.0.2.7:8545/";
const CHAIN = `0x${(6_777_972).toString(16)}`;
const OTHER_CHAIN = "0x539";
const GHOST = 10n ** 18n;
const WALLET = `0x3a${"0".repeat(34)}091c`;
const KEY = Array.from({ length: 24 }, (_, i) => `word${String.fromCharCode(97 + i)}`).join(" ");

const settle = async (n = 4) => {
  for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve));
};

// Waits, on real time, until `ready()` holds.
async function until(ready, ms = 15_000) {
  const end = Date.now() + ms;
  while (!ready()) {
    if (Date.now() > end) assert.fail("timed out waiting");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

// --- Stand-in nodes ---

// A node's behaviour, changed by a test as it runs: `mode` is "up", "down"
// (a refused connection), "hang" (no answer until the request is given up),
// "http" (an HTTP 502) or "wrong" (up, on another chain). `ghost` makes it
// list the ghost module, as a local Ghost node does.
function node({ mode = "up", ghost = false, balance = 0n } = {}) {
  return { mode, ghost, balance };
}

// A JSON answer of HTTP `status`.
function reply(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

// A fetch serving `nodes`, keyed by URL; every request is recorded with the
// node's URL and method. A URL with no node is a refused connection.
function network(nodes) {
  const calls = [];
  const fetch = async (url, init) => {
    const at = new URL(url).href;
    const { id, method, params } = JSON.parse(init.body);
    calls.push({ url: at, method, params, init });
    const n = nodes[at];
    if (!n || n.mode === "down") throw new TypeError("Failed to fetch");
    if (n.mode === "hang") {
      return new Promise((resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason));
      });
    }
    if (n.mode === "http") return reply({ error: "bad gateway" }, 502);
    const result = {
      rpc_modules: n.ghost ? { eth: "1.0", net: "1.0", web3: "1.0", ghost: "1.0", rpc: "1.0" } : { eth: "1.0" },
      eth_chainId: n.mode === "wrong" ? OTHER_CHAIN : CHAIN,
      eth_getBalance: `0x${n.balance.toString(16)}`,
    }[method];
    if (result === undefined) return reply({ jsonrpc: "2.0", id, error: { code: -32601, message: `the method ${method} does not exist` } });
    return reply({ jsonrpc: "2.0", id, result });
  };
  const to = (url) => calls.filter((c) => c.url === url);
  return { fetch, calls, to };
}

// --- The list ---

test("the public test nodes are Spark, then the VM, on the public test network this build pins", () => {
  // The URLs are written only in rpc.mjs: two HTTPS nodes, Spark first, each
  // on the Ghost RPC path.
  assert.equal(PUBLIC_ENDPOINTS.length, 2);
  assert.notEqual(SPARK, VM);
  for (const url of PUBLIC_ENDPOINTS) {
    const parsed = new URL(url);
    assert.equal(parsed.protocol, "https:", url);
    assert.equal(parsed.pathname, "/ghost-rpc", url);
  }
  assert.match(new URL(SPARK).hostname, /^spark-/);
  assert.doesNotMatch(new URL(VM).hostname, /^spark-/);
  assert.ok(Object.isFrozen(PUBLIC_ENDPOINTS));
  assert.equal(PUBLIC_CHAIN_ID, 6_777_972n);
  assert.ok(networkOf(NETWORKS, PUBLIC_CHAIN_ID), "the chain they must name is one whose start this build pins");
  assert.equal(DEFAULT_ENDPOINT, "http://127.0.0.1:8545");
  // A short check, and every request bounded.
  assert.ok(NODE_CHECK_MS > 0 && NODE_CHECK_MS <= 5000, `${NODE_CHECK_MS} ms`);
  assert.ok(REQUEST_TIMEOUT_MS > 0 && REQUEST_TIMEOUT_MS <= 60_000, `${REQUEST_TIMEOUT_MS} ms`);
  // The page names no external URL; the list lives in rpc.mjs.
  for (const url of PUBLIC_ENDPOINTS) assert.ok(!html.includes(new URL(url).host));
});

// --- The chain check ---

test("a node is used only when eth_chainId names the public test network", async () => {
  const net = network({ [SPARK]: node() });
  assert.equal(await answersChain(net.fetch, SPARK), true);
  assert.equal(net.calls.length, 1);
  const { init } = net.calls[0];
  assert.deepEqual(Object.keys(init).sort(), ["body", "cache", "credentials", "headers", "method", "signal"]);
  assert.equal(init.body, CHAIN_ID_BODY);
  assert.deepEqual(JSON.parse(init.body), { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] });
  assert.equal(init.credentials, "omit");
  assert.equal(init.cache, "no-store");
  assert.ok(init.signal instanceof AbortSignal);

  for (const mode of ["wrong", "down", "http"]) {
    assert.equal(await answersChain(network({ [SPARK]: node({ mode }) }).fetch, SPARK), false, mode);
  }
  for (const body of [{ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "no" } }, { result: 6777972 }, { result: "0xzz" }, null]) {
    assert.equal(await answersChain(async () => reply(body), SPARK), false, JSON.stringify(body));
  }
  assert.equal(await answersChain(async () => ({ ok: true, json: async () => JSON.parse("<html>") }), SPARK), false);
});

test("a node that never answers its chain check is given up after the short time", async () => {
  const net = network({ [SPARK]: node({ mode: "hang" }) });
  const started = Date.now();
  assert.equal(await answersChain(net.fetch, SPARK, { timeoutMs: 100 }), false);
  const took = Date.now() - started;
  assert.ok(took >= 90 && took < 2000, `gave up after ${took} ms`);
  assert.ok(net.calls[0].init.signal.aborted);
});

test("pickNode asks the nodes in order and stops at the first that answers", async () => {
  const net = network({ [SPARK]: node({ mode: "wrong" }), [VM]: node() });
  assert.equal(await pickNode(net.fetch, PUBLIC_ENDPOINTS), VM);
  assert.deepEqual(
    net.calls.map((c) => c.url),
    [SPARK, VM],
  );
  const up = network({ [SPARK]: node(), [VM]: node() });
  assert.equal(await pickNode(up.fetch, PUBLIC_ENDPOINTS), SPARK);
  assert.equal(up.to(VM).length, 0, "the VM is not asked once Spark answers");
  assert.equal(await pickNode(network({}).fetch, PUBLIC_ENDPOINTS), null);
});

// --- The client: every request bounded, and the move to the next node ---

test("every request carries a time limit and a hanging one fails instead of holding the page", async () => {
  const net = network({ [SPARK]: node({ mode: "hang" }) });
  const rpc = createRpc(SPARK, { fetch: net.fetch, timeoutMs: 100 });
  const started = Date.now();
  await assert.rejects(rpc.call("eth_blockNumber"));
  assert.ok(Date.now() - started < 2000);
  assert.ok(net.calls[0].init.signal instanceof AbortSignal);
  assert.ok(net.calls[0].init.signal.aborted);
});

test("(e) the node in use failing moves the client to the next one that answers, once", async () => {
  const nodes = { [SPARK]: node({ balance: 7n }), [VM]: node({ balance: 7n }) };
  const net = network(nodes);
  const moves = [];
  const rpc = createRpc(SPARK, { fetch: net.fetch, fallbacks: [VM], onMove: (url) => moves.push(url) });
  assert.equal(rpc.url, SPARK);
  assert.equal(await rpc.call("eth_getBalance", [WALLET, "latest"]), "0x7");

  // A JSON-RPC error is an answer: no move.
  await assert.rejects(rpc.call("eth_unknown"), RpcError);
  assert.equal(rpc.url, SPARK);
  assert.equal(net.to(VM).length, 0);

  // Spark stops answering: that request fails, and the client moves.
  nodes[SPARK].mode = "down";
  await assert.rejects(rpc.call("eth_getBalance", [WALLET, "latest"]), /Failed to fetch/);
  assert.equal(rpc.url, VM);
  assert.deepEqual(moves, [VM]);
  assert.deepEqual(
    net.to(VM).map((c) => c.method),
    ["eth_chainId"],
    "the VM's chain is checked before it is used",
  );
  assert.equal(await rpc.call("eth_getBalance", [WALLET, "latest"]), "0x7");
  assert.equal(net.to(VM).at(-1).method, "eth_getBalance");

  // One pass: the VM failing too moves nowhere, and nothing is polled.
  nodes[VM].mode = "down";
  nodes[SPARK].mode = "up";
  const before = net.calls.length;
  await assert.rejects(rpc.call("eth_blockNumber"));
  await assert.rejects(rpc.call("eth_blockNumber"));
  assert.equal(rpc.url, VM);
  assert.deepEqual(moves, [VM]);
  assert.deepEqual(
    net.calls.slice(before).map((c) => c.url),
    [VM, VM],
    "no request to Spark again",
  );
});

test("an HTTP error or no answer in time also moves on; a fallback on another chain is passed over", async () => {
  for (const mode of ["http", "hang"]) {
    const nodes = { [SPARK]: node({ mode }), [VM]: node({ mode: "wrong" }), [TYPED]: node() };
    const net = network(nodes);
    const rpc = createRpc(SPARK, { fetch: net.fetch, fallbacks: [VM, TYPED], timeoutMs: 100, checkMs: 100 });
    await assert.rejects(rpc.call("eth_blockNumber"));
    assert.equal(rpc.url, TYPED, mode);
  }
  // None of the fallbacks answers: the client stays, and later failures
  // ask none of them again.
  const net = network({});
  const rpc = createRpc(SPARK, { fetch: net.fetch, fallbacks: [VM] });
  await assert.rejects(rpc.call("eth_blockNumber"));
  await assert.rejects(rpc.call("eth_blockNumber"));
  assert.equal(rpc.url, SPARK);
  assert.equal(net.to(VM).length, 1, "the VM was checked once");
});

test("failures while a move is under way move once", async () => {
  const nodes = { [SPARK]: node({ mode: "down" }), [VM]: node(), [TYPED]: node() };
  const net = network(nodes);
  const moves = [];
  const rpc = createRpc(SPARK, { fetch: net.fetch, fallbacks: [VM, TYPED], onMove: (url) => moves.push(url) });
  await Promise.allSettled([rpc.call("eth_blockNumber"), rpc.call("eth_blockNumber"), rpc.call("eth_blockNumber")]);
  assert.deepEqual(moves, [VM]);
  assert.equal(rpc.url, VM);
});

test("(f) a client of a typed endpoint has nothing to move to", async () => {
  const net = network({ [TYPED]: node({ mode: "down" }), [SPARK]: node(), [VM]: node() });
  const rpc = createRpc(TYPED, { fetch: net.fetch });
  await assert.rejects(rpc.call("eth_blockNumber"));
  assert.equal(rpc.url, TYPED);
  assert.deepEqual(
    net.calls.map((c) => c.url),
    [TYPED],
  );
});

// --- The flow ---

const noProver = {
  request: async (op) => {
    throw new Error(`no worker request expected, got ${op}`);
  },
};

const testWallet = () => ({
  id: "test-wallet",
  name: "Test wallet",
  connect: async () => ({ address: WALLET }),
  signTransaction: async () => assert.fail("nothing is signed"),
});

test("(b) with no node on this computer the flow uses Spark, and reads the wallet's balance from it", async () => {
  const net = network({ [SPARK]: node({ balance: 3n * GHOST }), [VM]: node({ balance: 9n * GHOST }) });
  const changes = [];
  const flow = createFlow({ prover: noProver, fetch: net.fetch, onChange: (s) => changes.push(s.endpoint) });
  assert.equal(flow.state.endpoint, LOCAL);
  assert.equal(await flow.usePublicNode(), SPARK);
  assert.equal(flow.state.endpoint, SPARK);
  assert.ok(changes.includes(SPARK), "the page is told");
  await flow.walletConnect(testWallet());
  assert.equal(flow.state.wallet.balance, 3n * GHOST);
  assert.equal(net.to(VM).length, 0);
  assert.deepEqual(
    net.to(SPARK).map((c) => c.method),
    ["eth_chainId", "eth_getBalance"],
  );
});

test("(c) Spark on another chain, failing or never answering: the flow uses the VM", async () => {
  for (const mode of ["wrong", "down", "http", "hang"]) {
    const net = network({ [SPARK]: node({ mode }), [VM]: node({ balance: 9n * GHOST }) });
    const flow = createFlow({ prover: noProver, fetch: net.fetch });
    const started = Date.now();
    assert.equal(await flow.usePublicNode(), VM, mode);
    if (mode === "hang") assert.ok(Date.now() - started < NODE_CHECK_MS + 2000, "Spark was given up after the short time");
    await flow.walletConnect(testWallet());
    assert.equal(flow.state.wallet.balance, 9n * GHOST);
    assert.deepEqual(
      net.to(SPARK).map((c) => c.method),
      ["eth_chainId"],
      "nothing else is asked of Spark",
    );
  }
});

test("(d) no public node answers: the flow stays on the default endpoint", async () => {
  const net = network({ [SPARK]: node({ mode: "wrong" }), [VM]: node({ mode: "down" }) });
  const flow = createFlow({ prover: noProver, fetch: net.fetch });
  assert.equal(await flow.usePublicNode(), null);
  assert.equal(flow.state.endpoint, LOCAL);
  await assert.rejects(flow.walletConnect(testWallet()));
  assert.equal(net.calls.at(-1).url, LOCAL);
});

test("(e) the chosen node failing mid-session moves the flow to the next one once", async () => {
  const nodes = { [SPARK]: node({ balance: 3n * GHOST }), [VM]: node({ balance: 9n * GHOST }) };
  const net = network(nodes);
  const flow = createFlow({ prover: noProver, fetch: net.fetch });
  await flow.usePublicNode();
  await flow.walletConnect(testWallet());
  assert.equal(flow.state.wallet.balance, 3n * GHOST);

  // A gateway answering 502 for a node gone (a request that hangs moves the
  // same way, after its time limit: see the client's tests above).
  nodes[SPARK].mode = "http";
  await assert.rejects(flow.walletRefresh());
  assert.equal(flow.state.endpoint, VM, "the failure moved the flow");
  assert.equal(await flow.walletRefresh(), 9n * GHOST);

  nodes[VM].mode = "down";
  nodes[SPARK].mode = "up";
  const before = net.calls.length;
  await assert.rejects(flow.walletRefresh());
  await assert.rejects(flow.walletRefresh());
  assert.equal(flow.state.endpoint, VM, "one pass: no move back");
  assert.ok(
    net.calls.slice(before).every((c) => c.url === VM),
    "nothing more is asked of Spark",
  );
});

test("(f) an endpoint typed while the flow looks is never replaced, and a typed one never moves", async () => {
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  const nodes = { [SPARK]: node(), [VM]: node(), [TYPED]: node({ balance: 5n * GHOST }) };
  const inner = network(nodes);
  const fetch = async (url, init) => {
    if (new URL(url).href === SPARK) await gate;
    return inner.fetch(url, init);
  };
  const flow = createFlow({ prover: noProver, fetch });
  const looking = flow.usePublicNode();
  await settle();
  flow.setEndpoint(TYPED);
  release();
  assert.equal(await looking, null);
  assert.equal(flow.state.endpoint, TYPED);
  assert.equal(inner.to(VM).length, 0);

  await flow.walletConnect(testWallet());
  assert.equal(flow.state.wallet.balance, 5n * GHOST);
  nodes[TYPED].mode = "down";
  const before = inner.calls.length;
  await assert.rejects(flow.walletRefresh());
  assert.equal(flow.state.endpoint, TYPED);
  assert.deepEqual(
    inner.calls.slice(before).map((c) => c.url),
    [TYPED],
  );
});

// --- The page ---

const tags = new Map([...html.matchAll(/<[a-z]+\b[^>]*\bid="([^"]+)"[^>]*>/gi)].map((m) => [m[1], m[0]]));

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
  fire(type, extra = {}) {
    for (const handler of this.listeners[type] ?? []) handler({ preventDefault() {}, key: undefined, ...extra });
  }
}

// The worker as the Summon open needs it: the key passes its check, and
// nothing else is asked.
const pageProver = {
  request: async (op) => {
    if (op === "checkKey") return { format: "words", groups: 21 };
    throw new Error(`no worker request expected, got ${op}`);
  },
};

// Starts app.mjs on a stand-in page with the real flow and the real look,
// both over `fetch`.
function startPage(fetch) {
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!tags.has(id)) return null;
      if (!elements.has(id)) {
        const el = new Element("x", id);
        el.hidden = /\shidden[\s>]/.test(tags.get(id));
        el.disabled = /\sdisabled[\s>]/.test(tags.get(id));
        for (const m of tags.get(id).matchAll(/\sdata-([a-z]+)="([^"]*)"/g)) el.dataset[m[1]] = m[2];
        elements.set(id, el);
      }
      return elements.get(id);
    },
    createElement: (tag) => new Element(tag),
    querySelectorAll: () => [],
    addEventListener() {},
  };
  let flow = null;
  const pageFlow = (options) => (flow = createFlow({ ...options, fetch }));
  const navigator = { userAgent: "Mozilla/5.0 (X11; Linux x86_64)", clipboard: { writeText: async () => {} } };

  const body = source.replace(/^import .*;$/gm, "");
  const names = ["document", "window", "navigator", "setInterval", "fetch", "formatGhost", "parseGhost", "parseAddress", "createFlow"];
  const more = ["normalKey", "wrongWords", "DEFAULT_COMMIT_ENTRY", "MAX_COMMIT_FEE", "WALLET_APPROVAL", "DEFAULT_ENDPOINT", "browserProver"];
  const rest = ["popupConnector", "createHeaderStore", "INSTALL_LINES", "INSTALL_SITE", "probeLocalNode", "systemOf"];
  new Function(...names, ...more, ...rest, body)(
    document,
    new Element("window"),
    navigator,
    () => 0,
    fetch,
    formatGhost,
    parseGhost,
    parseAddress,
    pageFlow,
    (t) => String(t).trim().split(/\s+/).join(" "),
    () => [],
    "0x67686f7374000000000000000000000000000005",
    10n ** 16n,
    WALLET_APPROVAL,
    DEFAULT_ENDPOINT,
    () => pageProver,
    testWallet,
    () => null,
    INSTALL_LINES,
    INSTALL_SITE,
    probeLocalNode,
    systemOf,
  );
  const $ = (id) => document.getElementById(id);
  return { $, flow: () => flow };
}

// The look has ended once a node line or the Run a node block shows.
const looked = (page) => () => !page.$("node-in-use").hidden || !page.$("local-node-run").hidden;

async function connectWallet(page) {
  page.$("wallet-option-popup").fire("click");
  await until(() => page.$("wallet-balance").textContent !== "?" || page.$("wallet-error").textContent !== "");
}

test("(a) a Ghost node on this computer is used: Your Ghost node, and no public node is asked", async () => {
  const net = network({ [LOCAL]: node({ ghost: true, balance: 2n * GHOST }), [SPARK]: node(), [VM]: node() });
  const page = startPage(net.fetch);
  await until(looked(page));
  assert.equal(page.$("node-in-use").hidden, false);
  assert.equal(page.$("node-name").textContent, "Your Ghost node");
  assert.equal(page.$("public-node-note").hidden, true);
  assert.equal(page.$("local-node-run").hidden, true);
  assert.equal(page.flow().state.endpoint, LOCAL);
  await connectWallet(page);
  assert.equal(page.$("wallet-balance").textContent, formatGhost(2n * GHOST));
  assert.equal(net.to(SPARK).length + net.to(VM).length, 0);
});

test("(b) no Ghost node on this computer: Spark is used, Public test node, and the balance shows", async () => {
  const net = network({ [SPARK]: node({ balance: parseGhost("12.5") }), [VM]: node() });
  const page = startPage(net.fetch);
  await until(looked(page));
  assert.equal(page.$("node-in-use").hidden, false);
  assert.equal(page.$("node-name").textContent, "Public test node");
  assert.equal(page.$("public-node-note").hidden, false);
  assert.equal(page.$("local-node-run").hidden, false, "Run a node stays offered");
  assert.equal(page.flow().state.endpoint, SPARK);
  assert.equal(page.$("endpoint").value, SPARK, "the endpoint box shows the node in use");
  assert.deepEqual(
    net.calls.slice(0, 2).map((c) => [c.url, c.method]),
    [
      [LOCAL, "rpc_modules"],
      [SPARK, "eth_chainId"],
    ],
    "the local look first, then Spark",
  );
  await connectWallet(page);
  assert.equal(page.$("wallet-balance").textContent, formatGhost(parseGhost("12.5")));
  assert.equal(page.$("wallet-error").textContent, "");
  assert.equal(net.to(VM).length, 0);
});

test("(c) Spark on another chain: the VM is used", async () => {
  const net = network({ [SPARK]: node({ mode: "wrong" }), [VM]: node({ balance: 4n * GHOST }) });
  const page = startPage(net.fetch);
  await until(looked(page));
  assert.equal(page.$("node-name").textContent, "Public test node");
  assert.equal(page.flow().state.endpoint, VM);
  assert.equal(page.$("endpoint").value, VM);
  await connectWallet(page);
  assert.equal(page.$("wallet-balance").textContent, formatGhost(4n * GHOST));
});

test("(d) every node fails: the Run a node block, and the network could not be read", async () => {
  const net = network({ [SPARK]: node({ mode: "wrong" }), [VM]: node({ mode: "http" }) });
  const page = startPage(net.fetch);
  await until(looked(page));
  assert.equal(page.$("local-node-run").hidden, false);
  assert.equal(page.$("node-in-use").hidden, true);
  assert.equal(page.flow().state.endpoint, LOCAL, "the page stays on the default endpoint");
  assert.equal(page.$("endpoint").value, LOCAL);
  // Opening a key reads the chain, which nothing answers.
  page.$("tab-summon").fire("click");
  page.$("summon-key").value = KEY;
  page.$("summon-key").fire("input", { inputType: "insertFromPaste" });
  await until(() => page.$("summon-error").textContent !== "");
  assert.equal(page.$("summon-error").textContent, "The network could not be read. Check the node under Network and try again.");
});

test("(e) the public node failing mid-session moves the page to the VM, once", async () => {
  const nodes = { [SPARK]: node({ balance: 3n * GHOST }), [VM]: node({ balance: 9n * GHOST }) };
  const net = network(nodes);
  const page = startPage(net.fetch);
  await until(looked(page));
  await connectWallet(page);
  assert.equal(page.$("wallet-balance").textContent, formatGhost(3n * GHOST));

  nodes[SPARK].mode = "down";
  page.$("wallet-refresh").fire("click");
  await until(() => page.$("wallet-error").textContent !== "");
  assert.equal(page.$("wallet-error").textContent, "The balance could not be read. Check the node under Network.");
  assert.equal(page.flow().state.endpoint, VM);
  assert.equal(page.$("endpoint").value, VM);
  assert.equal(page.$("node-name").textContent, "Public test node");

  page.$("wallet-refresh").fire("click");
  await until(() => page.$("wallet-balance").textContent === formatGhost(9n * GHOST));
  assert.equal(page.$("wallet-error").textContent, "");
});

test("(f) an endpoint typed on the page is never replaced by the look", async () => {
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  const inner = network({ [TYPED]: node({ balance: 6n * GHOST }), [SPARK]: node(), [VM]: node() });
  const fetch = async (url, init) => {
    if (new URL(url).href === LOCAL) await gate;
    return inner.fetch(url, init);
  };
  const page = startPage(fetch);
  await settle();
  page.$("endpoint").value = TYPED;
  page.$("network-form").fire("submit");
  await settle();
  release();
  await settle(20);
  assert.equal(page.flow().state.endpoint, TYPED);
  assert.equal(page.$("endpoint").value, TYPED);
  assert.equal(page.$("node-in-use").hidden, true);
  assert.equal(page.$("local-node-run").hidden, true);
  assert.equal(inner.to(SPARK).length + inner.to(VM).length, 0, "no public node is asked");
  await connectWallet(page);
  assert.equal(page.$("wallet-balance").textContent, formatGhost(6n * GHOST));
});

test("the page leaves the endpoint box alone when it is saved unchanged, so the node found stays", async () => {
  const net = network({ [SPARK]: node(), [VM]: node() });
  const page = startPage(net.fetch);
  await until(looked(page));
  page.$("network-form").fire("submit");
  await settle();
  assert.equal(page.flow().state.endpoint, SPARK);
  assert.equal(page.$("node-name").textContent, "Public test node");
});
