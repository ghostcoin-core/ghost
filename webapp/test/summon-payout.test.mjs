// Summon's payout: by default a Summon pays a fresh address of the connected
// wallet, never the address the Vanish came from. The payout field starts
// with that address (the connector's newReceiveAddress, ghost_newReceiveAddress
// in the pop-up wallet), or with the connected address when the wallet has
// no such request, and a warning shows when the payout is the connected
// address or one this page vanished from. A full Summon whose amount fewer
// than 10 checked commits share warns too and suggests a partial Summon.
// Warnings are advice and never block. A reveal that cannot be made is not
// proved at all.
//
// The page tests run app.mjs against a small stand-in page and a stand-in
// flow, with nothing built. The flow tests run the real prover, built for
// wasm32-unknown-unknown, against the node stand-in, when a module is built.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { toHex } from "../src/bytes.mjs";
import { formatGhost, parseAddress, parseGhost } from "../src/chain.mjs";
import { DEFAULT_COMMIT_ENTRY, WALLET_APPROVAL, coinRecord, createFlow } from "../src/flow.mjs";
import { METHOD_NOT_FOUND, popupConnector } from "../src/popup-wallet.mjs";
import { WalletRejected } from "../src/wallet-connect.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, testAccountAddress, testConnector, wasmPath } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const BUILT = existsSync(wasmPath) ? false : `no WebAssembly module built at ${wasmPath}`;

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");
const flowSource = readFileSync(new URL("../src/flow.mjs", import.meta.url), "utf8");

const GHOST = 10n ** 18n;
const FEE = 10n ** 14n;
const WALLET = `0x3a${"0".repeat(34)}091c`;
const FRESH = `0x7c${"0".repeat(34)}044d`;
const VANISHED = `0x9e${"0".repeat(34)}066f`;
const OTHER = `0x4f${"0".repeat(34)}0aa1`;
const KEY = Array.from({ length: 24 }, (_, i) => `word${String.fromCharCode(97 + i)}`).join(" ");
const normalKey = (text) => String(text).trim().split(/\s+/).join(" ");

const SAME = /^This is your connected wallet's address, the one a Vanish is sent from\. .*links this Summon to its Vanish\./;
const SENT_VANISH = /^This address sent a Vanish from this page\. .*links this Summon to its Vanish\./;
const FEW = /^A full Summon shows 2 GHOST with the network fee, and only (\d+) (Vanish|Vanishes) the app checked are of that amount, so the amount alone can link this Summon to its Vanish\. A partial Summon, less than Max, avoids that\.$/;

// --- A stand-in page: one element for each id of index.html ---

const tags = new Map([...html.matchAll(/<[a-z0-9]+\b[^>]*\bid="([^"]+)"[^>]*>/gi)].map((m) => [m[1], m[0]]));

class Element {
  constructor(tag, id = null) {
    this.tagName = tag;
    this.id = id;
    this.children = [];
    this.text = "";
    this.title = "";
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

const settle = async (n = 6) => {
  for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve));
};

// Starts app.mjs with a stand-in flow whose key holds 2 GHOST. `wallet`
// false starts with no wallet connected. `fresh()` answers the flow's
// newReceiveAddress (an address, null for a wallet without the request, or
// a throw). `matches` is the flow's amountMatches, `vanishedFrom` its list
// of addresses this page sent a Vanish from.
function startPage({ wallet = true, fresh = () => FRESH, matches = 50, vanishedFrom = [] } = {}) {
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
  const window = new Element("window");
  const $ = (id) => document.getElementById(id);
  const screens = () => ["form", "confirm", "waiting", "done"].filter((s) => !$(`summon-${s}`).hidden);
  const log = { reveals: [], fresh: 0 };
  let state = null;

  function createFlow({ onChange }) {
    state = {
      endpoint: "http://127.0.0.1:8545",
      commitEntry: DEFAULT_COMMIT_ENTRY,
      chainRefused: null,
      wallet: wallet ? { id: "test-wallet", name: "Test wallet", address: WALLET, balance: 5n * GHOST } : null,
      vanishedFrom,
      busy: null,
      progress: null,
      error: null,
      vanish: null,
      summon: null,
    };
    const emit = () => onChange(state);
    return {
      state,
      async newReceiveAddress() {
        log.fresh++;
        return fresh();
      },
      async walletConnect(connector) {
        const { address } = await connector.connect();
        state.wallet = { id: connector.id, name: connector.name, address, balance: 5n * GHOST };
        emit();
        return address;
      },
      walletDisconnect() {
        state.wallet = null;
        emit();
      },
      async summonOpen(text) {
        state.summon = { key: normalKey(text), format: "words", groups: 21, coins: [], claim: null, lastReveal: null, pinned: null };
        Object.assign(state.summon, {
          status: "unclaimed",
          current: { number: 1n, amount: 2n * GHOST, treeIndex: 0, position: 3 },
          fee: FEE,
          available: 2n * GHOST - FEE,
          amountMatches: matches,
          wait: null,
        });
        emit();
        return state.summon;
      },
      async summonReveal({ amount, recipient }) {
        log.reveals.push({ amount, recipient });
        state.summon.lastReveal = { stage: "done", txHash: "0x01", out: parseGhost(amount), recipient, fee: FEE, block: 9 };
        emit();
        return state.summon.lastReveal;
      },
      summonClose() {
        state.summon = null;
        emit();
      },
      vanishCancel() {
        state.vanish = null;
        emit();
      },
    };
  }

  const body = source.replace(/^import .*;$/gm, "");
  const names = ["document", "window", "navigator", "setInterval", "formatGhost", "parseGhost", "parseAddress", "createFlow", "normalKey"];
  const more = ["wrongWords", "DEFAULT_COMMIT_ENTRY", "MAX_COMMIT_FEE", "WALLET_APPROVAL", "DEFAULT_ENDPOINT", "browserProver", "downloadKeyImage"];
  new Function(...names, ...more, "popupConnector", body)(
    document,
    window,
    { clipboard: { writeText: async () => {} } },
    () => 0,
    formatGhost,
    parseGhost,
    parseAddress,
    createFlow,
    normalKey,
    () => [],
    DEFAULT_COMMIT_ENTRY,
    10n ** 16n,
    WALLET_APPROVAL,
    "http://127.0.0.1:8545",
    () => ({}),
    async () => {},
    () => ({ id: "ghost-popup-wallet", name: "Ghost wallet", connect: async () => ({ address: WALLET }) }),
  );
  $("tab-summon").fire("click");
  return { $, log, screens, state: () => state };
}

async function paste(page) {
  page.$("summon-key").value = KEY;
  page.$("summon-key").fire("input", { inputType: "insertFromPaste" });
  await settle();
}

function type(page, id, value) {
  page.$(id).value = value;
  page.$(id).fire("input", { inputType: "insertText" });
}

// Types `amount`, presses Summon and, when the confirm screen opens, Confirm
// Summon.
async function summon(page, amount) {
  type(page, "summon-amount", amount);
  page.$("summon-form").fire("submit");
  await settle();
  const warned = page.$("summon-confirm-warning").textContent;
  if (!page.$("summon-confirm").hidden) page.$("summon-confirm-button").fire("click");
  await settle();
  return warned;
}

// --- The payout field ---

test("by default the payout field holds a fresh address of the wallet, and the Summon pays it, with no warning", async () => {
  const page = startPage();
  assert.equal(page.log.fresh, 0, "no address is asked for before a key's coin shows");
  await paste(page);
  assert.equal(page.log.fresh, 1);
  assert.equal(page.$("summon-payout").value, FRESH);
  assert.equal(page.$("summon-payout-warning").textContent, "");
  const warned = await summon(page, "0.5");
  assert.equal(warned, "");
  assert.deepEqual(page.log.reveals, [{ amount: "0.5", recipient: FRESH }]);
  assert.notEqual(page.log.reveals[0].recipient, WALLET, "not the address the Vanish came from");
  assert.equal(page.$("summon-done-address").textContent, "0x7c…44d");
});

test("a wallet without the request: the field starts with the connected address and the same-address warning shows, but does not block", async () => {
  for (const fresh of [() => null, () => Promise.reject(Object.assign(new Error("unknown method"), { code: -32601 }))]) {
    const page = startPage({ fresh });
    await paste(page);
    assert.equal(page.$("summon-payout").value, WALLET);
    assert.match(page.$("summon-payout-warning").textContent, SAME);
    const warned = await summon(page, "0.5");
    assert.match(warned, SAME, "the confirm screen warns too");
    assert.deepEqual(page.log.reveals, [{ amount: "0.5", recipient: WALLET }], "the warning never blocks");
    assert.deepEqual(page.screens(), ["done"]);
  }
});

test("with no wallet the field is empty and Summon asks to connect; once connected it fills", async () => {
  const page = startPage({ wallet: false });
  await paste(page);
  assert.equal(page.$("summon-payout").value, "");
  assert.equal(page.log.fresh, 0);
  assert.equal(page.$("summon-submit").textContent, "Connect wallet");
  page.$("summon-form").fire("submit");
  await settle();
  assert.equal(page.$("wallet-panel").hidden, false, "the wallet list opens");
  assert.equal(page.log.reveals.length, 0);

  page.$("wallet-option-popup").fire("click");
  await settle();
  assert.equal(page.$("summon-payout").value, FRESH);
  assert.equal(page.$("summon-submit").textContent, "Summon");

  // Disconnected: the filled address goes with the wallet.
  page.$("wallet-disconnect").fire("click");
  await settle();
  assert.equal(page.$("summon-payout").value, "");
});

test("a typed payout is kept, warned about when it is the wallet's or a vanishing address, and checked with parseAddress", async () => {
  const page = startPage({ vanishedFrom: [VANISHED] });
  await paste(page);
  type(page, "summon-payout", WALLET.toUpperCase().replace("0X", "0x"));
  assert.match(page.$("summon-payout-warning").textContent, SAME, "the same address in any case");
  type(page, "summon-payout", VANISHED);
  assert.match(page.$("summon-payout-warning").textContent, SENT_VANISH);
  type(page, "summon-payout", OTHER);
  assert.equal(page.$("summon-payout-warning").textContent, "");

  for (const bad of ["", "0x12", `0x${"g".repeat(40)}`]) {
    type(page, "summon-payout", bad);
    type(page, "summon-amount", "0.5");
    page.$("summon-form").fire("submit");
    await settle();
    assert.deepEqual(page.screens(), ["form"], JSON.stringify(bad));
    assert.equal(page.$("summon-error").textContent, "Enter the address to pay, 0x and 40 hex digits.");
  }
  type(page, "summon-payout", `0x${"0".repeat(40)}`);
  page.$("summon-form").fire("submit");
  await settle();
  assert.equal(page.$("summon-error").textContent, "The zero address can't receive a Summon: the GHOST would be lost.");
  assert.equal(page.log.reveals.length, 0);

  type(page, "summon-payout", VANISHED);
  const warned = await summon(page, "0.5");
  assert.match(warned, SENT_VANISH);
  assert.deepEqual(page.log.reveals, [{ amount: "0.5", recipient: VANISHED }]);
});

test("an address typed before the wallet answers is never replaced by it", async () => {
  let answer;
  const page = startPage({ fresh: () => new Promise((resolve) => (answer = resolve)) });
  await paste(page);
  type(page, "summon-payout", OTHER);
  answer(FRESH);
  await settle();
  assert.equal(page.$("summon-payout").value, OTHER);
  await summon(page, "0.5");
  assert.equal(page.log.reveals[0].recipient, OTHER);
});

// --- The amount warning ---

test("a full Summon whose amount fewer than 10 checked commits share warns and suggests a partial one; a partial Summon does not", async () => {
  const page = startPage({ matches: 3 });
  await paste(page);
  // Partial: no warning.
  type(page, "summon-amount", "1");
  assert.equal(page.$("summon-amount-warning").textContent, "");
  // Full, by Max: out + fee is all the key holds.
  page.$("summon-max").fire("click");
  assert.equal(page.$("summon-amount").value, "1.9999");
  const [, count] = FEW.exec(page.$("summon-amount-warning").textContent) ?? [];
  assert.equal(count, "3");
  const warned = await summon(page, "1.9999");
  assert.match(warned, FEW, "the confirm screen warns too");
  assert.deepEqual(page.log.reveals, [{ amount: "1.9999", recipient: FRESH }], "the warning never blocks");

  const one = startPage({ matches: 1 });
  await paste(one);
  one.$("summon-max").fire("click");
  assert.match(one.$("summon-amount-warning").textContent, /only 1 Vanish the app checked/);

  // Ten or more of that amount: no warning.
  const many = startPage({ matches: 10 });
  await paste(many);
  many.$("summon-max").fire("click");
  assert.equal(many.$("summon-amount-warning").textContent, "");
  assert.equal(await summon(many, "1.9999"), "");

  // A partial Summon shows none, however few match.
  const partial = startPage({ matches: 0 });
  await paste(partial);
  assert.equal(await summon(partial, "1.5"), "");
});

// --- The cover text and the decoy ---

test("the cover text gives no advice to wait, and the page proves no decoy", () => {
  assert.doesNotMatch(source, /Fewer coins|The choice is yours|wait for more/);
  assert.ok(!flowSource.includes(["decoy", "Args"].join("")), "no decoy input is built");
  assert.doesNotMatch(flowSource, /decoy: true/);
});

test("coinRecord reads a commit's amount v, and none for a reveal", () => {
  const topics = { commit: toHex(new Uint8Array(32).fill(1)), reveal: toHex(new Uint8Array(32).fill(2)) };
  const v = 123n * GHOST + 7n;
  const data = new Uint8Array(4 + 4 + 32 + 32 + 156);
  const word = BigInt.asUintN(256, v).toString(16).padStart(64, "0");
  for (let i = 0; i < 32; i++) data[40 + i] = parseInt(word.slice(2 * i, 2 * i + 2), 16);
  const commit = coinRecord({ succeeded: true, topics: [new Uint8Array(32).fill(1)], data }, topics);
  assert.equal(commit.v, v);
  const reveal = coinRecord(
    { succeeded: true, topics: [new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)], data: new Uint8Array(4 + 4 + 32 + 156 + 20 + 32) },
    topics,
  );
  assert.equal(reveal.v, null);
});

// --- The pop-up connector's ghost_newReceiveAddress ---

// The page's window with a stand-in pop-up on WALLET_ORIGIN: every message
// the page posts is recorded, and `answer(data)` delivers the wallet's reply.
function popupPage() {
  const listeners = new Set();
  const posts = [];
  const popup = { closed: false, close() {}, postMessage: (data, targetOrigin) => posts.push({ data, targetOrigin }) };
  const win = {
    open: () => popup,
    addEventListener: (kind, handler) => kind === "message" && listeners.add(handler),
    removeEventListener: (kind, handler) => listeners.delete(handler),
    setInterval: (fn, ms) => setInterval(fn, ms).unref(),
    clearInterval: (t) => clearInterval(t),
  };
  const answer = (data) => listeners.forEach((h) => h({ data, origin: WALLET_ORIGIN, source: popup }));
  return { win, posts, answer };
}

const WALLET_ORIGIN = "https://wallet.example";

test("the pop-up connector asks ghost_newReceiveAddress; method not found reads as null, a rejection stays one", async () => {
  const page = popupPage();
  const c = popupConnector({ win: page.win, origin: WALLET_ORIGIN, pollMs: 5 });
  await assert.rejects(c.newReceiveAddress(), /connect the wallet first/);
  const connecting = c.connect();
  page.answer({ ready: true });
  await settle();
  page.answer({ id: page.posts[0].data.id, result: { address: WALLET } });
  await connecting;

  // A fresh address, read in lower case.
  let asking = c.newReceiveAddress();
  await settle();
  assert.deepEqual(page.posts.at(-1), { data: { id: page.posts.at(-1).data.id, method: "ghost_newReceiveAddress" }, targetOrigin: WALLET_ORIGIN });
  page.answer({ id: page.posts.at(-1).data.id, result: { address: FRESH.toUpperCase().replace("0X", "0x") } });
  assert.deepEqual(await asking, { address: FRESH });

  // A wallet that does not know the request answers method not found, with
  // the code the pop-up wallet uses for it.
  const walletSource = readFileSync(new URL("../../wallet/src/wallet.mjs", import.meta.url), "utf8");
  assert.match(walletSource, new RegExp(`METHOD_NOT_FOUND = ${METHOD_NOT_FOUND};`));
  asking = c.newReceiveAddress();
  await settle();
  page.answer({ id: page.posts.at(-1).data.id, error: { code: METHOD_NOT_FOUND, message: "unknown method ghost_newReceiveAddress" } });
  assert.equal(await asking, null);

  // Turned down, or a malformed answer: errors, never an address.
  asking = c.newReceiveAddress();
  await settle();
  page.answer({ id: page.posts.at(-1).data.id, error: { code: 4001, message: "rejected" } });
  await assert.rejects(asking, WalletRejected);
  asking = c.newReceiveAddress();
  await settle();
  page.answer({ id: page.posts.at(-1).data.id, result: { address: "0x12" } });
  await assert.rejects(asking, /without a receive address/);
  c.disconnect();
});

// --- The flow, against the node stand-in ---

async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const worker = nodeProver();
  const ops = [];
  const prover = {
    request(op, args, onProgress) {
      ops.push(op);
      return worker.request(op, args, onProgress);
    },
  };
  const flow = createFlow({ prover, endpoint: node.url, networks: node.networks(), pollMs: 5, maxPolls: 50, sleep: async () => node.mine() });
  node.fund(TEST_WALLET_ADDRESS, 100n * GHOST);
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { node, flow, ops, done };
}

async function vanish(flow, amount) {
  const key = await flow.vanishStart(amount);
  const sent = await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]));
  assert.equal(sent.ok, true);
  return key;
}

test("newReceiveAddress hands out a new account's address each call, or null for a wallet without the request", { timeout: 300_000, skip: BUILT }, async () => {
  const { flow, done } = await setUp();
  try {
    assert.equal(await flow.newReceiveAddress(), null, "no wallet connected");
    const log = [];
    await flow.walletConnect(testConnector({ log }));
    const first = await flow.newReceiveAddress();
    const second = await flow.newReceiveAddress();
    assert.equal(first, await testAccountAddress(1));
    assert.equal(second, await testAccountAddress(2));
    assert.match(first, /^0x[0-9a-f]{40}$/);
    assert.notEqual(first, TEST_WALLET_ADDRESS, "never the connected address");
    assert.notEqual(first, second, "a new address each call");
    assert.deepEqual(log, ["connect", "newReceiveAddress", "newReceiveAddress"]);

    // A wallet answering "method not found", or with no such method: null.
    await flow.walletConnect(testConnector({ fresh: false }));
    assert.equal(await flow.newReceiveAddress(), null);
    const { newReceiveAddress, ...plain } = testConnector();
    assert.equal(typeof newReceiveAddress, "function");
    await flow.walletConnect(plain);
    assert.equal(await flow.newReceiveAddress(), null);

    // A wallet answering something else is refused, not used.
    await flow.walletConnect({ ...testConnector(), newReceiveAddress: async () => ({ address: "0x12" }) });
    await assert.rejects(flow.newReceiveAddress(), /without a receive address/);
    await flow.walletConnect({ ...testConnector(), newReceiveAddress: async () => ({ address: `0x${"0".repeat(40)}` }) });
    await assert.rejects(flow.newReceiveAddress(), /zero address/);
  } finally {
    await done();
  }
});

test("the flow counts the checked commits of the coin's amount, notes the Vanish's address, and proves nothing for a reveal that cannot be made", { timeout: 600_000, skip: BUILT }, async () => {
  const { node, flow, ops, done } = await setUp();
  try {
    await flow.walletConnect(testConnector());
    const one = await vanish(flow, "1");
    await vanish(flow, "1");
    const odd = await vanish(flow, "0.7");
    assert.deepEqual(flow.state.vanishedFrom, [TEST_WALLET_ADDRESS]);
    node.mineTo(node.tip() + 3);

    const opened = await flow.summonOpen(one);
    assert.equal(opened.current.amount, GHOST);
    assert.equal(opened.amountMatches, 2, "two commits of 1 GHOST, its own included");
    flow.summonClose();
    assert.equal((await flow.summonOpen(odd)).amountMatches, 1, "only its own commit is of 0.7 GHOST");

    // More than the coin can send: refused with no proof made.
    const before = ops.length;
    await assert.rejects(flow.summonReveal({ amount: "5", recipient: OTHER }), /the coin holds/);
    assert.ok(!ops.slice(before).some((op) => op === "prove" || op === "proveTestDepth"), `ops: ${ops.slice(before).join(", ")}`);
    assert.equal(node.reveals.length, 0);
  } finally {
    await done();
  }
});
