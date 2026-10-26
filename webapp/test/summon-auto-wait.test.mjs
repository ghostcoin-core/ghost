// A Summon right after a Vanish, by one person with one wallet: nobody else
// commits, nobody presses a block command, and nobody presses anything
// after Confirm Summon. While the coin's block is not yet 2 blocks deep
// (SETTLE_DEPTH, spec 02, section 8) the flow proves nothing, polls the tip
// with its block-waiting helper and shows one plain line; once the block is
// 2 deep it proves against the newest settled root, the coin's own block's
// tree, and sends.
//
// The flow tests run the real prover, built for wasm32-unknown-unknown,
// against the node stand-in, when a module is built. The page test runs
// app.mjs against a stand-in page and a stand-in flow, with nothing built.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { SETTLE_DEPTH, formatGhost, parseAddress, parseGhost } from "../src/chain.mjs";
import { DEFAULT_COMMIT_ENTRY, WALLET_APPROVAL, WaitError, createFlow, settleWait } from "../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet, wasmPath } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const BUILT = existsSync(wasmPath) ? false : `no WebAssembly module built at ${wasmPath}`;
const GHOST = 10n ** 18n;
const RECIPIENT = "0x2222222222222222222222222222222222222222";

// A stand-in node and a flow on it, one wallet, no other commit. While the
// flow waits (`sleep`), the chain grows by one block on its own, unless
// `chain.mining` is false. Each proof records the tip it was started at and
// whether it is of a real key's coin.
async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const worker = nodeProver();
  const proofs = [];
  const prover = {
    request(op, args, onProgress) {
      if (op === "prove" || op === "proveTestDepth") proofs.push({ tip: node.tip(), real: Boolean(args && args.key) });
      return worker.request(op, args, onProgress);
    },
  };
  const chain = { mining: true };
  const stages = [];
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks: node.networks(),
    pollMs: 5,
    maxPolls: 20,
    resendMs: 3,
    sleep: async () => {
      if (chain.mining) node.mine();
    },
    onChange: (s) => {
      if (s.progress && stages.at(-1) !== s.progress.stage) stages.push(s.progress.stage);
    },
  });
  await openTestWallet(flow, node);
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { node, flow, chain, proofs, stages, done };
}

async function vanish(flow, amount) {
  const key = await flow.vanishStart(amount);
  const sent = await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]));
  assert.equal(sent.ok, true);
  return key;
}

test("one wallet Vanishes and Summons at once: the Summon waits for its block by itself and goes on", { timeout: 600_000, skip: BUILT }, async () => {
  const { node, flow, chain, proofs, stages, done } = await setUp();
  try {
    // Empty blocks only: nobody has committed before or after.
    node.mineTo(12);
    chain.mining = false;
    const key = await vanish(flow, "1");
    assert.equal(node.leaves.length, 1, "the only coin on the chain");
    const block = node.leaves[0].block;
    assert.ok(node.tip() < block + SETTLE_DEPTH, "its block is not yet 2 deep");

    // Opening the key: one plain line, nothing about anyone else.
    const opened = await flow.summonOpen(key);
    assert.equal(opened.status, "unclaimed");
    assert.equal(opened.cover, null);
    assert.deepEqual(opened.wait, { message: settleWait(block), from: block + SETTLE_DEPTH });
    assert.doesNotMatch(opened.wait.message, /someone|anyone|nobody|other/);

    // Summon, once: no Check, no block command, no second wallet.
    chain.mining = true;
    const fromStage = stages.length;
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(reveal.stage, "done");
    assert.equal(flow.state.error, null);

    // It waited with the plain line, proving nothing, then proved once, at
    // the first tip at which the coin's block was 2 deep.
    assert.ok(stages.slice(fromStage).includes(settleWait(block)), `stages: ${stages.slice(fromStage).join(" | ")}`);
    assert.deepEqual(proofs, [{ tip: block + SETTLE_DEPTH, real: true }], "one real proof, 2 blocks after the Vanish");
    assert.equal(node.reveals.length, 1);
    assert.equal(toHex(node.reveals[0].root), toHex(node.blocks[block].coinTreeRoot), "against the coin's own block's tree");
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
    // Nobody else committed: the only later leaf is the reveal's remainder.
    assert.equal(node.leaves.length, 2);

    // The remainder is summoned the same way, again with no other commit.
    const again = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(again.stage, "done");
    assert.equal(node.reveals.length, 2);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 2n);
    assert.equal(proofs.length, 2);
    assert.ok(proofs[1].tip >= node.leaves[1].block + SETTLE_DEPTH, "the remainder's block was 2 deep");
  } finally {
    await done();
  }
});

test("a Summon whose coin's block never gets 2 deep gives up after the flow's polls, proving and sending nothing", { timeout: 600_000, skip: BUILT }, async () => {
  const { node, flow, chain, proofs, done } = await setUp();
  try {
    node.mineTo(12);
    chain.mining = false;
    const key = await vanish(flow, "1");
    const block = node.leaves[0].block;
    await flow.summonOpen(key);
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => {
      assert.ok(!(err instanceof WaitError), "the wait is the flow's, not the holder's");
      assert.match(err.message, new RegExp(`the chain has not reached block ${block + SETTLE_DEPTH} yet`));
      return true;
    });
    assert.deepEqual(proofs, []);
    assert.equal(node.reveals.length, 0);
    assert.equal(flow.state.busy, null);
  } finally {
    await done();
  }
});

// The endpoint's requests from request `from` up to the reveal's send, with
// hashes left out and block numbers counted from the tip `base` at which
// Summon was pressed: what the endpoint can tell apart before the reveal.
function beforeSend(node, from, base) {
  const calls = node.requests.slice(from).map((r) => JSON.stringify([r.method, r.params]));
  const sent = calls.findIndex((c) => c.startsWith('["eth_sendRawTransaction"'));
  assert.ok(sent > 0, "the reveal was sent");
  return calls.slice(0, sent).map((c) =>
    c
      .replace(/0x[0-9a-f]{64}/g, "0xhash")
      .replace(/^\["eth_getBlockByNumber",\["(0x[0-9a-f]+)"/, (_, n) => {
        const number = Number(BigInt(n));
        return `["eth_getBlockByNumber",["${number === 0 ? "genesis" : `tip${number - base >= 0 ? "+" : ""}${number - base}`}"`;
      }),
  );
}

// A page whose history is the same every time: a Vanish of key `early`,
// empty blocks to 40, then a Vanish of key `fresh` at block `young`, the
// tip. Then `which` of the two keys is opened and summoned at once; the
// requests from the press up to the send, the tip at the press and the
// tips the flow proved at.
async function summonOnePage(which) {
  const { node, flow, chain, proofs, done } = await setUp();
  try {
    const keys = { early: await vanish(flow, "1") };
    node.mineTo(40);
    chain.mining = false;
    keys.fresh = await vanish(flow, "1");
    const young = node.leaves.at(-1).block;
    assert.equal(node.tip(), young);
    const { wait } = await flow.summonOpen(keys[which]);
    const coinBlock = node.leaves[which === "early" ? 0 : 1].block;
    chain.mining = true;
    const base = node.tip();
    const from = node.requests.length;
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(reveal.stage, "done");
    assert.equal(node.reveals.length, 1);
    return { young, coinBlock, wait: wait && { ...wait }, base, requests: beforeSend(node, from, base), proofs: [...proofs] };
  } finally {
    await done();
  }
}

test("the requests before a Summon's send do not depend on the coin's block", { timeout: 600_000, skip: BUILT }, async () => {
  // The same page history; one summons the coin of the block at the tip,
  // the other a coin about 40 blocks deep.
  const fresh = await summonOnePage("fresh");
  const early = await summonOnePage("early");
  assert.equal(fresh.young, early.young);
  assert.equal(fresh.coinBlock, fresh.young, "a coin 0 blocks deep");
  assert.ok(early.coinBlock + 32 < early.young, "a coin long settled");
  assert.deepEqual(fresh.wait, { message: settleWait(fresh.young), from: fresh.young + SETTLE_DEPTH });
  assert.equal(early.wait, null);
  assert.equal(fresh.base, early.base, "Summon pressed at the same tip");

  // Both wait for the page's own newest block, the Vanish the endpoint
  // took, to be 2 deep: the tip, polls until it has moved 2 blocks, then
  // one scan, the proof's place and the fee, the same requests in the same
  // order, whichever coin the key holds.
  assert.ok(fresh.requests.filter((r) => r.startsWith('["eth_blockNumber"')).length >= 3, "the tip was polled");
  assert.deepEqual(early.requests, fresh.requests, "an old coin and a coin 0 blocks deep ask the same before the send");
  assert.deepEqual(fresh.proofs, [{ tip: fresh.young + SETTLE_DEPTH, real: true }]);
  assert.deepEqual(early.proofs, fresh.proofs, "each proved once, at the same tip");
});

// --- The page: app.mjs on a stand-in page with a stand-in flow ---

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");
const tags = new Map([...html.matchAll(/<[a-z]+\b[^>]*\bid="([^"]+)"[^>]*>/gi)].map((m) => [m[1], m[0]]));
const WALLET = `0x3a${"0".repeat(34)}091c`;
const KEY = Array.from({ length: 24 }, (_, i) => `word${String.fromCharCode(97 + i)}`).join(" ");
const FEE = 10n ** 14n;
const BLOCK = 9;

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

const settle = async (n = 4) => {
  for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve));
};

// Starts app.mjs with a stand-in flow whose key holds a coin in block
// BLOCK, not yet 2 deep. Its reveal reports the real flow's plain line
// (settleWait) for `polls` polls, each step released by `next()`, then
// proves, sends and is Done.
function startPage({ polls = 2 } = {}) {
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
  const $ = (id) => document.getElementById(id);
  const screens = () => ["form", "confirm", "waiting", "done"].filter((s) => !$(`summon-${s}`).hidden);
  const log = { reveals: 0, seen: [] };
  let release = null;
  const next = async () => {
    const r = release;
    release = null;
    if (r) r();
    await settle();
  };

  function createFlow({ onChange }) {
    const state = {
      endpoint: "http://127.0.0.1:8545",
      commitEntry: DEFAULT_COMMIT_ENTRY,
      chainRefused: null,
      wallet: { id: "test-wallet", name: "Test wallet", address: WALLET, balance: 5n * GHOST },
      busy: null,
      progress: null,
      error: null,
      vanish: null,
      summon: null,
    };
    const emit = () => onChange(state);
    const progress = (stage) => {
      state.progress = stage ? { stage, since: 0 } : null;
      emit();
      log.seen.push({ stage, screens: screens(), line: $("progress").textContent });
    };
    const coin = (s, wait) => {
      s.status = "unclaimed";
      s.current = { number: 1n, amount: 2n * GHOST, treeIndex: 0, position: 0 };
      s.fee = FEE;
      s.available = 2n * GHOST - FEE;
      s.cover = wait ? null : { height: BLOCK, covers: 1, total: 1 };
      s.wait = wait ? { message: settleWait(BLOCK), from: BLOCK + SETTLE_DEPTH } : null;
    };
    return {
      state,
      async summonOpen(text) {
        state.summon = { key: text.trim(), format: "words", groups: 21, coins: [], claim: null, lastReveal: null, pinned: null };
        coin(state.summon, true);
        emit();
        return state.summon;
      },
      async summonRefresh() {
        return state.summon;
      },
      async summonReveal({ amount, recipient }) {
        const s = state.summon;
        log.reveals += 1;
        state.busy = "revealing";
        try {
          progress("looking for the key's coins");
          for (let i = 0; i < polls; i += 1) {
            progress(settleWait(BLOCK));
            await new Promise((resolve) => (release = resolve));
          }
          progress("proving in the background worker");
          await null;
          progress("sending the reveal");
          s.lastReveal = { stage: "sent", txHash: "0x01", out: parseGhost(amount), recipient, fee: FEE, block: null };
          progress("waiting for a block");
          await null;
          s.lastReveal.stage = "done";
          s.lastReveal.block = BLOCK + 3;
          coin(s, false);
          return s.lastReveal;
        } finally {
          state.busy = null;
          progress(null);
        }
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
  const names = ["document", "window", "navigator", "setInterval", "formatGhost", "parseGhost", "createFlow", "normalKey"];
  const more = ["wrongWords", "DEFAULT_COMMIT_ENTRY", "MAX_COMMIT_FEE", "WALLET_APPROVAL", "DEFAULT_ENDPOINT", "browserProver", "downloadKeyImage"];
  const local = ["createHeaderStore", "INSTALL_LINES", "INSTALL_SITE", "probeLocalNode", "systemOf"];
  new Function(...names, ...more, "popupConnector", "parseAddress", ...local, body)(
    document,
    new Element("window"),
    { clipboard: { writeText: async () => {} } },
    () => 0,
    formatGhost,
    parseGhost,
    createFlow,
    (text) => String(text).trim().split(/\s+/).join(" "),
    () => [],
    DEFAULT_COMMIT_ENTRY,
    10n ** 16n,
    WALLET_APPROVAL,
    "http://127.0.0.1:8545",
    () => ({}),
    async () => {},
    () => assert.fail("no pop-up wallet"),
    parseAddress,
    // No header store, and a look for a local node that finds none without
    // reaching the network.
    () => null,
    { Linux: "" },
    "",
    async () => false,
    () => "Linux",
  );
  $("tab-summon").fire("click");
  return { $, log, screens, next };
}

const PLAIN_LINE = /^Your coin's block is not yet 2 blocks deep\. Summon waits for it by itself, then goes on\.$/;

test("the page shows one plain line for a coin not yet 2 deep, keeps Summon enabled and goes on to Done with no extra click", async () => {
  const page = startPage({ polls: 3 });
  const { $ } = page;
  $("summon-key").value = KEY;
  $("summon-key").fire("input", { inputType: "insertFromPaste" });
  await settle();

  // The form: the plain line, Summon enabled, no Check again to press.
  assert.deepEqual(page.screens(), ["form"]);
  assert.match($("summon-note").textContent, PLAIN_LINE);
  assert.equal($("summon-submit").textContent, "Summon");
  assert.equal($("summon-submit").disabled, false, "a coin not yet 2 deep can still be summoned");
  assert.equal($("summon-refresh").hidden, true, "nothing to press while the page waits");

  // Summon, then Confirm Summon: the only two presses.
  $("summon-amount").value = "0.5";
  $("summon-form").fire("submit");
  await settle();
  assert.deepEqual(page.screens(), ["confirm"]);
  $("summon-confirm-button").fire("click");
  await settle();
  assert.equal(page.log.reveals, 1);

  // While the flow waits for the block: the waiting screen and the one
  // plain line.
  const waiting = page.log.seen.filter((e) => e.stage === settleWait(BLOCK));
  assert.ok(waiting.length >= 1);
  for (const e of waiting) {
    assert.deepEqual(e.screens, ["waiting"]);
    assert.match(e.line, PLAIN_LINE);
  }
  // Blocks come; the page itself goes on, with no further press.
  await page.next();
  await page.next();
  await page.next();
  await settle(8);
  assert.equal(page.log.seen.filter((e) => e.stage === settleWait(BLOCK)).length, 3);
  const proving = page.log.seen.find((e) => e.stage === "proving in the background worker");
  assert.ok(proving, "the reveal went on by itself");
  assert.equal(proving.line, "", "the plain line is gone once the proof is made");
  assert.deepEqual(page.screens(), ["done"]);
  assert.equal(page.log.reveals, 1, "one Summon, no second press");
  assert.equal($("summon-done-amount").textContent, "0.5");
});

test("the page no longer asks the holder to wait for someone else", () => {
  assert.doesNotMatch(source, /\.alone\b/);
  assert.doesNotMatch(source, /someone else/i);
  // The note on the form while the coin's block settles asks for no press.
  const at = source.indexOf("function summonNote(");
  assert.notEqual(at, -1);
  assert.doesNotMatch(source.slice(at, source.indexOf("\n}\n", at)), /Press/);
  assert.doesNotMatch(source, /Press Refresh to check again/);
});
