// The smallest Vanish (spec 07, section 5, "The smallest Vanish"): the page
// refuses a Vanish under MIN_VANISH_FEES Summon fees for the next block,
// from the endpoint's tip header alone. The flow runs against the node
// stand-in, whose fee is written apart from the app's; then app.mjs runs on a
// small stand-in page over that same real flow, so the refusal is the line
// the user sees, and nothing is sent.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { MIN_VANISH_FEES, formatGhost, minVanishFor, parseGhost } from "../src/chain.mjs";
import { DEFAULT_COMMIT_ENTRY, MAX_COMMIT_FEE, WALLET_APPROVAL, createFlow, normalKey, wrongWords } from "../src/flow.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, testConnector } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
const GWEI = 10n ** 9n;
const HALF_FULL = { gasUsed: 15_000_000n, gasLimit: 30_000_000n };

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

async function until(what, ready, ms = 120_000) {
  const end = Date.now() + ms;
  while (!ready()) {
    if (Date.now() > end) assert.fail(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

// A flow on the node stand-in. `prover` defaults to one that fails any
// request: the minimum needs none.
async function setUp({ prover = null } = {}) {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  node.fund(TEST_WALLET_ADDRESS, 100n * GHOST);
  const ops = [];
  const worker = prover ?? {
    request: async (op) => {
      ops.push(op);
      throw new Error(`no worker request expected, got ${op}`);
    },
    terminate() {},
  };
  const make = (onChange = () => {}) =>
    createFlow({
      prover: worker,
      endpoint: node.url,
      commitEntry: DEFAULT_COMMIT_ENTRY,
      networks: node.networks(),
      pollMs: 5,
      sleep: async () => node.mine(),
      onChange,
    });
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { node, make, ops, done };
}

test("the Vanish minimum is four Summon fees", async () => {
  assert.equal(MIN_VANISH_FEES, 4n);
  // The worked number of spec 07, section 5, at b_ref 1 gwei.
  assert.equal(minVanishFor({ baseFee: GWEI, ...HALF_FULL }), 104401981374637640n);
  // The next block's base fee, not the tip's: a full tip raises it 12.5%.
  const full = minVanishFor({ baseFee: GWEI, gasUsed: 30_000_000n, gasLimit: 30_000_000n });
  assert.equal(full, minVanishFor({ baseFee: GWEI + GWEI / 8n, ...HALF_FULL }));
  assert.ok(full > 104401981374637640n);

  const { node, make, ops, done } = await setUp();
  try {
    const flow = make();
    // At the stand-in's own base fee, then at another one, with the next
    // block both inside a window and at a window's first block.
    for (const [baseFee, tip] of [
      [GWEI, 5],
      [3n * GWEI, 11],
      [3n * GWEI, 13],
    ]) {
      node.setBaseFee(baseFee);
      node.mineTo(tip);
      const before = node.requests.length;
      const min = await flow.minVanish();
      assert.equal(min, 4n * node.fee(node.tip() + 1), `base fee ${baseFee}, tip ${tip}`);
      // One header read, the tip's, and nothing else of the chain.
      const asked = node.requests.slice(before).map((r) => r.method);
      assert.deepEqual(asked, ["eth_getBlockByNumber"]);
      assert.equal(node.requests.at(-1).params[0], "latest");
    }
    assert.deepEqual(ops, [], "no worker request: no header chain is checked");
    assert.equal(flow.state.vanish, null);
  } finally {
    await done();
  }
});

// --- The page: app.mjs over the real flow ---

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
  fire(type) {
    for (const handler of this.listeners[type] ?? []) handler({ preventDefault() {}, key: undefined });
  }
}

// Starts app.mjs on a stand-in page whose flow is the real one, made by
// `make` against the node stand-in. Returns the page and that flow.
function startPage(make) {
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!tags.has(id)) return null;
      if (!elements.has(id)) {
        const el = new Element("x", id);
        el.hidden = /\shidden[\s>]/.test(tags.get(id));
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
  const visible = () => ["form", "key", "check", "waiting", "done", "after"].filter((s) => !$(`vanish-${s}`).hidden);
  let flow = null;
  const pageFlow = ({ onChange }) => (flow = make(onChange));

  const body = source.replace(/^import .*;$/gm, "");
  const names = ["document", "window", "navigator", "setInterval", "formatGhost", "parseGhost", "createFlow", "normalKey"];
  const more = ["wrongWords", "DEFAULT_COMMIT_ENTRY", "MAX_COMMIT_FEE", "WALLET_APPROVAL", "DEFAULT_ENDPOINT", "browserProver", "downloadKeyImage"];
  const local = ["createHeaderStore", "INSTALL_LINES", "INSTALL_SITE", "probeLocalNode", "systemOf"];
  new Function(...names, ...more, ...local, body)(
    document,
    window,
    { clipboard: { writeText: async () => {} } },
    () => 0,
    formatGhost,
    parseGhost,
    pageFlow,
    normalKey,
    wrongWords,
    DEFAULT_COMMIT_ENTRY,
    MAX_COMMIT_FEE,
    WALLET_APPROVAL,
    "http://127.0.0.1:8545",
    () => ({}),
    async () => {},
    // No header store, and a look for a local node that finds none without
    // reaching the network.
    () => null,
    { Linux: "" },
    "",
    async () => false,
    () => "Linux",
  );
  return { $, visible, flow };
}

test("a Vanish below the minimum is refused with one plain line", async () => {
  const prover = nodeProver();
  const { node, make, done } = await setUp({ prover });
  try {
    const page = startPage(make);
    await page.flow.walletConnect(testConnector());
    const min = 4n * node.fee(node.tip() + 1);
    // 0.1044... GHOST, shown rounded up to 4 decimals.
    assert.equal(min, 104401981374637640n);
    const LINE = "Vanish at least 0.1045 GHOST: a smaller coin could not pay the Summon fee later.";

    const submit = async (amount) => {
      page.$("vanish-error").textContent = "";
      page.$("vanish-amount").value = amount;
      page.$("vanish-form").fire("submit");
      await until(`the answer to ${amount}`, () => page.$("vanish-error").textContent !== "" || page.visible().join() === "key");
    };

    for (const amount of ["0.1", formatGhost(min - 1n), "0.000000000000000001"]) {
      await submit(amount);
      assert.equal(page.$("vanish-error").textContent, LINE, amount);
      assert.deepEqual(page.visible(), ["form"], amount);
      assert.equal(page.flow.state.vanish, null, `no key is made for ${amount}`);
      assert.equal(page.$("error").textContent, "", "the flow's own text stays off the page");
    }
    assert.equal(node.accountTxs.length, 0, "no commit sent");
    assert.equal(node.requests.filter((r) => r.method === "eth_sendRawTransaction").length, 0);

    // The minimum itself goes on to the key screen.
    await submit(formatGhost(min));
    assert.equal(page.$("vanish-error").textContent, "");
    assert.deepEqual(page.visible(), ["key"]);
    assert.equal(page.flow.state.vanish.amount, min);
    assert.equal(node.accountTxs.length, 0, "nothing is sent before the check");
  } finally {
    await done();
  }
});
