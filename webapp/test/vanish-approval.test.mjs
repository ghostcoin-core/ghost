// Vanish asks the connected wallet to approve the commit before anything is
// sent. The flow controller runs against the node stand-in with the tests'
// wallet connector (support/env.mjs), which holds each signature until the
// test approves or turns it down; then app.mjs runs on a small stand-in page
// over that same real flow, so the screens are those the user sees. A
// rejection, or any other failure to sign, sends nothing.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { formatGhost, parseGhost } from "../src/chain.mjs";
import { DEFAULT_COMMIT_ENTRY, MAX_COMMIT_FEE, WALLET_APPROVAL, createFlow, normalKey, wrongWords } from "../src/flow.mjs";
import { USER_REJECTED, WalletRejected, injectedProvider, snapConnector } from "../src/wallet-connect.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, testConnector } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
const REJECTED = "You rejected it in your wallet. Nothing was sent.";
const SIGN_FAILED = "Your wallet could not sign the Vanish. Nothing was sent.";
const RAW = "synthetic wallet failure text";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

const rejection = () => Object.assign(new Error("User rejected the request."), { code: USER_REJECTED });

// The tests' wallet, holding each signature until the test answers it:
// `asked()` resolves with the fields once the wallet is asked to sign;
// `approve()` signs them, `refuse(err)` makes the wallet throw `err`.
// `signed` holds every transaction the wallet signed.
function heldWallet() {
  const wallet = { asks: 0, signed: [] };
  let answer = null;
  let onAsk = null;
  const base = testConnector({
    approve: (fields) => {
      wallet.asks++;
      const decided = new Promise((resolve, reject) => {
        answer = { resolve, reject };
      });
      if (onAsk) onAsk(fields);
      return decided;
    },
  });
  wallet.connector = {
    ...base,
    async signTransaction(fields) {
      const signed = await base.signTransaction(fields);
      wallet.signed.push(signed);
      return signed;
    },
  };
  wallet.asked = () =>
    new Promise((resolve) => {
      onAsk = resolve;
    });
  wallet.approve = () => answer.resolve();
  wallet.refuse = (err) => answer.reject(err);
  return wallet;
}

async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  node.fund(TEST_WALLET_ADDRESS, 100n * GHOST);
  const make = (onChange = () => {}) =>
    createFlow({
      prover,
      endpoint: node.url,
      commitEntry: DEFAULT_COMMIT_ENTRY,
      networks: node.networks(),
      pollMs: 5,
      sleep: async () => node.mine(),
      onChange,
    });
  const done = async () => {
    prover.terminate();
    await node.close();
  };
  return { node, make, done };
}

const sends = (node) => node.requests.filter((r) => r.method === "eth_sendRawTransaction");

// The three words the save check asks, from the key the flow shows.
function rightWords(v) {
  const words = v.key.split(" ");
  return v.groups.map((p) => words[p - 1]);
}

async function until(what, ready, ms = 120_000) {
  const end = Date.now() + ms;
  while (!ready()) {
    if (Date.now() > end) assert.fail(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

// --- The flow ---

test("the flow sends the commit once the wallet approves it, with the envelope the wallet signed", async () => {
  const { node, make, done } = await setUp();
  try {
    const stages = [];
    const flow = make((s) => {
      if (s.progress && stages.at(-1) !== s.progress.stage) stages.push(s.progress.stage);
    });
    const wallet = heldWallet();
    await flow.walletConnect(wallet.connector);
    await flow.vanishStart("1");
    flow.vanishSaved();
    const asked = wallet.asked();
    const check = flow.vanishCheck(rightWords(flow.state.vanish));
    const fields = await asked;
    // While the wallet shows it, the flow waits on the approval and nothing
    // has reached the endpoint.
    assert.equal(flow.state.progress.stage, WALLET_APPROVAL);
    assert.equal(sends(node).length, 0);
    assert.equal(toHex(fields.to), DEFAULT_COMMIT_ENTRY);
    assert.equal(fields.value, GHOST);
    wallet.approve();
    const sent = await check;
    assert.equal(sent.ok, true);
    assert.equal(sends(node).length, 1, "sent once");
    assert.equal(sends(node)[0].params[0], toHex(wallet.signed[0].envelope), "the envelope the wallet returned");
    assert.equal(sent.txHash, toHex(wallet.signed[0].txHash));
    assert.equal(node.accountTxs.length, 1);
    assert.ok(stages.indexOf(WALLET_APPROVAL) < stages.indexOf("sending the commit"), stages.join(" / "));
  } finally {
    await done();
  }
});

test("a rejection in the wallet, by code or by name, sends nothing", async () => {
  const { node, make, done } = await setUp();
  try {
    const flow = make();
    const wallet = heldWallet();
    await flow.walletConnect(wallet.connector);
    await flow.vanishStart("1");
    flow.vanishSaved();
    for (const turnedDown of [rejection(), new WalletRejected("the transaction")]) {
      const asked = wallet.asked();
      const check = flow.vanishCheck(rightWords(flow.state.vanish));
      await asked;
      wallet.refuse(turnedDown);
      await assert.rejects(check, (err) => {
        assert.equal(err.name, "WalletRejected");
        assert.match(err.message, /rejected in your wallet; nothing was sent/);
        return true;
      });
      assert.equal(sends(node).length, 0, "eth_sendRawTransaction is never called");
      assert.equal(node.accountTxs.length, 0);
    }
    assert.equal(wallet.signed.length, 0);
  } finally {
    await done();
  }
});

test("any other failure to sign sends nothing and says the wallet could not sign", async () => {
  const { node, make, done } = await setUp();
  try {
    const flow = make();
    const wallet = heldWallet();
    await flow.walletConnect(wallet.connector);
    await flow.vanishStart("1");
    flow.vanishSaved();
    const asked = wallet.asked();
    const check = flow.vanishCheck(rightWords(flow.state.vanish));
    await asked;
    wallet.refuse(new Error(RAW));
    await assert.rejects(check, (err) => {
      assert.equal(err.name, "WalletSignFailed");
      assert.notEqual(err.name, "WalletRejected");
      assert.match(err.message, /^the wallet could not sign the transaction: .*; nothing was sent$/);
      return true;
    });
    assert.equal(sends(node).length, 0);
    assert.equal(node.accountTxs.length, 0);
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
  const wallets = ["injectedProvider", "snapConnector"];
  new Function(...names, ...more, ...wallets, body)(
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
    injectedProvider,
    snapConnector,
  );
  return { $, visible, flow, ids: () => [...elements.keys()] };
}

// Vanish `amount` on the page up to the check, then types the right words
// and submits it; resolves once the wallet is asked to sign.
async function vanishToWallet(page, wallet, amount = "1") {
  page.$("vanish-amount").value = amount;
  page.$("vanish-form").fire("submit");
  await until("the key screen", () => page.visible().join() === "key");
  page.$("vanish-saved").fire("click");
  await until("the check screen", () => page.visible().join() === "check");
  const words = rightWords(page.flow.state.vanish);
  page.$("vanish-check-groups").querySelectorAll("input").forEach((input, i) => (input.value = words[i]));
  const asked = wallet.asked();
  page.$("vanish-check").fire("submit");
  await asked;
  await until("the approval line", () => page.$("vanish-waiting-text").textContent !== "");
}

test("on the page: the waiting screen asks for the wallet's approval; approved, the commit goes out once", async () => {
  const { node, make, done } = await setUp();
  try {
    const page = startPage(make);
    const wallet = heldWallet();
    await page.flow.walletConnect(wallet.connector);
    await vanishToWallet(page, wallet);
    assert.deepEqual(page.visible(), ["waiting"]);
    assert.equal(page.$("vanish-waiting-text").textContent, "Approve the Vanish in your wallet");
    assert.equal(sends(node).length, 0, "nothing is sent before the approval");

    wallet.approve();
    await until("Done", () => page.visible().join() === "done");
    assert.equal(sends(node).length, 1);
    assert.equal(sends(node)[0].params[0], toHex(wallet.signed[0].envelope));
    assert.equal(wallet.asks, 1);
    assert.equal(page.$("vanish-error").textContent, "");
  } finally {
    await done();
  }
});

test("on the page: rejected in the wallet, nothing is sent, the key is dropped and the card is back at the amount", async () => {
  const { node, make, done } = await setUp();
  try {
    const page = startPage(make);
    const wallet = heldWallet();
    await page.flow.walletConnect(wallet.connector);
    await vanishToWallet(page, wallet, "1.5");
    const key = page.flow.state.vanish.key;
    assert.equal(page.$("vanish-waiting-text").textContent, "Approve the Vanish in your wallet");

    wallet.refuse(rejection());
    await until("the amount screen", () => page.visible().join() === "form");
    assert.equal(page.$("vanish-error").textContent, REJECTED);
    assert.equal(sends(node).length, 0, "eth_sendRawTransaction is never called");
    assert.equal(node.accountTxs.length, 0);
    // The new key is gone from the flow and from the page.
    assert.equal(page.flow.state.vanish, null);
    assert.equal(page.$("vanish-words").children.length, 0);
    assert.equal(page.$("vanish-check-groups").children.length, 0);
    for (const id of page.ids()) assert.ok(!page.$(id).textContent.includes(key), id);
    // The amount stays typed, to try again.
    assert.equal(page.$("vanish-amount").value, "1.5");
    assert.equal(page.$("error").textContent, "");

    // A new Vanish makes a new key and asks the wallet again.
    await vanishToWallet(page, wallet, "1.5");
    assert.notEqual(page.flow.state.vanish.key, key);
    wallet.approve();
    await until("Done", () => page.visible().join() === "done");
    assert.equal(sends(node).length, 1);
    assert.equal(wallet.asks, 2);
  } finally {
    await done();
  }
});

test("on the page: another signing error sends nothing and shows its own line", async () => {
  const { node, make, done } = await setUp();
  try {
    const page = startPage(make);
    const wallet = heldWallet();
    await page.flow.walletConnect(wallet.connector);
    await vanishToWallet(page, wallet);
    wallet.refuse(new Error(RAW));
    await until("the error line", () => page.$("vanish-error").textContent !== "");
    assert.equal(page.$("vanish-error").textContent, SIGN_FAILED);
    assert.notEqual(page.$("vanish-error").textContent, REJECTED);
    assert.deepEqual(page.visible(), ["check"]);
    assert.equal(sends(node).length, 0);
    for (const id of page.ids()) assert.ok(!page.$(id).textContent.includes(RAW), id);
  } finally {
    await done();
  }
});
