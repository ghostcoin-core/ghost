// The card's Show wallet button: while a wallet approval waits (connect, or
// a Vanish's commit), one secondary button under the status line brings the
// Ghost wallet's window to the front; a window the user closed is opened
// again and asked again. The connector's show() (popup-wallet.mjs) runs
// against a stand-in page window, the flow's walletShow() and walletAsking
// against the node stand-in with the real flow, and app.mjs on a small
// stand-in page.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { formatGhost, parseGhost } from "../src/chain.mjs";
import { DEFAULT_COMMIT_ENTRY, MAX_COMMIT_FEE, WALLET_APPROVAL, createFlow, normalKey, wrongWords } from "../src/flow.mjs";
import { PopupBlocked, popupConnector } from "../src/popup-wallet.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, testConnector, wasmPath } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const WALLET = "https://wallet.example";
const ADDRESS = `0x${"ab".repeat(20)}`;
const APPROVE_LINE = "Approve the Vanish in the Ghost wallet window. Can't see it? Show wallet.";
const settle = () => new Promise((resolve) => setImmediate(resolve));
const KEY = Array.from({ length: 24 }, (_, i) => `word${String.fromCharCode(97 + i)}`).join(" ");

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const css = readFileSync(new URL("../style.css", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

// --- The connector ---

// The page's window: each window.open makes a stand-in pop-up that logs its
// focus calls and the requests posted to it. Messages from a pop-up are
// delivered with `say(popup, data)`. The closed flag is polled only every
// minute here, so a window closed by the test stays unnoticed until show().
function fakePage({ block = false } = {}) {
  const listeners = new Set();
  const page = {
    windows: [],
    open() {
      if (block) return null;
      const w = { closed: false, focuses: 0, posts: [], focus: () => (w.focuses += 1), postMessage: (data, to) => w.posts.push({ data, to }), close: () => (w.closed = true) };
      page.windows.push(w);
      return w;
    },
    addEventListener: (type, handler) => type === "message" && listeners.add(handler),
    removeEventListener: (type, handler) => listeners.delete(handler),
    say: (source, data) => listeners.forEach((h) => h({ data, origin: WALLET, source })),
    listeners,
    setInterval: (fn) => setInterval(fn, 60_000).unref(),
    clearInterval: (t) => clearInterval(t),
  };
  return page;
}

test("show() focuses the open wallet window while a request waits, and does nothing otherwise", async () => {
  const page = fakePage();
  const c = popupConnector({ win: page, origin: WALLET });
  assert.equal(c.show(), false, "nothing waits before any request");
  assert.equal(page.windows.length, 0, "show() opens no window while nothing waits");

  const connecting = c.connect();
  const [w] = page.windows;
  page.say(w, { ready: true });
  await settle();
  assert.equal(w.focuses, 1, "the request focuses the window once");
  assert.equal(c.show(), true);
  assert.equal(w.focuses, 2, "Show wallet focuses it again");
  assert.equal(page.windows.length, 1, "an open window is not opened again");
  page.say(w, { id: w.posts[0].data.id, result: { address: ADDRESS } });
  assert.deepEqual(await connecting, { address: ADDRESS });

  assert.equal(c.show(), false, "nothing waits once the wallet answered");
  assert.equal(w.focuses, 2);
  c.disconnect();
});

test("show() opens a closed wallet window again and asks the waiting request again there", async () => {
  const page = fakePage();
  const c = popupConnector({ win: page, origin: WALLET });
  const connecting = c.connect();
  const [first] = page.windows;
  page.say(first, { ready: true });
  await settle();
  assert.deepEqual(first.posts.map((p) => p.data.method), ["ghost_getAccount"]);

  // The user closes the window before the page noticed.
  first.closed = true;
  assert.equal(c.show(), true);
  assert.equal(page.windows.length, 2, "a new window is opened");
  const second = page.windows[1];
  // Nothing is posted before the new window says it is listening; ready
  // from the closed window does not count.
  page.say(first, { ready: true });
  await settle();
  assert.equal(second.posts.length, 0);
  page.say(second, { ready: true });
  await settle();
  assert.deepEqual(
    second.posts.map((p) => [p.to, p.data.method, p.data.id]),
    [[WALLET, "ghost_getAccount", first.posts[0].data.id]],
    "the same request is asked again, to the wallet's origin only",
  );
  assert.equal(second.focuses, 1);
  // An answer from the closed window is not taken; the new one's is.
  page.say(first, { id: first.posts[0].data.id, result: { address: `0x${"66".repeat(20)}` } });
  page.say(second, { id: second.posts[0].data.id, result: { address: ADDRESS } });
  assert.deepEqual(await connecting, { address: ADDRESS });
  c.disconnect();
  assert.equal(second.closed, true);
});

test("show() with the window blocked turns the waiting request down and says the window was blocked", async () => {
  const page = fakePage();
  const c = popupConnector({ win: page, origin: WALLET });
  const connecting = c.connect();
  const caught = connecting.catch((err) => err);
  page.windows[0].closed = true;
  page.open = () => null;
  assert.throws(() => c.show(), PopupBlocked);
  const err = await caught;
  assert.equal(err.name, "WalletRejected");
  assert.equal(page.listeners.size, 0, "the page stops listening");
  assert.equal(c.show(), false);
});

// --- The flow ---

const GHOST = 10n ** 18n;
const BUILT = existsSync(wasmPath) ? false : `no WebAssembly module built at ${wasmPath}`;

// A wallet with a show() that logs each call, and its connect and signature
// held until the test lets them go. `base` answers both once let go.
function heldWallet(base) {
  const held = { shows: 0, release: null };
  const hold = () =>
    new Promise((resolve) => {
      held.release = resolve;
    });
  held.connector = {
    ...base,
    async connect() {
      await hold();
      return base.connect();
    },
    async signTransaction(fields) {
      await hold();
      return base.signTransaction(fields);
    },
    show() {
      held.shows += 1;
      return true;
    },
  };
  return held;
}

// A node that answers only eth_getBalance, through the flow's fetch.
const balanceFetch = async (_url, request) => {
  const { id, method } = JSON.parse(request.body);
  assert.equal(method, "eth_getBalance");
  return { ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id, result: "0x56bc75e2d63100000" }) };
};

test("the flow says while the wallet asks to connect, and walletShow() reaches that wallet only then", async () => {
  const seen = [];
  const flow = createFlow({ prover: {}, fetch: balanceFetch, onChange: (s) => seen.push(s.walletAsking) });
  const wallet = heldWallet({ id: "test-wallet", name: "Test wallet", connect: async () => ({ address: ADDRESS }), signTransaction: async () => assert.fail("no signature") });
  assert.equal(flow.state.walletAsking, false);
  assert.equal(flow.walletShow(), false, "no wallet asks before connect");

  const connecting = flow.walletConnect(wallet.connector);
  await until("the connect request", () => wallet.release !== null);
  assert.equal(flow.state.walletAsking, true);
  assert.equal(seen.at(-1), true, "the page is told the wallet asks");
  assert.equal(flow.walletShow(), true);
  assert.equal(wallet.shows, 1);
  wallet.release();
  assert.equal(await connecting, ADDRESS);
  assert.equal(flow.state.walletAsking, false);
  assert.equal(seen.at(-1), false, "the page is told it no longer asks");
  assert.equal(flow.walletShow(), false, "connected and idle, nothing to show");
  assert.equal(wallet.shows, 1);

  // Turned down: the button goes too.
  const refusing = { id: "x", name: "x", connect: async () => assert.fail("held"), signTransaction: async () => null };
  const other = heldWallet(refusing);
  const failing = flow.walletConnect(other.connector).catch((err) => err);
  await until("the second connect request", () => other.release !== null);
  assert.equal(flow.state.walletAsking, true);
  other.release();
  assert.ok((await failing) instanceof Error);
  assert.equal(flow.state.walletAsking, false);
  assert.equal(seen.at(-1), false);
  assert.equal(flow.walletShow(), false);

  // A wallet without show() cannot be shown, and saying so is not an error.
  const plain = { id: "p", name: "p", connect: () => new Promise(() => {}), signTransaction: async () => null };
  flow.walletConnect(plain).catch(() => {});
  await settle();
  assert.equal(flow.state.walletAsking, true);
  assert.equal(flow.walletShow(), false);
});

async function until(what, ready, ms = 120_000) {
  const end = Date.now() + ms;
  while (!ready()) {
    if (Date.now() > end) assert.fail(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

test("the flow says while the wallet asks to approve a Vanish's commit, and walletShow() reaches it then", { timeout: 600_000, skip: BUILT }, async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  node.fund(TEST_WALLET_ADDRESS, 100n * GHOST);
  try {
    const flow = createFlow({
      prover,
      endpoint: node.url,
      commitEntry: DEFAULT_COMMIT_ENTRY,
      networks: node.networks(),
      pollMs: 5,
      sleep: async () => node.mine(),
    });
    const wallet = heldWallet(testConnector());
    const connecting = flow.walletConnect(wallet.connector);
    await until("the connect request", () => wallet.release !== null);
    wallet.release();
    wallet.release = null;
    await connecting;
    assert.equal(flow.walletShow(), false);

    await flow.vanishStart("1");
    const groups = flow.vanishSaved();
    const words = flow.state.vanish.key.split(" ");
    const checking = flow.vanishCheck(groups.map((p) => words[p - 1]));
    await until("the signature request", () => wallet.release !== null);
    assert.equal(flow.state.progress.stage, WALLET_APPROVAL);
    assert.equal(flow.state.walletAsking, true);
    assert.equal(flow.walletShow(), true);
    assert.equal(wallet.shows, 1);
    wallet.release();
    await checking;
    assert.equal(flow.state.walletAsking, false);
    assert.equal(flow.walletShow(), false);
    assert.equal(wallet.shows, 1);
  } finally {
    prover.terminate();
    await node.close();
  }
});

// --- The page ---

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

test("the card holds one secondary Show wallet button under the status line, hidden at first", () => {
  const buttons = [...html.matchAll(/<button\b[^>]*>\s*Show wallet\s*<\/button>/g)];
  assert.equal(buttons.length, 1, "one Show wallet button");
  const tag = buttons[0][0];
  assert.match(tag, /\bid="show-wallet"/);
  assert.match(tag, /\bclass="secondary"/);
  assert.match(tag, /\btype="button"/);
  assert.match(tag, /\shidden[\s>]/);
  assert.ok(element("card").includes(tag), "inside the card");
  const activity = element("activity");
  assert.ok(activity.indexOf('id="progress"') < activity.indexOf('id="show-wallet"'), "under the status line");
  assert.equal(html.match(/class="secondary"/g).length, 1, "the only secondary button");
  assert.match(css, /button\.secondary\s*\{/);
});

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

// Starts app.mjs on a stand-in page with a stand-in flow: `ask(what)` puts
// the flow in a wallet approval ("connect" or "vanish"), `answer()` ends it.
// walletShow() logs each call and throws `showError` when set.
function startPage() {
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!tags.has(id)) return null;
      if (!elements.has(id)) {
        const el = new Element("x", id);
        el.hidden = /\shidden[\s>]/.test(tags.get(id));
        for (const m of tags.get(id).matchAll(/\sdata-([a-z-]+)="([^"]*)"/g)) {
          el.dataset[m[1].replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = m[2];
        }
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
  const log = { shows: 0, showError: null };
  const control = {};

  function createFlow({ onChange }) {
    const state = {
      endpoint: "http://127.0.0.1:8545",
      commitEntry: DEFAULT_COMMIT_ENTRY,
      chainRefused: null,
      wallet: null,
      walletAsking: false,
      busy: null,
      progress: null,
      error: null,
      vanish: null,
      summon: null,
    };
    const emit = () => onChange(state);
    control.ask = () => {
      state.walletAsking = true;
      state.busy = "connecting the wallet";
      emit();
    };
    control.answer = () => {
      state.walletAsking = false;
      state.busy = null;
      state.progress = null;
      emit();
      if (control.finish) control.finish();
    };
    // The Vanish up to its check screen, with the key's first three words
    // asked.
    control.toCheck = () => {
      state.wallet = { id: "test-wallet", name: "Test wallet", address: TEST_WALLET_ADDRESS, balance: 5n * GHOST };
      state.vanish = { stage: "check", key: KEY, view: "words", digits: null, amount: GHOST, groups: [1, 2, 3], wrong: [] };
      emit();
    };
    return {
      state,
      usePublicNode: async () => null,
      // The words match: the wallet is asked to approve the commit, held
      // until answer().
      vanishCheck() {
        state.vanish.wrong = [];
        state.walletAsking = true;
        state.busy = "sending the Vanish";
        state.progress = { stage: WALLET_APPROVAL, since: 0 };
        emit();
        return new Promise((resolve) => {
          control.finish = () => resolve({ ok: false, wrong: [] });
        });
      },
      walletShow() {
        log.shows += 1;
        if (log.showError) throw log.showError;
        return true;
      },
      vanishCancel() {
        state.vanish = null;
        emit();
      },
      summonClose() {
        state.summon = null;
        emit();
      },
    };
  }

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
    createFlow,
    normalKey,
    wrongWords,
    DEFAULT_COMMIT_ENTRY,
    MAX_COMMIT_FEE,
    WALLET_APPROVAL,
    "http://127.0.0.1:8545",
    () => ({}),
    async () => {},
    () => null,
    { Linux: "" },
    "",
    async () => false,
    () => "Linux",
  );
  return { $, log, control };
}

test("on the page: Show wallet shows while the wallet asks to connect, and a click shows the wallet", async () => {
  const page = startPage();
  await settle();
  assert.equal(page.$("show-wallet").hidden, true, "hidden while nothing waits");
  page.control.ask();
  assert.equal(page.$("show-wallet").hidden, false);
  page.$("show-wallet").fire("click");
  assert.equal(page.log.shows, 1, "the click reaches the wallet at once, inside the user's gesture");
  assert.equal(page.$("show-wallet").getAttribute("aria-busy"), null, "it stays usable while the step runs");
  page.control.answer();
  assert.equal(page.$("show-wallet").hidden, true, "hidden once the wallet answered");
});

test("on the page: the Vanish waiting line names the Ghost wallet window and Show wallet is under it", async () => {
  const page = startPage();
  await settle();
  page.control.toCheck();
  const inputs = page.$("vanish-check-groups").querySelectorAll("input");
  assert.equal(inputs.length, 3);
  inputs.forEach((input, i) => (input.value = KEY.split(" ")[i]));
  page.$("vanish-check").fire("submit");
  await settle();
  await settle();
  assert.equal(page.$("vanish-waiting").hidden, false, "the waiting screen");
  assert.equal(page.$("vanish-waiting-text").textContent, APPROVE_LINE);
  assert.equal(page.$("show-wallet").hidden, false);
  page.$("show-wallet").fire("click");
  assert.equal(page.log.shows, 1);

  // A blocked window says so in the wallet panel's line.
  page.log.showError = new PopupBlocked();
  page.$("show-wallet").fire("click");
  assert.match(page.$("wallet-error").textContent, /^The wallet window was blocked\./);
  page.control.answer();
  assert.equal(page.$("show-wallet").hidden, true);
});
