// Summon's confirm step: pressing Summon proves and sends nothing; the card
// shows "Summon X GHOST to 0x3a…91c" with Confirm Summon and Cancel, and only
// Confirm Summon calls the flow's summonReveal. No wallet signature is asked
// for: the Phantom Key's proof authorizes the reveal. app.mjs runs against a
// small stand-in page and a stand-in flow that logs every call made of it.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { formatGhost, parseGhost } from "../src/chain.mjs";
import { WALLET_APPROVAL } from "../src/flow.mjs";

const normalKey = (text) => String(text).trim().split(/\s+/).join(" ");

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

const GHOST = 10n ** 18n;
const FEE = 10n ** 14n;
const WALLET = "0x3a00000000000000000000000000000000091c";
const OTHER_WALLET = "0x5b00000000000000000000000000000000077e";
const KEY = Array.from({ length: 24 }, (_, i) => `word${String.fromCharCode(97 + i)}`).join(" ");

// The markup of the element with `id`, its closing tag included.
function element(id) {
  const open = new RegExp(`<([a-z0-9]+)\\b[^>]*\\bid="${id}"[^>]*>`, "i").exec(html);
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

const settle = async (n = 4) => {
  for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve));
};

// Starts app.mjs with a stand-in flow whose key holds 2 GHOST. Every call
// made of the flow is logged by name in `log.calls`; the reveal waits until
// `release()` when `hold` is set.
function startPage({ hold = false } = {}) {
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
  const log = { calls: [], reveals: [] };
  let release = () => {};
  const held = new Promise((resolve) => {
    release = resolve;
  });
  let state = null;

  function createFlow({ onChange }) {
    state = {
      endpoint: "http://127.0.0.1:8545",
      commitEntry: "0x67686f7374000000000000000000000000000005",
      chainRefused: null,
      wallet: { id: "test-wallet", name: "Test wallet", address: WALLET, balance: 5n * GHOST },
      busy: null,
      progress: null,
      error: null,
      vanish: null,
      summon: null,
    };
    const emit = () => onChange(state);
    const coinState = (s) => {
      s.status = "unclaimed";
      s.current = { number: 1n, amount: 2n * GHOST, treeIndex: 0, position: 3 };
      s.fee = FEE;
      s.available = 2n * GHOST - FEE;
      s.wait = null;
    };
    const flow = {
      state,
      async summonOpen(text) {
        state.summon = { key: normalKey(text), format: "words", groups: 21, coins: [], claim: null, lastReveal: null, pinned: null };
        coinState(state.summon);
        emit();
        return state.summon;
      },
      async summonReveal({ amount, recipient }) {
        log.reveals.push({ amount, recipient });
        state.busy = "revealing";
        state.progress = { stage: "proving in the background worker", since: 0 };
        emit();
        if (hold) await held;
        const out = parseGhost(amount);
        state.summon.lastReveal = { stage: "done", txHash: "0x01", out, recipient, fee: FEE, block: 9 };
        state.busy = null;
        state.progress = null;
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
      walletDisconnect() {
        state.wallet = null;
        emit();
      },
    };
    // Every call of the flow, by name.
    for (const [name, value] of Object.entries(flow)) {
      if (typeof value !== "function") continue;
      flow[name] = (...args) => {
        log.calls.push(name);
        return value(...args);
      };
    }
    return flow;
  }

  const body = source.replace(/^import .*;$/gm, "");
  const names = ["document", "window", "navigator", "setInterval", "formatGhost", "parseGhost", "createFlow", "normalKey"];
  const more = ["wrongWords", "DEFAULT_COMMIT_ENTRY", "MAX_COMMIT_FEE", "WALLET_APPROVAL", "DEFAULT_ENDPOINT", "browserProver", "downloadKeyImage"];
  new Function(...names, ...more, body)(
    document,
    window,
    { clipboard: { writeText: async () => {} } },
    () => 0,
    formatGhost,
    parseGhost,
    createFlow,
    normalKey,
    () => [],
    "0x67686f7374000000000000000000000000000005",
    10n ** 16n,
    WALLET_APPROVAL,
    "http://127.0.0.1:8545",
    () => ({}),
    async () => {},
  );
  $("tab-summon").fire("click");
  return { $, log, screens, window, release, state: () => state };
}

// Pastes the key, types `amount` and presses Summon.
async function pressSummon(page, amount) {
  page.$("summon-key").value = KEY;
  page.$("summon-key").fire("input", { inputType: "insertFromPaste" });
  await settle();
  page.$("summon-amount").value = amount;
  page.log.calls.length = 0;
  page.$("summon-form").fire("submit");
  await settle();
}

// --- The markup ---

test("the confirm screen: the amount and address line, one primary Confirm Summon, and Cancel", () => {
  const screen = element("summon-confirm");
  assert.match(tags.get("summon-confirm"), /\bhidden\b/);
  assert.match(screen, /<h2><span id="summon-confirm-text"><\/span><\/h2>/);
  assert.match(element("summon-confirm-button"), /^<button\b[^>]*class="primary[^"]*"[^>]*type="button"[^>]*>Confirm Summon<\/button>$/);
  assert.match(element("summon-cancel"), /^<button\b[^>]*type="button"[^>]*>Cancel<\/button>$/);
  assert.doesNotMatch(tags.get("summon-cancel"), /primary/);
  assert.equal(screen.match(/class="primary/g).length, 1, "one primary button");
  assert.doesNotMatch(screen, /<(input|textarea)\b/, "nothing to type on the confirm screen");
});

test("only Confirm Summon calls summonReveal", () => {
  assert.equal(source.split("flow.summonReveal(").length, 2, "one call of summonReveal");
  const at = source.indexOf("flow.summonReveal(");
  const handler = source.lastIndexOf("addEventListener(", at);
  assert.ok(source.slice(handler - 40, handler).includes('$("summon-confirm-button")'), "inside Confirm Summon's handler");
});

// --- Driven through app.mjs ---

test("Summon opens the confirm screen naming the amount and the wallet, and proves nothing", async () => {
  const page = startPage();
  await pressSummon(page, "0.5");
  assert.deepEqual(page.screens(), ["confirm"]);
  assert.equal(page.$("summon-confirm-text").textContent, "Summon 0.5 GHOST to 0x3a…91c");
  assert.equal(page.$("summon-confirm").title, WALLET, "the full address as the title");
  assert.equal(page.log.reveals.length, 0, "summonReveal is not called before Confirm");
  assert.deepEqual(page.log.calls, [], "nothing is asked of the flow");
  assert.equal(page.$("summon-error").textContent, "");

  // The amount as typed.
  const typed = startPage();
  await pressSummon(typed, "1.50");
  assert.equal(typed.$("summon-confirm-text").textContent, "Summon 1.50 GHOST to 0x3a…91c");
  assert.equal(typed.log.reveals.length, 0);
});

test("Cancel returns to the form with the key and amount kept, and calls nothing", async () => {
  const page = startPage();
  await pressSummon(page, "0.5");
  page.$("summon-cancel").fire("click");
  await settle();
  assert.deepEqual(page.screens(), ["form"]);
  assert.equal(page.log.reveals.length, 0, "summonReveal is never called");
  assert.deepEqual(page.log.calls, [], "nothing is asked of the flow");
  assert.equal(page.$("summon-key").value, KEY);
  assert.equal(page.$("summon-amount").value, "0.5");
  assert.ok(page.state().summon, "the key stays open");
  assert.equal(page.$("summon-submit").textContent, "Summon");
  assert.equal(page.$("summon-confirm-text").textContent, "");

  // Confirm after a Cancel does nothing; Summon then asks again.
  page.$("summon-confirm-button").fire("click");
  await settle();
  assert.equal(page.log.reveals.length, 0);
  page.$("summon-form").fire("submit");
  await settle();
  assert.deepEqual(page.screens(), ["confirm"]);
  assert.equal(page.log.reveals.length, 0);
});

test("Confirm Summon calls summonReveal once with the amount and the wallet's address; a second press does nothing", async () => {
  const page = startPage({ hold: true });
  await pressSummon(page, "0.5");
  page.$("summon-confirm-button").fire("click");
  await settle();
  assert.deepEqual(page.screens(), ["waiting"]);
  assert.equal(page.$("summon-waiting-amount").textContent, "0.5");
  page.$("summon-confirm-button").fire("click");
  page.$("summon-form").fire("submit");
  await settle();
  assert.deepEqual(page.log.reveals, [{ amount: "0.5", recipient: WALLET }]);
  page.release();
  await settle(8);
  assert.deepEqual(page.screens(), ["done"]);
  assert.deepEqual(page.log.reveals, [{ amount: "0.5", recipient: WALLET }], "called once");
  assert.equal(page.$("summon-done-address").textContent, "0x3a…91c");
});

test("a wallet changed while the confirm screen shows sends nothing", async () => {
  const page = startPage();
  await pressSummon(page, "0.5");
  page.state().wallet = { id: "test-wallet", name: "Test wallet", address: OTHER_WALLET, balance: 5n * GHOST };
  page.$("summon-confirm-button").fire("click");
  await settle();
  assert.equal(page.log.reveals.length, 0);
  assert.deepEqual(page.screens(), ["form"]);
  assert.equal(page.$("summon-error").textContent, "Your wallet changed before you confirmed. Nothing was sent. Press Summon again.");
});

test("leaving the tab, or the page, on the confirm screen drops it and the key, and sends nothing", async () => {
  const page = startPage();
  await pressSummon(page, "0.5");
  page.$("tab-vanish").fire("click");
  page.$("tab-summon").fire("click");
  assert.deepEqual(page.screens(), ["form"]);
  page.$("summon-confirm-button").fire("click");
  await settle();
  assert.equal(page.log.reveals.length, 0);
  assert.equal(page.$("summon-key").value, "");

  const other = startPage();
  await pressSummon(other, "0.5");
  other.window.fire("pagehide");
  other.$("summon-confirm-button").fire("click");
  await settle();
  assert.equal(other.log.reveals.length, 0);
});
