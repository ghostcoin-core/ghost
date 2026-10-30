// The Phantom Key is never offered as an image file (a phone puts a saved
// image in its photo library and cloud backup, where gallery-scanning
// malware reads it), and a copied key is cleared from the clipboard 60
// seconds later, with a line on screen that says so. index.html and app.mjs
// are read as text; app.mjs runs against a small stand-in page, a stand-in
// flow, a stand-in clipboard and a hand-driven clock, so no browser, no wasm
// and no module build are needed.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { formatGhost, parseGhost } from "../src/chain.mjs";
import { WALLET_APPROVAL, wrongWords } from "../src/flow.mjs";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");
const build = readFileSync(new URL("../build.sh", import.meta.url), "utf8");

// --- A stand-in page: one element for each id of index.html ---

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

const settle = async () => {
  for (let i = 0; i < 4; i++) await new Promise((resolve) => setImmediate(resolve));
};

const KEY = Array.from({ length: 24 }, (_, i) => `word${String.fromCharCode(97 + i)}`).join(" ");

// Starts app.mjs with a clipboard that records each text written to it
// (`refuseClear` refuses the empty one) and a clock that runs a timer only
// when the test moves it on.
function startPage({ refuseClear = false } = {}) {
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
  const $ = (id) => document.getElementById(id);
  const window = new Element("window");

  const clipboard = [];
  const navigator = {
    userAgent: "Linux",
    clipboard: {
      async writeText(text) {
        if (text === "" && refuseClear) throw new Error("the document is not focused");
        clipboard.push(text);
      },
    },
  };

  let now = 0;
  let nextId = 1;
  const timers = new Map();
  const setTimeout = (fn, ms) => {
    const id = nextId++;
    timers.set(id, { fn, at: now + ms });
    return id;
  };
  const clearTimeout = (id) => timers.delete(id);
  // Moves the clock on by `ms`, running each timer that falls due.
  const advance = (ms) => {
    now += ms;
    for (const [id, t] of [...timers]) {
      if (t.at <= now) {
        timers.delete(id);
        t.fn();
      }
    }
  };

  function createFlow({ onChange }) {
    const state = {
      endpoint: "http://127.0.0.1:8545",
      commitEntry: "0x67686f7374000000000000000000000000000005",
      chainRefused: null,
      wallet: { id: "test-wallet", name: "Test wallet", address: "0x3a00000000000000000000000000000000091c", balance: 5n * 10n ** 18n },
      busy: null,
      progress: null,
      error: null,
      vanish: null,
      summon: null,
    };
    const emit = () => onChange(state);
    return {
      state,
      async minVanish() {
        return 10n ** 15n;
      },
      async vanishStart(amountText) {
        state.vanish = { stage: "shown", key: KEY, view: "words", digits: null, amount: parseGhost(amountText), groups: null, wrong: [] };
        emit();
        return KEY;
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
  const names = ["document", "window", "navigator", "setInterval", "setTimeout", "clearTimeout", "formatGhost", "parseGhost", "createFlow", "normalKey"];
  const more = ["wrongWords", "DEFAULT_COMMIT_ENTRY", "MAX_COMMIT_FEE", "WALLET_APPROVAL", "DEFAULT_ENDPOINT", "browserProver", "popupConnector"];
  const local = ["createHeaderStore", "INSTALL_LINES", "INSTALL_SITE", "probeLocalNode", "systemOf"];
  new Function(...names, ...more, ...local, body)(
    document,
    window,
    navigator,
    () => 0,
    setTimeout,
    clearTimeout,
    formatGhost,
    parseGhost,
    createFlow,
    (t) => t,
    wrongWords,
    "0x67686f7374000000000000000000000000000005",
    10n ** 16n,
    WALLET_APPROVAL,
    "http://127.0.0.1:8545",
    () => ({}),
    () => ({}),
    () => null,
    { Linux: "" },
    "",
    async () => false,
    () => "Linux",
  );
  return { $, clipboard, advance, timers };
}

async function toKeyScreen(page) {
  page.$("vanish-amount").value = "1.5";
  page.$("vanish-form").fire("submit");
  await settle();
  assert.equal(page.$("vanish-key").hidden, false, "the key screen is shown");
}

test("Copy puts the key on the clipboard and says it is cleared in 60 seconds", async () => {
  const page = await startPage();
  await toKeyScreen(page);
  page.$("vanish-copy").fire("click");
  await settle();
  assert.deepEqual(page.clipboard, [KEY]);
  assert.match(page.$("vanish-copy-note").textContent, /clipboard is cleared in 60 seconds/);
  assert.equal(page.$("vanish-error").textContent, "");
});

test("the clipboard is cleared 60 seconds after a copy, not before, and the note says so", async () => {
  const page = startPage();
  await toKeyScreen(page);
  page.$("vanish-copy").fire("click");
  await settle();
  page.advance(59_999);
  await settle();
  assert.deepEqual(page.clipboard, [KEY], "still there just before 60 seconds");
  page.advance(1);
  await settle();
  assert.deepEqual(page.clipboard, [KEY, ""], "an empty text is written over the key");
  assert.equal(page.$("vanish-copy-note").textContent, "The clipboard was cleared.");
  assert.equal(page.timers.size, 0);
});

test("a second copy restarts the 60 seconds and the key is cleared once", async () => {
  const page = startPage();
  await toKeyScreen(page);
  page.$("vanish-copy").fire("click");
  await settle();
  page.advance(30_000);
  page.$("vanish-copy").fire("click");
  await settle();
  page.advance(30_000);
  await settle();
  assert.deepEqual(page.clipboard, [KEY, KEY]);
  page.advance(30_000);
  await settle();
  assert.deepEqual(page.clipboard, [KEY, KEY, ""]);
  assert.equal(page.timers.size, 0);
});

test("a clear the browser refuses is said on screen", async () => {
  const page = startPage({ refuseClear: true });
  await toKeyScreen(page);
  page.$("vanish-copy").fire("click");
  await settle();
  page.advance(60_000);
  await settle();
  assert.match(page.$("vanish-copy-note").textContent, /could not be cleared/);
});

test("Claim's Copy uses the same clear and has its own note", () => {
  assert.equal(source.match(/CLIPBOARD_CLEAR_MS = 60_000/g).length, 1);
  assert.match(source, /copyKey\(shownKey\(h\), \$\(`\$\{prefix\}-copy-note`\)\)/);
  assert.match(source, /copyKey\(v\.key, \$\("vanish-copy-note"\)\)/);
  // Every write of a key to the clipboard goes through copyKey.
  assert.equal(source.match(/navigator\.clipboard\.writeText\(/g).length, 3, "the copy, the clear and the install line");
  assert.match(tags.get("claim-copy-note"), /role="status"/);
  assert.match(tags.get("vanish-copy-note"), /role="status"/);
  assert.match(html, /clipboard is cleared 60 seconds after a copy/);
});

test("the key is not offered as an image: no Download button and no image code", () => {
  for (const id of ["vanish-download", "claim-download"]) assert.ok(!tags.has(id), `no element ${id}`);
  assert.doesNotMatch(html, />\s*Download[^<]*</i);
  assert.doesNotMatch(html, /as an image/i);
  const imageModule = ["key", "image"].join("");
  assert.ok(!existsSync(new URL(`../src/${imageModule}.mjs`, import.meta.url)));
  assert.ok(!source.includes(imageModule), "app.mjs does not load the image module");
  assert.ok(!build.includes(` ${imageModule} `), "build.sh does not ship the image module");
  const drawn = [
    ["download", "Key", "Image"],
    ["to", "Blob("],
    ["create", "Object", "URL("],
    ["to", "Data", "URL("],
    ["get", "Context("],
  ].map((parts) => parts.join(""));
  for (const name of drawn) assert.ok(!source.includes(name), `app.mjs names ${name}`);
});
