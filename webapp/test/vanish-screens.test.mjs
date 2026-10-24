// The Vanish screens inside the card: Save your Phantom Key (the 24-word
// grid, Copy, Download, "I saved it"), Check your key (three labelled word
// inputs, the wrong-answer line, "Show key again", the send) and Done.
// index.html and app.mjs are read as text; app.mjs runs against a small
// stand-in page and a stand-in flow, so no browser and no module build are
// needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { formatGhost, parseGhost } from "../src/chain.mjs";
import { WALLET_APPROVAL, wrongWords } from "../src/flow.mjs";
import { WalletRejected } from "../src/wallet-connect.mjs";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

const WRONG = "Those words don't match your key. Check what you saved and try again.";

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

// The words of a piece of markup, with each amount the app fills in shown
// as <amount>.
function words(markup) {
  return markup
    .replace(/<span id="vanish-[a-z]+-amount"><\/span>/g, "<amount>")
    .replace(/<(?!amount>)[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// The source of a call whose text up to its opening parenthesis is `start`,
// up to its closing parenthesis.
function call(start) {
  const at = source.indexOf(start);
  assert.notEqual(at, -1, `app.mjs has ${start}`);
  let depth = 0;
  for (let i = at + start.length - 1; i < source.length; i++) {
    if (source[i] === "(") depth++;
    if (source[i] === ")" && --depth === 0) return source.slice(at, i + 1);
  }
  assert.fail(`${start} is closed`);
}

// --- A stand-in page: one element for each id of index.html ---

// Each id's opening tag, for its starting `hidden` and `data-` attributes.
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

const settle = () => new Promise((resolve) => setImmediate(resolve));

const KEY = Array.from({ length: 24 }, (_, i) => `word${String.fromCharCode(97 + i)}`).join(" ");
const POSITIONS = [2, 9, 17];

// Starts app.mjs on a fresh stand-in page with a stand-in flow whose
// vanishCheck sends only when the three words match, as the real one does.
// With `refuse`, the network refuses the commit after the check passes: that
// raw text, or that error as the flow throws it.
function startPage({ refuse = null } = {}) {
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
  const log = { sent: 0, cancels: 0, checks: [], screenWhileChecking: [] };
  const $ = (id) => document.getElementById(id);
  const visible = () => ["form", "key", "check", "waiting", "done", "after"].filter((s) => !$(`vanish-${s}`).hidden);

  function createFlow({ onChange }) {
    const state = {
      endpoint: "http://127.0.0.1:8545",
      commitEntry: "0x67686f7374000000000000000000000000000005",
      chainRefused: null,
      wallet: {
        id: "test-wallet",
        name: "Test wallet",
        address: "0x3a00000000000000000000000000000000091c",
        balance: 5n * 10n ** 18n,
      },
      busy: null,
      progress: null,
      error: null,
      vanish: null,
      summon: null,
    };
    const emit = () => onChange(state);
    return {
      state,
      async vanishStart(amountText) {
        const amount = parseGhost(amountText);
        state.vanish = { stage: "shown", key: KEY, view: "words", digits: null, amount, groups: null, wrong: [] };
        emit();
        return KEY;
      },
      vanishSaved() {
        state.vanish.stage = "check";
        state.vanish.groups = POSITIONS;
        emit();
        return POSITIONS;
      },
      async vanishCheck(answers) {
        const v = state.vanish;
        log.checks.push(answers);
        log.screenWhileChecking.push(visible().join());
        v.wrong = wrongWords(v.key, v.groups, answers);
        emit();
        if (v.wrong.length > 0) return { ok: false, wrong: v.wrong };
        if (refuse) {
          const err = refuse instanceof Error ? refuse : new Error(refuse);
          state.error = err.message;
          emit();
          throw err;
        }
        log.sent++;
        v.key = null;
        v.stage = "done";
        v.block = 7;
        emit();
        return { ok: true };
      },
      vanishCancel() {
        log.cancels++;
        state.vanish = null;
        emit();
      },
      // Leaving Summon, and pagehide, close the Summon key too.
      summonClose() {
        state.summon = null;
        emit();
      },
    };
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
    (t) => t,
    wrongWords,
    "0x67686f7374000000000000000000000000000005",
    10n ** 16n,
    WALLET_APPROVAL,
    "http://127.0.0.1:8545",
    () => ({}),
    async () => {},
  );
  return { $, log, visible, window };
}

// Types `answers` into the check's inputs, in order, and submits the form.
async function submitCheck(page, answers) {
  const inputs = page.$("vanish-check-groups").querySelectorAll("input");
  inputs.forEach((input, i) => (input.value = answers[i]));
  page.$("vanish-check").fire("submit");
  await settle();
  await settle();
}

async function toCheck(page) {
  page.$("vanish-amount").value = "1.5";
  page.$("vanish-form").fire("submit");
  await settle();
  await settle();
  page.$("vanish-saved").fire("click");
  await settle();
}

const right = POSITIONS.map((p) => KEY.split(" ")[p - 1]);

// --- The wording of the three screens ---

test("Save your Phantom Key: the warning, the 24-word grid, Copy, Download and I saved it", () => {
  const screen = element("vanish-key");
  assert.match(screen, /<h2>Save your Phantom Key<\/h2>/);
  assert.ok(
    words(screen).includes(
      "These 24 words are the only way to summon your <amount> GHOST. Anyone with them can take it. If you lose them, no one can get it back.",
    ),
    words(screen),
  );
  assert.match(element("vanish-words"), /^<ol\b[^>]*class="word-grid"/);
  assert.match(element("vanish-copy"), />Copy</);
  assert.match(element("vanish-download"), />Download</);
  assert.match(element("vanish-saved"), /class="primary[^"]*"[^>]*>I saved it</);
  // No digit form of the key in the card.
  assert.doesNotMatch(element("panel-vanish"), /digits/i);
  const css = readFileSync(new URL("../style.css", import.meta.url), "utf8");
  assert.match(css, /\.word-grid\s*\{[^}]*grid-template-columns:\s*repeat\(3,/);
});

test("Check your key: three typed words, Show key again and the Vanish button", () => {
  const screen = element("vanish-check");
  assert.match(screen, /^<form\b/);
  assert.match(screen, /<h2>Check your key<\/h2>/);
  assert.ok(words(screen).includes("Type these three words from your saved key."));
  assert.match(element("vanish-back"), />Show key again</);
  assert.match(element("vanish-send"), /type="submit"/);
  assert.equal(words(element("vanish-send")), "Vanish <amount> GHOST");
  assert.ok(source.includes(`"${WRONG}"`), "app.mjs has the wrong-answer sentence");
});

test("Done: the ghost icon, the amount vanished, how to use the key and Done", () => {
  const screen = element("vanish-done");
  assert.match(screen, /<use href="#icon-ghost">/);
  assert.ok(words(screen).includes("<amount> GHOST vanished"));
  assert.ok(words(screen).includes("Your Phantom Key now holds it. To use it, open Summon and paste your key."));
  assert.match(element("vanish-done-button"), /class="primary[^"]*"[^>]*>Done</);
  assert.match(element("vanish-waiting"), /class="bar"/);
});

// --- The screens, driven through app.mjs ---

test("Vanish shows the key as a numbered grid of its 24 words, put in as text", async () => {
  const page = startPage();
  assert.deepEqual(page.visible(), ["form"]);
  page.$("vanish-amount").value = "1.5";
  page.$("vanish-form").fire("submit");
  await settle();
  assert.deepEqual(page.visible(), ["key"]);
  assert.equal(page.$("vanish-key-amount").textContent, "1.5");
  const grid = page.$("vanish-words").children;
  assert.equal(grid.length, 24);
  assert.deepEqual(
    grid.map((li) => li.children.map((c) => c.textContent)),
    KEY.split(" ").map((w, i) => [String(i + 1), w]),
  );
});

test("the check asks three labelled words, and a wrong word sends nothing", async () => {
  const page = startPage();
  await toCheck(page);
  assert.deepEqual(page.visible(), ["check"]);
  const labels = page.$("vanish-check-groups").children;
  assert.deepEqual(
    labels.map((l) => l.text),
    POSITIONS.map((p) => `Word ${p}`),
  );
  assert.ok(labels.every((l) => l.tagName === "label" && l.children[0].tagName === "input"));
  assert.equal(page.$("vanish-send-amount").textContent, "1.5");

  await submitCheck(page, [right[0], "wrong", right[2]]);
  assert.equal(page.log.sent, 0, "nothing is sent");
  assert.deepEqual(page.log.screenWhileChecking, ["check"], "no waiting bar for a wrong word");
  assert.deepEqual(page.visible(), ["check"]);
  assert.equal(page.$("vanish-error").textContent, WRONG);
  const inputs = page.$("vanish-check-groups").querySelectorAll("input");
  assert.deepEqual(
    inputs.map((i) => i.getAttribute("aria-invalid")),
    ["false", "true", "false"],
  );

  // Show key again, then back to the check.
  page.$("vanish-back").fire("click");
  assert.deepEqual(page.visible(), ["key"]);
  assert.equal(page.$("vanish-words").children.length, 24);
  page.$("vanish-saved").fire("click");
  await settle();
  assert.deepEqual(page.visible(), ["check"]);
  assert.equal(page.log.sent, 0);
});

test("the right words send, with the waiting bar until the check returns, then Done", async () => {
  const page = startPage();
  await toCheck(page);
  await submitCheck(page, right);
  assert.deepEqual(page.log.screenWhileChecking, ["waiting"]);
  assert.equal(page.log.sent, 1);
  assert.deepEqual(page.visible(), ["done"]);
  assert.equal(page.$("vanish-done-amount").textContent, "1.5");
  assert.equal(page.$("vanish-error").textContent, "");
});

test("the send happens only from the check form's submit", () => {
  assert.equal(source.split("flow.vanishCheck(").length, 2, "one call of vanishCheck");
  assert.ok(call('$("vanish-check").addEventListener(').includes("flow.vanishCheck("));
  assert.doesNotMatch(source, /\.(click|submit|requestSubmit)\(\)/, "nothing submits the check for the user");
});

test("Done clears the key and returns to an empty Vanish tab", async () => {
  const page = startPage();
  await toCheck(page);
  await submitCheck(page, right);
  page.$("vanish-done-button").fire("click");
  assert.equal(page.log.cancels, 1, "vanishCancel is called");
  assert.deepEqual(page.visible(), ["form"]);
  assert.equal(page.$("vanish-amount").value, "");
  assert.equal(page.$("vanish-words").children.length, 0);
  assert.ok(call("$(id).addEventListener(").includes("forgetVanish()"));
  assert.match(/function forgetVanish\(\) \{[\s\S]*?\n\}/.exec(source)[0], /flow\.vanishCancel\(\)/);
});

test("leaving the Vanish tab, or the page, drops the key and sends nothing", async () => {
  const page = startPage();
  await toCheck(page);
  assert.equal(page.$("vanish-words").children.length, 24);
  page.$("tab-summon").fire("click");
  assert.equal(page.log.cancels, 1, "the tab switch calls vanishCancel");
  assert.equal(page.$("vanish-words").children.length, 0, "the grid is emptied");
  assert.equal(page.$("vanish-check-groups").children.length, 0);
  assert.equal(page.log.sent, 0);
  page.$("tab-vanish").fire("click");
  assert.deepEqual(page.visible(), ["form"]);

  const other = startPage();
  other.$("vanish-amount").value = "1";
  other.$("vanish-form").fire("submit");
  await settle();
  assert.equal(other.$("vanish-words").children.length, 24);
  other.window.fire("pagehide");
  assert.equal(other.log.cancels, 1);
  assert.equal(other.$("vanish-words").children.length, 0);
  assert.equal(other.log.sent, 0);
});

test("an error is one fixed plain line in the card, never the exception's text", async () => {
  const page = startPage();
  page.$("vanish-amount").value = "100";
  page.$("vanish-form").fire("submit");
  await settle();
  await settle();
  assert.deepEqual(page.visible(), ["form"]);
  assert.equal(page.$("vanish-error").textContent, "Your balance is too low for this amount and the network fee.");
  assert.equal(page.$("error").textContent, "");

  page.$("vanish-amount").value = "one";
  page.$("vanish-form").fire("submit");
  await settle();
  await settle();
  assert.equal(page.$("vanish-error").textContent, "Enter an amount of GHOST, for example 1.5.");

  // A refusal from the network after the check: back to the check, one
  // plain line, the node's own text nowhere on the page.
  const raw = "synthetic raw failure text from the node";
  const refused = startPage({ refuse: raw });
  await toCheck(refused);
  await submitCheck(refused, right);
  assert.deepEqual(refused.log.screenWhileChecking, ["waiting"]);
  assert.deepEqual(refused.visible(), ["check"]);
  assert.equal(refused.$("vanish-error").textContent, "The network refused the commit. Try again.");
  assert.equal(refused.$("error").textContent, "");
  for (const id of tags.keys()) assert.ok(!refused.$(id).textContent.includes(raw), id);

  // Turned down in the wallet: the key is dropped and the card is back at
  // the amount (vanish-approval.test.mjs covers it in full).
  const rejected = startPage({ refuse: new WalletRejected("the transaction") });
  await toCheck(rejected);
  await submitCheck(rejected, right);
  assert.deepEqual(rejected.visible(), ["form"]);
  assert.equal(rejected.$("vanish-error").textContent, "You rejected it in your wallet. Nothing was sent.");
  assert.equal(rejected.log.sent, 0);
  assert.equal(rejected.log.cancels, 1, "the key is dropped");
});
