// The Summon screens inside the card: the paste box, the amount box with
// "In this key" and Max, the waiting screen with its three steps, and Done.
// index.html and app.mjs are read as text; app.mjs runs against a small
// stand-in page and a stand-in flow, so no browser and no module build are
// needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { MIN_VANISH_FEES, formatGhost, parseAddress, parseGhost } from "../src/chain.mjs";
import { WALLET_APPROVAL } from "../src/flow.mjs";

// A typed key as the flow controller's normalKey gives it to the module: any
// run of white space made one space.
const normalKey = (text) => String(text).trim().split(/\s+/).join(" ");

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

const GHOST = 10n ** 18n;
const FEE = 10n ** 14n;
const WALLET = `0x3a${"0".repeat(34)}091c`;
// The fresh address the stand-in wallet hands out for the payout.
const FRESH = `0x7c${"0".repeat(34)}044d`;
const FRESH_2 = `0x8d${"0".repeat(34)}055e`;
const KEY = Array.from({ length: 24 }, (_, i) => `word${String.fromCharCode(97 + i)}`).join(" ");
// The id of the old reveal form's payout field, built so this file does not
// spell it.
const PAYOUT_FIELD = ["reveal", "to"].join("-");

const NOT_A_KEY = "That doesn't look like a Phantom Key. It should be 24 words.";
const NO_AMOUNT = "Enter an amount to summon.";

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

// The words of a piece of markup, with each value the app fills in shown as
// <value>.
function words(markup) {
  return markup
    .replace(/<span id="summon-[a-z-]+"><\/span>/g, "<value>")
    .replace(/<(?!value>)[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .replace(/ \./g, ".")
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

// The text of a top-level `function name(...) {...}` of app.mjs.
function fn(name) {
  const m = new RegExp(`\\nfunction ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\}\\n`).exec(source);
  assert.ok(m, `app.mjs has function ${name}`);
  return m[0];
}

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
  fire(type, extra = {}) {
    for (const handler of this.listeners[type] ?? []) handler({ preventDefault() {}, key: undefined, ...extra });
  }
}

const settle = async (n = 4) => {
  for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve));
};

// Starts app.mjs on a fresh stand-in page with a stand-in flow. The key holds
// `amount`; `wallet` false starts with no wallet connected; `refuse` makes the
// reveal fail with that raw text before anything is sent.
// `popup` stands for popupConnector (popup-wallet.mjs). The wallet's fresh
// addresses are handed out from `fresh` in turn (null: a wallet without the
// request).
function startPage({ amount = 2n * GHOST, wallet = true, refuse = null, popup = () => assert.fail("no pop-up wallet"), fresh = [FRESH] } = {}) {
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
  const steps = () => ["proof", "send", "confirm"].map((s) => $(`summon-step-${s}`).dataset.state || "-").join(" ");
  const log = { opens: [], reveals: [], closes: 0, steps: [], bars: [], waitingAmount: [], connects: [], disconnects: 0, fresh: 0 };
  let held = amount;

  function createFlow({ onChange }) {
    const state = {
      endpoint: "http://127.0.0.1:8545",
      commitEntry: "0x67686f7374000000000000000000000000000005",
      chainRefused: null,
      wallet: wallet ? { id: "test-wallet", name: "Test wallet", address: WALLET, balance: 5n * GHOST } : null,
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
      log.steps.push(steps());
      log.bars.push($("summon-bar").dataset.step);
      log.waitingAmount.push($("summon-waiting-amount").textContent);
    };
    const coinState = (s) => {
      s.status = "unclaimed";
      s.current = { number: 1n, amount: held, treeIndex: 0, position: 3 };
      s.fee = FEE;
      // As the flow: MIN_VANISH_FEES network fees.
      s.smallestCoin = MIN_VANISH_FEES * FEE;
      s.available = held > FEE ? held - FEE : 0n;
      s.wait = null;
    };
    return {
      state,
      // As the real flow: the connector's address, then its balance.
      async walletConnect(connector) {
        log.connects.push(connector.name);
        const { address } = await connector.connect();
        state.wallet = { id: connector.id, name: connector.name, address, balance: 5n * GHOST };
        emit();
        return address;
      },
      walletDisconnect() {
        log.disconnects++;
        state.wallet = null;
        emit();
      },
      async newReceiveAddress() {
        log.fresh++;
        if (!state.wallet || fresh === null) return null;
        return fresh[(log.fresh - 1) % fresh.length];
      },
      async summonOpen(text) {
        log.opens.push(text);
        const key = normalKey(text);
        await null;
        const fail = (said) => {
          state.error = said;
          emit();
          throw new Error(said);
        };
        if (key.split(" ").length !== 24) fail(`not a valid Phantom Key: a key has 24 words, not ${key.split(" ").length}`);
        if (key.includes("notaword")) fail("not a valid Phantom Key: word 5 is not in the word list");
        if (key !== KEY) fail("not a valid Phantom Key: the words do not pass the check: one of them is wrong or out of place");
        state.summon = { key, format: "words", groups: 21, coins: [], claim: null, lastReveal: null, pinned: null };
        coinState(state.summon);
        emit();
        return state.summon;
      },
      async summonRefresh() {
        coinState(state.summon);
        emit();
        return state.summon;
      },
      async summonReveal({ amount: text, recipient }) {
        const s = state.summon;
        log.reveals.push({ amount: text, recipient });
        state.busy = "revealing";
        const out = parseGhost(text);
        try {
          progress("looking for the key's coins");
          await null;
          progress("proving in the background worker");
          await null;
          if (refuse) {
            state.error = refuse;
            throw new Error(refuse);
          }
          progress("sending the reveal");
          await null;
          s.lastReveal = { stage: "sent", txHash: "0x01", out, recipient, fee: FEE, block: null };
          progress("waiting for a block");
          await null;
          progress("checking the block");
          s.lastReveal.stage = "done";
          s.lastReveal.block = 9;
          held -= out + FEE;
          coinState(s);
          return s.lastReveal;
        } finally {
          state.busy = null;
          progress(null);
        }
      },
      summonClose() {
        log.closes++;
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
    popup,
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
  return { $, log, screens, window };
}

// Pastes `text` into the key box, as the browser reports a paste.
async function paste(page, text) {
  page.$("summon-key").value = text;
  page.$("summon-key").fire("input", { inputType: "insertFromPaste" });
  await settle();
}

// Types `amount`, presses Summon and, when the confirm screen opens, Confirm
// Summon.
async function summon(page, amount) {
  page.$("summon-amount").value = amount;
  page.$("summon-form").fire("submit");
  await settle();
  if (!page.$("summon-confirm").hidden) page.$("summon-confirm-button").fire("click");
  await settle(8);
}

// --- The wording of the screens ---

test("the Summon tab starts with the paste box and a greyed Paste a key button", () => {
  const panel = element("panel-summon");
  const key = /<textarea\b[^>]*id="summon-key"[^>]*>/.exec(panel);
  assert.ok(key, "the paste box is a textarea in the Summon panel");
  assert.match(key[0], /placeholder="Paste your Phantom Key"/);
  assert.match(element("summon-submit"), /^<button\b[^>]*class="primary[^"]*"[^>]*type="submit"[^>]*\bdisabled\b[^>]*>Paste a key</);
  // The amount box, as Vanish's: 0.00, the ghost icon and GHOST inside it.
  const area = element("summon-amount-area");
  assert.match(tag("summon-amount-area"), /\bhidden\b/);
  const box = /<label class="amount-box">[\s\S]*?<\/label>/.exec(area);
  assert.ok(box, "an amount box");
  assert.match(box[0], /<input id="summon-amount"[^>]*placeholder="0\.00"/);
  assert.match(box[0], /<use href="#icon-ghost">/);
  assert.match(box[0], /GHOST\s*<\/span>/);
  assert.match(area, /<p class="balance-line">\s*In this key: <span id="summon-in-key">—<\/span>\s*<button id="summon-max" class="link"[^>]*>Max</);
  // One error line under the fields.
  assert.match(tag("summon-error"), /class="error-line"/);
});

test("the payout field is a plain address input under the amount; the only inputs are the key, the amount and it", () => {
  assert.ok(!html.includes(PAYOUT_FIELD), "index.html");
  assert.ok(!source.includes(PAYOUT_FIELD), "app.mjs");
  const panel = element("panel-summon").replace(/<div id="claim-container"[\s\S]*$/, "");
  const fields = [...panel.matchAll(/<(input|textarea)\b[^>]*\bid="([^"]+)"/g)].map((m) => m[2]);
  assert.deepEqual(fields, ["summon-key", "summon-amount", "summon-payout"]);
  const area = element("summon-amount-area");
  assert.ok(area.indexOf('id="summon-amount"') < area.indexOf('id="summon-payout"'), "under the amount");
  assert.match(tag("summon-payout"), /type="text"/);
  assert.match(area, /<label class="payout-box">\s*<span>Pay to<\/span>/);
  for (const id of ["summon-payout-warning", "summon-amount-warning"]) assert.match(tag(id), /class="warning-line"/, id);
  // Checked with the address parser the flow uses, on Summon only.
  assert.match(source, /parseAddress\(\$\("summon-payout"\)\.value\)/);
});

test("the waiting screen: Summoning, a thin bar, three steps and keep this page open", () => {
  const screen = element("summon-waiting");
  assert.match(screen, /<h2>Summoning <span id="summon-waiting-amount"><\/span> GHOST<\/h2>/);
  assert.match(element("summon-bar"), /class="bar steps"/);
  assert.deepEqual(
    ["summon-step-proof", "summon-step-send", "summon-step-confirm"].map((id) => words(element(id))),
    ["Making your proof", "Sending to the network", "Confirming"],
  );
  assert.ok(words(screen).endsWith("Keep this page open. This takes about 10 seconds."), words(screen));
  // The steps follow the flow, not a clock: no timer moves them.
  const stepOf = fn("summonStepOf");
  assert.match(stepOf, /state\.progress/);
  assert.match(stepOf, /lastReveal/);
  assert.doesNotMatch(stepOf, /Date|since|setTimeout|setInterval/);
});

test("the Done screen: the ghost icon, the amount summoned, the payout address and Done", () => {
  const screen = element("summon-done");
  assert.match(screen, /<use href="#icon-ghost">/);
  assert.ok(words(screen).includes("<value> GHOST summoned"), words(screen));
  assert.ok(words(screen).includes("Sent to <value>."), words(screen));
  assert.doesNotMatch(screen, /your wallet/);
  assert.match(element("summon-done-button"), /class="primary[^"]*"[^>]*>Done</);
  assert.ok(source.includes("GHOST is still in your key. The same key still works."));
  assert.ok(source.includes('"This key is now empty."'));
  // The reveal's block can be checked again from Done.
  assert.match(element("summon-recheck"), />Check the summon is still in the chain</);
});

test("the error sentences are fixed in app.mjs", () => {
  for (const line of [NOT_A_KEY, NO_AMOUNT]) assert.ok(source.includes(`"${line}"`), line);
  assert.ok(source.includes("`This key holds ${formatGhost(s.current.amount)} GHOST.`"));
  assert.ok(source.includes("isn't a Phantom Key word"));
  assert.doesNotMatch(fn("summonErrorText"), /return [^;]*(said|err\.message)/, "never the exception's text");
});

test("the reveal is paid to the confirmed payout address, from one place", () => {
  assert.equal(source.split("flow.summonReveal(").length, 2, "one call of summonReveal");
  assert.match(call("flow.summonReveal("), /recipient: c\.address \}/);
});

// --- The screens, driven through app.mjs ---

// The opening tag of the element with `id`.
function tag(id) {
  return tags.get(id);
}

test("paste a key, summon part of it to a fresh address, see the rest, then summon the rest to another", async () => {
  const page = startPage({ fresh: [FRESH, FRESH_2] });
  assert.deepEqual(page.screens(), ["form"]);
  assert.equal(page.$("summon-submit").textContent, "Paste a key");
  assert.equal(page.$("summon-submit").disabled, true);
  assert.equal(page.$("summon-amount-area").hidden, true);

  await paste(page, `  ${KEY.split(" ").slice(0, 12).join(" ")}\n${KEY.split(" ").slice(12).join(" ")} `);
  assert.equal(page.log.opens.length, 1);
  assert.equal(page.$("summon-amount-area").hidden, false);
  assert.equal(page.$("summon-in-key").textContent, "2 GHOST");
  assert.equal(page.$("summon-submit").textContent, "Summon");
  assert.equal(page.$("summon-submit").disabled, false);
  assert.equal(page.$("summon-error").textContent, "");
  assert.equal(page.$("summon-payout").value, FRESH, "the payout field starts with a fresh address");
  assert.equal(page.$("summon-payout-warning").textContent, "");

  await summon(page, "0.5");
  assert.deepEqual(page.log.reveals, [{ amount: "0.5", recipient: FRESH }], "paid to the fresh address");
  // The steps tick off as the flow reaches them.
  assert.deepEqual(page.log.steps.slice(0, 5), [
    "now - -",
    "now - -",
    "done now -",
    "done done now",
    "done done now",
  ]);
  assert.deepEqual(page.log.bars.slice(0, 5), ["1", "1", "2", "3", "3"]);
  assert.equal(page.log.waitingAmount[0], "0.5");
  assert.deepEqual(page.screens(), ["done"]);
  assert.equal(page.$("summon-done-amount").textContent, "0.5");
  assert.equal(page.$("summon-done-address").textContent, "0x7c…44d");
  assert.equal(page.$("summon-done-rest").textContent, "1.4999 GHOST is still in your key. The same key still works.");

  // Done clears the key and returns to an empty Summon tab.
  page.$("summon-done-button").fire("click");
  assert.equal(page.log.closes, 1, "summonClose is called");
  assert.deepEqual(page.screens(), ["form"]);
  assert.equal(page.$("summon-key").value, "");
  assert.equal(page.$("summon-amount").value, "");
  assert.equal(page.$("summon-payout").value, "");
  assert.equal(page.$("summon-submit").textContent, "Paste a key");
  assert.equal(page.$("summon-amount-area").hidden, true);

  // The rest: Max fills what can go out after the fee, the payout is a new
  // fresh address, and the key is then empty.
  await paste(page, KEY);
  assert.equal(page.$("summon-payout").value, FRESH_2);
  assert.equal(page.$("summon-in-key").textContent, "1.4999 GHOST");
  page.$("summon-max").fire("click");
  assert.equal(page.$("summon-amount").value, "1.4998");
  page.$("summon-form").fire("submit");
  await settle();
  assert.deepEqual(page.screens(), ["confirm"]);
  assert.equal(page.log.reveals.length, 1, "nothing more is proved before Confirm Summon");
  page.$("summon-confirm-button").fire("click");
  await settle(8);
  assert.equal(page.log.reveals[1].recipient, FRESH_2);
  assert.deepEqual(page.screens(), ["done"]);
  assert.equal(page.$("summon-done-rest").textContent, "This key is now empty.");
});

test("with no wallet connected the main button reads Connect wallet and opens the wallet list", async () => {
  const page = startPage({ wallet: false });
  await paste(page, KEY);
  assert.equal(page.$("summon-submit").textContent, "Connect wallet");
  assert.equal(page.$("summon-payout").value, "", "no wallet: the payout field is empty");
  assert.equal(page.log.fresh, 0, "no wallet is asked for an address");
  assert.equal(page.$("wallet-button-text").textContent, "Connect wallet");
  assert.equal(page.$("wallet-panel").hidden, true);
  page.$("summon-form").fire("submit");
  await settle();
  assert.equal(page.$("wallet-panel").hidden, false);
  assert.equal(page.log.reveals.length, 0, "nothing is sent");
});

test("Connect wallet lists the Ghost wallet only; connected, the button shows the short address", async () => {
  // Not connected: the list, with the Ghost wallet as the one choice.
  const address = `0x3a${"0".repeat(34)}091c`;
  let made = 0;
  const page = startPage({
    wallet: false,
    popup: (...args) => {
      made++;
      assert.deepEqual(args, [], "the pop-up wallet opens on its own hosted origin");
      return { id: "ghost-popup-wallet", name: "Ghost wallet", connect: async () => ({ address }) };
    },
  });
  assert.equal(page.$("wallet-button-text").textContent, "Connect wallet");
  assert.equal(page.$("wallet-title").textContent, "Connect a wallet");
  assert.equal(page.$("wallet-connect").hidden, false);
  assert.equal(page.$("wallet-open").hidden, true);
  assert.equal(page.$("wallet-option-snap"), null, "no MetaMask entry");
  assert.equal(page.$("vanish-submit").textContent, "Connect wallet");
  page.$("wallet-option-popup").fire("click");
  await settle();
  assert.equal(made, 1);
  assert.deepEqual(page.log.connects, ["Ghost wallet"]);
  assert.equal(page.$("wallet-button-text").textContent, "0x3a…91c");
  assert.equal(page.$("wallet-title").textContent, "Wallet");
  assert.equal(page.$("wallet-connect").hidden, true);
  assert.equal(page.$("wallet-open").hidden, false);
  assert.equal(page.$("wallet-address").textContent, address);
  assert.equal(page.$("wallet-balance").textContent, "5");
  assert.equal(page.$("vanish-submit").textContent, "Vanish");
  assert.equal(page.$("wallet-error").textContent, "");

  page.$("wallet-disconnect").fire("click");
  await settle();
  assert.equal(page.log.disconnects, 1);
  assert.equal(page.$("wallet-button-text").textContent, "Connect wallet");
  assert.equal(page.$("wallet-open").hidden, true);
  assert.equal(page.$("wallet-address").textContent, "");

  // A wallet failing for another reason: a fixed plain line, nothing connected.
  const failing = startPage({
    wallet: false,
    popup: () => ({ name: "Ghost wallet", connect: async () => Promise.reject(new Error("the wallet refused the connection: synthetic test failure")) }),
  });
  failing.$("wallet-option-popup").fire("click");
  await settle();
  assert.equal(failing.$("wallet-error").textContent, "The wallet could not be connected. Try again.");
  assert.equal(failing.$("wallet-button-text").textContent, "Connect wallet");
});

test("Connect wallet offers the Ghost pop-up wallet; a blocked pop-up asks to open the page in the browser", async () => {
  const address = `0x5b${"0".repeat(34)}0a2e`;
  const page = startPage({
    wallet: false,
    popup: () => ({ id: "ghost-popup-wallet", name: "Ghost wallet", connect: async () => ({ address }) }),
  });
  page.$("wallet-option-popup").fire("click");
  await settle();
  assert.deepEqual(page.log.connects, ["Ghost wallet"]);
  assert.equal(page.$("wallet-button-text").textContent, "0x5b…a2e");
  assert.equal(page.$("wallet-address").textContent, address);
  assert.equal(page.$("wallet-error").textContent, "");

  // An in-app browser that refuses the pop-up: a plain line, nothing connected.
  const blocked = startPage({
    wallet: false,
    popup: () => ({
      name: "Ghost wallet",
      connect: async () => Promise.reject(Object.assign(new Error("the browser blocked the wallet window"), { name: "PopupBlocked" })),
    }),
  });
  blocked.$("wallet-option-popup").fire("click");
  await settle();
  assert.match(blocked.$("wallet-error").textContent, /^The wallet window was blocked\. .*open it in your browser/);
  assert.equal(blocked.$("wallet-button-text").textContent, "Connect wallet");

  // Closed or turned down in the pop-up.
  const rejecting = startPage({
    wallet: false,
    popup: () => ({ name: "Ghost wallet", connect: async () => Promise.reject(new Error("the connection was rejected in your wallet; nothing was sent")) }),
  });
  rejecting.$("wallet-option-popup").fire("click");
  await settle();
  assert.equal(rejecting.$("wallet-error").textContent, "You rejected the connection in your wallet.");
});

test("a key is checked when it holds 24 words or on leaving the box, with no error while typing", async () => {
  const page = startPage();
  page.$("summon-key").value = KEY.split(" ").slice(0, 10).join(" ");
  page.$("summon-key").fire("input", { inputType: "insertText" });
  await settle();
  assert.equal(page.log.opens.length, 0, "not checked while short");
  assert.equal(page.$("summon-error").textContent, "");
  // 24 words typed, one of them wrong: checked, but no error while typing.
  const typed = KEY.replace("worde", "notaword");
  page.$("summon-key").value = typed;
  page.$("summon-key").fire("input", { inputType: "insertText" });
  await settle();
  assert.equal(page.log.opens.length, 1);
  assert.equal(page.$("summon-error").textContent, "");
  // Leaving the box shows it, named by position, never the word.
  page.$("summon-key").fire("blur");
  await settle();
  assert.equal(page.$("summon-error").textContent, "Word 5 isn't a Phantom Key word. Check it against the key you saved.");
  assert.equal(page.$("summon-amount-area").hidden, true, "a refused key is not opened");
  assert.equal(page.$("error").textContent, "", "the flow's raw text stays off the page");

  // A short key left in the box.
  const short = startPage();
  short.$("summon-key").value = KEY.split(" ").slice(0, 23).join(" ");
  short.$("summon-key").fire("input", { inputType: "insertText" });
  short.$("summon-key").fire("blur");
  await settle();
  assert.equal(short.$("summon-error").textContent, NOT_A_KEY);

  // A pasted key that fails its check shows at once.
  const swapped = KEY.split(" ");
  [swapped[1], swapped[2]] = [swapped[2], swapped[1]];
  const pasted = startPage();
  await paste(pasted, swapped.join(" "));
  assert.equal(
    pasted.$("summon-error").textContent,
    "This key doesn't pass its check. A word may be wrong or out of order: check it against the key you saved.",
  );
});

test("an amount that does not parse or is more than the key holds is flagged, not sent", async () => {
  const page = startPage();
  await paste(page, KEY);
  for (const amount of ["", "one", "0", "1.5.2"]) {
    await summon(page, amount);
    assert.equal(page.$("summon-error").textContent, NO_AMOUNT, JSON.stringify(amount));
  }
  await summon(page, "3");
  assert.equal(page.$("summon-error").textContent, "This key holds 2 GHOST.");
  await summon(page, "2");
  assert.equal(
    page.$("summon-error").textContent,
    "This key holds 2 GHOST. After the network fee, at most 1.9999 GHOST can be summoned.",
  );
  assert.equal(page.log.reveals.length, 0, "nothing is sent");
  assert.deepEqual(page.screens(), ["form"]);
});

test("a partial Summon warns when the remainder is below the minimum", async () => {
  const SMALL_REST =
    "What stays in this key is too small to Summon again: its network fee could cost all of it. Summon a little less, or Max.";
  const page = startPage();
  await paste(page, KEY);
  const typed = (amount) => {
    page.$("summon-amount").value = amount;
    page.$("summon-amount").fire("input");
    return page.$("summon-amount-warning").textContent;
  };
  // 2 GHOST in the key, a fee of 0.0001: 1.9997 leaves 0.0002, two fees,
  // under the four of MIN_VANISH_FEES.
  assert.equal(typed("1.9997"), SMALL_REST);
  // One wei under four fees still warns; four fees exactly do not.
  assert.equal(typed(formatGhost(2n * GHOST - FEE - MIN_VANISH_FEES * FEE + 1n)), SMALL_REST);
  assert.equal(typed("1.9995"), "");
  // A large remainder, and a full Summon (Max: nothing remains), show none.
  assert.equal(typed("1"), "");
  page.$("summon-max").fire("click");
  assert.equal(page.$("summon-amount").value, "1.9999");
  assert.equal(page.$("summon-amount-warning").textContent, "");

  // The confirm screen shows it among its warnings, and it never blocks.
  page.$("summon-amount").value = "1.9997";
  page.$("summon-form").fire("submit");
  await settle();
  assert.deepEqual(page.screens(), ["confirm"]);
  assert.equal(page.$("summon-confirm-warning").textContent, SMALL_REST);
  page.$("summon-confirm-button").fire("click");
  await settle(8);
  assert.deepEqual(page.log.reveals, [{ amount: "1.9997", recipient: FRESH }]);
  assert.deepEqual(page.screens(), ["done"]);
});

test("a failed summon is one fixed plain line, never the exception's text", async () => {
  const raw = "synthetic raw failure text from the node";
  const page = startPage({ refuse: raw });
  await paste(page, KEY);
  await summon(page, "1");
  assert.deepEqual(page.screens(), ["form"]);
  assert.equal(page.$("summon-error").textContent, "The network didn't take the summon. Nothing left your key. Try again.");
  assert.equal(page.$("error").textContent, "");
  for (const id of tags.keys()) assert.ok(!page.$(id).textContent.includes(raw), id);
});

test("leaving the Summon tab, or the page, drops the key", async () => {
  const page = startPage();
  await paste(page, KEY);
  page.$("summon-amount").value = "1";
  page.$("tab-vanish").fire("click");
  assert.equal(page.log.closes, 1, "the tab switch calls summonClose");
  assert.equal(page.$("summon-key").value, "");
  assert.equal(page.$("summon-amount").value, "");
  page.$("tab-summon").fire("click");
  assert.equal(page.$("summon-submit").textContent, "Paste a key");
  assert.equal(page.$("summon-amount-area").hidden, true);

  const other = startPage();
  await paste(other, KEY);
  other.window.fire("pagehide");
  assert.equal(other.log.closes, 1);
  assert.equal(other.$("summon-key").value, "");
  assert.equal(other.log.reveals.length, 0);

  assert.match(fn("forgetSummon"), /flow\.summonClose\(\)/);
  assert.match(fn("selectTab"), /forgetSummon\(\)/);
});
