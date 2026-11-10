// The wallet's window comes to the front for each request, so an approval
// is not missed behind the app: the web app's connector (popup-wallet.mjs)
// focuses the pop-up before each request it posts, and the wallet
// (wallet.mjs, with main.mjs's screens) focuses its own window and titles
// it "Ghost app is asking: approve below" while the request waits, the
// title going back once answered. Runs without the built module: nothing
// here reaches a signature.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

import { popupConnector } from "../../webapp/src/popup-wallet.mjs";
import { ASKING_TITLE, createWallet } from "../src/wallet.mjs";
import { repoDir, scriptedUi, settle, until } from "./fakes.mjs";

const APP = "https://app.example";
const WALLET = "https://wallet.example";
const ADDRESS = `0x${"ab".repeat(20)}`;

// The page's window, whose pop-up logs each focus and each post in
// `events`, and answers every request with `reply(message)`.
function fakePage(reply) {
  const listeners = new Set();
  const deliver = (event) => setImmediate(() => listeners.forEach((h) => h(event)));
  const page = {
    events: [],
    opened: 0,
    popup: null,
    open() {
      page.opened += 1;
      const popup = {
        closed: false,
        close() {
          popup.closed = true;
        },
        focus() {
          page.events.push("focus");
        },
        postMessage(data, targetOrigin) {
          page.events.push(data.method);
          assert.equal(targetOrigin, WALLET);
          deliver({ data: { id: data.id, result: reply(data) }, origin: WALLET, source: popup });
        },
      };
      page.popup = popup;
      deliver({ data: { ready: true }, origin: WALLET, source: popup });
      return popup;
    },
    addEventListener: (type, handler) => type === "message" && listeners.add(handler),
    removeEventListener: (type, handler) => listeners.delete(handler),
    setInterval: (fn, ms) => setInterval(fn, ms).unref(),
    clearInterval: (t) => clearInterval(t),
  };
  return page;
}

test("the connector focuses the wallet's window before each request it posts", async () => {
  const page = fakePage(() => ({ address: ADDRESS }));
  const c = popupConnector({ win: page, origin: WALLET, pollMs: 5 });
  await c.connect();
  assert.deepEqual(page.events, ["focus", "ghost_getAccount"]);
  await c.newReceiveAddress();
  await c.newReceiveAddress();
  assert.equal(page.opened, 1, "the same pop-up answers every request");
  assert.deepEqual(page.events, ["focus", "ghost_getAccount", "focus", "ghost_newReceiveAddress", "focus", "ghost_newReceiveAddress"]);
  c.disconnect();
});

test("a window without focus still gets the request", async () => {
  const page = fakePage(() => ({ address: ADDRESS }));
  const open = page.open;
  page.open = () => {
    const popup = open();
    delete popup.focus;
    return popup;
  };
  const c = popupConnector({ win: page, origin: WALLET, pollMs: 5 });
  assert.deepEqual(await c.connect(), { address: ADDRESS });
  assert.deepEqual(page.events, ["ghost_getAccount"]);
  c.disconnect();
});

// A wallet with a stored vault whose screens are `ui`; the approval screen
// is the only one reached, and Reject there means nothing is ever signed.
function setUp(ui) {
  const opener = {
    sent: [],
    postMessage: (data, origin) => opener.sent.push({ data, origin }),
  };
  const store = {
    get: async () => ({ kind: "password" }),
    getRescueFrom: async () => 0,
    getIssued: async () => 0,
  };
  const wallet = createWallet({ ghost: {}, store, ui, subtle: null, credentials: null, random: null, origins: [APP], opener });
  return { wallet, opener };
}

test("the wallet asks for attention with its title while a request waits, and puts the title back once answered", async () => {
  assert.equal(ASKING_TITLE, "Ghost app is asking: approve below");
  let titlesAtApproval = null;
  let release;
  const held = new Promise((r) => {
    release = r;
  });
  const ui = scriptedUi({
    approve: async (summary, kind, self) => {
      titlesAtApproval = self.titles.slice();
      await held;
      return null;
    },
  });
  const { wallet, opener } = setUp(ui);
  wallet.onMessage({ data: { id: 1, method: "ghost_getAccount" }, origin: APP, source: opener });
  await until(() => titlesAtApproval !== null, "approval screen");
  assert.deepEqual(titlesAtApproval, [ASKING_TITLE], "focused and titled before the approval screen");
  await settle();
  assert.deepEqual(ui.titles, [ASKING_TITLE], "the title stays while the user has not answered");
  release();
  await until(() => opener.sent.length === 1);
  assert.equal(opener.sent[0].data.error.code, 4001);
  assert.deepEqual(ui.titles, [ASKING_TITLE, null], "the title goes back once answered");

  // The next request asks again.
  wallet.onMessage({ data: { id: 2, method: "ghost_newReceiveAddress" }, origin: APP, source: opener });
  await until(() => opener.sent.length === 2);
  assert.deepEqual(ui.titles, [ASKING_TITLE, null, ASKING_TITLE, null]);
});

test("a refused request or a stranger's message does not pull the wallet to the front", async () => {
  const ui = scriptedUi({ approve: () => assert.fail("no screen") });
  const { wallet, opener } = setUp(ui);
  wallet.onMessage({ data: { id: 1, method: "ghost_nothing" }, origin: APP, source: opener });
  await until(() => opener.sent.length === 1);
  wallet.onMessage({ data: { id: 2, method: "ghost_getAccount" }, origin: "https://evil.example", source: opener });
  await settle();
  assert.equal(opener.sent.length, 1);
  assert.deepEqual(ui.titles, []);
});

// main.mjs's attention, run on stand-ins for the window and the document
// (the page itself needs the built module).
async function mainAttention(win, doc) {
  const source = await readFile(resolve(repoDir, "wallet/src/main.mjs"), "utf8");
  const pageTitle = source.match(/^const PAGE_TITLE = document\.title;$/m);
  assert.ok(pageTitle, "main.mjs keeps the page's own title");
  const method = source.match(/^ {2}attention\(title\) \{\n[\s\S]*?\n {2}\},$/m);
  assert.ok(method, "main.mjs's screens have attention(title)");
  const make = new Function("window", "document", `const PAGE_TITLE = document.title; return { ${method[0]} };`);
  return make(win, doc).attention;
}

test("main.mjs focuses the wallet's window and titles its window and tab", async () => {
  const win = { focused: 0, focus: () => (win.focused += 1) };
  const doc = { title: "Ghost wallet" };
  const attention = await mainAttention(win, doc);
  attention(ASKING_TITLE);
  assert.equal(win.focused, 1);
  assert.equal(doc.title, "Ghost app is asking: approve below");
  attention(null);
  assert.equal(doc.title, "Ghost wallet");
  assert.equal(win.focused, 1, "answering does not focus again");
});
