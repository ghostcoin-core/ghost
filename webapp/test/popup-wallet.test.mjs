// The pop-up wallet connector (popup-wallet.mjs) against the real wallet
// logic (wallet/src/wallet.mjs) on the built module, with a stand-in for
// window.open and postMessage between the two origins: connect and sign
// with a signature the module verifies, replies accepted only from the
// wallet's origin and window, requests posted to that origin only, Reject
// and a closed pop-up as 4001 with nothing signed, and a blocked pop-up.

import assert from "node:assert/strict";
import { test } from "node:test";

import { WEBAPP_ORIGINS } from "../../wallet/src/config.mjs";
import { createWallet, vaultStore } from "../../wallet/src/wallet.mjs";
import { fakeIndexedDB, loadTestGhost, scriptedUi, settle, spyGhost, testRandom } from "../../wallet/test/fakes.mjs";
import { fromHex, toHex } from "../src/bytes.mjs";
import { POPUP_WALLET, POPUP_WALLET_ORIGIN, PopupBlocked, popupConnector } from "../src/popup-wallet.mjs";
import { WalletRejected } from "../src/wallet-connect.mjs";

const APP = "https://app.example";
const WALLET = "https://wallet.example";
const ghost = await loadTestGhost();

const FIELDS = {
  chainId: 7_777_001n,
  genesis: Uint8Array.from({ length: 32 }, (_, i) => i),
  nonce: 3n,
  maxPriorityFeePerGas: 1_000_000_000n,
  maxFeePerGas: 3_000_000_000n,
  gasLimit: 122_744n,
  to: fromHex(`0x67686f7374${"0".repeat(28)}05`, 20),
  value: 10n ** 18n,
  data: Uint8Array.of(0x00, 0x02, 0xab),
};

// The page's window on APP. window.open makes a pop-up on WALLET running
// the wallet's logic with `ui`; messages cross between the two as the
// browser carries them, only to the origin they are addressed to.
function fakePage({ ui = scriptedUi(), block = false } = {}) {
  const listeners = new Set();
  const spy = spyGhost(ghost);
  const page = {
    opened: [],
    posts: [],
    popup: null,
    spy,
    open(url, target, features) {
      page.opened.push({ url, target, features });
      if (block) return null;
      const popup = {
        closed: false,
        close() {
          popup.closed = true;
        },
        postMessage(data, targetOrigin) {
          page.posts.push({ data: structuredClone(data), targetOrigin });
          if (popup.closed || targetOrigin !== WALLET) return;
          const copy = structuredClone(data);
          setImmediate(() => wallet.onMessage({ data: copy, origin: APP, source: opener }));
        },
      };
      const opener = {
        postMessage(data, targetOrigin) {
          if (popup.closed || targetOrigin !== APP) return;
          page.deliver({ data: structuredClone(data), origin: WALLET, source: popup });
        },
      };
      const wallet = createWallet({
        ghost: spy,
        store: vaultStore(fakeIndexedDB()),
        ui,
        subtle: globalThis.crypto.subtle,
        credentials: null,
        random: testRandom(),
        origins: [APP],
        opener,
      });
      page.popup = popup;
      setImmediate(() => wallet.announce());
      return popup;
    },
    addEventListener: (type, handler) => type === "message" && listeners.add(handler),
    removeEventListener: (type, handler) => listeners.delete(handler),
    deliver: (event) => setImmediate(() => listeners.forEach((h) => h(event))),
    listeners,
    setInterval: (fn, ms) => setInterval(fn, ms).unref(),
    clearInterval: (t) => clearInterval(t),
  };
  return page;
}

const connector = (page) => popupConnector({ win: page, origin: WALLET, pollMs: 5 });
const signs = (page) => page.spy.calls.filter((c) => c === "ghost_wallet_sign").length;

test("connect and sign through the pop-up: the account and a signature the module verifies", async () => {
  const page = fakePage();
  const c = connector(page);
  assert.equal(c.id, POPUP_WALLET.id);
  assert.equal(c.name, "Ghost wallet");
  const { address } = await c.connect();
  assert.match(address, /^0x[0-9a-f]{40}$/);
  assert.deepEqual(page.opened, [{ url: `${WALLET}/`, target: "_blank", features: "popup,width=420,height=720" }]);
  assert.doesNotMatch(page.opened[0].features, /noopener|noreferrer/, "the wallet needs its opener");

  const signed = await c.signTransaction(FIELDS);
  assert.equal(page.opened.length, 1, "the same pop-up answers every request");
  assert.equal(toHex(signed.sender), address);
  assert.deepEqual(ghost.keccak256(signed.envelope), signed.txHash);
  const verified = ghost.accountTxVerify({ chainId: FIELDS.chainId, genesis: FIELDS.genesis, envelope: signed.envelope });
  assert.equal(toHex(verified.sender), address);
  assert.equal(verified.value, FIELDS.value);
  assert.deepEqual(verified.to, FIELDS.to);

  // Every request went to the wallet's origin only, with the fields as 0x hex.
  assert.deepEqual(
    page.posts.map((p) => [p.targetOrigin, p.data.method]),
    [
      [WALLET, "ghost_getAccount"],
      [WALLET, "ghost_signTransaction"],
    ],
  );
  assert.equal(page.posts[1].data.params.chainId, "0x76aae9");

  c.disconnect();
  assert.equal(page.popup.closed, true, "disconnect closes the wallet window");
  assert.equal(page.listeners.size, 0);
  await assert.rejects(c.signTransaction(FIELDS), /connect the wallet first/);
});

test("replies from another origin or another window are ignored", async () => {
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const page = fakePage({ ui: scriptedUi({ approve: async () => (await held, { password: "correct horse battery" }) }) });
  const c = connector(page);
  const connecting = c.connect();
  await new Promise((r) => setTimeout(r, 50));
  const forged = { id: 1, result: { address: `0x${"66".repeat(20)}`, publicKey: "0x01" } };
  page.deliver({ data: forged, origin: "https://evil.example", source: page.popup });
  page.deliver({ data: forged, origin: WALLET, source: { closed: false } });
  page.deliver({ data: forged, origin: `${WALLET}.evil.example`, source: page.popup });
  await settle();
  release();
  const { address } = await connecting;
  assert.notEqual(address, forged.result.address);
  c.disconnect();

});

test("the page opens the hosted wallet, and the wallet answers the hosted page only", async () => {
  assert.equal(POPUP_WALLET_ORIGIN, "https://ghost-wallet-nine.vercel.app");
  assert.deepEqual(WEBAPP_ORIGINS, ["https://ghost-webapp-alpha.vercel.app"]);
  assert.ok(Object.isFrozen(WEBAPP_ORIGINS));

  // With no origin given, the connector opens the hosted wallet and posts
  // to it only.
  const page = fakePage();
  const popup = { closed: false, close() {}, postMessage: (data, targetOrigin) => page.posts.push({ data, targetOrigin }) };
  page.open = (url, target, features) => {
    page.opened.push({ url, target, features });
    return popup;
  };
  const c = popupConnector({ win: page, pollMs: 5 });
  const connecting = c.connect();
  assert.deepEqual(page.opened.map((o) => o.url), ["https://ghost-wallet-nine.vercel.app/"]);
  // A ready message from another origin is not the wallet's; the hosted one is.
  page.deliver({ data: { ready: true }, origin: "https://wallet.example", source: popup });
  await settle();
  assert.equal(page.posts.length, 0);
  page.deliver({ data: { ready: true }, origin: POPUP_WALLET_ORIGIN, source: popup });
  await settle();
  assert.deepEqual(page.posts.map((p) => [p.targetOrigin, p.data.method]), [[POPUP_WALLET_ORIGIN, "ghost_getAccount"]]);
  const address = `0x${"ab".repeat(20)}`;
  page.deliver({ data: { id: page.posts[0].data.id, result: { address } }, origin: POPUP_WALLET_ORIGIN, source: popup });
  assert.deepEqual(await connecting, { address });
  c.disconnect();
});

test("Reject in the pop-up and closing the pop-up sign nothing and turn the request down (4001)", async () => {
  // Rejected on the approval screen.
  const rejecting = fakePage({ ui: scriptedUi({ approve: () => null }) });
  const r = connector(rejecting);
  await assert.rejects(r.connect(), (err) => err instanceof WalletRejected && err.message === "the connection was rejected in your wallet; nothing was sent");
  r.disconnect();

  // Closed while the approval screen is open.
  let approvals = 0;
  const closing = fakePage({
    ui: scriptedUi({
      approve: () => {
        approvals += 1;
        if (approvals === 1) return { password: "correct horse battery" };
        closing.popup.closed = true;
        return new Promise(() => {});
      },
    }),
  });
  const k = connector(closing);
  await k.connect();
  await assert.rejects(k.signTransaction(FIELDS), (err) => err instanceof WalletRejected && /^the transaction was rejected/.test(err.message));
  assert.equal(signs(closing), 0, "nothing was signed");
  assert.equal(closing.listeners.size, 0, "the page stops listening to a closed pop-up");

  // Closed before the wallet was ready.
  const early = fakePage();
  const e = connector(early);
  const connecting = e.connect();
  early.popup.closed = true;
  await assert.rejects(connecting, WalletRejected);
});

test("a refusal from the wallet is an error naming the field, and nothing is signed", async () => {
  const page = fakePage();
  const c = connector(page);
  await c.connect();
  await assert.rejects(c.signTransaction({ ...FIELDS, to: null }), /the wallet refused the transaction: to is not 20 bytes/);
  await assert.rejects(c.signTransaction({ ...FIELDS, chainId: 1n }), /chainId 1 is not a network/);
  await assert.rejects(c.signTransaction({ ...FIELDS, maxPriorityFeePerGas: FIELDS.maxFeePerGas + 1n }), /maxPriorityFeePerGas is above maxFeePerGas/);
  assert.equal(signs(page), 0);
  c.disconnect();
});

test("a blocked pop-up is a PopupBlocked error, and nothing is asked", async () => {
  const page = fakePage({ block: true });
  const c = connector(page);
  await assert.rejects(c.connect(), (err) => err instanceof PopupBlocked && err.name === "PopupBlocked" && /open this page in your browser/.test(err.message));
  assert.equal(page.posts.length, 0);
  assert.equal(page.listeners.size, 0);
  // A window the browser closed at once counts as blocked too.
  const shut = fakePage();
  shut.open = () => ({ closed: true });
  await assert.rejects(connector(shut).connect(), PopupBlocked);
});
