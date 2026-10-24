// The Ghost pop-up wallet as a connector of wallet-connect.mjs: a small
// static site on its own origin (wallet/ in this repository) that keeps the
// account's ML-DSA-44 key, opened with window.open and asked over
// postMessage. The page reads only messages from the wallet's origin and
// from the window it opened, and posts its requests to that origin only.
// The wallet shows each request in its own window and answers once the
// user approves it there; closing the window turns the request down
// (code 4001).

import { fromHex } from "./bytes.mjs";
import { USER_REJECTED, WalletRejected, snapTransaction } from "./wallet-connect.mjs";

// The wallet's origin; the host step sets the real one.
export const POPUP_WALLET_ORIGIN = "https://wallet.ghostcoin.com";
export const POPUP_WALLET = { id: "ghost-popup-wallet", name: "Ghost wallet" };

// The browser refused to open the wallet's window, as in-app browsers do.
export class PopupBlocked extends Error {
  constructor() {
    super("the browser blocked the wallet window: open this page in your browser and try again");
    this.name = "PopupBlocked";
  }
}

// `win`: the page's window; `origin`: the wallet's origin; `pollMs`: how
// often the window's closed flag is read.
export function popupConnector({ win = globalThis, origin = POPUP_WALLET_ORIGIN, pollMs = 250 } = {}) {
  let popup = null;
  let ready = null;
  let markReady = null;
  let timer = null;
  let address = null;
  let nextId = 1;
  const pending = new Map();

  function onMessage(event) {
    if (!popup || event.source !== popup || event.origin !== origin) return;
    const m = event.data;
    if (!m || typeof m !== "object") return;
    if (m.ready === true) return markReady();
    const asked = pending.get(m.id);
    if (!asked) return;
    pending.delete(m.id);
    if (m.error) asked.reject(Object.assign(new Error(String(m.error.message)), { code: m.error.code }));
    else asked.resolve(m.result);
  }

  // The window is gone: every open request is turned down.
  function lost() {
    win.clearInterval(timer);
    win.removeEventListener("message", onMessage);
    popup = null;
    for (const asked of pending.values()) asked.reject(Object.assign(new Error("the wallet window was closed"), { code: USER_REJECTED }));
    pending.clear();
  }

  function open() {
    if (popup && !popup.closed) return;
    if (popup) lost();
    const w = win.open(`${origin}/`, "_blank", "popup,width=420,height=720");
    if (!w || w.closed) throw new PopupBlocked();
    popup = w;
    ready = new Promise((resolve) => {
      markReady = resolve;
    });
    win.addEventListener("message", onMessage);
    timer = win.setInterval(() => {
      if (popup === w && w.closed) lost();
    }, pollMs);
  }

  // Posts one request once the wallet said it is listening, and waits for
  // its answer.
  async function ask(what, method, params) {
    open();
    const target = popup;
    const id = nextId++;
    const answer = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
    try {
      await Promise.race([ready, answer]);
      target.postMessage(params === undefined ? { id, method } : { id, method, params }, origin);
      return await answer;
    } catch (err) {
      if (err && err.code === USER_REJECTED) throw new WalletRejected(what);
      throw new Error(`the wallet refused ${what}: ${(err && err.message) || err}`);
    }
  }

  return {
    ...POPUP_WALLET,

    async connect() {
      const account = await ask("the connection", "ghost_getAccount");
      if (!account || typeof account.address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(account.address)) {
        throw new Error("the wallet answered without a Ghost account address");
      }
      address = account.address.toLowerCase();
      return { address };
    },

    async signTransaction(fields) {
      if (!address) throw new Error("connect the wallet first");
      const answer = await ask("the transaction", "ghost_signTransaction", snapTransaction(fields));
      try {
        const signed = { sender: fromHex(answer.sender, 20), txHash: fromHex(answer.txHash, 32), envelope: fromHex(answer.envelope) };
        if (signed.envelope.length === 0) throw new Error("an empty envelope");
        return signed;
      } catch {
        throw new Error("the wallet answered without a signed transaction");
      }
    },

    // Forgets the account and closes the wallet's window; the wallet keeps
    // its key.
    disconnect() {
      address = null;
      const w = popup;
      if (w) {
        lost();
        w.close();
      }
    },
  };
}
