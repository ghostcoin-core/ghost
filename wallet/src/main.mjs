// The pop-up wallet's page: loads the module from the base64 ES module the
// build writes (the wallet fetches nothing), and gives wallet.mjs its
// screens. Each screen waits for one button; what the user typed is read
// at the click and the field cleared.

import { loadGhost } from "../../webapp/src/wasm.mjs";
import { WEBAPP_ORIGINS } from "./config.mjs";
import { WASM } from "./ghost-wasm.mjs";
import { createWallet, vaultStore } from "./wallet.mjs";

const $ = (id) => document.getElementById(id);
const SCREENS = ["status", "start", "words", "check", "restore", "lock", "approve"];

function show(name) {
  for (const s of SCREENS) $(`${s}-screen`).hidden = s !== name;
}

// Resolves with the value of the first of `buttons` ({ id: read }) clicked.
function wait(buttons) {
  return new Promise((resolve) => {
    for (const [id, read] of Object.entries(buttons)) {
      $(id).onclick = () => {
        $("error").textContent = "";
        resolve(read());
      };
    }
  });
}

// The value of a field, which is then emptied.
function take(id) {
  const value = $(id).value;
  $(id).value = "";
  return value;
}

function row(list, term, value) {
  const dt = document.createElement("dt");
  dt.textContent = term;
  const dd = document.createElement("dd");
  dd.textContent = value;
  list.append(dt, dd);
}

const ui = {
  status(text) {
    $("status").textContent = text;
    show("status");
  },
  error(text) {
    $("error").textContent = text;
  },
  start() {
    show("start");
    return wait({ create: () => "create", restore: () => "restore" });
  },
  showWords(words) {
    $("words").replaceChildren(
      ...words.map((w) => {
        const li = document.createElement("li");
        li.textContent = w;
        return li;
      }),
    );
    show("words");
    return wait({ "words-done": () => $("words").replaceChildren() });
  },
  checkWords(positions) {
    positions.forEach((p, i) => {
      $(`check-label-${i}`).textContent = `Word ${p}`;
    });
    show("check");
    return wait({ "check-done": () => positions.map((_, i) => take(`check-${i}`)) });
  },
  restoreWords() {
    show("restore");
    return wait({ "restore-done": () => take("restore-words") });
  },
  chooseLock(passkey) {
    $("lock-passkey").hidden = !passkey;
    show("lock");
    return wait({
      "lock-passkey": () => ({ kind: "passkey" }),
      "lock-done": () => ({ kind: "password", password: take("lock-password"), again: take("lock-password-again") }),
    });
  },
  approve(summary, kind) {
    const list = $("approve-details");
    list.replaceChildren();
    $("approve-origin").textContent = summary.origin;
    if (summary.kind === "connect") {
      $("approve-title").textContent = "Share your account address";
      row(list, "The app sees", "your account address and public key, never your words or key");
    } else if (summary.kind === "receive") {
      $("approve-title").textContent = "Share a new receive address";
      row(list, "The app sees", "a new account address and its public key, never your words or key");
    } else {
      $("approve-title").textContent = "Sign a transaction";
      row(list, "From", summary.from ?? "your first account (unlock to sign with it)");
      row(list, "Amount", `${summary.amount} GHOST`);
      row(list, "Maximum fee", `${summary.maxFee} GHOST`);
      row(list, "To", summary.to);
      row(list, "Chain id", summary.chainId);
      row(list, "Data", `${summary.dataBytes} bytes`);
    }
    $("approve-password-label").hidden = kind !== "password";
    show("approve");
    return wait({ approve: () => ({ password: take("approve-password") }), reject: () => null });
  },
};

function decodeBase64(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

if (!window.opener) {
  ui.status("Open this wallet from the Ghost app.");
} else {
  const wallet = createWallet({
    ghost: await loadGhost(decodeBase64(WASM)),
    store: vaultStore(indexedDB),
    ui,
    subtle: crypto.subtle,
    credentials: globalThis.PublicKeyCredential ? navigator.credentials : null,
    random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    origins: WEBAPP_ORIGINS,
    opener: window.opener,
  });
  window.addEventListener("message", wallet.onMessage);
  wallet.announce();
}
