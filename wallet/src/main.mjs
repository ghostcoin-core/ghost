// The pop-up wallet's page: loads the module from the base64 ES module the
// build writes (the wallet fetches nothing), and gives wallet.mjs its
// screens. Each screen waits for one button; what the user typed is read
// at the click and the field cleared.

import { loadGhost } from "../../webapp/src/wasm.mjs";
import { WEBAPP_ORIGINS } from "./config.mjs";
import { WASM } from "./ghost-wasm.mjs";
import { createWallet, vaultStore } from "./wallet.mjs";

const $ = (id) => document.getElementById(id);
const SCREENS = ["status", "start", "words", "check", "restore", "lock", "key", "guard-key", "coins", "approve"];

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

// List items of `texts`, for the warnings of a Guard screen.
function items(texts) {
  return texts.map((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    return li;
  });
}

// The three check words, typed back under `title`.
function checkThree(title, positions) {
  $("check-title").textContent = title;
  positions.forEach((p, i) => {
    $(`check-label-${i}`).textContent = `Word ${p}`;
  });
  show("check");
  return wait({ "check-done": () => positions.map((_, i) => take(`check-${i}`)) });
}

const GUARD_KEY_TITLES = {
  guardRestore: "Restore from a Phantom Key",
  guardSpend: "Spend a Guard coin",
  guardWordsOnly: "Words-only spend of a Guard coin",
};

const RULE_NAMES = { guard: "Guard coin", empty: "plain coin", other: "coin with another rule" };

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
    return checkThree("Check your backup", positions);
  },
  // A Guard commit's new Phantom Key, shown once with the warnings.
  showKey(words, warnings) {
    $("key-words").replaceChildren(...items(words));
    $("key-warnings").replaceChildren(...items(warnings));
    show("key");
    return wait({ "key-done": () => $("key-words").replaceChildren() });
  },
  checkKey(positions) {
    return checkThree("Check your Phantom Key", positions);
  },
  // The Phantom Key of a Guard request, typed here; null for Reject.
  guardKey(summary) {
    $("guard-key-title").textContent = GUARD_KEY_TITLES[summary.kind];
    $("guard-key-origin").textContent = summary.origin;
    show("guard-key");
    return wait({
      "guard-key-done": () => take("guard-key-words"),
      "guard-key-reject": () => {
        take("guard-key-words");
        return null;
      },
    });
  },
  // The coins a restore found, each with its warnings.
  showCoins(coins) {
    const list = coins.map((coin) => {
      const li = document.createElement("li");
      const state = coin.spent ? "spent" : "unspent";
      li.textContent = `Number ${coin.number}: ${coin.amount} GHOST, ${RULE_NAMES[coin.rule]}, ${state}, at position ${coin.position}`;
      if (coin.warnings.length > 0) {
        const warnings = document.createElement("ul");
        warnings.className = "warnings";
        warnings.replaceChildren(...items(coin.warnings));
        li.append(warnings);
      }
      return li;
    });
    $("coins").replaceChildren(...(list.length > 0 ? list : items(["No coin of these words in the tree the app gave."])));
    show("coins");
    return wait({ "coins-done": () => $("coins").replaceChildren() });
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
    } else if (summary.kind === "rescue") {
      $("approve-title").textContent = "Rescue: move the whole balance";
      row(list, "From", summary.from ?? "your first account (unlock to sign with it)");
      row(list, "Signed with", "the rescue key (scheme 0x0004)");
      row(list, "Balance", `${summary.balance} GHOST`);
      row(list, "Amount moved", `${summary.amount} GHOST`);
      row(list, "Maximum fee", `${summary.maxFee} GHOST`);
      row(list, "Chain id", summary.chainId);
    } else if (summary.kind === "guardCommit") {
      $("approve-title").textContent = "Guard commit: a new coin under your stop card";
      row(list, "From", summary.from ?? "your first account (unlock to sign with it)");
      row(list, "Scheme", summary.scheme ?? "known once unlocked");
      row(list, "Amount", `${summary.amount} GHOST`);
      row(list, "Maximum fee", `${summary.maxFee} GHOST`);
      row(list, "Commit entry", summary.to);
      row(list, "Guard address", summary.guardAddress);
      row(list, "Cost of a cancel", `${summary.actionCost} GHOST`);
      row(list, "Chain id", summary.chainId);
      row(list, "Phantom Key", "a new one, made and shown in this wallet");
    } else if (summary.kind === "guardSpend") {
      $("approve-title").textContent = "Guard: spend normally";
      row(list, "Coin holds", `${summary.amount} GHOST`);
      row(list, "Amount", `${summary.out} GHOST`);
      row(list, "Fee", `${summary.fee} GHOST`);
      row(list, "To", summary.recipient);
      row(list, "Left in the key", `${summary.remainder} GHOST`);
      row(list, "Left under", summary.remainderRule === "guard" ? "a new Guard rule of your stop card" : "no rule: a plain coin");
      row(list, "Chain id", summary.chainId);
    } else if (summary.kind === "guardWordsOnly") {
      $("approve-title").textContent = "Guard: words-only spend";
      row(list, "Coin holds", `${summary.amount} GHOST`);
      row(list, "Into Guard's slot", `${summary.slot} GHOST`);
      row(list, "Fee", `${summary.fee} GHOST`);
      row(list, "Paid after the hold (72 hours) to", summary.recipient);
      row(list, "Cost of a cancel", `${summary.actionCost} GHOST`);
      row(list, "During the hold", "the coin's stop card can cancel this spend");
      row(list, "Chain id", summary.chainId);
    } else {
      $("approve-title").textContent = "Sign a transaction";
      row(list, "From", summary.from ?? "your first account (unlock to sign with it)");
      row(list, "Scheme", summary.scheme ?? "known once unlocked");
      row(list, "Rescue key", summary.rescueKey === null ? "known once unlocked" : summary.rescueKey ? "yes" : "no");
      row(list, "Amount", `${summary.amount} GHOST`);
      row(list, "Maximum fee", `${summary.maxFee} GHOST`);
      row(list, "To", summary.to);
      row(list, "Chain id", summary.chainId);
      row(list, "Data", `${summary.dataBytes} bytes`);
    }
    $("approve-warnings").replaceChildren(...items(summary.warnings ?? []));
    $("approve-password-label").hidden = kind !== "password";
    // The rescue destination and the stop root are typed here, never taken
    // from the app.
    const rescue = summary.kind === "rescue";
    const stop = summary.kind === "guardCommit" || (summary.kind === "guardSpend" && summary.remainderRule === "guard");
    $("approve-destination-label").hidden = !rescue;
    $("approve-stop-label").hidden = !stop;
    show("approve");
    return wait({
      approve: () => {
        const destination = take("approve-destination");
        const stopRoot = take("approve-stop");
        const password = take("approve-password");
        if (rescue) return { password, destination };
        return stop ? { password, stopRoot } : { password };
      },
      reject: () => {
        take("approve-destination");
        take("approve-stop");
        return null;
      },
    });
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
