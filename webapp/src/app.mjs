// The page: renders the flow controller's state and forwards the user's
// input to it. All logic is in flow.mjs; nothing here keeps a key beyond
// the element that shows it, which is emptied when the step ends.

import { formatGhost, parseGhost } from "./chain.mjs";
import { DEFAULT_COMMIT_ENTRY, MAX_COMMIT_FEE, createFlow, normalKey, wrongWords } from "./flow.mjs";
import { downloadKeyImage } from "./keyimage.mjs";
import { browserProver } from "./prover.mjs";
import { DEFAULT_ENDPOINT } from "./rpc.mjs";

const $ = (id) => document.getElementById(id);

// Every block the app counts is one this page checked itself: its hash, its
// difficulty and its proof-of-work seal, on the chain with the most work
// from the start this build pins.
const SEAL_TRUST =
  "Confirmation comes only from blocks this page checked itself, proof-of-work seal and difficulty included, on the heaviest chain from the start this build pins for the network.";

// A sent transaction is marked Done when a block holds it. That block is
// neither final settlement nor privacy, and the text says so.
const IN_A_BLOCK =
  "Marked Done when a block holds it. One block is not final: each block after it makes it harder to undo, and blocks add no privacy.";

const flow = createFlow({
  prover: browserProver(),
  endpoint: DEFAULT_ENDPOINT,
  commitEntry: DEFAULT_COMMIT_ENTRY,
  onChange: render,
});

$("endpoint").value = flow.state.endpoint;
$("commit-entry").value = flow.state.commitEntry;

// The Vanish card's own state, beside the flow's: whether the commit is being
// sent (from the moment the three words match until the flow's check call
// returns), whether the key is shown again from the check screen, and the
// card's one plain error line. "vanish" in `errorOwner` keeps the flow's raw
// error text out of the page while that line speaks for it.
let vanishSending = false;
let vanishShowAgain = false;
let vanishError = null;
let errorOwner = null;

const WRONG_WORDS = "Those words don't match your key. Check what you saved and try again.";

// The card's error line for a Vanish step that failed: a fixed sentence
// chosen by what failed, never the exception's own text.
function vanishErrorText(err, step) {
  const said = String((err && err.message) || "");
  if (/^enter an amount|largest amount a coin can hold/.test(said)) return "Enter an amount of GHOST, for example 1.5.";
  if (/less than the amount/.test(said)) return "Your balance is too low for this amount and the network fee.";
  if (/the app signs/.test(said)) return "The network's fee is higher than the app pays right now. Try again later.";
  if (/^open a wallet/.test(said)) return "Open your wallet first.";
  if (/^wait until/.test(said)) return "Wait until the current step is done.";
  const v = flow.state.vanish;
  if (step === "send" && v && v.stage === "dropped") {
    return "The chain dropped the commit. The key you saved still holds the coin if it comes back.";
  }
  if (step === "send" && v && v.stage === "sent") return "The commit was sent, but no checked block holds it yet.";
  const fixed = {
    start: "The key could not be made. Try again.",
    send: "The network refused the commit. Try again.",
    copy: "The key could not be copied. Write it down instead.",
    download: "The image could not be made. Write the key down instead.",
    recheck: "The commit could not be checked. Try again.",
  };
  return fixed[step] || "Something went wrong. Try again.";
}

// Runs a Vanish step from a user action; a failure shows as the card's one
// plain error line.
function vanishAct(step, run) {
  return (event) => {
    if (event) event.preventDefault();
    errorOwner = "vanish";
    vanishError = null;
    render(flow.state);
    Promise.resolve()
      .then(run)
      .catch((err) => {
        vanishError = vanishErrorText(err, step);
        render(flow.state);
      });
  };
}

// Runs a flow step from a user action; errors are shown from the state.
function act(step) {
  return (event) => {
    if (event) event.preventDefault();
    errorOwner = null;
    Promise.resolve()
      .then(step)
      .catch((err) => {
        $("error").textContent = err.message;
      });
  };
}

// The save check's inputs: one whole word for each position asked, of a
// key's 24 words or of the wallet's seed.
function checkInputs(container, positions, wrong) {
  if (container.dataset.positions !== positions.join(",")) {
    container.replaceChildren(
      ...positions.map((p) => {
        const label = document.createElement("label");
        label.textContent = `Word ${p}`;
        const input = document.createElement("input");
        input.type = "text";
        input.inputMode = "text";
        input.autocomplete = "off";
        input.autocapitalize = "off";
        input.spellcheck = false;
        input.maxLength = 8;
        input.dataset.position = String(p);
        label.appendChild(input);
        return label;
      }),
    );
    container.dataset.positions = positions.join(",");
  }
  for (const input of container.querySelectorAll("input")) {
    input.setAttribute("aria-invalid", String(wrong.includes(Number(input.dataset.position))));
  }
}

function answers(container) {
  return [...container.querySelectorAll("input")].map((input) => input.value);
}

function clearCheck(container) {
  container.replaceChildren();
  delete container.dataset.positions;
}

// The key of Claim as it is shown: its words, or its digit view.
function shownKey(holder) {
  return holder.view === "digits" && holder.digits ? holder.digits : holder.key;
}

// The key panel and save check of Claim (`prefix`).
function renderKeyStep(prefix, holder) {
  const panel = $(`${prefix}-key`);
  const text = $(`${prefix}-key-text`);
  const form = $(`${prefix}-check`);
  const groups = $(`${prefix}-check-groups`);
  const showing = Boolean(holder && holder.key && (holder.stage === "shown" || holder.stage === "check"));
  panel.hidden = !showing;
  if (showing) {
    const shown = shownKey(holder);
    if (text.textContent !== shown) {
      text.textContent = shown;
      text.classList.add("blurred");
      $(`${prefix}-show`).textContent = "Show";
    }
    $(`${prefix}-digits`).textContent = holder.view === "digits" ? "Show as words" : "Show as digits";
  } else {
    text.textContent = "";
  }
  $(`${prefix}-saved`).disabled = !holder || holder.stage !== "shown";
  form.hidden = !holder || holder.stage !== "check";
  if (holder && holder.stage === "check") checkInputs(groups, holder.groups, holder.wrong);
  else clearCheck(groups);
}

function describeSummon(s) {
  const lines = [];
  if (s.status === "scanning") return "Reading the chain…";
  if (s.status === "refused") return `No confirmations: ${s.refusal ?? "the endpoint's chain failed the proof-of-work check"}.`;
  if (s.status === "not-found") lines.push("No coin for this key yet. A commit shows once its block is in.");
  if (s.status === "claimed") lines.push("Claimed: a block of the chain holds the move or reveal of this key's coin.");
  if (s.status === "unclaimed" && s.current) {
    lines.push(`Unclaimed: ${formatGhost(s.current.amount)} GHOST.`);
    lines.push(`Fee now: ${formatGhost(s.fee)} GHOST; at most ${formatGhost(s.available)} GHOST can go out.`);
  }
  const r = s.lastReveal;
  if (r && r.stage === "sent") {
    lines.push(`Sent: ${formatGhost(r.out)} GHOST to ${r.recipient}, transaction ${r.txHash}. ${IN_A_BLOCK}`);
  }
  if (r && r.stage === "done") lines.push(`Done: revealed ${formatGhost(r.out)} GHOST to ${r.recipient} in block ${r.block}.`);
  if (r && r.stage === "dropped") lines.push(`Reveal dropped: ${r.dropped}.`);
  lines.push(
    `Chain tip: block ${s.tip ?? "?"}. The coin tree's leaves and notes and the spent markers were checked against the block receipts of every block from the start this build pins.`,
  );
  lines.push(SEAL_TRUST);
  return lines.join(" ");
}

// How many coins the settled tree holds, or why the app waits. The count is
// of commitments, not people; the holder decides whether to wait for more.
function describeCover(s) {
  if (s.status !== "unclaimed" || !s.current) return null;
  if (s.wait && s.wait.alone) {
    return {
      warning: true,
      text: `Not yet: ${s.wait.message}. Press Refresh after someone else has committed.`,
    };
  }
  if (s.wait) return { warning: true, text: `Not yet: ${s.wait.message}. Press Refresh to check again.` };
  if (!s.cover) return null;
  const { height, covers, total } = s.cover;
  const more = total > covers ? ` ${total - covers} more are in newer blocks and will count once they are settled.` : "";
  return {
    warning: false,
    text:
      `The tree holds ${covers} coins as of block ${height}.${more} ` +
      "That is a count of commitments, not of people, and not a promise of anonymity: one party can make many of them, and amounts or timing can still match your reveal to your commit. " +
      "Fewer coins make it easier to link the reveal to your commit: reveal now, or wait for more coins and press Refresh. The choice is yours.",
  };
}

// The wallet: new words and their save check, or the open account.
function renderWallet(w) {
  $("wallet-closed").hidden = Boolean(w);
  const text = $("wallet-words-text");
  const showing = Boolean(w && w.words && (w.stage === "shown" || w.stage === "check"));
  $("wallet-words").hidden = !showing;
  if (showing) {
    if (text.textContent !== w.words) {
      text.textContent = w.words;
      text.classList.add("blurred");
      $("wallet-show").textContent = "Show";
    }
  } else {
    text.textContent = "";
  }
  $("wallet-saved").disabled = !w || w.stage !== "shown";
  $("wallet-check").hidden = !w || w.stage !== "check";
  if (w && w.stage === "check") checkInputs($("wallet-check-words"), w.groups, w.wrong);
  else clearCheck($("wallet-check-words"));
  const open = Boolean(w && w.stage === "open");
  $("wallet-open").hidden = !open;
  $("wallet-address").textContent = open ? w.address : "";
  $("wallet-balance").textContent = open && w.balance !== null ? formatGhost(w.balance) : "?";

  // The top-right button and the Vanish tab's balance line.
  $("wallet-button-text").textContent = open ? shortAddress(w.address) : "Open wallet";
  $("wallet-button").title = open ? w.address : "";
  const known = open && w.balance !== null;
  $("vanish-balance").textContent = known ? `${formatGhost(w.balance)} GHOST` : "—";
  $("vanish-max").disabled = !known;
  $("vanish-submit").textContent = open ? "Vanish" : "Open wallet";
}

// An address as the wallet button shows it: 0x3a…91c.
function shortAddress(address) {
  return `${address.slice(0, 4)}…${address.slice(-3)}`;
}

// The most a Vanish can commit: the balance less the most the commit's gas
// can cost.
function maxVanish(balance) {
  return balance > MAX_COMMIT_FEE ? balance - MAX_COMMIT_FEE : 0n;
}

// The 24 words in the numbered grid, put in with textContent only. The grid
// is filled while the key is shown or checked and emptied otherwise.
function renderWords(key) {
  const grid = $("vanish-words");
  if (!key) {
    grid.replaceChildren();
    return;
  }
  if (grid.childElementCount > 0) return;
  grid.replaceChildren(
    ...key.trim().split(/\s+/).map((word, i) => {
      const item = document.createElement("li");
      const number = document.createElement("span");
      number.className = "n";
      number.textContent = String(i + 1);
      const text = document.createElement("span");
      text.textContent = word;
      item.append(number, text);
      return item;
    }),
  );
}

// The Vanish card: the amount box, then Save your Phantom Key, Check your
// key, the waiting bar while the commit is sent, and Done.
function renderVanish(v) {
  const holding = Boolean(v && v.key && (v.stage === "shown" || v.stage === "check"));
  renderWords(holding ? v.key : null);
  const screen = vanishSending
    ? "waiting"
    : !v
      ? "form"
      : v.stage === "shown" || (v.stage === "check" && vanishShowAgain)
        ? "key"
        : v.stage === "check"
          ? "check"
          : v.stage === "done"
            ? "done"
            : "after";
  $("vanish-form").hidden = screen !== "form";
  $("vanish-key").hidden = screen !== "key";
  $("vanish-check").hidden = screen !== "check";
  $("vanish-waiting").hidden = screen !== "waiting";
  $("vanish-done").hidden = screen !== "done";
  $("vanish-after").hidden = screen !== "after";

  const amount = v ? formatGhost(v.amount) : "";
  for (const id of ["vanish-key-amount", "vanish-send-amount", "vanish-done-amount"]) $(id).textContent = amount;
  if (v && v.stage === "check") checkInputs($("vanish-check-groups"), v.groups, v.wrong);
  else clearCheck($("vanish-check-groups"));
  $("vanish-waiting-text").textContent =
    screen !== "waiting" ? "" : v && v.stage === "sent" ? "Sent. Waiting for a block to hold it…" : "Sending your commit…";

  const wrong = screen === "check" && v.wrong.length > 0;
  $("vanish-error").textContent = vanishError || (wrong ? WRONG_WORDS : "");
}

function render(state) {
  renderWallet(state.wallet);

  const v = state.vanish;
  renderVanish(v);
  const vanishStatus = {
    sent: () => `Sent: a commit of ${formatGhost(v.amount)} GHOST, transaction ${v.txHash}. ${IN_A_BLOCK}`,
    done: () =>
      `Done: committed ${formatGhost(v.amount)} GHOST in block ${v.block}. Keep your key safe; the app has forgotten it. ${SEAL_TRUST}`,
    dropped: () =>
      `Commit dropped: ${v.dropped}. Start Vanish again. The key you saved still holds the coin if the commit comes back.`,
  };
  $("vanish-status").textContent = v && vanishStatus[v.stage] ? vanishStatus[v.stage]() : "";
  $("vanish-recheck").hidden = !v || (v.stage !== "done" && v.stage !== "dropped");

  const s = state.summon;
  $("summon-panel").hidden = !s;
  if (s) {
    $("summon-status").textContent = describeSummon(s);
    const cover = describeCover(s);
    $("summon-cover").hidden = !cover;
    $("summon-cover").textContent = cover ? cover.text : "";
    $("summon-cover").classList.toggle("warning", Boolean(cover && cover.warning));
    $("reveal-form").hidden = !s.current;
    $("reveal-submit").disabled = Boolean(s.wait);
    $("claim").hidden = !s.current && !(s.claim && (s.claim.stage === "done" || s.claim.stage === "dropped"));
    renderKeyStep("claim", s.claim);
    const c = s.claim;
    const claimStatus = {
      sent: () => `Sent: a claim of ${formatGhost(c.amount)} GHOST to the new key, transaction ${c.txHash}. ${IN_A_BLOCK}`,
      done: () => `Done: claimed ${formatGhost(c.amount)} GHOST to the new key in block ${c.block}. ${SEAL_TRUST}`,
      dropped: () => `Claim dropped: ${c.dropped}. Press Refresh, then Claim again.`,
    };
    $("claim-status").textContent = c && claimStatus[c.stage] ? claimStatus[c.stage]() : "";
    $("claim-start").disabled = Boolean((c && c.stage !== "done" && c.stage !== "dropped") || s.wait);
  }

  $("chain-status").textContent = state.chainRefused ? `No confirmations: ${state.chainRefused}.` : "";
  $("network-button").classList.toggle("attention", Boolean(state.chainRefused));

  const p = state.progress;
  // A Vanish step speaks in the card: its waiting line and its error line.
  const vanishOwns = errorOwner === "vanish";
  $("progress").textContent =
    vanishSending
      ? ""
      : p
        ? `${p.stage}… ${Math.round((Date.now() - p.since) / 1000)} s`
        : state.busy
          ? `${state.busy}…`
          : "";
  $("error").textContent = vanishOwns ? "" : state.error || "";
  for (const button of document.querySelectorAll("main button, #wallet-panel button, #network-panel button")) {
    if (!button.dataset.keepEnabled) button.toggleAttribute("aria-busy", Boolean(state.busy));
  }
}

// The elapsed time while a step runs.
setInterval(() => {
  if (flow.state.progress) render(flow.state);
}, 1000);

// `view(v)` shows the key as "words" or "digits". Copy and the image take
// the key as it is shown; both are conveniences beside writing it down.
function wireKeyButtons(prefix, holder, view) {
  $(`${prefix}-show`).addEventListener("click", () => {
    const text = $(`${prefix}-key-text`);
    const hidden = text.classList.toggle("blurred");
    $(`${prefix}-show`).textContent = hidden ? "Show" : "Hide";
  });
  $(`${prefix}-digits`).addEventListener(
    "click",
    act(() => {
      const h = holder();
      if (h && h.key) return view(h.view === "digits" ? "words" : "digits");
      return null;
    }),
  );
  $(`${prefix}-copy`).addEventListener(
    "click",
    act(async () => {
      const h = holder();
      if (h && h.key) await navigator.clipboard.writeText(shownKey(h));
    }),
  );
  $(`${prefix}-download`).addEventListener(
    "click",
    act(async () => {
      const h = holder();
      if (h && h.key) await downloadKeyImage(shownKey(h));
    }),
  );
}

$("network-form").addEventListener(
  "submit",
  act(() => {
    flow.setEndpoint($("endpoint").value);
    flow.setCommitEntry($("commit-entry").value);
    $("endpoint").value = flow.state.endpoint;
  }),
);
$("wallet-create").addEventListener("click", act(() => flow.walletCreate()));
$("wallet-show").addEventListener("click", () => {
  const hidden = $("wallet-words-text").classList.toggle("blurred");
  $("wallet-show").textContent = hidden ? "Show" : "Hide";
});
$("wallet-saved").addEventListener("click", act(() => flow.walletSaved()));
$("wallet-check").addEventListener("submit", act(() => flow.walletCheck(answers($("wallet-check-words")))));
$("wallet-restore-form").addEventListener(
  "submit",
  act(async () => {
    // The words leave the field once the wallet is open; a typo stays there
    // to be corrected.
    const field = $("wallet-restore-words");
    const text = field.value;
    field.value = "";
    try {
      await flow.walletRestore(text);
    } catch (err) {
      if (!flow.state.wallet) field.value = text;
      throw err;
    }
  }),
);
$("wallet-refresh").addEventListener("click", act(() => flow.walletRefresh()));
$("wallet-close").addEventListener("click", act(() => flow.walletClose()));

// The key leaves the page's memory: the flow drops the Vanish step and the
// grid is emptied. On Done, on leaving the Vanish tab and on pagehide; before
// the three words match, nothing has been sent.
function forgetVanish() {
  $("vanish-words").replaceChildren();
  clearCheck($("vanish-check-groups"));
  vanishShowAgain = false;
  vanishError = null;
  flow.vanishCancel();
}

// The Vanish button opens the wallet panel while no wallet is open.
$("vanish-form").addEventListener(
  "submit",
  vanishAct("start", async () => {
    const w = flow.state.wallet;
    if (!w || w.stage !== "open") return openPanel("wallet-panel");
    const amount = parseGhost($("vanish-amount").value);
    if (w.balance !== null && amount > maxVanish(w.balance)) {
      throw new Error("the wallet holds less than the amount and the most the gas can cost");
    }
    vanishShowAgain = false;
    await flow.vanishStart($("vanish-amount").value);
    // The tab was left while the key was made: it goes at once.
    if ($("card").dataset.tab !== "vanish") forgetVanish();
    return null;
  }),
);
$("vanish-max").addEventListener("click", () => {
  const w = flow.state.wallet;
  if (w && w.stage === "open" && w.balance !== null) $("vanish-amount").value = formatGhost(maxVanish(w.balance));
});
// Copy and Download take the 24 words; both are conveniences beside writing
// them down.
$("vanish-copy").addEventListener(
  "click",
  vanishAct("copy", async () => {
    const v = flow.state.vanish;
    if (v && v.key) await navigator.clipboard.writeText(v.key);
  }),
);
$("vanish-download").addEventListener(
  "click",
  vanishAct("download", async () => {
    const v = flow.state.vanish;
    if (v && v.key) await downloadKeyImage(v.key);
  }),
);
$("vanish-saved").addEventListener(
  "click",
  vanishAct("saved", () => {
    if (vanishShowAgain) {
      vanishShowAgain = false;
      render(flow.state);
      return;
    }
    flow.vanishSaved();
  }),
);
$("vanish-back").addEventListener("click", () => {
  vanishShowAgain = true;
  vanishError = null;
  render(flow.state);
});
// The only place the commit is sent: the check form's submit. The waiting
// bar shows once the three words match, until the flow's check returns; a
// wrong word sends nothing and the card stays on the check.
$("vanish-check").addEventListener(
  "submit",
  vanishAct("send", async () => {
    const v = flow.state.vanish;
    const given = answers($("vanish-check-groups"));
    vanishSending = Boolean(v && v.key && v.groups && wrongWords(v.key, v.groups, given).length === 0);
    render(flow.state);
    try {
      await flow.vanishCheck(given);
    } finally {
      vanishSending = false;
      render(flow.state);
    }
  }),
);
$("vanish-recheck").addEventListener("click", vanishAct("recheck", () => flow.vanishRecheck()));
for (const id of ["vanish-done-button", "vanish-after-done"]) {
  $(id).addEventListener("click", () => {
    forgetVanish();
    $("vanish-amount").value = "";
  });
}
window.addEventListener("pagehide", forgetVanish);

$("summon-form").addEventListener(
  "submit",
  act(async () => {
    // The key leaves the field once it is open; a typo stays there to be
    // corrected. The refusal names at most a position, never a word.
    const field = $("summon-key");
    const text = field.value;
    field.value = "";
    try {
      await flow.summonOpen(text);
    } catch (err) {
      if (!flow.state.summon || flow.state.summon.key !== normalKey(text)) field.value = text;
      throw err;
    }
  }),
);
$("summon-refresh").addEventListener("click", act(() => flow.summonRefresh()));
$("summon-close").addEventListener("click", act(() => flow.summonClose()));
$("reveal-form").addEventListener(
  "submit",
  act(() => flow.summonReveal({ amount: $("reveal-amount").value, recipient: $("reveal-to").value })),
);
$("claim-start").addEventListener("click", act(() => flow.claimStart()));
wireKeyButtons(
  "claim",
  () => flow.state.summon && flow.state.summon.claim,
  (view) => flow.claimView(view),
);
$("claim-saved").addEventListener("click", act(() => flow.claimSaved()));
$("claim-check").addEventListener("submit", act(() => flow.claimCheck(answers($("claim-check-groups")))));

// The folder tabs: a click, or the arrow keys, Home and End on the tab list.
const TABS = ["vanish", "summon"];

function selectTab(name, focus) {
  // Leaving Vanish drops its key; nothing is sent unless the check passed.
  if ($("card").dataset.tab === "vanish" && name !== "vanish") forgetVanish();
  for (const t of TABS) {
    const on = t === name;
    const tab = $(`tab-${t}`);
    tab.setAttribute("aria-selected", String(on));
    tab.tabIndex = on ? 0 : -1;
    $(`panel-${t}`).hidden = !on;
  }
  $("card").dataset.tab = name;
  if (focus) $(`tab-${name}`).focus();
}

for (const t of TABS) $(`tab-${t}`).addEventListener("click", () => selectTab(t, false));
$("tab-vanish").parentElement.addEventListener("keydown", (event) => {
  const at = TABS.indexOf($("card").dataset.tab);
  const to = {
    ArrowLeft: (at + TABS.length - 1) % TABS.length,
    ArrowRight: (at + 1) % TABS.length,
    Home: 0,
    End: TABS.length - 1,
  }[event.key];
  if (to === undefined) return;
  event.preventDefault();
  selectTab(TABS[to], true);
});

// The wallet, Network and About panels: one open at a time, each toggled by
// its button and closed by Escape.
const PANELS = { "wallet-panel": "wallet-button", "network-panel": "network-button", "about-panel": "about-button" };

function openPanel(id) {
  for (const [panel, button] of Object.entries(PANELS)) {
    $(panel).hidden = panel !== id;
    $(button).setAttribute("aria-expanded", String(panel === id));
  }
}

function closePanels() {
  const open = Object.keys(PANELS).find((panel) => !$(panel).hidden);
  openPanel(null);
  if (open) $(PANELS[open]).focus();
}

for (const [panel, button] of Object.entries(PANELS)) {
  $(button).addEventListener("click", () => ($(panel).hidden ? openPanel(panel) : closePanels()));
}
for (const button of document.querySelectorAll("[data-close]")) button.addEventListener("click", closePanels);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closePanels();
});

render(flow.state);
