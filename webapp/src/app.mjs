// The page: renders the flow controller's state and forwards the user's
// input to it. All logic is in flow.mjs; nothing here keeps a key beyond
// the element that shows it, which is emptied when the step ends.

import { formatGhost } from "./chain.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow, normalKey } from "./flow.mjs";
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

// Runs a flow step from a user action; errors are shown from the state.
function act(step) {
  return (event) => {
    if (event) event.preventDefault();
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

// The key of Vanish or Claim as it is shown: its words, or its digit view.
function shownKey(holder) {
  return holder.view === "digits" && holder.digits ? holder.digits : holder.key;
}

// The key panel and save check of Vanish or Claim.
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
}

function render(state) {
  renderWallet(state.wallet);

  const v = state.vanish;
  renderKeyStep("vanish", v);
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

  const p = state.progress;
  $("progress").textContent = p ? `${p.stage}… ${Math.round((Date.now() - p.since) / 1000)} s` : state.busy ? `${state.busy}…` : "";
  $("error").textContent = state.error || "";
  for (const button of document.querySelectorAll("main button")) {
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

$("vanish-form").addEventListener("submit", act(() => flow.vanishStart($("vanish-amount").value)));
wireKeyButtons("vanish", () => flow.state.vanish, (view) => flow.vanishView(view));
$("vanish-saved").addEventListener("click", act(() => flow.vanishSaved()));
$("vanish-check").addEventListener("submit", act(() => flow.vanishCheck(answers($("vanish-check-groups")))));
$("vanish-recheck").addEventListener("click", act(() => flow.vanishRecheck()));

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

render(flow.state);
