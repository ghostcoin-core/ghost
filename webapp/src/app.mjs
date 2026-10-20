// The page: renders the flow controller's state and forwards the user's
// input to it. All logic is in flow.mjs; nothing here keeps a key beyond
// the element that shows it, which is emptied when the step ends.

import { formatGhost } from "./chain.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow } from "./flow.mjs";
import { downloadKeyImage } from "./keyimage.mjs";
import { browserProver } from "./prover.mjs";
import { DEFAULT_ENDPOINT } from "./rpc.mjs";

const $ = (id) => document.getElementById(id);

// Headers are checked against their hashes and each other, not their seals.
const SEAL_TRUST =
  "Confirmation trusts the chosen endpoint for the proof-of-work seal of each block, which the app does not verify.";

const flow = createFlow({
  prover: browserProver(),
  wallet: window.ethereum || null,
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

function checkInputs(container, positions, wrong) {
  if (container.dataset.positions !== positions.join(",")) {
    container.replaceChildren(
      ...positions.map((p) => {
        const label = document.createElement("label");
        label.textContent = `Group ${p}`;
        const input = document.createElement("input");
        input.type = "text";
        input.inputMode = "numeric";
        input.autocomplete = "off";
        input.maxLength = 4;
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

// The key panel and save check of Vanish or Claim.
function renderKeyStep(prefix, holder) {
  const panel = $(`${prefix}-key`);
  const text = $(`${prefix}-key-text`);
  const form = $(`${prefix}-check`);
  const groups = $(`${prefix}-check-groups`);
  const showing = Boolean(holder && holder.key && (holder.stage === "shown" || holder.stage === "check"));
  panel.hidden = !showing;
  if (showing) {
    if (text.textContent !== holder.key) {
      text.textContent = holder.key;
      text.classList.add("blurred");
      $(`${prefix}-show`).textContent = "Show";
    }
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
  if (s.status === "not-found") lines.push("No coin for this key yet. A commit shows once its block is in.");
  if (s.status === "claimed") lines.push("Claimed: a block of the chain holds the move or reveal of this key's coin.");
  if (s.status === "unclaimed" && s.current) {
    lines.push(`Unclaimed: ${formatGhost(s.current.amount)} GHOST.`);
    lines.push(`Fee now: ${formatGhost(s.fee)} GHOST; at most ${formatGhost(s.available)} GHOST can go out.`);
  }
  const r = s.lastReveal;
  if (r && r.stage === "sent") {
    lines.push(`Sent: ${formatGhost(r.out)} GHOST to ${r.recipient}, transaction ${r.txHash}. Done once a block holds it.`);
  }
  if (r && r.stage === "done") lines.push(`Done: revealed ${formatGhost(r.out)} GHOST to ${r.recipient} in block ${r.block}.`);
  if (r && r.stage === "dropped") lines.push(`Reveal dropped: ${r.dropped}.`);
  lines.push(`Chain tip: block ${s.tip ?? "?"}. Notes are not yet checked against block receipts.`);
  lines.push(SEAL_TRUST);
  return lines.join(" ");
}

// What a reveal or claim now would hide the coin among, or why the app
// waits. The holder decides whether that cover is enough or to wait for more.
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
      `A reveal or claim now hides this coin among the ${covers} coins in the tree as of block ${height}.${more} ` +
      "Fewer coins make it easier to link the reveal to your commit: reveal now, or wait for more coins and press Refresh. The choice is yours.",
  };
}

function render(state) {
  const w = state.wallet;
  $("wallet-status").textContent = w ? `${w.account} on chain ${w.chainId}` : "";

  const v = state.vanish;
  renderKeyStep("vanish", v);
  const vanishStatus = {
    sent: () => `Sent: a commit of ${formatGhost(v.amount)} GHOST, transaction ${v.txHash}. Done once a block holds it.`,
    done: () =>
      `Done: committed ${formatGhost(v.amount)} GHOST in block ${v.block}. Keep your key safe; the app has forgotten it. ${SEAL_TRUST}`,
    dropped: () =>
      `Commit dropped: ${v.dropped}. Your wallet may send it again by itself; if it does not, start Vanish again. The key you saved still holds the coin if the commit comes back.`,
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
      sent: () => `Sent: a claim of ${formatGhost(c.amount)} GHOST to the new key, transaction ${c.txHash}. Done once a block holds it.`,
      done: () => `Done: claimed ${formatGhost(c.amount)} GHOST to the new key in block ${c.block}. ${SEAL_TRUST}`,
      dropped: () => `Claim dropped: ${c.dropped}. Press Refresh, then Claim again.`,
    };
    $("claim-status").textContent = c && claimStatus[c.stage] ? claimStatus[c.stage]() : "";
    $("claim-start").disabled = Boolean((c && c.stage !== "done" && c.stage !== "dropped") || s.wait);
  }

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

function wireKeyButtons(prefix, holder) {
  $(`${prefix}-show`).addEventListener("click", () => {
    const text = $(`${prefix}-key-text`);
    const hidden = text.classList.toggle("blurred");
    $(`${prefix}-show`).textContent = hidden ? "Show" : "Hide";
  });
  $(`${prefix}-copy`).addEventListener(
    "click",
    act(async () => {
      const h = holder();
      if (h && h.key) await navigator.clipboard.writeText(h.key);
    }),
  );
  $(`${prefix}-download`).addEventListener(
    "click",
    act(async () => {
      const h = holder();
      if (h && h.key) await downloadKeyImage(h.key);
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
$("connect").addEventListener("click", act(() => flow.connectWallet()));

$("vanish-form").addEventListener("submit", act(() => flow.vanishStart($("vanish-amount").value)));
wireKeyButtons("vanish", () => flow.state.vanish);
$("vanish-saved").addEventListener("click", act(() => flow.vanishSaved()));
$("vanish-check").addEventListener("submit", act(() => flow.vanishCheck(answers($("vanish-check-groups")))));
$("vanish-recheck").addEventListener("click", act(() => flow.vanishRecheck()));

$("summon-form").addEventListener(
  "submit",
  act(async () => {
    // The digits leave the field once the key is open; a typo stays there
    // to be corrected.
    const field = $("summon-key");
    const text = field.value;
    field.value = "";
    try {
      await flow.summonOpen(text);
    } catch (err) {
      if (!flow.state.summon || flow.state.summon.key !== text.trim()) field.value = text;
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
wireKeyButtons("claim", () => flow.state.summon && flow.state.summon.claim);
$("claim-saved").addEventListener("click", act(() => flow.claimSaved()));
$("claim-check").addEventListener("submit", act(() => flow.claimCheck(answers($("claim-check-groups")))));

render(flow.state);
