// The page: renders the flow controller's state and forwards the user's
// input to it. All logic is in flow.mjs; nothing here keeps a key beyond
// the element that shows it, which is emptied when the step ends.

import { formatGhost } from "./chain.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow } from "./flow.mjs";
import { downloadKeyImage } from "./keyimage.mjs";
import { browserProver } from "./prover.mjs";
import { DEFAULT_ENDPOINT } from "./rpc.mjs";

const $ = (id) => document.getElementById(id);

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
  if (s.status === "claimed") lines.push("Claimed: this key's coin has been moved or revealed.");
  if (s.status === "pending") lines.push("A transaction of this key is waiting for its block.");
  if (s.status === "unclaimed" && s.current) {
    lines.push(`Unclaimed: ${formatGhost(s.current.amount)} GHOST.`);
    lines.push(`Fee now: ${formatGhost(s.fee)} GHOST; at most ${formatGhost(s.available)} GHOST can go out.`);
  }
  if (s.lastReveal && s.lastReveal.block) {
    lines.push(`Revealed ${formatGhost(s.lastReveal.out)} GHOST to ${s.lastReveal.recipient} in block ${s.lastReveal.block}.`);
  }
  lines.push(`Chain tip: block ${s.tip ?? "?"}. Notes are not yet checked against block receipts.`);
  return lines.join(" ");
}

function render(state) {
  const w = state.wallet;
  $("wallet-status").textContent = w ? `${w.account} on chain ${w.chainId}` : "";

  const v = state.vanish;
  renderKeyStep("vanish", v);
  const vanishStatus = {
    pending: () => `Commit sent (${v.txHash}); waiting for its block.`,
    confirmed: () => `Committed ${formatGhost(v.amount)} GHOST in block ${v.block}. Keep your key safe; the app has forgotten it.`,
  };
  $("vanish-status").textContent = v && vanishStatus[v.stage] ? vanishStatus[v.stage]() : "";

  const s = state.summon;
  $("summon-panel").hidden = !s;
  if (s) {
    $("summon-status").textContent = describeSummon(s);
    $("reveal-form").hidden = !s.current;
    $("claim").hidden = !s.current && !(s.claim && s.claim.stage === "confirmed");
    renderKeyStep("claim", s.claim);
    const c = s.claim;
    const claimStatus = {
      pending: () => `Claim sent (${c.txHash}); waiting for its block.`,
      confirmed: () => `Claimed ${formatGhost(c.amount)} GHOST to the new key in block ${c.block}.`,
    };
    $("claim-status").textContent = c && claimStatus[c.stage] ? claimStatus[c.stage]() : "";
    $("claim-start").disabled = Boolean(c && c.stage !== "confirmed");
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
