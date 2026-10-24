// The page: renders the flow controller's state and forwards the user's
// input to it. All logic is in flow.mjs; nothing here keeps a key beyond
// the element that shows it, which is emptied when the step ends.

import { formatGhost, parseGhost } from "./chain.mjs";
import { DEFAULT_COMMIT_ENTRY, MAX_COMMIT_FEE, WALLET_APPROVAL, createFlow, normalKey, wrongWords } from "./flow.mjs";
import { downloadKeyImage } from "./keyimage.mjs";
import { browserProver } from "./prover.mjs";
import { popupConnector } from "./popup-wallet.mjs";
import { DEFAULT_ENDPOINT } from "./rpc.mjs";
import { injectedProvider, snapConnector } from "./wallet-connect.mjs";

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
// card's one plain error line. "vanish" or "summon" in `errorOwner` keeps the
// flow's raw error text out of the page while that card's line speaks for it.
let vanishSending = false;
let vanishShowAgain = false;
let vanishError = null;
let errorOwner = null;

const WRONG_WORDS = "Those words don't match your key. Check what you saved and try again.";
const REJECTED = "You rejected it in your wallet. Nothing was sent.";

// Whether a Vanish failed because the user turned the commit down in the
// wallet: the flow's WalletRejected, or the wallet's own code 4001.
function rejectedInWallet(err) {
  return Boolean(err) && (err.name === "WalletRejected" || err.code === 4001);
}

// The card's error line for a Vanish step that failed: a fixed sentence
// chosen by what failed, never the exception's own text.
function vanishErrorText(err, step) {
  const said = String((err && err.message) || "");
  if (/^enter an amount|largest amount a coin can hold/.test(said)) return "Enter an amount of GHOST, for example 1.5.";
  if (/less than the amount/.test(said)) return "Your balance is too low for this amount and the network fee.";
  if (/the app signs/.test(said)) return "The network's fee is higher than the app pays right now. Try again later.";
  if (/^connect a wallet/.test(said)) return "Connect your wallet first.";
  if (rejectedInWallet(err)) return REJECTED;
  if (/^the wallet could not sign/.test(said)) return "Your wallet could not sign the Vanish. Nothing was sent.";
  if (/^the wallet was disconnected/.test(said)) return "The wallet was disconnected. Nothing was sent.";
  if (/^the (wallet answered|signed transaction|wallet's transaction hash)/.test(said)) {
    return "Your wallet's answer did not match the transaction. Nothing was sent.";
  }
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

// The Summon card's own state, beside the flow's: whether the pasted key is
// being opened (and whether its error is to be shown: a paste or leaving
// the box, not typing), whether the reveal is being sent, the reveal record
// from before it (so the steps tick only for this one), the amount sent,
// the Done screen's figures and the card's one plain error line. The
// reveal is paid to the connected wallet's address only. `summonConfirm`
// is the confirm screen's summon while it shows: the amount as typed, as
// formatted, and the wallet's address it names.
let summonOpening = false;
let summonLoud = false;
let summonConfirm = null;
let summonSending = false;
let summonBefore = null;
let summonPending = null;
let summonAmount = "";
let summonDone = null;
let summonRecheck = null;
let summonError = null;

const NOT_A_KEY = "That doesn't look like a Phantom Key. It should be 24 words.";
const NO_AMOUNT = "Enter an amount to summon.";
const SPENT = "This key's coin has already been summoned or moved. The key holds nothing now.";
const REFUSED = "The network's chain failed the app's own check, so nothing from it is shown. Try another node under Network.";
const DROPPED = "The chain dropped the summon before a block kept it. Your key still holds the coin. Summon again.";
const WALLET_CHANGED = "Your wallet changed before you confirmed. Nothing was sent. Press Summon again.";
const SUMMON_STEPS = ["summon-step-proof", "summon-step-send", "summon-step-confirm"];
const STEP_NAMES = ["Making your proof", "Sending to the network", "Confirming"];

// "This key holds <value> GHOST.", and, when the amount fits the key but not
// beside the network fee, the most that can go out.
function holdsText(s, out) {
  const holds = `This key holds ${formatGhost(s.current.amount)} GHOST.`;
  if (out === undefined || out > s.current.amount) return holds;
  return `${holds} After the network fee, at most ${formatGhost(s.available)} GHOST can be summoned.`;
}

// The card's error line for a Summon step that failed: a fixed sentence
// chosen by what failed, never the exception's own text. A key that does
// not pass its check is named by a word's position at most.
function summonErrorText(err, step) {
  const said = String((err && err.message) || "");
  if (/^wait until/.test(said)) return "Wait until the current step is done.";
  const s = flow.state.summon;
  if (s && s.status === "refused") return REFUSED;
  if (step === "open") {
    if (s) return "The network could not be read. Check the node under Network and try again.";
    const word = /word (\d+) is not in the word list/.exec(said);
    if (word) return `Word ${word[1]} isn't a Phantom Key word. Check it against the key you saved.`;
    if (/do not pass the check/.test(said)) {
      return "This key doesn't pass its check. A word may be wrong or out of order: check it against the key you saved.";
    }
    if (/^not a valid Phantom Key: group \d+ does not match/.test(said)) {
      return "These digits don't pass their check. A digit may be wrong: check them against the key you saved.";
    }
    return NOT_A_KEY;
  }
  const r = s && s.lastReveal;
  if (r && r !== summonBefore && r.stage === "dropped") return DROPPED;
  if (r && r !== summonBefore && r.stage === "sent") {
    return "The summon was sent, but no checked block holds it yet. Press Check again in a minute.";
  }
  if (/^enter an amount/.test(said)) return NO_AMOUNT;
  if (s && s.current && /^the coin holds/.test(said)) return holdsText(s, 0n);
  if (/unspent|no coin to reveal/.test(said)) return SPENT;
  if (step === "recheck") return "The summon could not be checked. Try again.";
  return "The network didn't take the summon. Nothing left your key. Try again.";
}

// What the open key holds after a summon, or null when the chain was not
// read.
function restOf(s) {
  if (!s || (s.status !== "unclaimed" && s.status !== "claimed")) return null;
  return s.current ? s.current.amount : 0n;
}

// The step of the waiting screen, from the flow's own progress and the
// reveal record: 1 while the proof is made, 2 while it is sent, 3 while a
// block is waited for and checked.
function summonStepOf(state) {
  const p = state.progress ? state.progress.stage : "";
  if (/waiting for a block|checking the block/.test(p)) return 3;
  if (/sending/.test(p)) return 2;
  if (p) return 1;
  const r = state.summon && state.summon.lastReveal;
  return r && r !== summonBefore ? 3 : 1;
}

// A line under the fields while the key is read or its coin must wait.
function summonNote(s) {
  if (summonOpening) return "Looking for your key's coin…";
  if (!s) return "";
  if (s.status === "not-found") return "No coin for this key yet. A Vanish shows here once a block holds it.";
  if (s.current && s.wait && s.wait.alone) {
    return "Your coin is the newest in the chain. So that it cannot be matched to your Vanish, it can be summoned a few blocks after someone else vanishes. Press Check again later.";
  }
  if (s.current && s.wait) return "Your coin can be summoned in a few blocks. Press Check again in a minute.";
  return "";
}

// The Summon card: the paste box and the amount box, the confirm screen,
// the waiting screen with its three steps while the reveal goes out, and
// Done.
function renderSummon(state) {
  const s = state.summon;
  const screen = summonSending ? "waiting" : summonDone ? "done" : summonConfirm ? "confirm" : "form";
  $("summon-form").hidden = screen !== "form";
  $("summon-confirm").hidden = screen !== "confirm";
  $("summon-waiting").hidden = screen !== "waiting";
  $("summon-done").hidden = screen !== "done";

  const c = screen === "confirm" ? summonConfirm : null;
  $("summon-confirm-text").textContent = c ? `Summon ${c.amount} GHOST to ${shortAddress(c.address)}` : "";
  $("summon-confirm").title = c ? c.address : "";

  const coin = Boolean(s && s.status === "unclaimed" && s.current && s.current.amount > 0n && !summonOpening);
  $("summon-amount-area").hidden = !coin;
  $("summon-in-key").textContent = coin ? `${formatGhost(s.current.amount)} GHOST` : "—";
  $("summon-note").textContent = summonNote(s);
  const pending = Boolean(s && s.lastReveal && s.lastReveal.stage === "sent");
  $("summon-refresh").hidden = !(coin && s.wait) && !pending;
  const connected = Boolean(state.wallet);
  $("summon-submit").textContent = !coin ? "Paste a key" : connected ? "Summon" : "Connect wallet";
  $("summon-submit").disabled = !coin || (connected && Boolean(s.wait || pending));

  const step = screen === "waiting" ? summonStepOf(state) : 0;
  $("summon-waiting-amount").textContent = screen === "waiting" ? summonAmount : "";
  $("summon-bar").dataset.step = String(Math.max(step, 1));
  SUMMON_STEPS.forEach((id, i) => {
    $(id).dataset.state = i + 1 < step ? "done" : i + 1 === step ? "now" : "";
  });
  $("summon-waiting-step").textContent = step ? `${STEP_NAMES[step - 1]}…` : "";

  const d = summonDone;
  $("summon-done-amount").textContent = d ? d.amount : "";
  $("summon-done-address").textContent = d ? d.address : "";
  $("summon-done-rest").textContent =
    !d || d.rest === null
      ? ""
      : d.rest > 0n
        ? `${formatGhost(d.rest)} GHOST is still in your key. The same key still works.`
        : "This key is now empty.";
  $("summon-recheck-status").textContent = d && summonRecheck ? summonRecheck : "";

  const spent = Boolean(s && !summonOpening && (s.status === "claimed" || (s.current && s.current.amount === 0n)));
  const refused = Boolean(s && s.status === "refused");
  $("summon-error").textContent = summonError || (refused ? REFUSED : spent && screen === "form" ? SPENT : "");
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
// key's 24 words.
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

// The flow's full Summon status and cover wording. The Summon card shows its
// own plain lines instead; these stay as the reference wording on cover and
// on a block holding a reveal, which the privacy wording test runs.
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

// The wallet panel's own error line: a fixed sentence chosen by what failed,
// never the exception's own text.
let walletError = null;

const SNAP_NOTE = "A quantum-safe Ghost account kept in MetaMask";
const NO_METAMASK = "Install MetaMask to use this wallet, then reload this page";
const POPUP_BLOCKED =
  "The wallet window was blocked. If this page is open inside another app, open it in your browser (Safari, Chrome or Firefox), then try again.";

function walletErrorText(err, step) {
  const said = String((err && err.message) || "");
  if (/^wait until/.test(said)) return "Wait until the current step is done.";
  if (err && err.name === "PopupBlocked") return POPUP_BLOCKED;
  if (step === "refresh") return "The balance could not be read. Check the node under Network.";
  if (/MetaMask is not installed/.test(said)) return "MetaMask is not installed in this browser. Install MetaMask, then reload this page.";
  if (/rejected in your wallet/.test(said)) return "You rejected the connection in your wallet.";
  if (/cannot run MetaMask Snaps/.test(said)) return "This wallet cannot run the Ghost Snap. Use MetaMask.";
  if (/did not install the Ghost Snap/.test(said)) return "The Ghost Snap was not installed. Try again.";
  // Connected, but the balance could not be read.
  if (flow.state.wallet) return "The balance could not be read. Check the node under Network.";
  return "The wallet could not be connected. Try again.";
}

// Runs a wallet step from a user action; a failure shows as the panel's one
// plain error line.
function walletAct(step, run) {
  return (event) => {
    if (event) event.preventDefault();
    errorOwner = "wallet";
    walletError = null;
    render(flow.state);
    Promise.resolve()
      .then(run)
      .catch((err) => {
        walletError = walletErrorText(err, step);
        render(flow.state);
      });
  };
}

// The wallet: the list of wallets to connect while none is, or the
// connected account. Only quantum-safe wallets are listed.
function renderWallet(w) {
  const connected = Boolean(w);
  $("wallet-title").textContent = connected ? "Wallet" : "Connect a wallet";
  $("wallet-connect").hidden = connected;
  $("wallet-option-snap-note").textContent = injectedProvider(window) ? SNAP_NOTE : NO_METAMASK;
  $("wallet-open").hidden = !connected;
  $("wallet-address").textContent = connected ? w.address : "";
  $("wallet-balance").textContent = connected && w.balance !== null ? formatGhost(w.balance) : "?";
  $("wallet-error").textContent = walletError || "";

  // The top-right button and the Vanish tab's balance line.
  $("wallet-button-text").textContent = connected ? shortAddress(w.address) : "Connect wallet";
  $("wallet-button").title = connected ? w.address : "";
  const known = connected && w.balance !== null;
  $("vanish-balance").textContent = known ? `${formatGhost(w.balance)} GHOST` : "—";
  $("vanish-max").disabled = !known;
  $("vanish-submit").textContent = connected ? "Vanish" : "Connect wallet";
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
// key, the waiting bar while the commit is sent (asking for the wallet's
// approval first), and Done.
function renderVanish(v, approving) {
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
    screen !== "waiting"
      ? ""
      : v && v.stage === "sent"
        ? "Sent. Waiting for a block to hold it…"
        : approving
          ? "Approve the Vanish in your wallet"
          : "Sending your commit…";

  const wrong = screen === "check" && v.wrong.length > 0;
  $("vanish-error").textContent = vanishError || (wrong ? WRONG_WORDS : "");
}

function render(state) {
  renderWallet(state.wallet);

  const v = state.vanish;
  renderVanish(v, Boolean(state.progress && state.progress.stage === WALLET_APPROVAL));
  const vanishStatus = {
    sent: () => `Sent: a commit of ${formatGhost(v.amount)} GHOST, transaction ${v.txHash}. ${IN_A_BLOCK}`,
    done: () =>
      `Done: committed ${formatGhost(v.amount)} GHOST in block ${v.block}. Keep your key safe; the app has forgotten it. ${SEAL_TRUST}`,
    dropped: () =>
      `Commit dropped: ${v.dropped}. Start Vanish again. The key you saved still holds the coin if the commit comes back.`,
  };
  $("vanish-status").textContent = v && vanishStatus[v.stage] ? vanishStatus[v.stage]() : "";
  $("vanish-recheck").hidden = !v || (v.stage !== "done" && v.stage !== "dropped");

  renderSummon(state);
  const s = state.summon;
  if (s) {
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
  // A Vanish or Summon step speaks in the card: its waiting screen and its
  // error line.
  const cardOwns = errorOwner === "vanish" || errorOwner === "summon" || errorOwner === "wallet";
  $("progress").textContent =
    vanishSending || summonOpening || summonSending
      ? ""
      : p
        ? `${p.stage}… ${Math.round((Date.now() - p.since) / 1000)} s`
        : state.busy
          ? `${state.busy}…`
          : "";
  $("error").textContent = cardOwns ? "" : state.error || "";
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
// The Ghost pop-up wallet, the default: its window opens from this click,
// keeps the account key on the wallet's own origin and asks the user there.
$("wallet-option-popup").addEventListener(
  "click",
  walletAct("connect", () => flow.walletConnect(popupConnector())),
);
// MetaMask with the Ghost Snap: MetaMask installs the Snap the first time
// and the Snap gives the Ghost account. The provider is read at the click,
// so a MetaMask that arrived after the page loaded is found.
$("wallet-option-snap").addEventListener(
  "click",
  walletAct("connect", async () => {
    const provider = injectedProvider(window);
    if (!provider) throw new Error("MetaMask is not installed");
    await flow.walletConnect(snapConnector(provider));
  }),
);
$("wallet-refresh").addEventListener(
  "click",
  walletAct("refresh", () => flow.walletRefresh()),
);
$("wallet-disconnect").addEventListener(
  "click",
  walletAct("disconnect", () => flow.walletDisconnect()),
);

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

// The Vanish button opens the wallet list while no wallet is connected.
$("vanish-form").addEventListener(
  "submit",
  vanishAct("start", async () => {
    const w = flow.state.wallet;
    if (!w) return openPanel("wallet-panel");
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
  if (w && w.balance !== null) $("vanish-amount").value = formatGhost(maxVanish(w.balance));
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
// wrong word sends nothing and the card stays on the check. The connected
// wallet then asks the user to approve the commit: turned down there,
// nothing is sent, the new key is dropped and the card is back at the
// amount. Any other failure to sign sends nothing either and stays on the
// check, with its own line.
$("vanish-check").addEventListener(
  "submit",
  vanishAct("send", async () => {
    const v = flow.state.vanish;
    const given = answers($("vanish-check-groups"));
    vanishSending = Boolean(v && v.key && v.groups && wrongWords(v.key, v.groups, given).length === 0);
    render(flow.state);
    try {
      await flow.vanishCheck(given);
    } catch (err) {
      if (rejectedInWallet(err)) forgetVanish();
      throw err;
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

// The key leaves the page's memory: the paste box and the amount are
// emptied and the flow closes the key. On Done, on leaving the Summon tab
// and on pagehide.
function forgetSummon() {
  $("summon-key").value = "";
  $("summon-amount").value = "";
  summonConfirm = null;
  summonDone = null;
  summonPending = null;
  summonRecheck = null;
  summonError = null;
  summonLoud = false;
  flow.summonClose();
}

// A pasted key is checked once it holds 24 words, or the 48, 84 or 96
// digits of the digit form's groups.
function keyComplete(text) {
  const parts = String(text).split(/[\s-]+/).filter(Boolean);
  if (parts.length === 24 && parts.every((p) => /^[a-z]+$/i.test(p))) return true;
  const digits = parts.join("");
  return parts.length > 0 && /^\d+$/.test(digits) && [48, 84, 96].includes(digits.length);
}

// Opens the pasted key: the worker checks it, then the flow scans for its
// coin. `loud` shows a refusal (a paste, or leaving the box); while typing
// none shows.
async function openKey(loud) {
  const text = $("summon-key").value;
  if (summonOpening) {
    summonLoud ||= loud;
    return;
  }
  const s = flow.state.summon;
  if (!text.trim() || (s && s.key === normalKey(text))) return;
  if (s) flow.summonClose();
  errorOwner = "summon";
  summonError = null;
  summonLoud = loud;
  summonOpening = true;
  render(flow.state);
  try {
    await flow.summonOpen(text);
  } catch (err) {
    if (summonLoud || flow.state.summon) summonError = summonErrorText(err, "open");
    // A key whose chain could not be read is closed, to be opened again.
    if (flow.state.summon && flow.state.summon.status === "scanning") flow.summonClose();
  } finally {
    summonOpening = false;
  }
  const now = flow.state.summon;
  // The tab was left while the key opened: it goes at once. A key edited
  // meanwhile is closed, to be checked again.
  if ($("card").dataset.tab !== "summon") forgetSummon();
  else if (now && now.key !== normalKey($("summon-key").value)) flow.summonClose();
  render(flow.state);
}

$("summon-key").addEventListener("input", (event) => {
  summonError = null;
  const s = flow.state.summon;
  if (s && !summonOpening && s.key !== normalKey($("summon-key").value)) flow.summonClose();
  const pasted = Boolean(event && /^insertFrom(Paste|Drop)/.test(event.inputType || ""));
  if (keyComplete($("summon-key").value)) openKey(pasted);
  else render(flow.state);
});
$("summon-key").addEventListener("blur", () => openKey(true));

// The Done screen's figures for a reveal the flow shows Done.
function summonDoneOf(r) {
  return { amount: formatGhost(r.out), address: shortAddress(r.recipient), rest: restOf(flow.state.summon) };
}

// Summon pays the connected wallet's address only; with no wallet connected
// the main button opens the wallet list. An amount that does not parse, or
// is more than the key can send, is refused here, never rounded. Pressing
// Summon proves and sends nothing: it opens the confirm screen, which names
// the amount and the wallet's address.
$("summon-form").addEventListener("submit", (event) => {
  if (event) event.preventDefault();
  const s = flow.state.summon;
  if (!s || !s.current || summonOpening || summonSending || summonConfirm) return;
  if (!flow.state.wallet) {
    openPanel("wallet-panel");
    return;
  }
  errorOwner = "summon";
  summonError = null;
  const text = $("summon-amount").value;
  let out = null;
  try {
    out = parseGhost(text);
  } catch {
    out = null;
  }
  if (out === null || out === 0n) summonError = NO_AMOUNT;
  else if (out > s.available) summonError = holdsText(s, out);
  if (!summonError) summonConfirm = { amount: text.trim(), shown: formatGhost(out), address: flow.state.wallet.address };
  render(flow.state);
});
$("summon-max").addEventListener("click", () => {
  const s = flow.state.summon;
  if (s && s.current) $("summon-amount").value = formatGhost(s.available);
});

// Cancel on the confirm screen: back to the form, the key and the amount
// as they were; nothing is proved or sent.
$("summon-cancel").addEventListener("click", () => {
  if (summonSending) return;
  summonConfirm = null;
  render(flow.state);
});

// Confirm Summon: the only place a reveal is proved and sent, for the amount
// and the address the confirm screen named. A second press while it runs
// does nothing; a wallet changed since the screen opened sends nothing.
$("summon-confirm-button").addEventListener("click", async () => {
  const c = summonConfirm;
  if (!c || summonSending) return;
  summonConfirm = null;
  errorOwner = "summon";
  summonError = null;
  const s = flow.state.summon;
  if (!s || !s.current) {
    render(flow.state);
    return;
  }
  if (!flow.state.wallet || flow.state.wallet.address !== c.address) {
    summonError = WALLET_CHANGED;
    render(flow.state);
    return;
  }
  summonAmount = c.shown;
  summonBefore = s.lastReveal;
  summonSending = true;
  render(flow.state);
  try {
    const r = await flow.summonReveal({ amount: c.amount, recipient: flow.state.wallet.address });
    summonDone = summonDoneOf(r);
    summonRecheck = null;
  } catch (err) {
    summonError = summonErrorText(err, "send");
    const r = flow.state.summon && flow.state.summon.lastReveal;
    summonPending = r && r !== summonBefore && r.stage === "sent" ? r : null;
  } finally {
    summonSending = false;
    summonBefore = null;
  }
  if ($("card").dataset.tab !== "summon") forgetSummon();
  render(flow.state);
});

// Check again: the flow asks about a reveal shown Sent again, and reads the
// key's coin and the tree-state rule anew.
$("summon-refresh").addEventListener("click", async () => {
  errorOwner = "summon";
  summonError = null;
  try {
    await flow.summonRefresh();
    const r = flow.state.summon && flow.state.summon.lastReveal;
    if (summonPending && r === summonPending && r.stage === "done") summonDone = summonDoneOf(r);
    if (r && r === summonPending && r.stage === "dropped") summonError = DROPPED;
    if (!r || r.stage !== "sent") summonPending = null;
  } catch (err) {
    summonError = summonErrorText(err, "recheck");
  }
  render(flow.state);
});

// After Done, the reveal's block is asked about again: a reorganisation can
// have dropped it, and the key then holds the coin again.
$("summon-recheck").addEventListener("click", async () => {
  errorOwner = "summon";
  summonError = null;
  summonRecheck = null;
  render(flow.state);
  try {
    await flow.summonRefresh();
    const s = flow.state.summon;
    const r = s && s.lastReveal;
    if (r && r.stage === "dropped") {
      summonDone = null;
      summonError = DROPPED;
    } else if (r && r.stage === "done" && summonDone) {
      summonRecheck = `Still in the chain at block ${r.block}.`;
      const rest = restOf(s);
      if (rest !== null) summonDone.rest = rest;
    }
  } catch (err) {
    summonError = summonErrorText(err, "recheck");
  }
  render(flow.state);
});
$("summon-done-button").addEventListener("click", () => {
  forgetSummon();
  render(flow.state);
});
window.addEventListener("pagehide", forgetSummon);
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
  // Leaving Summon drops its key from the page and the flow.
  if ($("card").dataset.tab === "summon" && name !== "summon") forgetSummon();
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
