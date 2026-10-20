// Sent at once, Done at the first block: against the scripted node stand-in,
// with the real prover, the page state of Vanish, a partial Summon and a
// Claim is Sent, with the amount and the transaction hash, as soon as the
// node takes the transaction and before any block holds it, and Done once
// the block that holds it is in the chain, with no later block waited for.
// A reorganisation that drops a transaction shown Done is said plainly and
// the holder can send again, with the pinned-coin guard against paying a
// reveal twice still in force. Behaviour only: nothing here is timed.

import assert from "node:assert/strict";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { CONFIRMATIONS } from "../src/chain.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow } from "../src/flow.mjs";
import { loadModule, nodeProver } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
const ACCOUNT = "0x1111111111111111111111111111111111111111";
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const RESEND_MS = 3;

function answersFor(key, positions) {
  const groups = key.split(" ");
  return positions.map((p) => groups[p - 1]);
}

// A stand-in node, its wallet and a flow on them. While the app waits for a
// block, the chain grows by one block (holding whatever waits in the pool),
// unless `chain.mining` is false. `snapshots` holds, for every state the
// flow emits, what the test checks of it and of the node at that moment.
async function setUp({ fetch = globalThis.fetch } = {}) {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const wallet = node.wallet(ACCOUNT);
  const worker = nodeProver();
  const work = [];
  const prover = {
    request(op, args, onProgress) {
      return worker.request(op, args, onProgress).finally(() => work.push({ op, decoy: Boolean(args && args.decoy) }));
    },
  };
  const chain = { mining: true };
  const sleep = async (ms) => {
    if (ms === RESEND_MS) return new Promise((resolve) => setTimeout(resolve, ms));
    if (chain.mining) node.mine();
  };
  const snapshots = [];
  const onChange = (state) => {
    const v = state.vanish;
    const r = state.summon?.lastReveal;
    const c = state.summon?.claim;
    snapshots.push({
      vanish: v && { stage: v.stage, txHash: v.txHash, amount: v.amount, block: v.block },
      reveal: r && { stage: r.stage, txHash: r.txHash, out: r.out, block: r.block },
      claim: c && { stage: c.stage, txHash: c.txHash, amount: c.amount, block: c.block },
      tip: node.tip(),
      pooled: node.pool.entries.map((e) => e.hash),
      reveals: node.reveals.length,
    });
  };
  const flow = createFlow({ prover, wallet, endpoint: node.url, pollMs: 5, maxPolls: 20, resendMs: RESEND_MS, sleep, fetch, onChange });
  node.foreignCommits(2);
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { node, wallet, flow, chain, snapshots, work, done };
}

async function vanish(flow, amount) {
  const key = await flow.vanishStart(amount);
  const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
  assert.equal(sent.ok, true);
  return { key, sent };
}

// The first snapshot in which `part` (vanish, reveal or claim) shows `stage`.
const firstAt = (snapshots, part, stage) => snapshots.find((s) => s[part]?.stage === stage);

test("the done depth is the transaction's own block", () => {
  assert.equal(CONFIRMATIONS, 1);
});

test("Vanish, a reveal and a claim show Sent when the node takes them and Done at the first block", async () => {
  const { node, wallet, flow, snapshots, done } = await setUp();
  try {
    node.pool.on = true;

    // --- Vanish ---
    const { key, sent } = await vanish(flow, "1");
    assert.equal(wallet.calls.filter((c) => c.method === "eth_sendTransaction").length, 1);
    const walletHash = sent.txHash;
    const vSent = firstAt(snapshots, "vanish", "sent");
    assert.ok(vSent, "the commit is shown Sent");
    assert.equal(vSent.vanish.txHash, walletHash, "with the transaction hash");
    assert.equal(vSent.vanish.amount, GHOST, "and the amount");
    assert.deepEqual(vSent.pooled, [walletHash], "while the commit still waits in the node's pool");
    const block = node.leaves.find((l) => toHex(l.commitment) === toHex(node.commits[0].commitment)).block;
    assert.ok(vSent.tip < block, "before any block holds it");
    const vDone = firstAt(snapshots, "vanish", "done");
    assert.equal(vDone.vanish.block, block, "Done in the block that holds it");
    assert.equal(flow.state.vanish.stage, "done");
    assert.equal(flow.state.vanish.block, block);
    assert.equal(node.tip(), block, "no block on top was waited for");

    // --- A partial reveal ---
    node.foreignCommits(1);
    node.mineTo(node.tip() + 2);
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    const before = snapshots.length;
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const rSent = firstAt(snapshots.slice(before), "reveal", "sent");
    assert.ok(rSent, "the reveal is shown Sent");
    assert.equal(rSent.reveal.out, GHOST / 4n);
    assert.match(rSent.reveal.txHash, /^0x[0-9a-f]{64}$/);
    assert.deepEqual(rSent.pooled, [rSent.reveal.txHash], "while the node holds it in its pool");
    assert.equal(rSent.reveals, 0, "and no block holds it");
    assert.equal(node.reveals.length, 1);
    assert.equal(node.reveals[0].hash, rSent.reveal.txHash);
    assert.ok(rSent.tip < node.reveals[0].block);
    assert.equal(reveal.stage, "done");
    assert.equal(reveal.block, node.reveals[0].block, "Done in the block that holds it");
    assert.equal(node.tip(), node.reveals[0].block, "no block on top was waited for");
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);

    // --- A claim of the remainder ---
    node.foreignCommits(1);
    node.mineTo(node.tip() + 2);
    await flow.summonRefresh();
    const newKey = await flow.claimStart();
    const fromClaim = snapshots.length;
    const claimed = await flow.claimCheck(answersFor(newKey, flow.claimSaved()));
    const cSent = firstAt(snapshots.slice(fromClaim), "claim", "sent");
    assert.ok(cSent, "the claim is shown Sent");
    assert.equal(cSent.claim.txHash, claimed.txHash);
    assert.equal(cSent.claim.amount, claimed.amount);
    assert.ok(cSent.claim.amount > 0n);
    assert.deepEqual(cSent.pooled, [claimed.txHash]);
    assert.equal(cSent.reveals, 1, "no block holds the claim yet");
    assert.equal(node.reveals.length, 2);
    assert.equal(claimed.block, node.reveals[1].block);
    assert.equal(node.tip(), claimed.block, "no block on top was waited for");
    assert.equal(flow.state.summon.claim.stage, "done");
    assert.equal(flow.state.summon.status, "claimed", "the old key shows claimed at the claim's own block");
  } finally {
    await done();
  }
});

// geth's reply to a send refused because its head kept moving.
const headMoved = (id) =>
  new Response(
    `{"jsonrpc":"2.0","id":${id},"error":{"code":-32000,"message":"chain head kept moving while the reveal was checked"}}\n`,
    { status: 200, headers: { "content-type": "application/json" } },
  );

test("a reorganisation that drops a reveal shown Done is said plainly, and it can be sent again once", async () => {
  let node = null;
  // From `lie.from` sends on, the endpoint takes the send, lets the chain
  // move on until the remainder could be revealed at another fee, and then
  // answers that its head moved.
  const lie = { from: Infinity, sends: [] };
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (call.method !== "eth_sendRawTransaction") return globalThis.fetch(url, init);
    lie.sends.push(call.params[0]);
    const response = await globalThis.fetch(url, init);
    if (lie.sends.length < lie.from) return response;
    assert.equal((await response.json()).error, undefined, "the node took the send");
    const block = node.reveals[node.reveals.length - 1].block;
    node.setBaseFee(2n * 10n ** 9n);
    node.mineTo(block + 40);
    node.foreignCommits(1);
    node.mineTo(block + 80);
    return headMoved(call.id);
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, chain, work, done } = set;
  try {
    const { key } = await vanish(flow, "1");
    node.mineTo(40);
    node.foreignCommits(1);
    node.mineTo(80);
    const opened = await flow.summonOpen(key);
    const coin = { ...opened.current };

    // Done in the reveal's own block.
    chain.mining = false;
    const first = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(first.stage, "done");
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
    const block = first.block;

    // A refresh with the reveal still in the chain leaves it Done.
    let s = await flow.summonRefresh();
    assert.equal(s.lastReveal.stage, "done");
    assert.equal(s.lastReveal.block, block);

    // The chain is reorganised onto one that never held the reveal.
    assert.equal(node.reorg(1), block);
    assert.ok(node.reorged.includes(first.txHash));
    assert.equal(node.balances.get(RECIPIENT), 0n);
    s = await flow.summonRefresh();
    assert.equal(s.lastReveal.stage, "dropped");
    assert.match(s.lastReveal.dropped, new RegExp(`reorganised and block ${block} no longer holds the reveal`));
    assert.match(s.lastReveal.dropped, /nothing it did stands. You can send it again/);
    assert.equal(s.status, "unclaimed", "the coin shows unspent again");
    assert.deepEqual(
      { number: s.current.number, position: s.current.position, amount: s.current.amount },
      { number: coin.number, position: coin.position, amount: coin.amount },
      "the same coin as before the reveal",
    );
    assert.equal(s.wait, null, "and can be revealed again");

    // Sent again. The endpoint takes the send and still answers that its
    // head moved: the app proves only the pinned coin again, finds it spent
    // and stops, so the recipient is paid once and the remainder never pays
    // the same reveal again.
    lie.from = lie.sends.length + 1;
    const fromWork = work.length;
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /no longer unspent/);
    assert.equal(lie.sends.length, lie.from, "the reveal was sent once again, and no more");
    assert.equal(node.reveals.length, 1, "one reveal is in the chain");
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n, "the recipient is paid once");
    assert.ok(
      work.slice(fromWork).filter((w) => w.op === "prove").every((w, i) => i === 0 || w.decoy),
      "the remainder is never proved",
    );
  } finally {
    await done();
  }
});

test("an endpoint's missing receipt never shows a reveal dropped, and a dropped reveal that comes back is not paid again", async () => {
  // With `hide` set the endpoint answers every receipt lookup with null, as
  // one that wants a reveal that went through to look dropped.
  const endpoint = { hide: false, envelopes: [] };
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (call.method === "eth_getTransactionReceipt" && endpoint.hide) {
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: call.id, result: null }), { status: 200 });
    }
    if (call.method === "eth_sendRawTransaction") endpoint.envelopes.push(call.params[0]);
    return globalThis.fetch(url, init);
  };
  const { node, flow, chain, work, done } = await setUp({ fetch });
  // The first reveal's envelope sent to the node again, as a node that put
  // it back in its pool after a reorganisation mines it again.
  const resendOriginal = async () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_sendRawTransaction", params: [endpoint.envelopes[0]] });
    const reply = await (await globalThis.fetch(node.url, { method: "POST", body })).json();
    assert.equal(reply.error, undefined, "the node takes the first reveal again");
  };
  try {
    const { key } = await vanish(flow, "1");
    node.mineTo(40);
    node.foreignCommits(1);
    node.mineTo(80);
    const coin = { ...(await flow.summonOpen(key)).current };
    chain.mining = false;
    const first = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(first.stage, "done");

    // The endpoint hides the receipt of a reveal still in its block.
    endpoint.hide = true;
    let s = await flow.summonRefresh();
    assert.equal(s.lastReveal.stage, "done", "a missing receipt is not a drop");
    assert.equal(s.current.number, 1n, "the remainder is the key's coin");

    // A reorganisation replaces the block, and the reveal lands again in a
    // later one; the receipt is still hidden. The chain holds the reveal's
    // new coin, so it stays Done.
    node.reorg(1);
    await resendOriginal();
    assert.equal(node.reveals.length, 1);
    s = await flow.summonRefresh();
    assert.equal(s.lastReveal.stage, "done", "a reveal the chain still holds is not shown dropped");
    assert.equal(s.pinned, null);
    assert.equal(s.current.number, 1n);

    // Now a reorganisation that really drops it: shown dropped, its coin
    // pinned for the send again.
    endpoint.hide = false;
    node.reorg(1);
    assert.equal(node.reveals.length, 0);
    s = await flow.summonRefresh();
    assert.equal(s.lastReveal.stage, "dropped");
    assert.equal(s.current.number, coin.number, "the first coin is unspent again");
    assert.deepEqual(s.pinned, { number: coin.number, position: coin.position, amount: coin.amount });

    // Before the holder sends again, the dropped reveal comes back. The
    // send again finds the pinned coin spent and pays nothing from the
    // remainder.
    await resendOriginal();
    const fromWork = work.length;
    const sends = endpoint.envelopes.length;
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /no longer unspent/);
    assert.equal(endpoint.envelopes.length, sends, "nothing is sent");
    assert.ok(work.slice(fromWork).filter((w) => w.op === "prove").every((w) => w.decoy), "the remainder is never proved");
    assert.equal(node.reveals.length, 1);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n, "the recipient is paid once");

    // A refresh finds the reveal in the chain again: Done, and the pin is
    // released, so the remainder can be revealed as the holder chooses.
    s = await flow.summonRefresh();
    assert.equal(s.lastReveal.stage, "done");
    assert.equal(s.pinned, null);
    node.foreignCommits(1);
    node.mineTo(node.tip() + 2);
    await flow.summonRefresh();
    await flow.summonReveal({ amount: "0.1", recipient: RECIPIENT });
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n + GHOST / 10n);
  } finally {
    await done();
  }
});

test("a reorganisation that drops a commit shown Done is said plainly, and Vanish can run again", async () => {
  const { node, flow, chain, done } = await setUp();
  try {
    chain.mining = false;
    const { sent } = await vanish(flow, "1");
    assert.equal(flow.state.vanish.stage, "done");
    const block = sent.block;
    assert.equal(node.tip(), block);

    // Still in the chain: still Done.
    node.mine();
    await flow.vanishRecheck();
    assert.equal(flow.state.vanish.stage, "done");
    assert.equal(flow.state.vanish.block, block);

    node.reorg(2);
    assert.ok(node.reorged.includes(sent.txHash));
    await flow.vanishRecheck();
    assert.equal(flow.state.vanish.stage, "dropped");
    assert.match(flow.state.vanish.dropped, new RegExp(`reorganised and block ${block} no longer holds the commit`));
    assert.match(flow.state.vanish.dropped, /You can send it again/);

    // The holder can start Vanish again and send a new commit.
    const again = await vanish(flow, "1");
    assert.equal(flow.state.vanish.stage, "done");
    assert.equal(node.tip(), again.sent.block);
  } finally {
    await done();
  }
});

test("a receipt from a block a reorganisation replaced while the app checked it is a dropped claim", async () => {
  let node = null;
  // Once armed, the first receipt the endpoint finds is answered as it was
  // and then the block it names is replaced by a reorganisation.
  const replace = { armed: false, block: null };
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    const response = await globalThis.fetch(url, init);
    if (call.method !== "eth_getTransactionReceipt" || !replace.armed) return response;
    const { result } = await response.clone().json();
    if (result) {
      replace.armed = false;
      replace.block = Number(BigInt(result.blockNumber));
      node.reorg(1);
    }
    return response;
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, chain, done } = set;
  try {
    const key = (await vanish(flow, "1")).key;
    node.mineTo(40);
    node.foreignCommits(1);
    node.mineTo(80);
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    const newKey = await flow.claimStart();
    const answers = answersFor(newKey, flow.claimSaved());
    chain.mining = false;
    replace.armed = true;
    await assert.rejects(flow.claimCheck(answers), /no longer holds the transaction/);
    const s = flow.state.summon;
    assert.equal(s.claim.stage, "dropped");
    assert.match(s.claim.dropped, new RegExp(`block ${replace.block} no longer holds the claim, nor does any other block`));
    assert.equal(node.reveals.length, 0);
    assert.equal((await flow.summonRefresh()).status, "unclaimed", "the old key still holds its coin");
    assert.ok(flow.state.summon.current, "and can claim again");
  } finally {
    await done();
  }
});
