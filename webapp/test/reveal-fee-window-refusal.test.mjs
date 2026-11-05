// A Summon reveal against a stand-in whose fee window moves on between the
// app's quote and the send: the node refuses the send with its exact words,
// "reveal fee is not the window fee: have F, want G", as it did in the
// webapp-real-node run that failed. That refusal is a changed fee, not a
// verdict on the reveal: the app counts it as one, quotes the fee again and
// proves again, within the same three attempts as a fee that lapsed while
// proving. The user never sees the refusal.
//
// Nothing is built: the endpoint is the in-process stand-in of
// support/moving-node.mjs and the prover a stub.

import assert from "node:assert/strict";
import test from "node:test";

import { isWindowFeeRefused } from "../src/flow.mjs";
import { buildModuleIfMissing, wasmPath } from "./support/env.mjs";
import { GHOST, flowOn, movingNode } from "./support/moving-node.mjs";

// The stand-in checks receipts with the built module.
buildModuleIfMissing(wasmPath);

const RECIPIENT = "0x2222222222222222222222222222222222222222";
const REFUSAL = /^reveal fee is not the window fee: have \d+, want \d+$/;
const FEE_CHANGED = "the fee changed every time a proof was ready; try again";

// The endpoint's methods asked between send `i` and send `i + 1`.
function afterSend(requests, i) {
  const at = [];
  requests.forEach((method, n) => method === "eth_sendRawTransaction" && at.push(n));
  return requests.slice(at[i] + 1, at[i + 1]);
}

async function summonWith(refuseWindowFee) {
  const node = movingNode({ step: 1, proveBlocks: 2, refuseWindowFee });
  const { flow, stages } = flowOn(node);
  const opened = await flow.summonOpen("synthetic test key");
  assert.equal(opened.status, "unclaimed");
  return { node, flow, stages, coin: opened.current };
}

test("a reveal the node refuses because the fee window moved after the quote is quoted again, proved again and goes through", async () => {
  const { node, flow, stages, coin } = await summonWith(1);

  const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

  assert.equal(node.windowFee.refused, 1, "the node refused one send for its fee window");
  assert.equal(node.sends.length, 2);
  assert.match(node.sends[0].error, REFUSAL, "the first send is refused with the node's words");
  assert.equal(node.sends[1].error, null, "the next send is taken");
  assert.deepEqual(
    node.sends.map((s) => s.proof),
    [0, 1],
    "the refused proof is not sent again: a new proof is made after the refusal",
  );
  assert.equal(node.proofs.length, 2, "proved again once");

  // The fee is quoted again for the tip after the refusal: the tip, its
  // header and the tree are read again before the new proof.
  const between = afterSend(node.requests, 0);
  assert.ok(between.includes("eth_blockNumber"), "the tip is read again after the refusal");
  assert.ok(between.includes("eth_getBlockByNumber"), "the tip's header is read again for the fee");
  assert.ok(between.includes("ghost_getTreePage"), "the coin tree is scanned again for the new proof");
  assert.ok(node.proofs[1].rootHeight > node.proofs[0].rootHeight, "the new proof is for a later tip");
  assert.ok(stages.includes("the fee window changed; proving again with its fee"));

  // Both proofs are of the same coin and spend the same marker; it is paid once.
  assert.ok(
    node.proofs.every((p) => p.number === coin.number && p.position === coin.position && p.amount === coin.amount),
    "every proof is of the first proof's coin",
  );
  assert.equal(new Set(node.proofs.map((p) => p.marker)).size, 1, "one marker across every send");
  assert.equal(node.reveals.length, 1, "one reveal in a block");
  assert.equal(node.reveals[0].proof, 1, "the block holds the new proof's reveal");
  assert.equal(reveal.block, node.reveals[0].block);
  assert.equal(node.balances.get(RECIPIENT), GHOST / 4n, "the recipient is paid exactly once");

  // The user never sees the refusal.
  assert.equal(flow.state.error, null);
  assert.ok(!stages.some((s) => /is not the window fee/.test(s)), "no stage shows the node's refusal");
  assert.equal(flow.state.summon.current.amount, GHOST - GHOST / 4n - node.reveals[0].fee);
});

test("two window fee refusals in a row still fit in the three fee attempts", async () => {
  const { node, flow } = await summonWith(2);

  await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

  assert.equal(node.windowFee.refused, 2);
  assert.deepEqual(
    node.sends.map((s) => [s.proof, s.error === null]),
    [
      [0, false],
      [1, false],
      [2, true],
    ],
  );
  assert.equal(node.reveals.length, 1);
  assert.equal(node.reveals[0].proof, 2);
  assert.equal(flow.state.error, null);
});

test("a node that refuses every send as not the window fee stops at the three fee attempts, without showing its refusal", async () => {
  const { node, flow } = await summonWith(Infinity);

  await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => {
    assert.equal(err.message, FEE_CHANGED);
    return true;
  });

  assert.equal(node.proofs.length, 3, "the three-attempt cap on fee changes holds");
  assert.equal(node.sends.length, 3, "each proof is sent once");
  assert.ok(node.sends.every((s) => REFUSAL.test(s.error)));
  assert.equal(node.reveals.length, 0);
  assert.equal(flow.state.error, FEE_CHANGED);
});

test("the window fee refusal is told by its code and the node's words", () => {
  const words = "reveal fee is not the window fee: have 231994092, want 185595274";
  assert.ok(isWindowFeeRefused({ code: -32000, message: words }));
  assert.ok(isWindowFeeRefused({ code: "-32000", message: words }));
  assert.ok(!isWindowFeeRefused({ code: -32602, message: words }), "another code is another error");
  assert.ok(!isWindowFeeRefused({ code: -32000, message: "marker already spent" }));
  assert.ok(!isWindowFeeRefused(null));
});
