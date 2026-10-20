// A Summon reveal against a stand-in that plays the CI node as it refused
// on main: the tip moving on with every look, and every send of the first
// proof's envelope refused with the head-moving error, the resends of that
// same envelope included. Resending one envelope never gets the reveal
// through there; a new proof for the tip by then does.
//
// When the proof takes as long as the real one (hundreds of 20 ms blocks),
// the refused proof's root is far below the tip by its first refusal, so the
// app proves again then instead of sending the same envelope up to 5 times.
// When the proof is quick, the envelope is sent its 5 times first.
//
// The Summon must succeed with a reveal whose envelope differs from the
// refused one, the recipient paid once, and every proof made of the first
// proof's input coin, never of another coin, with one marker across every
// send.
//
// Nothing is built: the endpoint is the in-process stand-in of
// support/moving-node.mjs and the prover a stub.

import assert from "node:assert/strict";
import test from "node:test";

import { HEAD_MOVED, HEAD_MOVED_PROOFS, HEAD_MOVED_SENDS, STALE_ROOT_DEPTH } from "../src/flow.mjs";
import { GHOST, flowOn, movingNode } from "./support/moving-node.mjs";

const RECIPIENT = "0x2222222222222222222222222222222222222222";

async function summonAgainstStaleEnvelope({ step, proveBlocks }) {
  // Only the stale envelope is refused; any other is taken however deep its
  // root, as on main a new proof was.
  const node = movingNode({ step, proveBlocks, refuseEnvelope: true, deepest: Infinity });
  const { flow } = flowOn(node);
  const opened = await flow.summonOpen("synthetic test key");
  assert.equal(opened.status, "unclaimed");
  const coin = opened.current;

  const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

  const { stale } = node;
  assert.ok(stale.envelope, "the node refused an envelope");
  const refused = node.sends.filter((s) => s.error !== null);
  assert.ok(refused.every((s) => s.error === HEAD_MOVED && s.envelope === stale.envelope), "only the first envelope is refused");
  assert.equal(stale.refused, refused.length);
  const landed = node.sends.at(-1);
  assert.equal(landed.error, null, "the last send is taken");
  assert.notEqual(landed.envelope, stale.envelope, "the reveal that lands is a different proof from the refused one");
  assert.ok(landed.tip > refused[0].tip, "proved again after the tip moved on");

  // The reveal is in a block, settled, and paid once.
  assert.equal(node.reveals.length, 1, "one reveal in a block");
  assert.equal(node.reveals[0].hash, String(reveal.txHash).toLowerCase(), "the block holds the fresh proof's reveal");
  assert.equal(reveal.block, node.reveals[0].block);
  assert.equal(node.balances.get(RECIPIENT), GHOST / 4n, "the recipient is paid exactly once");

  // Every proof is of the first input coin, and every envelope spends the
  // same marker.
  assert.ok(node.proofs.length >= 2 && node.proofs.length <= HEAD_MOVED_PROOFS, `proved again, within the bound (${node.proofs.length} proofs)`);
  assert.ok(
    node.proofs.every((p) => p.number === coin.number && p.position === coin.position && p.amount === coin.amount),
    "every proof is of the first input coin",
  );
  assert.equal(new Set(node.proofs.map((p) => p.marker)).size, 1, "one marker across every send");

  assert.equal(flow.state.error, null);
  assert.equal(flow.state.summon.current.amount, GHOST - GHOST / 4n - node.reveals[0].fee);
  return { node, refused };
}

test("a Summon whose first proof the node refuses on every send is proved again and goes through, from the first coin only", async () => {
  // About 6 s of 20 ms blocks while the worker proves, 12 between two looks.
  const { node, refused } = await summonAgainstStaleEnvelope({ step: 12, proveBlocks: 300 });
  assert.ok(refused[0].depth > STALE_ROOT_DEPTH, "the first proof's root was far below the tip when it was sent");
  assert.equal(refused.length, 1, "a root that far behind is proved again after one refusal, not sent again");
  assert.equal(node.proofs.length, 2);
});

test("a Summon whose quick first proof the node refuses on all 5 sends is proved again and goes through", async () => {
  const { node, refused } = await summonAgainstStaleEnvelope({ step: 1, proveBlocks: 2 });
  assert.equal(refused.length, HEAD_MOVED_SENDS, "every send of the first proof refused, at most 5 of them");
  assert.ok(refused.every((s) => s.depth <= STALE_ROOT_DEPTH), "sent again only while its root was near the tip");
  assert.equal(node.proofs.length, 2);
});
