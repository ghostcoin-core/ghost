// A Summon reveal against an endpoint whose tip moves on every poll, as the
// CI node's does at a block about every 20 ms: it never holds still, so a
// flow that waits for a still tip before a resend waits out every poll, sends
// an envelope whose root has fallen far below the tip, and runs out of sends
// and proofs ("chain head kept moving while the reveal was checked").
//
// The reveal must go through without the tip holding still: a resend after
// one short wait and one look at the tip, and a new proof against the settled
// root of the tip by then once the refused proof's root is far below it. A
// node that refuses send after send is tried again for minutes, not seconds;
// the caps on sends per proof, proofs and time hold, and every proof is of
// the first coin.
//
// Nothing is built: the endpoint is the in-process stand-in of
// support/moving-node.mjs and the prover a stub.

import assert from "node:assert/strict";
import test from "node:test";

import { SETTLE_DEPTH } from "../src/chain.mjs";
import { HEAD_MOVED, HEAD_MOVED_MS, HEAD_MOVED_PROOFS, HEAD_MOVED_SENDS, LEAF_WINDOW, STALE_ROOT_DEPTH } from "../src/flow.mjs";
import { flowOn, movingNode } from "./support/moving-node.mjs";

const RECIPIENT = "0x2222222222222222222222222222222222222222";

// The endpoint's requests from the first send on, split at each send.
function between(requests) {
  const first = requests.indexOf("eth_sendRawTransaction");
  const gaps = [];
  let gap = [];
  for (const method of requests.slice(first + 1)) {
    if (method === "eth_sendRawTransaction") {
      gaps.push(gap);
      gap = [];
    } else {
      gap.push(method);
    }
  }
  return gaps;
}

test("a reveal refused while the tip moves on every poll is sent again after one look at the tip, and goes through", async () => {
  const node = movingNode({ step: 1, proveBlocks: 2, refuseFirst: 3 });
  const { flow, stages } = flowOn(node);
  assert.equal((await flow.summonOpen("synthetic test key")).status, "unclaimed");
  const fromRequests = node.requests.length;

  const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

  assert.deepEqual(
    node.sends.map((s) => s.error),
    [HEAD_MOVED, HEAD_MOVED, HEAD_MOVED, null],
    "three refused sends, then the one the node takes",
  );
  assert.equal(node.proofs.length, 1, "proved once: the root stayed near the tip");
  assert.equal(new Set(node.sends.map((s) => s.envelope)).size, 1, "the same envelope each time");
  // No wait for a still tip: one look at the tip between a refusal and the
  // resend, though the tip moved every time.
  for (const [i, gap] of between(node.requests.slice(fromRequests)).entries()) {
    assert.equal(gap.filter((m) => m === "eth_blockNumber").length, 1, `one look at the tip before send ${i + 2}`);
  }
  assert.ok(node.sends.every((s, i) => i === 0 || s.tip > node.sends[i - 1].tip), "the tip moved before every resend");
  assert.ok(!stages.some((s) => /still/.test(s)), "the flow never waits for a still tip");

  assert.equal(node.reveals.length, 1, "one reveal in a block");
  assert.equal(reveal.block, node.reveals[0].block);
  assert.equal(flow.state.error, null);
  assert.equal(flow.state.summon.current.position, node.coins.at(-1).position, "the remainder is the key's coin now");
});

test("a refused proof whose root has fallen far below the moving tip is proved again for the tip, not sent again", async () => {
  // 12 blocks between two looks, as 20 ms blocks over a 250 ms wait.
  const node = movingNode({ step: 12, proveBlocks: 4, refuseFirst: 2 });
  const { flow, waits } = flowOn(node);
  const opened = await flow.summonOpen("synthetic test key");
  const coin = opened.current;

  const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

  assert.equal(node.proofs.length, 2, "proved again once");
  assert.deepEqual(node.sends.map((s) => [s.proof, s.error]), [[0, HEAD_MOVED], [0, HEAD_MOVED], [1, null]]);
  assert.ok(
    node.sends.every((s) => s.depth <= STALE_ROOT_DEPTH),
    `no envelope sent with its root more than ${STALE_ROOT_DEPTH} blocks below the tip (${node.sends.map((s) => s.depth)})`,
  );
  assert.equal(STALE_ROOT_DEPTH, SETTLE_DEPTH + LEAF_WINDOW);
  assert.ok(node.proofs[1].rootHeight > node.sends[1].tip, "the new proof is against the settled root of a later tip");
  assert.ok(
    node.proofs.every((p) => p.number === coin.number && p.position === coin.position && p.amount === coin.amount),
    "every proof is of the first proof's coin",
  );
  assert.equal(waits.filter((ms) => ms === 250).length, 2, "one fixed 250 ms wait before each resend or new proof");

  assert.equal(node.reveals.length, 1, "one reveal in a block, paid once");
  assert.equal(node.reveals[0].proof, 1);
  assert.equal(reveal.block, node.reveals[0].block);
  assert.equal(flow.state.error, null);
});

test("a reveal refused on every send while the tip keeps moving stops at the proof cap, with nothing asked after the last refusal", async () => {
  const node = movingNode({ step: 12, proveBlocks: 4, refuseFirst: Infinity });
  const { flow } = flowOn(node);
  const coin = (await flow.summonOpen("synthetic test key")).current;
  const fromRequests = node.requests.length;

  await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => {
    assert.equal(err.message, HEAD_MOVED);
    return true;
  });

  assert.ok(node.clock.ms < HEAD_MOVED_MS, "the proof cap, not the time bound, ended it");
  assert.equal(node.proofs.length, HEAD_MOVED_PROOFS, `at most ${HEAD_MOVED_PROOFS} proofs`);
  for (let p = 0; p < HEAD_MOVED_PROOFS; p += 1) {
    const own = node.sends.filter((s) => s.proof === p).length;
    assert.ok(own >= 1 && own <= HEAD_MOVED_SENDS, `proof ${p + 1} sent 1 to 5 times (${own})`);
  }
  assert.equal(node.sends.filter((s) => s.proof === HEAD_MOVED_PROOFS - 1).length, HEAD_MOVED_SENDS, "the last proof is sent 5 times");
  assert.ok(node.sends.length <= HEAD_MOVED_SENDS * HEAD_MOVED_PROOFS);
  assert.equal(node.requests.slice(fromRequests).at(-1), "eth_sendRawTransaction", "nothing is asked after the last refusal");
  assert.ok(node.proofs.every((p) => p.number === coin.number && p.position === coin.position), "every proof is of the same coin");
  assert.equal(node.reveals.length, 0);
  assert.equal(flow.state.error, HEAD_MOVED);
});

// The CI node: a block every 20 ms, a proof that takes about 6 s (300
// blocks), and the node's exact refusal on send after send while the reveal
// is otherwise good (it takes any canonical root, however deep). The flow
// must keep going well past a few seconds and a handful of sends.
test("a reveal the node refuses with the head-moving error for 40 sends over minutes, then takes, goes through, paid once", async () => {
  const node = movingNode({ step: 12, proveBlocks: 300, proveMs: 6000, refuseFirst: 40, deepest: Infinity });
  const { flow } = flowOn(node);
  const coin = (await flow.summonOpen("synthetic test key")).current;

  const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

  assert.equal(node.sends.length, 41, "40 refused sends, then the one the node takes");
  assert.ok(node.sends.slice(0, 40).every((s) => s.error === HEAD_MOVED));
  assert.equal(node.sends[40].error, null);
  assert.ok(node.clock.ms > 30_000, `kept going for more than 30 s of refusals (${node.clock.ms} ms)`);
  // A proof's root is hundreds of blocks below the tip by its first refusal,
  // so each refused proof is proved again for the tip by then.
  assert.equal(node.proofs.length, 41);
  assert.ok(node.sends.every((s, i) => s.proof === i), "one send of each proof");
  assert.ok(node.proofs.every((p, i) => i === 0 || p.rootHeight > node.proofs[i - 1].rootHeight), "each proof against a later settled root");
  assert.ok(
    node.proofs.every((p) => p.number === coin.number && p.position === coin.position && p.amount === coin.amount),
    "every proof is of the first proof's coin",
  );
  assert.equal(node.reveals.length, 1, "one reveal in a block, paid once");
  assert.equal(node.reveals[0].proof, 40);
  assert.equal(reveal.block, node.reveals[0].block);
  assert.equal(flow.state.error, null);
});

test("a reveal the node refuses with the head-moving error on every send surfaces the refusal once the generous time bound has passed", async () => {
  const node = movingNode({ step: 12, proveBlocks: 300, proveMs: 6000, refuseFirst: Infinity, deepest: Infinity });
  const { flow } = flowOn(node);
  await flow.summonOpen("synthetic test key");
  const fromRequests = node.requests.length;

  await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => {
    assert.equal(err.message, HEAD_MOVED);
    return true;
  });

  assert.ok(node.clock.ms >= HEAD_MOVED_MS, "not before the time bound");
  assert.ok(node.clock.ms < HEAD_MOVED_MS + 10_000, "soon after it");
  assert.ok(node.proofs.length > 50 && node.proofs.length < HEAD_MOVED_PROOFS);
  for (let p = 0; p < node.proofs.length; p += 1) {
    assert.ok(node.sends.filter((s) => s.proof === p).length <= HEAD_MOVED_SENDS, `proof ${p + 1} sent at most 5 times`);
  }
  assert.equal(node.requests.slice(fromRequests).at(-1), "eth_sendRawTransaction", "nothing is asked after the last refusal");
  assert.equal(node.reveals.length, 0);
});
