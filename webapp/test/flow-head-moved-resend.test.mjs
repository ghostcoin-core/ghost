// The flow's reveal against a node whose head keeps moving, continued from
// flow-head-moved.test.mjs: a reveal the endpoint took before it refused,
// new proofs once the fee changed, a node that keeps mining, refusals on
// every send, and refusals that are final.

import assert from "node:assert/strict";
import test from "node:test";

import { HEAD_MOVED_SENDS } from "../src/flow.mjs";
import { PROOFS, RECIPIENT, SPEC_FEE, isRevealSend, setUp } from "./support/flow-setup.mjs";
import { readyToReveal, sendsIn, gethHeadMoved } from "./support/flow-reveal-setup.mjs";

// An endpoint that broadcasts the reveal, waits until its remainder can be
// revealed at another fee and only then answers with the head-moving
// refusal must not get a second payment: a new proof is only ever of the
// first proof's coin, and that coin is spent.
test("a reveal the endpoint took before it answered that the head moved is not paid again from the remainder", async () => {
  let node = null;
  const sends = [];
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (isRevealSend(call)) {
      sends.push(call.params[0]);
      const response = await globalThis.fetch(url, init);
      if (sends.length === 1) {
        assert.equal((await response.json()).error, undefined, "the node took the first send");
        const block = node.reveals[0].block;
        node.setBaseFee(2n * 10n ** 9n);
        node.mineTo(block + 40);
        node.foreignCommits(1);
        node.mineTo(block + 80);
        return new Response(gethHeadMoved(call.id), { status: 200, headers: { "content-type": "application/json" } });
      }
      return response;
    }
    return globalThis.fetch(url, init);
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, work, done } = set;
  try {
    await readyToReveal(node, flow);
    const fromWork = work.length;
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /no longer unspent/);
    assert.equal(sends.length, 1, "nothing is sent again");
    assert.equal(node.reveals.length, 1, "one reveal is in a block");
    assert.equal(node.balances.get(RECIPIENT.toLowerCase()), 25n * 10n ** 16n, "the recipient is paid once");
    assert.deepEqual(
      work.slice(fromWork).filter((w) => w.op === "prove").map((w) => w.decoy),
      [false],
      "the first proof only: the remainder is never proved, and nothing stands in for it",
    );
    assert.match(flow.state.error, /no longer unspent/);
  } finally {
    await done();
  }
});

test("a reveal refused while the head moves is proved again once the fee changed", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    await readyToReveal(node, flow);
    // The blocks that arrive during the node's check open a fee window at a
    // higher base fee: the proof's fee is no longer in force.
    node.setBaseFee(2n * 10n ** 9n);
    node.moveHeadOnReveal(1, { blocks: 4 });
    const from = node.requests.length;
    const fromWork = work.length;
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const sends = sendsIn(node.requests.slice(from));
    assert.equal(sends.length, 2);
    assert.notEqual(sends[0].params[0], sends[1].params[0], "a new envelope");
    assert.deepEqual(work.slice(fromWork).filter((w) => w.op === "prove").map((w) => w.decoy), [false, false]);
    assert.equal(node.reveals.length, 1);
    assert.ok(node.reveals[0].fee > SPEC_FEE, "the reveal carries the raised fee");
  } finally {
    await done();
  }
});

// The CI node seals a block every 20 ms; the app sends one proof up to 5
// times, after one short wait and one look at the tip each time, so a fifth
// send the node takes lands.
test("a reveal the node refuses 4 times while its head moves is taken on its fifth send", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    await readyToReveal(node, flow);
    node.moveHeadOnReveal(4, { blocks: 1 });
    const from = node.requests.length;
    const fromWork = work.length;
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const asked = node.requests.slice(from);
    const sends = sendsIn(asked);
    assert.equal(node.headMoving.refused, 4);
    assert.equal(sends.length, 5, "four refused sends, then the one the node takes");
    assert.equal(new Set(sends.map((r) => r.params[0])).size, 1, "the same envelope each time");
    assert.equal(work.slice(fromWork).filter((w) => w.op === "prove").length, 1, "proved once");
    for (let i = 1; i < sends.length; i += 1) {
      const between = asked.slice(asked.indexOf(sends[i - 1]) + 1, asked.indexOf(sends[i]));
      assert.equal(between.filter((r) => r.method === "eth_blockNumber").length, 1, `one look at the tip before send ${i + 1}`);
    }
    assert.equal(node.reveals.length, 1);
    assert.equal(flow.state.error, null);
  } finally {
    await done();
  }
});

// A node that keeps sealing a block every MINING_MS and refuses the first
// sends: its head never holds still, and the app's reveal is still taken
// while the node mines, without waiting for a still tip. (The page checks
// the seal of every header it adopts, about a quarter of a second each here,
// so the stand-in seals more slowly than that.)
const MINING_MS = 400;
test("a reveal refused while the node keeps mining goes through without its head holding still", async () => {
  let node = null;
  let takenWhileMining = null;
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (isRevealSend(call) && node.headMoving.refused === 0 && !node.headMoving.miner) {
      node.startMining(MINING_MS, { refuse: false });
      node.moveHeadOnReveal(2, { blocks: 1 });
    }
    const mining = node !== null && node.headMoving.miner !== null;
    const response = await globalThis.fetch(url, init);
    if (isRevealSend(call) && !(await response.clone().json()).error) takenWhileMining = mining;
    return response;
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, work, done } = set;
  try {
    await readyToReveal(node, flow);
    const fromWork = work.length;
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(node.headMoving.refused, 2, "refused while the node mined");
    assert.equal(takenWhileMining, true, "taken while the node still mined");
    const proofs = work.slice(fromWork).filter((w) => w.op === "prove");
    assert.ok(proofs.length >= 1 && proofs.length <= PROOFS);
    assert.ok(proofs.every((w) => !w.decoy && w.position === proofs[0].position), "each time of the same coin");
    assert.equal(node.reveals.length, 1);
  } finally {
    node.stopMining();
    await done();
  }
});

test("a reveal refused on every send of every proof while the head keeps moving surfaces the node's refusal", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    await readyToReveal(node, flow);
    node.moveHeadOnReveal(1000, { blocks: 1 });
    const from = node.requests.length;
    const fromWork = work.length;
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /kept moving/);
    const asked = node.requests.slice(from);
    const sends = sendsIn(asked);
    assert.equal(sends.length, HEAD_MOVED_SENDS * PROOFS, "at most 5 sends of each of the proofs");
    assert.equal(node.headMoving.refused, HEAD_MOVED_SENDS * PROOFS);
    assert.equal(asked.at(-1).method, "eth_sendRawTransaction", "nothing is asked after the last refusal");
    const proofs = work.slice(fromWork).filter((w) => w.op === "prove");
    assert.equal(proofs.length, PROOFS, "proved again after each proof's 5 refused sends, up to the bound");
    assert.ok(
      proofs.every((w) => !w.decoy && w.position === proofs[0].position && w.number === proofs[0].number),
      "each time of the same coin",
    );
    for (let p = 0; p < PROOFS; p += 1) {
      const own = sends.slice(p * HEAD_MOVED_SENDS, (p + 1) * HEAD_MOVED_SENDS).map((r) => r.params[0]);
      assert.equal(new Set(own).size, 1, `proof ${p + 1}'s envelope, 5 times`);
      if (p > 0) assert.notEqual(own[0], sends[(p - 1) * HEAD_MOVED_SENDS].params[0], `proof ${p + 1} is a new envelope`);
    }
    assert.equal(node.reveals.length, 0);
    assert.match(flow.state.error, /kept moving/);
  } finally {
    await done();
  }
});

test("any other refusal of a reveal is final", async () => {
  let refusals = 0;
  let askedBefore = null;
  let node = null;
  // An endpoint that refuses each reveal with another -32000 error.
  const fetch = async (url, init) => {
    if (isRevealSend(JSON.parse(init.body))) {
      refusals += 1;
      askedBefore = node.requests.length;
      const error = { code: -32000, message: "chain head moved" };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error }), { status: 200 });
    }
    return globalThis.fetch(url, init);
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, done } = set;
  try {
    await readyToReveal(node, flow);
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => err.message === "chain head moved");
    assert.equal(refusals, 1, "sent once");
    assert.equal(node.requests.length, askedBefore, "nothing is asked after the refusal");
    assert.equal(node.reveals.length, 0);
  } finally {
    await done();
  }
});
