// The flow's reveal against a node whose head keeps moving: the refusals
// ghost-node gives a reveal it could not check on a head that stayed put,
// and the resends, geth's own reply bytes among them. The tests after these
// are in flow-head-moved-resend.test.mjs; the files are split so each fits
// a CI job.

import assert from "node:assert/strict";
import test from "node:test";

import { RECIPIENT, SPEC_FEE, isRevealSend, setUp } from "./support/flow-setup.mjs";
import { readyToReveal, sendsIn, gethHeadMoved } from "./support/flow-reveal-setup.mjs";

// The node refuses a reveal it could not check on a head that stayed put
// (`chain head kept moving while the reveal was checked`); the app sends it
// again, and only after that refusal asks anything more.
test("a reveal the node refuses while its head keeps moving is sent again, the same envelope at the same fee", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    await readyToReveal(node, flow);
    // A block arrives during each of the node's checks; the fee window
    // stays, so the proof's fee is still the one in force.
    node.moveHeadOnReveal(2, { blocks: 1 });
    const from = node.requests.length;
    const fromWork = work.length;
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const asked = node.requests.slice(from);
    const sends = sendsIn(asked);
    assert.equal(node.headMoving.refused, 2);
    assert.equal(sends.length, 3, "two refused sends, then the one the node takes");
    assert.equal(new Set(sends.map((r) => r.params[0])).size, 1, "the same envelope each time");
    assert.equal(work.slice(fromWork).filter((w) => w.op === "prove").length, 1, "proved once");
    assert.equal(node.reveals.length, 1);
    assert.equal(node.reveals[0].fee, SPEC_FEE);
    assert.ok(reveal.block > 82, "settled after the blocks mined during the refusals");
    // Between two sends: the tip once, after a short wait, then its header
    // and the fee window's.
    const first = asked.indexOf(sends[0]);
    const second = asked.indexOf(sends[1]);
    const between = asked.slice(first + 1, second).map((r) => r.method);
    assert.equal(between[0], "eth_blockNumber", "the tip once");
    assert.ok(between.length > 1 && between.slice(1).every((m) => m === "eth_getBlockByNumber"));
  } finally {
    await done();
  }
});

test("the stand-in refuses a reveal while its head moves with geth's JSON-RPC reply", async () => {
  const replies = [];
  const fetch = async (url, init) => {
    const response = await globalThis.fetch(url, init);
    const call = JSON.parse(init.body);
    if (isRevealSend(call)) {
      replies.push({ id: call.id, status: response.status, text: await response.clone().text() });
    }
    return response;
  };
  const { node, flow, done } = await setUp({ fetch });
  try {
    await readyToReveal(node, flow);
    node.moveHeadOnReveal(1, { blocks: 1 });
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(replies.length, 2);
    assert.equal(replies[0].status, 200);
    assert.deepEqual(JSON.parse(replies[0].text), JSON.parse(gethHeadMoved(replies[0].id)));
    assert.equal(node.reveals.length, 1);
  } finally {
    await done();
  }
});

test("a reveal refused with geth's own reply bytes is sent again", async () => {
  let node = null;
  const sends = [];
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (isRevealSend(call)) {
      sends.push(call.params[0]);
      if (sends.length === 1) {
        // The head moves while geth checks the reveal; the fee window stays.
        node.mine();
        return new Response(gethHeadMoved(call.id), { status: 200, headers: { "content-type": "application/json" } });
      }
    }
    return globalThis.fetch(url, init);
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, done } = set;
  try {
    await readyToReveal(node, flow);
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(sends.length, 2, "the refused send, then the one the node takes");
    assert.equal(sends[0], sends[1], "the same envelope");
    assert.equal(node.reveals.length, 1);
    assert.equal(flow.state.error, null);
  } finally {
    await done();
  }
});
