// The recovery test's filler sends (e2e/fillers.mjs) against a fake node
// that, like the real one, refuses a send over 80 signature verifications in
// any second on one connection. Time is a fake clock that sleeps advance.

import assert from "node:assert/strict";
import test from "node:test";

import { FILLER_BATCH, FILLER_BATCH_GAP_MS, sendPaced } from "./e2e/fillers.mjs";

const BUDGET = 80;
const REFUSAL = "signature verification budget exceeded";

function fakeNode({ known = new Set() } = {}) {
  let t = 0;
  const accepted = [];
  const times = [];
  const node = {
    now: () => t,
    sleep: async (ms) => {
      t += ms;
    },
    accepted,
    // Each send takes 1 ms of the fake clock.
    rpc: async (method, [raw]) => {
      assert.equal(method, "eth_sendRawTransaction");
      t += 1;
      const recent = times.filter((at) => at > t - 1000);
      times.length = 0;
      times.push(...recent);
      if (times.length >= BUDGET) throw new Error(`eth_sendRawTransaction: ${REFUSAL}`);
      times.push(t);
      if (known.has(raw)) throw new Error("eth_sendRawTransaction: already known");
      accepted.push(raw);
      return `0xhash${raw}`;
    },
  };
  return node;
}

const sign = (i) => ({ raw: `tx${i}`, hash: `0xhash${i}` });

test("an unpaced burst of 200 is refused at its 81st send, naming the index and the node's message", async () => {
  const node = fakeNode();
  await assert.rejects(
    sendPaced({ rpc: node.rpc, count: 200, sign, batch: 200, gapMs: 0, now: node.now, sleep: node.sleep }),
    (err) => {
      assert.match(err.message, /filler send 80 of 200/);
      assert.match(err.message, new RegExp(REFUSAL));
      return true;
    },
  );
  assert.equal(node.accepted.length, BUDGET);
});

test("the paced helper sends 200 without a refusal", async () => {
  assert.ok(FILLER_BATCH <= 60);
  assert.ok(FILLER_BATCH_GAP_MS >= 1100);
  const node = fakeNode();
  const hashes = await sendPaced({ rpc: node.rpc, count: 200, sign, now: node.now, sleep: node.sleep });
  assert.equal(hashes.length, 200);
  assert.deepEqual(hashes, Array.from({ length: 200 }, (_, i) => `0xhash${i}`));
  assert.deepEqual(node.accepted, Array.from({ length: 200 }, (_, i) => `tx${i}`));
  assert.ok(node.now() >= 3 * FILLER_BATCH_GAP_MS, "four batches, three gaps");
});

test("batches of more than 80 a second are refused even with the gap", async () => {
  const node = fakeNode();
  await assert.rejects(
    sendPaced({ rpc: node.rpc, count: 200, sign, batch: 100, now: node.now, sleep: node.sleep }),
    /filler send 80 of 200 refused/,
  );
});

test("an already known send counts as sent; it is not refused", async () => {
  const node = fakeNode({ known: new Set(["tx3"]) });
  const hashes = await sendPaced({ rpc: node.rpc, count: 5, sign, now: node.now, sleep: node.sleep });
  assert.deepEqual(hashes, ["0xhash0", "0xhash1", "0xhash2", "0xhash3", "0xhash4"]);
});

test("any other send error stops the run with its index", async () => {
  const rpc = async (_method, [raw]) => {
    if (raw === "tx2") throw new Error("eth_sendRawTransaction: nonce too low");
  };
  await assert.rejects(sendPaced({ rpc, count: 5, sign, now: () => 0, sleep: async () => {} }), /filler send 2 of 5 refused: .*nonce too low/);
});
