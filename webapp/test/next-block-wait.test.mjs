// The recovery test's wait past the block in which coin tree 0 filled
// (e2e/fillers.mjs `waitPastBlock`), against a fake node whose head moves on
// a fake clock that sleeps advance.

import assert from "node:assert/strict";
import test from "node:test";

import { waitPastBlock } from "./e2e/fillers.mjs";

// A node at `start` that mines a block every `blockMs` of the fake clock
// (never, when blockMs is null).
function fakeNode({ start, blockMs }) {
  let t = 0;
  const calls = [];
  const head = () => (blockMs === null ? start : start + Math.floor(t / blockMs));
  return {
    now: () => t,
    sleep: async (ms) => {
      t += ms;
    },
    calls,
    head,
    rpc: async (method, params) => {
      calls.push(method);
      assert.equal(method, "eth_blockNumber");
      assert.deepEqual(params, []);
      return `0x${head().toString(16)}`;
    },
  };
}

test("returns only once the head is past the given block, not at it", async () => {
  const node = fakeNode({ start: 10, blockMs: 3000 });
  const head = await waitPastBlock({ rpc: node.rpc, block: 11, pollMs: 500, now: node.now, sleep: node.sleep });
  assert.equal(head, 12);
  assert.equal(node.head(), 12);
  // Head 11 (equal to the block) was seen and waited through.
  assert.ok(node.now() >= 6000, `waited ${node.now()} ms`);
  assert.ok(node.calls.length > 1);
});

test("returns at once when the head is already past", async () => {
  const node = fakeNode({ start: 20, blockMs: 3000 });
  const head = await waitPastBlock({ rpc: node.rpc, block: 7, now: node.now, sleep: node.sleep });
  assert.equal(head, 20);
  assert.equal(node.calls.length, 1);
  assert.equal(node.now(), 0);
});

test("gives up with a clear error after the timeout when the head stays at the block", async () => {
  const node = fakeNode({ start: 5, blockMs: null });
  await assert.rejects(
    waitPastBlock({ rpc: node.rpc, block: 5, pollMs: 500, timeoutMs: 10_000, now: node.now, sleep: node.sleep }),
    (err) => {
      assert.match(err.message, /timed out after 10 s waiting for a block past 5; the head is still 5/);
      return true;
    },
  );
  assert.ok(node.now() >= 10_000 && node.now() < 11_000, `gave up at ${node.now()} ms`);
});

test("refuses a block that is not a whole number", async () => {
  const node = fakeNode({ start: 0, blockMs: 1 });
  await assert.rejects(waitPastBlock({ rpc: node.rpc, block: Number.NaN, now: node.now, sleep: node.sleep }), /block is NaN/);
});
