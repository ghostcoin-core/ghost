// The real-node test's block pacer, offline: a stand-in node whose
// miner_start makes it seal a block every 5 ms until miner_stop, as the
// internal network's node seals as fast as it can while mining.

import assert from "node:assert/strict";
import test from "node:test";

import { startBlockPacer } from "./support/block-pacer.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const SEAL_MS = 5;

function fakeNode() {
  const node = { height: 0, starts: 0, stops: 0, timer: null, startArgs: [] };
  const methods = {
    eth_blockNumber: () => `0x${node.height.toString(16)}`,
    eth_mining: () => node.timer !== null,
    miner_start: (params) => {
      node.starts += 1;
      node.startArgs.push(params);
      if (node.timer === null) node.timer = setInterval(() => (node.height += 1), SEAL_MS);
      return null;
    },
    miner_stop: () => {
      node.stops += 1;
      clearInterval(node.timer);
      node.timer = null;
      return null;
    },
  };
  node.rpc = async (method, params = []) => {
    if (!methods[method]) throw new Error(`the fake node has no ${method}`);
    return methods[method](params);
  };
  return node;
}

test("the pacer seals about one block per cycle and leaves the miner stopped", async () => {
  const node = fakeNode();
  const began = Date.now();
  const pacer = startBlockPacer({ rpc: node.rpc, intervalMs: 50 });
  try {
    while (node.starts < 6) await sleep(5);
  } finally {
    await pacer.stop();
  }
  const elapsed = Date.now() - began;
  const cycles = node.starts;
  const blocks = node.height;

  assert.equal(node.stops, node.starts, "every miner_start is followed by a miner_stop");
  assert.ok(node.startArgs.every((params) => params.length === 1 && params[0] === 1), "1 thread");
  assert.ok(blocks >= cycles, `at least one block per cycle: ${blocks} blocks in ${cycles} cycles`);
  assert.ok(blocks <= 3 * cycles, `a few blocks per cycle at most: ${blocks} blocks in ${cycles} cycles`);
  const unpaced = Math.floor(elapsed / SEAL_MS);
  assert.ok(blocks * 2 < unpaced, `far fewer than an unpaced miner: ${blocks} blocks against ${unpaced} in ${elapsed} ms`);

  // Stopped: not mining, and nothing more is sealed.
  assert.equal(await node.rpc("eth_mining"), false);
  const after = node.height;
  await sleep(100);
  assert.equal(node.height, after, "no block after stop()");
  assert.equal(node.starts, cycles, "no cycle after stop()");
});

test("stop() during the pause ends the loop at once", async () => {
  const node = fakeNode();
  const pacer = startBlockPacer({ rpc: node.rpc, intervalMs: 60_000 });
  while (node.stops < 1) await sleep(5);
  const began = Date.now();
  await pacer.stop();
  assert.ok(Date.now() - began < 1000, "not held up by the 60-second pause");
  assert.equal(node.starts, 1);
  assert.equal(node.stops, 1);
  assert.equal(await node.rpc("eth_mining"), false);
});
