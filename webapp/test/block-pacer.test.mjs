// The real-node test's block pacer, offline: a stand-in node whose
// miner_start makes it seal a block every 5 ms until miner_stop, as the
// internal network's node seals as fast as it can while mining. Its blocks
// carry a base fee: by default the same on every block, so the pacer's
// warm-up has nothing to wait for; `baseFee(n)` gives block n's. Its pool
// is empty unless `pending(n)` says how many transactions are pending at
// height n; `sealMs` slows its miner down.

import assert from "node:assert/strict";
import test from "node:test";

import { startBlockPacer } from "./support/block-pacer.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const SEAL_MS = 5;

function fakeNode({ height = 1, baseFee = () => 1000n, pending = () => 0, sealMs = SEAL_MS } = {}) {
  const node = { height, starts: 0, stops: 0, timer: null, startArgs: [], startHeights: [], stopHeights: [] };
  const block = (n) => ({ number: `0x${n.toString(16)}`, baseFeePerGas: `0x${baseFee(n).toString(16)}` });
  const methods = {
    eth_blockNumber: () => `0x${node.height.toString(16)}`,
    eth_getBlockByNumber: ([tag]) => block(tag === "latest" ? node.height : Number(BigInt(tag))),
    eth_mining: () => node.timer !== null,
    txpool_status: () => ({ pending: `0x${pending(node.height).toString(16)}`, queued: "0x0" }),
    miner_start: (params) => {
      node.starts += 1;
      node.startArgs.push(params);
      node.startHeights.push(node.height);
      if (node.timer === null) node.timer = setInterval(() => (node.height += 1), sealMs);
      return null;
    },
    miner_stop: () => {
      node.stops += 1;
      node.stopHeights.push(node.height);
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
  assert.equal((await pacer.warmUp).settled, true, "a settled fee needs no warm-up");
  try {
    while (node.starts < 6) await sleep(5);
  } finally {
    await pacer.stop();
  }
  const elapsed = Date.now() - began;
  const cycles = node.starts;
  const blocks = node.height - 1;

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

// Each block lowers the fee by an eighth, down to `floor`.
function fallingFee(start, floor) {
  const fees = [start];
  return (n) => {
    while (fees.length <= n) {
      const prev = fees[fees.length - 1];
      fees.push(prev - prev / 8n > floor ? prev - prev / 8n : floor);
    }
    return fees[n];
  };
}

test("seals at full speed until the base fee settles", async () => {
  const fee = fallingFee(1_000_000n, 1000n);
  let settledAt = 1;
  while (fee(settledAt) !== fee(settledAt - 1)) settledAt += 1;
  assert.ok(settledAt > 40, `the fee changes on many blocks first: ${settledAt}`);

  const node = fakeNode({ height: 0, baseFee: fee });
  const began = Date.now();
  const pacer = startBlockPacer({ rpc: node.rpc, intervalMs: 60_000 });
  let warm;
  try {
    warm = await pacer.warmUp;
    const warmMs = Date.now() - began;
    // The fee the next proof sees holds still once the warm-up is over.
    const latest = await node.rpc("eth_getBlockByNumber", ["latest", false]);
    const parentTag = `0x${(BigInt(latest.number) - 1n).toString(16)}`;
    const parent = await node.rpc("eth_getBlockByNumber", [parentTag, false]);
    assert.equal(latest.baseFeePerGas, parent.baseFeePerGas, "settled: the latest fee equals its parent's");
    assert.equal(warm.settled, true);
    assert.equal(warm.baseFee, 1000n);
    assert.ok(warm.blocks >= settledAt, `${warm.blocks} blocks sealed in the warm-up`);
    // One unpaced miner run, not one paced cycle (60 s apart here) per block.
    assert.ok(warmMs < 10_000, `the warm-up took ${warmMs} ms`);
    // Then the paced cycles: one more start, after which the pause holds.
    while (node.stops < 2) await sleep(5);
    assert.equal(node.starts, 2);
    assert.equal(node.startHeights[0], 0, "the warm-up starts the miner once, at genesis");
    assert.ok(node.startHeights[1] >= settledAt, `the first paced cycle starts at ${node.startHeights[1]}`);
  } finally {
    await pacer.stop();
  }
  assert.equal(node.stops, node.starts);
  assert.equal(await node.rpc("eth_mining"), false);
});

test("the warm-up gives up at its block bound and the pacer goes on pacing", async () => {
  // A fee that never settles.
  const node = fakeNode({ height: 0, baseFee: (n) => 1_000_000n - BigInt(n) });
  const pacer = startBlockPacer({ rpc: node.rpc, intervalMs: 50, warmUpBlocks: 30 });
  let warm;
  try {
    warm = await pacer.warmUp;
    while (node.starts < 3) await sleep(5);
  } finally {
    await pacer.stop();
  }
  assert.equal(warm.settled, false);
  assert.ok(warm.blocks >= 30 && warm.blocks < 200, `${warm.blocks} blocks in the warm-up`);
  assert.equal(typeof warm.baseFee, "bigint", "the fee it saw is reported");
  assert.equal(node.stops, node.starts);
  assert.equal(await node.rpc("eth_mining"), false);
});

// One paced cycle (the next is 60 s away), from height 1.
async function oneCycle(node) {
  const pacer = startBlockPacer({ rpc: node.rpc, intervalMs: 60_000 });
  const began = Date.now();
  try {
    while (node.stops < 1) await sleep(5);
  } finally {
    await pacer.stop();
  }
  assert.equal(node.starts, 1);
  assert.equal(node.stops, 1);
  assert.equal(await node.rpc("eth_mining"), false, "the miner is stopped after");
  return { blocks: node.stopHeights[0] - node.startHeights[0], ms: Date.now() - began };
}

test("keeps mining while a transaction is pending", async () => {
  // One transaction pending until block 9 includes it; without mining on, a
  // cycle seals a block or two and stops short of it.
  const clearedAt = 9;
  const node = fakeNode({ pending: (n) => (n < clearedAt ? 1 : 0) });
  const { blocks } = await oneCycle(node);
  const stoppedAt = node.stopHeights[0];
  assert.ok(stoppedAt >= clearedAt, `the miner ran until the pool cleared: stopped at ${stoppedAt}`);
  assert.ok(stoppedAt <= clearedAt + 3, `and stopped soon after it cleared: stopped at ${stoppedAt}`);
  assert.ok(blocks <= 23, `never past the cap: ${blocks} blocks in the cycle`);
});

test("a transaction that stays pending holds the miner for at most about 20 blocks", async () => {
  const node = fakeNode({ pending: () => 1 });
  const { blocks } = await oneCycle(node);
  assert.ok(blocks >= 20 && blocks <= 23, `${blocks} blocks in the cycle`);
});

test("a transaction that stays pending holds a slow miner for at most about 5 seconds", async () => {
  const node = fakeNode({ pending: () => 1, sealMs: 400 });
  const { blocks, ms } = await oneCycle(node);
  assert.ok(blocks < 20, `the block cap is not what stopped it: ${blocks} blocks`);
  assert.ok(ms >= 5000 && ms < 7000, `the cycle took ${ms} ms`);
});
