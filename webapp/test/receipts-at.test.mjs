// The receipts of a coin's own block (receipts-at.mjs): the block that
// appended a position, the 8 blocks asked for (the real one and decoys, drawn
// without bias and kept per coin for the page session), the one record at a
// position and its check against the coin's leaf, note and salt. Then, against
// the stand-in (support/fake-node.mjs) with the real module in a worker and the
// whole-chain check stood down, a scan whose coin record is changed, dropped
// or repeated in the receipts of the coin's block is refused after restore.

import assert from "node:assert/strict";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, RECEIPTS_FAILED, createFlow } from "../src/flow.mjs";
import {
  RECEIPT_BLOCKS,
  blockOfPosition,
  checkRecord,
  createBlockSets,
  drawBlocks,
  findRecord,
} from "../src/receipts-at.mjs";
import { loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const random = (n) => crypto.getRandomValues(new Uint8Array(n));

// A random source giving `values` (32-bit integers, big-endian) one per
// 4-byte draw, and counting the draws.
function scripted(values) {
  const source = (n) => {
    assert.equal(n, 4, "4 random bytes a draw");
    assert.ok(source.draws < values.length, "no more scripted values");
    const value = values[source.draws];
    source.draws += 1;
    return Uint8Array.of(value >>> 24, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
  };
  source.draws = 0;
  return source;
}

// A random source that counts its draws.
function counting() {
  const source = (n) => {
    source.draws += 1;
    return random(n);
  };
  source.draws = 0;
  return source;
}

function assertAscendingDistinct(blocks) {
  for (let i = 1; i < blocks.length; i += 1) assert.ok(blocks[i] > blocks[i - 1], `ascending and distinct: ${blocks}`);
}

test("blockOfPosition names the first block whose coin root holds the position, across a tree rollover", () => {
  // Tree 0 holds 8 leaves; block 4 is the first of tree 1.
  const places = [
    { treeIndex: 0, count: 3 },
    { treeIndex: 0, count: 3 },
    { treeIndex: 0, count: 5 },
    { treeIndex: 0, count: 8 },
    { treeIndex: 1, count: 2 },
    { treeIndex: 1, count: 2 },
    { treeIndex: 1, count: 4 },
  ];
  assert.equal(blockOfPosition(places, 0, 0), 0);
  assert.equal(blockOfPosition(places, 0, 2), 0);
  assert.equal(blockOfPosition(places, 0, 3), 2, "not block 1, which added nothing");
  assert.equal(blockOfPosition(places, 0, 4), 2);
  assert.equal(blockOfPosition(places, 0, 5), 3);
  assert.equal(blockOfPosition(places, 0, 7), 3);
  assert.equal(blockOfPosition(places, 1, 0), 4);
  assert.equal(blockOfPosition(places, 1, 1), 4);
  assert.equal(blockOfPosition(places, 1, 2), 6);
  assert.equal(blockOfPosition(places, 1, 3), 6);
  // A block that both filled tree 0 and started tree 1 is past every
  // position of tree 0.
  const rolled = [
    { treeIndex: 0, count: 6 },
    { treeIndex: 1, count: 1 },
  ];
  assert.equal(blockOfPosition(rolled, 0, 5), 0);
  assert.equal(blockOfPosition(rolled, 0, 6), 1);
  assert.equal(blockOfPosition(rolled, 0, 7), 1);
  assert.equal(blockOfPosition(rolled, 1, 0), 1);
});

test("blockOfPosition gives null for a position no block holds yet", () => {
  const places = [
    { treeIndex: 0, count: 3 },
    { treeIndex: 0, count: 8 },
    { treeIndex: 1, count: 2 },
  ];
  assert.equal(blockOfPosition(places, 1, 2), null);
  assert.equal(blockOfPosition(places, 1, 100), null);
  assert.equal(blockOfPosition(places, 2, 0), null);
  assert.equal(blockOfPosition([{ treeIndex: 0, count: 0 }], 0, 0), null, "an empty tree holds nothing");
  assert.equal(blockOfPosition([], 0, 0), null);
});

test("drawBlocks gives 8 distinct blocks in block order with the real block among them", () => {
  assert.equal(RECEIPT_BLOCKS, 8);
  for (let i = 0; i < 200; i += 1) {
    const real = i % 1000;
    const blocks = drawBlocks({ random, total: 1000, real });
    assert.equal(blocks.length, RECEIPT_BLOCKS);
    assertAscendingDistinct(blocks);
    assert.ok(blocks.includes(real), `the real block ${real} is among ${blocks}`);
    assert.ok(blocks.every((b) => Number.isInteger(b) && b >= 0 && b < 1000));
  }
  // Among 9 blocks with block 4 real, each other block is a decoy 7 times in
  // 8: over many draws every one shows up.
  const seen = new Set();
  for (let i = 0; i < 400; i += 1) for (const b of drawBlocks({ random, total: 9, real: 4 })) seen.add(b);
  assert.deepEqual([...seen].sort((a, b) => a - b), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
  // The real block is never drawn as its own decoy.
  const source = scripted([4, 4, 0, 1, 2, 3, 5, 6, 7]);
  assert.deepEqual(drawBlocks({ random: source, total: 20, real: 4 }), [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.throws(() => drawBlocks({ random, total: 5, real: 5 }), /not among/);
});

test("drawBlocks without a real block draws 8 decoys, and takes every block when fewer than 8 exist", () => {
  for (let i = 0; i < 50; i += 1) {
    const blocks = drawBlocks({ random, total: 100, real: null });
    assert.equal(blocks.length, RECEIPT_BLOCKS);
    assertAscendingDistinct(blocks);
  }
  assert.deepEqual(drawBlocks({ random, total: 5, real: null }), [0, 1, 2, 3, 4]);
  assert.deepEqual(drawBlocks({ random, total: 5, real: 3 }), [0, 1, 2, 3, 4]);
  assert.deepEqual(drawBlocks({ random, total: 8, real: null }), [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(drawBlocks({ random, total: 1, real: 0 }), [0]);
  assert.deepEqual(drawBlocks({ random, total: 0, real: null }), []);
  // A repeat draw of a block already taken is drawn again.
  const source = scripted([3, 3, 3, 0, 1, 2, 4, 5, 6, 7]);
  assert.deepEqual(drawBlocks({ random: source, total: 50, real: null }), [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.equal(source.draws, 10);
});

test("drawBlocks rejects random values that would favour the low blocks", () => {
  // Among 10 blocks the largest multiple of 10 that fits in 32 bits is
  // 4294967290: the values from it to 2^32 - 1 would make blocks 0 to 5 more
  // likely, so they are drawn again; 4294967289 is the last value taken.
  const source = scripted([4294967290, 4294967295, 4294967289, 1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(drawBlocks({ random: source, total: 10, real: null }), [1, 2, 3, 4, 5, 6, 7, 9]);
  assert.equal(source.draws, 10, "every scripted value is drawn");
  // With a power of two of blocks no value is rejected.
  const even = scripted([0xffffffff, 0, 1, 2, 3, 4, 5, 6]);
  assert.deepEqual(drawBlocks({ random: even, total: 16, real: null }), [0, 1, 2, 3, 4, 5, 6, 15]);
  assert.equal(even.draws, 8);
});

const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const record = (treeIndex, position, fill, salt = bytes(16, fill + 2)) => ({
  treeIndex,
  position,
  leaf: bytes(32, fill),
  note: bytes(156, fill + 1),
  salt,
  marker: null,
  v: 1n,
});

test("findRecord returns the one record at a tree index and position and refuses none or two", () => {
  const records = [record(0, 6, 1), record(0, 7, 2), record(1, 7, 3)];
  assert.equal(findRecord(records, 0, 7), records[1]);
  assert.equal(findRecord(records, 1, 7), records[2], "the tree index tells two records at one position apart");
  assert.throws(() => findRecord(records, 0, 8), /no record at position 8 of coin tree 0/);
  assert.throws(() => findRecord(records, 2, 7), /no record at position 7 of coin tree 2/);
  assert.throws(() => findRecord([], 0, 0), /no record/);
  assert.throws(() => findRecord([...records, record(0, 7, 4)], 0, 7), /2 records at position 7 of coin tree 0/);
});

test("checkRecord accepts the coin leaf, note and salt and refuses a changed leaf, note or salt", () => {
  const held = record(0, 7, 1);
  const coin = { leaf: bytes(32, 1), note: bytes(156, 2), salt: bytes(16, 3) };
  assert.doesNotThrow(() => checkRecord(held, coin));
  // A salt null on both sides is equal.
  assert.doesNotThrow(() => checkRecord(record(0, 7, 1, null), { ...coin, salt: null }));
  const changed = (b, at) => {
    const out = Uint8Array.from(b);
    out[at] ^= 1;
    return out;
  };
  assert.throws(() => checkRecord(held, { ...coin, leaf: changed(coin.leaf, 31) }), /the leaf at position 7 of coin tree 0 differs/);
  assert.throws(() => checkRecord(held, { ...coin, note: changed(coin.note, 100) }), /the note at position 7 of coin tree 0 differs/);
  assert.throws(() => checkRecord(held, { ...coin, salt: changed(coin.salt, 0) }), /the salt at position 7 of coin tree 0 differs/);
  assert.throws(() => checkRecord(held, { ...coin, salt: null }), /the salt at position 7 of coin tree 0 differs/);
  assert.throws(() => checkRecord(record(0, 7, 1, null), coin), /the salt at position 7 of coin tree 0 differs/);
});

test("the decoy blocks are drawn once per coin and reused on every later scan", () => {
  const source = counting();
  const sets = createBlockSets({ random: source });
  const coin = "7:0:5";
  const first = sets.blocksFor(coin, { first: 0, last: 100, real: 40 });
  assert.equal(first.length, RECEIPT_BLOCKS);
  assertAscendingDistinct(first);
  assert.ok(first.includes(40));
  const drawn = source.draws;
  assert.ok(drawn >= RECEIPT_BLOCKS - 1);
  // Every later scan of the coin, the chain grown or not, asks the same
  // blocks and draws nothing.
  assert.deepEqual(sets.blocksFor(coin, { first: 0, last: 100, real: 40 }), first);
  assert.deepEqual(sets.blocksFor(coin, { first: 0, last: 140, real: 40 }), first);
  assert.equal(source.draws, drawn);
  // Another coin has decoys of its own; a key with no coin keeps its 8.
  const other = sets.blocksFor("7:0:6", { first: 0, last: 140, real: 40 });
  assert.ok(source.draws > drawn);
  assert.ok(other.includes(40));
  const none = sets.blocksFor("7:none", { first: 0, last: 140, real: null });
  assert.equal(none.length, RECEIPT_BLOCKS);
  const afterNone = source.draws;
  assert.deepEqual(sets.blocksFor("7:none", { first: 0, last: 300, real: null }), none);
  assert.equal(source.draws, afterNone);
  // A stored decoy above the tip (a shorter chain after a reorganisation) is
  // drawn again; the others stay.
  const reorg = createBlockSets({ random: scripted([90, 5, 6, 7, 8, 9, 10, 11, 1, 2]) });
  const before = reorg.blocksFor(coin, { first: 0, last: 100, real: 40 });
  assert.deepEqual(before, [5, 6, 7, 8, 9, 10, 40, 90]);
  assert.deepEqual(reorg.blocksFor(coin, { first: 0, last: 50, real: 40 }), [5, 6, 7, 8, 9, 10, 11, 40]);
  assert.deepEqual(reorg.blocksFor(coin, { first: 0, last: 100, real: 40 }), [5, 6, 7, 8, 9, 10, 11, 40], "kept from then on");
  // The blocks lie between the chain's start and the tip; a short chain is
  // asked whole.
  const pinned = sets.blocksFor("9:0:1", { first: 1000, last: 1200, real: 1100 });
  assert.ok(pinned.every((n) => n >= 1000 && n <= 1200));
  assert.ok(pinned.includes(1100));
  assert.deepEqual(sets.blocksFor("9:none", { first: 1000, last: 1004, real: null }), [1000, 1001, 1002, 1003, 1004]);
  assert.deepEqual(sets.blocksFor("9:none", { first: 1000, last: 1020, real: null }).slice(0, 5), [1000, 1001, 1002, 1003, 1004]);
  assert.throws(() => sets.blocksFor("9:0:2", { first: 1000, last: 1200, real: 1201 }), /not between/);
});

// --- Against the stand-in ---

const answersFor = (key, positions) => positions.map((p) => key.split(" ")[p - 1]);

// A flow with its own worker on `node`. With `standDown`, the worker's
// whole-chain steps (receiptsAdd, receiptsCheck) answer without checking, so
// only the check of the coin's own block stands between a changed receipt
// and the key's coins.
function freshFlow(node, { standDown = false } = {}) {
  const worker = nodeProver();
  const ops = [];
  const prover = {
    request(op, args, onProgress) {
      ops.push(op);
      if (standDown && (op === "receiptsAdd" || op === "receiptsCheck")) return Promise.resolve({});
      return worker.request(op, args, onProgress);
    },
  };
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks: node.networks(),
    pollMs: 5,
    maxPolls: 20,
    sleep: async () => node.mine(),
  });
  return { flow, ops, close: () => worker.terminate() };
}

async function chainWithCoin() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  node.foreignCommits(2);
  const { flow, close } = freshFlow(node);
  try {
    await openTestWallet(flow, node);
    const key = await flow.vanishStart("1");
    assert.equal((await flow.vanishCheck(answersFor(key, flow.vanishSaved()))).ok, true);
    const position = node.leaves.findIndex((l) => toHex(l.commitment) === toHex(node.commits[0].commitment));
    node.foreignCommits(2);
    node.mineTo(node.tip() + 3);
    return { node, key, position };
  } finally {
    close();
  }
}

async function openOnFreshPage(node, key, options) {
  const { flow, ops, close } = freshFlow(node, options);
  const from = node.requests.length;
  try {
    const outcome = await flow.summonOpen(key).then(
      (s) => ({ status: s.status }),
      (err) => ({ error: err.message }),
    );
    return { outcome, ops, requests: node.requests.slice(from) };
  } finally {
    close();
  }
}

test("a coin record changed, dropped or repeated in its own block's receipts is refused after restore", async () => {
  const { node, key, position } = await chainWithCoin();
  try {
    const block = node.leaves[position].block;
    const honest = await openOnFreshPage(node, key, { standDown: true });
    assert.deepEqual(honest.outcome, { status: "unclaimed" });
    assert.deepEqual(
      honest.requests.filter((r) => r.method === "eth_getBlockReceipts").map((r) => r.params),
      node.blocks.map((b) => [toHex(b.hash)]),
      "an honest scan asks each block's receipts once: the coin's block and its decoys are already held",
    );
    const refusedAfterRestore = (opened, detail) => {
      assert.ok(opened.outcome.error, `refused, not ${JSON.stringify(opened.outcome)}`);
      assert.ok(opened.outcome.error.startsWith(RECEIPTS_FAILED), opened.outcome.error);
      assert.match(opened.outcome.error, detail);
      assert.ok(opened.ops.includes("restore"), "the coin was found first");
      assert.ok(!opened.ops.includes("prove"), "nothing is proved");
      assert.ok(!opened.requests.some((r) => r.method === "eth_sendRawTransaction"), "nothing is sent");
    };
    // The key's note changed in its commit log.
    node.dishonest.receipts = (number, list) => {
      if (number !== block) return list;
      const data = list[0].logs[0].data;
      const at = 2 + 2 * 120;
      list[0].logs[0].data = `${data.slice(0, at)}${data[at] === "0" ? "1" : "0"}${data.slice(at + 1)}`;
      return list;
    };
    refusedAfterRestore(
      await openOnFreshPage(node, key, { standDown: true }),
      new RegExp(`the note at position ${position} of coin tree 0 differs from its receipt`),
    );
    // The key's commit dropped from its block.
    node.dishonest.receipts = (number, list) => (number === block ? [] : list);
    refusedAfterRestore(await openOnFreshPage(node, key, { standDown: true }), new RegExp(`no record at position ${position} of coin tree 0`));
    // The key's commit served twice.
    node.dishonest.receipts = (number, list) => (number === block ? [...list, ...list] : list);
    refusedAfterRestore(await openOnFreshPage(node, key, { standDown: true }), new RegExp(`2 records at position ${position} of coin tree 0`));
    // A stranger's record changed is not this check's: the whole-chain check
    // covers it.
    const stranger = node.leaves.findIndex((l, i) => i !== position && l.block !== block);
    const strangerBlock = node.leaves[stranger].block;
    node.dishonest.receipts = (number, list) => (number === strangerBlock ? [] : list);
    assert.deepEqual((await openOnFreshPage(node, key, { standDown: true })).outcome, { status: "unclaimed" });
    node.dishonest.receipts = null;
    assert.deepEqual((await openOnFreshPage(node, key)).outcome, { status: "unclaimed" });
  } finally {
    await node.close();
  }
});
