// Summon of a coin older than block E - 32 (E: an epoch block) on a quiet
// chain: a coin is committed, a second commitment follows it more than 32
// blocks before E, and no commitment comes in blocks E - 32 to E. E's tree
// holds a leaf after that coin, so E is picked and its reveal goes through.
// A coin no leaf follows is still refused.
//
// First, leafBlock is checked against a copy of choose_tree_state from
// client/src/tree_state.rs, with nothing built. Next, two Summon tests run
// against a stand-in node with a built WebAssembly module, when one exists.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, WaitError, createFlow, leafBlock } from "../src/flow.mjs";
import { loadModule, nodeProver, wasmPath } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const BUILT = existsSync(wasmPath) ? false : `no WebAssembly module built at ${wasmPath}`;

// choose_tree_state for one epoch candidate (tree_state.rs): an epoch block
// 12 deep, above a leaf's block, whose root differs from that block's root.
function chosen({ tip, leafHeight, leafRoot, height, root }) {
  return height % 32 === 0 && height <= tip - 12 && height > leafHeight && toHex(root) !== toHex(leafRoot);
}

// A scan at epoch block `epoch` whose tree holds `count(n)` leaves at block
// n; a tree of c leaves has root bytes all equal to c.
function scanOf(epoch, count) {
  const rootOf = (c) => new Uint8Array(32).fill(c);
  const epochHeaders = [];
  for (let n = epoch - 32; n <= epoch; n += 1) epochHeaders.push({ number: n, coinTreeRoot: rootOf(count(n)) });
  const epochCounts = epochHeaders.map((h) => count(h.number));
  const total = epochCounts[epochCounts.length - 1];
  const prefixRoots = Array.from({ length: total + 1 }, (_, c) => rootOf(c));
  return { epochHeaders, epochCounts, prefixRoots };
}

function ask(scan, epoch, position) {
  const leaf = leafBlock(scan, position);
  if (!leaf) return null;
  return chosen({ tip: epoch + 12, leafHeight: leaf.height, leafRoot: leaf.root, height: epoch, root: scan.epochHeaders.at(-1).coinTreeRoot });
}

test("a leaf older than E - 32, followed by a leaf before E - 32 and none in E - 32 to E, can be revealed", () => {
  // Leaves 0 and 1 by block 3, a coin (2) at block 5, a second commit (3)
  // at block 10, and nothing up to epoch block 64.
  const scan = scanOf(64, (n) => (n >= 10 ? 4 : n >= 5 ? 3 : 2));
  assert.equal(scan.epochCounts[0], scan.epochCounts.at(-1), "no commitment in blocks 32 to 64");
  const leaf = leafBlock(scan, 2);
  assert.equal(leaf.height, 32);
  assert.notEqual(toHex(leaf.root), toHex(scan.epochHeaders.at(-1).coinTreeRoot));
  assert.equal(ask(scan, 64, 2), true, "coin 2 can be revealed");
  assert.equal(ask(scan, 64, 0), true, "so can leaf 0");
});

test("a leaf older than E - 32 that is last in E's tree is refused", () => {
  const scan = scanOf(64, (n) => (n >= 5 ? 3 : 2));
  assert.equal(ask(scan, 64, 2), false);
  assert.equal(ask(scan, 64, 1), true, "leaf 1 is followed by leaf 2");
});

test("a leaf in E - 32 to E keeps its first header's root", () => {
  const scan = scanOf(64, (n) => (n >= 50 ? 4 : n >= 40 ? 3 : 2));
  const leaf = leafBlock(scan, 2);
  assert.equal(leaf.height, 40);
  assert.equal(toHex(leaf.root), toHex(scan.epochHeaders[8].coinTreeRoot));
  assert.equal(ask(scan, 64, 2), true);
  assert.equal(ask(scan, 64, 3), false, "leaf 3, last and added at block 50, is refused");
  assert.equal(leafBlock(scan, 4), null, "leaf 4 is past E's tree");
});

const GHOST = 10n ** 18n;
const ACCOUNT = "0x1111111111111111111111111111111111111111";
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const STILL_MS = 3;
// Epoch block 64 is 12 deep at block 76; its window is blocks 32 to 64.
const EPOCH = 64;
const TIP = EPOCH + 12;

async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const wallet = node.wallet(ACCOUNT);
  const worker = nodeProver();
  const asked = [];
  const prover = {
    request(op, args, onProgress) {
      if (op === "chooseTreeState") asked.push(args);
      return worker.request(op, args, onProgress);
    },
  };
  // While an app waits for a block, its chain grows by one.
  const sleep = async (ms) => {
    if (ms === STILL_MS) return new Promise((resolve) => setTimeout(resolve, ms));
    node.mine();
  };
  const flow = createFlow({ prover, wallet, endpoint: node.url, pollMs: 5, maxPolls: 20, stillMs: STILL_MS, sleep });
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { node, flow, asked, done };
}

async function vanish(flow, amount) {
  const key = await flow.vanishStart(amount);
  const sent = await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]));
  assert.equal(sent.ok, true);
  return key;
}

// Leaf count of coin tree 0 at block `n`.
function countAt(node, n) {
  return node.leaves.filter((l) => l.block <= n).length;
}

test("a coin followed by a commit more than 32 blocks before E can be summoned on a quiet chain", { timeout: 600_000, skip: BUILT }, async () => {
  const { node, flow, asked, done } = await setUp();
  try {
    node.foreignCommits(2);
    const key = await vanish(flow, "25");
    const position = node.leaves.findIndex((l) => toHex(l.commitment) === toHex(node.commits[0].commitment));
    // A second commit, and empty blocks up to block 76.
    node.foreignCommits(1);
    const second = node.leaves[node.leaves.length - 1].block;
    assert.ok(second < EPOCH - 32, "second commitment is older than block E - 32");
    node.mineTo(TIP);
    assert.equal(countAt(node, EPOCH - 32), countAt(node, EPOCH), "no commitment in blocks E - 32 to E");
    assert.ok(countAt(node, EPOCH) > position + 1, "E's tree holds a leaf after coin");

    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    const reveal = await flow.summonReveal({ amount: "1", recipient: RECIPIENT });

    assert.equal(node.reveals.length, 1, "one reveal in a block");
    assert.equal(reveal.block, node.reveals[0].block);
    assert.equal(toHex(node.reveals[0].root), toHex(node.blocks[EPOCH].coinTreeRoot), "proved against E's root");
    assert.equal(node.balances.get(RECIPIENT), GHOST);
    assert.equal(flow.state.error, null);
    const followed = asked.find((a) => a.height === EPOCH && toHex(a.leafRoot) !== toHex(a.root));
    assert.ok(followed, "chooseTreeState saw a leaf root unlike E's root");
  } finally {
    await done();
  }
});

test("a coin older than block E - 32 that no leaf follows is still refused", { timeout: 600_000, skip: BUILT }, async () => {
  const { node, flow, done } = await setUp();
  try {
    node.foreignCommits(2);
    const key = await vanish(flow, "1");
    node.mineTo(TIP);
    const position = node.leaves.findIndex((l) => toHex(l.commitment) === toHex(node.commits[0].commitment));
    assert.equal(countAt(node, EPOCH), position + 1, "coin is last in E's tree");

    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    await assert.rejects(
      flow.summonReveal({ amount: "0.5", recipient: RECIPIENT }),
      (err) => err instanceof WaitError && /^no commitment followed .* before epoch block 64;/.test(err.message),
    );
    assert.equal(node.reveals.length, 0);
  } finally {
    await done();
  }
});
