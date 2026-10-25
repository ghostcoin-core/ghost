// Summon of a coin older than the headers a scan reads (blocks S - 32 to
// the tip, S the settled block 2 below the tip) on a quiet chain: a coin is
// committed, a second commitment follows it more than 32 blocks before S,
// and no commitment comes after. S's tree holds a leaf after that coin, so S
// is picked and its reveal goes through. A coin no leaf follows is still
// refused. (The file keeps its name from the epoch rule this replaced.)
//
// First, leafBlock is checked against a copy of choose_tree_state from
// client/src/tree_state.rs, with nothing built. Next, two Summon tests run
// against a stand-in node with a built WebAssembly module, when one exists.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, WaitError, createFlow, leafBlock } from "../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet, wasmPath } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const BUILT = existsSync(wasmPath) ? false : `no WebAssembly module built at ${wasmPath}`;

// choose_tree_state for one candidate (tree_state.rs): a block 2 deep, above
// a leaf's block, whose root differs from that block's root.
function chosen({ tip, leafHeight, leafRoot, height, root }) {
  return height <= tip - 2 && height > leafHeight && toHex(root) !== toHex(leafRoot);
}

// A scan at settled block `settled` whose tree holds `count(n)` leaves at
// block n; a tree of c leaves has root bytes all equal to c. Only the
// headers of S - 32 to S matter here.
function scanOf(settled, count) {
  const rootOf = (c) => new Uint8Array(32).fill(c);
  const rootHeaders = [];
  for (let n = settled - 32; n <= settled; n += 1) rootHeaders.push({ number: n, coinTreeRoot: rootOf(count(n)) });
  const rootCounts = rootHeaders.map((h) => count(h.number));
  const total = rootCounts[rootCounts.length - 1];
  const prefixRoots = Array.from({ length: total + 1 }, (_, c) => rootOf(c));
  return { rootHeaders, rootCounts, prefixRoots };
}

function ask(scan, settled, position) {
  const leaf = leafBlock(scan, position);
  if (!leaf) return null;
  return chosen({ tip: settled + 2, leafHeight: leaf.height, leafRoot: leaf.root, height: settled, root: scan.rootHeaders.at(-1).coinTreeRoot });
}

test("a leaf older than S - 32, followed by a leaf before S - 32 and none in S - 32 to S, can be revealed", () => {
  // Leaves 0 and 1 by block 3, a coin (2) at block 5, a second commit (3)
  // at block 10, and nothing up to settled block 64.
  const scan = scanOf(64, (n) => (n >= 10 ? 4 : n >= 5 ? 3 : 2));
  assert.equal(scan.rootCounts[0], scan.rootCounts.at(-1), "no commitment in blocks 32 to 64");
  const leaf = leafBlock(scan, 2);
  assert.equal(leaf.height, 32);
  assert.notEqual(toHex(leaf.root), toHex(scan.rootHeaders.at(-1).coinTreeRoot));
  assert.equal(ask(scan, 64, 2), true, "coin 2 can be revealed");
  assert.equal(ask(scan, 64, 0), true, "so can leaf 0");
});

test("a leaf older than S - 32 that is last in S's tree is refused", () => {
  const scan = scanOf(64, (n) => (n >= 5 ? 3 : 2));
  assert.equal(ask(scan, 64, 2), false);
  assert.equal(ask(scan, 64, 1), true, "leaf 1 is followed by leaf 2");
});

test("a leaf in S - 32 to S keeps its first header's root", () => {
  const scan = scanOf(64, (n) => (n >= 50 ? 4 : n >= 40 ? 3 : 2));
  const leaf = leafBlock(scan, 2);
  assert.equal(leaf.height, 40);
  assert.equal(toHex(leaf.root), toHex(scan.rootHeaders[8].coinTreeRoot));
  assert.equal(ask(scan, 64, 2), true);
  assert.equal(ask(scan, 64, 3), false, "leaf 3, last and added at block 50, is refused");
  assert.equal(leafBlock(scan, 4), null, "leaf 4 is past S's tree");
});

const GHOST = 10n ** 18n;
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const RESEND_MS = 3;
// At tip 76 the settled block is 74 and the headers read start at block 42.
const TIP = 76;
const SETTLED = TIP - 2;
const FIRST = SETTLED - 32;

async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
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
    if (ms === RESEND_MS) return new Promise((resolve) => setTimeout(resolve, ms));
    node.mine();
  };
  const flow = createFlow({ prover, endpoint: node.url, networks: node.networks(), pollMs: 5, maxPolls: 20, resendMs: RESEND_MS, sleep });
  await openTestWallet(flow, node);
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

test("a coin followed by a commit more than 32 blocks before S can be summoned on a quiet chain", { timeout: 600_000, skip: BUILT }, async () => {
  const { node, flow, asked, done } = await setUp();
  try {
    node.foreignCommits(2);
    const key = await vanish(flow, "25");
    const position = node.leaves.findIndex((l) => toHex(l.commitment) === toHex(node.commits[0].commitment));
    // A second commit, and empty blocks up to block 76.
    node.foreignCommits(1);
    const second = node.leaves[node.leaves.length - 1].block;
    assert.ok(second < FIRST, "second commitment is older than block S - 32");
    node.mineTo(TIP);
    assert.equal(countAt(node, FIRST), countAt(node, SETTLED), "no commitment in blocks S - 32 to S");
    assert.ok(countAt(node, SETTLED) > position + 1, "S's tree holds a leaf after coin");

    const opened = await flow.summonOpen(key);
    assert.equal(opened.status, "unclaimed");
    assert.deepEqual(opened.cover, { height: SETTLED, covers: countAt(node, SETTLED), total: node.leaves.length });
    assert.equal(opened.wait, null);
    const reveal = await flow.summonReveal({ amount: "1", recipient: RECIPIENT });

    assert.equal(node.reveals.length, 1, "one reveal in a block");
    assert.equal(reveal.block, node.reveals[0].block);
    const root = toHex(node.reveals[0].root);
    assert.ok(
      node.blocks.some((b, n) => n > second && n + 2 <= TIP && toHex(b.coinTreeRoot) === root),
      "proved against a settled root after the second commit",
    );
    assert.equal(node.balances.get(RECIPIENT), GHOST);
    assert.equal(flow.state.error, null);
    const followed = asked.find((a) => toHex(a.leafRoot) !== toHex(a.root));
    assert.ok(followed, "chooseTreeState saw a leaf root unlike S's root");
  } finally {
    await done();
  }
});

test("a coin older than block S - 32 that no leaf follows is still refused", { timeout: 600_000, skip: BUILT }, async () => {
  const { node, flow, done } = await setUp();
  try {
    node.foreignCommits(2);
    const key = await vanish(flow, "1");
    node.mineTo(TIP);
    const position = node.leaves.findIndex((l) => toHex(l.commitment) === toHex(node.commits[0].commitment));
    assert.equal(countAt(node, SETTLED), position + 1, "coin is last in S's tree");

    const opened = await flow.summonOpen(key);
    assert.equal(opened.status, "unclaimed");
    assert.equal(opened.cover, null);
    assert.equal(opened.wait.alone, true, "the app warns that nobody committed since");
    await assert.rejects(
      flow.summonReveal({ amount: "0.5", recipient: RECIPIENT }),
      (err) => err instanceof WaitError && err.alone && /^nobody has committed a coin since this one/.test(err.message),
    );
    assert.equal(node.reveals.length, 0);
  } finally {
    await done();
  }
});
