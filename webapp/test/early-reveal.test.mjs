// No forced wait before a reveal (spec 02, section 8): planReveal proves
// against the root of the block 2 below the tip as soon as that block is at
// or above the coin's block, and reports how many coins that root covers.
// Nobody else has to commit first: the coin's own block's root is used once
// it is 2 deep. Until then it waits with one plain line.
//
// Nothing is built: the prover is a stub whose chooseTreeState is a copy of
// choose_tree_state for one candidate (client/src/tree_state.rs).

import assert from "node:assert/strict";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { SETTLE_DEPTH } from "../src/chain.mjs";
import { LEAF_WINDOW, WaitError, leafBlock, planReveal, settleWait } from "../src/flow.mjs";

const rootOf = (count) => new Uint8Array(32).fill(count);

// choose_tree_state for one candidate: a root SETTLE_DEPTH deep, at or
// above the leaf's block, whatever its root.
function rule({ tip, leafHeight, height }) {
  return height + 2 <= tip && height >= leafHeight;
}

function stubProver() {
  const asked = [];
  return {
    asked,
    async request(op, args) {
      assert.equal(op, "chooseTreeState", "planReveal asks the worker only for the rule");
      asked.push(args);
      return { chosen: rule(args) };
    },
  };
}

// A scan as scanKey makes it at tip `tip`, on a chain whose block n holds
// count(n) coin leaves; a tree of c leaves has root bytes all equal to c,
// and leaf i is the 32 bytes all equal to i + 100.
function scanAt(tip, count) {
  const settled = tip - SETTLE_DEPTH;
  const low = settled < LEAF_WINDOW ? 0 : settled - LEAF_WINDOW;
  const rootHeaders = [];
  for (let n = low; n <= tip; n += 1) rootHeaders.push({ number: n, coinTreeRoot: rootOf(count(n)) });
  const rootCounts = rootHeaders.map((h) => count(h.number));
  const total = count(tip);
  const prefixRoots = Array.from({ length: total + 1 }, (_, c) => rootOf(c));
  const leaves = new Uint8Array(total * 32);
  for (let i = 0; i < total; i += 1) leaves.fill(i + 100, i * 32, i * 32 + 32);
  const settledAt = settled - low;
  return {
    chain: { tip: rootHeaders.at(-1), genesis: { hash: new Uint8Array(32) } },
    tree: { count: total, leaves },
    rootHeaders,
    rootCounts,
    prefixRoots,
    settledAt,
    settledLeaves: leaves.slice(0, rootCounts[settledAt] * 32),
    fee: 7n,
  };
}

// Leaves 0 and 1 at block 3, the holder's coin (leaf 2) at block 50.
const COIN = { position: 2 };
const quiet = (n) => (n >= 50 ? 3 : n >= 3 ? 2 : 0);
// A stranger commits leaf 3 at block 51, the block after the coin.
const followed = (n) => (n >= 51 ? 4 : quiet(n));

test("a coin is revealed against the root 2 blocks below the tip, the newest settled one", async () => {
  assert.equal(SETTLE_DEPTH, 2);
  const prover = stubProver();
  const plan = await planReveal(prover, scanAt(53, followed), COIN);
  assert.equal(plan.height, 51, "block 51, two below tip 53: no epoch block, no 12-block depth");
  assert.equal(toHex(plan.root), toHex(rootOf(4)));
  assert.equal(plan.covers, 4, "the root covers the four coins in block 51's tree");
  assert.equal(plan.leaves.length, 4 * 32, "proved over exactly those leaves");
  assert.equal(plan.fee, 7n);
  assert.equal(prover.asked[0].leafHeight, 50);

  // Later, always the newest settled root, covering every coin by then.
  const more = (n) => (n >= 70 ? 9 : followed(n));
  const later = await planReveal(stubProver(), scanAt(90, more), COIN);
  assert.equal(later.height, 88);
  assert.equal(later.covers, 9);
});

test("a coin nobody committed after is revealed once its own block is 2 deep", async () => {
  for (const tip of [52, 53, 60, 200]) {
    const prover = stubProver();
    const plan = await planReveal(prover, scanAt(tip, quiet), COIN);
    assert.equal(plan.height, tip - 2);
    assert.equal(toHex(plan.root), toHex(rootOf(3)), "the tree that ends with the coin's own block");
    assert.equal(plan.covers, 3, "it covers every coin up to and with this one");
    assert.equal(plan.leaves.length, 3 * 32);
    assert.equal(prover.asked.length, 1);
  }
  // At tip 52 that is the root of the coin's own block, asked for as such.
  const prover = stubProver();
  await planReveal(prover, scanAt(52, quiet), COIN);
  assert.equal(prover.asked[0].height, 50);
  assert.equal(toHex(prover.asked[0].root), toHex(prover.asked[0].leafRoot));
});

test("a coin whose block is not yet 2 deep waits with one plain line naming the block it goes on at", async () => {
  for (const [count, tip] of [
    [quiet, 50],
    [quiet, 51],
    [followed, 51],
  ]) {
    await assert.rejects(planReveal(stubProver(), scanAt(tip, count), COIN), (err) => {
      assert.ok(err instanceof WaitError);
      assert.equal(err.from, 52, "the coin's block 50, 2 deep");
      assert.equal(err.message, settleWait(50));
      assert.match(err.message, /block 50, is not yet 2 blocks deep; the Summon goes on by itself at block 52$/);
      assert.equal(Object.keys(err).includes("alone"), false);
      return true;
    });
  }
  // A coin added in the last two blocks of a long chain, alone, too.
  const fresh = (n) => (n >= 59 ? 3 : 2);
  await assert.rejects(planReveal(stubProver(), scanAt(60, fresh), COIN), (err) => err instanceof WaitError && err.from === 61);
  assert.equal((await planReveal(stubProver(), scanAt(61, fresh), COIN)).height, 59);
});

test("a coin older than the headers read is revealed, followed or not", async () => {
  // The coin at block 5, a stranger at block 10, nothing after: at tip 100
  // the headers start at block 66.
  const old = (n) => (n >= 10 ? 4 : n >= 5 ? 3 : 2);
  const scan = scanAt(100, old);
  assert.equal(scan.rootHeaders[0].number, 66);
  assert.equal(leafBlock(scan, 2).count, 3);
  const plan = await planReveal(stubProver(), scan, COIN);
  assert.equal(plan.height, 98);
  assert.equal(plan.covers, 4);
  // Without the stranger it is revealed too.
  const alone = (n) => (n >= 5 ? 3 : 2);
  const lone = await planReveal(stubProver(), scanAt(100, alone), COIN);
  assert.equal(lone.height, 98);
  assert.equal(lone.covers, 3);
});
