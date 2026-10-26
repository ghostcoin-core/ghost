// Every coin tree index, from tree 0 up to the tip's (spec 05, section 3 and
// section 8, RT-5 and RT-6): the stand-in node is given trees of a few leaves
// (`treeLeaves`), so that it rolls over to tree 1 and 2 as a node of smaller
// trees would. fetchTrees reads each tree in whole pages, checks a full
// earlier tree against its final root in a header and the last against the
// tip's root, asks for no index past the tip's tree, and refuses a page or
// tree that is not the one asked for. The flow follows a commit into a later
// tree, checks every tree's notes, salts and the markers against the block
// receipts, restores a key's coins across trees and proves a coin of a full
// earlier tree against that tree's final root.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, toHex } from "../src/bytes.mjs";
import {
  DEFAULT_COMMIT_ENTRY,
  RECEIPTS_FAILED,
  SMALL_TREE_REVEAL,
  checkTreesAgainstReceipts,
  createFlow,
  fetchTrees,
  keccak256,
  prefixRootsAt,
  treeCheckAt,
  treeRootsAt,
} from "../src/flow.mjs";
import { buildModuleIfMissing, loadModule, nodeProver, openTestWallet, wasmPath } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

// The module is built as webapp/README.md's "Test it" builds it, when no
// build is there yet, with the toolchain CI pins.
buildModuleIfMissing(wasmPath);
const ghost = await loadModule();
const TREE_LEAVES = 3;

// The worker's tree requests over the built module itself, counted.
function treeProver() {
  const ops = [];
  return {
    ops,
    async request(op, args) {
      ops.push(op);
      if (op === "treeCheck") {
        ghost.treeCheck(args);
        return { ok: true };
      }
      if (op === "prefixRoots") return { roots: ghost.prefixRoots(args.leaves, args.from, args.to) };
      throw new Error(`unexpected ${op}`);
    },
  };
}

// JSON-RPC to the stand-in, as the app's client sends it.
function rpcTo(node) {
  let id = 0;
  return {
    async call(method, params) {
      id += 1;
      const reply = await fetch(node.url, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
      const body = await reply.json();
      if (body.error) throw new Error(body.error.message);
      return body.result;
    },
  };
}

// The tree requests the stand-in was sent, as [method, tree index, page]:
// the note bucket reads of a restore are left out.
const treeRequests = (node) =>
  node.requests.filter((r) => r.method.startsWith("ghost_") && r.method !== "ghost_getNoteBucket").map((r) => [r.method, r.params[1], ...(r.method === "ghost_getTreePage" ? [r.params[2]] : [])]);

const tipOf = (node) => node.blocks[node.tip()];
// Whether a header of the stand-in's chain carries `root`.
const inHeaders = (node) => async (root) => node.blocks.some((b) => toHex(b.coinTreeRoot) === toHex(root));
const leavesOf = (list) => concat(list.map((l) => l.commitment));

async function withNode(options, fn) {
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, ...options });
  try {
    return await fn(node);
  } finally {
    await node.close();
  }
}

test("fetchTrees reads every coin tree from tree 0 up to the tip's, each against its own root", async () => {
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    // Seven leaves, one block each: trees 0 and 1 full, tree 2 with one.
    node.foreignCommits(7);
    const prover = treeProver();
    const trees = await fetchTrees(rpcTo(node), prover, tipOf(node), { headerWithRoot: inHeaders(node), treeLeaves: TREE_LEAVES });
    assert.deepEqual(trees.map((t) => [t.treeIndex, t.count]), [[0, 3], [1, 3], [2, 1]]);
    for (const [k, tree] of trees.entries()) {
      assert.equal(toHex(tree.leaves), toHex(leavesOf(node.leaves.slice(3 * k, 3 * k + 3))), `tree ${k}'s leaves`);
      assert.equal(tree.records.length, tree.count * 188);
      assert.equal(tree.salts.length, tree.count);
    }
    // Each full tree's root is the final root in the header of the block
    // that filled it (blocks 3 and 6); the last is the tip's.
    assert.equal(toHex(trees[0].root), toHex(node.blocks[3].coinTreeRoot));
    assert.equal(toHex(trees[1].root), toHex(node.blocks[6].coinTreeRoot));
    assert.equal(toHex(trees[2].root), toHex(tipOf(node).coinTreeRoot));
    assert.notEqual(toHex(trees[0].root), toHex(trees[1].root));
    // Whole pages in order, tree after tree, and no index past the tip's.
    assert.deepEqual(treeRequests(node), [
      ["ghost_getPageRoots", "0x0"],
      ["ghost_getTreePage", "0x0", "0x0"],
      ["ghost_getPageRoots", "0x1"],
      ["ghost_getTreePage", "0x1", "0x0"],
      ["ghost_getPageRoots", "0x2"],
      ["ghost_getTreePage", "0x2", "0x0"],
    ]);
    assert.equal(prover.ops.filter((op) => op === "treeCheck").length, 3, "every tree is checked against its root");
  });
});

test("fetchTrees asks for no tree index past the anchor's tree", async () => {
  // A release-sized tree: one tree, read as fetchTree reads it.
  await withNode({}, async (node) => {
    node.foreignCommits(2);
    const trees = await fetchTrees(rpcTo(node), treeProver(), tipOf(node), { headerWithRoot: inHeaders(node) });
    assert.deepEqual(trees.map((t) => [t.treeIndex, t.count]), [[0, 2]]);
    assert.deepEqual(treeRequests(node), [
      ["ghost_getPageRoots", "0x0"],
      ["ghost_getTreePage", "0x0", "0x0"],
    ]);
  });
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    // Tree 0 just full, nothing in tree 1: the tip's root is tree 0's final
    // root, and the read ends there.
    node.foreignCommits(3);
    let trees = await fetchTrees(rpcTo(node), treeProver(), tipOf(node), { headerWithRoot: inHeaders(node), treeLeaves: TREE_LEAVES });
    assert.deepEqual(trees.map((t) => [t.treeIndex, t.count]), [[0, 3]]);
    assert.ok(treeRequests(node).every(([, index]) => index === "0x0"), "tree 1 is never asked for");
    // As of a block before the rollover, on a chain past it: tree 0 only,
    // as it was then.
    node.foreignCommits(2);
    node.requests.length = 0;
    trees = await fetchTrees(rpcTo(node), treeProver(), node.blocks[2], { headerWithRoot: inHeaders(node), treeLeaves: TREE_LEAVES });
    assert.deepEqual(trees.map((t) => [t.treeIndex, t.count]), [[0, 2]]);
    assert.ok(treeRequests(node).every(([, index]) => index === "0x0"), "tree 1 is never asked for");
  });
});

test("fetchTrees refuses a page or a tree that is not the one asked for", async () => {
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    node.foreignCommits(5);
    const read = () => fetchTrees(rpcTo(node), treeProver(), tipOf(node), { headerWithRoot: inHeaders(node), treeLeaves: TREE_LEAVES });
    assert.equal((await read()).length, 2);

    // Tree 0's page where tree 1's was asked for.
    node.dishonest.page = (p, honest, honestPage, k) => (k === 1 ? honestPage(p, 0) : honest);
    await assert.rejects(read(), /page 0 of coin tree 1 from the endpoint is not the page asked for/);
    // Tree 1's page labelled as tree 1 but with another index in it.
    node.dishonest.page = (p, honest, honestPage, k) => (k === 1 ? { ...honest, treeIndex: "0x0" } : honest);
    await assert.rejects(read(), /page 0 of coin tree 1 from the endpoint is not the page asked for/);
    // Tree 1 with a changed page root.
    node.dishonest.page = null;
    node.dishonest.pageRoots = (roots, k) => (k === 1 ? [toHex(node.blocks[1].coinTreeRoot)] : roots);
    await assert.rejects(read(), /does not give the header's coin root|does not match/);
    node.dishonest.pageRoots = null;

    // Tree 0 cut short at an earlier block's tree, whose root a header does
    // carry: a tree that is not full is the anchor's, so it must give the
    // tip's root, and it does not.
    node.dishonest.pageRoots = (roots, k) => (k === 0 ? [toHex(ghost.treeRoots(node.leaves[0].commitment).pageRoots[0])] : roots);
    node.dishonest.page = (p, honest, honestPage, k) => (k === 0 ? { ...honest, filled: "0x1", entries: honest.entries.slice(0, 1) } : honest);
    await assert.rejects(read(), /header's coin root/);
    // Tree 0 with more leaves than a tree holds.
    node.dishonest.pageRoots = null;
    node.dishonest.page = (p, honest, honestPage, k) => {
      if (k !== 0) return honest;
      const entries = [...honest.entries, honestPage(0, 1).entries[0]];
      return { ...honest, filled: `0x${entries.length.toString(16)}`, entries };
    };
    await assert.rejects(read(), /coin tree 0 from the endpoint holds 4 leaves, more than a tree holds \(3\)/);
    node.dishonest.page = null;
    assert.equal((await read()).length, 2, "the honest trees still read");
  });
});

test("fetchTrees refuses a full tree whose final root no header carries, and a tree served twice", async () => {
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    // One block both fills tree 0 and starts tree 1: no header carries tree
    // 0's final root, so no header proves the tree.
    node.foreignCommits(2);
    node.foreignCommitsInOneBlock(2);
    const read = () => fetchTrees(rpcTo(node), treeProver(), tipOf(node), { headerWithRoot: inHeaders(node), treeLeaves: TREE_LEAVES });
    await assert.rejects(read(), /coin tree 0 from the endpoint is full, but no header of the page's chain carries its final root/);
  });
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    node.foreignCommits(7);
    const read = () => fetchTrees(rpcTo(node), treeProver(), tipOf(node), { headerWithRoot: inHeaders(node), treeLeaves: TREE_LEAVES });
    // Tree 0 served again as tree 1: full, and its root a header's, but the
    // same tree twice.
    const treeZeroRoots = ghost.treeRoots(leavesOf(node.leaves.slice(0, 3))).pageRoots.map(toHex);
    node.dishonest.pageRoots = (roots, k) => (k === 1 ? treeZeroRoots : roots);
    node.dishonest.page = (p, honest, honestPage, k) => (k === 1 ? { ...honestPage(p, 0), treeIndex: "0x1" } : honest);
    await assert.rejects(read(), /coin tree 1 from the endpoint is a tree it served before/);
    // The header check itself: with no header holding a full tree's root,
    // the read stops at that tree.
    node.dishonest.pageRoots = null;
    node.dishonest.page = null;
    const noHeader = fetchTrees(rpcTo(node), treeProver(), tipOf(node), { headerWithRoot: async () => false, treeLeaves: TREE_LEAVES });
    await assert.rejects(noHeader, /coin tree 0 from the endpoint is full, but no header/);
  });
});

test("the flow follows a commit into a later tree, and finds a coin in either tree", async () => {
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    const prover = nodeProver();
    const asked = [];
    const watched = {
      request(op, args, onProgress) {
        asked.push(op);
        return prover.request(op, args, onProgress);
      },
    };
    // Each poll mines a block; once one holds a commit from the pool,
    // `afterPool` can add a stranger's commit after it, so the tip can be in
    // a later tree than the commit.
    let afterPool = () => {};
    const sleep = async () => {
      const pooled = node.pool.entries.length > 0;
      node.mine();
      if (pooled) afterPool();
    };
    try {
      const flow = createFlow({ prover: watched, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep, treeLeaves: TREE_LEAVES });
      await openTestWallet(flow, node);
      const words = (key) => flow.vanishSaved().map((p) => key.split(" ")[p - 1]);

      // A commit that fills tree 0, and a stranger's that starts tree 1
      // before the app looks: the commit is found in the full tree 0.
      node.foreignCommits(2);
      node.pool.on = true;
      afterPool = () => {
        node.pool.on = false;
        node.foreignCommits(1);
        afterPool = () => {};
      };
      let key = await flow.vanishStart("1");
      let sent = await flow.vanishCheck(words(key));
      assert.equal(sent.ok, true);
      assert.equal(node.leaves.length, 4, "tree 0 full and tree 1 started");
      assert.equal(toHex(node.leaves[2].commitment), toHex(node.commits.at(-1).commitment), "the commit filled tree 0");
      assert.equal(flow.state.vanish.stage, "done");

      // A commit at position 0 of tree 1, in the block that started nothing
      // else: its parent's root is tree 0's final root.
      const fresh = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, treeLeaves: TREE_LEAVES });
      try {
        const flow2 = createFlow({ prover: watched, endpoint: fresh.url, networks: fresh.networks(), pollMs: 5, sleep: async () => fresh.mine(), treeLeaves: TREE_LEAVES });
        await openTestWallet(flow2, fresh);
        fresh.foreignCommits(3);
        key = await flow2.vanishStart("1");
        sent = await flow2.vanishCheck(flow2.vanishSaved().map((p) => key.split(" ")[p - 1]));
        assert.equal(sent.ok, true);
        assert.equal(fresh.leaves.length, 4);
        assert.equal(toHex(fresh.leaves[3].commitment), toHex(fresh.commits.at(-1).commitment), "the commit is tree 1's first leaf");

        // Its scan reads both trees, checks both against the receipts here
        // (the worker's check covers tree 0 alone), and tries the key on
        // each tree's notes: the coin is tree 1's first leaf.
        asked.length = 0;
        fresh.requests.length = 0;
        const s = await flow2.summonOpen(key);
        assert.equal(s.status, "unclaimed");
        assert.deepEqual([s.current.treeIndex, s.current.position, s.current.amount], [1, 0, 10n ** 18n]);
        assert.ok(!asked.includes("receiptsCheck"), "the worker's tree 0 check is not asked of a rolled-over chain");
        assert.equal(asked.filter((op) => op === "restore").length, 2, "one restore per tree");
        const firstRestore = asked.indexOf("restore");
        assert.ok(asked.includes("keccak256") && asked.indexOf("keccak256") < firstRestore, "the receipts are read before the key is tried");
        assert.equal(flow2.state.chainRefused, null);
        const indices = new Set(fresh.requests.filter((r) => r.method === "ghost_getPageRoots").map((r) => r.params[1]));
        assert.deepEqual([...indices], ["0x0", "0x1"], "both trees were read, and no other");
      } finally {
        await fresh.close();
      }

      // A chain whose tree 0 is just full, with nothing in tree 1: one tree,
      // so the scan goes on and finds the coin that filled it.
      const full = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, treeLeaves: TREE_LEAVES });
      try {
        const flow3 = createFlow({ prover: watched, endpoint: full.url, networks: full.networks(), pollMs: 5, sleep: async () => full.mine(), treeLeaves: TREE_LEAVES });
        await openTestWallet(flow3, full);
        full.foreignCommits(2);
        key = await flow3.vanishStart("1");
        sent = await flow3.vanishCheck(flow3.vanishSaved().map((p) => key.split(" ")[p - 1]));
        assert.equal(sent.ok, true);
        assert.equal(full.leaves.length, TREE_LEAVES);
        const s = await flow3.summonOpen(key);
        assert.equal(s.status, "unclaimed", "the coin in the full tree 0 is found");
        assert.equal(s.current.position, 2);
      } finally {
        await full.close();
      }
    } finally {
      prover.terminate();
    }
  });
});

test("restore is asked with each tree's own index", async () => {
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    const prover = nodeProver();
    // Every restore request and what the worker answered, as asked.
    const restores = [];
    const watched = {
      async request(op, args, onProgress) {
        const reply = await prover.request(op, args, onProgress);
        if (op === "restore") restores.push({ treeIndex: args.treeIndex, found: reply.found });
        return reply;
      },
    };
    try {
      const flow = createFlow({ prover: watched, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine(), treeLeaves: TREE_LEAVES });
      await openTestWallet(flow, node);
      // Tree 0 filled by strangers; the key's commit is tree 1's first leaf.
      node.foreignCommits(3);
      const key = await flow.vanishStart("1");
      const sent = await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]));
      assert.equal(sent.ok, true);
      assert.equal(node.leaves.length, TREE_LEAVES + 1);

      restores.length = 0;
      const s = await flow.summonOpen(key);
      // One restore per tree, each naming its own tree.
      assert.deepEqual(restores.map((r) => r.treeIndex), [0, 1]);
      // Tree 0 holds none of the key's coins; tree 1's restore reports its
      // coin in tree 1, as the module found it.
      assert.deepEqual(restores[0].found, []);
      assert.deepEqual(restores[1].found.map((c) => [c.treeIndex, c.position]), [[1, 0]]);
      assert.equal(s.status, "unclaimed");
      assert.deepEqual([s.current.treeIndex, s.current.position], [1, 0]);
      assert.deepEqual(s.coins.map((c) => [c.treeIndex, c.position]), [[1, 0]]);
    } finally {
      prover.terminate();
    }
  });
});

// Two leaves per tree: leaf i is 32 bytes of i + 1, its note 156 bytes of
// i + 50 and, beside a commit's leaf, its salt 16 bytes of i + 100; leaf 2
// is a reveal's remainder, with no salt beside it. A record is what a
// receipt's coin tree log appended.
const REMAINDER = 2;
const leafOf = (i) => new Uint8Array(32).fill(i + 1);
const noteOf = (i) => new Uint8Array(156).fill(i + 50);
const saltOf = (i) => (i === REMAINDER ? null : new Uint8Array(16).fill(i + 100));
const treeOfLeaves = (treeIndex, list) => ({
  treeIndex,
  count: list.length,
  records: concat(list.flatMap((i) => [leafOf(i), noteOf(i)])),
  salts: list.map(saltOf),
});
const record = (treeIndex, position, i, marker = null) => ({ treeIndex, position, leaf: leafOf(i), note: noteOf(i), salt: saltOf(i), marker });
const MARKER = new Uint8Array(32).fill(0xaa);

test("checkTreesAgainstReceipts checks every tree, the rollover and the markers against the receipts' records", () => {
  const base = {
    trees: [treeOfLeaves(0, [0, 1]), treeOfLeaves(1, [2])],
    blockRecords: [[], [record(0, 0, 0)], [record(0, 1, 1)], [record(1, 0, 2, MARKER)]],
    start: { treeIndex: 0, count: 0 },
    treeLeaves: 2,
    markerBlocks: 4,
    fromGenesis: true,
    markers: MARKER,
  };
  checkTreesAgainstReceipts(base);
  const check = (change) => () => checkTreesAgainstReceipts({ ...base, ...change });

  // A note, leaf or salt of tree 1 that is not its receipt's.
  const otherNote = { ...treeOfLeaves(1, [2]), records: concat([leafOf(2), noteOf(9)]) };
  assert.throws(check({ trees: [base.trees[0], otherNote] }), /the note at position 0 of coin tree 1 differs from its receipt/);
  assert.throws(check({ trees: [base.trees[0], treeOfLeaves(1, [7])] }), /the leaf at position 0 of coin tree 1 differs/);
  assert.throws(check({ trees: [base.trees[0], { ...treeOfLeaves(1, [2]), salts: [new Uint8Array(16)] }] }), /the salt at position 0 of coin tree 1/);
  // A leaf no receipt holds, one the tree lacks, and a tree not read.
  assert.throws(check({ trees: [base.trees[0], treeOfLeaves(1, [2, 3])] }), /the leaf at position 1 of coin tree 1 is not in the receipts/);
  assert.throws(check({ blockRecords: [...base.blockRecords, [record(1, 1, 3)]] }), /the leaf at position 1 of coin tree 1 is missing/);
  assert.throws(check({ trees: [base.trees[0]] }), /position 0 of coin tree 1, a tree past those read/);
  // The rollover comes after exactly `treeLeaves` leaves, and nothing is
  // skipped or repeated across it.
  assert.throws(check({ treeLeaves: 3 }), /the record of coin tree 1, position 0 is out of sequence/);
  assert.throws(check({ blockRecords: [[], [record(0, 0, 0)], [record(1, 0, 2, MARKER)]] }), /out of sequence/);
  assert.throws(check({ blockRecords: [...base.blockRecords.slice(0, 3), [record(0, 1, 1)], base.blockRecords[3]] }), /out of sequence/);
  // The markers: none missing, invented or out of the blocks they were read at.
  assert.throws(check({ markers: new Uint8Array(0) }), /spent marker 0 is missing/);
  assert.throws(check({ markers: concat([MARKER, MARKER]) }), /spent marker 1 is not in the receipts/);
  assert.throws(check({ markers: new Uint8Array(32).fill(0xbb) }), /spent marker 0 differs from its receipt/);
  assert.throws(check({ markerBlocks: 3 }), /spent marker 0 is not in the receipts/);

  // From a start in tree 1 (a pinned header): tree 0 and the earlier
  // markers no receipt of the chain covers are not compared.
  checkTreesAgainstReceipts({
    ...base,
    trees: [treeOfLeaves(0, [5, 6]), treeOfLeaves(1, [2])],
    blockRecords: [[record(1, 0, 2, MARKER)]],
    start: { treeIndex: 1, count: 0 },
    markerBlocks: 1,
    fromGenesis: false,
    markers: concat([new Uint8Array(32).fill(0xcc), MARKER]),
  });
});

const RECIPIENT = "0x00000000000000000000000000000000000beef1";
const GHOST = 10n ** 18n;

test("a coin of a full earlier tree is revealed against that tree's final root, and restored with its remainder in the next tree", async () => {
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    const prover = nodeProver();
    try {
      const options = { prover, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine(), treeLeaves: TREE_LEAVES };
      const original = createFlow(options);
      await openTestWallet(original, node);
      node.foreignCommits(1);
      const key = await original.vanishStart("1");
      assert.equal((await original.vanishCheck(original.vanishSaved().map((p) => key.split(" ")[p - 1]))).ok, true);
      assert.equal(toHex(node.leaves[1].commitment), toHex(node.commits.at(-1).commitment), "the coin is leaf 1 of tree 0");
      // A stranger fills tree 0 and another starts tree 1.
      node.foreignCommits(2);
      node.mineTo(node.tip() + 2);
      const filled = node.blocks.findIndex((b) => b.leafCount === TREE_LEAVES);

      let s = await original.summonOpen(key);
      assert.equal(s.status, "unclaimed");
      assert.deepEqual([s.current.treeIndex, s.current.position], [0, 1]);
      assert.equal(s.wait, null, "a coin of a full earlier tree needs no wait");
      assert.deepEqual(s.cover, { height: filled, covers: TREE_LEAVES, total: TREE_LEAVES });
      const first = await original.summonReveal({ amount: "0.25", recipient: RECIPIENT });
      const sent = node.reveals.at(-1);
      assert.equal(toHex(sent.root), toHex(node.blocks[filled].coinTreeRoot), "proved against tree 0's final root");
      assert.equal(toHex(node.leaves[4].commitment), toHex(sent.remainder), "the remainder is leaf 1 of tree 1");
      s = original.state.summon;
      assert.deepEqual([s.current.treeIndex, s.current.position, s.current.number], [1, 1, 1n]);
      original.summonClose();

      // A clean device restores the spent coin in tree 0 and the remainder in
      // tree 1 from the key alone.
      const clean = createFlow(options);
      s = await clean.summonOpen(key);
      assert.equal(s.status, "unclaimed");
      assert.deepEqual(
        s.coins.map((c) => [c.treeIndex, c.position, c.number, c.spent]),
        [
          [0, 1, 0n, true],
          [1, 1, 1n, false],
        ],
      );
      assert.equal(s.current.amount, GHOST - GHOST / 4n - first.fee);
      clean.summonClose();

      // Once a later leaf of tree 1 is settled, the remainder is revealed
      // against a settled root of tree 1, and its own remainder starts tree 2.
      node.foreignCommits(1);
      node.mineTo(node.tip() + 2);
      s = await clean.summonOpen(key);
      assert.equal(s.wait, null);
      await clean.summonReveal({ amount: "0.25", recipient: RECIPIENT });
      const second = node.reveals.at(-1);
      assert.notEqual(toHex(second.root), toHex(node.blocks[filled].coinTreeRoot));
      assert.equal(toHex(second.root), toHex(node.blocks[node.blocks.findIndex((b) => b.leafCount === 2 * TREE_LEAVES)].coinTreeRoot));
      assert.equal(node.balances.get(RECIPIENT), GHOST / 2n);
      s = clean.state.summon;
      assert.deepEqual([s.current.treeIndex, s.current.position, s.current.number], [2, 0, 2n]);
      assert.equal(clean.state.chainRefused, null);
    } finally {
      prover.terminate();
    }
  });
});

test("a scan of a rolled-over chain refuses a note or salt the receipts do not show, before the key is tried", async () => {
  await withNode({ treeLeaves: TREE_LEAVES }, async (node) => {
    const prover = nodeProver();
    const asked = [];
    const watched = {
      request(op, args, onProgress) {
        asked.push(op);
        return prover.request(op, args, onProgress);
      },
    };
    try {
      const flow = createFlow({ prover: watched, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine(), treeLeaves: TREE_LEAVES });
      await openTestWallet(flow, node);
      node.foreignCommits(4);
      const key = await flow.vanishStart("1");
      assert.equal((await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]))).ok, true);
      node.mineTo(node.tip() + 2);
      const honest = await flow.summonOpen(key);
      assert.deepEqual([honest.current.treeIndex, honest.current.position], [1, 1], "the honest chain restores the coin at tree 1, position 1");

      // Each change the endpoint makes, by the leaf's index in every tree's
      // leaves in order (tree 1 starts at index 3).
      const changes = [
        [() => (node.dishonest.note = (i, note) => (i === 3 ? noteOf(0) : note)), /the note at position 0 of coin tree 1 differs from its receipt/],
        [() => (node.dishonest.note = (i, note) => (i === 1 ? noteOf(0) : note)), /the note at position 1 of coin tree 0 differs from its receipt/],
        [() => (node.dishonest.salt = (i, salt) => (i === 4 ? null : salt)), /the salt at position 1 of coin tree 1 differs from its receipt/],
      ];
      for (const [change, why] of changes) {
        change();
        asked.length = 0;
        await assert.rejects(flow.summonOpen(key), (err) => err.message.includes(RECEIPTS_FAILED) && why.test(err.message));
        assert.ok(!asked.includes("restore"), `no note was tried with the key (${why})`);
        Object.assign(node.dishonest, { note: null, salt: null, markers: null });
      }
      assert.equal((await flow.summonOpen(key)).status, "unclaimed", "the honest chain still reads");
    } finally {
      prover.terminate();
    }
  });
});

// Trees of 14 levels, as spec 05, RT-1 Part B builds the node for the
// rollover: 16,384 leaves, four pages.
const SMALL_DEPTH = 14;
const SMALL_LEAVES = 2 ** SMALL_DEPTH;
const tagged = (tag) => concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)]);
// `count` leaves, each the module's Keccak-256 of a few bytes.
const someLeaves = (count, seed = 0) => concat(Array.from({ length: count }, (_, i) => ghost.keccak256(Uint8Array.of(seed, i & 0xff, i >> 8))));

test("the page's tree hashing is the module's at 32 levels, and a 14-level root is the level-14 node of the same tree", () => {
  for (const n of [0, 1, 31, 135, 136, 137, 271, 272, 400]) {
    const msg = Uint8Array.from({ length: n }, (_, i) => (i * 7 + 3) & 0xff);
    assert.equal(toHex(keccak256(msg)), toHex(ghost.keccak256(msg)), `Keccak-256 of ${n} bytes`);
  }
  for (const count of [0, 1, 2, 3, 5, 4097]) {
    const leaves = someLeaves(count);
    const module = ghost.treeRoots(leaves);
    const page = treeRootsAt(32, leaves);
    assert.equal(toHex(page.root), toHex(module.root), `the 32-level root of ${count} leaves`);
    assert.deepEqual(page.pageRoots.map(toHex), module.pageRoots.map(toHex));
  }
  const nine = someLeaves(9);
  assert.deepEqual(prefixRootsAt(32, nine, 0, 9).map(toHex), ghost.prefixRoots(nine, 0, 9).map(toHex));
  assert.deepEqual(prefixRootsAt(32, nine, 4, 7).map(toHex), ghost.prefixRoots(nine, 4, 7).map(toHex));

  // A 14-level root, climbed 18 more levels over empty subtrees with the
  // module's own hash, is the module's 32-level root of the same leaves.
  const node = (level, left, right) => ghost.keccak256(concat([tagged("ghost/coin-tree-node/v1"), Uint8Array.of(level), left, right]));
  const z = [ghost.keccak256(tagged("ghost/empty-leaf/v1"))];
  for (let level = 0; level < 32; level += 1) z.push(node(level, z[level], z[level]));
  const full = someLeaves(SMALL_LEAVES, 1);
  for (const leaves of [someLeaves(0), someLeaves(1), nine, someLeaves(4097), full]) {
    let root = treeRootsAt(SMALL_DEPTH, leaves).root;
    assert.notEqual(toHex(root), toHex(ghost.treeRoots(leaves).root), "a 14-level root is not the 32-level one");
    for (let level = SMALL_DEPTH; level < 32; level += 1) root = node(level, root, z[level]);
    assert.equal(toHex(root), toHex(ghost.treeRoots(leaves).root), `${leaves.length / 32} leaves`);
  }
  // Every prefix root is that prefix's root, the full tree's included.
  prefixRootsAt(SMALL_DEPTH, nine, 0, 9).forEach((root, count) => {
    assert.equal(toHex(root), toHex(treeRootsAt(SMALL_DEPTH, nine.slice(0, 32 * count)).root), `prefix of ${count}`);
  });
  const fullRoot = treeRootsAt(SMALL_DEPTH, full);
  assert.equal(toHex(prefixRootsAt(SMALL_DEPTH, full, SMALL_LEAVES, SMALL_LEAVES)[0]), toHex(fullRoot.root));
  assert.throws(() => prefixRootsAt(SMALL_DEPTH, concat([full, nine.slice(0, 32)]), 0, SMALL_LEAVES + 1), /outside the leaves/);

  // The tree check at 14 levels, in the worker's words.
  const pageRoots = concat(fullRoot.pageRoots);
  treeCheckAt(SMALL_DEPTH, { pageRoots, leaves: full, root: fullRoot.root });
  assert.throws(() => treeCheckAt(SMALL_DEPTH, { pageRoots, leaves: full, root: ghost.treeRoots(full).root }), /does not give the header's coin root/);
  const changed = full.slice();
  changed[5] ^= 1;
  assert.throws(() => treeCheckAt(SMALL_DEPTH, { pageRoots, leaves: changed, root: fullRoot.root }), /page 0 does not match its page root/);
  assert.throws(() => treeCheckAt(SMALL_DEPTH, { pageRoots, leaves: full.slice(0, -32), root: fullRoot.root }), /page 3 does not match/);
  assert.throws(() => treeCheckAt(11, { pageRoots, leaves: full, root: fullRoot.root }), /11 levels is not supported/);
  assert.throws(() => createFlow({ treeDepth: SMALL_DEPTH, treeLeaves: SMALL_LEAVES + 1 }), /cannot hold 16385 leaves/);
});

test("on a node of 14-level trees the flow checks, follows and restores across trees with that depth's roots, and proves nothing", async () => {
  await withNode({ treeDepth: SMALL_DEPTH }, async (node) => {
    const prover = nodeProver();
    try {
      const options = { prover, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine(), treeDepth: SMALL_DEPTH };
      const flow = createFlow(options);
      await openTestWallet(flow, node);
      const words = (f, key) => f.vanishSaved().map((p) => key.split(" ")[p - 1]);
      // Strangers' coins in one block, then key KB's coin as tree 0's
      // second to last leaf; one more fills tree 0, the next starts tree 1.
      node.foreignCommitsInOneBlock(SMALL_LEAVES - 2);
      const kb = await flow.vanishStart("1");
      assert.equal((await flow.vanishCheck(words(flow, kb))).ok, true);
      assert.equal(toHex(node.leaves[SMALL_LEAVES - 2].commitment), toHex(node.commits.at(-1).commitment));
      node.foreignCommits(2);
      node.mineTo(node.tip() + 2);

      // The headers carry 14-level roots: tree 0's final root, in the block
      // that filled it, is the page's 14-level root of its leaves.
      const filled = node.blocks.findIndex((b) => b.leafCount === SMALL_LEAVES);
      const treeZero = leavesOf(node.leaves.slice(0, SMALL_LEAVES));
      assert.equal(toHex(node.blocks[filled].coinTreeRoot), toHex(treeRootsAt(SMALL_DEPTH, treeZero).root));
      assert.notEqual(toHex(node.blocks[filled].coinTreeRoot), toHex(ghost.treeRoots(treeZero).root));

      // A device of the release depth refuses those roots.
      const release = createFlow({ ...options, treeDepth: undefined });
      await assert.rejects(release.summonOpen(kb), /does not give the header's coin root/);

      // Told the depth, a device reads both trees and finds KB in the full
      // tree 0, against whose final root it would prove, with no wait.
      let s = await flow.summonOpen(kb);
      assert.equal(s.status, "unclaimed");
      assert.deepEqual([s.current.treeIndex, s.current.position], [0, SMALL_LEAVES - 2]);
      assert.equal(s.wait, null);
      assert.deepEqual(s.cover, { height: filled, covers: SMALL_LEAVES, total: SMALL_LEAVES });
      // The default module's worker proves only against 32-level roots: the
      // reveal is refused before anything is sent. The test-depth module's
      // reveal is test-depth-reveal.test.mjs's.
      await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => err.message === SMALL_TREE_REVEAL);
      assert.equal(node.reveals.length, 0);
      flow.summonClose();

      // Key KA commits into tree 1; a clean device restores it there.
      const ka = await flow.vanishStart("1");
      assert.equal((await flow.vanishCheck(words(flow, ka))).ok, true);
      node.mineTo(node.tip() + 2);
      const clean = createFlow(options);
      s = await clean.summonOpen(ka);
      assert.equal(s.status, "unclaimed");
      assert.deepEqual([s.current.treeIndex, s.current.position, s.current.amount], [1, 1, GHOST]);
      s = await clean.summonOpen(kb);
      assert.deepEqual([s.current.treeIndex, s.current.position], [0, SMALL_LEAVES - 2]);
      assert.equal(clean.state.chainRefused, null);
    } finally {
      prover.terminate();
    }
  });
});
