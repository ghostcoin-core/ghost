// Every coin tree index, from tree 0 up to the tip's (spec 05, section 3 and
// section 8, RT-5 and RT-6): the stand-in node is given trees of a few leaves
// (`treeLeaves`), so that it rolls over to tree 1 and 2 as a node of smaller
// trees would. fetchTrees reads each tree in whole pages, checks a full
// earlier tree against its final root in a header and the last against the
// tip's root, asks for no index past the tip's tree, and refuses a page or
// tree that is not the one asked for. The flow follows a commit into a later
// tree, and stops a scan of a rolled-over chain before the key is tried on a
// note: the worker checks only tree 0's notes against the receipts.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { concat, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, LATER_TREES_UNCHECKED, createFlow, fetchTrees } from "../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet, wasmPath, webappDir } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

// The module is built as webapp/README.md's "Test it" builds it, when no
// build is there yet, with the toolchain CI pins.
if (!existsSync(wasmPath)) {
  const env = { ...process.env, RUSTUP_TOOLCHAIN: process.env.RUSTUP_TOOLCHAIN || "1.99.1" };
  if (!env.RUSTUP_HOME && existsSync("/usr/local/rustup")) env.RUSTUP_HOME = "/usr/local/rustup";
  const manifest = resolve(webappDir, "wasm/Cargo.toml");
  execFileSync("cargo", ["build", "--release", "--locked", "--target", "wasm32-unknown-unknown", "--manifest-path", manifest], { env, stdio: "inherit" });
}
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

// The tree requests the stand-in was sent, as [method, tree index, page].
const treeRequests = (node) =>
  node.requests.filter((r) => r.method.startsWith("ghost_")).map((r) => [r.method, r.params[1], ...(r.method === "ghost_getTreePage" ? [r.params[2]] : [])]);

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

test("the flow follows a commit into a later tree, and refuses to scan a rolled-over chain before the key is tried", async () => {
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

        // Its scan reads both trees, then stops: the notes of tree 1 cannot
        // be checked against the receipts, so the key is tried on nothing.
        asked.length = 0;
        fresh.requests.length = 0;
        await assert.rejects(flow2.summonOpen(key), (err) => err.message.includes(LATER_TREES_UNCHECKED) && /rolled over to coin tree 1/.test(err.message));
        assert.ok(!asked.includes("restore"), "no note was tried with the key");
        assert.ok(!asked.includes("receiptsCheck"), "no unchecked note was passed off as checked");
        assert.equal(flow2.state.chainRefused, null, "the chain itself is not refused");
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
