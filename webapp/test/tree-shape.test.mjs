// The app reads the coin tree in the node's shape (ghost-node
// docs/trees-and-headers.md, "Wallet tree pages"): `ghost_getPageRoots`
// answers a plain array of page roots, and `ghost_getTreePage` a page as
// `{ kind, treeIndex, page, filled, entries: [{ leaf, note, salt? }] }`,
// `salt` beside a commit's leaf, none beside a reveal's remainder. fetchTree
// is fed that JSON exactly, with the real tree check of the built module,
// and refuses anything else.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { concat, fromHex, toHex } from "../src/bytes.mjs";
import { fetchTree } from "../src/flow.mjs";
import { loadModule, wasmPath, webappDir } from "./support/env.mjs";

// The module is built as webapp/README.md's "Test it" builds it, when no
// build is there yet, with the toolchain CI pins.
if (!existsSync(wasmPath)) {
  const env = { ...process.env, RUSTUP_TOOLCHAIN: process.env.RUSTUP_TOOLCHAIN || "1.99.1" };
  if (!env.RUSTUP_HOME && existsSync("/usr/local/rustup")) env.RUSTUP_HOME = "/usr/local/rustup";
  const manifest = resolve(webappDir, "wasm/Cargo.toml");
  execFileSync("cargo", ["build", "--release", "--locked", "--target", "wasm32-unknown-unknown", "--manifest-path", manifest], { env, stdio: "inherit" });
}
const ghost = await loadModule();

// Spec 05, section 11: the one-leaf-pair tree of wasm.test.mjs, its only
// page root and its root, and the root of the empty tree.
const LEAF_A = "0x562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458";
const LEAF_B = "0x93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15";
const PAGE_ROOT = "0x06d032e35a1f30a5773c38d9631f5e4ec069786f4d22131ef0bbba75acf2b717";
const ROOT = "0x142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5";
const EMPTY_ROOT = "0x8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8";
const NOTE_A = `0x${"a1".repeat(156)}`;
const NOTE_B = `0x${"b2".repeat(156)}`;
const ANCHOR_HASH = `0x${"5a".repeat(32)}`;

const anchor = (root = ROOT) => ({ hash: fromHex(ANCHOR_HASH, 32), coinTreeRoot: fromHex(root, 32) });

// The answers as the node's documentation shows them.
const docsPageRoots = () => [PAGE_ROOT];
const docsPage = () => ({
  kind: "coin",
  treeIndex: "0x0",
  page: "0x0",
  filled: "0x2",
  entries: [
    { leaf: LEAF_A, note: NOTE_A },
    { leaf: LEAF_B, note: NOTE_B },
  ],
});

// An endpoint answering `pageRoots` and `pages[p]`, recording each call.
function endpoint(pageRoots, pages) {
  const calls = [];
  return {
    calls,
    async call(method, params) {
      calls.push({ method, params });
      if (method === "ghost_getPageRoots") return pageRoots;
      if (method === "ghost_getTreePage") return pages[Number(BigInt(params[2]))];
      throw new Error(`unexpected ${method}`);
    },
  };
}

// The worker's interface over the built module itself.
const prover = { request: async (op, args) => ghost[op](args) };

test("fetchTree reads the node's page roots and page into the right leaves and notes", async () => {
  const rpc = endpoint(docsPageRoots(), [docsPage()]);
  const tree = await fetchTree(rpc, prover, anchor());
  assert.equal(tree.count, 2);
  assert.equal(toHex(tree.leaves), toHex(concat([fromHex(LEAF_A), fromHex(LEAF_B)])));
  assert.equal(toHex(tree.records), toHex(concat([LEAF_A, NOTE_A, LEAF_B, NOTE_B].map((h) => fromHex(h)))));
  assert.deepEqual(tree.salts, [null, null], "no salt served, none read");
  assert.deepEqual(rpc.calls, [
    { method: "ghost_getPageRoots", params: ["coin", "0x0", ANCHOR_HASH] },
    { method: "ghost_getTreePage", params: ["coin", "0x0", "0x0", ANCHOR_HASH] },
  ]);
});

test("fetchTree reads an empty tree from an empty page-roots array", async () => {
  const rpc = endpoint([], []);
  const tree = await fetchTree(rpc, prover, anchor(EMPTY_ROOT));
  assert.equal(tree.count, 0);
  assert.equal(tree.leaves.length, 0);
  assert.equal(rpc.calls.length, 1, "no page is asked for");
});

test("fetchTree refuses page roots that are not an array", async () => {
  for (const answer of [{ pageRoots: [PAGE_ROOT] }, null, PAGE_ROOT, {}]) {
    await assert.rejects(fetchTree(endpoint(answer, [docsPage()]), prover, anchor()), /page roots are not a list/);
  }
  await assert.rejects(fetchTree(endpoint([PAGE_ROOT.slice(0, -2)], [docsPage()]), prover, anchor()), /expected 32 bytes/);
});

test("fetchTree refuses a page not in the node's shape", async () => {
  const notWhole = /page 0 from the endpoint is not a whole page/;
  const { entries } = docsPage();
  const shapes = [
    // The web app's former shape.
    { count: "0x2", leaves: [LEAF_A, LEAF_B], notes: [NOTE_A, NOTE_B] },
    { ...docsPage(), entries: undefined },
    { ...docsPage(), entries: { 0: entries[0], 1: entries[1], length: 2 } },
  ];
  for (const page of shapes) await assert.rejects(fetchTree(endpoint(docsPageRoots(), [page]), prover, anchor()));
  // `filled` must be a hex quantity.
  for (const filled of [2, "2", undefined]) {
    await assert.rejects(fetchTree(endpoint(docsPageRoots(), [{ ...docsPage(), filled }]), prover, anchor()), /hex quantity/);
  }
  // `filled` is the number of entries.
  for (const filled of ["0x1", "0x3"]) {
    await assert.rejects(fetchTree(endpoint(docsPageRoots(), [{ ...docsPage(), filled }]), prover, anchor()), notWhole);
  }
  await assert.rejects(
    fetchTree(endpoint(docsPageRoots(), [{ ...docsPage(), entries: entries.slice(0, 1) }]), prover, anchor()),
    notWhole,
  );
  // The last page holds 1 to 4,096 leaves.
  await assert.rejects(
    fetchTree(endpoint(docsPageRoots(), [{ ...docsPage(), filled: "0x0", entries: [] }]), prover, anchor()),
    notWhole,
  );
  const over = Array.from({ length: 4097 }, () => entries[0]);
  await assert.rejects(
    fetchTree(endpoint(docsPageRoots(), [{ ...docsPage(), filled: "0x1001", entries: over }]), prover, anchor()),
    notWhole,
  );
  // A page before the last is full.
  await assert.rejects(
    fetchTree(endpoint([PAGE_ROOT, PAGE_ROOT], [docsPage(), docsPage()]), prover, anchor()),
    notWhole,
  );
  // Each leaf and note has its length.
  const short = { ...docsPage(), entries: [entries[0], { leaf: LEAF_B, note: NOTE_B.slice(0, -2) }] };
  await assert.rejects(fetchTree(endpoint(docsPageRoots(), [short]), prover, anchor()), /expected 156 bytes/);
  const noLeaf = { ...docsPage(), entries: [entries[0], { note: NOTE_B }] };
  await assert.rejects(fetchTree(endpoint(docsPageRoots(), [noLeaf]), prover, anchor()), /expected hex bytes/);
});

test("fetchTree reads the optional salt beside a leaf and refuses one that is not 16 bytes", async () => {
  const SALT = `0x${"c3".repeat(16)}`;
  const page = docsPage();
  page.entries[1] = { ...page.entries[1], salt: SALT };
  const tree = await fetchTree(endpoint(docsPageRoots(), [page]), prover, anchor());
  // A reveal's remainder has none; a commit's leaf has its salt. The records
  // stay leaf and note, 188 bytes each.
  assert.deepEqual(tree.salts.map((s) => (s === null ? null : toHex(s))), [null, SALT]);
  assert.equal(tree.records.length, 2 * 188);
  assert.equal(toHex(tree.records), toHex(concat([LEAF_A, NOTE_A, LEAF_B, NOTE_B].map((h) => fromHex(h)))));
  for (const salt of [SALT.slice(0, -2), `${SALT}00`, "0xzz", null, 16, ""]) {
    const bad = docsPage();
    bad.entries[0] = { ...bad.entries[0], salt };
    await assert.rejects(fetchTree(endpoint(docsPageRoots(), [bad]), prover, anchor()), /page 0 from the endpoint is malformed/, String(salt));
  }
});

// Each page must be the one asked for, so none is missing, repeated or out
// of order behind a whole page of the right size.
test("fetchTree refuses a page that is not the one asked for", async () => {
  const notAsked = /page 0 from the endpoint is not the page asked for: a page is missing, repeated or out of order/;
  for (const change of [{ page: "0x1" }, { page: undefined }, { page: "1" }, { treeIndex: "0x1" }, { kind: "data" }, { kind: undefined }]) {
    await assert.rejects(fetchTree(endpoint(docsPageRoots(), [{ ...docsPage(), ...change }]), prover, anchor()), notAsked, JSON.stringify(change));
  }
  // The same page number written with a leading zero is still that page.
  const tree = await fetchTree(endpoint(docsPageRoots(), [{ ...docsPage(), page: "0x00" }]), prover, anchor());
  assert.equal(tree.count, 2);
});

// Tree `k` is asked for by its index, and a page of any other index is
// refused, tree 0's included.
test("fetchTree asks for the tree index given and refuses a page of another", async () => {
  const rpc = endpoint(docsPageRoots(), [{ ...docsPage(), treeIndex: "0x2" }]);
  const tree = await fetchTree(rpc, prover, anchor(), 2);
  assert.equal(tree.count, 2);
  assert.deepEqual(rpc.calls, [
    { method: "ghost_getPageRoots", params: ["coin", "0x2", ANCHOR_HASH] },
    { method: "ghost_getTreePage", params: ["coin", "0x2", "0x0", ANCHOR_HASH] },
  ]);
  const notAsked = /page 0 of coin tree 2 from the endpoint is not the page asked for/;
  for (const treeIndex of ["0x0", "0x1", "0x3", undefined]) {
    await assert.rejects(fetchTree(endpoint(docsPageRoots(), [{ ...docsPage(), treeIndex }]), prover, anchor(), 2), notAsked, String(treeIndex));
  }
});

test("fetchTree checks the page roots and leaves against the anchor's coin root", async () => {
  const changed = docsPage();
  changed.entries[1] = { ...changed.entries[1], leaf: LEAF_B.replace(/5$/, "4") };
  await assert.rejects(fetchTree(endpoint(docsPageRoots(), [changed]), prover, anchor()), /page 0 does not match/);
  await assert.rejects(fetchTree(endpoint(docsPageRoots(), [docsPage()]), prover, anchor(EMPTY_ROOT)), /header's coin root/);
});
