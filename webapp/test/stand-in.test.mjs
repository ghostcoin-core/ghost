// The node stand-in refuses the commits the real node refuses: not to the
// commit entry address, data not exactly 190 bytes, a version other than
// 0x0001, in the node's words (`commit data is not 190 bytes of version 1`).
// It accepts the 190-byte payload of spec 07, and a refusal adds no leaf.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { concat, fromHex, toHex, toQuantity } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY } from "../src/flow.mjs";
import { loadModule } from "./support/env.mjs";
import { COMMIT_DATA_ERROR, HEAD_MOVED_ERROR, startFakeNode } from "./support/fake-node.mjs";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const GHOST = 10n ** 18n;
const vector = JSON.parse(await readFile(new URL("./vectors/commit-payload.json", import.meta.url), "utf8"));
const fingerprint = fromHex(vector.fingerprint, 32);
const note = fromHex(vector.note, 156);

async function withNode(check) {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  try {
    await check(node, node.wallet(ACCOUNT));
  } finally {
    await node.close();
  }
}

const send = (wallet, { to = DEFAULT_COMMIT_ENTRY, value = toQuantity(GHOST), data }) =>
  wallet.request({ method: "eth_sendTransaction", params: [{ from: ACCOUNT, to, value, data }] });

const dataError = (err) => err.message === COMMIT_DATA_ERROR;

test("the stand-in refuses the old 189-byte commit of version 0x01", () =>
  withNode(async (node, wallet) => {
    const old = concat([Uint8Array.of(0x01), fingerprint, note]);
    assert.equal(old.length, 189);
    await assert.rejects(send(wallet, { data: toHex(old) }), dataError);
    assert.equal(node.leaves.length, 0);
    assert.equal(node.commits.length, 0);
  }));

test("the stand-in refuses a wrong version and a wrong length", () =>
  withNode(async (node, wallet) => {
    for (const version of [[0x00, 0x02], [0x01, 0x00], [0x00, 0x00], [0x01, 0x01]]) {
      await assert.rejects(send(wallet, { data: toHex(concat([Uint8Array.from(version), fingerprint, note])) }), dataError);
    }
    const right = fromHex(vector.data, 190);
    await assert.rejects(send(wallet, { data: toHex(concat([right, Uint8Array.of(0)])) }), dataError);
    await assert.rejects(send(wallet, { data: toHex(right.slice(0, 189)) }), dataError);
    await assert.rejects(send(wallet, { data: "0x" }), dataError);
    await assert.rejects(send(wallet, { data: null }), dataError);
    await assert.rejects(send(wallet, { data: `${vector.data}0` }), dataError, "not whole bytes of hex");
    assert.equal(node.leaves.length, 0);
    assert.equal(node.commits.length, 0);
  }));

test("the stand-in refuses a commit not to the commit entry address", () =>
  withNode(async (node, wallet) => {
    for (const to of ["0x0000000000000000000000000000000000000000", "0x67686f7374000000000000000000000000000007", null]) {
      await assert.rejects(send(wallet, { to, data: vector.data }), /not the commit entry address/);
    }
    assert.equal(node.leaves.length, 0);
  }));

test("the stand-in refuses an amount it cannot take", () =>
  withNode(async (node, wallet) => {
    for (const value of ["0x0", toQuantity(1n << 96n), "not a number"]) {
      await assert.rejects(send(wallet, { value, data: vector.data }), /commit amount out of range/);
    }
    assert.equal(node.leaves.length, 0);
  }));

test("the stand-in accepts the 190-byte commit of version 0x0001", () =>
  withNode(async (node, wallet) => {
    const hash = await send(wallet, { data: vector.data });
    assert.match(hash, /^0x[0-9a-f]{64}$/);
    assert.equal(node.commits.length, 1);
    assert.equal(node.leaves.length, 1);
    // The leaf is C = K(tag, COIN, F, v) of spec 01, vector coin-commit, and
    // the note is the payload's last 156 bytes.
    assert.equal(toHex(node.leaves[0].commitment), vector.commitment);
    assert.equal(toHex(node.leaves[0].note), vector.note);
  }));

// The stand-in's tree page methods answer in exactly the node's shape
// (ghost-node docs/trees-and-headers.md, "Wallet tree pages") and refuse
// what the node refuses, as JSON-RPC errors in its words.
async function rpcCall(node, method, params) {
  const response = await fetch(node.url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return response.json();
}

const tipHash = (node) => toHex(node.blocks[node.tip()].hash);

test("the stand-in serves page roots as an array and coin pages as { kind, treeIndex, page, filled, entries }", () =>
  withNode(async (node, wallet) => {
    const empty = await rpcCall(node, "ghost_getPageRoots", ["coin", "0x0", tipHash(node)]);
    assert.deepEqual(empty.result, [], "an empty coin tree has no page roots");
    await send(wallet, { data: vector.data });
    node.foreignCommits(1);
    const anchor = tipHash(node);
    const roots = await rpcCall(node, "ghost_getPageRoots", ["coin", "0x0", anchor]);
    assert.ok(Array.isArray(roots.result));
    assert.equal(roots.result.length, 1);
    assert.match(roots.result[0], /^0x[0-9a-f]{64}$/);
    const page = await rpcCall(node, "ghost_getTreePage", ["coin", "0x0", "0x0", anchor]);
    assert.deepEqual(Object.keys(page.result).sort(), ["entries", "filled", "kind", "page", "treeIndex"]);
    assert.equal(page.result.kind, "coin");
    assert.equal(page.result.treeIndex, "0x0");
    assert.equal(page.result.page, "0x0");
    assert.equal(page.result.filled, "0x2");
    assert.deepEqual(page.result.entries[0], { leaf: vector.commitment, note: vector.note });
    assert.deepEqual(Object.keys(page.result.entries[1]).sort(), ["leaf", "note"]);
    const data = await rpcCall(node, "ghost_getPageRoots", ["data", "0x0", anchor]);
    assert.deepEqual(data.result, [], "no data commitment, no data page roots");
    const markers = await rpcCall(node, "ghost_getTreePage", ["coin-markers", "0x0", "0x0", anchor]);
    assert.deepEqual(markers.result, { count: "0x0", markers: [] });
  }));

test("the stand-in refuses the tree page requests the node refuses, in its words", () =>
  withNode(async (node) => {
    const anchor = tipHash(node);
    const unknown = `0x${"ee".repeat(32)}`;
    const refusals = [
      // A wrong number of parameters.
      ["ghost_getPageRoots", ["coin", "0x0"], /missing value for required argument/, -32602],
      ["ghost_getPageRoots", ["coin", "0x0", anchor, "0x0"], /too many arguments/, -32602],
      ["ghost_getTreePage", ["coin", "0x0", anchor], /missing value for required argument/, -32602],
      ["ghost_getTreePage", ["coin", "0x0", "0x0", anchor, "0x0"], /too many arguments/, -32602],
      // An unknown kind.
      ["ghost_getPageRoots", ["coins", "0x0", anchor], /^invalid argument 0: unknown tree kind$/, -32602],
      ["ghost_getTreePage", ["markers", "0x0", "0x0", anchor], /^invalid argument 0: unknown tree kind$/, -32602],
      // An anchor that is not a 32-byte hash: a block number, a tag.
      ["ghost_getPageRoots", ["coin", "0x0", "0x1"], /^invalid argument 2:/, -32602],
      ["ghost_getTreePage", ["coin", "0x0", "0x0", "latest"], /^invalid argument 3:/, -32602],
      // An unknown anchor.
      ["ghost_getPageRoots", ["coin", "0x0", unknown], /^unknown anchor block$/],
      ["ghost_getTreePage", ["coin", "0x0", "0x0", unknown], /^unknown anchor block$/],
      // A page beyond any tree.
      ["ghost_getTreePage", ["coin", "0x0", "0x100000", anchor], /^page number beyond the tree$/],
      ["ghost_getTreePage", ["coin-markers", "0x0", "0x100000", anchor], /^page number beyond the tree$/],
      // A tree index other than 0.
      ["ghost_getPageRoots", ["coin", "0x1", anchor], /^tree index does not exist at the anchor$/],
      ["ghost_getTreePage", ["coin", "0x1", "0x0", anchor], /^tree index does not exist at the anchor$/],
      // Page roots of a marker kind.
      ["ghost_getPageRoots", ["coin-markers", "0x0", anchor], /^invalid argument 0:/, -32602],
      ["ghost_getPageRoots", ["data-markers", "0x0", anchor], /^invalid argument 0:/, -32602],
    ];
    for (const [method, params, words, code] of refusals) {
      const reply = await rpcCall(node, method, params);
      const what = `${method} ${JSON.stringify(params)}`;
      assert.equal(reply.result, undefined, `${what} is refused`);
      assert.match(reply.error.message, words, what);
      if (code !== undefined) assert.equal(reply.error.code, code, what);
    }
    // The last page below the bound is still answered, empty.
    const last = await rpcCall(node, "ghost_getTreePage", ["coin", "0x0", "0xfffff", anchor]);
    assert.equal(last.result.filled, "0x0");
    assert.deepEqual(last.result.entries, []);
  }));

// The head-moving switch refuses only a reveal the stand-in would take: one
// it refuses for what it is still gets that refusal, no block is mined and
// the switch stays armed. (flow.test.mjs sends valid reveals through it.)
test("the stand-in refuses with the head-moving error only a reveal it would take", () =>
  withNode(async (node) => {
    assert.equal(HEAD_MOVED_ERROR, "chain head kept moving while the reveal was checked", "the node's words");
    node.moveHeadOnReveal(2, { blocks: 1 });
    const tip = node.tip();
    const reply = await rpcCall(node, "eth_sendRawTransaction", ["0x50c0"]);
    assert.equal(reply.result, undefined, "a malformed reveal is refused");
    assert.notEqual(reply.error.message, HEAD_MOVED_ERROR);
    assert.equal(node.headMoving.count, 2, "still armed");
    assert.equal(node.headMoving.refused, 0);
    assert.equal(node.tip(), tip, "no block mined");
  }));

// The stand-in's own miner seals blocks on a timer until it is stopped;
// meanwhile a malformed reveal still gets its own refusal.
test("the stand-in's miner moves the head until it is stopped", () =>
  withNode(async (node) => {
    const tip = node.tip();
    node.startMining(2);
    await new Promise((resolve) => setTimeout(resolve, 60));
    const reply = await rpcCall(node, "eth_sendRawTransaction", ["0x50c0"]);
    assert.notEqual(reply.error.message, HEAD_MOVED_ERROR);
    node.stopMining();
    const stopped = node.tip();
    assert.ok(stopped > tip, "blocks were mined");
    assert.equal(node.headMoving.miner, null);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(node.tip(), stopped, "no block after the stop");
  }));

// A miner can also run without refusing sends and put a stranger's commit in
// every few blocks; a transaction lookup finds what a block holds and nothing
// for a hash the node never took.
test("the stand-in's miner can commit as it mines, and a lookup finds only what the node holds", () =>
  withNode(async (node, wallet) => {
    const leaves = node.leaves.length;
    node.startMining(2, { refuse: false, commitEvery: 3 });
    assert.equal(node.headMoving.refuseWhileMining, false);
    await new Promise((resolve) => setTimeout(resolve, 60));
    node.stopMining();
    assert.ok(node.leaves.length > leaves, "the miner committed");
    assert.equal(node.headMoving.refuseWhileMining, true, "a plain restart refuses sends again");
    const hash = await send(wallet, { data: vector.data });
    const found = await rpcCall(node, "eth_getTransactionByHash", [hash]);
    assert.equal(found.result.hash, hash);
    assert.match(found.result.blockNumber, /^0x[0-9a-f]+$/);
    const unknown = await rpcCall(node, "eth_getTransactionByHash", [`0x${"ab".repeat(32)}`]);
    assert.equal(unknown.result, null);
  }));
