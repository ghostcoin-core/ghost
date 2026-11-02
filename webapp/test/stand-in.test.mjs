// The node stand-in refuses the commits the real node refuses: not to the
// commit entry address, data not 206 bytes of version 0x0002 (the 190-byte
// commit of version 0x0001 among it), in the node's words (`commit data is
// not 206 bytes of version 2: N bytes`). It accepts the salted 206-byte
// payload the app sends, keeps its salt with its leaf and serves it as
// `salt`; a refusal adds no leaf.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, fromHex, toHex, toQuantity, word } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, coinRecord, receiptBytes } from "../src/flow.mjs";
import { loadModule } from "./support/env.mjs";
import { COIN_TREE_ACCOUNT, COMMIT_DATA_ERROR, HEAD_MOVED_ERROR, startFakeNode } from "./support/fake-node.mjs";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const GHOST = 10n ** 18n;
// A synthetic F and note: the stand-in opens no note.
const fingerprint = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
const note = Uint8Array.from({ length: 156 }, (_, i) => i);
const salt = Uint8Array.from({ length: 16 }, (_, i) => 0x10 + i);
// A version 2 payload: F, the salt and the note.
const salted = toHex(concat([Uint8Array.of(0x00, 0x02), fingerprint, salt, note]));
// Another version 2 payload of the same F under another salt.
const otherSalt = Uint8Array.from({ length: 16 }, (_, i) => 0x30 + i);
const salted2 = toHex(concat([Uint8Array.of(0x00, 0x02), fingerprint, otherSalt, note]));
// The 190-byte commit of version 0x0001, made before the salt.
const unsalted = toHex(concat([Uint8Array.of(0x00, 0x01), fingerprint, note]));

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

// The node's words, then the length when the data was read.
const dataError = (err) => err.message === COMMIT_DATA_ERROR || err.message.startsWith(`${COMMIT_DATA_ERROR}: `);

test("the stand-in's refusal is the node's words, with the length", () =>
  withNode(async (_node, wallet) => {
    assert.equal(COMMIT_DATA_ERROR, "commit data is not 206 bytes of version 2");
    await assert.rejects(send(wallet, { data: toHex(new Uint8Array(205)) }), (err) => err.message === `${COMMIT_DATA_ERROR}: 205 bytes`);
  }));

test("the stand-in refuses the old 189-byte commit of version 0x01", () =>
  withNode(async (node, wallet) => {
    const old = concat([Uint8Array.of(0x01), fingerprint, note]);
    assert.equal(old.length, 189);
    await assert.rejects(send(wallet, { data: toHex(old) }), dataError);
    assert.equal(node.leaves.length, 0);
    assert.equal(node.commits.length, 0);
  }));

test("the stand-in refuses the 190-byte commit of version 0x0001", () =>
  withNode(async (node, wallet) => {
    assert.equal(fromHex(unsalted).length, 190);
    await assert.rejects(send(wallet, { data: unsalted }), (err) => err.message === `${COMMIT_DATA_ERROR}: 190 bytes`);
    assert.equal(node.leaves.length, 0, "no leaf");
    assert.equal(node.commits.length, 0);
    // The same F and note with a salt, as version 2, is taken.
    await send(wallet, { data: salted });
    assert.equal(node.leaves.length, 1);
  }));

test("the stand-in refuses a wrong version and a wrong length", () =>
  withNode(async (node, wallet) => {
    // 190 bytes of any version, 206 bytes of any version but 2.
    for (const version of [[0x00, 0x01], [0x00, 0x02], [0x01, 0x00], [0x00, 0x00], [0x01, 0x01]]) {
      await assert.rejects(send(wallet, { data: toHex(concat([Uint8Array.from(version), fingerprint, note])) }), dataError);
    }
    for (const version of [[0x00, 0x01], [0x02, 0x00], [0x00, 0x03], [0x01, 0x02]]) {
      await assert.rejects(send(wallet, { data: toHex(concat([Uint8Array.from(version), fingerprint, salt, note])) }), dataError);
    }
    const rightSalted = fromHex(salted, 206);
    await assert.rejects(send(wallet, { data: toHex(concat([rightSalted, Uint8Array.of(0)])) }), dataError);
    await assert.rejects(send(wallet, { data: toHex(rightSalted.slice(0, 205)) }), dataError);
    await assert.rejects(send(wallet, { data: "0x" }), dataError);
    await assert.rejects(send(wallet, { data: null }), dataError);
    await assert.rejects(send(wallet, { data: `${salted}0` }), dataError, "not whole bytes of hex");
    assert.equal(node.leaves.length, 0);
    assert.equal(node.commits.length, 0);
  }));

test("the stand-in accepts the 206-byte commit of version 0x0002 and keeps its salt with the leaf", () =>
  withNode(async (node, wallet) => {
    await send(wallet, { data: salted });
    assert.equal(node.commits.length, 1);
    assert.equal(node.leaves.length, 1);
    // C = K(tag, COIN_V2, F, v), the note after the salt, the salt kept.
    const ghost = await loadModule();
    assert.equal(toHex(node.leaves[0].commitment), toHex(ghost.coinCommitment(fingerprint, GHOST, 2)));
    assert.equal(toHex(node.leaves[0].note), toHex(note));
    assert.equal(toHex(node.leaves[0].salt), toHex(salt));
    const page = await rpcCall(node, "ghost_getTreePage", ["coin", "0x0", "0x0", tipHash(node)]);
    assert.deepEqual(page.result.entries[0], { leaf: toHex(node.leaves[0].commitment), note: toHex(note), salt: toHex(salt) });
  }));

test("the stand-in refuses a commit not to the commit entry address", () =>
  withNode(async (node, wallet) => {
    for (const to of ["0x0000000000000000000000000000000000000000", "0x67686f7374000000000000000000000000000007", null]) {
      await assert.rejects(send(wallet, { to, data: salted }), /not the commit entry address/);
    }
    assert.equal(node.leaves.length, 0);
  }));

test("the stand-in refuses an amount it cannot take", () =>
  withNode(async (node, wallet) => {
    for (const value of ["0x0", toQuantity(1n << 96n), "not a number"]) {
      await assert.rejects(send(wallet, { value, data: salted }), /commit amount out of range/);
    }
    assert.equal(node.leaves.length, 0);
  }));

// The app reads a commit log of 244 bytes, its salt last; the 228-byte log of
// a commit of version 1, with no salt, is refused like any other length.
test("a version 1 commit log is refused", () => {
  const topics = { commit: toHex(new Uint8Array(32).fill(1)), reveal: toHex(new Uint8Array(32).fill(2)) };
  const head = concat([new Uint8Array(4), Uint8Array.of(0, 0, 0, 3), new Uint8Array(32).fill(7), word(GHOST), note]);
  const log = (data) => ({ succeeded: true, topics: [new Uint8Array(32).fill(1)], data });
  assert.equal(head.length, 228);
  assert.throws(() => coinRecord(log(head), topics), /commit log's data is not its length/);
  const record = coinRecord(log(concat([head, salt])), topics);
  assert.equal(toHex(record.salt), toHex(salt));
  assert.equal(record.position, 3);
  assert.equal(record.v, GHOST);
  assert.equal(toHex(record.note), toHex(note));
  // Any other length is refused too.
  for (const bytes of [concat([head, salt.slice(1)]), concat([head, salt, Uint8Array.of(0)])]) {
    assert.throws(() => coinRecord(log(bytes), topics), /commit log's data is not its length/);
  }
});

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
    await send(wallet, { data: salted });
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
    // Every commit's entry has its 16-byte salt, a stranger's too.
    assert.deepEqual(page.result.entries[0], { leaf: toHex(node.leaves[0].commitment), note: toHex(note), salt: toHex(salt) });
    assert.deepEqual(Object.keys(page.result.entries[1]).sort(), ["leaf", "note", "salt"]);
    assert.match(page.result.entries[1].salt, /^0x[0-9a-f]{32}$/);
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

// The stand-in serves every block's receipts by block hash, as geth's
// eth_getBlockReceipts does, in the node's log layout (as the client library
// reads it), and each header's receiptsRoot is the root of those receipts.
test("the stand-in serves each block's receipts by hash, in the node's log layout, under its header's receiptsRoot", () =>
  withNode(async (node, wallet) => {
    const ghost = await loadModule();
    const topic = (tag) => toHex(ghost.keccak256(concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)])));
    await send(wallet, { data: salted });
    await send(wallet, { data: salted2 });
    node.mine();
    const [first, second] = node.leaves;
    for (const block of node.blocks) {
      const reply = await rpcCall(node, "eth_getBlockReceipts", [toHex(block.hash)]);
      assert.ok(Array.isArray(reply.result));
      assert.equal(reply.result.length, block === node.blocks[first.block] || block === node.blocks[second.block] ? 1 : 0);
      assert.equal(toHex(ghost.receiptsRoot(reply.result.map(receiptBytes))), block.json.receiptsRoot, `block ${block.number}`);
      for (const receipt of reply.result) {
        assert.equal(receipt.blockHash, toHex(block.hash));
        assert.equal(receipt.status, "0x1");
      }
    }
    assert.equal(node.blocks[0].json.receiptsRoot, "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", "genesis: the empty trie");
    // A commit's log: 244 bytes, its salt last.
    const logOf = async (leaf) => (await rpcCall(node, "eth_getBlockReceipts", [toHex(node.blocks[leaf.block].hash)])).result[0].logs;
    for (const [leaf, position, bytes] of [
      [first, 0, 244],
      [second, 1, 244],
    ]) {
      const logs = await logOf(leaf);
      assert.equal(logs.length, 1);
      assert.equal(logs[0].address, COIN_TREE_ACCOUNT);
      assert.deepEqual(logs[0].topics, [topic("ghost/commit-receipt/v1")]);
      const data = fromHex(logs[0].data);
      assert.equal(data.length, bytes);
      assert.equal(toHex(data.slice(0, 8)), toHex(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, position)), "tree 0, its position");
      assert.equal(toHex(data.slice(8, 40)), toHex(leaf.commitment));
      assert.equal(toHex(data.slice(40, 72)), toHex(node.word(GHOST)));
      assert.equal(toHex(data.slice(72, 228)), toHex(leaf.note));
      assert.equal(toHex(data.slice(228)), toHex(leaf.salt));
    }
    // A block the stand-in does not know has no receipts.
    assert.equal((await rpcCall(node, "eth_getBlockReceipts", [`0x${"ee".repeat(32)}`])).result, null);
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

// The stale-envelope switch, likewise, picks no envelope from a malformed
// reveal: it still gets its own refusal and nothing is mined.
test("the stand-in's stale-envelope switch refuses only a reveal it would take", () =>
  withNode(async (node) => {
    node.refuseStaleEnvelope({ blocks: 2 });
    const tip = node.tip();
    const reply = await rpcCall(node, "eth_sendRawTransaction", ["0x50c0"]);
    assert.notEqual(reply.error.message, HEAD_MOVED_ERROR);
    assert.equal(node.headMoving.stale.envelope, null, "no envelope picked yet");
    assert.equal(node.headMoving.stale.refused, 0);
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
    const hash = await send(wallet, { data: salted });
    const found = await rpcCall(node, "eth_getTransactionByHash", [hash]);
    assert.equal(found.result.hash, hash);
    assert.match(found.result.blockNumber, /^0x[0-9a-f]+$/);
    const unknown = await rpcCall(node, "eth_getTransactionByHash", [`0x${"ab".repeat(32)}`]);
    assert.equal(unknown.result, null);
  }));
