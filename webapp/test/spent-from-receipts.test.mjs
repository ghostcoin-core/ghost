// The app takes a scan's spent markers from the reveal logs of the block
// receipts it has just checked against each block's receiptsRoot (spec 05,
// section 8, "Marker status"), never from the endpoint's marker pages.
// Against the stand-in (support/fake-node.mjs, which serves real receipts in
// the node's log layout), with the real module in a worker: a scan asks for
// no marker page; a marker list the endpoint hides or invents changes
// neither the requests nor the result; a fully claimed key shows claimed;
// and heldMarkers, which picks the markers out of the receipts' records.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow, heldMarkers } from "../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const RECIPIENT = "0x2222222222222222222222222222222222222222";

const answersFor = (key, positions) => positions.map((p) => key.split(" ")[p - 1]);

// A flow with its own worker on `node`, recording the worker's requests.
function freshFlow(node) {
  const worker = nodeProver();
  const ops = [];
  const prover = {
    request(op, args, onProgress) {
      ops.push(op);
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

// A stand-in whose tree holds strangers' coins around the key's coin, and
// the key; `position` is the key's leaf.
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
    return { ghost, node, key, position };
  } finally {
    close();
  }
}

// The endpoint's requests as (method, params), with no JSON-RPC id.
const seen = (node, from) => node.requests.slice(from).map((r) => JSON.stringify([r.method, r.params]));

// Opens `key` on a fresh page: what the endpoint saw, the worker's steps and
// the outcome, with the coins it shows and which of them are spent.
async function openOnFreshPage(node, key) {
  const { flow, ops, close } = freshFlow(node);
  const from = node.requests.length;
  try {
    const outcome = await flow.summonOpen(key).then(
      (s) => ({
        status: s.status,
        current: s.current && { number: s.current.number, amount: s.current.amount },
        coins: s.coins.map(({ number, amount, spent }) => ({ number, amount, spent })),
      }),
      (err) => ({ error: err.message }),
    );
    return { outcome, requests: seen(node, from), ops, state: flow.state };
  } finally {
    close();
  }
}

const isMarkerPage = (request) => request.startsWith('["ghost_getTreePage",["coin-markers"');

// A key whose coin a partial reveal has spent, with its remainder unspent.
async function chainWithPartialReveal() {
  const { node, key } = await chainWithCoin();
  const { flow, close } = freshFlow(node);
  try {
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(node.spent.length, 1);
    node.mineTo(node.tip() + 3);
    return { node, key, marker: toHex(node.spent[0].marker) };
  } finally {
    close();
  }
}

test("a scan never asks the endpoint for a marker page", async () => {
  const { node, key } = await chainWithPartialReveal();
  try {
    const opened = await openOnFreshPage(node, key);
    assert.equal(opened.outcome.status, "unclaimed", JSON.stringify(opened.outcome, (_k, v) => (typeof v === "bigint" ? `${v}` : v)));
    assert.equal(opened.outcome.coins.length, 2, "the spent coin and its remainder");
    assert.deepEqual(
      opened.outcome.coins.map((c) => c.spent),
      [true, false],
      "the spent coin shows spent, from the markers of the reveal receipts",
    );
    assert.equal(opened.outcome.current.number, 1n, "the key opens on its remainder");
    assert.deepEqual(opened.requests.filter(isMarkerPage), [], "no marker page is asked for");
    assert.ok(!opened.requests.some((r) => r.includes('"coin-markers"')), "no request names the marker pages");
    // Headers, page roots and pages, then the receipts: nothing of the tree
    // is asked once the receipts are.
    const firstReceipts = opened.requests.findIndex((r) => r.startsWith('["eth_getBlockReceipts"'));
    assert.ok(firstReceipts > 0, "the receipts are read");
    const afterReceipts = opened.requests.slice(firstReceipts);
    assert.ok(!afterReceipts.some((r) => r.startsWith('["ghost_getTreePage"') || r.startsWith('["ghost_getPageRoots"')), "the tree is read before the receipts");
    const checked = opened.ops.indexOf("receiptsCheck");
    assert.ok(checked >= 0 && checked < opened.ops.indexOf("restore"), "the receipts are checked before restore");
  } finally {
    await node.close();
  }
});

test("a hidden or invented marker list changes neither the requests nor the result", async () => {
  const { node, key, marker } = await chainWithPartialReveal();
  try {
    const honest = await openOnFreshPage(node, key);
    assert.equal(honest.outcome.status, "unclaimed");
    assert.deepEqual(
      honest.outcome.coins.map((c) => c.spent),
      [true, false],
    );

    // Hidden: served alone, the spent coin would look unspent.
    node.dishonest.markers = (list) => list.filter((m) => m !== marker);
    const hidden = await openOnFreshPage(node, key);
    // Invented: a marker no reveal receipt holds.
    node.dishonest.markers = (list) => [...list, `0x${"5e".repeat(32)}`];
    const invented = await openOnFreshPage(node, key);
    // Another in place of the real one.
    node.dishonest.markers = (list) => list.map(() => `0x${"5e".repeat(32)}`);
    const replaced = await openOnFreshPage(node, key);
    node.dishonest.markers = null;

    for (const [name, opened] of [
      ["hidden", hidden],
      ["invented", invented],
      ["replaced", replaced],
    ]) {
      assert.deepEqual(opened.outcome, honest.outcome, `a ${name} marker list gives the honest result`);
      assert.deepEqual(opened.requests, honest.requests, `a ${name} marker list changes no request`);
      assert.deepEqual(opened.ops, honest.ops, `a ${name} marker list changes no work in the worker`);
    }
  } finally {
    await node.close();
  }
});

test("a fully claimed key shows claimed from the markers of the reveal receipts", async () => {
  const { node, key } = await chainWithCoin();
  const { flow, close } = freshFlow(node);
  let newKey;
  try {
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    newKey = await flow.claimStart();
    const claimed = await flow.claimCheck(answersFor(newKey, flow.claimSaved()));
    assert.equal(claimed.ok, true);
    assert.equal(node.reveals.length, 1, "the claim is in a block");
    assert.equal(flow.state.summon.status, "claimed");
  } finally {
    close();
  }
  try {
    node.mineTo(node.tip() + 3);
    // The endpoint hides the claim's marker: the receipts still hold it.
    node.dishonest.markers = () => [];
    const opened = await openOnFreshPage(node, key);
    node.dishonest.markers = null;
    assert.equal(opened.outcome.status, "claimed");
    assert.equal(opened.outcome.current, null);
    assert.deepEqual(
      opened.outcome.coins.map((c) => c.spent),
      [true],
      "the key's one coin is spent",
    );
    assert.deepEqual(opened.requests.filter(isMarkerPage), [], "no marker page is asked for");
    assert.equal((await openOnFreshPage(node, newKey)).outcome.status, "unclaimed", "the new key holds the value");
  } finally {
    await node.close();
  }
});

test("heldMarkers returns the markers of the reveal records of the first markerBlocks blocks, in order", () => {
  const marker = (byte) => new Uint8Array(32).fill(byte);
  const commit = (position) => ({ treeIndex: 0, position, leaf: marker(0x10 + position), marker: null, v: 1n });
  const reveal = (position, byte) => ({ treeIndex: 0, position, leaf: marker(0x10 + position), marker: marker(byte), v: null });
  const blockRecords = [
    [commit(0), commit(1)],
    [reveal(2, 0xa1), commit(3), reveal(4, 0xa2)],
    [],
    [reveal(5, 0xa3)],
    [reveal(6, 0xa4)],
  ];

  // Commits give none, and the markers keep block and log order.
  assert.equal(toHex(heldMarkers(blockRecords, 5)), toHex(concat([marker(0xa1), marker(0xa2), marker(0xa3), marker(0xa4)])));
  // A pinned markerBlocks stops early: the blocks past it give none.
  assert.equal(toHex(heldMarkers(blockRecords, 4)), toHex(concat([marker(0xa1), marker(0xa2), marker(0xa3)])));
  assert.equal(toHex(heldMarkers(blockRecords, 2)), toHex(concat([marker(0xa1), marker(0xa2)])));
  // Blocks of commits alone hold no marker.
  const none = heldMarkers(blockRecords, 1);
  assert.ok(none instanceof Uint8Array);
  assert.equal(none.length, 0);
  assert.equal(heldMarkers([], 3).length, 0);
  // One Uint8Array, 32 bytes a marker.
  const all = heldMarkers(blockRecords, blockRecords.length);
  assert.ok(all instanceof Uint8Array);
  assert.equal(all.length, 4 * 32);
});
