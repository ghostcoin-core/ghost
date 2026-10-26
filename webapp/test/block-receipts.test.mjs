// The app checks every leaf, note and salt a scan reads against the block
// receipts of the page's header chain, and every block's receipts against
// the receiptsRoot of the header that chain holds, before the key is tried
// on any note; the spent markers it takes from those receipts
// (spent-from-receipts.test.mjs). Against the stand-in (support/fake-node.mjs,
// which serves real receipts in the node's log layout), with the real module
// in a worker: an honest scan passes; an altered note or salt, a dropped or
// reordered page, a receipts root that differs and a block whose receipts
// cannot be fetched are each refused
// before restore, marker lookup, proving or any reveal; and the endpoint
// sees the same requests whether the leaf it tampered with is the key's or
// another's.

import assert from "node:assert/strict";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, RECEIPTS_FAILED, createFlow } from "../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

// The worker steps that use the key: restore (trial decryption and the
// marker lookup), the tree-state rule for its coin and the proof.
const KEY_STEPS = new Set(["restore", "chooseTreeState", "prove"]);

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

// A refused scan stops before restore, so it never sends the one bucket probe
// an honest scan's restore step asks a node without ghost_getNoteBucket:
// the refused scan's requests followed by that probe.
function withRestoreProbe(refused, honest) {
  const probe = honest.at(-1);
  assert.ok(probe.startsWith('["ghost_getNoteBucket",["coin",'), `the honest scan ends on the bucket probe, not ${probe}`);
  assert.equal(honest.filter((r) => r.startsWith('["ghost_getNoteBucket"')).length, 1, "asked once");
  return [...refused, probe];
}

// Opens `key` on a fresh page: what the endpoint saw, the worker's steps and
// the outcome.
async function openOnFreshPage(node, key) {
  const { flow, ops, close } = freshFlow(node);
  const from = node.requests.length;
  try {
    const outcome = await flow.summonOpen(key).then(
      (s) => ({ status: s.status }),
      (err) => ({ error: err.message }),
    );
    return { outcome, requests: seen(node, from), ops, state: flow.state };
  } finally {
    close();
  }
}

// A refusal of the receipts check, with `detail` among its words, and no
// step that uses the key.
function refusedBeforeKey(opened, detail) {
  assert.ok(opened.outcome.error, `refused, not ${JSON.stringify(opened.outcome)}`);
  assert.ok(opened.outcome.error.startsWith(RECEIPTS_FAILED), opened.outcome.error);
  assert.match(opened.outcome.error, detail);
  assert.match(opened.outcome.error, /uses the key for nothing/);
  assert.deepEqual(opened.ops.filter((op) => KEY_STEPS.has(op)), [], "nothing is restored, looked up or proved");
  assert.ok(!opened.requests.some((r) => r.startsWith('["eth_sendRawTransaction"')), "nothing is sent");
  assert.equal(opened.state.summon.status, "refused", "no coin is shown");
  assert.deepEqual(opened.state.summon.coins, []);
}

test("an honest scan passes: every block's receipts asked once, by hash, in chain order, before restore", async () => {
  const { node, key } = await chainWithCoin();
  const { flow, ops, close } = freshFlow(node);
  try {
    let from = node.requests.length;
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    const asked = node.requests.slice(from).filter((r) => r.method === "eth_getBlockReceipts");
    assert.deepEqual(
      asked.map((r) => r.params),
      node.blocks.map((b) => [toHex(b.hash)]),
      "the receipts of every block from genesis to the tip, each by its hash alone",
    );
    const checked = ops.indexOf("receiptsCheck");
    assert.ok(ops.indexOf("receiptsAdd") >= 0 && ops.indexOf("receiptsAdd") < checked);
    assert.ok(checked >= 0 && checked < ops.indexOf("restore"), "checked before restore");
    // Each block's receipts are asked for once per page session: a later
    // scan asks only for the block added since.
    node.foreignCommits(1);
    from = node.requests.length;
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    assert.deepEqual(
      node.requests.slice(from).filter((r) => r.method === "eth_getBlockReceipts").map((r) => r.params),
      [[toHex(node.blocks[node.tip()].hash)]],
    );
  } finally {
    close();
    await node.close();
  }
});

test("an altered note is refused before restore, and the requests do not say whether it was the key's", async () => {
  const { node, key, position } = await chainWithCoin();
  try {
    const honest = await openOnFreshPage(node, key);
    assert.deepEqual(honest.outcome, { status: "unclaimed" });
    const stranger = position + 1;
    const alter = (target) => (at, note) => {
      if (at !== target) return note;
      const altered = Uint8Array.from(note);
      altered[100] ^= 1;
      return altered;
    };

    node.dishonest.note = alter(position);
    const mine = await openOnFreshPage(node, key);
    refusedBeforeKey(mine, new RegExp(`the note at position ${position} differs from its receipt`));

    node.dishonest.note = alter(stranger);
    const theirs = await openOnFreshPage(node, key);
    refusedBeforeKey(theirs, new RegExp(`the note at position ${stranger} differs from its receipt`));
    node.dishonest.note = null;

    assert.ok(mine.requests.some((r) => r.startsWith('["eth_getBlockReceipts"')));
    assert.deepEqual(mine.requests, theirs.requests, "the same requests whether the altered leaf is the key's or another's");
    assert.ok(!mine.requests.some((r) => r.startsWith('["ghost_getNoteBucket"')), "no bucket is asked before restore");
    assert.deepEqual(
      withRestoreProbe(mine.requests, honest.requests),
      honest.requests,
      "and the same as an honest scan's, up to its restore step",
    );
    assert.deepEqual(mine.ops, theirs.ops, "the same work in the worker");
  } finally {
    await node.close();
  }
});

test("an altered or missing salt beside the key's leaf is refused before restore", async () => {
  const { node, key, position } = await chainWithCoin();
  try {
    node.dishonest.salt = (at, real) => {
      if (at !== position) return real;
      const altered = Uint8Array.from(real);
      altered[0] ^= 1;
      return altered;
    };
    refusedBeforeKey(await openOnFreshPage(node, key), new RegExp(`the salt at position ${position} differs from its receipt`));
    node.dishonest.salt = (at, real) => (at === position ? null : real);
    refusedBeforeKey(await openOnFreshPage(node, key), new RegExp(`the salt at position ${position} differs from its receipt`));
  } finally {
    await node.close();
  }
});

test("a dropped, repeated or reordered page is refused before restore", async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  try {
    // Two pages: 4,096 leaves and 4 more.
    node.foreignCommitsInOneBlock(4100);
    node.mineTo(4);
    const key = ghost.newKey(crypto.getRandomValues(new Uint8Array(32)));
    const q = (n) => `0x${n.toString(16)}`;
    const cases = [
      // Page 0 dropped: the list without its root, page 1 served as page 0.
      [() => {
        node.dishonest.pageRoots = (roots) => roots.slice(1);
        node.dishonest.page = (p, _honest, at) => ({ ...at(p + 1), page: q(p) });
      }, /do not fill|header's coin root|not a whole page/],
      // The last page dropped.
      [() => {
        node.dishonest.pageRoots = (roots) => roots.slice(0, -1);
      }, /header's coin root/],
      // Page 0 served again when page 1 is asked for.
      [() => {
        node.dishonest.page = (_p, _honest, at) => at(0);
      }, /not the page asked for/],
      // The two pages swapped, each under its own page number.
      [() => {
        node.dishonest.page = (p, _honest, at) => ({ ...at(1 - p), page: q(p) });
      }, /not a whole page|does not match its page root/],
    ];
    for (const [tamper, refusal] of cases) {
      node.dishonest.pageRoots = null;
      node.dishonest.page = null;
      tamper();
      const opened = await openOnFreshPage(node, key);
      assert.ok(opened.outcome.error, `refused, not ${JSON.stringify(opened.outcome)}`);
      assert.match(opened.outcome.error, refusal);
      assert.deepEqual(opened.ops.filter((op) => KEY_STEPS.has(op)), [], "nothing is restored, looked up or proved");
    }
    node.dishonest.pageRoots = null;
    node.dishonest.page = null;
    assert.deepEqual((await openOnFreshPage(node, key)).outcome, { status: "not-found" }, "the honest pages pass");
  } finally {
    await node.close();
  }
});

test("receipts that do not give the header's receiptsRoot, or a block whose receipts cannot be fetched, are refused", async () => {
  const { node, key, position } = await chainWithCoin();
  try {
    const block = node.leaves[position].block;
    // The key's commit log with one byte of its note changed: the receipts
    // then agree with the altered note but not with the header.
    node.dishonest.receipts = (number, list) => {
      if (number !== block) return list;
      const data = list[0].logs[0].data;
      const at = 2 + 2 * 120;
      list[0].logs[0].data = `${data.slice(0, at)}${data[at] === "0" ? "1" : "0"}${data.slice(at + 1)}`;
      return list;
    };
    refusedBeforeKey(
      await openOnFreshPage(node, key),
      new RegExp(`the receipts of block ${block}: the receipts do not match the header's receipts root`),
    );
    // A receipt dropped from the block.
    node.dishonest.receipts = (number, list) => (number === block ? [] : list);
    refusedBeforeKey(await openOnFreshPage(node, key), /do not match the header's receipts root/);
    // No receipts at all for a block, and a receipt not in the node's shape.
    node.dishonest.receipts = (number, list) => (number === 1 ? null : list);
    refusedBeforeKey(await openOnFreshPage(node, key), /did not return the receipts of block 1/);
    node.dishonest.receipts = (number, list) => (number === 1 ? [{ ...list[0], logsBloom: "0x00" }] : list);
    refusedBeforeKey(await openOnFreshPage(node, key), /a receipt of block 1 is malformed/);
    node.dishonest.receipts = null;
    assert.deepEqual((await openOnFreshPage(node, key)).outcome, { status: "unclaimed" });
  } finally {
    await node.close();
  }
});
