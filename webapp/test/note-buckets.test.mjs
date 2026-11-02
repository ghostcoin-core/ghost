// Restore by note buckets (spec 01, sections 8 and 9): the module's bucket
// bits and lookup tags against the spec's vectors; restoreByBuckets, the web
// app's twin of the client library's restore_coins_by_tags, with a stub
// bucket source and prover for its batches and against the node stand-in
// (support/fake-node.mjs, `buckets: true`) for the wire; and the scan
// (flow.mjs, scanKey), which restores by buckets cross-checked against the
// pages it read and falls back to the full page scan for a node that does
// not serve buckets, refuses a read, or serves a bucket that is malformed or
// disagrees with the pages.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { BucketRefused, TAG_BATCH, createBucketReader, restoreByBuckets, restoreTreesByBuckets, tagPrefix } from "../src/buckets.mjs";
import { concat, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow } from "../src/flow.mjs";
import { createProver } from "../src/prover.mjs";
import { createRpc } from "../src/rpc.mjs";
import { createWorker } from "../src/worker-core.mjs";
import { buildModuleIfMissing, loadModule, nodeProver, openTestWallet, wasmPath } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

buildModuleIfMissing(wasmPath);
const ghost = await loadModule();

const GHOST = 10n ** 18n;
// Spec 01, section 14: the example key, as its digit view.
const EXAMPLE_KEY = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
// Spec 01, section 14: bucket-rule-0 to bucket-rule-5, [notes, bits].
const BUCKET_RULE = [
  [0, 0],
  [8191, 0],
  [8192, 1],
  [1_048_576, 8],
  [3_650_000_000, 19],
  [1_099_511_627_776, 24],
];
const ACCOUNT = "0x1111111111111111111111111111111111111111";

// The worker's message interface over the built module, in this thread.
function moduleProver() {
  let deliver = () => {};
  const onMessage = createWorker(
    () => readFile(wasmPath),
    (reply) => deliver(reply),
  );
  return createProver({
    post: (message) => onMessage(message),
    listen: (handler) => {
      deliver = handler;
    },
    terminate: () => {},
  });
}

// A prover whose bucket bits are `bits` (for a small tree, as the stand-in
// is told with `bucketBits`), its other requests the module's, each op
// recorded.
function bitsProver(inner, bits) {
  const ops = [];
  return {
    ops,
    request(op, args, onProgress) {
      ops.push({ op, args });
      if (op === "bucketBits" && bits !== null) return Promise.resolve({ bits });
      return inner.request(op, args, onProgress);
    },
  };
}

// A stub prover for the batch logic: bucket bits `bits`, the module's tags,
// and a restoreAt that finds the coins of the numbers in `owned` up to the
// last number of the batch asked so far.
function stubProver({ bits, owned }) {
  const calls = [];
  return {
    calls,
    async request(op, args) {
      calls.push({ op, args });
      if (op === "bucketBits") return { bits };
      if (op === "noteTags") return { tags: ghost.noteTags(args) };
      if (op === "restoreAt") {
        const batches = calls.filter((c) => c.op === "noteTags").length;
        const found = [...owned].filter((n) => n < batches * TAG_BATCH).map((n) => ({ number: BigInt(n), position: n }));
        return { found };
      }
      throw new Error(`the stub prover has no ${op}`);
    },
  };
}

// A stub bucket source: each prefix's bucket holds one entry of its own and
// one entry every bucket holds, so a restore sees that one served twice.
function stubBuckets() {
  const reads = [];
  const shared = { position: 0, leaf: new Uint8Array(32).fill(1), note: new Uint8Array(156), salt: null };
  return {
    reads,
    async readBucket(treeIndex, bits, prefix) {
      reads.push({ treeIndex, bits, prefix });
      return [shared, { position: 1 + prefix, leaf: new Uint8Array(32).fill(2), note: new Uint8Array(156), salt: null }];
    },
  };
}

// The distinct prefixes, in first-seen order, of the key's tags of numbers
// `first` to `first + count - 1` at `bits` bits.
function prefixesOf(key, bits, first, count) {
  return [...new Set(ghost.noteTags({ key, first, count }).map((tag) => tagPrefix(tag, bits)))];
}

// A coin of `key` committed on the stand-in by its scripted sender, as a
// commit sends it: 1 GHOST, number 0, salted.
async function commitTo(node, key) {
  const { payload } = ghost.commit({ chainId: node.chainId, amount: GHOST, seed: randomBytes(32), key });
  await node.wallet(ACCOUNT).request({
    method: "eth_sendTransaction",
    params: [{ from: ACCOUNT, to: DEFAULT_COMMIT_ENTRY, value: "0xde0b6b3a7640000", data: toHex(payload) }],
  });
}

// The key's coins by the full page scan: the module's restore over every
// leaf, note and salt of the stand-in's tree, as the scan's coins show.
function pageCoins(node, key) {
  const found = ghost.restore({
    chainId: node.chainId,
    key,
    records: concat(node.leaves.flatMap((l) => [l.commitment, l.note])),
    salts: node.leaves.map((l) => l.salt),
    markers: concat(node.spent.map((s) => s.marker)),
    treeIndex: 0,
  });
  return found.map(({ number, amount, treeIndex, position, spent }) => ({ number, amount, treeIndex, position, spent }));
}

const bucketReads = (node, from = 0) => node.requests.slice(from).filter((r) => r.method === "ghost_getNoteBucket");

// A flow on a stand-in, with `bits` bucket bits for both (null: the rule),
// a connected wallet and strangers' coins on the chain.
async function setUp({ buckets, bits = null }) {
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, buckets, bucketBits: bits });
  const worker = nodeProver();
  const prover = bitsProver(worker, bits);
  const flow = createFlow({ prover, endpoint: node.url, networks: node.networks(), pollMs: 5, maxPolls: 20, sleep: async () => node.mine() });
  await openTestWallet(flow, node);
  node.foreignCommits(3);
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { node, flow, prover, done };
}

// Vanish of 1 GHOST with a right save check, strangers' coins after it and
// a few blocks; the key.
async function vanish(flow, node) {
  const key = await flow.vanishStart("1");
  const words = key.split(" ");
  const sent = await flow.vanishCheck(flow.vanishSaved().map((p) => words[p - 1]));
  assert.equal(sent.ok, true);
  node.foreignCommits(2);
  node.mineTo(node.tip() + 4);
  return key;
}

// Opens `key` and gives its status, its coins and the worker ops it asked.
async function open(flow, prover, key) {
  const from = prover.ops.length;
  const s = await flow.summonOpen(key);
  return { status: s.status, coins: s.coins, ops: prover.ops.slice(from).map((o) => o.op) };
}

const byBuckets = (ops) => ops.includes("restoreAt") && !ops.includes("restore");
const byPages = (ops) => ops.includes("restore") && !ops.includes("restoreAt");

test("bucket bits and note tags from the module match the spec vectors", async () => {
  const prover = moduleProver();
  for (const [notes, bits] of BUCKET_RULE) {
    assert.equal(ghost.bucketBits(notes), bits, `bucket bits of ${notes} notes`);
    assert.deepEqual(await prover.request("bucketBits", { count: notes }), { bits }, `the worker's bucket bits of ${notes} notes`);
  }
  const { tags } = await prover.request("noteTags", { key: EXAMPLE_KEY, first: 0, count: 2 });
  assert.deepEqual(tags.map(toHex), ["0x4d6c00", "0x7c28b7"], "note-tag-index-0 and note-tag-index-1");
  assert.deepEqual(ghost.noteTags({ key: EXAMPLE_KEY, first: 1, count: 1 }).map(toHex), ["0x7c28b7"]);
  assert.equal(ghost.noteTags({ key: EXAMPLE_KEY, first: 0, count: 16 }).length, 16);
  assert.equal(tagPrefix(tags[0], 8), 0x4d);
  assert.equal(tagPrefix(tags[0], 19), 0x26b60);
  assert.equal(tagPrefix(tags[0], 24), 0x4d6c00);
  assert.equal(tagPrefix(tags[0], 0), 0, "below 8,192 notes the whole tree is one bucket");
  assert.throws(() => ghost.noteTags({ key: "not a key", first: 0, count: 1 }), /not a valid Phantom Key/);
});

test("a restore reads only the buckets of the key's own tags, 16 numbers a batch, each prefix once", async () => {
  const key = ghost.newKey(randomBytes(32));
  // 3 bits: 8 buckets for 16 tags, so some tags share one.
  for (const bits of [3, 24]) {
    const prover = stubProver({ bits, owned: [0] });
    const source = stubBuckets();
    const restored = await restoreByBuckets({ prover, readBucket: source.readBucket, key, chainId: 7n, treeIndex: 2, count: 50_000, spent: new Uint8Array(0) });
    const expected = prefixesOf(key, bits, 0, 16);
    if (bits === 3) assert.ok(expected.length < 16, "tags share a bucket");
    assert.deepEqual(source.reads.map((r) => r.prefix), expected, `the key's prefixes at ${bits} bits, each read once`);
    assert.ok(source.reads.every((r) => r.treeIndex === 2 && r.bits === bits));
    assert.deepEqual(prover.calls.find((c) => c.op === "bucketBits").args, { count: 50_000 }, "bits for the tree's leaf count");
    assert.deepEqual(prover.calls.filter((c) => c.op === "noteTags").map((c) => [c.args.first, c.args.count]), [[0, 16]], "one batch of 16");
    const restores = prover.calls.filter((c) => c.op === "restoreAt");
    assert.equal(restores.length, 1);
    const positions = restores[0].args.entries.map((e) => e.position);
    assert.deepEqual(positions, [0, ...expected.map((p) => 1 + p).sort((a, b) => a - b)], "in position order, a note served twice tried once");
    assert.equal(restored.bucketReads, expected.length);
    assert.equal(restored.notesTried, 2 * expected.length);
    assert.deepEqual(restored.found.map((c) => c.number), [0n]);
  }

  // On the wire: the stand-in's buckets of 4 bits, a key's coin among
  // strangers'.
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, buckets: true, bucketBits: 4 });
  try {
    node.foreignCommits(20);
    await commitTo(node, key);
    node.foreignCommits(20);
    const anchor = node.blocks.at(-1);
    const prover = bitsProver(moduleProver(), 4);
    const { readBucket } = createBucketReader({ rpc: createRpc(node.url), anchorHash: anchor.hash });
    const restored = await restoreByBuckets({ prover, readBucket, key, chainId: node.chainId, treeIndex: 0, count: node.leaves.length, spent: new Uint8Array(0) });
    assert.deepEqual(
      restored.found.map(({ number, amount, treeIndex, position, spent }) => ({ number, amount, treeIndex, position, spent })),
      pageCoins(node, key),
    );
    const asked = bucketReads(node).map((r) => r.params);
    const expected = prefixesOf(key, 4, 0, 16);
    assert.deepEqual(asked, expected.map((p) => ["coin", "0x0", "0x4", `0x${p.toString(16)}`, toHex(anchor.hash)]));
    assert.ok(restored.notesTried < node.leaves.length, "fewer notes tried than the tree holds");
    assert.equal(restored.bucketReads, expected.length);
  } finally {
    await node.close();
  }
});

test("the next batch is read only when the last number of the batch was found", async () => {
  const key = ghost.newKey(randomBytes(32));
  const range = (n) => Array.from({ length: n }, (_, i) => i);
  for (const [owned, batches] of [
    [range(15), 1],
    [range(16), 2],
    [range(32), 3],
  ]) {
    const prover = stubProver({ bits: 24, owned });
    const source = stubBuckets();
    await restoreByBuckets({ prover, readBucket: source.readBucket, key, chainId: 7n, treeIndex: 0, count: 1 << 30, spent: new Uint8Array(0) });
    const firsts = prover.calls.filter((c) => c.op === "noteTags").map((c) => c.args.first);
    assert.deepEqual(firsts, range(batches).map((b) => 16 * b), `numbers 0 to ${owned.length - 1} found: ${batches} batches`);
    assert.equal(prover.calls.filter((c) => c.op === "restoreAt").length, batches, "a restore after each batch");
    assert.deepEqual(
      source.reads.map((r) => r.prefix),
      prefixesOf(key, 24, 0, 16 * batches),
      "only the buckets of those batches' tags, each once",
    );
  }

  // On the wire: a key with only its number 0 is read in one batch.
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, buckets: true, bucketBits: 6 });
  try {
    node.foreignCommits(4);
    await commitTo(node, key);
    const prover = bitsProver(moduleProver(), 6);
    const { readBucket } = createBucketReader({ rpc: createRpc(node.url), anchorHash: node.blocks.at(-1).hash });
    const restored = await restoreByBuckets({ prover, readBucket, key, chainId: node.chainId, treeIndex: 0, count: node.leaves.length, spent: new Uint8Array(0) });
    assert.deepEqual(restored.found.map((c) => c.number), [0n]);
    assert.deepEqual(prover.ops.filter((o) => o.op === "noteTags").map((o) => o.args.first), [0]);
    assert.deepEqual(bucketReads(node).map((r) => Number(BigInt(r.params[3]))), prefixesOf(key, 6, 0, 16));
  } finally {
    await node.close();
  }
});

test("the coins restored by buckets equal the coins restored by the full page scan", async () => {
  const { node, flow, prover, done } = await setUp({ buckets: true, bits: 2 });
  try {
    const first = await vanish(flow, node);
    const second = await vanish(flow, node);
    const stranger = ghost.newKey(randomBytes(32));
    for (const [key, status] of [
      [first, "unclaimed"],
      [second, "unclaimed"],
      [stranger, "not-found"],
    ]) {
      const from = node.requests.length;
      const opened = await open(flow, prover, key);
      assert.equal(opened.status, status);
      assert.ok(byBuckets(opened.ops), "restored by buckets");
      assert.ok(bucketReads(node, from).length > 0);
      assert.deepEqual(opened.coins, pageCoins(node, key), "the coins of the full page scan");
    }
    assert.equal(pageCoins(node, first).length, 1);
  } finally {
    await done();
  }
});

test("a node without ghost_getNoteBucket gets the full page scan and is not asked again", async () => {
  const { node, flow, prover, done } = await setUp({ buckets: false });
  try {
    const key = await vanish(flow, node);
    const other = ghost.newKey(randomBytes(32));
    const scans = [];
    for (const k of [key, key, other]) scans.push(await open(flow, prover, k));
    assert.deepEqual(scans.map((s) => s.status), ["unclaimed", "unclaimed", "not-found"]);
    assert.ok(scans.every((s) => byPages(s.ops)), "every scan is the full page scan");
    assert.equal(bucketReads(node).length, 1, "asked once in the life of the flow");
    assert.equal(scans[0].ops.filter((op) => op === "noteTags").length, 1);
    assert.ok(scans.slice(1).every((s) => !s.ops.includes("noteTags") && !s.ops.includes("bucketBits")), "no bucket work after it");
    assert.deepEqual(scans[0].coins, pageCoins(node, key));
  } finally {
    await done();
  }
});

test("a refused bucket read falls back to the full page scan for that scan only", async () => {
  const { node, flow, prover, done } = await setUp({ buckets: true });
  try {
    const key = await vanish(flow, node);
    const coins = pageCoins(node, key);
    assert.equal(coins.length, 1);
    const scan = async (bucket, how, why) => {
      node.dishonest.bucket = bucket;
      const from = node.requests.length;
      const opened = await open(flow, prover, key);
      assert.equal(opened.status, "unclaimed", why);
      assert.ok(how(opened.ops), why);
      assert.equal(bucketReads(node, from).length, 1, `${why}: the bucket is asked for`);
      assert.deepEqual(opened.coins, coins, why);
    };
    await scan(
      () => {
        throw new Error("note buckets are not ready");
      },
      byPages,
      "a node error",
    );
    await scan(null, byBuckets, "the next scan reads buckets again");
    await scan((entries) => entries.map((e) => ({ ...e, salt: "0x00" })), byPages, "a salt of the wrong length");
    await scan((entries) => [...entries].reverse(), byPages, "positions out of order");
    await scan((entries) => entries.map((e) => ({ ...e, leaf: "0x12" })), byPages, "a leaf of the wrong length");
    await scan((entries) => [...entries, entries[0]], byPages, "a position served twice");
    await scan(null, byBuckets, "honest again");

    // The reader refuses what the node does not serve for the bucket asked.
    const reader = (reply) => createBucketReader({ rpc: { call: async () => reply }, anchorHash: node.blocks.at(-1).hash });
    const honest = { kind: "coin", treeIndex: "0x0", bits: "0x8", prefix: "0x4d", count: "0x0", entries: [] };
    assert.deepEqual(await reader(honest).readBucket(0, 8, 0x4d), []);
    for (const [change, why] of [
      [{ kind: "coin-markers" }, "kind"],
      [{ treeIndex: "0x1" }, "tree index"],
      [{ bits: "0x9" }, "bits"],
      [{ prefix: "0x4e" }, "prefix"],
      [{ count: "0x1" }, "count"],
      [{ entries: null }, "entries"],
    ]) {
      await assert.rejects(reader({ ...honest, ...change }).readBucket(0, 8, 0x4d), /malformed/, why);
    }
    const note = (tag) => toHex(concat([tag, new Uint8Array(153)]));
    const entry = { position: "0x5", leaf: toHex(new Uint8Array(32)), note: note(Uint8Array.of(0x4d, 0x6c, 0x00)) };
    assert.equal((await reader({ ...honest, count: "0x1", entries: [entry] }).readBucket(0, 8, 0x4d)).length, 1);
    await assert.rejects(
      reader({ ...honest, count: "0x1", entries: [{ ...entry, note: note(Uint8Array.of(0x4e, 0, 0)) }] }).readBucket(0, 8, 0x4d),
      /not of the bucket/,
      "a note of another bucket",
    );
  } finally {
    await done();
  }
});

test("a bucket that disagrees with the pages read is dropped for the full page scan", async () => {
  const { node, flow, prover, done } = await setUp({ buckets: true });
  try {
    const key = await vanish(flow, node);
    const coins = pageCoins(node, key);
    const ours = coins[0].position;
    const scan = async (bucket, how, why) => {
      node.dishonest.bucket = bucket;
      const opened = await open(flow, prover, key);
      assert.equal(opened.status, "unclaimed", why);
      assert.ok(how(opened.ops), why);
      assert.deepEqual(opened.coins, coins, why);
    };
    const salt = `0x${"11".repeat(16)}`;
    await scan((entries) => entries.map((e) => (e.salt ? { ...e, salt } : e)), byPages, "a salt the pages do not hold");
    await scan(
      (entries) => entries.map((e) => (Number(BigInt(e.position)) === ours ? { ...e, leaf: toHex(node.leaves[0].commitment) } : e)),
      byPages,
      "a leaf the pages do not hold there",
    );
    await scan(
      (entries) => [...entries, { ...entries.find((e) => Number(BigInt(e.position)) === ours), position: `0x${(node.leaves.length + 3).toString(16)}` }],
      byPages,
      "a position past the pages read",
    );
    await scan(
      (entries) => entries.map((e) => (Number(BigInt(e.position)) === ours ? { ...e, salt: undefined } : e)),
      byPages,
      "a salt left out that the pages hold",
    );
    // A bucket is not covered by a root: one that leaves out a note the
    // pages hold of its prefix would hide coins, so it is dropped too.
    await scan(() => [], byPages, "an empty bucket");
    await scan((entries) => entries.filter((e) => Number(BigInt(e.position)) !== ours), byPages, "the key's own note withheld");
    await scan((entries) => entries.filter((e) => Number(BigInt(e.position)) !== ours + 1), byPages, "a stranger's note withheld");
    await scan((entries) => entries.slice(0, -1), byPages, "the bucket's last note withheld");
    // The key is never tried on a bucket that disagrees: no restoreAt ran
    // in those scans, and the next honest scan reads buckets again.
    await scan(null, byBuckets, "honest again");
  } finally {
    await done();
  }

  // Withholding the last coin of a batch would stop the restore before the
  // next batch: a key with numbers 0 to 16 among strangers' notes, buckets
  // of 4 bits checked against its pages.
  const key = ghost.newKey(randomBytes(32));
  const tags = ghost.noteTags({ key, first: 0, count: 17 });
  // Position 17 is a stranger's note in number 0's bucket.
  const notes = [
    ...tags.map((tag) => concat([tag, new Uint8Array(153)])),
    concat([tags[0], Uint8Array.from(randomBytes(153))]),
    ...Array.from({ length: 20 }, () => Uint8Array.from(randomBytes(156))),
  ];
  const tree = {
    treeIndex: 0,
    count: notes.length,
    records: concat(notes.flatMap((note, i) => [new Uint8Array(32).fill(i + 1), note])),
    salts: notes.map(() => null),
  };
  const rpc = (withhold) => ({
    call: async (method, [kind, treeIndex, bits, prefix]) => {
      assert.equal(method, "ghost_getNoteBucket");
      const entries = notes
        .map((note, position) => ({ position, note }))
        .filter(({ position, note }) => position !== withhold && tagPrefix(note, Number(bits)) === Number(prefix))
        .map(({ position, note }) => ({ position: `0x${position.toString(16)}`, leaf: toHex(new Uint8Array(32).fill(position + 1)), note: toHex(note) }));
      return { kind, treeIndex, bits, prefix, count: `0x${entries.length.toString(16)}`, entries };
    },
  });
  // The coins of the numbers 0 to 16 whose notes (at position = number)
  // the restore was given.
  const owner = () => {
    const calls = [];
    return {
      calls,
      async request(op, args) {
        calls.push(op);
        if (op === "bucketBits") return { bits: 4 };
        if (op === "noteTags") return { tags: ghost.noteTags(args) };
        if (op === "restoreAt") {
          const given = new Set(args.entries.map((e) => e.position));
          return { found: tags.map((_, n) => n).filter((n) => given.has(n)).map((n) => ({ number: BigInt(n), position: n })) };
        }
        throw new Error(`no ${op}`);
      },
    };
  };
  const restore = (prover, withhold) =>
    restoreTreesByBuckets({ prover, rpc: rpc(withhold), anchorHash: `0x${"00".repeat(32)}`, key, chainId: 7n, trees: [tree], spent: new Uint8Array(0) });
  const honest = owner();
  assert.equal((await restore(honest, null)).length, 17, "every coin, over two batches");
  assert.equal(honest.calls.filter((op) => op === "restoreAt").length, 2);
  for (const withhold of [15, 16, 0, 17]) {
    const prover = owner();
    await assert.rejects(restore(prover, withhold), (err) => err instanceof BucketRefused && /leaves out/.test(err.message), `position ${withhold} withheld`);
    assert.ok(!prover.calls.includes("restoreAt") || withhold === 16, "the key is not tried on a bucket that leaves a note out");
  }
});
