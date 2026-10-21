// The page's header chain: the app adopts the endpoint's headers only through
// the client library's header chain in the worker (lib.rs, ghost_chain_*),
// from the start this build pins, and takes every height, coin root and
// confirmation from the chain with the most work.
//
// Against the stand-in (support/fake-node.mjs), at the internal network's
// test constants (difficulty 1 on the 30-second schedule, so an honest seal
// passes at any nonce): a chain whose headers carry a seal that is not
// valid, and one whose headers carry a wrong difficulty, are refused with
// the plain words of POW_FAILED and no confirmation; a lighter competing
// chain is refused and the heavier one kept, until the competing chain
// outweighs it and the reorganisation is followed. A network with no entry
// in this build's table, and a start whose hash is not the pinned one, are
// refused too. The module's own exports are checked directly first.

import assert from "node:assert/strict";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, POW_FAILED, createFlow } from "../src/flow.mjs";
import { NETWORKS, readHeader } from "../src/header.mjs";
import { loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { FAKE_CHAIN_ID, TEST_CHAIN_PARAMS, startFakeNode } from "./support/fake-node.mjs";

const RECIPIENT = "0x2222222222222222222222222222222222222222";
const refusedForPow = (detail) => (err) => {
  assert.ok(err.message.startsWith(POW_FAILED), err.message);
  assert.match(err.message, /shows no confirmations/);
  if (detail) assert.match(err.message, detail);
  return true;
};

function answersFor(key, positions) {
  const groups = key.split(" ");
  return positions.map((p) => groups[p - 1]);
}

// A stand-in, a worker and a flow on them with the wallet open; `networks`
// picks the table the flow is given (the stand-in's entry by default).
async function setUp({ node: options = {}, networks = (node) => node.networks() } = {}) {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, ...options });
  // Strangers' coins in blocks 1 and 2, before the table is read.
  node.foreignCommits(2);
  const prover = nodeProver();
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks: networks(node),
    pollMs: 5,
    maxPolls: 20,
    sleep: async () => node.mine(),
  });
  await openTestWallet(flow, node);
  const done = async () => {
    prover.terminate();
    await node.close();
  };
  return { ghost, node, flow, done };
}

// A key made for `amount` GHOST and its commit sent with a right save check.
async function vanish(flow, amount = "1") {
  const key = await flow.vanishStart(amount);
  const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
  return { key, sent };
}

// --- The module's exports ---

const q = (n) => `0x${BigInt(n).toString(16)}`;
const zeros = (n) => toHex(new Uint8Array(n));
const GENESIS_TIME = 1_700_000_000;
const LATER = GENESIS_TIME + 10_000_000;

// A header at the test constants, `branch` in its miner field.
function draft(number, parentHash, { timestamp = GENESIS_TIME + 30 * number, difficulty = 1n, branch = 0 } = {}) {
  const miner = new Uint8Array(20);
  miner[19] = branch;
  const { rlp } = readHeader({
    parentHash,
    sha3Uncles: zeros(32),
    miner: toHex(miner),
    stateRoot: zeros(32),
    transactionsRoot: zeros(32),
    receiptsRoot: zeros(32),
    logsBloom: zeros(256),
    difficulty: q(difficulty),
    number: q(number),
    gasLimit: q(30_000_000),
    gasUsed: q(0),
    timestamp: q(timestamp),
    extraData: "0x",
    mixHash: zeros(32),
    nonce: zeros(8),
    baseFeePerGas: q(1_000_000_000),
    coinTreeRoot: zeros(32),
    dataTreeRoot: zeros(32),
  });
  return rlp;
}

test("the module's chain adopts sealed headers, refuses a wrong hash, difficulty or seal, and keeps the heaviest branch", async () => {
  const ghost = await loadModule();
  const genesis = draft(0, zeros(32));
  const genesisHash = ghost.chainStart({ params: TEST_CHAIN_PARAMS, start: { header: genesis } });
  assert.equal(toHex(genesisHash), toHex(ghost.keccak256(genesis)));
  const entry = (rlp) => ({ hash: ghost.keccak256(rlp), rlp });

  // Branch A: blocks 1 to 3.
  const a = [];
  for (let n = 1; n <= 3; n += 1) a.push(draft(n, toHex(n === 1 ? genesisHash : ghost.keccak256(a[n - 2])), { branch: 1 }));
  let added = ghost.chainAdd({ now: LATER, headers: a.map(entry) });
  assert.equal(added.adopted, 3);
  assert.equal(added.refused, null);
  assert.equal(added.best.height, 3n);
  assert.equal(added.best.work, 4n, "genesis and three blocks of difficulty 1");

  // A hash that is not the header's.
  const four = draft(4, toHex(ghost.keccak256(a[2])), { branch: 1 });
  added = ghost.chainAdd({ now: LATER, headers: [{ hash: new Uint8Array(32), rlp: four }] });
  assert.deepEqual([added.adopted, added.refused.why, added.refused.number], [0, "hash", 4n]);

  // A wrong difficulty: 2 where the schedule requires 1.
  added = ghost.chainAdd({ now: LATER, headers: [entry(draft(4, toHex(ghost.keccak256(a[2])), { difficulty: 2n, branch: 1 }))] });
  assert.equal(added.refused.why, "check");
  assert.match(added.refused.reason, /required difficulty/);

  // Neither is held: the honest block 4 is adopted after them.
  assert.equal(ghost.chainAdd({ now: LATER, headers: [entry(four)] }).refused, null, "the honest block 4 passes");

  // Ahead of the clock by more than the drift: not adopted yet.
  const ahead = draft(5, toHex(ghost.keccak256(four)), { branch: 1 });
  added = ghost.chainAdd({ now: GENESIS_TIME + 30 * 5 - 31, headers: [entry(ahead)] });
  assert.equal(added.refused.why, "ahead");
  assert.equal(ghost.chainAdd({ now: GENESIS_TIME + 30 * 5, headers: [entry(ahead)] }).refused, null, "adopted once the clock caught up");

  // Branch B from block 1: lighter while shorter, heavier once longer.
  const b = [];
  for (let n = 2; n <= 7; n += 1) b.push(draft(n, toHex(n === 2 ? ghost.keccak256(a[0]) : ghost.keccak256(b[n - 3])), { branch: 2 }));
  added = ghost.chainAdd({ now: LATER, headers: b.slice(0, 4).map(entry) });
  assert.equal(added.adopted, 4);
  assert.equal(toHex(added.best.hash), toHex(ghost.keccak256(ahead)), "the lighter branch does not take over");
  let view = ghost.chainView({ hash: ghost.keccak256(b[3]), from: 1, to: 0 });
  assert.equal(view.held, true);
  assert.equal(view.confirmations, 0n, "a header of the lighter branch has no confirmations");
  added = ghost.chainAdd({ now: LATER, headers: b.slice(4).map(entry) });
  assert.equal(added.best.height, 7n);
  assert.equal(added.removed, 4n, "blocks 2 to 5 of branch A left the best chain");
  view = ghost.chainView({ hash: ghost.keccak256(a[0]), from: 0, to: 3 });
  assert.equal(view.confirmations, 7n, "block 1, shared, is 7 deep");
  assert.deepEqual(view.hashes.map(toHex), [genesisHash, ghost.keccak256(a[0]), ghost.keccak256(b[0]), ghost.keccak256(b[1])].map(toHex));
  assert.equal(ghost.chainView({ hash: ghost.keccak256(a[2]), from: 1, to: 0 }).confirmations, 0n);
});

test("the module's chain refuses an unmined seal above a pinned start stamped ahead of the schedule", async () => {
  const ghost = await loadModule();
  // A pinned block 1000, 32 half-lives ahead of the schedule: its children
  // require difficulty 2^32, which an unmined nonce does not meet.
  const ahead = 32 * 3600;
  const pin = draft(1000, toHex(new Uint8Array(32).fill(7)), { timestamp: GENESIS_TIME + 30_000 - ahead });
  const keyBlock = new Uint8Array(32).fill(9);
  const pinHash = ghost.chainStart({
    params: TEST_CHAIN_PARAMS,
    start: { header: pin, height: 1000, totalWork: 1001n, genesisTimestamp: GENESIS_TIME, keyBlocks: [[0, keyBlock]] },
  });
  const child = draft(1001, toHex(pinHash), { timestamp: GENESIS_TIME + 30_030 - ahead, difficulty: 1n << 32n });
  const added = ghost.chainAdd({ now: LATER, headers: [{ hash: ghost.keccak256(child), rlp: child }] });
  assert.equal(added.refused.why, "check");
  assert.match(added.refused.reason, /above the target/);
  assert.equal(added.best.height, 1000n, "nothing above the start is held");
  // The same child with difficulty 1 carries the wrong difficulty instead.
  const easy = draft(1001, toHex(pinHash), { timestamp: GENESIS_TIME + 30_030 - ahead });
  assert.match(ghost.chainAdd({ now: LATER, headers: [{ hash: ghost.keccak256(easy), rlp: easy }] }).refused.reason, /required difficulty/);
  // A key block that is not on the epoch schedule is refused at the start.
  assert.throws(
    () =>
      ghost.chainStart({
        params: TEST_CHAIN_PARAMS,
        start: { header: pin, height: 1000, totalWork: 1001n, genesisTimestamp: GENESIS_TIME, keyBlocks: [[5, keyBlock]] },
      }),
    /start header is refused/,
  );
});

// --- The app against the stand-in ---

test("this build pins no network yet, and a network with no entry shows no confirmations", async () => {
  assert.deepEqual(Object.keys(NETWORKS), [], "no launch network or pinned start exists yet");
  const { node, flow, done } = await setUp({ networks: () => NETWORKS });
  try {
    const key = await flow.vanishStart("1");
    await assert.rejects(flow.summonOpen(key), new RegExp(`no pinned start for network ${FAKE_CHAIN_ID}`));
    assert.equal(flow.state.summon.status, "refused");
    assert.match(flow.state.chainRefused, /shows no confirmations/);
    await assert.rejects(flow.vanishCheck(answersFor(key, flow.vanishSaved())), /no pinned start/);
    assert.equal(node.accountTxs.length, 0, "nothing is signed or sent");
  } finally {
    await done();
  }
});

test("a start header whose hash is not the pinned one is refused", async () => {
  const { node, flow, done } = await setUp({
    networks: (n) => {
      const table = n.networks({ pinAt: 1 });
      table[String(FAKE_CHAIN_ID)].pin.hash = toHex(new Uint8Array(32).fill(0xab));
      return table;
    },
  });
  try {
    const key = await flow.vanishStart("1");
    await assert.rejects(flow.summonOpen(key), refusedForPow(/block 1 is not the start this build pins/));
    assert.equal(node.accountTxs.length, 0);
  } finally {
    await done();
  }
});

test("a chain whose seals are not valid is refused: no confirmations, nothing sent", async () => {
  // Every block after genesis stamped 32 half-lives ahead of the schedule,
  // with the 2^32 that requires and a nonce nobody mined; the build pins
  // block 1, so blocks 2 and on must carry a valid seal.
  const { node, flow, done } = await setUp({ node: { earlyHalfLives: 32 }, networks: (n) => n.networks({ pinAt: 1 }) });
  try {
    node.mineTo(12);
    const key = await flow.vanishStart("1");
    await assert.rejects(flow.summonOpen(key), refusedForPow(/block 2: the seal's hash is above the target/));
    const s = flow.state.summon;
    assert.equal(s.status, "refused");
    assert.deepEqual([s.coins, s.current, s.tip], [[], null, null], "no coin and no tip are shown");
    assert.match(flow.state.chainRefused, /^the endpoint's chain failed the proof-of-work check/);
    // The commit needs the tip's base fee: it is not signed.
    await assert.rejects(flow.vanishCheck(answersFor(key, flow.vanishSaved())), refusedForPow(/seal/));
    assert.notEqual(flow.state.vanish.stage, "done");
    assert.equal(node.accountTxs.length, 0, "nothing is signed or sent");
  } finally {
    await done();
  }
});

test("the same pinned start with honest seals is followed to Done", async () => {
  const { node, flow, done } = await setUp({ networks: (n) => n.networks({ pinAt: 1 }) });
  try {
    const { sent } = await vanish(flow);
    assert.equal(sent.ok, true);
    assert.equal(flow.state.vanish.stage, "done");
    assert.equal(flow.state.chainRefused, null);
    assert.equal(sent.block, node.tip());
  } finally {
    await done();
  }
});

test("a chain whose headers carry a wrong difficulty is refused: the commit in it is never Done", async () => {
  const { node, flow, done } = await setUp();
  try {
    const first = await vanish(flow);
    assert.equal(flow.state.vanish.stage, "done", "the honest chain confirms");
    // From the next block on, difficulty 2 where the schedule requires 1:
    // well formed, hashed right, and sealed for the difficulty it carries.
    node.setDifficulty(2);
    const key = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(key, flow.vanishSaved())), refusedForPow(/does not carry the required difficulty/));
    assert.equal(node.accountTxs.length, 2, "the commit reached the endpoint");
    assert.equal(flow.state.vanish.stage, "sent", "shown Sent, never Done");
    assert.equal(flow.state.vanish.block, null);
    await assert.rejects(flow.summonOpen(first.key), refusedForPow(/required difficulty/));
    assert.equal(flow.state.summon.status, "refused");
    assert.equal(flow.state.summon.current, null, "no coin is shown from that chain");
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /no coin to reveal/);
    assert.equal(node.reveals.length, 0);
  } finally {
    await done();
  }
});

test("a lighter competing chain is refused and the heavier one kept, until it outweighs it", async () => {
  const { node, flow, done } = await setUp();
  try {
    const { key, sent } = await vanish(flow);
    assert.equal(flow.state.vanish.stage, "done");
    const block = sent.block;
    node.mineTo(block + 3);
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    const heavyTip = node.tip();

    // The endpoint now serves a chain that replaces the last 5 blocks, the
    // commit's among them, with 2: less work than the chain the page holds.
    node.reorg(5, { length: 2 });
    assert.ok(node.tip() < heavyTip);
    await assert.rejects(flow.vanishRecheck(), (err) => {
      assert.match(err.message, /less proof of work than the chain this page has already checked/);
      assert.match(err.message, new RegExp(`tip at block ${heavyTip}\\)`), "the heavier chain is the one kept");
      return true;
    });
    assert.equal(flow.state.vanish.stage, "done", "the lighter chain does not undo the commit");
    assert.equal(flow.state.vanish.block, block);
    await assert.rejects(flow.summonRefresh(), /less proof of work/);
    assert.equal(flow.state.summon.status, "refused");

    // Once the competing chain has more work, the page follows it: the
    // commit's block is gone, and so is the coin.
    node.mineTo(heavyTip + 1);
    assert.equal((await flow.vanishRecheck()).stage, "dropped");
    assert.equal(flow.state.chainRefused, null);
    assert.equal((await flow.summonRefresh()).status, "not-found");
    assert.equal(flow.state.summon.tip, node.tip());
  } finally {
    await done();
  }
});
