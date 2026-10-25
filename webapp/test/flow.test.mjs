// The proof of done: the app's flow controller, driven headless through
// Vanish (with a save check that first fails, then passes), a partial
// Summon and a Claim, with the real prover built for wasm32-unknown-unknown
// running in a worker_threads worker through the browser worker's message
// interface, against the scripted node stand-in. The stand-in verifies each
// reveal's proof with the real verifier before it accepts it, and records
// every request so the test can check that no key word, seed word or secret
// reached the endpoint. The commit is an account transaction (type 0x52)
// signed by the connected wallet (the tests' connector), which the stand-in
// checks as the node does.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import {
  ACCOUNT_EXTRA_GAS,
  COMMIT_GAS_CAP,
  DEFAULT_COMMIT_ENTRY,
  PRIORITY_FEE_CAP,
  HEAD_MOVED_SENDS,
  WaitError,
  ZERO_ADDRESS,
  createFlow,
} from "../src/flow.mjs";
import { DEFAULT_ENDPOINT } from "../src/rpc.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, openTestWallet, webappDir } from "./support/env.mjs";
import { COMMIT_ESTIMATE_GAS, PRIORITY_FEE, startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
// Spec 07, vector window-genesis: the fee at a base fee of 1 gwei.
const SPEC_FEE = 33_036_375_802_978_007n;
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const ENDPOINT_METHODS = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getTransactionReceipt",
  "eth_getBlockReceipts",
  "eth_sendRawTransaction",
  "eth_getTransactionCount",
  "eth_getBalance",
  "eth_maxPriorityFeePerGas",
  "eth_estimateGas",
  "ghost_getPageRoots",
  "ghost_getTreePage",
]);

function answersFor(key, positions) {
  const words = key.split(" ");
  return positions.map((p) => words[p - 1]);
}

// A word that differs from the right one in its last letter.
function mistype(word) {
  return word.slice(0, -1) + (word.at(-1) === "a" ? "b" : "a");
}

// Every run of three words of a key: no request may hold any of them, in any
// case.
function wordRuns(key) {
  const words = key.split(" ");
  const runs = [];
  for (let i = 0; i + 3 <= words.length; i += 1) runs.push(words.slice(i, i + 3).join(" "));
  return runs;
}

test("Vanish, a partial Summon and a Claim against the node stand-in", async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  const stages = [];
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks: node.networks(),
    pollMs: 5,
    // While the app waits, the chain grows by a block.
    sleep: async () => node.mine(),
    onChange: (s) => {
      if (s.progress && stages[stages.length - 1] !== s.progress.stage) stages.push(s.progress.stage);
    },
  });
  try {
    // Strangers' coins before ours.
    node.foreignCommits(3);
    // --- The wallet: connected, never created in the page ---
    await assert.rejects(flow.vanishStart("1"), /connect a wallet first/);
    assert.equal(flow.state.vanish, null, "no key is made before a wallet is connected");
    const address = await openTestWallet(flow, node);
    assert.equal(address, TEST_WALLET_ADDRESS);
    assert.equal(flow.state.wallet.address, TEST_WALLET_ADDRESS);
    assert.equal(flow.state.wallet.balance, 100n * GHOST);
    assert.deepEqual(Object.keys(flow.state.wallet).sort(), ["address", "balance", "id", "name"], "no seed or key in the state");

    // --- Vanish ---
    const key = await flow.vanishStart("1");
    assert.match(key, /^[a-z]+( [a-z]+){23}$/, "a key of 24 words");
    assert.equal(flow.state.vanish.stage, "shown");
    assert.throws(() => flow.claimSaved(), /show the key first/);

    const positions = flow.vanishSaved();
    assert.equal(positions.length, 3);
    assert.equal(new Set(positions).size, 3, "three distinct words");
    assert.deepEqual([...positions].sort((a, b) => a - b), positions, "asked in order");
    for (const p of positions) assert.ok(p >= 1 && p <= 24);

    // A wrong re-type blocks the commit: nothing reaches the wallet or the chain.
    const right = answersFor(key, positions);
    const wrong = [...right];
    wrong[1] = mistype(wrong[1]);
    const leavesBefore = node.leaves.length;
    const refused = await flow.vanishCheck(wrong);
    assert.deepEqual(refused, { ok: false, wrong: [positions[1]] });
    assert.equal(flow.state.vanish.stage, "check");
    assert.equal(node.accountTxs.length, 0);
    assert.equal(node.leaves.length, leavesBefore);
    assert.equal(node.commits.length, 0);

    // The right groups send it.
    const sent = await flow.vanishCheck(right);
    assert.equal(sent.ok, true);
    assert.equal(flow.state.vanish.stage, "done");
    assert.equal(flow.state.vanish.key, null, "the app drops the key once the commit is sent");
    // One account transaction, signed by the wallet's key and checked by the
    // stand-in for this chain: to the commit entry, 1 GHOST, nonce 0, with
    // the gas of its signature on top of the estimate.
    assert.equal(node.accountTxs.length, 1);
    const commitTx = node.accountTxs[0];
    assert.equal(commitTx.from, TEST_WALLET_ADDRESS);
    assert.equal(toHex(commitTx.to), DEFAULT_COMMIT_ENTRY);
    assert.equal(commitTx.value, GHOST);
    assert.equal(commitTx.nonce, 0n);
    assert.equal(commitTx.gasLimit, COMMIT_ESTIMATE_GAS + ACCOUNT_EXTRA_GAS);
    assert.equal(commitTx.maxPriorityFeePerGas, PRIORITY_FEE);
    assert.equal(commitTx.hash, sent.txHash);
    assert.equal(flow.state.wallet.balance, 99n * GHOST, "the balance is read again after the commit");
    assert.equal(node.requests.filter((r) => r.method === "eth_sendTransaction").length, 0);
    assert.equal(node.commits.length, 1);
    const ourCommitment = toHex(node.commits[0].commitment);

    // Strangers' coins after ours, then more blocks than the 2 that settle them.
    node.foreignCommits(2);
    node.mineTo(44);

    // --- Summon: the received key shows unclaimed ---
    let s = await flow.summonOpen(key);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.coins.length, 1);
    assert.equal(s.current.amount, GHOST);
    assert.equal(s.fee, SPEC_FEE);
    assert.equal(s.available, GHOST - SPEC_FEE);

    // Not to the zero address, whose credit nobody can spend.
    const before = node.requests.length;
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: ZERO_ADDRESS }), /zero address/);
    assert.equal(node.requests.length, before, "nothing is asked or sent");

    // A partial reveal of 0.25 GHOST to any other address.
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.ok(reveal.block > 44);
    assert.equal(node.reveals.length, 1);
    assert.equal(node.reveals[0].fee, SPEC_FEE, "the fee of spec 07 for a base fee of 1 gwei");
    assert.equal(node.reveals[0].out, GHOST / 4n);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
    assert.ok(stages.includes("proving in the background worker"), "progress is shown while proving");
    s = flow.state.summon;
    assert.equal(s.status, "unclaimed", "still unclaimed after a partial reveal");
    assert.equal(s.coins.length, 2);
    assert.equal(s.coins.filter((c) => c.spent).length, 1);
    const left = GHOST - GHOST / 4n - SPEC_FEE;
    assert.equal(s.current.amount, left);
    assert.equal(s.current.number, 1n);

    // More coins after the remainder, then block 76.
    node.foreignCommits(1);
    node.mineTo(76);

    // --- Claim ---
    const newKey = await flow.claimStart();
    assert.match(newKey, /^[a-z]+( [a-z]+){23}$/);
    assert.notEqual(newKey, key);
    const claimPositions = flow.claimSaved();
    const claimWrong = answersFor(newKey, claimPositions);
    claimWrong[0] = mistype(claimWrong[0]);
    assert.equal((await flow.claimCheck(claimWrong)).ok, false);
    assert.equal(node.reveals.length, 1, "a wrong re-type of the new key sends no claim");
    const claimed = await flow.claimCheck(answersFor(newKey, claimPositions));
    assert.equal(claimed.ok, true);
    assert.equal(claimed.amount, left - SPEC_FEE);
    assert.equal(node.reveals.length, 2);
    assert.equal(node.reveals[1].out, 0n, "a claim sends nothing out");
    assert.equal(toHex(node.reveals[1].recipient), "0x0000000000000000000000000000000000000000");
    assert.equal(flow.state.summon.status, "claimed");
    assert.equal(flow.state.summon.claim.stage, "done");
    assert.equal(flow.state.summon.claim.key, null);

    // Opened afresh, the old key shows claimed from the chain's markers...
    s = await flow.summonOpen(key);
    assert.equal(s.status, "claimed");
    assert.equal(s.current, null);
    // ...and the new key holds the value, unclaimed.
    s = await flow.summonOpen(newKey);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.amount, left - SPEC_FEE);
    assert.equal(s.current.number, 0n);
    flow.summonClose();

    // --- Nothing secret left the app ---
    const traffic = node.requests;
    assert.ok(node.requests.length > 0);
    for (const r of node.requests) assert.ok(ENDPOINT_METHODS.has(r.method), `unexpected method ${r.method}`);
    for (const secretKey of [key, newKey]) {
      for (const r of traffic) {
        assert.ok(!r.body.includes(secretKey), "a whole key was sent");
        for (const run of wordRuns(secretKey)) assert.ok(!r.body.toLowerCase().includes(run), `key words were sent in ${r.method}`);
      }
    }
    for (const r of node.requests) {
      assert.ok(!r.body.toLowerCase().includes(ourCommitment.slice(2)), `${r.method} named the coin's commitment`);
    }
    // Tree data only ever in whole pages from page 0, as of a block hash.
    for (const r of node.requests.filter((x) => x.method === "ghost_getTreePage")) {
      assert.equal(r.params.length, 4);
      assert.equal(r.params[2], "0x0", "the internal network's tree fits one page");
      assert.match(r.params[3], /^0x[0-9a-f]{64}$/);
    }
    // Block receipts only by the hash of a block of the chain, each block
    // once, from genesis to the last tip read, in chain order.
    const blockHashes = node.blocks.map((b) => toHex(b.hash));
    const asked = node.requests.filter((x) => x.method === "eth_getBlockReceipts").map((r) => r.params);
    assert.ok(asked.every((params) => params.length === 1), "one block hash per request");
    assert.deepEqual(
      asked.map(([hash]) => hash),
      blockHashes.slice(0, asked.length),
      "every block from genesis on, once each, in order",
    );
  } finally {
    prover.terminate();
    await node.close();
  }
});

// A stand-in node, a scripted wallet and a flow on them, with strangers'
// coins on the chain. While the app waits the chain grows by a block, unless
// `chain.mining` is set to false.
// How long the app waits before it sends a refused reveal again.
const RESEND_MS = 3;
// Proofs of one reveal the app makes here before a head-moving refusal
// surfaces: a few, since each is a real proof (the app's own bound is
// generous, and reveal-moving-head.test.mjs covers it with a stub prover).
const PROOFS = 4;

async function setUp({ fetch = globalThis.fetch, now = () => Date.now() } = {}) {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const worker = nodeProver();
  // Every worker request, with how many endpoint requests came before it
  // started and after it ended, and how long it took.
  const work = [];
  // `hooks.prove(args)`, when set, runs before each proof and gives the
  // arguments the worker is sent.
  const hooks = { prove: null };
  const prover = {
    request(op, args, onProgress) {
      if (op === "prove" && hooks.prove) args = hooks.prove(args);
      const at = node.requests.length;
      const started = performance.now();
      return worker.request(op, args, onProgress).finally(() => {
        work.push({
          op,
          decoy: Boolean(args && args.decoy),
          position: args?.position,
          number: args?.number,
          at,
          end: node.requests.length,
          ms: performance.now() - started,
        });
      });
    },
  };
  const chain = { mining: true };
  // While the app waits for a block, the chain grows by one; while it waits
  // before a resend, time passes and only the stand-in's own miner moves it.
  const sleep = async (ms) => {
    if (ms === RESEND_MS) return new Promise((resolve) => setTimeout(resolve, ms));
    if (chain.mining) node.mine();
  };
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks: node.networks(),
    pollMs: 5,
    maxPolls: 20,
    resendMs: RESEND_MS,
    headMovedProofs: PROOFS,
    sleep,
    now,
    fetch,
  });
  await openTestWallet(flow, node);
  node.foreignCommits(2);
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { node, flow, chain, work, hooks, done };
}

// The endpoint's requests since request `from`, with the worker requests
// since worker request `fromWork` in their place among them: what the
// endpoint can time.
function timeline(node, work, from, fromWork) {
  const events = [];
  const ops = work.slice(fromWork);
  for (let i = from; i <= node.requests.length; i += 1) {
    for (const w of ops.filter((x) => x.at === i)) events.push(`worker:${w.op}`);
    if (i < node.requests.length) events.push(JSON.stringify([node.requests[i].method, node.requests[i].params]));
  }
  return events;
}

// A timeline with block hashes left out and block numbers (but genesis)
// counted from block `base`, so that runs from tips the same distance past
// the start of a fee window compare.
function relative(events, base) {
  return events.map((e) =>
    e
      .replace(/0x[0-9a-f]{64}/g, "0xhash")
      .replace(/^\["eth_getBlockByNumber",\["(0x[0-9a-f]+)"/, (_, n) => {
        const number = Number(BigInt(n));
        return `["eth_getBlockByNumber",["${number === 0 ? "genesis" : `base${number - base >= 0 ? "+" : ""}${number - base}`}"`;
      }),
  );
}

// Vanish of `amount` GHOST with a right save check; the new key.
async function vanish(flow, amount) {
  const key = await flow.vanishStart(amount);
  const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
  assert.equal(sent.ok, true);
  return key;
}

// What the endpoint saw since request `from`, without the JSON-RPC ids.
const seen = (node, from) => node.requests.slice(from).map((r) => JSON.stringify([r.method, r.params]));

// Claims the coin of `key` from another device: a second flow, with its own
// worker, on the same stand-in, whose build pins a recent header (so it
// checks few seals). A page that opened `key` before still shows the coin,
// which its next scan finds spent.
async function claimElsewhere(node, key) {
  const prover = nodeProver();
  // Below the settled block, so the coin, older than the pin, counts as
  // followed by the leaves the settled tree holds.
  const networks = node.networks({ pinAt: node.tip() - 4 });
  const elsewhere = createFlow({ prover, endpoint: node.url, networks, pollMs: 5, maxPolls: 20, sleep: async () => node.mine() });
  try {
    assert.equal((await elsewhere.summonOpen(key)).status, "unclaimed");
    const newKey = await elsewhere.claimStart();
    assert.equal((await elsewhere.claimCheck(answersFor(newKey, elsewhere.claimSaved()))).ok, true);
  } finally {
    prover.terminate();
  }
}

// A reveal of the open key, which holds no unspent coin any more, refused
// once: its scan reads the blocks added since the page last looked, so the
// next attempt starts from the same tip with the same receipts held.
async function noCoinAttempt(flow) {
  await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /holds no unspent coin/);
}

test("the requests do not depend on whether the key owns a coin", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    const owner = await vanish(flow, "1");
    const other = await vanish(flow, "1");
    node.foreignCommits(1);
    node.mineTo(44);
    assert.equal((await flow.summonOpen(other)).status, "unclaimed");

    // The other key's coin is claimed from another device: this page still
    // shows it, and its next reveal finds no unspent coin. Every note the
    // endpoint serves is honest, as the block receipts require.
    await claimElsewhere(node, other);
    await noCoinAttempt(flow);

    let from = node.requests.length;
    let fromWork = work.length;
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /holds no unspent coin/);
    const notOwner = seen(node, from);
    const notOwnerTimes = timeline(node, work, from, fromWork);
    const notOwnerProofs = work.slice(fromWork).filter((w) => w.op === "prove");
    assert.equal(notOwnerProofs.length, 1, "a key with no coin still has a proof made");
    assert.equal(notOwnerProofs[0].decoy, true, "of a decoy");

    from = node.requests.length;
    assert.equal((await flow.summonOpen(owner)).status, "unclaimed");
    const openOwner = seen(node, from);
    from = node.requests.length;
    assert.equal((await flow.summonOpen(other)).status, "claimed");
    assert.deepEqual(seen(node, from), openOwner, "opening a key asks the same whether it owns the coin or not");

    // Back on the owner's key, a reveal that fails after restore found the
    // coin: the endpoint sees exactly what it saw for the key without one.
    await flow.summonOpen(owner);
    from = node.requests.length;
    fromWork = work.length;
    await assert.rejects(flow.summonReveal({ amount: "5", recipient: RECIPIENT }), /at most/);
    const owned = seen(node, from);
    assert.ok(owned.some((r) => r.startsWith('["eth_getBlockByNumber"')), "the settled and fee headers are fetched");
    assert.deepEqual(owned, notOwner, "a failed reveal asks the same whether the key owns the coin or not");
    assert.deepEqual(
      timeline(node, work, from, fromWork),
      notOwnerTimes,
      "the worker does the same work at the same place among the requests whether the key owns the coin or not",
    );
    assert.deepEqual(
      work.slice(fromWork).filter((w) => w.op === "prove").map((w) => w.decoy),
      [true],
      "a reveal that cannot be made proves a decoy",
    );
    assert.equal(node.reveals.length, 1, "only the claim from the other device");

    // A reveal that goes through: up to the reveal itself, the endpoint
    // sees what it saw when the key held no coin and the app gave up.
    assert.ok(notOwner.at(-1).startsWith('["eth_getBlockByNumber"'), "the abort path asks for the tip and fee headers");
    from = node.requests.length;
    fromWork = work.length;
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const revealed = seen(node, from);
    const sentAt = revealed.findIndex((r) => r.startsWith('["eth_sendRawTransaction"'));
    assert.ok(sentAt > 0);
    assert.deepEqual(revealed.slice(0, sentAt), notOwner, "the requests before the reveal do not depend on what restore found");
    const revealedTimes = timeline(node, work, from, fromWork);
    const sentEvent = revealedTimes.findIndex((r) => r.startsWith('["eth_sendRawTransaction"'));
    assert.deepEqual(revealedTimes.slice(0, sentEvent), notOwnerTimes, "nor does where the proof work falls among them");
    const real = work.slice(fromWork).filter((w) => w.op === "prove");
    assert.equal(real[0].decoy, false, "the reveal is a real proof");
    assert.equal(real[0].at, real[0].end, "no request is made while proving");
    // The delay before the next request is a proof's either way.
    assert.ok(
      notOwnerProofs[0].ms > real[0].ms / 4,
      `the decoy took ${Math.round(notOwnerProofs[0].ms)} ms, the real proof ${Math.round(real[0].ms)} ms`,
    );
    assert.equal(node.reveals.length, 2);
  } finally {
    await done();
  }
});

test("a refused proof and a fee change leave the requests and their timing as for a key without a coin", async () => {
  const { node, flow, work, hooks, done } = await setUp();
  const GWEI = 10n ** 9n;
  try {
    const owner = await vanish(flow, "1");
    const other = await vanish(flow, "1");
    node.foreignCommits(1);
    node.mineTo(44);
    assert.equal((await flow.summonOpen(other)).status, "unclaimed");
    // The other key's coin is claimed from another device, so the page's
    // reveal of it finds no unspent coin. Each attempt starts at the start of
    // a fee window, with the receipts of every block to it already held.
    await claimElsewhere(node, other);
    node.mineTo(76);
    await noCoinAttempt(flow);

    // While the first proof of an attempt is made, the next fee window's
    // blocks arrive with a higher base fee, so the fee changes and the
    // reveal is proved again.
    let baseFee = GWEI;
    const feeChange = () => {
      let first = true;
      return (args) => {
        if (first) {
          first = false;
          baseFee += GWEI;
          node.setBaseFee(baseFee);
          for (let i = 0; i < 4; i += 1) node.mine();
        }
        return args;
      };
    };
    const attempt = async (base) => {
      const from = node.requests.length;
      const fromWork = work.length;
      const outcome = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }).then(
        () => null,
        (err) => err,
      );
      const events = relative(timeline(node, work, from, fromWork), base);
      return { outcome, events, proofs: work.slice(fromWork).filter((w) => w.op === "prove") };
    };

    // The key without a coin: a decoy proved for each attempt.
    hooks.prove = feeChange();
    const none = await attempt(76);
    assert.match(none.outcome.message, /holds no unspent coin/);
    assert.deepEqual(none.proofs.map((p) => p.decoy), [true, true], "a decoy for the first attempt and for the retry");

    // The owner's key, with every real proof refused in the worker (its
    // coin not under the root it is sent): the same requests at the same
    // places among the worker's work, and each refusal takes a proof's time.
    node.foreignCommits(1);
    node.mineTo(108);
    assert.equal((await flow.summonOpen(owner)).status, "unclaimed");
    const change = feeChange();
    hooks.prove = (args) => {
      change(args);
      if (args.decoy) return args;
      const root = Uint8Array.from(args.root);
      root[0] ^= 1;
      return { ...args, root };
    };
    const refused = await attempt(108);
    assert.match(refused.outcome.message, /not in the tree/);
    assert.deepEqual(refused.proofs.map((p) => p.decoy), [false, false], "the coin's own proof, twice");
    assert.deepEqual(refused.events, none.events, "a refused proof and a retry ask the same, in the same order");
    for (const p of refused.proofs) {
      assert.ok(
        p.ms > none.proofs[0].ms / 4,
        `a refused proof took ${Math.round(p.ms)} ms, a decoy ${Math.round(none.proofs[0].ms)} ms`,
      );
    }
    assert.equal(node.reveals.length, 1, "only the claim from the other device");

    // The owner's key again, proved after the retry: up to the reveal, the
    // same as without a coin.
    node.foreignCommits(1);
    node.mineTo(140);
    assert.equal((await flow.summonOpen(owner)).status, "unclaimed");
    hooks.prove = feeChange();
    const made = await attempt(140);
    assert.equal(made.outcome, null);
    const sentAt = made.events.findIndex((e) => e.startsWith('["eth_sendRawTransaction"'));
    assert.ok(sentAt > 0);
    assert.deepEqual(made.events.slice(0, sentAt), none.events, "the retried reveal asks the same before it is sent");
    assert.deepEqual(made.proofs.map((p) => p.decoy), [false, false]);
    assert.equal(node.reveals.length, 2);
    assert.ok(node.reveals[1].fee > SPEC_FEE, "the reveal carries the raised fee");
  } finally {
    await done();
  }
});

test("a fabricated receipt does not confirm a claim the chain does not hold", async () => {
  const { node, flow, done } = await setUp();
  try {
    const key = await vanish(flow, "1");
    // A later commitment after block 40, then block 77 and on.
    node.mineTo(40);
    node.foreignCommits(1);
    node.mineTo(80);
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
    const newKey = await flow.claimStart();
    const positions = flow.claimSaved();

    // The endpoint withholds the claim, returns its hash, and answers the
    // receipt lookup with a success in a block mined after it was sent.
    node.dishonest.withhold = () => ({ status: "0x1", blockNumber: `0x${node.mine().toString(16)}` });
    await assert.rejects(flow.claimCheck(answersFor(newKey, positions)), /has not settled/);
    assert.equal(node.withheld.length, 1, "the claim reached the endpoint");
    assert.equal(node.reveals.length, 0, "and was never executed");
    const s = flow.state.summon;
    assert.notEqual(s.claim.stage, "done");
    assert.equal(s.status, "unclaimed", "the old key stays unclaimed");
    assert.ok(s.current, "and still shows its coin");

    // A receipt naming a block the chain does not have is refused too, as is
    // one naming block 77, which was in the chain before the claim was sent;
    // a fresh look at the key still shows it unclaimed.
    for (const [blockNumber, refusal] of [
      ["0x400", /not a block of the chain/],
      ["0x4d", /before the transaction was sent/],
    ]) {
      node.dishonest.withhold = () => ({ status: "0x1", blockNumber });
      await flow.claimStart();
      const again = flow.claimSaved();
      await assert.rejects(flow.claimCheck(answersFor(flow.state.summon.claim.key, again)), refusal);
      assert.notEqual(flow.state.summon.claim.stage, "done");
    }
    assert.equal(node.reveals.length, 0);
    assert.equal((await flow.summonRefresh()).status, "unclaimed");
  } finally {
    await done();
  }
});

// A key with a coin old enough to claim, opened, and a new key whose save
// check is under way; the right answers for it.
async function readyToClaim(node, flow) {
  const key = await vanish(flow, "1");
  node.mineTo(40);
  node.foreignCommits(1);
  node.mineTo(80);
  assert.equal((await flow.summonOpen(key)).status, "unclaimed");
  const newKey = await flow.claimStart();
  return answersFor(newKey, flow.claimSaved());
}

test("headers whose coin root was altered under their real hash are refused", async () => {
  const { node, flow, done } = await setUp();
  try {
    const answers = await readyToClaim(node, flow);
    // The endpoint withholds the claim and serves, from a new block on, a
    // coin tree that holds the claim's new coin, with each header's
    // coinTreeRoot set to that tree's root and its hash left as it was.
    node.dishonest.withhold = (hash, reveal) => {
      const block = node.mine();
      node.dishonest.forge = { from: block, extra: [{ commitment: reveal.remainder, note: reveal.note }] };
      return { transactionHash: hash, status: "0x1", blockNumber: `0x${block.toString(16)}` };
    };
    await assert.rejects(flow.claimCheck(answers), /does not hash to/);
    assert.equal(node.withheld.length, 1);
    assert.equal(node.reveals.length, 0, "the claim was never executed");
    assert.notEqual(flow.state.summon.claim.stage, "done");
    assert.equal(flow.state.summon.status, "unclaimed");
    // A fresh look at the key refuses the altered tip header too.
    await assert.rejects(flow.summonRefresh(), /does not hash to/);
    assert.equal(flow.state.summon.status, "unclaimed");
  } finally {
    await done();
  }
});

test("a claim is Done, and the old key claimed, at the first block that holds it", async () => {
  const { node, flow, chain, done } = await setUp();
  try {
    const answers = await readyToClaim(node, flow);
    // No block is mined while the app waits: only the claim's own block.
    chain.mining = false;
    const claimed = await flow.claimCheck(answers);
    assert.equal(node.reveals.length, 1, "the claim is in a block");
    const block = node.reveals[0].block;
    assert.equal(node.tip(), block, "no block on top of the claim's");
    assert.equal(claimed.block, block);
    const s = flow.state.summon;
    assert.equal(s.claim.stage, "done");
    assert.equal(s.status, "claimed", "the old key shows claimed at the claim's own block");
    assert.equal((await flow.summonRefresh()).status, "claimed");
    assert.equal(node.tip(), block);
  } finally {
    await done();
  }
});

test("a coin is summoned 2 blocks after a later commit, and a coin nobody followed waits", async () => {
  const { node, flow, done } = await setUp();
  try {
    const lonely = await vanish(flow, "1");
    // Nobody has committed since: the app warns plainly and waits.
    node.mineTo(node.tip() + 10);
    let s = await flow.summonOpen(lonely);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.cover, null);
    assert.equal(s.wait.alone, true);
    assert.match(s.wait.message, /^nobody has committed a coin since this one/);
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => err instanceof WaitError && err.alone);
    assert.equal(node.reveals.length, 0, "never proved against its own block root");

    // A stranger commits in block `block`; one block later it is not yet
    // settled, two blocks later the coin can be revealed against its root.
    node.foreignCommits(1);
    const block = node.tip();
    s = await flow.summonOpen(lonely);
    assert.equal(s.wait.alone, false);
    assert.match(s.wait.message, new RegExp(`revealed from block ${block + 2}`));
    node.mineTo(block + 2);
    s = await flow.summonOpen(lonely);
    assert.equal(s.wait, null);
    assert.deepEqual(s.cover, { height: block, covers: node.leaves.length, total: node.leaves.length });
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(node.reveals.length, 1);
    assert.equal(toHex(node.reveals[0].root), toHex(node.blocks[block].coinTreeRoot), "the root of the stranger's block");
    assert.ok(reveal.block > block + 2);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
  } finally {
    await done();
  }
});

// A key with a coin old enough to reveal, opened at block 80.
async function readyToReveal(node, flow) {
  const key = await vanish(flow, "1");
  node.mineTo(40);
  node.foreignCommits(1);
  node.mineTo(80);
  assert.equal((await flow.summonOpen(key)).status, "unclaimed");
}

// A reveal or claim sent (type 0x50), not the commit's account transaction.
const isRevealSend = (call) => call.method === "eth_sendRawTransaction" && String(call.params?.[0]).startsWith("0x50");
const sendsIn = (requests) => requests.filter(isRevealSend);

// The node refuses a reveal it could not check on a head that stayed put
// (`chain head kept moving while the reveal was checked`); the app sends it
// again, and only after that refusal asks anything more.
test("a reveal the node refuses while its head keeps moving is sent again, the same envelope at the same fee", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    await readyToReveal(node, flow);
    // A block arrives during each of the node's checks; the fee window
    // stays, so the proof's fee is still the one in force.
    node.moveHeadOnReveal(2, { blocks: 1 });
    const from = node.requests.length;
    const fromWork = work.length;
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const asked = node.requests.slice(from);
    const sends = sendsIn(asked);
    assert.equal(node.headMoving.refused, 2);
    assert.equal(sends.length, 3, "two refused sends, then the one the node takes");
    assert.equal(new Set(sends.map((r) => r.params[0])).size, 1, "the same envelope each time");
    assert.equal(work.slice(fromWork).filter((w) => w.op === "prove").length, 1, "proved once");
    assert.equal(node.reveals.length, 1);
    assert.equal(node.reveals[0].fee, SPEC_FEE);
    assert.ok(reveal.block > 82, "settled after the blocks mined during the refusals");
    // Between two sends: the tip once, after a short wait, then its header
    // and the fee window's.
    const first = asked.indexOf(sends[0]);
    const second = asked.indexOf(sends[1]);
    const between = asked.slice(first + 1, second).map((r) => r.method);
    assert.equal(between[0], "eth_blockNumber", "the tip once");
    assert.ok(between.length > 1 && between.slice(1).every((m) => m === "eth_getBlockByNumber"));
  } finally {
    await done();
  }
});

// geth's own reply to a refused send, byte for byte: HTTP 200, code -32000
// and the pool's words unwrapped (ghost-node ghostpool errHeadMoving, through
// TxPool.Add, SendTx and SubmitTransaction), then a newline.
const gethHeadMoved = (id) =>
  `{"jsonrpc":"2.0","id":${id},"error":{"code":-32000,"message":"chain head kept moving while the reveal was checked"}}\n`;

test("the stand-in refuses a reveal while its head moves with geth's JSON-RPC reply", async () => {
  const replies = [];
  const fetch = async (url, init) => {
    const response = await globalThis.fetch(url, init);
    const call = JSON.parse(init.body);
    if (isRevealSend(call)) {
      replies.push({ id: call.id, status: response.status, text: await response.clone().text() });
    }
    return response;
  };
  const { node, flow, done } = await setUp({ fetch });
  try {
    await readyToReveal(node, flow);
    node.moveHeadOnReveal(1, { blocks: 1 });
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(replies.length, 2);
    assert.equal(replies[0].status, 200);
    assert.deepEqual(JSON.parse(replies[0].text), JSON.parse(gethHeadMoved(replies[0].id)));
    assert.equal(node.reveals.length, 1);
  } finally {
    await done();
  }
});

test("a reveal refused with geth's own reply bytes is sent again", async () => {
  let node = null;
  const sends = [];
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (isRevealSend(call)) {
      sends.push(call.params[0]);
      if (sends.length === 1) {
        // The head moves while geth checks the reveal; the fee window stays.
        node.mine();
        return new Response(gethHeadMoved(call.id), { status: 200, headers: { "content-type": "application/json" } });
      }
    }
    return globalThis.fetch(url, init);
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, done } = set;
  try {
    await readyToReveal(node, flow);
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(sends.length, 2, "the refused send, then the one the node takes");
    assert.equal(sends[0], sends[1], "the same envelope");
    assert.equal(node.reveals.length, 1);
    assert.equal(flow.state.error, null);
  } finally {
    await done();
  }
});

// An endpoint that broadcasts the reveal, waits until its remainder can be
// revealed at another fee and only then answers with the head-moving
// refusal must not get a second payment: a new proof is only ever of the
// first proof's coin, and that coin is spent.
test("a reveal the endpoint took before it answered that the head moved is not paid again from the remainder", async () => {
  let node = null;
  const sends = [];
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (isRevealSend(call)) {
      sends.push(call.params[0]);
      const response = await globalThis.fetch(url, init);
      if (sends.length === 1) {
        assert.equal((await response.json()).error, undefined, "the node took the first send");
        const block = node.reveals[0].block;
        node.setBaseFee(2n * 10n ** 9n);
        node.mineTo(block + 40);
        node.foreignCommits(1);
        node.mineTo(block + 80);
        return new Response(gethHeadMoved(call.id), { status: 200, headers: { "content-type": "application/json" } });
      }
      return response;
    }
    return globalThis.fetch(url, init);
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, work, done } = set;
  try {
    await readyToReveal(node, flow);
    const fromWork = work.length;
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /no longer unspent/);
    assert.equal(sends.length, 1, "nothing is sent again");
    assert.equal(node.reveals.length, 1, "one reveal is in a block");
    assert.equal(node.balances.get(RECIPIENT.toLowerCase()), 25n * 10n ** 16n, "the recipient is paid once");
    assert.ok(
      work.slice(fromWork).filter((w) => w.op === "prove").every((w, i) => i === 0 || w.decoy),
      "the remainder is never proved",
    );
    assert.match(flow.state.error, /no longer unspent/);
  } finally {
    await done();
  }
});

test("a reveal refused while the head moves is proved again once the fee changed", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    await readyToReveal(node, flow);
    // The blocks that arrive during the node's check open a fee window at a
    // higher base fee: the proof's fee is no longer in force.
    node.setBaseFee(2n * 10n ** 9n);
    node.moveHeadOnReveal(1, { blocks: 4 });
    const from = node.requests.length;
    const fromWork = work.length;
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const sends = sendsIn(node.requests.slice(from));
    assert.equal(sends.length, 2);
    assert.notEqual(sends[0].params[0], sends[1].params[0], "a new envelope");
    assert.deepEqual(work.slice(fromWork).filter((w) => w.op === "prove").map((w) => w.decoy), [false, false]);
    assert.equal(node.reveals.length, 1);
    assert.ok(node.reveals[0].fee > SPEC_FEE, "the reveal carries the raised fee");
  } finally {
    await done();
  }
});

// The CI node seals a block every 20 ms; the app sends one proof up to 5
// times, after one short wait and one look at the tip each time, so a fifth
// send the node takes lands.
test("a reveal the node refuses 4 times while its head moves is taken on its fifth send", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    await readyToReveal(node, flow);
    node.moveHeadOnReveal(4, { blocks: 1 });
    const from = node.requests.length;
    const fromWork = work.length;
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const asked = node.requests.slice(from);
    const sends = sendsIn(asked);
    assert.equal(node.headMoving.refused, 4);
    assert.equal(sends.length, 5, "four refused sends, then the one the node takes");
    assert.equal(new Set(sends.map((r) => r.params[0])).size, 1, "the same envelope each time");
    assert.equal(work.slice(fromWork).filter((w) => w.op === "prove").length, 1, "proved once");
    for (let i = 1; i < sends.length; i += 1) {
      const between = asked.slice(asked.indexOf(sends[i - 1]) + 1, asked.indexOf(sends[i]));
      assert.equal(between.filter((r) => r.method === "eth_blockNumber").length, 1, `one look at the tip before send ${i + 1}`);
    }
    assert.equal(node.reveals.length, 1);
    assert.equal(flow.state.error, null);
  } finally {
    await done();
  }
});

// A node that keeps sealing a block every MINING_MS and refuses the first
// sends: its head never holds still, and the app's reveal is still taken
// while the node mines, without waiting for a still tip. (The page checks
// the seal of every header it adopts, about a quarter of a second each here,
// so the stand-in seals more slowly than that.)
const MINING_MS = 400;
test("a reveal refused while the node keeps mining goes through without its head holding still", async () => {
  let node = null;
  let takenWhileMining = null;
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (isRevealSend(call) && node.headMoving.refused === 0 && !node.headMoving.miner) {
      node.startMining(MINING_MS, { refuse: false });
      node.moveHeadOnReveal(2, { blocks: 1 });
    }
    const mining = node !== null && node.headMoving.miner !== null;
    const response = await globalThis.fetch(url, init);
    if (isRevealSend(call) && !(await response.clone().json()).error) takenWhileMining = mining;
    return response;
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, work, done } = set;
  try {
    await readyToReveal(node, flow);
    const fromWork = work.length;
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(node.headMoving.refused, 2, "refused while the node mined");
    assert.equal(takenWhileMining, true, "taken while the node still mined");
    const proofs = work.slice(fromWork).filter((w) => w.op === "prove");
    assert.ok(proofs.length >= 1 && proofs.length <= PROOFS);
    assert.ok(proofs.every((w) => !w.decoy && w.position === proofs[0].position), "each time of the same coin");
    assert.equal(node.reveals.length, 1);
  } finally {
    node.stopMining();
    await done();
  }
});

test("a reveal refused on every send of every proof while the head keeps moving surfaces the node's refusal", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    await readyToReveal(node, flow);
    node.moveHeadOnReveal(1000, { blocks: 1 });
    const from = node.requests.length;
    const fromWork = work.length;
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /kept moving/);
    const asked = node.requests.slice(from);
    const sends = sendsIn(asked);
    assert.equal(sends.length, HEAD_MOVED_SENDS * PROOFS, "at most 5 sends of each of the proofs");
    assert.equal(node.headMoving.refused, HEAD_MOVED_SENDS * PROOFS);
    assert.equal(asked.at(-1).method, "eth_sendRawTransaction", "nothing is asked after the last refusal");
    const proofs = work.slice(fromWork).filter((w) => w.op === "prove");
    assert.equal(proofs.length, PROOFS, "proved again after each proof's 5 refused sends, up to the bound");
    assert.ok(
      proofs.every((w) => !w.decoy && w.position === proofs[0].position && w.number === proofs[0].number),
      "each time of the same coin",
    );
    for (let p = 0; p < PROOFS; p += 1) {
      const own = sends.slice(p * HEAD_MOVED_SENDS, (p + 1) * HEAD_MOVED_SENDS).map((r) => r.params[0]);
      assert.equal(new Set(own).size, 1, `proof ${p + 1}'s envelope, 5 times`);
      if (p > 0) assert.notEqual(own[0], sends[(p - 1) * HEAD_MOVED_SENDS].params[0], `proof ${p + 1} is a new envelope`);
    }
    assert.equal(node.reveals.length, 0);
    assert.match(flow.state.error, /kept moving/);
  } finally {
    await done();
  }
});

test("any other refusal of a reveal is final", async () => {
  let refusals = 0;
  let askedBefore = null;
  let node = null;
  // An endpoint that refuses each reveal with another -32000 error.
  const fetch = async (url, init) => {
    if (isRevealSend(JSON.parse(init.body))) {
      refusals += 1;
      askedBefore = node.requests.length;
      const error = { code: -32000, message: "chain head moved" };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error }), { status: 200 });
    }
    return globalThis.fetch(url, init);
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, done } = set;
  try {
    await readyToReveal(node, flow);
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => err.message === "chain head moved");
    assert.equal(refusals, 1, "sent once");
    assert.equal(node.requests.length, askedBefore, "nothing is asked after the refusal");
    assert.equal(node.reveals.length, 0);
  } finally {
    await done();
  }
});

test("a commit the node takes but answers with an error is shown Sent, and one it does not take is refused", async () => {
  const { node, flow, done } = await setUp();
  try {
    node.quirks.errorAfterAccountTx = true;
    const key = await flow.vanishStart("1");
    const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
    assert.equal(sent.ok, true);
    assert.equal(sent.txHash, node.accountTxs[0].hash);
    assert.equal(flow.state.vanish.stage, "done");
    // A refusal the node means: nothing is held, the error stands.
    node.quirks.errorAfterAccountTx = false;
    node.quirks.refuseAccountTx = true;
    const again = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(again, flow.vanishSaved())), /txpool is full/);
    assert.equal(node.accountTxs.length, 1);
    // An endpoint that asks for a large priority fee or gas: the priority
    // fee is held at its cap, and gas above the cap is refused unsigned.
    node.quirks.refuseAccountTx = false;
    node.quirks.priorityFee = 1000n * PRIORITY_FEE_CAP;
    const capped = await flow.vanishStart("1");
    assert.equal((await flow.vanishCheck(answersFor(capped, flow.vanishSaved()))).ok, true);
    assert.equal(node.accountTxs[1].maxPriorityFeePerGas, PRIORITY_FEE_CAP);
    node.quirks.estimateGas = COMMIT_GAS_CAP;
    const heavy = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(heavy, flow.vanishSaved())), /more than the 500000 the app signs/);
    node.quirks.estimateGas = null;
    node.setBaseFee(10n ** 12n);
    node.mine();
    const pricey = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(pricey, flow.vanishSaved())), /more than the 0\.01 GHOST the app signs/);
    assert.equal(node.accountTxs.length, 2);
    // A balance that cannot pay: nothing is signed or sent.
    node.setBaseFee(10n ** 9n);
    node.mine();
    node.fund(TEST_WALLET_ADDRESS, 0n);
    const sends = node.requests.filter((r) => r.method === "eth_sendRawTransaction").length;
    const third = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(third, flow.vanishSaved())), /less than the amount/);
    assert.equal(node.requests.filter((r) => r.method === "eth_sendRawTransaction").length, sends);
  } finally {
    await done();
  }
});

test("the built-in endpoint is the local internal network", () => {
  const flow = createFlow({ prover: { request: async () => ({}) } });
  assert.equal(flow.state.endpoint, new URL(DEFAULT_ENDPOINT).href);
  assert.match(DEFAULT_ENDPOINT, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.throws(() => flow.setEndpoint("ftp://example.org"), /http or https/);
  assert.throws(() => flow.setEndpoint("https://user:pw@example.org"), /user name/);
  assert.equal(flow.setEndpoint("https://node.example.org/rpc"), "https://node.example.org/rpc");
  assert.throws(() => flow.setCommitEntry(ZERO_ADDRESS), /zero address/);
  assert.equal(flow.state.commitEntry, DEFAULT_COMMIT_ENTRY, "a refused entry leaves the setting as it was");
  assert.equal(flow.setCommitEntry(RECIPIENT), RECIPIENT);
});

test("index.html loads only same-origin scripts and names no external URL", async () => {
  const html = await readFile(resolve(webappDir, "index.html"), "utf8");
  assert.doesNotMatch(html, /https?:\/\//i, "no absolute http URL");
  assert.doesNotMatch(html, /(src|href)\s*=\s*["']?\/\//i, "no protocol-relative URL");
  const scripts = [...html.matchAll(/<script\b([^>]*)>/gi)].map((m) => m[1]);
  assert.ok(scripts.length >= 1);
  for (const attrs of scripts) {
    const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs);
    assert.ok(src, "no inline script");
    assert.match(src[1], /^\.?\/?[\w./-]+\.mjs$/, `script ${src[1]} is not a same-origin module`);
  }
  for (const m of html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
    assert.doesNotMatch(m[1], /^[a-z][a-z0-9+.-]*:/i, `${m[1]} is not same-origin`);
  }
  const csp = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i.exec(html);
  assert.ok(csp, "a Content-Security-Policy");
  assert.match(csp[1], /script-src 'self'/);
  assert.match(csp[1], /default-src 'none'|default-src 'self'/);
});
