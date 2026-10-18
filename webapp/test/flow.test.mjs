// The proof of done: the app's flow controller, driven headless through
// Vanish (with a save check that first fails, then passes), a partial
// Summon and a Claim, with the real prover built for wasm32-unknown-unknown
// running in a worker_threads worker through the browser worker's message
// interface, against the scripted node stand-in. The stand-in verifies each
// reveal's proof with the real verifier before it accepts it, and records
// every request so the test can check that no key digit or secret reached
// the endpoint or the wallet.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, ZERO_ADDRESS, createFlow } from "../src/flow.mjs";
import { DEFAULT_ENDPOINT } from "../src/rpc.mjs";
import { loadModule, nodeProver, webappDir } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
// Spec 07, vector window-genesis: the fee at a base fee of 1 gwei.
const SPEC_FEE = 25_954_253_644_941_297n;
const ACCOUNT = "0x1111111111111111111111111111111111111111";
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const ENDPOINT_METHODS = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getTransactionReceipt",
  "eth_sendRawTransaction",
  "ghost_getPageRoots",
  "ghost_getTreePage",
]);

function answersFor(key, positions) {
  const groups = key.split(" ");
  return positions.map((p) => groups[p - 1]);
}

// A group that differs from the right one in its last digit.
function mistype(group) {
  return group.slice(0, 3) + String((Number(group[3]) + 1) % 10);
}

// Every run of three groups of a key, without separators: no request may
// hold any of them.
function digitRuns(key) {
  const digits = key.replace(/\s/g, "");
  const runs = [];
  for (let i = 0; i + 12 <= digits.length; i += 4) runs.push(digits.slice(i, i + 12));
  return runs;
}

test("Vanish, a partial Summon and a Claim against the node stand-in", async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const wallet = node.wallet(ACCOUNT);
  const prover = nodeProver();
  const stages = [];
  const flow = createFlow({
    prover,
    wallet,
    endpoint: node.url,
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
    await flow.connectWallet();
    assert.equal(flow.state.wallet.account, ACCOUNT);

    // --- Vanish ---
    const key = await flow.vanishStart("1");
    assert.match(key, /^\d{4}( \d{4}){11}$/, "a standard key of twelve groups");
    assert.equal(flow.state.vanish.stage, "shown");
    assert.throws(() => flow.claimSaved(), /show the key first/);

    const positions = flow.vanishSaved();
    assert.equal(positions.length, 3);
    assert.equal(new Set(positions).size, 3, "three distinct groups");
    assert.deepEqual([...positions].sort((a, b) => a - b), positions, "asked in order");
    for (const p of positions) assert.ok(p >= 1 && p <= 12);

    // A wrong re-type blocks the commit: nothing reaches the wallet or the chain.
    const right = answersFor(key, positions);
    const wrong = [...right];
    wrong[1] = mistype(wrong[1]);
    const leavesBefore = node.leaves.length;
    const refused = await flow.vanishCheck(wrong);
    assert.deepEqual(refused, { ok: false, wrong: [positions[1]] });
    assert.equal(flow.state.vanish.stage, "check");
    assert.equal(wallet.calls.filter((c) => c.method === "eth_sendTransaction").length, 0);
    assert.equal(node.leaves.length, leavesBefore);
    assert.equal(node.commits.length, 0);

    // The right groups send it.
    const sent = await flow.vanishCheck(right);
    assert.equal(sent.ok, true);
    assert.equal(flow.state.vanish.stage, "confirmed");
    assert.equal(flow.state.vanish.key, null, "the app drops the key once the commit is sent");
    const sends = wallet.calls.filter((c) => c.method === "eth_sendTransaction");
    assert.equal(sends.length, 1);
    assert.equal(sends[0].params[0].to, DEFAULT_COMMIT_ENTRY);
    assert.equal(BigInt(sends[0].params[0].value), GHOST);
    assert.equal(node.commits.length, 1);
    const ourCommitment = toHex(node.commits[0].commitment);

    // Strangers' coins after ours, then enough blocks for epoch block 32.
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

    // More coins after the remainder, then epoch block 64.
    node.foreignCommits(1);
    node.mineTo(76);

    // --- Claim ---
    const newKey = await flow.claimStart();
    assert.match(newKey, /^\d{4}( \d{4}){11}$/);
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
    assert.equal(flow.state.summon.claim.stage, "confirmed");
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
    const traffic = [...node.requests, ...wallet.calls];
    assert.ok(node.requests.length > 0);
    for (const r of node.requests) assert.ok(ENDPOINT_METHODS.has(r.method), `unexpected method ${r.method}`);
    for (const secretKey of [key, newKey]) {
      for (const r of traffic) {
        assert.ok(!r.body.includes(secretKey), "a whole key was sent");
        for (const run of digitRuns(secretKey)) assert.ok(!r.body.includes(run), `key digits were sent in ${r.method}`);
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
  } finally {
    prover.terminate();
    await node.close();
  }
});

// A stand-in node, a scripted wallet and a flow on them, with strangers'
// coins on the chain. While the app waits the chain grows by a block, unless
// `chain.mining` is set to false.
async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const wallet = node.wallet(ACCOUNT);
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
        work.push({ op, decoy: Boolean(args && args.decoy), at, end: node.requests.length, ms: performance.now() - started });
      });
    },
  };
  const chain = { mining: true };
  const sleep = async () => {
    if (chain.mining) node.mine();
  };
  const flow = createFlow({ prover, wallet, endpoint: node.url, pollMs: 5, maxPolls: 20, sleep });
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
// an epoch block and a fee window compare.
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

test("altered notes cannot make the requests depend on whether the key owns a coin", async () => {
  const { node, flow, work, done } = await setUp();
  try {
    const owner = await vanish(flow, "1");
    const target = node.leaves.findIndex((l) => toHex(l.commitment) === toHex(node.commits[0].commitment));
    const other = await vanish(flow, "1");
    node.foreignCommits(1);
    node.mineTo(44);
    assert.equal((await flow.summonOpen(other)).status, "unclaimed");

    // The endpoint keeps every leaf and root but zeroes every note except
    // the targeted coin's: only the targeted coin's owner still finds one.
    node.dishonest.note = (position, note) => (position === target ? note : new Uint8Array(note.length));

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
    assert.equal((await flow.summonOpen(other)).status, "not-found");
    assert.deepEqual(seen(node, from), openOwner, "opening a key asks the same whether it owns the coin or not");

    // Back on the owner's key, a reveal that fails after restore found the
    // coin: the endpoint sees exactly what it saw for the key without one.
    await flow.summonOpen(owner);
    from = node.requests.length;
    fromWork = work.length;
    await assert.rejects(flow.summonReveal({ amount: "5", recipient: RECIPIENT }), /at most/);
    const owned = seen(node, from);
    assert.ok(owned.some((r) => r.startsWith('["eth_getBlockByNumber"')), "the epoch and fee headers are fetched");
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
    assert.equal(node.reveals.length, 0);

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
    assert.equal(node.reveals.length, 1);
  } finally {
    await done();
  }
});

test("a refused proof and a fee change leave the requests and their timing as for a key without a coin", async () => {
  const { node, flow, work, hooks, done } = await setUp();
  const GWEI = 10n ** 9n;
  try {
    const owner = await vanish(flow, "1");
    const target = node.leaves.findIndex((l) => toHex(l.commitment) === toHex(node.commits[0].commitment));
    const other = await vanish(flow, "1");
    node.foreignCommits(1);
    // Each attempt starts 12 blocks past an epoch block, at the start of a
    // fee window.
    node.mineTo(76);
    assert.equal((await flow.summonOpen(other)).status, "unclaimed");
    node.dishonest.note = (position, note) => (position === target ? note : new Uint8Array(note.length));

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
    assert.equal(node.reveals.length, 0);

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
    assert.equal(node.reveals.length, 1);
    assert.ok(node.reveals[0].fee > SPEC_FEE, "the reveal carries the raised fee");
  } finally {
    await done();
  }
});

test("a fabricated receipt does not confirm a claim the chain does not hold", async () => {
  const { node, flow, done } = await setUp();
  try {
    const key = await vanish(flow, "1");
    // A later commitment inside epoch window 32 to 64, then block 77 and on.
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
    assert.notEqual(s.claim.stage, "confirmed");
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
      assert.notEqual(flow.state.summon.claim.stage, "confirmed");
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
    assert.notEqual(flow.state.summon.claim.stage, "confirmed");
    assert.equal(flow.state.summon.status, "unclaimed");
    // A fresh look at the key refuses the altered tip header too.
    await assert.rejects(flow.summonRefresh(), /does not hash to/);
    assert.equal(flow.state.summon.status, "unclaimed");
  } finally {
    await done();
  }
});

test("a claim is confirmed, and the old key claimed, only with 6 blocks on top", async () => {
  const { node, flow, chain, done } = await setUp();
  try {
    const answers = await readyToClaim(node, flow);
    chain.mining = false;
    await assert.rejects(flow.claimCheck(answers), /blocks on top/);
    assert.equal(node.reveals.length, 1, "the claim is in a block");
    const s = flow.state.summon;
    assert.equal(s.claim.stage, "pending");
    assert.equal(s.status, "unclaimed");
    const block = node.reveals[0].block;
    node.mineTo(block + 5);
    assert.equal((await flow.summonRefresh()).status, "unclaimed", "five blocks on top are not enough");
    node.mineTo(block + 6);
    assert.equal((await flow.summonRefresh()).status, "claimed");
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
