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
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { ACCOUNT_EXTRA_GAS, DEFAULT_COMMIT_ENTRY, ZERO_ADDRESS, createFlow } from "../src/flow.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { COMMIT_ESTIMATE_GAS, PRIORITY_FEE, startFakeNode } from "./support/fake-node.mjs";
import {
  GHOST,
  SPEC_FEE,
  RECIPIENT,
  ENDPOINT_METHODS,
  answersFor,
  mistype,
  wordRuns,
  setUp,
  timeline,
  relative,
  vanish,
  seen,
  claimElsewhere,
  noCoinAttempt,
} from "./support/flow-setup.mjs";

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
    assert.equal(node.reveals[0].fee, SPEC_FEE, "the fee of spec 10 for a base fee of 1 gwei");
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
    const notOwnerProofs = work.slice(fromWork).filter((w) => w.op === "prove");
    assert.deepEqual(notOwnerProofs, [], "a key with no coin has no proof made");

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
      work.slice(fromWork).filter((w) => w.op === "prove"),
      [],
      "a reveal that cannot be made proves nothing",
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
    const real = work.slice(fromWork).filter((w) => w.op === "prove");
    assert.equal(real.length, 1, "one proof, of the coin");
    assert.equal(real[0].decoy, false, "the reveal is a real proof");
    assert.equal(real[0].at, real[0].end, "no request is made while proving");
    assert.equal(node.reveals.length, 2);
  } finally {
    await done();
  }
});

test("a refused proof and a fee change ask what a reveal that goes through asks; a key without a coin has nothing proved", async () => {
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

    // The key without a coin: nothing is proved, no stand-in proof either.
    hooks.prove = feeChange();
    const none = await attempt(76);
    assert.match(none.outcome.message, /holds no unspent coin/);
    assert.deepEqual(none.proofs, [], "no proof for a reveal that cannot be made");

    // The owner's key, with every real proof refused in the worker (its
    // coin not under the root it is sent), the fee changing during the first.
    node.foreignCommits(1);
    node.mineTo(108);
    assert.equal((await flow.summonOpen(owner)).status, "unclaimed");
    const change = feeChange();
    hooks.prove = (args) => {
      change(args);
      const root = Uint8Array.from(args.root);
      root[0] ^= 1;
      return { ...args, root };
    };
    const refused = await attempt(108);
    assert.match(refused.outcome.message, /not in the tree/);
    assert.deepEqual(refused.proofs.map((p) => p.decoy), [false, false], "the coin's own proof, twice");
    assert.equal(node.reveals.length, 1, "only the claim from the other device");

    // The owner's key again, proved after the retry: up to the reveal, the
    // same requests and worker work as the refused one.
    node.foreignCommits(1);
    node.mineTo(140);
    assert.equal((await flow.summonOpen(owner)).status, "unclaimed");
    hooks.prove = feeChange();
    const made = await attempt(140);
    assert.equal(made.outcome, null);
    const sentAt = made.events.findIndex((e) => e.startsWith('["eth_sendRawTransaction"'));
    assert.ok(sentAt > 0);
    assert.deepEqual(made.events.slice(0, sentAt), refused.events, "the retried reveal asks what the refused one asked before it is sent");
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
