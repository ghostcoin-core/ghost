// Vanish, a partial Summon and a Claim with the real prover against a real
// release `geth` of ghost-node, not the stand-in: a one-node internal
// network (chain 6777971) that mines its own blocks. The web app's flow
// controller drives it exactly as the page does, with its built-in wallet:
// the commit is an account transaction (type 0x52) signed in the worker
// with the ML-DSA-44 key of the tests' seed, sent with
// eth_sendRawTransaction. That account is the miner's etherbase, so block
// rewards fund it; no elliptic-curve key or keystore is used. The test then reads
// the chain itself: the commit transaction's type and sender, its 190 bytes
// and its leaf, the reveal's marker, the remainder's leaf, the recipient's
// balance, and the claim.
//
// GHOST_NODE_GETH is the path to the geth binary (webapp/scripts/build-node.sh
// builds one at the commit in NODE_COMMIT). Without it the test prints
// `SKIP: GHOST_NODE_GETH is not set` and runs nothing. It is not loaded from
// test/index.js.
//
// The genesis is the internal network's (params/ghost InternalNetGenesis in
// ghost-node, written out in its scripts/internal-net.sh, which a test in
// ghost-node keeps equal to it).

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { concat, fromHex, toHex, toQuantity } from "../../src/bytes.mjs";
import { ACCOUNT_EXTRA_GAS, DEFAULT_COMMIT_ENTRY, WaitError, createFlow } from "../../src/flow.mjs";
import { TEST_WALLET_ADDRESS, TEST_WALLET_WORDS, loadModule, nodeProver } from "../support/env.mjs";

const GETH = process.env.GHOST_NODE_GETH;
const NETWORK_ID = 6_777_971n;
const GHOST = 10n ** 18n;
const NOTE_BYTES = 156;
const PAGE = 4096;
// A reveal proves against the root of the block this many below the tip.
const SETTLE_DEPTH = 2;
// The internal network's chain constants (spec 06, section 4.2, with its
// genesis difficulty as D_START = D_MIN = 1).
const INTERNAL_CHAIN_PARAMS = { blockTime: 30, halfLife: 3600, startDifficulty: 1, minDifficulty: 1, futureDrift: 30 };

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function answersFor(key, positions) {
  const groups = key.split(" ");
  return positions.map((p) => groups[p - 1]);
}

function rpcClient(url) {
  let id = 0;
  return async function call(method, params = []) {
    id += 1;
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    const body = await response.json();
    if (body.error) throw new Error(`${method}: ${body.error.message}`);
    return body.result;
  };
}

// A one-node internal network in a temporary directory: init, then geth
// mining to the tests' wallet account with HTTP JSON-RPC on a port the
// system picks.
async function startGeth() {
  const dir = await mkdtemp(join(tmpdir(), "ghost-real-node-"));
  const log = [];
  const run = (args) => {
    const result = spawnSync(GETH, args, { encoding: "utf8" });
    log.push(result.stdout, result.stderr);
    if (result.status !== 0) throw new Error(`geth ${args.join(" ")} failed:\n${result.stderr}`);
    return result.stdout;
  };
  const genesis = join(dir, "genesis.json");
  await writeFile(genesis, await readFile(new URL("./internal-genesis.json", import.meta.url)));
  const datadir = join(dir, "node");
  run(["--datadir", datadir, "init", genesis]);
  const miner = TEST_WALLET_ADDRESS;

  const child = spawn(
    GETH,
    [
      "--datadir", datadir,
      "--networkid", String(NETWORK_ID),
      "--syncmode", "full",
      "--port", "0",
      "--authrpc.port", "0",
      "--nat", "none",
      "--nodiscover",
      "--ipcdisable",
      "--http", "--http.addr", "127.0.0.1", "--http.port", "0",
      "--http.api", "eth,net,web3,ghost",
      "--mine", "--miner.threads", "1", "--miner.etherbase", miner,
      "--verbosity", "3",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  let exited = null;
  child.on("exit", (code, signal) => {
    exited = signal || String(code);
  });
  let started = false;
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`geth opened no HTTP endpoint:\n${output.slice(-4000)}`)), 120_000);
    const onData = (chunk) => {
      output = (output + chunk).slice(-200_000);
      if (started) return;
      // The JSON-RPC server, not the engine API's (which has auth=true).
      const http = /HTTP server started.*endpoint=([0-9.]+:\d+).*auth=false/.exec(output);
      if (http) {
        started = true;
        clearTimeout(timer);
        resolve(`http://${http[1]}/`);
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", () => {
      clearTimeout(timer);
      reject(new Error(`geth stopped (${exited}):\n${output.slice(-4000)}`));
    });
  }).catch(async (err) => {
    child.kill("SIGKILL");
    await rm(dir, { recursive: true, force: true });
    throw err;
  });
  return {
    url,
    miner,
    rpc: rpcClient(url),
    alive: () => exited === null,
    tail: () => output.slice(-6000),
    async stop() {
      if (exited === null) {
        child.kill("SIGTERM");
        for (let i = 0; i < 100 && exited === null; i += 1) await sleep(100);
        if (exited === null) child.kill("SIGKILL");
      }
      await rm(dir, { recursive: true, force: true });
    },
  };
}

if (!GETH) {
  console.log("SKIP: GHOST_NODE_GETH is not set");
} else {
  test("Vanish, a partial Summon and a Claim against a real ghost-node", { timeout: 3_600_000 }, async () => {
    const ghost = await loadModule();
    const node = await startGeth();
    const { rpc } = node;
    const prover = nodeProver();

    const blockNumber = async () => Number(BigInt(await rpc("eth_blockNumber")));
    const balance = async (address) => BigInt(await rpc("eth_getBalance", [address, "latest"]));

    async function waitFor(what, check, { ms = 1000, limit = 1800 } = {}) {
      for (let i = 0; i < limit; i += 1) {
        assert.ok(node.alive(), `geth stopped while waiting for ${what}`);
        const value = await check();
        if (value) return value;
        await sleep(ms);
      }
      throw new Error(`timed out waiting for ${what}`);
    }

    const receiptOf = (hash) => waitFor(`the receipt of ${hash}`, () => rpc("eth_getTransactionReceipt", [hash]));

    // Every leaf of coin tree 0, and every spent coin marker, as of the tip.
    async function chainTree() {
      const tip = await rpc("eth_getBlockByNumber", ["latest", false]);
      // The node's shape: the page roots as an array, and a page as
      // `{ kind, treeIndex, page, filled, entries: [{ leaf, note }] }`.
      const pageRoots = await rpc("ghost_getPageRoots", ["coin", "0x0", tip.hash]);
      assert.ok(Array.isArray(pageRoots), "the page roots are an array");
      const leaves = [];
      for (let p = 0; p < pageRoots.length; p += 1) {
        const page = await rpc("ghost_getTreePage", ["coin", "0x0", toQuantity(p), tip.hash]);
        assert.equal(page.entries.length, Number(BigInt(page.filled)), `page ${p} holds \`filled\` entries`);
        leaves.push(...page.entries.map((entry) => String(entry.leaf).toLowerCase()));
      }
      const markers = [];
      for (let p = 0; ; p += 1) {
        const page = await rpc("ghost_getTreePage", ["coin-markers", "0x0", toQuantity(p), tip.hash]);
        markers.push(...page.markers.map((m) => String(m).toLowerCase()));
        if (Number(BigInt(page.count)) < PAGE) break;
      }
      return { leaves, markers };
    }

    // A commit by someone else: a random F and a note no key opens. It puts
    // a leaf after ours, which the tree-state rule waits for. It is an
    // account transaction from the funded account, signed here with the
    // module directly rather than through the flow.
    async function strangerCommit() {
      const data = concat([Uint8Array.of(0x00, 0x01), randomBytes(32), randomBytes(NOTE_BYTES)]);
      const value = GHOST / 100n;
      const call = { from: node.miner, to: DEFAULT_COMMIT_ENTRY, value: toQuantity(value), data: toHex(data) };
      const tip = await rpc("eth_getBlockByNumber", ["latest", false]);
      const priority = BigInt(await rpc("eth_maxPriorityFeePerGas"));
      const signed = ghost.walletSign({
        words: TEST_WALLET_WORDS,
        index: 0,
        chainId: NETWORK_ID,
        genesis: fromHex((await rpc("eth_getBlockByNumber", ["0x0", false])).hash, 32),
        nonce: BigInt(await rpc("eth_getTransactionCount", [node.miner, "pending"])),
        maxPriorityFeePerGas: priority,
        maxFeePerGas: 2n * BigInt(tip.baseFeePerGas) + priority,
        gasLimit: BigInt(await rpc("eth_estimateGas", [call])) + ACCOUNT_EXTRA_GAS,
        to: fromHex(DEFAULT_COMMIT_ENTRY, 20),
        value,
        data,
        seed: randomBytes(32),
      });
      const hash = toHex(signed.txHash);
      // The node answers an error once its pool has taken a type 0x52
      // transaction (its RPC log line recovers the sender with the plain
      // signer); what counts is that it holds the transaction.
      await rpc("eth_sendRawTransaction", [toHex(signed.envelope)]).catch(() => null);
      assert.ok(await rpc("eth_getTransactionByHash", [hash]), "the node holds the stranger's commit");
      const receipt = await receiptOf(hash);
      assert.equal(receipt.status, "0x1", "the stranger's commit is executed");
      assert.equal(receipt.type, "0x52");
      return Number(BigInt(receipt.blockNumber));
    }

    // Until `block` is 2 blocks deep, so that the settled tree holds a leaf
    // added after the coin's.
    async function waitSettledAfter(block) {
      await waitFor(`block ${block + SETTLE_DEPTH}`, async () => (await blockNumber()) >= block + SETTLE_DEPTH);
    }

    // Each stage the flow reports is logged once, so a resend of a reveal the
    // node refused while its head kept moving shows in the job's log.
    let lastStage = null;
    // The Sent state of the commit, the reveal and the claim (the last one,
    // should a reveal be proved again), as the page shows it: the
    // transaction hash and amount, before its block.
    const sentSeen = { vanish: null, reveal: null, claim: null };
    const onChange = (state) => {
      const stage = state.progress?.stage ?? null;
      if (stage !== null && stage !== lastStage) console.log(`flow: ${stage}`);
      lastStage = stage;
      const v = state.vanish;
      const r = state.summon?.lastReveal;
      const c = state.summon?.claim;
      if (v?.stage === "sent" && !sentSeen.vanish) sentSeen.vanish = { txHash: v.txHash, amount: v.amount };
      if (r?.stage === "sent" && sentSeen.reveal?.txHash !== r.txHash) sentSeen.reveal = { txHash: r.txHash, out: r.out };
      if (c?.stage === "sent" && sentSeen.claim?.txHash !== c.txHash) sentSeen.claim = { txHash: c.txHash, amount: c.amount };
    };
    // The node keeps sealing a block about every 20 ms throughout, so its
    // tip never holds still: a reveal it refuses while its head kept moving
    // is sent again after a short wait, or proved again against the settled
    // root of the tip by then, and that gets the Summon and the Claim
    // through.
    //
    // This build pins no network, so the test adds the internal network's
    // entry, starting the page's header chain at the genesis of the node it
    // started itself; every header after it is checked in the worker, seal
    // and difficulty included, at the internal network's test constants.
    const genesisBlock = await rpc("eth_getBlockByNumber", ["0x0", false]);
    const networks = {
      [String(NETWORK_ID)]: {
        params: INTERNAL_CHAIN_PARAMS,
        genesisTimestamp: Number(BigInt(genesisBlock.timestamp)),
        genesisHash: genesisBlock.hash,
        pin: null,
      },
    };
    const flow = createFlow({ prover, endpoint: node.url, networks, pollMs: 1000, maxPolls: 1800, onChange });

    // A stranger's commit, then the tip 2 blocks past it: from then on the
    // settled block's tree holds a leaf after the coin, and the coin can be
    // revealed at once.
    async function strangerCommitSettled() {
      const block = await strangerCommit();
      await waitSettledAfter(block);
      console.log(`a stranger committed in block ${block}; it is ${SETTLE_DEPTH} blocks deep`);
      return block;
    }

    try {
      assert.equal(BigInt(await rpc("eth_chainId")), NETWORK_ID);
      assert.equal((await rpc("eth_getBlockByNumber", ["0x0", false])).timestamp, "0x6abda280", "the internal network's genesis");
      // Test funds come only from block rewards, to the wallet's account.
      await waitFor("the wallet's funds", async () => (await balance(node.miner)) >= 2n * GHOST);

      // --- The wallet: restored from its 24 words ---
      assert.equal(await flow.walletRestore(TEST_WALLET_WORDS), TEST_WALLET_ADDRESS);
      assert.ok(flow.state.wallet.balance >= 2n * GHOST, "the wallet shows the account's balance");

      // --- Vanish: 1 GHOST into a new key ---
      const key = await flow.vanishStart("1");
      const positions = flow.vanishSaved();
      const sent = await flow.vanishCheck(answersFor(key, positions));
      assert.equal(sent.ok, true);
      assert.equal(flow.state.vanish.stage, "done");

      // On chain: a transaction to the commit entry address of 1 GHOST whose
      // data is the 190 bytes of ghostpriv.CommitData, version 0x0001, and a
      // new leaf C = K(tag, COIN, F, v).
      const commitTx = await rpc("eth_getTransactionByHash", [sent.txHash]);
      assert.equal(commitTx.type, "0x52", "a quantum-safe account transaction");
      // The sender is derived from the key: the wallet's nonce moved.
      assert.equal(BigInt(await rpc("eth_getTransactionCount", [TEST_WALLET_ADDRESS, "latest"])), 1n);
      assert.equal(String(commitTx.to).toLowerCase(), DEFAULT_COMMIT_ENTRY);
      assert.equal(BigInt(commitTx.value), GHOST);
      const data = fromHex(commitTx.input);
      assert.equal(data.length, 190);
      assert.equal(toHex(data.slice(0, 2)), "0x0001");
      const commitReceipt = await rpc("eth_getTransactionReceipt", [sent.txHash]);
      assert.equal(commitReceipt.status, "0x1");
      // Sent as soon as the wallet had it, Done in the block that holds it.
      assert.deepEqual(sentSeen.vanish, { txHash: sent.txHash, amount: GHOST });
      assert.equal(flow.state.vanish.block, Number(BigInt(commitReceipt.blockNumber)), "Done at the commit's own block");
      const coin = toHex(ghost.coinCommitment(data.slice(2, 34), GHOST));
      let tree = await chainTree();
      assert.ok(tree.leaves.includes(coin), "the commit's leaf is in the coin tree");
      // The note on chain opens with the key.
      const restored = ghost.restore({
        chainId: NETWORK_ID,
        key,
        records: concat([fromHex(coin, 32), data.slice(34)]),
        markers: new Uint8Array(0),
      });
      assert.equal(restored.length, 1);
      assert.equal(restored[0].amount, GHOST);
      // The coin's marker, from the key alone (the seed only changes the note).
      const marker = toHex(ghost.commit({ chainId: NETWORK_ID, amount: GHOST, seed: new Uint8Array(32), key }).marker);
      assert.ok(!tree.markers.includes(marker));

      // --- Nobody has committed since the coin: the app waits ---
      const recipient = toHex(randomBytes(20));
      assert.equal(await balance(recipient), 0n);
      let s = await flow.summonOpen(key);
      assert.equal(s.status, "unclaimed");
      assert.equal(s.current.amount, GHOST);
      assert.equal(s.wait?.alone, true, "no leaf follows the coin yet");
      assert.equal(s.cover, null);
      await assert.rejects(flow.summonReveal({ amount: "0.25", recipient }), (err) => {
        assert.ok(err instanceof WaitError, `the app waits: ${err.message}`);
        assert.equal(err.alone, true);
        assert.match(err.message, /^nobody has committed a coin since this one/);
        console.log(`tree-state rule holds: ${err.message}`);
        return true;
      });
      assert.equal(await balance(recipient), 0n, "nothing was revealed");

      // --- Summon: 0.25 GHOST to a fresh address, 2 blocks after a
      // stranger's commit, with no further wait ---
      const followed = await strangerCommitSettled();
      s = await flow.summonRefresh();
      assert.equal(s.wait, null, "the coin can be revealed now");
      assert.ok(s.cover.height >= followed, "against a settled root that holds the stranger's leaf");
      const reveal = await flow.summonReveal({ amount: "0.25", recipient });
      const left = GHOST - GHOST / 4n - reveal.fee;

      const revealReceipt = await rpc("eth_getTransactionReceipt", [reveal.txHash]);
      assert.equal(revealReceipt.status, "0x1");
      assert.equal(revealReceipt.type, "0x50", "a private transaction");
      assert.deepEqual(sentSeen.reveal, { txHash: reveal.txHash, out: GHOST / 4n }, "shown Sent with the amount and hash");
      assert.equal(reveal.stage, "done");
      assert.equal(reveal.block, Number(BigInt(revealReceipt.blockNumber)), "Done at the reveal's own block");
      // Log data: tree index (4), position (4), remainder (32), note (156),
      // recipient (20), out (32).
      const revealLog = fromHex(revealReceipt.logs[0].data);
      const remainder = toHex(revealLog.slice(8, 40));
      assert.equal(toHex(revealLog.slice(196, 216)), recipient);
      assert.equal(BigInt(toHex(revealLog.slice(216, 248))), GHOST / 4n);
      assert.equal(await balance(recipient), GHOST / 4n, "the recipient holds what was revealed");
      tree = await chainTree();
      assert.ok(tree.markers.includes(marker), "the coin's marker is spent");
      assert.ok(tree.leaves.includes(remainder), "the remainder's leaf is in the coin tree");
      s = flow.state.summon;
      assert.equal(s.status, "unclaimed", "still unclaimed after a partial reveal");
      assert.equal(s.current.number, 1n);
      assert.equal(s.current.amount, left, "the remainder is the coin less what went out and the fee");

      // The remainder is the newest coin: it waits too, until a stranger
      // commits after it.
      assert.equal(s.wait?.alone, true, "no leaf follows the remainder yet");
      await strangerCommitSettled();

      // --- Claim: the remainder to a new key, with no further wait ---
      const newKey = await flow.claimStart();
      const claimPositions = flow.claimSaved();
      const claimed = await flow.claimCheck(answersFor(newKey, claimPositions));
      assert.equal(claimed.ok, true);
      assert.ok(claimed.amount > 0n && claimed.amount < left, "the claim pays its fee from the remainder");
      const claimReceipt = await rpc("eth_getTransactionReceipt", [claimed.txHash]);
      assert.equal(claimReceipt.status, "0x1");
      assert.equal(claimReceipt.type, "0x50");
      assert.deepEqual(sentSeen.claim, { txHash: claimed.txHash, amount: claimed.amount }, "shown Sent with the amount and hash");
      assert.equal(claimed.block, Number(BigInt(claimReceipt.blockNumber)), "Done at the claim's own block");
      const claimLog = fromHex(claimReceipt.logs[0].data);
      assert.equal(toHex(claimLog.slice(196, 216)), "0x0000000000000000000000000000000000000000");
      assert.equal(BigInt(toHex(claimLog.slice(216, 248))), 0n, "a claim sends nothing out");
      tree = await chainTree();
      assert.ok(tree.leaves.includes(toHex(claimLog.slice(8, 40))), "the claimed coin's leaf is in the coin tree");
      assert.equal(await balance(recipient), GHOST / 4n, "the claim leaves the recipient's balance as it was");

      // Every confirmation above came from the page's own header chain.
      assert.equal(flow.state.chainRefused, null, "the node's chain passed the proof-of-work check");

      // The old key shows claimed, the new key holds the claimed amount.
      s = await flow.summonOpen(key);
      assert.equal(s.status, "claimed");
      s = await flow.summonOpen(newKey);
      assert.equal(s.status, "unclaimed");
      assert.equal(s.current.amount, claimed.amount);
      flow.summonClose();
      // The account sent the commit and the two strangers' commits, all type
      // 0x52, and nothing else.
      assert.equal(BigInt(await rpc("eth_getTransactionCount", [TEST_WALLET_ADDRESS, "latest"])), 3n);
    } catch (err) {
      console.error(`--- last lines of geth's log ---\n${node.tail()}`);
      throw err;
    } finally {
      prover.terminate();
      await node.stop();
    }
  });
}
