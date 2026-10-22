// Recovery with every project-run service gone: the coin lifecycle on an
// internal network of three release `geth` nodes of ghost-node, then a clean
// device that restores keys from their digits alone, through an independent
// node that synced from its peers only, and spends them.
//
// It runs only under scripts/recovery-blackout.sh, which builds the node from
// its published source (twice, and compares the bytes) and the wallet with
// webapp/build.sh before anything is blocked, then runs this file inside a
// network namespace whose only way out is a dummy interface behind an
// nftables rule that rejects and counts every packet, and fails the run if a
// project-run host is reachable or any packet tried to leave. Without
// GHOST_RECOVERY_NETNS (set by that script) and GHOST_NODE_GETH it prints
// `SKIP: ...` and runs nothing. It is not loaded from test/index.js.
//
// The nodes, all on the namespace's loopback, discovery off, no bootstrap
// nodes, peers only by enode and only on 127.0.0.0/8:
//
// - A, a miner of the network (etherbase: the tests' wallet account, so its
//   rewards fund the commits);
// - C, a second miner, cut off from the others for a while to mine a heavier
//   branch, so that the network reorganises during the recovery;
// - B, the independent node: no miner, initialised from the genesis file and
//   synced from A and C over the peer protocol alone. The clean device talks
//   to B and to nothing else.
//
// The devices run the web app's own flow controller and the WebAssembly
// module the wallet build made (GHOST_WEBAPP_WASM), in a worker_threads
// worker that speaks the browser worker's messages, as real-node.test.mjs
// does. The original device makes the commitments; the clean device starts
// with an empty header chain and is given only the keys' digit views.
//
// Cases, each reported as pass, fail or skip in GHOST_RECOVERY_RESULTS (a
// JSON file the script reads):
//
// 1. partial-reveal-then-claim: key K1 commits 1 GHOST and the original
//    device reveals 0.25 of it; the clean device restores K1 from its digits,
//    finds the spent coin and the remainder, and claims the remainder to a
//    new key.
// 2. reorganisation-during-recovery: C is cut off; A mines a few blocks,
//    one of them holding key K4's commit, and the clean device sees K4's coin
//    through B; C mines a longer branch without it and rejoins while the
//    clean device is scanning; B and the device follow the heavier branch,
//    and K4's coin is gone from the device's view.
// 3. older-tree-state: key K2 committed before everything above, more than
//    34 blocks (the scan's header window plus the settle depth) below the tip
//    when the clean device restores it from its digits and reveals part of
//    it on the branch that won the reorganisation.
// 4. rollover: keys KB and KA commit in coin tree 0, strangers' commits
//    fill it, the next commit starts tree 1 at position 0, and KA's
//    remainder of a partial reveal lands in tree 1; the clean device reads
//    both trees and restores KA's spent coin and its remainder.
// 5. commitment-in-full-tree: KB's coin, left unspent in the full tree 0, is
//    restored by the clean device and revealed in part.
//
// Cases 4 and 5 need a coin tree that can fill: they run only when the
// script says the node holds GHOST_RECOVERY_TREE_LEAVES leaves per tree,
// fewer than the release's 2^32 (spec 05, RT-1 Part B), and the devices are
// told the same count and the trees' depth (GHOST_RECOVERY_TREE_DEPTH, 14
// in Part B), whose roots they check. Otherwise they are skipped with the
// reason below. At a depth below 32 every reveal, these cases' included, is
// made by the test-depth module the script builds (the test-tree-depth
// feature, lib.rs test_depth), which carries the stub proof Part B's node
// takes with its stub verifier (RT-8) in place of a STARK, and the node must
// accept it; with the page's module, which proves only against 32-level
// roots, the run stops at once rather than fail at a reveal.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { concat, fromHex, toHex, toQuantity } from "../../src/bytes.mjs";
import { ACCOUNT_EXTRA_GAS, DEFAULT_COMMIT_ENTRY, STALE_ROOT_DEPTH, createFlow } from "../../src/flow.mjs";
import { startBlockPacer } from "../support/block-pacer.mjs";
import { sendPaced, waitPastBlock } from "./fillers.mjs";
import { TEST_WALLET_ADDRESS, TEST_WALLET_WORDS, loadModule, nodeProver } from "../support/env.mjs";

const GETH = process.env.GHOST_NODE_GETH;
const NETNS = process.env.GHOST_RECOVERY_NETNS;
const RESULTS = process.env.GHOST_RECOVERY_RESULTS;
const NETWORK_ID = 6_777_971n;
const GHOST = 10n ** 18n;
const NOTE_BYTES = 156;
const SALT_BYTES = 16;
const SETTLE_DEPTH = 2;
const INTERNAL_CHAIN_PARAMS = { blockTime: 30, halfLife: 3600, startDifficulty: 1, minDifficulty: 1, futureDrift: 30 };
// Fixed ports: the namespace is the test's own, so nothing else holds them.
const PORTS = { A: { p2p: 30411, http: 18541 }, B: { p2p: 30412, http: 18542 }, C: { p2p: 30413, http: 18543 } };
// The second miner's etherbase: any address other than the wallet's.
const C_ETHERBASE = "0x00000000000000000000000000000000000c0ffe";

// Leaves per coin tree of the node under test, from the script: unset for a
// release node, whose trees hold 2^32.
const TREE_LEAVES_SET = process.env.GHOST_RECOVERY_TREE_LEAVES;
const TREE_LEAVES = TREE_LEAVES_SET ? Number(TREE_LEAVES_SET) : null;
// Levels of its coin trees, whose roots its headers carry (spec 05, RT-1
// Part B: 14), from the script: 32 unless set.
const TREE_DEPTH = process.env.GHOST_RECOVERY_TREE_DEPTH ? Number(process.env.GHOST_RECOVERY_TREE_DEPTH) : 32;

export const ROLLOVER_SKIP =
  "not on main: the node under test holds 2^32 leaves per coin tree (the release's only size: its tree package " +
  "refuses any other), so a rollover needs 2^32 commits. It runs once the node can be built with smaller coin trees " +
  "(spec 05, RT-1 Part B, a change in the node's own repository) and the script is given that size in " +
  "GHOST_RECOVERY_TREE_LEAVES; the web app already reads every coin tree index up to the tip's";
export const FULL_TREE_SKIP =
  "not on main: a commitment left in a full earlier tree index needs the same rollover (spec 05, RT-2 Part B), " +
  "so it waits for the same node build of smaller coin trees";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function answersFor(key, positions) {
  const words = key.split(" ");
  return positions.map((p) => words[p - 1]);
}

// Every request this process makes must stay on the namespace's loopback:
// the nodes of the internal network. Anything else is recorded, refused and
// fails the test; the nftables rule of the script counts it as well.
const offLoopback = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
  if (url.hostname !== "127.0.0.1") {
    offLoopback.push(url.href);
    throw new Error(`refused: ${url.href} is not on the internal network`);
  }
  return realFetch(input, init);
};

// The clean device may ask the independent node and nothing else.
// `hold(method)` pauses the device's next request for that JSON-RPC method
// before it is sent: the returned `reached` resolves once the request is
// held, and `release()` sends it on. The reorganisation case uses it to
// change the node's branch while a scan is part way through.
function onlyTo(endpoint, seen) {
  const allowed = new URL(endpoint);
  let holding = null;
  const guarded = async (input, init) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (url.host !== allowed.host) {
      seen.push(url.href);
      throw new Error(`refused: the clean device asked ${url.href}`);
    }
    if (holding && typeof init?.body === "string") {
      let method = null;
      try {
        method = JSON.parse(init.body).method;
      } catch {
        // not a JSON-RPC body
      }
      if (method === holding.method) {
        const h = holding;
        holding = null;
        h.reach();
        await h.released;
      }
    }
    return globalThis.fetch(input, init);
  };
  guarded.hold = (method) => {
    let reach;
    let release;
    const reached = new Promise((resolve) => {
      reach = resolve;
    });
    const released = new Promise((resolve) => {
      release = resolve;
    });
    holding = { method, reach, released };
    return { reached, release };
  };
  return guarded;
}

function rpcClient(url) {
  let id = 0;
  return async function call(method, params = []) {
    id += 1;
    const response = await globalThis.fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    const body = await response.json();
    if (body.error) throw new Error(`${method}: ${body.error.message}`);
    return body.result;
  };
}

// One node of the internal network in `root`: init from the genesis file,
// then geth with discovery off, no bootstrap nodes, peers only on loopback,
// and HTTP JSON-RPC on its fixed port. `etherbase` makes it a miner (started
// and stopped by a block pacer); without it the node has no miner API.
async function startNode(root, name, { etherbase = null } = {}) {
  const { p2p, http } = PORTS[name];
  const datadir = join(root, name);
  const log = [];
  const genesis = join(root, "genesis.json");
  const init = spawnSync(GETH, ["--datadir", datadir, "init", genesis], { encoding: "utf8" });
  log.push(init.stdout, init.stderr);
  if (init.status !== 0) throw new Error(`geth init for ${name} failed:\n${init.stderr}`);
  const args = [
    "--datadir", datadir,
    "--networkid", String(NETWORK_ID),
    "--syncmode", "full",
    "--port", String(p2p),
    "--authrpc.port", "0",
    "--nat", "none",
    "--nodiscover",
    "--bootnodes", "",
    "--netrestrict", "127.0.0.0/8",
    "--ipcdisable",
    "--http", "--http.addr", "127.0.0.1", "--http.port", String(http),
    "--http.api", etherbase ? "eth,net,web3,ghost,miner,txpool,admin" : "eth,net,web3,ghost,txpool,admin",
    "--verbosity", "3",
  ];
  if (etherbase) args.push("--miner.threads", "1", "--miner.etherbase", etherbase, "--miner.noempty");
  const child = spawn(GETH, args, { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  let exited = null;
  child.on("exit", (code, signal) => {
    exited = signal || String(code);
  });
  let started = false;
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`geth ${name} opened no HTTP endpoint:\n${output.slice(-4000)}`)), 120_000);
    const onData = (chunk) => {
      output = (output + chunk).slice(-200_000);
      if (started) return;
      const found = /HTTP server started.*endpoint=([0-9.]+:\d+).*auth=false/.exec(output);
      if (found) {
        started = true;
        clearTimeout(timer);
        resolve(`http://${found[1]}/`);
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", () => {
      clearTimeout(timer);
      reject(new Error(`geth ${name} stopped (${exited}):\n${output.slice(-4000)}`));
    });
  }).catch((err) => {
    child.kill("SIGKILL");
    throw err;
  });
  const rpc = rpcClient(url);
  return {
    name,
    url,
    rpc,
    alive: () => exited === null,
    tail: () => output.slice(-4000),
    async enode() {
      const info = await rpc("admin_nodeInfo");
      // The enode with its loopback address and its own port.
      return String(info.enode).replace(/@[^?]+/, `@127.0.0.1:${p2p}`).replace(/\?.*$/, "");
    },
    async peerIds() {
      return (await rpc("admin_peers")).map((p) => String(p.id));
    },
    async head() {
      const b = await rpc("eth_getBlockByNumber", ["latest", false]);
      return { number: Number(BigInt(b.number)), hash: b.hash };
    },
    async stop() {
      if (exited === null) {
        child.kill("SIGTERM");
        for (let i = 0; i < 100 && exited === null; i += 1) await sleep(100);
        if (exited === null) child.kill("SIGKILL");
      }
    },
  };
}

if (!GETH || !NETNS) {
  console.log(
    `SKIP: ${!GETH ? "GHOST_NODE_GETH" : "GHOST_RECOVERY_NETNS"} is not set; run scripts/recovery-blackout.sh, ` +
      "which builds the node and the wallet and runs this test with every project-run host blocked",
  );
} else {
  test("recovery with every project-run service blocked", { timeout: 7_200_000 }, async (t) => {
    const results = [];
    const saveResults = async () => {
      if (RESULTS) await writeFile(RESULTS, `${JSON.stringify(results, null, 2)}\n`);
    };
    let broken = null;
    // A case: recorded as pass or fail; once one fails, the cases after it
    // are recorded as not run, since each builds on the chain the earlier
    // ones left.
    async function runCase(name, fn) {
      if (broken) {
        results.push({ case: name, result: "not-run", detail: `an earlier case failed: ${broken}` });
        await saveResults();
        return;
      }
      await t.test(name, async () => {
        try {
          const detail = await fn();
          results.push({ case: name, result: "pass", detail: detail ?? "" });
        } catch (err) {
          broken = name;
          results.push({ case: name, result: "fail", detail: err.message.slice(0, 2000) });
          throw err;
        } finally {
          await saveResults();
        }
      });
    }
    async function skipCase(name, reason) {
      results.push({ case: name, result: "skip", detail: reason });
      await saveResults();
      await t.test(name, { skip: reason }, () => {});
    }

    const ghost = await loadModule();
    if (TREE_DEPTH !== 32) {
      // A node of smaller trees takes only the test-depth module's reveals.
      const levels = ghost.w.ghost_test_depth_levels;
      assert.ok(
        typeof ghost.w.ghost_prove_test_depth === "function" && typeof levels === "function" && levels() === TREE_DEPTH,
        `a node of ${TREE_DEPTH}-level trees needs GHOST_WEBAPP_WASM to be the test-depth module of that depth (test-tree-depth)`,
      );
    }
    const root = await mkdtemp(join(tmpdir(), "ghost-recovery-"));
    await writeFile(join(root, "genesis.json"), await readFile(new URL("./internal-genesis.json", import.meta.url)));
    const nodes = [];
    const pacers = [];
    const provers = [];
    let following = true;
    const followers = [];
    const cleanDeviceAsked = [];

    async function waitFor(what, check, { ms = 500, limit = 240 } = {}) {
      for (let i = 0; i < limit; i += 1) {
        for (const n of nodes) assert.ok(n.alive(), `geth ${n.name} stopped while waiting for ${what}`);
        const value = await check();
        if (value) return value;
        await sleep(ms);
      }
      throw new Error(`timed out waiting for ${what} (${(ms * limit) / 1000} s)`);
    }

    try {
      const A = await startNode(root, "A", { etherbase: TEST_WALLET_ADDRESS });
      nodes.push(A);
      const C = await startNode(root, "C", { etherbase: C_ETHERBASE });
      nodes.push(C);
      const B = await startNode(root, "B");
      nodes.push(B);
      const enode = { A: await A.enode(), B: await B.enode(), C: await C.enode() };
      const idOf = (e) => /^enode:\/\/([0-9a-f]+)@/.exec(e)[1];
      // Static peers, dialled one way: C to A, B to A and to C.
      await C.rpc("admin_addPeer", [enode.A]);
      await B.rpc("admin_addPeer", [enode.A]);
      await B.rpc("admin_addPeer", [enode.C]);
      await waitFor("the peers to connect", async () => (await B.peerIds()).length === 2 && (await C.peerIds()).length >= 1);

      let pacerA = startBlockPacer({ rpc: A.rpc, intervalMs: 2000 });
      pacers.push(pacerA);
      const warm = await pacerA.warmUp;
      console.log(`block pacer: warm-up ${warm.settled ? "settled" : "not settled"} after ${warm.blocks} blocks`);

      const balance = async (node, address) => BigInt(await node.rpc("eth_getBalance", [address, "latest"]));
      const receiptOn = (node, hash, what = hash) =>
        waitFor(`the receipt of ${what} on ${node.name}`, () => node.rpc("eth_getTransactionReceipt", [hash]), { limit: 240 });
      // Until B holds A's head (or `other`'s): B syncs from its peers only.
      async function synced(other = A) {
        return waitFor(`B to sync to ${other.name}'s head`, async () => {
          const [b, o] = [await B.head(), await other.head()];
          return b.hash === o.hash ? b : null;
        });
      }

      // A device: a fresh prover (worker) and flow controller, its header
      // chain starting at the genesis of `node`, its clock the later of the
      // wall clock and `node`'s latest block time (as in real-node.test.mjs).
      async function device(node, fetchFn) {
        const prover = nodeProver();
        provers.push(prover);
        const g = await node.rpc("eth_getBlockByNumber", ["0x0", false]);
        const networks = {
          [String(NETWORK_ID)]: {
            params: INTERNAL_CHAIN_PARAMS,
            genesisTimestamp: Number(BigInt(g.timestamp)),
            genesisHash: g.hash,
            pin: null,
          },
        };
        let nodeTime = Number(BigInt((await node.rpc("eth_getBlockByNumber", ["latest", false])).timestamp));
        followers.push(
          (async () => {
            while (following && node.alive()) {
              try {
                nodeTime = Math.max(nodeTime, Number(BigInt((await node.rpc("eth_getBlockByNumber", ["latest", false])).timestamp)));
              } catch {
                // read again next time
              }
              await sleep(250);
            }
          })(),
        );
        const clock = () => Math.max(Math.floor(Date.now() / 1000), nodeTime);
        let lastStage = null;
        const onChange = (state) => {
          const stage = state.progress?.stage ?? null;
          if (stage !== null && stage !== lastStage) console.log(`${node.name} device: ${stage}`);
          lastStage = stage;
        };
        return createFlow({
          prover,
          endpoint: node.url,
          networks,
          pollMs: 1000,
          maxPolls: 1800,
          onChange,
          clock,
          ...(fetchFn ? { fetch: fetchFn } : {}),
          ...(TREE_LEAVES ? { treeLeaves: TREE_LEAVES, treeDepth: TREE_DEPTH } : {}),
        });
      }

      // Commits by someone else from the funded account on A, `count` of
      // them with consecutive nonces, paced under the node's per-connection
      // signature budget (fillers.mjs): version 2 commits of a random F and
      // salt and a note no key opens, of `value` each. A send the node
      // refuses fails the case. Returns their hashes.
      async function sendStrangerCommits(count, value = GHOST / 100n) {
        const tip = await A.rpc("eth_getBlockByNumber", ["latest", false]);
        const priority = BigInt(await A.rpc("eth_maxPriorityFeePerGas"));
        const genesis = fromHex((await A.rpc("eth_getBlockByNumber", ["0x0", false])).hash, 32);
        const first = BigInt(await A.rpc("eth_getTransactionCount", [TEST_WALLET_ADDRESS, "pending"]));
        let gasLimit = null;
        const sign = async (i) => {
          const data = concat([Uint8Array.of(0x00, 0x02), randomBytes(32), randomBytes(SALT_BYTES), randomBytes(NOTE_BYTES)]);
          const call = { from: TEST_WALLET_ADDRESS, to: DEFAULT_COMMIT_ENTRY, value: toQuantity(value), data: toHex(data) };
          gasLimit ??= BigInt(await A.rpc("eth_estimateGas", [call])) + ACCOUNT_EXTRA_GAS;
          const signed = ghost.walletSign({
            words: TEST_WALLET_WORDS,
            index: 0,
            chainId: NETWORK_ID,
            genesis,
            nonce: first + BigInt(i),
            maxPriorityFeePerGas: priority,
            maxFeePerGas: 2n * BigInt(tip.baseFeePerGas) + priority,
            gasLimit,
            to: fromHex(DEFAULT_COMMIT_ENTRY, 20),
            value,
            data,
            seed: randomBytes(32),
          });
          return { raw: toHex(signed.envelope), hash: toHex(signed.txHash) };
        };
        return sendPaced({ rpc: A.rpc, count, sign });
      }

      // A commit by someone else, waited for until SETTLE_DEPTH blocks are
      // on it, so that the tree-state rule finds a leaf after the coins.
      // Returns its receipt.
      async function strangerCommitReceipt() {
        const [hash] = await sendStrangerCommits(1);
        const receipt = await receiptOn(A, hash, "a stranger's commit");
        assert.equal(receipt.status, "0x1");
        const block = Number(BigInt(receipt.blockNumber));
        await waitFor(`block ${block + SETTLE_DEPTH} on A`, async () => (await A.head()).number >= block + SETTLE_DEPTH);
        return receipt;
      }

      async function strangerCommit() {
        return Number(BigInt((await strangerCommitReceipt()).blockNumber));
      }

      // Where a receipt's leaf went: the coin tree index and the position in
      // it, the first 8 bytes of its log's data.
      function appendedAt(receipt) {
        const data = fromHex(receipt.logs[0].data);
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        return { tree: view.getUint32(0), position: view.getUint32(4) };
      }

      // The isolation the script set up, seen from inside: B is no miner,
      // has no bootstrap nodes and only the internal network's two miners
      // as peers.
      assert.equal(BigInt(await B.rpc("eth_chainId")), NETWORK_ID);
      await assert.rejects(B.rpc("miner_start", [1]), "B has no miner");

      await waitFor("the wallet's funds on A", async () => (await balance(A, TEST_WALLET_ADDRESS)) >= 3n * GHOST, { ms: 1000, limit: 600 });

      // --- The original device makes the commitments ---
      const original = await device(A);
      assert.equal(await original.walletRestore(TEST_WALLET_WORDS), TEST_WALLET_ADDRESS);
      async function vanish(amount) {
        const key = await original.vanishStart(amount);
        const sent = await original.vanishCheck(answersFor(key, original.vanishSaved()));
        assert.equal(sent.ok, true, `Vanish of ${amount} GHOST`);
        const receipt = await A.rpc("eth_getTransactionReceipt", [sent.txHash]);
        return { key, digits: ghost.keyDigits(key), block: Number(BigInt(receipt.blockNumber)), txHash: sent.txHash };
      }

      const K2 = await vanish("0.5");
      console.log(`K2 committed 0.5 GHOST in block ${K2.block}`);
      const K1 = await vanish("1");
      console.log(`K1 committed 1 GHOST in block ${K1.block}`);
      await strangerCommit();
      const recipient1 = toHex(randomBytes(20));
      let s = await original.summonOpen(K1.key);
      assert.equal(s.wait, null, "K1 can be revealed");
      const reveal1 = await original.summonReveal({ amount: "0.25", recipient: recipient1 });
      const left1 = GHOST - GHOST / 4n - reveal1.fee;
      assert.equal(await balance(A, recipient1), GHOST / 4n);
      // A leaf after the remainder, so that the clean device can claim it.
      await strangerCommit();
      original.summonClose();

      // --- The independent node: synced from peers only ---
      const synchedHead = await synced();
      const peers = await B.peerIds();
      assert.deepEqual(new Set(peers), new Set([idOf(enode.A), idOf(enode.C)]), "B's only peers are A and C");
      console.log(`B synced from its peers to block ${synchedHead.number}`);

      // --- The clean device: an empty header chain, the digits alone, and B ---
      const cleanFetch = onlyTo(B.url, cleanDeviceAsked);
      const clean = await device(B, cleanFetch);

      await runCase("partial-reveal-then-claim", async () => {
        let r = await clean.summonOpen(K1.digits);
        assert.equal(r.status, "unclaimed");
        assert.equal(r.coins.length, 2, "the spent coin and its remainder are found");
        assert.ok(r.coins.find((c) => c.number === 0n)?.spent, "coin number 0 shows spent");
        assert.equal(r.current.number, 1n);
        assert.equal(r.current.amount, left1, "the remainder is the coin less the reveal and its fee");
        assert.equal(r.wait, null, "the remainder can be claimed");
        const newKey = await clean.claimStart();
        const claimed = await clean.claimCheck(answersFor(newKey, clean.claimSaved()));
        assert.equal(claimed.ok, true);
        const receipt = await receiptOn(B, claimed.txHash, "the claim");
        assert.equal(receipt.status, "0x1");
        assert.equal(receipt.type, "0x50");
        r = await clean.summonOpen(K1.digits);
        assert.equal(r.status, "claimed", "K1 shows claimed");
        r = await clean.summonOpen(newKey);
        assert.equal(r.status, "unclaimed");
        assert.equal(r.current.amount, claimed.amount, "the new key holds the claimed remainder");
        clean.summonClose();
        return `K1 restored from its digits (coin 0 spent, remainder ${left1} wei) and the remainder claimed in block ${claimed.block}`;
      });

      await runCase("reorganisation-during-recovery", async () => {
        await synced();
        // Cut C off: B drops it, C drops A.
        await B.rpc("admin_removePeer", [enode.C]);
        await C.rpc("admin_removePeer", [enode.A]);
        await waitFor("C to have no peers", async () => (await C.peerIds()).length === 0);
        const fork = await C.head();
        console.log(`C cut off at block ${fork.number}`);
        // A's branch: K4's commit and two blocks on it, seen by B.
        const K4 = await vanish("0.3");
        await waitFor("two blocks on K4's commit", async () => (await A.head()).number >= K4.block + 2);
        await pacerA.stop();
        const aBranch = await synced();
        const aHashAfterFork = (await B.rpc("eth_getBlockByNumber", [toQuantity(fork.number + 1), false])).hash;
        let r = await clean.summonOpen(K4.digits);
        assert.equal(r.status, "unclaimed", "before the reorganisation the clean device sees K4's coin through B");
        clean.summonClose();
        // C's branch: longer than A's, without K4's commit.
        const pacerC = startBlockPacer({ rpc: C.rpc, intervalMs: 300, warmUpBlocks: 0 });
        pacers.push(pacerC);
        await waitFor("C's branch to pass A's", async () => (await C.head()).number >= aBranch.number + 6, { limit: 600 });
        await pacerC.stop();
        const cHead = await C.head();
        console.log(`A's branch ends at block ${aBranch.number}, C's at block ${cHead.number}`);
        // C rejoins while the clean device scans K2: the scan is held at its
        // first tree page, after it has adopted A's tip, until B has
        // switched to C's branch.
        const held = cleanFetch.hold("ghost_getTreePage");
        const scan = clean.summonOpen(K2.digits).then(
          (v) => ({ v }),
          (err) => ({ err }),
        );
        const reached = await Promise.race([held.reached.then(() => true), scan.then(() => false)]);
        assert.ok(reached, "the scan reached its first tree page");
        assert.equal((await B.head()).hash, aBranch.hash, "the scan is held while B is still on A's branch");
        await B.rpc("admin_addPeer", [enode.C]);
        await C.rpc("admin_addPeer", [enode.A]);
        await synced(C);
        await waitFor("A to follow C's branch", async () => (await A.head()).hash === cHead.hash);
        held.release();
        let first = await scan;
        const interrupted = first.err ? first.err.message : null;
        let rescans = 0;
        // A scan the reorganisation cut short is started again, as the
        // holder would; it must then end on the new branch.
        while (first.err && rescans < 3) {
          console.log(`the scan met the reorganisation (${first.err.message}); scanning again`);
          rescans += 1;
          first = await clean.summonOpen(K2.digits).then((v) => ({ v }), (err) => ({ err }));
        }
        if (first.err) throw first.err;
        // Where the scan that was running when C rejoined ended: on A's
        // branch (the refresh below must then move it) or already on C's.
        const scanTip = first.v.tip;
        r = await clean.summonRefresh();
        assert.equal(r.tip, cHead.number, "the clean device's tip is C's head");
        const nowAtFork = (await B.rpc("eth_getBlockByNumber", [toQuantity(fork.number + 1), false])).hash;
        assert.notEqual(nowAtFork, aHashAfterFork, "B replaced A's branch");
        assert.equal(r.status, "unclaimed", "K2's coin, from before the fork, is on the new branch");
        assert.equal(clean.state.chainRefused, null);
        clean.summonClose();
        r = await clean.summonOpen(K4.digits);
        assert.equal(r.status, "not-found", "K4's commit, only on A's branch, is gone from the clean device's view");
        assert.equal(await B.rpc("eth_getTransactionReceipt", [K4.txHash]), null, "K4's commit is in no block of B's chain");
        clean.summonClose();
        // Mining resumes on A.
        pacerA = startBlockPacer({ rpc: A.rpc, intervalMs: 2000, warmUpBlocks: 0 });
        pacers.push(pacerA);
        return (
          `fork at block ${fork.number}; A's branch to ${aBranch.number} with K4's commit, C's to ${cHead.number}; ` +
          `a scan held at its first tree page on A's tip while B switched to C's branch ` +
          `${interrupted ? `stopped (${interrupted.slice(0, 200)}) and ` : ""}ended at block ${scanTip}` +
          `${rescans ? ` after ${rescans} restart(s)` : ""}; ` +
          `on refresh B and the clean device are on C's branch`
        );
      });

      await runCase("older-tree-state", async () => {
        await waitFor("K2 to be below the scan window", async () => (await B.head()).number - K2.block > STALE_ROOT_DEPTH + 2, { ms: 1000, limit: 600 });
        await synced();
        const tip = (await B.head()).number;
        let r = await clean.summonOpen(K2.digits);
        assert.equal(r.status, "unclaimed");
        assert.equal(r.current.amount, GHOST / 2n);
        assert.equal(r.wait, null, "an old coin needs no wait");
        const recipient2 = toHex(randomBytes(20));
        const reveal = await clean.summonReveal({ amount: "0.2", recipient: recipient2 });
        const receipt = await receiptOn(B, reveal.txHash, "K2's reveal");
        assert.equal(receipt.status, "0x1");
        assert.equal(receipt.type, "0x50");
        await waitFor("the recipient's balance on B", async () => (await balance(B, recipient2)) === GHOST / 5n);
        r = clean.state.summon;
        assert.equal(r.current.number, 1n, "the remainder stays under K2");
        clean.summonClose();
        return `K2, committed in block ${K2.block}, ${tip - K2.block} blocks below the tip, restored from its digits and 0.2 GHOST revealed in block ${reveal.block}`;
      });

      if (TREE_LEAVES === null) {
        await skipCase("rollover", ROLLOVER_SKIP);
        await skipCase("commitment-in-full-tree", FULL_TREE_SKIP);
      } else {
        // KB's coin, left in the full tree 0 for the last case.
        let inFullTree = null;
        await runCase("rollover", async () => {
          assert.ok(Number.isSafeInteger(TREE_LEAVES) && TREE_LEAVES > 0 && TREE_LEAVES < 2 ** 32, `GHOST_RECOVERY_TREE_LEAVES is ${TREE_LEAVES_SET}`);
          const KB = await vanish("0.4");
          const KA = await vanish("1");
          const before = await strangerCommitReceipt();
          let at = appendedAt(before);
          assert.equal(at.tree, 0, "coin tree 0 is not full before the filler");
          // The filler: strangers' commits of 1 wei, in batches the pool
          // takes, until coin tree 0 holds TREE_LEAVES leaves.
          let filledIn = Number(BigInt(before.blockNumber));
          for (let left = TREE_LEAVES - at.position - 1; left > 0; ) {
            const batch = Math.min(left, 200);
            const hashes = await sendStrangerCommits(batch, 1n);
            for (const hash of hashes) {
              const receipt = await receiptOn(A, hash, "a filler commit");
              assert.equal(receipt.status, "0x1");
              filledIn = Math.max(filledIn, Number(BigInt(receipt.blockNumber)));
            }
            left -= batch;
            console.log(`coin tree 0: ${TREE_LEAVES - left} of ${TREE_LEAVES} leaves`);
          }
          // The node takes no commitment in the block in which tree 0 filled;
          // tree 1 starts in a later block (spec 05).
          const head = await waitPastBlock({ rpc: A.rpc, block: filledIn });
          console.log(`coin tree 0 filled in block ${filledIn}; head ${head}`);
          at = appendedAt(await strangerCommitReceipt());
          assert.deepEqual(at, { tree: 1, position: 0 }, "the next commit starts coin tree 1 at position 0");
          // KA's partial reveal: its remainder lands in tree 1.
          const recipient = toHex(randomBytes(20));
          const s = await original.summonOpen(KA.key);
          assert.equal(s.wait, null, "KA can be revealed");
          const reveal = await original.summonReveal({ amount: "0.25", recipient });
          const remainderAt = appendedAt(await receiptOn(A, reveal.txHash, "KA's reveal"));
          assert.equal(remainderAt.tree, 1, "KA's remainder is in coin tree 1");
          original.summonClose();
          await strangerCommit();
          await synced();
          // The clean device reads both trees and restores KA across them.
          const r = await clean.summonOpen(KA.digits);
          assert.equal(r.status, "unclaimed");
          assert.equal(r.coins.length, 2, "KA's spent coin in tree 0 and its remainder in tree 1 are found");
          assert.ok(r.coins.find((c) => c.number === 0n)?.spent, "coin number 0 shows spent");
          assert.equal(r.current.number, 1n);
          assert.equal(r.current.amount, GHOST - GHOST / 4n - reveal.fee);
          clean.summonClose();
          inFullTree = KB;
          return `coin tree 0 filled at ${TREE_LEAVES} leaves; the next commit started tree 1; KA's remainder at tree 1, position ${remainderAt.position}, restored by the clean device`;
        });
        await runCase("commitment-in-full-tree", async () => {
          assert.ok(inFullTree, "the rollover case left KB's coin in the full tree 0");
          let r = await clean.summonOpen(inFullTree.digits);
          assert.equal(r.status, "unclaimed", "KB's coin in the full tree 0 is found");
          assert.equal(r.current.amount, (GHOST * 4n) / 10n);
          assert.equal(r.wait, null, "a coin in a full earlier tree needs no wait");
          const recipient = toHex(randomBytes(20));
          const reveal = await clean.summonReveal({ amount: "0.1", recipient });
          const receipt = await receiptOn(B, reveal.txHash, "KB's reveal");
          assert.equal(receipt.status, "0x1");
          await waitFor("the recipient's balance on B", async () => (await balance(B, recipient)) === GHOST / 10n);
          r = clean.state.summon;
          assert.equal(r.current.number, 1n, "the remainder stays under KB");
          clean.summonClose();
          return `KB, committed in block ${inFullTree.block} in coin tree 0, restored from its digits after the rollover and 0.1 GHOST revealed in block ${reveal.block}`;
        });
      }

      assert.equal(clean.state.chainRefused, null, "the independent node's chain passed the clean device's proof-of-work check");
      assert.deepEqual(cleanDeviceAsked, [], "the clean device asked nothing but the independent node");
      assert.deepEqual(offLoopback, [], "nothing in this test left the internal network");
      assert.equal(broken, null, `case ${broken} failed`);
    } catch (err) {
      for (const n of nodes) console.error(`--- last lines of geth ${n.name}'s log ---\n${n.tail()}`);
      throw err;
    } finally {
      following = false;
      await Promise.all(followers);
      for (const p of provers) p.terminate();
      for (const p of pacers) await p.stop();
      for (const n of nodes) await n.stop();
      await saveResults();
      await rm(root, { recursive: true, force: true });
    }
  });
}
