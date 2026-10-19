// Vanish, a partial Summon and a Claim with the real prover against a real
// release `geth` of ghost-node, not the stand-in: a one-node internal
// network (chain 6777971) that mines its own blocks. The web app's flow
// controller drives it exactly as the page does; the wallet is the node's
// own unlocked miner account, through eth_sendTransaction as a browser
// wallet would send it. The test then reads the chain itself: the commit's
// 190 bytes and its leaf, the reveal's marker, the remainder's leaf, the
// recipient's balance, and the claim.
//
// GHOST_NODE_GETH is the path to the geth binary (webapp/scripts/build-node.sh
// builds one at the commit in NODE_COMMIT). Without it the test prints
// `SKIP: GHOST_NODE_GETH is not set` and runs nothing. It is not loaded from
// test/index.js.
//
// The genesis is the internal network's (params/ghost InternalNetGenesis in
// ghost-node, written out in its scripts/internal-net.sh, which a test in
// ghost-node keeps equal to it); the miner key is that script's fixed test
// key, the number 6777971.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { concat, fromHex, toHex, toQuantity } from "../../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, WaitError, createFlow } from "../../src/flow.mjs";
import { loadModule, nodeProver } from "../support/env.mjs";

const GETH = process.env.GHOST_NODE_GETH;
const NETWORK_ID = 6_777_971n;
const GHOST = 10n ** 18n;
const NOTE_BYTES = 156;
const PAGE = 4096;
const EPOCH = 32;
const EPOCH_DEPTH = 12;
// Test-only miner key and keystore password, as in ghost-node's script.
const MINER_KEY_NUMBER = 6_777_971;
const KEYSTORE_PASSWORD = "internal-net-test-only";

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

// A one-node internal network in a temporary directory: init, the miner key
// imported, then geth mining with HTTP JSON-RPC on a port the system picks.
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
  await writeFile(join(dir, "miner.key"), `${MINER_KEY_NUMBER.toString(16).padStart(64, "0")}\n`);
  await writeFile(join(dir, "password"), `${KEYSTORE_PASSWORD}\n`);
  const datadir = join(dir, "node");
  run(["--datadir", datadir, "init", genesis]);
  const imported = run(["--datadir", datadir, "--lightkdf", "account", "import", "--password", join(dir, "password"), join(dir, "miner.key")]);
  const found = /Address: \{([0-9a-fA-F]{40})\}/.exec(imported);
  if (!found) throw new Error(`could not read the miner address from: ${imported}`);
  const miner = `0x${found[1].toLowerCase()}`;

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
      "--unlock", miner, "--password", join(dir, "password"),
      // The miner account is the test's wallet; the endpoint listens on
      // 127.0.0.1 only.
      "--allow-insecure-unlock",
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

    // A commit by someone else, from the miner: a random F and a note no key
    // opens. It puts a leaf after ours, which the epoch rule waits for.
    async function strangerCommit() {
      const data = concat([Uint8Array.of(0x00, 0x01), randomBytes(32), randomBytes(NOTE_BYTES)]);
      const hash = await rpc("eth_sendTransaction", [
        { from: node.miner, to: DEFAULT_COMMIT_ENTRY, value: toQuantity(GHOST / 100n), data: toHex(data) },
      ]);
      const receipt = await receiptOf(hash);
      assert.equal(receipt.status, "0x1", "the stranger's commit is executed");
      return Number(BigInt(receipt.blockNumber));
    }

    // Until the epoch block at or after `block` is 12 blocks deep, so that
    // the epoch tree holds a leaf added after the coin's.
    async function waitEpochAfter(block) {
      const epoch = Math.ceil(block / EPOCH) * EPOCH;
      await waitFor(`block ${epoch + EPOCH_DEPTH}`, async () => (await blockNumber()) >= epoch + EPOCH_DEPTH);
    }

    // The wallet: the node's unlocked miner account, as an EIP-1193 provider.
    const walletCalls = [];
    const wallet = {
      async request({ method, params }) {
        walletCalls.push({ method, params });
        if (method === "eth_requestAccounts" || method === "eth_accounts") return [node.miner];
        if (method === "eth_chainId") return rpc("eth_chainId");
        if (method === "eth_sendTransaction") return rpc("eth_sendTransaction", params);
        throw Object.assign(new Error("unsupported"), { code: 4200 });
      },
    };

    const flow = createFlow({ prover, wallet, endpoint: node.url, pollMs: 1000, maxPolls: 1800 });

    // The last block at which a commit in block `block` can still let a coin
    // before it be revealed: the epoch window ending at the epoch block E
    // after it holds the commit until E + 32 is the epoch block, which the
    // app picks from block E + 32 + 12 on.
    const lastUsefulBlock = (block) => Math.ceil(block / EPOCH) * EPOCH + EPOCH + EPOCH_DEPTH - 1;

    // A reveal or claim, again whenever the epoch rule says to wait. Each
    // reason is logged. The wait is bounded in blocks: past the next epoch
    // block and its depth, plus one epoch window, from the tip when the
    // first wait starts: the step before it proves for tens of seconds while
    // blocks keep coming, so a tip read before it is long gone. When no
    // commitment followed the coin inside the window, a stranger commits
    // again and the step waits for that commit's epoch; that is done at most
    // STRANGER_COMMITS times, so the wait ends.
    const STRANGER_COMMITS = 3;
    async function untilEpoch(step) {
      let startTip = null;
      let deadline = null;
      let commits = 0;
      for (;;) {
        assert.ok(node.alive(), "geth stopped while waiting for the epoch rule");
        try {
          return await step();
        } catch (err) {
          if (!(err instanceof WaitError)) throw err;
          if (startTip === null) {
            startTip = await blockNumber();
            deadline = lastUsefulBlock(startTip + 1);
          }
          const tip = await blockNumber();
          console.log(`epoch rule holds: ${err.message} (tip ${tip}, gives up after block ${deadline})`);
          if (err.message.startsWith("no commitment followed the coin")) {
            if (commits === STRANGER_COMMITS) {
              throw new Error(`the epoch rule never let the coin be revealed after ${commits} more stranger commits: ${err.message}`);
            }
            commits += 1;
            const block = await strangerCommit();
            console.log(`a stranger committed in block ${block}; waiting for its epoch block`);
            deadline = lastUsefulBlock(block);
            await waitEpochAfter(block);
          } else if (tip > deadline) {
            throw new Error(`the epoch rule never let the coin be revealed by block ${deadline}: ${err.message}`);
          } else {
            await sleep(5000);
          }
        }
      }
    }

    try {
      assert.equal(BigInt(await rpc("eth_chainId")), NETWORK_ID);
      assert.equal((await rpc("eth_getBlockByNumber", ["0x0", false])).timestamp, "0x6abda280", "the internal network's genesis");
      // Test funds come only from block rewards.
      await waitFor("the miner's funds", async () => (await balance(node.miner)) >= 2n * GHOST);

      // --- Vanish: 1 GHOST into a new key ---
      await flow.connectWallet();
      const key = await flow.vanishStart("1");
      const positions = flow.vanishSaved();
      const sent = await flow.vanishCheck(answersFor(key, positions));
      assert.equal(sent.ok, true);
      assert.equal(flow.state.vanish.stage, "confirmed");

      // On chain: a transaction to the commit entry address of 1 GHOST whose
      // data is the 190 bytes of ghostpriv.CommitData, version 0x0001, and a
      // new leaf C = K(tag, COIN, F, v).
      const commitTx = await rpc("eth_getTransactionByHash", [sent.txHash]);
      assert.equal(String(commitTx.to).toLowerCase(), DEFAULT_COMMIT_ENTRY);
      assert.equal(BigInt(commitTx.value), GHOST);
      const data = fromHex(commitTx.input);
      assert.equal(data.length, 190);
      assert.equal(toHex(data.slice(0, 2)), "0x0001");
      const commitReceipt = await rpc("eth_getTransactionReceipt", [sent.txHash]);
      assert.equal(commitReceipt.status, "0x1");
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

      // A leaf after ours, then an epoch block that holds both.
      await waitEpochAfter(await strangerCommit());

      // --- Summon: 0.25 GHOST to a fresh address ---
      const recipient = toHex(randomBytes(20));
      assert.equal(await balance(recipient), 0n);
      let s = await flow.summonOpen(key);
      assert.equal(s.status, "unclaimed");
      assert.equal(s.current.amount, GHOST);
      const reveal = await untilEpoch(() => flow.summonReveal({ amount: "0.25", recipient }));
      const left = GHOST - GHOST / 4n - reveal.fee;

      const revealReceipt = await rpc("eth_getTransactionReceipt", [reveal.txHash]);
      assert.equal(revealReceipt.status, "0x1");
      assert.equal(revealReceipt.type, "0x50", "a private transaction");
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

      await waitEpochAfter(await strangerCommit());

      // --- Claim: the remainder to a new key ---
      const newKey = await flow.claimStart();
      const claimPositions = flow.claimSaved();
      const claimed = await untilEpoch(() => flow.claimCheck(answersFor(newKey, claimPositions)));
      assert.equal(claimed.ok, true);
      assert.ok(claimed.amount > 0n && claimed.amount < left, "the claim pays its fee from the remainder");
      const claimReceipt = await rpc("eth_getTransactionReceipt", [claimed.txHash]);
      assert.equal(claimReceipt.status, "0x1");
      assert.equal(claimReceipt.type, "0x50");
      const claimLog = fromHex(claimReceipt.logs[0].data);
      assert.equal(toHex(claimLog.slice(196, 216)), "0x0000000000000000000000000000000000000000");
      assert.equal(BigInt(toHex(claimLog.slice(216, 248))), 0n, "a claim sends nothing out");
      tree = await chainTree();
      assert.ok(tree.leaves.includes(toHex(claimLog.slice(8, 40))), "the claimed coin's leaf is in the coin tree");
      assert.equal(await balance(recipient), GHOST / 4n, "the claim leaves the recipient's balance as it was");

      // The old key shows claimed, the new key holds the claimed amount.
      s = await flow.summonOpen(key);
      assert.equal(s.status, "claimed");
      s = await flow.summonOpen(newKey);
      assert.equal(s.status, "unclaimed");
      assert.equal(s.current.amount, claimed.amount);
      flow.summonClose();
      assert.equal(walletCalls.filter((c) => c.method === "eth_sendTransaction").length, 1, "the wallet sent the commit only");
    } catch (err) {
      console.error(`--- last lines of geth's log ---\n${node.tail()}`);
      throw err;
    } finally {
      prover.terminate();
      await node.stop();
    }
  });
}
