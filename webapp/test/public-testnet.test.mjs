// The public test network, the one the one-line installer joins: this
// build's entry for it (header.mjs, NETWORKS) and its real chain.
//
// The entry's params are the network's own in ghost-node at 853ca88786fe
// (params/ghost/testnet.go, TestNetParams: the 30-second launch preset of
// consensus/ghostrules with its own start and minimum difficulty), and its
// genesis is TestNetGenesis there. The fixture holds blocks 0 to 24 as
// eth_getBlockByNumber (full transactions off) returned them, recorded
// once from a build-26-853ca88786fe node synced from the network's seeds.
//
// The recorded headers are fed through the module's header chain at the
// entry's params, and through the flow itself with this build's table and a
// stand-in endpoint that serves the fixture: the start is the pinned
// genesis, every hash recomputes, every difficulty and RandomX seal checks,
// and the page adopts the chain to its tip. A header altered after the fact
// is refused.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { fromHex, toHex } from "../src/bytes.mjs";
import { POW_FAILED, createFlow } from "../src/flow.mjs";
import { NETWORKS, networkOf, readHeader } from "../src/header.mjs";
import { buildModuleIfMissing, loadModule, nodeProver, wasmPath } from "./support/env.mjs";

// The module is built as webapp/README.md's "Test it" builds it, when no
// build is there yet, with the toolchain CI pins.
buildModuleIfMissing(wasmPath);

const CHAIN_ID = 6_777_972;
const GENESIS_HASH = "0xdfe4271fd12d302e15c68e381ade8076207f70d3778eebd69604566fb6979436";
const GENESIS_TIMESTAMP = 1_793_124_000;
// ghost-node at 853ca88786fe: ghostrules.Launch30s() for the block time,
// half-life and drift; TestNetStartDifficulty (2^14) and TestNetMinDifficulty
// (2^12).
const GHOST_NODE_PARAMS = { blockTime: 30, halfLife: 3600, startDifficulty: 16384, minDifficulty: 4096, futureDrift: 30 };

const BLOCKS = JSON.parse(readFileSync(new URL("./fixtures/public-testnet-headers.json", import.meta.url), "utf8"));
const TIP = BLOCKS.length - 1;
// A clock a minute past the recorded tip.
const NOW = Number(BigInt(BLOCKS[TIP].timestamp)) + 60;

test("this build lists the public test network: chain id, genesis and the chain constants of ghost-node", () => {
  const entry = networkOf(NETWORKS, CHAIN_ID);
  assert.ok(entry, "network 6777972 has an entry");
  assert.equal(networkOf(NETWORKS, 6_777_972n), entry, "found by the chain id as eth_chainId reads");
  assert.deepEqual({ ...entry.params }, GHOST_NODE_PARAMS);
  assert.equal(entry.genesisTimestamp, GENESIS_TIMESTAMP);
  assert.equal(entry.genesisHash, GENESIS_HASH);
  assert.equal(entry.pin, null, "the chain is checked from genesis");
  assert.ok(Object.isFrozen(NETWORKS));
});

test("the fixture is the network's chain from its genesis", () => {
  assert.ok(TIP >= 20, "blocks 0 to 20 at least");
  BLOCKS.forEach((block, n) => assert.equal(Number(BigInt(block.number)), n));
  assert.equal(BLOCKS[0].hash, GENESIS_HASH);
  assert.equal(Number(BigInt(BLOCKS[0].timestamp)), GENESIS_TIMESTAMP);
  assert.equal(BigInt(BLOCKS[0].difficulty), BigInt(GHOST_NODE_PARAMS.startDifficulty));
  for (let n = 1; n <= TIP; n += 1) assert.equal(BLOCKS[n].parentHash, BLOCKS[n - 1].hash);
});

test("the module's header chain at the entry's params adopts the recorded headers from genesis", async () => {
  const ghost = await loadModule();
  const entry = NETWORKS[String(CHAIN_ID)];
  const headers = BLOCKS.map((block) => ({ hash: fromHex(block.hash, 32), rlp: readHeader(block).rlp }));
  for (const { hash, rlp } of headers) assert.equal(toHex(ghost.keccak256(rlp)), toHex(hash), "each header hashes to its block hash");

  const start = ghost.chainStart({ params: entry.params, start: { header: headers[0].rlp } });
  assert.equal(toHex(start), GENESIS_HASH);
  const added = ghost.chainAdd({ now: NOW, headers: headers.slice(1) });
  assert.equal(added.refused, null);
  assert.equal(added.adopted, TIP);
  assert.equal(added.best.height, BigInt(TIP));
  assert.equal(toHex(added.best.hash), BLOCKS[TIP].hash);
  const work = BLOCKS.reduce((sum, block) => sum + BigInt(block.difficulty), 0n);
  assert.equal(added.best.work, work, "the total work is the sum of the recorded difficulties");

  // At other constants the same headers carry the wrong difficulty.
  ghost.chainStart({ params: { ...entry.params, minDifficulty: 8192 }, start: { header: headers[0].rlp } });
  const wrong = ghost.chainAdd({ now: NOW, headers: [headers[1]] });
  assert.equal(wrong.refused.why, "check");
  assert.match(wrong.refused.reason, /required difficulty/);
});

// A stand-in endpoint on the network that serves `blocks` and nothing but
// headers and their (empty) receipts.
function fixtureEndpoint(blocks) {
  const answer = (method, params) => {
    if (method === "eth_chainId") return { result: `0x${CHAIN_ID.toString(16)}` };
    if (method === "eth_blockNumber") return { result: blocks.at(-1).number };
    if (method === "eth_getBlockByNumber") {
      const n = params[0] === "latest" ? blocks.length - 1 : Number(BigInt(params[0]));
      return { result: blocks[n] ?? null };
    }
    if (method === "eth_getBlockReceipts") return { result: blocks.some((b) => b.hash === params[0]) ? [] : null };
    return { error: { code: -32601, message: `the stand-in serves no ${method}` } };
  };
  const fetch = async (_url, { body }) => {
    const { id, method, params } = JSON.parse(body);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id, ...answer(method, params) }), { headers: { "content-type": "application/json" } });
  };
  return fetch;
}

// The flow with this build's table (no `networks` given), its saves kept.
function flowOn(blocks) {
  const saves = [];
  const headerStore = {
    async load() {
      return [];
    },
    async save(key, records) {
      saves.push({ key, records });
    },
    async clear() {},
  };
  const prover = nodeProver();
  const flow = createFlow({ prover, fetch: fixtureEndpoint(blocks), headerStore, clock: () => NOW, sleep: async () => {} });
  return { flow, prover, saves };
}

test("the page adopts the public test network's real chain from the pinned genesis", async () => {
  const { flow, prover, saves } = flowOn(BLOCKS);
  try {
    const { key } = await prover.request("newKey");
    // The headers pass; the scan then stops at the coin tree, which the
    // stand-in does not serve.
    await assert.rejects(flow.summonOpen(key), (err) => {
      assert.ok(!err.message.startsWith(POW_FAILED), err.message);
      assert.doesNotMatch(err.message, /no pinned start|shows no confirmations/);
      assert.match(err.message, /the stand-in serves no ghost_/);
      return true;
    });
    assert.equal(flow.state.chainRefused, null);
    assert.equal(saves.length, 1, "the adopted headers are saved once");
    assert.equal(saves[0].key, `${CHAIN_ID}:${GENESIS_HASH}`, "kept for this network from its genesis");
    assert.deepEqual(
      saves[0].records.map((r) => r.hash),
      BLOCKS.slice(1).map((b) => b.hash),
      "blocks 1 to the tip, all adopted",
    );
  } finally {
    prover.terminate();
  }
});

test("a recorded header with an altered seal is refused: no confirmations", async () => {
  const altered = structuredClone(BLOCKS);
  const n = 7;
  altered[n].nonce = `0x${(BigInt(altered[n].nonce) ^ 1n).toString(16).padStart(16, "0")}`;
  const { flow, prover, saves } = flowOn(altered);
  try {
    const { key } = await prover.request("newKey");
    // The block's hash no longer recomputes from its header.
    await assert.rejects(flow.summonOpen(key), new RegExp(`header of block ${n} does not hash to the block hash`));
    assert.equal(saves.length, 0, "nothing is saved");

    // Rehashed to match, the seal itself fails.
    const { flow: second, prover: other, saves: saved } = flowOn(rehashed(altered, n, await loadModule()));
    try {
      await assert.rejects(second.summonOpen(key), (err) => {
        assert.ok(err.message.startsWith(POW_FAILED), err.message);
        assert.match(err.message, new RegExp(`block ${n}: the seal's hash is above the target`));
        return true;
      });
      assert.match(second.state.chainRefused, /shows no confirmations/);
      assert.equal(saved.length, 0);
    } finally {
      other.terminate();
    }
  } finally {
    prover.terminate();
  }
});

// `blocks` with the hash of block `n` recomputed from its fields, and the
// parent hashes above it relinked and rehashed.
function rehashed(blocks, n, ghost) {
  const out = structuredClone(blocks);
  for (let i = n; i < out.length; i += 1) {
    if (i > n) out[i].parentHash = out[i - 1].hash;
    out[i].hash = toHex(ghost.keccak256(readHeader(out[i]).rlp));
  }
  return out;
}
