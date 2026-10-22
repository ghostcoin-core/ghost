// The test-depth reveal (lib.rs, test_depth; flow.mjs, TEST_DEPTH_REVEAL): a
// module built with the test-tree-depth feature reveals a coin of a 14-level
// coin tree, as the test node of spec 05, RT-1 Part B builds them, with the
// stub proof that node's verifier takes (RT-8 Part B) in place of a STARK:
// K("ghost/test-proof/v1", binding digest) in the first 32 bytes of the
// proof field and zeros after. The default module has no such reveal and
// still refuses one with SMALL_TREE_REVEAL, and a flow of 32 levels never
// asks for it.
//
// GHOST_WEBAPP_TEST_DEPTH_WASM names the test-depth module; without it the
// module is built into ghost-test-depth under the temporary directory.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { concat, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, SMALL_TREE_REVEAL, createFlow, keccak256, treeRootsAt } from "../src/flow.mjs";
import { Ghost } from "../src/wasm.mjs";
import {
  buildModuleIfMissing,
  loadModule,
  nodeProver,
  openTestWallet,
  testDepthTargetDir,
  testDepthWasmPath,
  wasmPath,
} from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

buildModuleIfMissing(wasmPath);
if (!process.env.GHOST_WEBAPP_TEST_DEPTH_WASM) {
  buildModuleIfMissing(testDepthWasmPath, { features: "test-tree-depth", targetDir: testDepthTargetDir });
}
const release = await loadModule(wasmPath);
const testDepth = await loadModule(testDepthWasmPath);
// The stand-in of a test node: it decodes a reveal as that node does, taking
// the stub proof (lib.rs, ghost_decode_envelope_test_depth).
const testNode = new Ghost({ ...testDepth.w, ghost_decode_envelope: testDepth.w.ghost_decode_envelope_test_depth });

const SMALL_DEPTH = 14;
const TREE_LEAVES = 3;
const GHOST = 10n ** 18n;
const RECIPIENT = "0x00000000000000000000000000000000000beef1";
// The envelope (spec 07, section 3): type, version, chain identifier,
// marker, root, remainder, recipient, out and fee, then the proof field and
// the note.
const PROOF_AT = 1 + 2 + 8 + 32 + 32 + 32 + 20 + 32 + 32;
const PROOF_FIELD_BYTES = 1_310_720;
const field = (envelope, at, n) => envelope.slice(at, at + n);

const tagged = (tag, ...parts) => keccak256(concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag), ...parts]));

// The stub proof of a salted coin reveal, from the envelope's own fields and
// the chain's genesis hash: the coin reveal binding digest (spec 02, section
// 7: chain identifier, version 0x0001, domain, statement 0x01, statement
// version 0x01, type COIN_V2 0x0201, purpose 0x01, then root, marker,
// remainder, recipient, out, fee, the empty rule and the remainder's note)
// under K("ghost/test-proof/v1", ...).
function stubOf(envelope, domain) {
  const binding = tagged(
    "ghost/coin-reveal-binding/v1",
    field(envelope, 3, 8),
    Uint8Array.of(0x00, 0x01),
    domain,
    Uint8Array.of(0x01, 0x01, 0x02, 0x01, 0x01),
    field(envelope, 43, 32), // root
    field(envelope, 11, 32), // marker
    field(envelope, 75, 32), // remainder
    field(envelope, 107, 20), // recipient
    field(envelope, 127, 32), // out
    field(envelope, 159, 32), // fee
    new Uint8Array(32), // rule
    envelope.slice(PROOF_AT + PROOF_FIELD_BYTES), // note
  );
  return tagged("ghost/test-proof/v1", binding);
}

// A prover that records the ops the flow asks for and the test-depth results.
function watchedProver(prover) {
  const asked = [];
  const proved = [];
  return {
    asked,
    proved,
    async request(op, args, onProgress) {
      asked.push(op);
      const result = await prover.request(op, args, onProgress);
      if (op === "proveTestDepth") proved.push(result);
      return result;
    },
  };
}

// A coin of key K in tree 0 of a chain of `treeDepth`-level trees of three
// leaves, filled by strangers and followed by tree 1, settled; `fn` gets the
// stand-in, the opened flow and K.
async function withCoinInFullTree({ ghost, path, treeDepth }, fn) {
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, treeDepth, treeLeaves: TREE_LEAVES });
  const prover = nodeProver(path);
  const watched = watchedProver(prover);
  try {
    const flow = createFlow({
      prover: watched,
      endpoint: node.url,
      networks: node.networks(),
      pollMs: 5,
      sleep: async () => node.mine(),
      treeDepth,
      treeLeaves: TREE_LEAVES,
    });
    await openTestWallet(flow, node);
    node.foreignCommits(1);
    const key = await flow.vanishStart("1");
    assert.equal((await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]))).ok, true);
    node.foreignCommits(2);
    node.mineTo(node.tip() + 2);
    const s = await flow.summonOpen(key);
    assert.equal(s.status, "unclaimed");
    assert.deepEqual([s.current.treeIndex, s.current.position], [0, 1], "the coin is leaf 1 of the full tree 0");
    assert.equal(s.wait, null);
    return await fn({ node, flow, key, watched });
  } finally {
    prover.terminate();
    await node.close();
  }
}

test("only the test-depth module has the test-depth reveal", () => {
  const names = (ghost) => new Set(Object.keys(ghost.w));
  const testOnly = ["ghost_prove_test_depth", "ghost_test_depth_levels", "ghost_decode_envelope_test_depth"];
  for (const name of testOnly) {
    assert.ok(names(testDepth).has(name), `the test-depth module exports ${name}`);
    assert.ok(!names(release).has(name), `the default module has no ${name}`);
  }
  assert.equal(testDepth.w.ghost_test_depth_levels(), SMALL_DEPTH);
  // Apart from those, the two modules export the same.
  assert.deepEqual([...names(testDepth)].filter((n) => !testOnly.includes(n)).sort(), [...names(release)].sort());
});

test("on a node of 14-level trees the test-depth module reveals a coin of a full tree with the stub proof, and the stand-in takes it", async () => {
  await withCoinInFullTree({ ghost: testNode, path: testDepthWasmPath, treeDepth: SMALL_DEPTH }, async ({ node, flow, watched }) => {
    const filled = node.blocks.findIndex((b) => b.leafCount === TREE_LEAVES);
    const treeZero = concat(node.leaves.slice(0, TREE_LEAVES).map((l) => l.commitment));
    const headerRoot = node.blocks[filled].coinTreeRoot;
    assert.equal(toHex(headerRoot), toHex(treeRootsAt(SMALL_DEPTH, treeZero).root), "the header carries tree 0's 14-level root");

    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(node.reveals.length, 1, "the stand-in took the reveal");
    const reveal = node.reveals[0];
    assert.equal(toHex(reveal.root), toHex(headerRoot), "proved against tree 0's 14-level root");
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
    assert.ok(watched.asked.includes("testDepthProver") && watched.asked.includes("proveTestDepth"));
    assert.ok(!watched.asked.includes("prove"), "no STARK is asked for");

    // The envelope: its proof field is the stub of its own binding digest,
    // then zeros.
    assert.equal(watched.proved.length, 1);
    const { envelope, txHash } = watched.proved[0];
    assert.equal(toHex(txHash), reveal.hash, "the stand-in took this envelope");
    assert.equal(envelope.length, PROOF_AT + PROOF_FIELD_BYTES + 156);
    assert.equal(toHex(field(envelope, 43, 32)), toHex(headerRoot));
    const proof = field(envelope, PROOF_AT, PROOF_FIELD_BYTES);
    assert.equal(proof.length, 1_310_720);
    assert.ok(proof.slice(32).every((b) => b === 0), "every byte after the first 32 is zero");
    assert.equal(toHex(proof.slice(0, 32)), toHex(stubOf(envelope, node.blocks[0].hash)), "the first 32 bytes are the stub");
    assert.equal(toHex(keccak256(envelope)), toHex(txHash));

    // Only that stub is taken: a changed stub, a byte after it or a decoder
    // that takes real proofs only, the default module's or the test-depth
    // module's own, refuse it.
    const decode = (ghost, bytes) => ghost.decodeEnvelope({ chainId: chainIdOf(envelope), domain: node.blocks[0].hash, envelope: bytes });
    assert.equal(toHex(decode(testNode, envelope.slice()).txHash), toHex(txHash));
    const changed = envelope.slice();
    changed[PROOF_AT] ^= 1;
    assert.throws(() => decode(testNode, changed), /the proof does not verify/);
    const trailing = envelope.slice();
    trailing[PROOF_AT + 32] = 1;
    assert.throws(() => decode(testNode, trailing), /the proof does not verify/);
    assert.throws(() => decode(release, envelope.slice()), /the proof does not verify/);
    assert.throws(() => decode(testDepth, envelope.slice()), /the proof does not verify/);

    // The remainder is the key's next coin, in tree 1.
    const s = flow.state.summon;
    assert.deepEqual([s.current.treeIndex, s.current.number], [1, 1n]);
    assert.equal(toHex(node.leaves.at(-1).commitment), toHex(reveal.remainder));
  });
});

test("the default module still refuses a reveal against a 14-level tree with SMALL_TREE_REVEAL", async () => {
  await withCoinInFullTree({ ghost: release, path: wasmPath, treeDepth: SMALL_DEPTH }, async ({ node, flow, watched }) => {
    await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => err.message === SMALL_TREE_REVEAL);
    assert.equal(node.reveals.length, 0, "nothing was sent");
    assert.ok(watched.asked.includes("testDepthProver"));
    assert.ok(!watched.asked.includes("proveTestDepth"), "the test-depth reveal is never asked of the default module");
  });
});

test("a flow of 32-level trees never asks for the test-depth reveal, even of the test-depth module", async () => {
  await withCoinInFullTree({ ghost: testDepth, path: testDepthWasmPath, treeDepth: 32 }, async ({ node, flow, watched }) => {
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(node.reveals.length, 1);
    assert.ok(watched.asked.includes("prove"), "the coin is proved with a STARK");
    assert.ok(!watched.asked.includes("testDepthProver") && !watched.asked.includes("proveTestDepth"));
    assert.equal(watched.proved.length, 0);
  });
});

function chainIdOf(envelope) {
  return new DataView(envelope.buffer, envelope.byteOffset + 3, 8).getBigUint64(0);
}
