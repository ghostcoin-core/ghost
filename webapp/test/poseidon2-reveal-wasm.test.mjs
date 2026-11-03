// The Poseidon2 reveal in the module (lib.rs, mod poseidon2_reveal): the
// version 2 coin reveal proved and verified with the proofs crate's Poseidon2
// parameters, through the background worker's message interface
// (worker-core.mjs) and through wasm.mjs. An honest reveal proves and
// verifies; a proof with one flipped byte, cut short or with a byte added is
// rejected; so is the proof against other public fields or chain constants;
// and the prover refuses, before proving, every case the native prover
// refuses, with its message.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { concat, equalBytes, fromWord, word } from "../src/bytes.mjs";
import { createProver } from "../src/prover.mjs";
import { NOTE_BYTES, SALT_BYTES } from "../src/wasm.mjs";
import { createWorker } from "../src/worker-core.mjs";
import { buildModuleIfMissing, loadModule, wasmPath } from "./support/env.mjs";

buildModuleIfMissing(wasmPath);
const ghost = await loadModule();

// The modeled bound on the proof (proofs crate, SCALE_MODELED_PROOF_BYTES),
// and the proof field a transaction carries today, which it does not fit.
const SCALE_MODELED_PROOF_BYTES = 2_330_908;
const PROOF_FIELD_BYTES = 1_310_720;

const fill = (length, byte) => new Uint8Array(length).fill(byte);
const encoder = new TextEncoder();
const COIN_V2 = Uint8Array.of(0x02, 0x01);
const EMPTY_RULE = new Uint8Array(32);

// K(tag, parts): Keccak-256 of the tag's length, the tag and the parts
// (proofs crate, hash.rs, `tagged`), with the module's Keccak-256.
const tagged = (tag, parts) => ghost.keccak256(concat([Uint8Array.of(tag.length), encoder.encode(tag), ...parts]));
const fingerprint = (coin, rule) =>
  tagged("ghost/coin-fingerprint/v2", [coin.s, coin.r, coin.b, coin.salt, COIN_V2, new Uint8Array(32), rule]);
const commitment = (coin, rule) => ghost.coinCommitment(fingerprint(coin, rule), coin.amount, 2);
const markerOf = (coin) => tagged("ghost/coin-marker/v2", [coin.r, coin.b, coin.salt]);
const overrideHash = (secret) => tagged("ghost/policy-override/v1", [secret]);

// Test values only: chain constants and coin secrets that are not Ghost's.
const CHAIN_ID = 7777001n;
const DOMAIN = fill(32, 0x11);
const OUT = 600_000n;
const FEE = 21n;
const COIN = { s: fill(32, 1), r: fill(32, 2), b: fill(32, 3), salt: fill(SALT_BYTES, 0xa5), amount: 1_000_000n, position: 2 };
const REMAINDER = { s: fill(32, 1), r: fill(32, 2), b: fill(32, 4), salt: fill(SALT_BYTES, 0x3c), amount: COIN.amount - OUT - FEE };
const LEAVES = [fill(32, 0x71), fill(32, 0x72), commitment(COIN, EMPTY_RULE), fill(32, 0x73)];
const ROOT = ghost.treeRoots(concat(LEAVES)).root;
const RECIPIENT = fill(20, 0x99);
const NOTE = fill(NOTE_BYTES, 0x33);

const request = (overrides = {}) => ({
  chainId: CHAIN_ID,
  domain: DOMAIN,
  opening: COIN,
  spend: null,
  remainder: REMAINDER,
  remainderRule: EMPTY_RULE,
  root: ROOT,
  recipient: RECIPIENT,
  out: OUT,
  fee: FEE,
  remainderNote: NOTE,
  leaves: LEAVES,
  ...overrides,
});

// The worker's message interface over the built module, in this thread.
function moduleWorker() {
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

const worker = moduleWorker();
const stages = [];
const PROVED = await worker.request("provePoseidon2Reveal", request(), (stage) => stages.push(stage));
const { reveal: REVEAL, proof: PROOF } = PROVED;
const verify = (reveal, proof, chain = {}) =>
  ghost.verifyPoseidon2Reveal({ chainId: CHAIN_ID, domain: DOMAIN, reveal, proof, ...chain });

test("the worker proves a reveal with the Poseidon2 parameters and it verifies", async () => {
  assert.deepEqual(stages.slice(-2), ["proving", "proved"]);
  assert.equal(typeof PROVED.provingMs, "number");
  assert.ok(PROVED.provingMs > 0);

  // The public fields are those the shipped statement publishes: the root,
  // the coin's marker, the remainder's commitment, the recipient, the
  // amounts and the note, with their own Keccak-256 hashes.
  assert.ok(equalBytes(REVEAL.root, ROOT), "root");
  assert.ok(equalBytes(REVEAL.marker, markerOf(COIN)), "marker");
  assert.ok(equalBytes(REVEAL.remainder, commitment(REMAINDER, EMPTY_RULE)), "remainder");
  assert.ok(equalBytes(REVEAL.recipient, RECIPIENT), "recipient");
  assert.equal(fromWord(REVEAL.out), OUT);
  assert.equal(fromWord(REVEAL.fee), FEE);
  assert.ok(equalBytes(REVEAL.remainderNote, NOTE), "note");

  // A real proof of the Poseidon2 configuration: within the modeled bound,
  // and larger than the proof field a transaction carries today.
  console.log(`Poseidon2 reveal: ${PROOF.length} bytes, proved in ${Math.round(PROVED.provingMs)} ms`);
  assert.ok(PROOF.length <= SCALE_MODELED_PROOF_BYTES, `${PROOF.length} bytes`);
  assert.ok(PROOF.length > PROOF_FIELD_BYTES, `${PROOF.length} bytes`);

  const verified = await worker.request("verifyPoseidon2Reveal", { chainId: CHAIN_ID, domain: DOMAIN, reveal: REVEAL, proof: PROOF });
  assert.equal(verified.ok, true);
  assert.equal(typeof verified.verifyingMs, "number");
  assert.equal(verify(REVEAL, PROOF), true);
});

test("a proof with one flipped byte is rejected", async () => {
  const len = PROOF.length;
  for (const at of [1, 20, Math.floor(len / 7), Math.floor(len / 3), Math.floor(len / 2), Math.floor((2 * len) / 3), len - 40, len - 1]) {
    const flipped = PROOF.slice();
    flipped[at] ^= 0x01;
    assert.throws(() => verify(REVEAL, flipped), Error, `byte ${at} of ${len} flipped`);
  }
  // Through the worker, a flipped byte is an error reply.
  const flipped = PROOF.slice();
  flipped[Math.floor(len / 2)] ^= 0x01;
  await assert.rejects(worker.request("verifyPoseidon2Reveal", { chainId: CHAIN_ID, domain: DOMAIN, reveal: REVEAL, proof: flipped }));
  // Cut short by a byte, or with a byte appended.
  assert.throws(() => verify(REVEAL, PROOF.slice(0, len - 1)));
  assert.throws(() => verify(REVEAL, concat([PROOF, new Uint8Array(1)])));
  assert.throws(() => verify(REVEAL, new Uint8Array(0)));
  // The honest proof still verifies: the copies above were changed, not it.
  assert.equal(verify(REVEAL, PROOF), true);
});

test("the proof is bound to the public fields and the chain constants", () => {
  assert.throws(() => verify({ ...REVEAL, fee: word(FEE + 1n) }, PROOF), /proof rejected|malformed proof/);
  assert.throws(() => verify({ ...REVEAL, recipient: fill(20, 0x98) }, PROOF), /proof rejected|malformed proof/);
  const note = NOTE.slice();
  note[NOTE_BYTES - 1] ^= 1;
  assert.throws(() => verify({ ...REVEAL, remainderNote: note }, PROOF), /proof rejected|malformed proof/);
  assert.throws(() => verify(REVEAL, PROOF, { domain: fill(32, 0x12) }), /proof rejected|malformed proof/);
  assert.throws(() => verify(REVEAL, PROOF, { chainId: CHAIN_ID + 1n }), /proof rejected|malformed proof/);
  // An amount above 2^96 - 1 is refused before the proof is looked at, as
  // the native verifier refuses it.
  assert.throws(() => verify({ ...REVEAL, out: word(1n << 96n) }, PROOF), /^Error: amount word above 2\^96 - 1$/);
  assert.throws(() => verify({ ...REVEAL, fee: word(1n << 96n) }, PROOF), /^Error: amount word above 2\^96 - 1$/);
});

test("the prover refuses what the native prover refuses, with its messages", async () => {
  const refused = (overrides) => () => ghost.provePoseidon2Reveal({ ...request(overrides), zk: fill(32, 0x6c) });
  const NOT_IN_TREE = /^Error: the commitment is not under the root$/;
  // Not the leaf at its position under the root.
  assert.throws(refused({ root: fill(32, 0) }), NOT_IN_TREE);
  assert.throws(refused({ opening: { ...COIN, position: 1 } }), NOT_IN_TREE);
  assert.throws(refused({ opening: { ...COIN, amount: COIN.amount + 1n }, remainder: { ...REMAINDER, amount: REMAINDER.amount + 1n } }), NOT_IN_TREE);
  // A remainder with the coin's blinding.
  assert.throws(refused({ remainder: { ...REMAINDER, b: COIN.b } }), /^Error: the remainder reuses the input's blinding$/);
  // Amounts that do not balance.
  assert.throws(refused({ remainder: { ...REMAINDER, amount: REMAINDER.amount + 1n } }), /^Error: v is not out \+ remainder \+ fee$/);
  // An amount word above 2^96 - 1.
  assert.throws(refused({ out: 1n << 96n }), /^Error: amount word above 2\^96 - 1$/);
  assert.throws(refused({ remainder: { ...REMAINDER, amount: 1n << 96n } }), /^Error: amount word above 2\^96 - 1$/);

  // The override switch and its secret.
  const secret = fill(32, 0x0e);
  const rule = {
    policyAddress: fill(20, 0x50),
    policyCodehash: fill(32, 0x51),
    paramsHash: fill(32, 0x52),
    overrideHash: overrideHash(secret),
    actionTag: fill(32, 0x53),
    actionSalt: fill(32, 0x54),
  };
  assert.throws(refused({ spend: { useOverride: 2, rule, overrideSecret: secret } }), /^Error: the override switch is neither 0 nor 1$/);
  assert.throws(refused({ spend: { rule: { ...rule, overrideHash: new Uint8Array(32) }, overrideSecret: secret } }), /^Error: the rule has no override$/);
  assert.throws(refused({ spend: { rule, overrideSecret: fill(32, 0x0f) } }), /^Error: the override secret does not match the rule$/);
  // A plain coin spent through a rule's override, with its right secret,
  // is not the leaf: the leaf's fingerprint holds the empty rule.
  assert.throws(refused({ spend: { rule, overrideSecret: secret } }), NOT_IN_TREE);

  // Through the worker, a refusal is an error reply with the same message.
  await assert.rejects(worker.request("provePoseidon2Reveal", request({ root: fill(32, 0) })), NOT_IN_TREE);
});
