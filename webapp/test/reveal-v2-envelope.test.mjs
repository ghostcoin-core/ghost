// The ordinary reveal at version 2 (spec 10, section 4): the wallet's reveal
// is type 0x50, version 0x0002, an envelope of exactly 1,311,291 bytes that
// ends with a 380-byte remainder note (note version 3, the empty rule's
// capsule), proved as statement S1 version 2 and checked by its verifier
// (the module's ghost_decode_envelope runs verify_coin_reveal_v2). No
// version 1 envelope, 1,311,067 bytes with a 156-byte note, is built or
// taken. Vanish, a partial Summon and a Claim run headless against the node
// stand-in with the real prover in a worker, and the envelopes they send
// are read back from the stand-in's request log.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, fromHex, toHex, word } from "../src/bytes.mjs";
import { FEE_WINDOW, G_PRIV, feeForPrice, windowPrice } from "../src/chain.mjs";
import { DEFAULT_COMMIT_ENTRY, coinRecord, createFlow, keccak256 } from "../src/flow.mjs";
import * as wasmConstants from "../src/wasm.mjs";
import { buildModuleIfMissing, loadModule, nodeProver, openTestWallet, wasmPath } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

buildModuleIfMissing(wasmPath);
const ghost = await loadModule();

const GHOST = 10n ** 18n;
const RECIPIENT = "0x2222222222222222222222222222222222222222";
// Spec 10, section 4.1: the version 2 envelope, and the version 1 one it
// replaces.
const V2_ENVELOPE_BYTES = 1 + 2 + 8 + 32 + 32 + 32 + 20 + 32 + 32 + 1_310_720 + 380;
const V1_ENVELOPE_BYTES = 1 + 2 + 8 + 32 + 32 + 32 + 20 + 32 + 32 + 1_310_720 + 156;
// Where the remainder note starts in the envelope.
const NOTE_AT = V2_ENVELOPE_BYTES - 380;
// Spec 10, section 10.3, [window-genesis-ordinary]: g_priv and the fee at a
// base fee of 1 gwei.
const SPEC_G_PRIV = 21_371_656n;
const SPEC_FEE = 26_448_599_764_588_822n;
// The policy guardRestore names rules against: any test value will do, as
// no coin here has a rule.
const POLICY = { address: new Uint8Array(20).fill(0x47), codehash: new Uint8Array(32).fill(0x5a) };

const tagTopic = (tag) => toHex(keccak256(concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)])));

function answersFor(key, positions) {
  const words = key.split(" ");
  return positions.map((p) => words[p - 1]);
}

// The leaves of the stand-in's tree as the module's restore reads them.
function treeOf(node) {
  return {
    records: concat(node.leaves.flatMap((leaf) => [leaf.commitment, leaf.note])),
    salts: node.leaves.map((leaf) => leaf.salt ?? null),
    markers: concat(node.spent.map((s) => s.marker)),
  };
}

// Every reveal envelope the app sent the stand-in, in order (a resend of the
// same envelope counted once).
function sentEnvelopes(node) {
  const seen = new Set();
  const out = [];
  for (const r of node.requests) {
    if (r.method !== "eth_sendRawTransaction") continue;
    const hex = String(r.params[0]).toLowerCase();
    if (fromHex(hex)[0] !== 0x50 || seen.has(hex)) continue;
    seen.add(hex);
    out.push(fromHex(hex));
  }
  return out;
}

// The checks every envelope of the wallet passes: its type, version and
// length, the version 2 verifier through the module's decoding, the
// 380-byte note at its end, and the refusal of any change to it.
function checkEnvelope(node, envelope) {
  assert.equal(envelope.length, V2_ENVELOPE_BYTES, "the version 2 length of spec 10, section 4.1");
  assert.equal(envelope.length, 1_311_291);
  assert.notEqual(envelope.length, V1_ENVELOPE_BYTES, "not the version 1 length");
  assert.equal(envelope[0], 0x50, "type 0x50");
  assert.deepEqual([...envelope.subarray(1, 3)], [0x00, 0x02], "version 0x0002");
  const where = { chainId: node.chainId, domain: node.blocks[0].hash };
  const decoded = ghost.decodeEnvelope({ ...where, envelope });
  assert.equal(toHex(decoded.txHash), toHex(keccak256(envelope)));
  // The remainder note is the envelope's last 380 bytes, whole.
  assert.equal(decoded.note.length, 380);
  assert.equal(toHex(decoded.note), toHex(envelope.subarray(NOTE_AT)));
  // A note version 3 with its capsule encrypted, not a 156-byte note
  // zero-padded: its last 224 bytes are not all zero.
  assert.ok(decoded.note.subarray(156).some((b) => b !== 0), "the note's capsule part is not zero padding");
  // The proof binds every byte of the note, the capsule's part included.
  for (const at of [0, 155, 156, 300, 379]) {
    const changed = envelope.slice();
    changed[NOTE_AT + at] ^= 1;
    assert.throws(() => ghost.decodeEnvelope({ ...where, envelope: changed }), /the proof does not verify/, `note byte ${at}`);
  }
  // The same envelope as version 1 is refused, and so is the version 1
  // length (its note cut to 156 bytes).
  const asVersion1 = envelope.slice();
  asVersion1[2] = 0x01;
  assert.throws(() => ghost.decodeEnvelope({ ...where, envelope: asVersion1 }), /unknown transaction version/);
  const short = concat([asVersion1.subarray(0, NOTE_AT), asVersion1.subarray(NOTE_AT, NOTE_AT + 156)]);
  assert.equal(short.length, V1_ENVELOPE_BYTES);
  assert.throws(() => ghost.decodeEnvelope({ ...where, envelope: short }), /expected size/);
  return decoded;
}

test("the module's envelope is the version 2 one: 0x50, 0x0002, 1,311,291 bytes; version 1 is refused", () => {
  const { envelopeBytes, commitPayloadBytes } = ghost.constants();
  assert.equal(envelopeBytes, V2_ENVELOPE_BYTES);
  assert.equal(commitPayloadBytes, 430);
  // The page's own copies of the constants agree with the module.
  assert.equal(wasmConstants.REVEAL_ENVELOPE_BYTES, envelopeBytes);
  assert.equal(wasmConstants.REVEAL_TYPE, 0x50);
  assert.deepEqual([...wasmConstants.REVEAL_VERSION], [0x00, 0x02]);
  assert.equal(wasmConstants.NOTE_BYTES, 380);

  const domain = new Uint8Array(32).fill(3);
  const decode = (envelope) => ghost.decodeEnvelope({ chainId: 7n, domain, envelope });
  const envelope = (length, version) => {
    const bytes = new Uint8Array(length);
    bytes[0] = 0x50;
    bytes.set(version, 1);
    bytes.set([0, 0, 0, 0, 0, 0, 0, 7], 3);
    return bytes;
  };
  // A version 1 envelope, of either length, is not taken.
  assert.throws(() => decode(envelope(V1_ENVELOPE_BYTES, [0x00, 0x01])), /expected size/);
  assert.throws(() => decode(envelope(V2_ENVELOPE_BYTES, [0x00, 0x01])), /unknown transaction version/);
  assert.throws(() => decode(envelope(V2_ENVELOPE_BYTES, [0x00, 0x03])), /unknown transaction version/);
  // A version 2 envelope of another length or type is not taken either.
  assert.throws(() => decode(envelope(V2_ENVELOPE_BYTES - 1, [0x00, 0x02])), /expected size/);
  assert.throws(() => decode(envelope(V2_ENVELOPE_BYTES + 1, [0x00, 0x02])), /expected size/);
  const policyType = envelope(V2_ENVELOPE_BYTES, [0x00, 0x02]);
  policyType[0] = 0x53;
  assert.throws(() => decode(policyType), /expected size/);
  // One of the right shape is decoded, then its proof checked: an empty
  // proof field does not verify, and another chain is refused first.
  assert.throws(() => decode(envelope(V2_ENVELOPE_BYTES, [0x00, 0x02])), /the proof does not verify/);
  const other = envelope(V2_ENVELOPE_BYTES, [0x00, 0x02]);
  other[10] = 8;
  assert.throws(() => decode(other), /wrong chain identifier/);
});

test("the version 2 fee: g_priv of spec 10, section 10.3", () => {
  assert.equal(G_PRIV, SPEC_G_PRIV);
  assert.equal(G_PRIV, 16n * 1_311_291n + 21_000n + 370_000n);
  const genesis = feeForPrice(windowPrice(1_000_000_000n));
  assert.equal(genesis.basePart, 24_044_181_604_171_656n);
  assert.equal(genesis.tip, 2_404_418_160_417_166n);
  assert.equal(genesis.fee, SPEC_FEE);
  assert.equal(FEE_WINDOW, 4);
});

test("a version 2 reveal log carries the whole 380-byte note under the one reveal topic", () => {
  const topics = {
    commit: tagTopic("ghost/commit-receipt/v1"),
    reveal: tagTopic("ghost/reveal-receipt/v1"),
  };
  const marker = new Uint8Array(32).fill(9);
  const note = Uint8Array.from({ length: 380 }, (_, i) => (i * 7 + 1) & 0xff);
  const head = concat([new Uint8Array(4), Uint8Array.of(0, 0, 0, 4), new Uint8Array(32).fill(8)]);
  const tail = concat([new Uint8Array(20).fill(5), word(1n)]);
  const log = (first, data) => ({ succeeded: true, topics: [fromHex(first, 32), marker], data });
  const data = concat([head, note, tail]);
  assert.equal(data.length, 472);
  const record = coinRecord(log(topics.reveal, data), topics);
  assert.equal(toHex(record.note), toHex(note), "the note as the tree stores it, not padded");
  assert.equal(toHex(record.marker), toHex(marker));
  assert.equal(record.position, 4);
  assert.equal(record.salt, null);
  assert.equal(record.v, null);
  // The version 1 log, under the same topic, still reads as it did, its note
  // zero-padded.
  const old = concat([head, note.subarray(0, 156), tail]);
  const v1 = coinRecord(log(topics.reveal, old), topics);
  assert.equal(toHex(v1.note), toHex(concat([note.subarray(0, 156), new Uint8Array(224)])));
  // Any other length is refused.
  for (const bad of [data.subarray(1), concat([data, Uint8Array.of(0)]), old.subarray(1), concat([old, Uint8Array.of(0)])]) {
    assert.throws(() => coinRecord(log(topics.reveal, bad), topics), /reveal log's data is not its length/);
  }
});

test("Vanish, a partial Summon and a Claim send version 2 reveals with 380-byte notes that restore", async () => {
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks: node.networks(),
    pollMs: 5,
    // While the app waits, the chain grows by a block.
    sleep: async () => node.mine(),
  });
  try {
    node.foreignCommits(2);
    await openTestWallet(flow, node);

    // --- Vanish ---
    const key = await flow.vanishStart("1");
    const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
    assert.equal(sent.ok, true);
    assert.equal(flow.state.vanish.stage, "done");
    node.foreignCommits(1);
    node.mineTo(44);

    // --- Summon: a partial reveal ---
    let s = await flow.summonOpen(key);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.amount, GHOST);
    assert.equal(s.fee, SPEC_FEE, "the version 2 fee at a base fee of 1 gwei");
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.ok(reveal.block > 44);
    assert.equal(node.reveals.length, 1);
    assert.equal(node.reveals[0].fee, SPEC_FEE);
    assert.equal(node.reveals[0].out, GHOST / 4n);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
    const left = GHOST - GHOST / 4n - SPEC_FEE;
    s = flow.state.summon;
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.amount, left);
    assert.equal(s.current.number, 1n);

    const [partial] = sentEnvelopes(node);
    const decoded = checkEnvelope(node, partial);
    assert.equal(toHex(decoded.marker), toHex(node.reveals[0].marker));
    assert.equal(decoded.out, GHOST / 4n);
    assert.equal(decoded.fee, SPEC_FEE);
    assert.equal(toHex(decoded.recipient), RECIPIENT);

    // The remainder sits in the tree with that 380-byte note as it is, and
    // the key restores it from the note alone: number 1, no salt beside the
    // leaf, the empty rule (its capsule is the empty one, or restore would
    // discard the note).
    const at = node.leaves.findIndex((leaf) => toHex(leaf.commitment) === toHex(decoded.remainder));
    assert.ok(at >= 0, "the remainder is a leaf");
    assert.equal(toHex(node.leaves[at].note), toHex(decoded.note));
    assert.equal(node.leaves[at].salt, null);
    const tree = treeOf(node);
    const found = ghost.restore({ chainId: node.chainId, key, ...tree });
    const remainder = found.find((coin) => coin.position === at);
    assert.ok(remainder, "the key restores its remainder");
    assert.equal(remainder.number, 1n);
    assert.equal(remainder.amount, left);
    assert.equal(remainder.spent, false);
    assert.equal(toHex(remainder.commitment), toHex(decoded.remainder));
    assert.ok(remainder.salt instanceof Uint8Array && remainder.salt.length === 16, "the salt is read from the note");
    const named = ghost.guardRestore({ chainId: node.chainId, policy: POLICY, key, ...tree });
    const named1 = named.find((coin) => coin.position === at);
    assert.equal(named1.rule, "empty");
    assert.equal(toHex(named1.ruleBytes), toHex(new Uint8Array(32)));
    // The spent coin is the vanished one, marked by the reveal's marker.
    const spent = found.find((coin) => toHex(coin.marker) === toHex(decoded.marker));
    assert.ok(spent && spent.spent && spent.number === 0n);

    // The block's receipt carries the version 2 reveal log with the whole
    // note under the node's one reveal topic, as the app read it to find the
    // spent marker.
    const block = node.blocks[node.reveals[0].block];
    const answer = await fetch(node.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBlockReceipts", params: [toHex(block.hash)] }),
    }).then((r) => r.json());
    const logs = answer.result.flatMap((receipt) => receipt.logs);
    const revealLogs = logs.filter((l) => l.topics[0] === tagTopic("ghost/reveal-receipt/v1"));
    assert.equal(revealLogs.length, 1);
    assert.equal(revealLogs[0].topics[1], toHex(decoded.marker));
    const logData = fromHex(revealLogs[0].data);
    assert.equal(logData.length, 472, "the version 2 length, not a version 1 log's 248");
    assert.equal(toHex(logData.subarray(40, 420)), toHex(decoded.note));

    node.foreignCommits(1);
    node.mineTo(76);

    // --- Claim ---
    const newKey = await flow.claimStart();
    const claimed = await flow.claimCheck(answersFor(newKey, flow.claimSaved()));
    assert.equal(claimed.ok, true);
    assert.equal(claimed.amount, left - SPEC_FEE);
    assert.equal(node.reveals.length, 2);
    assert.equal(node.reveals[1].out, 0n);
    assert.equal(flow.state.summon.status, "claimed");

    const envelopes = sentEnvelopes(node);
    assert.equal(envelopes.length, 2);
    const claim = checkEnvelope(node, envelopes[1]);
    assert.equal(claim.out, 0n);
    assert.equal(claim.fee, SPEC_FEE);

    // The claim's remainder is number 0 of the new key, restored from its
    // 380-byte note under the new key only.
    const after = treeOf(node);
    const position = node.leaves.findIndex((leaf) => toHex(leaf.commitment) === toHex(claim.remainder));
    assert.equal(toHex(node.leaves[position].note), toHex(claim.note));
    const moved = ghost.restore({ chainId: node.chainId, key: newKey, ...after });
    assert.equal(moved.length, 1);
    assert.equal(moved[0].position, position);
    assert.equal(moved[0].number, 0n);
    assert.equal(moved[0].amount, left - SPEC_FEE);
    assert.equal(moved[0].spent, false);
    assert.equal(ghost.guardRestore({ chainId: node.chainId, policy: POLICY, key: newKey, ...after })[0].rule, "empty");
    const old = ghost.restore({ chainId: node.chainId, key, ...after });
    assert.ok(old.every((coin) => coin.spent), "the old key's coins are all spent");
    assert.ok(!old.some((coin) => coin.position === position), "the claim's note does not open under the old key");

    // Opened afresh, the old key shows claimed and the new key holds it.
    s = await flow.summonOpen(key);
    assert.equal(s.status, "claimed");
    s = await flow.summonOpen(newKey);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.amount, left - SPEC_FEE);
    assert.equal(s.current.number, 0n);
    flow.summonClose();
  } finally {
    prover.terminate();
    await node.close();
  }
});
