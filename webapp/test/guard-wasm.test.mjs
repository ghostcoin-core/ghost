// Ghost Guard in the module (lib.rs, mod guard; spec 10, sections 3.1, 12
// and 13): the Guard commit, restore of a Guard coin, the warnings, the
// refusals of the client library, the words-only spend (the key's words and
// the chain data only), a cancel refused without the stop root, the stop
// card's cancel and the restore of the coin it re-commits, the normal spend
// with the override, the transfer and the release.
//
// The Guard address and code hash are test values: the real ones are not
// final. The coin tree is built here from the module's own commits and
// spends, as the node would append them.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, equalBytes, fromWord, word } from "../src/bytes.mjs";
import { NOTE_BYTES } from "../src/wasm.mjs";
import { loadModule } from "./support/env.mjs";

const ghost = await loadModule();

const CHAIN_ID = 7777001n;
const DOMAIN = new Uint8Array(32).fill(0x11);
const POLICY = { address: new Uint8Array(20).fill(0x47), codehash: new Uint8Array(32).fill(0x5a) };
const STOP_ROOT = new Uint8Array(32).fill(0xa5);
const OTHER_STOP_ROOT = new Uint8Array(32).fill(0xb5);
const ROOM = { filledLeaves: 100n, leavesPerBlock: 64n };
const COMMITTED = 1_000_000_000_000n;
const FEE = 21_000n;
const PAID = 100_000_000n;
const BASE_FEE = 3n;
const G_ACTION = 15_905_968n;
const ACTION_COST = G_ACTION * BASE_FEE;
const RECIPIENT = new Uint8Array(20).fill(0x99);
const CANCEL_SELECTOR = Uint8Array.of(0xca, 0x11, 0xce, 0x1d);
const RELEASE_SELECTOR = Uint8Array.of(0x7e, 0x1e, 0xa5, 0xe0);
const SLOT_HEIGHT = 5_000n;
const SLOT_TIME = 1_700_000_000n;
const HOLD_BLOCKS = 8_640n;
const HOLD_SECONDS = 259_200n;

const seed = (byte) => new Uint8Array(32).fill(byte);
const WALLET = ghost.walletNew(Uint8Array.from({ length: 32 }, (_, i) => 5 * i + 3));
const OTHER_WALLET = ghost.walletNew(Uint8Array.from({ length: 32 }, (_, i) => 7 * i + 1));
const OWNER = ghost.newKey(seed(0x31));
const RESCUE = ghost.newKey(seed(0x32));
const STRANGER = ghost.newKey(seed(0x33));

// The coin tree as the node holds it: leaves with their notes, the salt
// beside each (null for a reveal's remainder), the spent markers.
const tree = { records: [], salts: [], markers: [] };
const records = () => concat(tree.records);
const push = (commitment, note, salt) => {
  assert.equal(commitment.length, 32);
  assert.equal(note.length, NOTE_BYTES);
  tree.records.push(concat([commitment, note]));
  tree.salts.push(salt);
  return tree.records.length - 1;
};
// A commit's leaf: `C` and the payload's note, its salt beside it.
const pushCommit = ({ commitment, payload }) => push(commitment, payload.slice(50), payload.slice(34, 50));
const restore = (key) => ghost.guardRestore({ chainId: CHAIN_ID, policy: POLICY, key, records: records(), salts: tree.salts, markers: concat(tree.markers) });

const commitOf = (overrides = {}) =>
  ghost.guardCommit({
    chainId: CHAIN_ID,
    policy: POLICY,
    walletWords: WALLET,
    guardIndex: 0,
    stopRoot: STOP_ROOT,
    amount: COMMITTED,
    room: ROOM,
    seed: seed(0x41),
    key: OWNER,
    ...overrides,
  });

// A plain coin of another key first, so the Guard coin is not alone.
pushCommit(ghost.commit({ chainId: CHAIN_ID, amount: 5_000n, seed: seed(0x21), key: STRANGER }));
const COMMIT = commitOf();
const COMMIT_POSITION = pushCommit(COMMIT);

test("a Guard commit carries its rule in the fingerprint and its capsule in the note, and restore finds a Guard coin", () => {
  // The 430-byte payload of format 0x0003: F, the salt, the 380-byte note.
  assert.equal(COMMIT.payload.length, 430);
  assert.deepEqual([...COMMIT.payload.slice(0, 2)], [0x00, 0x03]);
  const fingerprint = COMMIT.payload.slice(2, 34);
  assert.ok(equalBytes(ghost.coinCommitment(fingerprint, COMMITTED, 2), COMMIT.commitment), "C is the node's");
  assert.ok(!COMMIT.rule.every((b) => b === 0), "the rule is not the empty rule");

  const [found] = restore(OWNER);
  assert.equal(restore(OWNER).length, 1);
  assert.equal(found.rule, "guard");
  assert.equal(found.number, 0n);
  assert.equal(found.amount, COMMITTED);
  assert.equal(found.position, COMMIT_POSITION);
  assert.equal(found.spent, false);
  assert.ok(equalBytes(found.commitment, COMMIT.commitment));
  assert.ok(equalBytes(found.marker, COMMIT.marker));
  assert.ok(equalBytes(found.ruleBytes, COMMIT.rule));
  assert.ok(equalBytes(found.salt, COMMIT.payload.slice(34, 50)));
  assert.equal(found.handedOverAsWords, true, "a coin with a rule carries the hand-over warning");
  for (const field of ["overrideHash", "actionTag", "actionSalt"]) assert.ok(!found.guard[field].every((b) => b === 0), field);

  // The plain coin of another key is found by its own key with no rule and
  // no warning, and is not the owner's.
  const [plain] = restore(STRANGER);
  assert.equal(plain.rule, "empty");
  assert.equal(plain.guard, null);
  assert.equal(plain.handedOverAsWords, false);
  // Under another policy the same coin is not a Guard coin.
  const other = ghost.guardRestore({
    chainId: CHAIN_ID,
    policy: { ...POLICY, codehash: new Uint8Array(32).fill(0x5b) },
    key: OWNER,
    records: records(),
    salts: tree.salts,
    markers: new Uint8Array(0),
  });
  assert.equal(other[0].rule, "other");
  assert.equal(other[0].handedOverAsWords, true);
});

test("the guard secret comes from the wallet seed and the stop root from the stop card, never from the Phantom Key", () => {
  const [found] = restore(OWNER);
  const guardOf = (overrides) => {
    const made = commitOf(overrides);
    const key = overrides.key ?? OWNER;
    const coin = ghost
      .guardRestore({
        chainId: CHAIN_ID,
        policy: POLICY,
        key,
        records: concat([made.commitment, made.payload.slice(50)]),
        salts: [made.payload.slice(34, 50)],
        markers: new Uint8Array(0),
      })
      .at(0);
    assert.equal(coin.rule, "guard");
    return coin.guard;
  };
  // Another Phantom Key, the same wallet seed: the same override hash.
  const otherKey = guardOf({ key: RESCUE, seed: seed(0x42) });
  assert.ok(equalBytes(otherKey.overrideHash, found.guard.overrideHash));
  // The words as bytes, as the wallet passes them: the same secret.
  const asBytes = guardOf({ walletWords: new TextEncoder().encode(WALLET), seed: seed(0x43) });
  assert.ok(equalBytes(asBytes.overrideHash, found.guard.overrideHash));
  // Another wallet seed or index: another override hash.
  assert.ok(!equalBytes(guardOf({ walletWords: OTHER_WALLET, seed: seed(0x44) }).overrideHash, found.guard.overrideHash));
  assert.ok(!equalBytes(guardOf({ guardIndex: 1, seed: seed(0x45) }).overrideHash, found.guard.overrideHash));
  // Every new coin draws a fresh action salt, so its action tag is new too.
  const again = guardOf({ seed: seed(0x46) });
  assert.ok(!equalBytes(again.actionSalt, found.guard.actionSalt));
  assert.ok(!equalBytes(again.actionTag, found.guard.actionTag));
});

test("the module refuses a Guard commit as the client library does", () => {
  const refusals = [
    [{ stopRoot: null }, /a Guard commit needs the stop root from the stop card/],
    [{ stopRoot: new Uint8Array(32) }, /the random source gave only zero bytes/],
    [{ room: { filledLeaves: 2n ** 32n - 64n * 8_640n, leavesPerBlock: 64n } }, /within the hold period of full/],
    [{ room: { filledLeaves: 0n, leavesPerBlock: 0n } }, /room cannot be checked/],
    [{ policy: { address: Uint8Array.from({ length: 20 }, (_, i) => (i === 19 ? 5 : 0)), codehash: POLICY.codehash } }, /reserved/],
    [{ policy: { address: POLICY.address, codehash: new Uint8Array(32) } }, /code hash is zero/],
    [{ amount: 0n }, /at least 1 wei/],
    [{ walletWords: "not the words of a wallet" }, /not a valid wallet seed/],
    [{ key: "not a key" }, /not a valid Phantom Key/],
  ];
  for (const [overrides, said] of refusals) assert.throws(() => commitOf(overrides), said, said.source);
});

test("guardCheck gives the two warnings: words alone stay under the giver's stop key, and a slot not above the action cost", () => {
  const above = ghost.guardCheck({ policy: POLICY, amount: ACTION_COST + 1n, baseFee: BASE_FEE, room: ROOM });
  assert.equal(above.actionCost, ACTION_COST);
  assert.deepEqual(above.warnings, { handedOverAsWords: true, slotNotAboveActionCost: false, actionCostUnknown: false });
  for (const amount of [ACTION_COST, 1n]) {
    const small = ghost.guardCheck({ policy: POLICY, amount, baseFee: BASE_FEE });
    assert.deepEqual(small.warnings, { handedOverAsWords: true, slotNotAboveActionCost: true, actionCostUnknown: false });
  }
  const unknown = ghost.guardCheck({ policy: POLICY, amount: COMMITTED, baseFee: 0n });
  assert.equal(unknown.actionCost, 0n);
  assert.deepEqual(unknown.warnings, { handedOverAsWords: true, slotNotAboveActionCost: false, actionCostUnknown: true });
  assert.throws(() => ghost.guardCheck({ policy: POLICY, amount: 0n, baseFee: BASE_FEE }), /at least 1 wei/);
  assert.throws(
    () => ghost.guardCheck({ policy: POLICY, amount: 1n, baseFee: 1n, room: { filledLeaves: 2n ** 32n - 1n, leavesPerBlock: 1n } }),
    /within the hold period of full/,
  );
});

// The fifteen words of slot(marker) for the slot a policy reveal opened,
// read from its envelope (spec 10, sections 5.1 and 7.2).
function slotWords(envelope, { height = SLOT_HEIGHT, timestamp = SLOT_TIME } = {}) {
  const p = envelope.subarray(1);
  const words = Array.from({ length: 15 }, () => new Uint8Array(32));
  words[0].set(p.subarray(170, 190), 12);
  words[1][31] = 1;
  words[2].set(p.subarray(106, 138));
  words[3].set(p.subarray(106, 138));
  words[9] = word(height);
  words[10] = word(timestamp);
  words[11].set(p.subarray(222, 254));
  words[12].set(p.subarray(254, 286));
  words[13].set(p.subarray(286, 318));
  words[14].set(p.subarray(318, 350));
  return words;
}

const zk = (byte) => new Uint8Array(32).fill(byte);
let wordsOnly = null;

test("the words-only spend takes the key's words and the chain alone and sweeps the coin into Guard's slot", () => {
  const [coin] = restore(OWNER);
  wordsOnly = ghost.guardWordsOnlySpend({
    chainId: CHAIN_ID,
    domain: DOMAIN,
    policy: POLICY,
    key: OWNER,
    records: records(),
    salts: tree.salts,
    position: coin.position,
    fee: FEE,
    recipient: RECIPIENT,
    seed: seed(0x51),
    zk: zk(0x52),
  });
  const { envelope } = wordsOnly;
  assert.equal(envelope.length, 1_311_451);
  assert.equal(envelope[0], 0x53);
  const p = envelope.subarray(1);
  assert.deepEqual([...p.subarray(0, 2)], [0x00, 0x01]);
  assert.equal(new DataView(p.buffer, p.byteOffset + 2, 8).getBigUint64(0), CHAIN_ID);
  assert.ok(equalBytes(p.subarray(10, 42), coin.marker), "it spends the Guard coin");
  assert.ok(equalBytes(wordsOnly.marker, coin.marker));
  assert.equal(fromWord(p.subarray(106, 138)), COMMITTED - FEE, "a full sweep less the fee");
  assert.equal(wordsOnly.slotAmount, COMMITTED - FEE);
  assert.equal(fromWord(p.subarray(138, 170)), FEE);
  assert.ok(equalBytes(p.subarray(170, 190), POLICY.address));
  assert.ok(equalBytes(p.subarray(190, 222), POLICY.codehash));
  assert.ok(equalBytes(p.subarray(254, 286), coin.guard.actionTag));
  assert.ok(equalBytes(p.subarray(286, 318), coin.guard.actionSalt));
  assert.ok(equalBytes(p.subarray(318, 350), concat([new Uint8Array(12), RECIPIENT])), "instr names the recipient");
  assert.equal(wordsOnly.remainder.number, 1n);
  assert.equal(wordsOnly.remainder.amount, 0n);
  assert.ok(equalBytes(ghost.keccak256(envelope), wordsOnly.txHash));

  // The key's words are needed: another key's words find no coin there.
  assert.throws(
    () => ghost.guardWordsOnlySpend({ chainId: CHAIN_ID, domain: DOMAIN, policy: POLICY, key: RESCUE, records: records(), salts: tree.salts, position: coin.position, fee: FEE, recipient: RECIPIENT, seed: seed(1), zk: zk(1) }),
    /not a coin of this key/,
  );
  // The plain coin is no Guard coin.
  assert.throws(
    () => ghost.guardWordsOnlySpend({ chainId: CHAIN_ID, domain: DOMAIN, policy: POLICY, key: STRANGER, records: records(), salts: tree.salts, position: 0, fee: FEE, recipient: RECIPIENT, seed: seed(1), zk: zk(1) }),
    /not a Guard coin of this policy/,
  );
});

const cancelOf = (overrides = {}) =>
  ghost.guardCancel({
    chainId: CHAIN_ID,
    domain: DOMAIN,
    policy: POLICY,
    marker: wordsOnly.marker,
    slot: slotWords(wordsOnly.envelope),
    stopRoot: STOP_ROOT,
    walletWords: WALLET,
    guardIndex: 0,
    newKey: RESCUE,
    debit: 2n * ACTION_COST,
    expiry: SLOT_HEIGHT + 100n,
    baseFee: BASE_FEE,
    headHeight: SLOT_HEIGHT + 10n,
    selector: CANCEL_SELECTOR,
    seed: seed(0x61),
    zk: zk(0x62),
    ...overrides,
  });

test("a words-only spend cannot be cancelled without the stop root, and the release waits for the hold", () => {
  assert.ok(wordsOnly, "the words-only spend ran");
  // The words alone: no stop root at all, or another card's.
  assert.throws(() => cancelOf({ stopRoot: null }), /a cancel needs the stop root from the stop card: the words alone cannot cancel/);
  assert.throws(() => cancelOf({ stopRoot: OTHER_STOP_ROOT }), /the stop root does not open this slot/);
  // The client library's other refusals.
  assert.throws(() => cancelOf({ debit: ACTION_COST - 1n }), /the debit is below the action cost/);
  assert.throws(() => cancelOf({ debit: COMMITTED }), /not larger than the debit/);
  assert.throws(() => cancelOf({ baseFee: 0n }), /the action cost is unknown/);
  assert.throws(() => cancelOf({ expiry: SLOT_HEIGHT + 10n }), /expiry is before the next block/);
  assert.throws(() => cancelOf({ policy: { ...POLICY, address: new Uint8Array(20).fill(0x48) } }), /not a Guard slot/);

  const release = (headHeight, headTimestamp) =>
    ghost.guardRelease({ policy: POLICY, marker: wordsOnly.marker, slot: slotWords(wordsOnly.envelope), headHeight, headTimestamp, selector: RELEASE_SELECTOR });
  assert.throws(() => release(SLOT_HEIGHT + HOLD_BLOCKS - 1n, SLOT_TIME + HOLD_SECONDS), /the hold is not over/);
  assert.throws(() => release(SLOT_HEIGHT + HOLD_BLOCKS, SLOT_TIME + HOLD_SECONDS - 1n), /the hold is not over/);
  const call = release(SLOT_HEIGHT + HOLD_BLOCKS, SLOT_TIME + HOLD_SECONDS);
  assert.ok(equalBytes(call.to, POLICY.address));
  assert.ok(equalBytes(call.data, concat([RELEASE_SELECTOR, wordsOnly.marker])));
});

test("the stop card's cancel re-commits the slot to a new key, and restore from the new key's words lists that Guard coin", () => {
  // The owner's words-only spend lands: its marker is spent, its zero-value
  // remainder appended with its note.
  tree.markers.push(wordsOnly.marker);
  push(wordsOnly.remainder.commitment, wordsOnly.envelope.subarray(wordsOnly.envelope.length - NOTE_BYTES), null);
  const spent = restore(OWNER);
  assert.equal(spent.find((c) => c.number === 0n).spent, true);

  const cancel = cancelOf();
  const settled = COMMITTED - FEE - 2n * ACTION_COST;
  assert.equal(cancel.newCoin.amount, settled);
  assert.equal(cancel.calldata.length, 432);
  assert.ok(equalBytes(cancel.calldata.subarray(0, 4), CANCEL_SELECTOR));
  assert.equal(cancel.envelope.length, 1 + 949_372);
  assert.equal(cancel.envelope[0], 0x54);

  // Guard's re-commit as the escrow native does it, from the calldata alone.
  const fingerprint = cancel.calldata.slice(4, 36);
  const salt = cancel.calldata.slice(36, 52);
  const note = cancel.calldata.slice(52);
  const leaf = ghost.coinCommitment(fingerprint, settled, 2);
  assert.ok(equalBytes(leaf, cancel.newCoin.commitment));
  const position = push(leaf, note, salt);

  // Restore from the new key's words lists the cancelled slot's new coin, a
  // Guard coin of the stop card's root under a fresh action salt.
  const found = restore(RESCUE);
  assert.equal(found.length, 1);
  const [coin] = found;
  assert.equal(coin.rule, "guard");
  assert.equal(coin.position, position);
  assert.equal(coin.amount, settled);
  assert.equal(coin.number, 0n);
  assert.equal(coin.spent, false);
  assert.ok(equalBytes(coin.ruleBytes, cancel.newCoin.rule));
  assert.ok(!equalBytes(coin.guard.actionSalt, slotWords(wordsOnly.envelope)[13]), "a fresh action salt");
  const [first] = restore(OWNER).filter((c) => c.number === 0n);
  assert.ok(equalBytes(coin.guard.overrideHash, first.guard.overrideHash), "the same wallet seed's guard secret");
});

test("the normal spend needs the guard secret, keeps the remainder under the chosen rule, and verifies", () => {
  const [coin] = restore(RESCUE);
  const spend = (overrides = {}) =>
    ghost.guardSpend({
      chainId: CHAIN_ID,
      domain: DOMAIN,
      policy: POLICY,
      walletWords: WALLET,
      guardIndex: 0,
      key: RESCUE,
      records: records(),
      salts: tree.salts,
      position: coin.position,
      recipient: RECIPIENT,
      out: PAID,
      fee: FEE,
      remainder: null,
      seed: seed(0x71),
      zk: zk(0x72),
      ...overrides,
    });
  // The words alone, or another wallet's seed, cannot make an ordinary spend.
  assert.throws(() => spend({ walletWords: OTHER_WALLET }), /the guard secret does not open this coin's override/);
  assert.throws(() => spend({ guardIndex: 1 }), /the guard secret does not open this coin's override/);
  assert.throws(() => spend({ remainder: { stopRoot: null, room: ROOM } }), /a Guard remainder needs the stop root/);
  assert.throws(() => spend({ out: coin.amount }), /refused/);
  assert.throws(
    () =>
      ghost.guardTransfer({
        chainId: CHAIN_ID,
        domain: DOMAIN,
        policy: POLICY,
        walletWords: WALLET,
        key: RESCUE,
        newKey: RESCUE,
        records: records(),
        salts: tree.salts,
        position: coin.position,
        recipient: RECIPIENT,
        out: PAID,
        fee: FEE,
        receiver: null,
        seed: seed(1),
        zk: zk(1),
      }),
    /a transfer must go to a new key/,
  );

  const built = spend({ remainder: { stopRoot: STOP_ROOT, room: ROOM } });
  const { envelope } = built;
  assert.equal(envelope.length, 1_311_291);
  assert.equal(envelope[0], 0x50);
  assert.deepEqual([...envelope.subarray(1, 3)], [0x00, 0x02]);
  assert.ok(equalBytes(built.marker, coin.marker));
  assert.ok(equalBytes(ghost.keccak256(envelope), built.txHash));
  assert.equal(built.remainder.number, 1n);
  assert.equal(built.remainder.amount, coin.amount - PAID - FEE);

  // Included: the remainder, a Guard coin under a rotated rule, is restored.
  tree.markers.push(built.marker);
  push(built.remainder.commitment, envelope.subarray(envelope.length - NOTE_BYTES), null);
  const after = restore(RESCUE);
  const remainder = after.find((c) => c.number === 1n);
  assert.equal(remainder.rule, "guard");
  assert.equal(remainder.spent, false);
  assert.ok(equalBytes(remainder.ruleBytes, built.remainder.rule));
  assert.ok(!equalBytes(remainder.ruleBytes, coin.ruleBytes), "the rule rotated");
  assert.equal(after.find((c) => c.number === 0n).spent, true);
});

test("a transfer hands the coin to the receiver's own Guard rule, and refuses a rule that reuses the coin's action salt", () => {
  const coin = restore(RESCUE).find((c) => c.number === 1n && !c.spent);
  // The receiver's own rule, as its capsule hands it over: a Guard coin of
  // another wallet seed and another stop card.
  const receiverKey = ghost.newKey(seed(0x34));
  const theirs = commitOf({ walletWords: OTHER_WALLET, stopRoot: OTHER_STOP_ROOT, key: receiverKey, seed: seed(0x81) });
  const [their] = ghost.guardRestore({
    chainId: CHAIN_ID,
    policy: POLICY,
    key: receiverKey,
    records: concat([theirs.commitment, theirs.payload.slice(50)]),
    salts: [theirs.payload.slice(34, 50)],
    markers: new Uint8Array(0),
  });
  const holder = ghost.newKey(seed(0x35));
  const transfer = (receiver, newKey = holder) =>
    ghost.guardTransfer({
      chainId: CHAIN_ID,
      domain: DOMAIN,
      policy: POLICY,
      walletWords: WALLET,
      key: RESCUE,
      newKey,
      records: records(),
      salts: tree.salts,
      position: coin.position,
      recipient: RECIPIENT,
      out: PAID,
      fee: FEE,
      receiver,
      seed: seed(0x82),
      zk: zk(0x83),
    });
  // The coin's own rule again: a new Guard coin may not reuse its salt.
  assert.throws(() => transfer({ ...coin.guard, room: ROOM }), /a new Guard coin would reuse an action salt/);

  const built = transfer({ ...their.guard, room: ROOM });
  assert.equal(built.envelope.length, 1_311_291);
  assert.equal(built.remainder.number, 0n, "number 0 of the new key");
  assert.equal(built.remainder.amount, coin.amount - PAID - FEE);
  tree.markers.push(built.marker);
  push(built.remainder.commitment, built.envelope.subarray(built.envelope.length - NOTE_BYTES), null);

  // The new key's words find it under the receiver's rule, not the giver's.
  const found = restore(holder);
  assert.equal(found.length, 1);
  const [received] = found;
  assert.equal(received.rule, "guard");
  assert.equal(received.amount, coin.amount - PAID - FEE);
  assert.ok(equalBytes(received.guard.overrideHash, their.guard.overrideHash));
  assert.ok(equalBytes(received.guard.actionTag, their.guard.actionTag));
  assert.ok(!equalBytes(received.guard.overrideHash, coin.guard.overrideHash));
  assert.equal(restore(RESCUE).every((c) => c.spent), true, "the giver's words hold nothing unspent");
});
