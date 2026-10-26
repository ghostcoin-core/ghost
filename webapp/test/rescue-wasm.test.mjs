// The module's rescue-key accounts (spec 09, section 5): the account of
// scheme 0x0003 with its 1,344-byte key, its two signing modes (0x0003 with
// ML-DSA-44, 0x0004 with SLH-DSA alone), ghost_account_tx_verify on both, and
// the app's gas allowance for such an account.

import assert from "node:assert/strict";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { ACCOUNT_EXTRA_GAS } from "../src/flow.mjs";
import { loadModule } from "./support/env.mjs";

const ghost = await loadModule();

const WORDS = ghost.walletNew(Uint8Array.from({ length: 32 }, (_, i) => 3 * i + 1));
const CHAIN_ID = 7777001n;
const GENESIS = new Uint8Array(32).fill(0xab);
const TO = Uint8Array.from({ length: 20 }, (_, i) => 0x40 + i);
const RESCUE_PUBLIC_KEY_BYTES = 1344;
// The RLP header of a 1,344-byte string: 0xb9 and the length in 2 bytes.
const KEY_HEADER = [0xb9, 0x05, 0x40];

const fields = (seed) => ({
  words: WORDS,
  index: 2,
  chainId: CHAIN_ID,
  genesis: GENESIS,
  nonce: 7n,
  maxPriorityFeePerGas: 1_000_000_000n,
  maxFeePerGas: 3_000_000_000n,
  gasLimit: 250_000n,
  to: TO,
  value: 123_456_789n,
  data: new Uint8Array(0),
  seed: new Uint8Array(32).fill(seed),
});

function find(haystack, needle, from = 0) {
  outer: for (let i = from; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// The scheme an envelope carries: the 2 bytes before the RLP header of the
// account's public key.
function envelopeScheme(envelope, publicKey) {
  const at = find(envelope, [...KEY_HEADER, ...publicKey]);
  assert.ok(at > 3, "the envelope carries the account's public key");
  assert.equal(envelope[at - 3], 0x82, "the scheme is a 2-byte string");
  return `0x${toHex(envelope.slice(at - 2, at)).slice(2)}`;
}

const verify = (envelope) => ghost.accountTxVerify({ chainId: CHAIN_ID, genesis: GENESIS, envelope });

test("the module derives the rescue-key account with a 1344 byte key and a different address from the plain account", () => {
  const rescue = ghost.walletRescueAccount(WORDS, 2);
  const plain = ghost.walletAccount(WORDS, 2);
  assert.equal(rescue.address.length, 20);
  assert.equal(rescue.publicKey.length, RESCUE_PUBLIC_KEY_BYTES);
  assert.equal(plain.publicKey.length, 1312);
  assert.notEqual(toHex(rescue.address), toHex(plain.address));
  // The same words and index derive the same account again; another index
  // another one.
  const again = ghost.walletRescueAccount(WORDS, 2);
  assert.equal(toHex(again.address), toHex(rescue.address));
  assert.equal(toHex(again.publicKey), toHex(rescue.publicKey));
  const other = ghost.walletRescueAccount(WORDS, 3);
  assert.notEqual(toHex(other.address), toHex(rescue.address));
  assert.notEqual(toHex(other.publicKey.slice(1312)), toHex(rescue.publicKey.slice(1312)));
  // Words that are not a wallet seed are refused.
  assert.throws(() => ghost.walletRescueAccount("not the words of a wallet", 0), /not a valid wallet seed/);
});

test("the module signs scheme 0x0003 and scheme 0x0004 and the verifier returns the same sender", () => {
  const { address, publicKey } = ghost.walletRescueAccount(WORDS, 2);
  const normal = ghost.walletSignRescueKey(fields(1));
  const rescue = ghost.walletSignRescue(fields(2));
  const plain = ghost.walletSign(fields(3));

  assert.equal(envelopeScheme(normal.envelope, publicKey), "0x0003");
  assert.equal(envelopeScheme(rescue.envelope, publicKey), "0x0004");
  // The SLH-DSA signature (7,856 bytes) is longer than ML-DSA-44's (2,420).
  assert.equal(rescue.envelope.length - normal.envelope.length, 7856 - 2420);
  for (const signed of [normal, rescue]) {
    assert.equal(toHex(signed.sender), toHex(address));
    assert.equal(toHex(signed.txHash), toHex(ghost.keccak256(signed.envelope)));
    const verified = verify(signed.envelope);
    assert.equal(toHex(verified.sender), toHex(address));
    assert.equal(toHex(verified.txHash), toHex(signed.txHash));
    assert.equal(toHex(verified.to), toHex(TO));
    assert.equal(verified.value, 123_456_789n);
    assert.equal(verified.nonce, 7n);
    assert.equal(verified.gasLimit, 250_000n);
    assert.equal(verified.data.length, 0);
  }
  // The scheme 0x0001 export is unchanged: the plain account signs.
  assert.equal(toHex(plain.sender), toHex(ghost.walletAccount(WORDS, 2).address));
  assert.equal(toHex(verify(plain.envelope).sender), toHex(plain.sender));
});

test("ghost_account_tx_verify refuses a 0x0004 envelope with a field changed", () => {
  const { publicKey } = ghost.walletRescueAccount(WORDS, 2);
  const signed = ghost.walletSignRescue(fields(4));
  assert.equal(toHex(verify(signed.envelope).sender), toHex(signed.sender));

  const changed = (at, value) => {
    const copy = signed.envelope.slice();
    copy[at] = value ?? copy[at] ^ 1;
    return copy;
  };
  const keyAt = find(signed.envelope, [...KEY_HEADER, ...publicKey]);
  const toAt = find(signed.envelope, TO);
  assert.ok(toAt > 0 && toAt < keyAt);
  const cases = [
    // The destination: a rescue cannot be redirected.
    ["to", changed(toAt + 5)],
    // The scheme: 0x0004 read as 0x0003.
    ["scheme", changed(keyAt - 1, 0x03)],
    // The SLH-DSA half of the key.
    ["public key", changed(keyAt + KEY_HEADER.length + RESCUE_PUBLIC_KEY_BYTES - 1)],
    // The signature's last byte.
    ["signature", changed(signed.envelope.length - 1)],
  ];
  for (const [what, envelope] of cases) assert.throws(() => verify(envelope), Error, what);
  // Signed for another genesis, it is refused too.
  assert.throws(() => ghost.accountTxVerify({ chainId: CHAIN_ID, genesis: new Uint8Array(32), envelope: signed.envelope }));
});

test("the account transaction extra gas covers a rescue-key account", () => {
  // 16 gas for each of the 2 + 1,344 + 2,420 bytes of scheme, public key and
  // ML-DSA-44 signature, and 3,000 for the check (spec 09, section 8.1).
  assert.ok(ACCOUNT_EXTRA_GAS >= 16n * 3_766n + 3_000n);
  assert.equal(ACCOUNT_EXTRA_GAS, 63_256n);
  // Measured from a real scheme 0x0003 envelope: its key and signature
  // lengths, which with the 2 scheme bytes are what the node charges for.
  const { publicKey } = ghost.walletRescueAccount(WORDS, 0);
  const signed = ghost.walletSignRescueKey({ ...fields(5), index: 0 });
  const keyAt = find(signed.envelope, [...KEY_HEADER, ...publicKey]);
  const signatureBytes = signed.envelope.length - (keyAt + KEY_HEADER.length + publicKey.length) - 3;
  assert.equal(signatureBytes, 2420);
  assert.ok(ACCOUNT_EXTRA_GAS >= 16n * BigInt(2 + publicKey.length + signatureBytes) + 3_000n);
});
