// The WebAssembly module against the golden vectors of spec 01 and spec 05,
// and its refusals.

import assert from "node:assert/strict";
import test from "node:test";

import { fromHex, toHex } from "../src/bytes.mjs";
import { loadModule } from "./support/env.mjs";

const ghost = await loadModule();

// Spec 01, vector coin-commit.
const VECTOR_KEY = "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417";
const LEAF_A = "562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458";
const LEAF_B = "93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15";

test("tree roots match spec 05, section 11", () => {
  assert.equal(toHex(ghost.treeRoots(new Uint8Array(0)).root), "0x8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8");
  const two = fromHex(LEAF_A + LEAF_B);
  const { root, pageRoots } = ghost.treeRoots(two);
  assert.equal(toHex(root), "0x142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5");
  assert.deepEqual(pageRoots.map(toHex), ["0x06d032e35a1f30a5773c38d9631f5e4ec069786f4d22131ef0bbba75acf2b717"]);
  const prefixes = ghost.prefixRoots(two, 0, 2).map(toHex);
  assert.equal(prefixes[0], "0x8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8");
  assert.equal(prefixes[2], toHex(root));
  assert.equal(prefixes[1], toHex(ghost.treeRoots(fromHex(LEAF_A)).root));
});

test("the tree check accepts matching data and refuses a changed leaf or root", () => {
  const two = fromHex(LEAF_A + LEAF_B);
  const { root, pageRoots } = ghost.treeRoots(two);
  ghost.treeCheck({ pageRoots: pageRoots[0], leaves: two, root });
  const changed = Uint8Array.from(two);
  changed[40] ^= 1;
  assert.throws(() => ghost.treeCheck({ pageRoots: pageRoots[0], leaves: changed, root }), /page 0 does not match/);
  const otherRoot = Uint8Array.from(root);
  otherRoot[0] ^= 1;
  assert.throws(() => ghost.treeCheck({ pageRoots: pageRoots[0], leaves: two, root: otherRoot }), /header's coin root/);
  assert.throws(() => ghost.treeCheck({ pageRoots: new Uint8Array(0), leaves: two, root }), /do not fill/);
});

test("the commit matches spec 01, vector coin-commit", () => {
  const commit = ghost.commit({ chainId: 7n, amount: 10n ** 18n, seed: new Uint8Array(32).fill(9), key: VECTOR_KEY });
  assert.equal(toHex(commit.commitment), `0x${LEAF_A}`);
  assert.equal(toHex(commit.marker), "0x671b869daf27c895e24a009e3d471e893e8e6ffe62f0309b4e5402c94c47ec85");
  assert.equal(commit.payload.length, ghost.constants().commitPayloadBytes);
  assert.equal(commit.payload[0], 0x01);
  assert.equal(toHex(commit.payload.slice(1, 33)), "0xb44338ab6f6dcb3d63772c457737afd38a841207725e1440d235c4f6be0c4d8b");
  assert.equal(toHex(ghost.coinCommitment(commit.payload.slice(1, 33), 10n ** 18n)), `0x${LEAF_A}`);
});

test("restore finds the committed coin from its note and passes over others", () => {
  const chainId = 7n;
  const commit = ghost.commit({ chainId, amount: 10n ** 18n, seed: crypto.getRandomValues(new Uint8Array(32)), key: VECTOR_KEY });
  const stranger = new Uint8Array(188).fill(3);
  const records = new Uint8Array([...stranger, ...commit.commitment, ...commit.payload.slice(33)]);
  let found = ghost.restore({ chainId, key: VECTOR_KEY, records, markers: new Uint8Array(0) });
  assert.equal(found.length, 1);
  assert.equal(found[0].position, 1);
  assert.equal(found[0].amount, 10n ** 18n);
  assert.equal(found[0].spent, false);
  found = ghost.restore({ chainId, key: VECTOR_KEY, records, markers: commit.marker });
  assert.equal(found[0].spent, true);
  // Another chain's note does not open.
  assert.equal(ghost.restore({ chainId: 8n, key: VECTOR_KEY, records, markers: new Uint8Array(0) }).length, 0);
});

test("keys: new keys are standard, typed keys are checked, errors hold no digit", () => {
  const key = ghost.newKey(crypto.getRandomValues(new Uint8Array(32)));
  assert.match(key, /^\d{4}( \d{4}){11}$/);
  assert.equal(ghost.checkKey(key), 12);
  assert.equal(ghost.checkKey(VECTOR_KEY.replaceAll(" ", "-")), 12);
  const bad = VECTOR_KEY.slice(0, -1) + "8";
  assert.throws(() => ghost.checkKey(bad), (err) => /group 12/.test(err.message) && !/\d{4}/.test(err.message));
  assert.throws(() => ghost.checkKey("1234"), /48 or 96 digits/);
  assert.notEqual(ghost.newKey(crypto.getRandomValues(new Uint8Array(32))), key);
});

test("the epoch rule refuses the leaf's own root and a shallow candidate", () => {
  const a = new Uint8Array(32).fill(1);
  const b = new Uint8Array(32).fill(2);
  assert.equal(ghost.chooseTreeState({ tip: 44, leafHeight: 4, leafRoot: a, height: 32, root: b }), true);
  assert.equal(ghost.chooseTreeState({ tip: 44, leafHeight: 4, leafRoot: a, height: 32, root: a }), false);
  assert.equal(ghost.chooseTreeState({ tip: 43, leafHeight: 4, leafRoot: a, height: 32, root: b }), false);
  assert.equal(ghost.chooseTreeState({ tip: 44, leafHeight: 32, leafRoot: a, height: 32, root: b }), false);
});

test("a malformed envelope is refused before any proof work", () => {
  const { envelopeBytes } = ghost.constants();
  assert.equal(envelopeBytes, 1 + 190 + 1_310_720 + 156);
  const domain = new Uint8Array(32);
  assert.throws(() => ghost.decodeEnvelope({ chainId: 7n, domain, envelope: new Uint8Array(100) }), /expected size/);
  const envelope = new Uint8Array(envelopeBytes);
  envelope[0] = 0x50;
  envelope[2] = 0x02;
  assert.throws(() => ghost.decodeEnvelope({ chainId: 7n, domain, envelope }), /version/);
  envelope[2] = 0x01;
  assert.throws(() => ghost.decodeEnvelope({ chainId: 7n, domain, envelope }), /chain/);
});
