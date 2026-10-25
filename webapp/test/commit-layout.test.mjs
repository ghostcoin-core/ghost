// The commit payload against the node's layouts (ghost-node
// core/ghostpriv/commit.go). The app sends version 2, the only one: version
// 0x0002 (2 bytes), F (32), the coin's salt (16), the note (156), 206 bytes
// (SaltedCommitDataSize).

import assert from "node:assert/strict";
import test from "node:test";

import { concat, fromHex, toHex } from "../src/bytes.mjs";
import { COMMIT_DATA_BYTES as APP_COMMIT_DATA_BYTES, DEFAULT_COMMIT_ENTRY } from "../src/flow.mjs";
import { loadModule } from "./support/env.mjs";
import { SALTED_COMMIT_DATA_BYTES, SALTED_COMMIT_VERSION } from "./support/fake-node.mjs";

const ghost = await loadModule();

// The example words key of spec 01, as its digit view, on chain 7.
const KEY = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
const CHAIN_ID = 7n;
const AMOUNT = 10n ** 18n;
const SEED = fromHex(`0x${"09".repeat(32)}`, 32);

const makeCommit = () => ghost.commit({ chainId: CHAIN_ID, amount: AMOUNT, seed: Uint8Array.from(SEED), key: KEY });

test("the module's commit payload is version 2: version, F, salt and note, 206 bytes", () => {
  const commit = makeCommit();
  assert.equal(ghost.constants().commitPayloadBytes, 206);
  assert.equal(APP_COMMIT_DATA_BYTES, 206, "the size the flow checks before it sends");
  assert.equal(commit.payload.length, 206);
  assert.equal(toHex(commit.payload.slice(0, 2)), "0x0002");
  const fingerprint = commit.payload.slice(2, 34);
  const salt = commit.payload.slice(34, 50);
  const note = commit.payload.slice(50);
  assert.equal(note.length, 156);
  assert.notEqual(toHex(salt), toHex(new Uint8Array(16)), "a salt drawn from the seed");
  // The node computes C from F, the amount and the version 2 tag.
  assert.equal(toHex(ghost.coinCommitment(fingerprint, AMOUNT, 2)), toHex(commit.commitment));
  // The same seed gives the same commit: the salt comes from it alone.
  assert.equal(toHex(makeCommit().payload), toHex(commit.payload));
  // The note carries the same salt: restore finds the coin from it alone.
  const records = concat([commit.commitment, note]);
  const found = ghost.restore({ chainId: CHAIN_ID, key: KEY, records, markers: new Uint8Array(0) });
  assert.equal(found.length, 1);
  assert.equal(toHex(found[0].salt), toHex(salt));
  assert.equal(toHex(found[0].marker), toHex(commit.marker));
});

test("the note opens with the key at its chain only", () => {
  const commit = makeCommit();
  const records = concat([commit.commitment, commit.payload.slice(50)]);
  const found = ghost.restore({ chainId: CHAIN_ID, key: KEY, records, markers: new Uint8Array(0) });
  assert.equal(found.length, 1);
  assert.equal(found[0].number, 0n);
  assert.equal(found[0].amount, AMOUNT);
  assert.equal(found[0].position, 0);
  assert.equal(toHex(found[0].salt), toHex(commit.payload.slice(34, 50)));
  assert.equal(ghost.restore({ chainId: CHAIN_ID + 1n, key: KEY, records, markers: new Uint8Array(0) }).length, 0);
  // Another key does not open it.
  const other = ghost.newKey(crypto.getRandomValues(new Uint8Array(32)));
  assert.equal(ghost.restore({ chainId: CHAIN_ID, key: other, records, markers: new Uint8Array(0) }).length, 0);
});

test("the stand-in reads the same layout", () => {
  assert.equal(SALTED_COMMIT_DATA_BYTES, 206);
  assert.equal(toHex(SALTED_COMMIT_VERSION), "0x0002");
});

test("the default commit entry is the internal network's coin commit entry", () => {
  assert.equal(DEFAULT_COMMIT_ENTRY, "0x67686f7374000000000000000000000000000005");
});
