// The commit payload against the node's layouts (ghost-node
// core/ghostpriv/commit.go). The app sends data format 0x0003, the only one:
// version 0x0003 (2 bytes), F (32), the coin's salt (16), the 380-byte note
// of note version 3 (spec 10, section 3.2), then the key's 16-byte lookup
// tag of number 0 (decision 0004), 446 bytes (SaltedCommitDataSize). The
// 430 bytes without the tag are what the node refuses since the lookup trees.

import assert from "node:assert/strict";
import test from "node:test";

import { readFileSync } from "node:fs";

import { concat, fromHex, toHex } from "../src/bytes.mjs";
import { COMMIT_DATA_BYTES as APP_COMMIT_DATA_BYTES, COMMIT_DATA_VERSION, DEFAULT_COMMIT_ENTRY } from "../src/flow.mjs";
import { LEAF_RECORD_BYTES, NOTE_BYTES } from "../src/wasm.mjs";
import { loadModule } from "./support/env.mjs";
import { SALTED_COMMIT_DATA_BYTES, SALTED_COMMIT_VERSION } from "./support/fake-node.mjs";

const ghost = await loadModule();

// The example words key of spec 01, as its digit view, on chain 7.
const KEY = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
const CHAIN_ID = 7n;
const AMOUNT = 10n ** 18n;
const SEED = fromHex(`0x${"09".repeat(32)}`, 32);

// Decision 0004's lookup tag of number 0 of that key: the first 16 bytes of
// S("ghost/note-lookup/v1", k_note, 0), as its vector block states it.
const DECISION_0004 = readFileSync(new URL("../../docs/decisions/0004-lookup-formats.md", import.meta.url), "utf8");
const TAG_OF_NUMBER_0 = /\[lookup-tag-index-0\][^[]*?\ntag = ([0-9a-f]{32})\n/.exec(DECISION_0004)[1];

const makeCommit = () => ghost.commit({ chainId: CHAIN_ID, amount: AMOUNT, seed: Uint8Array.from(SEED), key: KEY });

test("the module's commit payload is version 3: version, F, salt, a 380-byte note and the lookup tag, 446 bytes", () => {
  const commit = makeCommit();
  assert.equal(ghost.constants().commitPayloadBytes, 446);
  assert.equal(APP_COMMIT_DATA_BYTES, 446, "the size the flow checks before it sends");
  assert.equal(toHex(COMMIT_DATA_VERSION), "0x0003", "the version the flow checks before it sends");
  assert.equal(commit.payload.length, 446);
  assert.equal(toHex(commit.payload.slice(0, 2)), "0x0003");
  const fingerprint = commit.payload.slice(2, 34);
  const salt = commit.payload.slice(34, 50);
  const note = commit.payload.slice(50, 430);
  assert.equal(note.length, 380);
  assert.equal(NOTE_BYTES, 380);
  assert.equal(LEAF_RECORD_BYTES, 32 + 380);
  // After the note, the key's lookup tag of number 0: decision 0004's vector.
  assert.equal(toHex(commit.payload.slice(430)), `0x${TAG_OF_NUMBER_0}`);
  assert.notEqual(toHex(salt), toHex(new Uint8Array(16)), "a salt drawn from the seed");
  // The empty-rule capsule is encrypted with the rest: nothing of the note
  // is left in the clear, its last 224 bytes no more than the rest.
  assert.notEqual(toHex(note.slice(156)), toHex(new Uint8Array(224)));
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
  const records = concat([commit.commitment, commit.payload.slice(50, 430)]);
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

test("a note cut to the 156 bytes of the old layout is not read", () => {
  const commit = makeCommit();
  // A record of the old length is refused whole by the module.
  const short = concat([commit.commitment, commit.payload.slice(50, 50 + 156)]);
  assert.throws(() => ghost.restore({ chainId: CHAIN_ID, key: KEY, records: short, markers: new Uint8Array(0) }));
  // Its first 156 bytes, zero-padded as a reveal's note is, open nothing.
  const padded = concat([commit.commitment, commit.payload.slice(50, 50 + 156), new Uint8Array(224)]);
  assert.equal(ghost.restore({ chainId: CHAIN_ID, key: KEY, records: padded, markers: new Uint8Array(0) }).length, 0);
});

test("the stand-in reads the same layout", () => {
  assert.equal(SALTED_COMMIT_DATA_BYTES, 446);
  assert.equal(toHex(SALTED_COMMIT_VERSION), "0x0003");
});

test("the default commit entry is the internal network's coin commit entry", () => {
  assert.equal(DEFAULT_COMMIT_ENTRY, "0x67686f7374000000000000000000000000000005");
});
