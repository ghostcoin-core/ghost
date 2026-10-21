// The commit payload against the node's layouts (ghost-node
// core/ghostpriv/commit.go) and the shared vector of
// test/vectors/commit-payload.json. The app sends version 2: version 0x0002
// (2 bytes), F (32), the coin's salt (16), the note (156), 206 bytes
// (SaltedCommitDataSize). The node still takes version 1: version 0x0001, F
// and the note, 190 bytes (CommitDataSize), the layout of the vector, whose
// coin is the version 1 coin of spec 01, vector coin-commit; the module still
// makes it when asked, for the tests that need a coin made before the salt.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { concat, fromHex, toHex } from "../src/bytes.mjs";
import { COMMIT_DATA_BYTES as APP_COMMIT_DATA_BYTES, DEFAULT_COMMIT_ENTRY } from "../src/flow.mjs";
import { loadModule } from "./support/env.mjs";
import {
  COMMIT_DATA_BYTES,
  COMMIT_VERSION,
  SALTED_COMMIT_DATA_BYTES,
  SALTED_COMMIT_VERSION,
} from "./support/fake-node.mjs";

const ghost = await loadModule();
const vector = JSON.parse(await readFile(new URL("./vectors/commit-payload.json", import.meta.url), "utf8"));

const vectorCommit = (version) =>
  ghost.commit({
    version,
    chainId: BigInt(vector.chainId),
    amount: BigInt(vector.amount),
    seed: fromHex(vector.seed, 32),
    key: vector.key,
  });

test("the vector's data is version, F and note, 190 bytes", () => {
  const data = fromHex(vector.data);
  assert.equal(data.length, 190);
  assert.equal(vector.version, "0x0001");
  assert.equal(toHex(data), toHex(concat([fromHex(vector.version, 2), fromHex(vector.fingerprint, 32), fromHex(vector.note, 156)])));
  // F gives the commitment of spec 01, vector coin-commit, as the node computes it.
  assert.equal(toHex(ghost.coinCommitment(fromHex(vector.fingerprint, 32), BigInt(vector.amount), 1)), vector.commitment);
});

test("the module's version 1 commit payload is the vector's data", () => {
  const commit = vectorCommit(1);
  assert.equal(ghost.constants().commitV1PayloadBytes, 190);
  assert.equal(commit.payload.length, 190);
  assert.equal(toHex(commit.commitment), vector.commitment);
  assert.equal(toHex(commit.marker), vector.marker);
  assert.equal(toHex(commit.payload.slice(0, 2)), vector.version);
  assert.equal(toHex(commit.payload.slice(2, 34)), vector.fingerprint);
  assert.equal(toHex(commit.payload.slice(34)), vector.note);
  assert.equal(toHex(commit.payload), vector.data);
});

test("the module's commit payload is version 2: version, F, salt and note, 206 bytes", () => {
  const commit = vectorCommit(undefined);
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
  assert.equal(toHex(ghost.coinCommitment(fingerprint, BigInt(vector.amount), 2)), toHex(commit.commitment));
  // Under a salt, the same key, number and amount give another leaf, F and
  // marker than version 1's.
  assert.notEqual(toHex(commit.commitment), vector.commitment);
  assert.notEqual(toHex(fingerprint), vector.fingerprint);
  assert.notEqual(toHex(commit.marker), vector.marker);
  // The note carries the same salt: restore finds the coin from it alone.
  const records = concat([commit.commitment, note]);
  const found = ghost.restore({ chainId: BigInt(vector.chainId), key: vector.key, records, markers: new Uint8Array(0) });
  assert.equal(found.length, 1);
  assert.equal(toHex(found[0].salt), toHex(salt));
  assert.equal(toHex(found[0].marker), toHex(commit.marker));
});

test("the vector's note opens with the key at the vector's chain only", () => {
  const records = concat([fromHex(vector.commitment, 32), fromHex(vector.note, 156)]);
  const found = ghost.restore({ chainId: BigInt(vector.chainId), key: vector.key, records, markers: new Uint8Array(0) });
  assert.equal(found.length, 1);
  assert.equal(found[0].number, 0n);
  assert.equal(found[0].amount, BigInt(vector.amount));
  assert.equal(found[0].position, 0);
  assert.equal(found[0].salt, null);
  assert.equal(ghost.restore({ chainId: BigInt(vector.chainId) + 1n, key: vector.key, records, markers: new Uint8Array(0) }).length, 0);
});

test("the stand-in reads the same layouts", () => {
  assert.equal(SALTED_COMMIT_DATA_BYTES, 206);
  assert.equal(toHex(SALTED_COMMIT_VERSION), "0x0002");
  assert.equal(COMMIT_DATA_BYTES, 190);
  assert.equal(toHex(COMMIT_VERSION), vector.version);
});

test("the default commit entry is the internal network's coin commit entry", () => {
  assert.equal(DEFAULT_COMMIT_ENTRY, "0x67686f7374000000000000000000000000000005");
});
