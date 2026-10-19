// The commit payload against spec 07's layout and the shared vector of
// test/vectors/commit-payload.json: version 0x0001 (2 bytes), F (32), the
// note (156), 190 bytes, as the node's ghostpriv.CommitData reads it. The
// vector is the other side's: the real-node test sends the same layout.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { concat, fromHex, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY } from "../src/flow.mjs";
import { loadModule } from "./support/env.mjs";
import { COMMIT_DATA_BYTES, COMMIT_VERSION } from "./support/fake-node.mjs";

const ghost = await loadModule();
const vector = JSON.parse(await readFile(new URL("./vectors/commit-payload.json", import.meta.url), "utf8"));

const vectorCommit = () =>
  ghost.commit({
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
  assert.equal(toHex(ghost.coinCommitment(fromHex(vector.fingerprint, 32), BigInt(vector.amount))), vector.commitment);
});

test("the module's commit payload is the vector's data", () => {
  const commit = vectorCommit();
  assert.equal(ghost.constants().commitPayloadBytes, 190);
  assert.equal(commit.payload.length, 190);
  assert.equal(toHex(commit.commitment), vector.commitment);
  assert.equal(toHex(commit.marker), vector.marker);
  assert.equal(toHex(commit.payload.slice(0, 2)), vector.version);
  assert.equal(toHex(commit.payload.slice(2, 34)), vector.fingerprint);
  assert.equal(toHex(commit.payload.slice(34)), vector.note);
  assert.equal(toHex(commit.payload), vector.data);
});

test("the vector's note opens with the key at the vector's chain only", () => {
  const records = concat([fromHex(vector.commitment, 32), fromHex(vector.note, 156)]);
  const found = ghost.restore({ chainId: BigInt(vector.chainId), key: vector.key, records, markers: new Uint8Array(0) });
  assert.equal(found.length, 1);
  assert.equal(found[0].number, 0n);
  assert.equal(found[0].amount, BigInt(vector.amount));
  assert.equal(found[0].position, 0);
  assert.equal(ghost.restore({ chainId: BigInt(vector.chainId) + 1n, key: vector.key, records, markers: new Uint8Array(0) }).length, 0);
});

test("the stand-in reads the same layout", () => {
  assert.equal(COMMIT_DATA_BYTES, 190);
  assert.equal(toHex(COMMIT_VERSION), vector.version);
});

test("the default commit entry is the internal network's coin commit entry", () => {
  assert.equal(DEFAULT_COMMIT_ENTRY, "0x67686f7374000000000000000000000000000005");
});
