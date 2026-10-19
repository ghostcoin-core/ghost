// The node stand-in refuses the commits the real node refuses: not to the
// commit entry address, data not exactly 190 bytes, a version other than
// 0x0001, in the node's words (`commit data is not 190 bytes of version 1`).
// It accepts the 190-byte payload of spec 07, and a refusal adds no leaf.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { concat, fromHex, toHex, toQuantity } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY } from "../src/flow.mjs";
import { loadModule } from "./support/env.mjs";
import { COMMIT_DATA_ERROR, startFakeNode } from "./support/fake-node.mjs";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const GHOST = 10n ** 18n;
const vector = JSON.parse(await readFile(new URL("./vectors/commit-payload.json", import.meta.url), "utf8"));
const fingerprint = fromHex(vector.fingerprint, 32);
const note = fromHex(vector.note, 156);

async function withNode(check) {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  try {
    await check(node, node.wallet(ACCOUNT));
  } finally {
    await node.close();
  }
}

const send = (wallet, { to = DEFAULT_COMMIT_ENTRY, value = toQuantity(GHOST), data }) =>
  wallet.request({ method: "eth_sendTransaction", params: [{ from: ACCOUNT, to, value, data }] });

const dataError = (err) => err.message === COMMIT_DATA_ERROR;

test("the stand-in refuses the old 189-byte commit of version 0x01", () =>
  withNode(async (node, wallet) => {
    const old = concat([Uint8Array.of(0x01), fingerprint, note]);
    assert.equal(old.length, 189);
    await assert.rejects(send(wallet, { data: toHex(old) }), dataError);
    assert.equal(node.leaves.length, 0);
    assert.equal(node.commits.length, 0);
  }));

test("the stand-in refuses a wrong version and a wrong length", () =>
  withNode(async (node, wallet) => {
    for (const version of [[0x00, 0x02], [0x01, 0x00], [0x00, 0x00], [0x01, 0x01]]) {
      await assert.rejects(send(wallet, { data: toHex(concat([Uint8Array.from(version), fingerprint, note])) }), dataError);
    }
    const right = fromHex(vector.data, 190);
    await assert.rejects(send(wallet, { data: toHex(concat([right, Uint8Array.of(0)])) }), dataError);
    await assert.rejects(send(wallet, { data: toHex(right.slice(0, 189)) }), dataError);
    await assert.rejects(send(wallet, { data: "0x" }), dataError);
    await assert.rejects(send(wallet, { data: null }), dataError);
    await assert.rejects(send(wallet, { data: `${vector.data}0` }), dataError, "not whole bytes of hex");
    assert.equal(node.leaves.length, 0);
    assert.equal(node.commits.length, 0);
  }));

test("the stand-in refuses a commit not to the commit entry address", () =>
  withNode(async (node, wallet) => {
    for (const to of ["0x0000000000000000000000000000000000000000", "0x67686f7374000000000000000000000000000007", null]) {
      await assert.rejects(send(wallet, { to, data: vector.data }), /not the commit entry address/);
    }
    assert.equal(node.leaves.length, 0);
  }));

test("the stand-in refuses an amount it cannot take", () =>
  withNode(async (node, wallet) => {
    for (const value of ["0x0", toQuantity(1n << 96n), "not a number"]) {
      await assert.rejects(send(wallet, { value, data: vector.data }), /commit amount out of range/);
    }
    assert.equal(node.leaves.length, 0);
  }));

test("the stand-in accepts the 190-byte commit of version 0x0001", () =>
  withNode(async (node, wallet) => {
    const hash = await send(wallet, { data: vector.data });
    assert.match(hash, /^0x[0-9a-f]{64}$/);
    assert.equal(node.commits.length, 1);
    assert.equal(node.leaves.length, 1);
    // The leaf is C = K(tag, COIN, F, v) of spec 01, vector coin-commit, and
    // the note is the payload's last 156 bytes.
    assert.equal(toHex(node.leaves[0].commitment), vector.commitment);
    assert.equal(toHex(node.leaves[0].note), vector.note);
  }));
