// The node writes both reveal versions under the one topic
// K("ghost/reveal-receipt/v1") and tells them apart by data length
// (ghost-node core/ghostpriv/reveal.go, revealLogSize and revealLogSizeV1):
// 472 bytes with the 380-byte note of a version 2 reveal, 248 bytes with the
// 156-byte note of a version 1 reveal. The app's reader (coinRecord) reads
// them the same way, and refuses any other length.

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { concat, fromHex, toHex, word } from "../src/bytes.mjs";
import { coinRecord, keccak256 } from "../src/flow.mjs";

const webappDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const tagTopic = (tag) => toHex(keccak256(concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)])));
// The topics the app hashes: a commit log's and the one reveal topic.
const topics = {
  commit: tagTopic("ghost/commit-receipt/v1"),
  reveal: tagTopic("ghost/reveal-receipt/v1"),
};

const marker = new Uint8Array(32).fill(0x09);
// Tree index 2, position 7, the remainder's leaf.
const head = concat([Uint8Array.of(0, 0, 0, 2), Uint8Array.of(0, 0, 0, 7), new Uint8Array(32).fill(0x08)]);
const recipient = new Uint8Array(20).fill(0x05);
const tail = concat([recipient, word(3n)]);
// A synthetic 380-byte note, none of its last 224 bytes zero.
const note = Uint8Array.from({ length: 380 }, (_, i) => ((i * 7 + 1) & 0xff) | 1);
const shortNote = note.slice(0, 156);
const v2Data = concat([head, note, tail]);
const v1Data = concat([head, shortNote, tail]);
const revealLog = (data, first = topics.reveal) => ({ succeeded: true, topics: [fromHex(first, 32), marker], data });

test("a 472-byte log under the reveal topic reads as version 2, its 380-byte note whole", () => {
  assert.equal(v2Data.length, 472);
  const record = coinRecord(revealLog(v2Data), topics);
  assert.equal(record.note.length, 380);
  assert.equal(toHex(record.note), toHex(note), "the note as the tree stores it, not padded or cut");
  assert.equal(record.treeIndex, 2);
  assert.equal(record.position, 7);
  assert.equal(toHex(record.leaf), toHex(new Uint8Array(32).fill(0x08)));
  assert.equal(toHex(record.marker), toHex(marker));
  assert.equal(record.salt, null);
  assert.equal(record.v, null);
});

test("a 248-byte log under the reveal topic still reads as version 1, its note zero-padded", () => {
  assert.equal(v1Data.length, 248);
  const record = coinRecord(revealLog(v1Data), topics);
  assert.equal(record.note.length, 380);
  assert.equal(toHex(record.note), toHex(concat([shortNote, new Uint8Array(224)])));
  assert.equal(record.position, 7);
  assert.equal(toHex(record.marker), toHex(marker));
  assert.equal(record.salt, null);
});

test("a reveal log of any other length, or off its topics, is refused", () => {
  const lengths = [0, 40, 247, 249, 264, 380, 468, 471, 473, 488];
  for (const length of lengths) {
    const data = concat([v2Data, new Uint8Array(Math.max(0, length - v2Data.length))]).subarray(0, length);
    assert.equal(data.length, length);
    assert.throws(() => coinRecord(revealLog(data), topics), /reveal log's data is not its length/, `${length} bytes`);
  }
  // Two topics exactly: the marker is the second.
  const noMarker = { succeeded: true, topics: [fromHex(topics.reveal, 32)], data: v2Data };
  assert.throws(() => coinRecord(noMarker, topics), /exactly two topics/);
  const third = { succeeded: true, topics: [fromHex(topics.reveal, 32), marker, marker], data: v2Data };
  assert.throws(() => coinRecord(third, topics), /exactly two topics/);
  // Any other first topic is no coin tree log, a later reveal tag's among them.
  for (const first of [tagTopic("ghost/reveal-receipt/v3"), tagTopic("ghost/policy-reveal-receipt/v1")]) {
    assert.throws(() => coinRecord(revealLog(v2Data, first), topics), /neither a commit nor a reveal/);
  }
  // A failed receipt with a reveal log.
  assert.throws(() => coinRecord({ ...revealLog(v2Data), succeeded: false }, topics), /failed receipt/);
});

test("the app names one reveal receipt topic, the node's", () => {
  const sources = readdirSync(resolve(webappDir, "src"))
    .filter((name) => name.endsWith(".mjs"))
    .map((name) => readFileSync(resolve(webappDir, "src", name), "utf8"));
  const tags = new Set(sources.flatMap((text) => [...text.matchAll(/"ghost\/reveal-receipt\/v(\d+)"/g)].map((m) => m[1])));
  assert.deepEqual([...tags], ["1"]);
});
