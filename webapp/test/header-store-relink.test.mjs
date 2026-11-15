// The headers the page checked, kept between sessions, continued from
// header-store.test.mjs (split so each file fits a CI job): a saved header
// that does not re-link is discarded, and blocked or missing storage leaves
// the page working.

import assert from "node:assert/strict";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { readHeader } from "../src/header.mjs";
import { HEADER_DATABASE, createHeaderStore } from "../src/header-store.mjs";
import { FAKE_CHAIN_ID } from "./support/fake-node.mjs";
import { PIN, memoryStore, brokenStore, pinnedChain, session } from "./support/header-store-setup.mjs";

test("a saved header that does not re-link is discarded", async () => {
  const chain = await pinnedChain(40);
  const { ghost, node } = chain;
  try {
    const clean = await session(chain, null);
    assert.equal(clean.sent.chainAdd, 40);
    const store = memoryStore();
    await session(chain, store);
    const key = `${FAKE_CHAIN_ID}:${toHex(node.blocks[PIN].hash)}`;
    assert.deepEqual([...store.entries.keys()], [key], "keyed by the chain identifier and the start hash");

    // A record re-hashed so that only the change named is wrong.
    const alter = (height, change) => {
      const record = store.entries.get(key).get(height);
      change(record);
      record.hash = toHex(ghost.keccak256(readHeader(record).rlp));
    };

    // Block 25's parent hash is not block 24's: it does not re-link.
    alter(PIN + 15, (r) => {
      r.parentHash = toHex(new Uint8Array(32).fill(0x42));
    });
    const relinked = await session(chain, store);
    assert.equal(store.calls.clear, 1, "the store entry is discarded");
    assert.equal(relinked.sent.chainAdd, 40, "every header from the pin is checked with its seal");
    assert.ok(relinked.sent.chainAddSaved <= 40);
    assert.deepEqual(relinked.shown, clean.shown, "the same confirmations as a clean session");
    assert.deepEqual(
      store.records().map((r) => r.hash),
      node.blocks.slice(PIN + 1).map((b) => toHex(b.hash)),
      "the entry is written again from the checked headers",
    );

    // Block 30 says it is block 31: not at its height.
    alter(PIN + 20, (r) => {
      r.number = `0x${(PIN + 21).toString(16)}`;
    });
    const renumbered = await session(chain, store);
    assert.equal(store.calls.clear, 2);
    assert.deepEqual(renumbered.sent, { chainAdd: 40, chainAddSaved: 0 }, "refused before any is added");
    assert.deepEqual(renumbered.shown, clean.shown);

    // A gap: a stored list that skips a height.
    store.entries.get(key).delete(PIN + 7);
    const gap = await session(chain, store);
    assert.equal(store.calls.clear, 3);
    assert.deepEqual(gap.sent, { chainAdd: 40, chainAddSaved: 0 });
    assert.deepEqual(gap.shown, clean.shown);

    // Healed: the next session checks no seal again.
    const healed = await session(chain, store);
    assert.deepEqual(healed.sent, { chainAdd: 0, chainAddSaved: 40 });
    assert.deepEqual(healed.shown, clean.shown);
  } finally {
    await node.close();
  }
});

test("blocked browser storage leaves the page working", async () => {
  const chain = await pinnedChain(30);
  try {
    const clean = await session(chain, null);
    assert.equal(clean.sent.chainAdd, 30);
    assert.equal(clean.shown.status, "unclaimed");

    const thrown = await session(chain, brokenStore());
    assert.deepEqual(thrown.sent, { chainAdd: 30, chainAddSaved: 0 });
    assert.deepEqual(thrown.shown, clean.shown);

    // No IndexedDB at all (as in Node), or one that throws or is blocked.
    assert.equal(createHeaderStore(null), null);
    assert.equal(createHeaderStore(), null, "this runtime has no indexedDB");
    const opens = [];
    const refusing = {
      open(name) {
        opens.push(name);
        throw new Error("the storage is refused");
      },
    };
    assert.equal(createHeaderStore(refusing), null);
    const blocked = createHeaderStore({
      open(name) {
        opens.push(name);
        const request = {};
        setTimeout(() => request.onblocked(), 0);
        return request;
      },
    });
    assert.deepEqual(opens, [HEADER_DATABASE, HEADER_DATABASE]);
    await assert.rejects(blocked.load("any"), /blocked/);
    const viaBlocked = await session(chain, blocked);
    assert.deepEqual(viaBlocked.sent, { chainAdd: 30, chainAddSaved: 0 });
    assert.deepEqual(viaBlocked.shown, clean.shown);
    const viaNone = await session(chain, createHeaderStore(null));
    assert.deepEqual(viaNone.shown, clean.shown);
  } finally {
    await chain.node.close();
  }
});
