// The headers the page checked, kept between sessions (flow.mjs, loadSaved
// and saveAdopted; header.mjs, createHeaderStore). Each session is a new
// createFlow and a new worker on the same stand-in (support/fake-node.mjs)
// and, unless it says otherwise, the same store; the prover is wrapped to
// count the headers sent to chainAdd, each one RandomX seal checked, and to
// chainAddSaved, which checks everything again but the seal.
//
// The chain is pinned at block 10 (the pin mechanism of header.mjs on a fake
// network; the launch network's pin is a host step). A first session checks
// every seal above the pin; a second checks none below the saved tip, only
// those above it. A saved header that does not re-link by parent hash, or
// is not at its height, makes the page drop the saved entry and check every
// header from the pin again, with the same result as a clean session.
// Storage that throws or is missing leaves the page working as with none.

import assert from "node:assert/strict";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { HEADER_FIELDS } from "../src/header.mjs";
import { TEST_WALLET_ADDRESS } from "./support/env.mjs";
import { PIN, memoryStore, pinnedChain, session } from "./support/header-store-setup.mjs";

test("a second session checks no seal below the saved tip", async () => {
  // 600 blocks above the pin. The first session's cost on a long chain is
  // one RandomX seal per header above the saved tip: all 600 here; on the
  // launch chain, every header from the pin to the tip once, and then only
  // the new ones. The year-one header size stays the modelled figure of
  // docs/scale/phone-results.md, not measured here.
  const chain = await pinnedChain(600);
  try {
    const store = memoryStore();
    const first = await session(chain, store);
    assert.deepEqual(first.sent, { chainAdd: 600, chainAddSaved: 0 }, "the first session checks every seal above the pin");
    assert.equal(first.shown.status, "unclaimed");
    assert.equal(first.shown.tip, PIN + 600);
    assert.equal(store.records().length, 600, "every header above the pin is saved");

    const second = await session(chain, store);
    assert.deepEqual(second.sent, { chainAdd: 0, chainAddSaved: 600 }, "no seal below the saved tip");
    assert.deepEqual(second.shown, first.shown, "the same coin, tip and confirmations");
    assert.equal(store.calls.clear, 0);

    chain.node.mineTo(PIN + 605);
    const third = await session(chain, store);
    assert.deepEqual(third.sent, { chainAdd: 5, chainAddSaved: 600 }, "only the 5 new headers are sealed-checked");
    assert.equal(third.shown.tip, PIN + 605);
    assert.deepEqual(third.shown.current, first.shown.current);
    assert.equal(store.records().length, 605, "the new headers are saved too");
  } finally {
    await chain.node.close();
  }
});

test("the saved records hold public header fields only", async () => {
  const chain = await pinnedChain(12);
  const { node, key } = chain;
  try {
    const store = memoryStore();
    await session(chain, store);
    const records = store.records();
    assert.equal(records.length, 12);
    const fields = [...HEADER_FIELDS.map(([name]) => name), "hash"].sort();
    for (const [i, record] of records.entries()) {
      const block = node.blocks[PIN + 1 + i];
      assert.deepEqual(Object.keys(record).sort(), fields, "the header JSON fields and the hash, nothing else");
      for (const value of Object.values(record)) assert.equal(typeof value, "string");
      assert.deepEqual(record, { ...block.json, hash: toHex(block.hash) }, "as the endpoint's JSON gave them");
    }
    // Neither the key nor the wallet's address, which the session had.
    const text = JSON.stringify([...store.entries]).toLowerCase();
    assert.ok(!text.includes(TEST_WALLET_ADDRESS.slice(2).toLowerCase()), "no address of the wallet");
    assert.ok(!text.includes(key.toLowerCase()), "no key");
  } finally {
    await node.close();
  }
});
