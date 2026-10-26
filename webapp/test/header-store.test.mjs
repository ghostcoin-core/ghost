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
import { DEFAULT_COMMIT_ENTRY, createFlow } from "../src/flow.mjs";
import { HEADER_FIELDS, readHeader } from "../src/header.mjs";
import { HEADER_DATABASE, createHeaderStore } from "../src/header-store.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { FAKE_CHAIN_ID, startFakeNode } from "./support/fake-node.mjs";

const PIN = 10;

function answersFor(key, positions) {
  const groups = key.split(" ");
  return positions.map((p) => groups[p - 1]);
}

// A store in memory with the IndexedDB store's behaviour: records by entry
// and block number, loaded in number order, a save dropping those above its
// last record. Copies go in and out, as structured cloning does.
function memoryStore() {
  const entries = new Map();
  const calls = { load: 0, save: 0, clear: 0 };
  const numberOf = (record) => Number(BigInt(record.number));
  return {
    entries,
    calls,
    // The records of the only entry, in number order.
    records() {
      assert.equal(entries.size, 1, "one entry: this chain and start");
      const [held] = entries.values();
      return [...held.keys()].sort((a, b) => a - b).map((n) => held.get(n));
    },
    async load(key) {
      calls.load += 1;
      const held = entries.get(key);
      if (!held) return [];
      return [...held.keys()].sort((a, b) => a - b).map((n) => structuredClone(held.get(n)));
    },
    async save(key, records) {
      calls.save += 1;
      const held = entries.get(key) ?? new Map();
      for (const record of records) held.set(numberOf(record), structuredClone(record));
      const top = numberOf(records.at(-1));
      for (const n of held.keys()) if (n > top) held.delete(n);
      entries.set(key, held);
    },
    async clear(key) {
      calls.clear += 1;
      entries.delete(key);
    },
  };
}

// A store whose every call throws, as browser storage that is refused.
const brokenStore = () => {
  const fail = async () => {
    throw new Error("the storage is refused");
  };
  return { load: fail, save: fail, clear: fail };
};

// A worker whose header requests are counted.
function countingProver() {
  const inner = nodeProver();
  const sent = { chainAdd: 0, chainAddSaved: 0 };
  const prover = {
    request(op, args, onProgress) {
      if (Object.hasOwn(sent, op)) sent[op] += args.headers.length;
      return inner.request(op, args, onProgress);
    },
    fail: (message) => inner.fail(message),
    terminate: () => inner.terminate(),
  };
  return { prover, sent };
}

// A stand-in pinned at PIN, a coin vanished at the block after it from a
// session with no store, then `blocks` blocks above the pin in all.
async function pinnedChain(blocks) {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  node.mineTo(PIN);
  const networks = node.networks({ pinAt: PIN });
  const { prover } = countingProver();
  const flow = createFlow({ prover, endpoint: node.url, networks, pollMs: 5, maxPolls: 20, sleep: async () => node.mine() });
  let key;
  try {
    await openTestWallet(flow, node);
    key = await flow.vanishStart("1");
    const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
    assert.equal(sent.ok, true);
  } finally {
    prover.terminate();
  }
  node.mineTo(PIN + blocks);
  return { ghost, node, networks, key };
}

// One page session: a new flow and worker on `store`, the key opened. What
// the page shows of it, and how many headers went to each check.
async function session({ node, networks, key }, store) {
  const { prover, sent } = countingProver();
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks,
    headerStore: store,
    pollMs: 5,
    maxPolls: 20,
    sleep: async () => node.mine(),
  });
  try {
    const s = await flow.summonOpen(key);
    const shown = {
      status: s.status,
      tip: s.tip,
      coins: s.coins,
      current: s.current,
      cover: s.cover,
      wait: s.wait,
      chainRefused: flow.state.chainRefused,
    };
    return { shown, sent: { ...sent } };
  } finally {
    prover.terminate();
  }
}

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
