// Shared set-up of the saved-header tests (header-store.test.mjs and
// header-store-relink.test.mjs): stores, a counting prover, a pinned chain
// and one session of the page. Importing this file runs nothing.

import assert from "node:assert/strict";

import { DEFAULT_COMMIT_ENTRY, createFlow } from "../../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet } from "./env.mjs";
import { startFakeNode } from "./fake-node.mjs";

export const PIN = 10;

export function answersFor(key, positions) {
  const groups = key.split(" ");
  return positions.map((p) => groups[p - 1]);
}

// A store in memory with the IndexedDB store's behaviour: records by entry
// and block number, loaded in number order, a save dropping those above its
// last record. Copies go in and out, as structured cloning does.
export function memoryStore() {
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
export const brokenStore = () => {
  const fail = async () => {
    throw new Error("the storage is refused");
  };
  return { load: fail, save: fail, clear: fail };
};

// A worker whose header requests are counted.
export function countingProver() {
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
export async function pinnedChain(blocks) {
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
export async function session({ node, networks, key }, store) {
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
