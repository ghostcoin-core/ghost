// The per-coin salt: the commit the app sends is version 2, 206 bytes, a
// fresh salt in the clear beside F; the node keeps it with the leaf and
// serves it as `salt`; the app reads it with the leaf and hands it to
// restore, which finds each coin with its salt (none for version 1) and
// refuses a coin whose salt beside the leaf is not the one in its note.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, toHex } from "../src/bytes.mjs";
import { COMMIT_DATA_BYTES, DEFAULT_COMMIT_ENTRY, createFlow, fetchTree } from "../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { COMMIT_DATA_ERROR, startFakeNode } from "./support/fake-node.mjs";

const ghost = await loadModule();
const GHOST = 10n ** 18n;
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
// A fixed words key (client/tests/word_key.rs), an example only.
const KEY =
  "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth various";

test("the commit is 206 bytes of version 2", async () => {
  // The module: version 0x0002, F, the salt, the note.
  const a = ghost.commit({ chainId: 7n, amount: GHOST, seed: random(32), key: KEY });
  const b = ghost.commit({ chainId: 7n, amount: GHOST, seed: random(32), key: KEY });
  assert.equal(COMMIT_DATA_BYTES, 206);
  for (const commit of [a, b]) {
    assert.equal(commit.payload.length, 206);
    assert.equal(toHex(commit.payload.slice(0, 2)), "0x0002");
    assert.equal(toHex(ghost.coinCommitment(commit.payload.slice(2, 34), GHOST, 2)), toHex(commit.commitment));
  }
  assert.notEqual(toHex(a.payload.slice(34, 50)), toHex(b.payload.slice(34, 50)), "each coin its own salt");
  assert.notEqual(toHex(a.commitment), toHex(b.commitment), "so one guess at a key checks one leaf");

  // The app: the worker draws the salt from its secure random source, and
  // the commit the wallet signs is that payload; the stand-in keeps the salt
  // with the leaf.
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  try {
    const flow = createFlow({ prover, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine() });
    await openTestWallet(flow, node);
    const key = await flow.vanishStart("1");
    const positions = flow.vanishSaved();
    const sent = await flow.vanishCheck(positions.map((p) => key.split(" ")[p - 1]));
    assert.equal(sent.ok, true);
    assert.equal(node.accountTxs.length, 1);
    const data = node.accountTxs[0].data;
    assert.equal(data.length, 206);
    assert.equal(toHex(data.slice(0, 2)), "0x0002");
    const leaf = node.leaves.at(-1);
    assert.equal(toHex(leaf.commitment), toHex(ghost.coinCommitment(data.slice(2, 34), GHOST, 2)));
    assert.equal(toHex(leaf.salt), toHex(data.slice(34, 50)));
    assert.equal(toHex(leaf.note), toHex(data.slice(50)));
    // The note carries the same salt, and opens with the key.
    const found = ghost.restore({ chainId: node.chainId, key, records: concat([leaf.commitment, leaf.note]), markers: new Uint8Array(0) });
    assert.equal(toHex(found[0].salt), toHex(data.slice(34, 50)));

    // The stand-in refuses what the node refuses, in its words.
    const wallet = node.wallet("0x1111111111111111111111111111111111111111");
    const send = (bytes) =>
      wallet.request({
        method: "eth_sendTransaction",
        params: [{ from: "0x1111111111111111111111111111111111111111", to: DEFAULT_COMMIT_ENTRY, value: "0x1", data: toHex(bytes) }],
      });
    for (const bytes of [data.slice(0, 205), concat([data, Uint8Array.of(0)]), concat([Uint8Array.of(0, 1), data.slice(2)])]) {
      await assert.rejects(send(bytes), (err) => err.message === `${COMMIT_DATA_ERROR}: ${bytes.length} bytes`);
    }
  } finally {
    prover.terminate();
    await node.close();
  }
});

test("restore reads the salt beside the leaf", async () => {
  const chainId = 7n;
  const commit = ghost.commit({ chainId, amount: GHOST, seed: random(32), key: KEY });
  const salt = commit.payload.slice(34, 50);
  const note = commit.payload.slice(50);
  const stranger = new Uint8Array(188).fill(3);
  const records = concat([stranger, commit.commitment, note]);
  const restore = (salts) => ghost.restore({ chainId, key: KEY, records, salts, markers: new Uint8Array(0) });

  // The salt beside the leaf, the stranger's leaf without one: the coin and
  // its salt.
  let found = restore([null, salt]);
  assert.equal(found.length, 1);
  assert.equal(found[0].position, 1);
  assert.equal(toHex(found[0].salt), toHex(salt));
  assert.equal(toHex(found[0].marker), toHex(commit.marker));
  // Without a salt beside it (as a remainder is served) the note's salt is used.
  found = restore([null, null]);
  assert.equal(toHex(found[0].salt), toHex(salt));
  // A salt beside the leaf that is not the note's: the coin is not trusted.
  const other = Uint8Array.from(salt);
  other[0] ^= 1;
  assert.deepEqual(restore([null, other]), []);
  // Spent: the marker is the salted one.
  found = ghost.restore({ chainId, key: KEY, records, salts: [null, salt], markers: commit.marker });
  assert.equal(found[0].spent, true);

  // fetchTree reads the salt from the node's page and the flow hands it to
  // restore beside the leaf; an altered salt makes the coin unfound, and one
  // that is not 16 bytes is refused like any malformed page.
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  const restored = [];
  const watched = {
    request(op, args, onProgress) {
      if (op === "restore") restored.push(args);
      return prover.request(op, args, onProgress);
    },
  };
  try {
    const flow = createFlow({ prover: watched, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine() });
    await openTestWallet(flow, node);
    node.foreignCommits(1);
    const key = await flow.vanishStart("1");
    await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]));
    const position = node.leaves.length - 1;
    const served = node.leaves[position].salt;
    node.foreignCommits(1);
    node.mineTo(44);

    const tip = node.blocks[node.tip()];
    const tree = await fetchTree(
      { call: (method, params) => fetch(node.url, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) }).then((r) => r.json()).then((r) => r.result) },
      { request: async (op, args) => ghost[op](args) },
      { hash: tip.hash, coinTreeRoot: tip.coinTreeRoot },
    );
    assert.equal(toHex(tree.salts[position]), toHex(served), "the salt the node serves beside the leaf");
    assert.equal(tree.salts.length, node.leaves.length);

    let s = await flow.summonOpen(key);
    assert.equal(s.status, "unclaimed");
    const asked = restored.at(-1);
    assert.equal(asked.salts.length, asked.records.length / 188, "one salt (or none) per leaf");
    assert.equal(toHex(asked.salts[position]), toHex(served), "handed to restore beside its leaf");

    // An endpoint that serves another salt beside the leaf: restore does not
    // trust the coin.
    node.dishonest.salt = (at, real) => {
      if (at !== position) return real;
      const altered = Uint8Array.from(real);
      altered[0] ^= 1;
      return altered;
    };
    s = await flow.summonOpen(key);
    assert.equal(s.status, "not-found");
    // One that is not 16 bytes: the page is refused, nothing is restored.
    node.dishonest.salt = (at, real) => (at === position ? "0x1234" : real);
    const before = restored.length;
    await assert.rejects(flow.summonOpen(key), /malformed: a salt is not 16 bytes/);
    assert.equal(restored.length, before);
    node.dishonest.salt = null;
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");
  } finally {
    prover.terminate();
    await node.close();
  }
});
