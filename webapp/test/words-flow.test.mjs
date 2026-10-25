// The app's flow with keys of 24 words and salted coins, headless against
// the node stand-in with the real prover in a worker: the save check asks
// three typed words, the digit view is a display option beside the words,
// the commit is version 2 with its salt, the salt read beside the leaf goes
// to the prover for the reveal and the claim (whose remainders are salted
// too), the stand-in verifies each proof as the node does, salted first then
// version 1, and a coin of version 1, made before the salt with a key of
// twelve digit groups, still reveals and claims.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow } from "../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
const RECIPIENT = "0x2222222222222222222222222222222222222222";
// Spec 01, vector coin-commit: a key of twelve digit groups, issued before
// the words. An example only.
const OLD_KEY = "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417";
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

const wordsOf = (key, positions) => positions.map((p) => key.split(" ")[p - 1]);

// Another word of the list in place of `word`.
const otherWord = (word) => (word === "zoo" ? "abandon" : "zoo");

// The stand-in, a worker and a flow on them; every worker request is
// recorded with its arguments.
async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const worker = nodeProver();
  const work = [];
  const prover = {
    request(op, args, onProgress) {
      work.push({ op, args });
      return worker.request(op, args, onProgress);
    },
  };
  const flow = createFlow({ prover, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine() });
  await openTestWallet(flow, node);
  node.foreignCommits(2);
  const proofs = () => work.filter((w) => w.op === "prove").map((w) => w.args);
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { ghost, node, flow, work, proofs, done };
}

// No request to the endpoint holds three words of `key` in a row, nor any
// run of three of its digit groups.
function assertNothingOfKey(node, key) {
  const words = key.split(" ");
  for (let i = 0; i + 3 <= words.length; i += 1) {
    const run = words.slice(i, i + 3).join(" ");
    for (const r of node.requests) assert.ok(!r.body.toLowerCase().includes(run), `${r.method} held words of the key`);
  }
}

test("the save check takes three typed words", async () => {
  const { node, flow, done } = await setUp();
  try {
    const key = await flow.vanishStart("1");
    assert.match(key, /^[a-z]+( [a-z]+){23}$/, "a new key of 24 words");
    assert.equal(flow.state.vanish.view, "words");

    // The digit view: 21 groups, shown beside the words, the same key.
    const digits = await flow.vanishView("digits");
    assert.match(digits, /^\d{4}( \d{4}){20}$/);
    assert.equal(flow.state.vanish.view, "digits");
    assert.equal(flow.state.vanish.digits, digits);
    assert.equal(flow.state.vanish.key, key, "the words stay the key");
    assert.equal(await flow.vanishView("words"), key);
    await assert.rejects(flow.vanishView("qr"), /words or as digits/);

    // Three distinct words of the 24, in order, asked whichever view shows.
    await flow.vanishView("digits");
    const positions = flow.vanishSaved();
    assert.equal(positions.length, 3);
    assert.equal(new Set(positions).size, 3);
    assert.deepEqual([...positions].sort((a, b) => a - b), positions);
    for (const p of positions) assert.ok(p >= 1 && p <= 24);

    // A wrong word, a word typed short, and digit groups instead of words:
    // nothing is sent.
    const right = wordsOf(key, positions);
    const wrong = [...right];
    wrong[1] = otherWord(wrong[1]);
    assert.deepEqual(await flow.vanishCheck(wrong), { ok: false, wrong: [positions[1]] });
    const short = [...right];
    short[0] = short[0].slice(0, -1);
    assert.deepEqual(await flow.vanishCheck(short), { ok: false, wrong: [positions[0]] });
    const groups = digits.split(" ");
    assert.deepEqual((await flow.vanishCheck(positions.map((p) => groups[p - 1]))).wrong, positions);
    assert.equal(flow.state.vanish.stage, "check");
    assert.equal(node.accountTxs.length, 0);
    assert.equal(node.commits.length, 0);

    // The right words, in any case and with spaces around them, send it.
    const sent = await flow.vanishCheck(right.map((w) => ` ${w.toUpperCase()} `));
    assert.equal(sent.ok, true);
    assert.equal(flow.state.vanish.stage, "done");
    assert.equal(flow.state.vanish.key, null, "the key is dropped once sent");
    assert.equal(flow.state.vanish.digits, null, "and its digit view with it");
    assert.equal(node.accountTxs[0].data.length, 206, "a salted commit");
    assertNothingOfKey(node, key);
  } finally {
    await done();
  }
});

test("a salted coin is revealed and claimed", async () => {
  const { ghost, node, flow, proofs, done } = await setUp();
  try {
    const key = await flow.vanishStart("1");
    assert.equal((await flow.vanishCheck(wordsOf(key, flow.vanishSaved()))).ok, true);
    const position = node.leaves.length - 1;
    const salt = node.leaves[position].salt;
    assert.equal(salt.length, 16, "the stand-in keeps the coin's salt");
    node.foreignCommits(2);
    node.mineTo(44);

    // Typed as it might be written down: upper case, hyphens, a line break.
    const words = key.split(" ");
    const typed = `${words.slice(0, 12).join("-").toUpperCase()}\n${words.slice(12).join("  ")}`;
    let s = await flow.summonOpen(typed);
    assert.equal(s.format, "words");
    assert.equal(s.groups, 21);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.amount, GHOST);
    assert.equal(s.current.position, position);

    // The reveal: the coin's salt, read beside its leaf, goes to the prover.
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    let made = proofs().filter((a) => !a.decoy);
    assert.equal(made.length, 1);
    assert.equal(toHex(made[0].salt), toHex(salt));
    assert.equal(node.reveals.length, 1, "the stand-in verified the proof and took it");
    assert.equal(node.reveals[0].out, GHOST / 4n);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
    // The remainder is served without a salt (its salt is in its note), and
    // restore finds it salted, under a fresh salt.
    const remainderAt = node.leaves.findIndex((l) => toHex(l.commitment) === toHex(node.reveals[0].remainder));
    assert.equal(node.leaves[remainderAt].salt, null);
    const records = concat(node.leaves.flatMap((l) => [l.commitment, l.note]));
    const found = ghost.restore({ chainId: node.chainId, key, records, markers: concat(node.spent.map((m) => m.marker)) });
    assert.deepEqual(found.map((c) => c.spent), [true, false]);
    assert.equal(toHex(found[0].salt), toHex(salt));
    assert.equal(found[1].salt.length, 16, "a salted input gives a salted remainder");
    assert.notEqual(toHex(found[1].salt), toHex(salt), "under a fresh salt");
    s = flow.state.summon;
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.number, 1n);

    // The claim, to a new key of 24 words with its own save check on words.
    node.foreignCommits(1);
    node.mineTo(76);
    const newKey = await flow.claimStart();
    assert.match(newKey, /^[a-z]+( [a-z]+){23}$/);
    assert.match(await flow.claimView("digits"), /^\d{4}( \d{4}){20}$/);
    const claimPositions = flow.claimSaved();
    const claimWrong = wordsOf(newKey, claimPositions);
    claimWrong[2] = otherWord(claimWrong[2]);
    assert.equal((await flow.claimCheck(claimWrong)).ok, false);
    assert.equal(node.reveals.length, 1, "a wrong word sends no claim");
    const claimed = await flow.claimCheck(wordsOf(newKey, claimPositions));
    assert.equal(claimed.ok, true);
    made = proofs().filter((a) => !a.decoy);
    assert.equal(made.length, 2);
    assert.equal(made[1].kind, "claim");
    assert.equal(toHex(made[1].salt), toHex(found[1].salt), "the remainder's salt, from its note");
    assert.equal(made[1].newKey, newKey);
    assert.equal(node.reveals.length, 2);
    assert.equal(flow.state.summon.status, "claimed");
    assert.equal(flow.state.summon.claim.key, null);
    assert.equal(flow.state.summon.claim.digits, null);

    // The new key holds the value, as a salted coin.
    s = await flow.summonOpen(newKey);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.number, 0n);
    assert.equal(s.current.amount, claimed.amount);
    const all = concat(node.leaves.flatMap((l) => [l.commitment, l.note]));
    const claimedCoin = ghost.restore({ chainId: node.chainId, key: newKey, records: all, markers: new Uint8Array(0) });
    assert.equal(claimedCoin[0].salt.length, 16);
    flow.summonClose();

    // No proof was ever a decoy, and no key left the app.
    assert.ok(proofs().every((a) => !a.decoy));
    assertNothingOfKey(node, key);
    assertNothingOfKey(node, newKey);
  } finally {
    await done();
  }
});

test("a version 1 coin still reveals", async () => {
  const { ghost, node, flow, proofs, done } = await setUp();
  try {
    // A coin made before the salt: a version 1 commit of a key of twelve
    // digit groups, which the node still takes. (The app never sends one.)
    const commit = ghost.commit({ version: 1, chainId: node.chainId, amount: GHOST, seed: random(32), key: OLD_KEY });
    assert.equal(commit.payload.length, 190);
    const wallet = node.wallet("0x1111111111111111111111111111111111111111");
    await wallet.request({
      method: "eth_sendTransaction",
      params: [{ from: "0x1111111111111111111111111111111111111111", to: DEFAULT_COMMIT_ENTRY, value: "0xde0b6b3a7640000", data: toHex(commit.payload) }],
    });
    const position = node.leaves.length - 1;
    assert.equal(node.leaves[position].salt, null, "no salt beside a version 1 leaf");
    node.foreignCommits(1);
    node.mineTo(44);

    let s = await flow.summonOpen(OLD_KEY);
    assert.equal(s.format, "standard");
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.position, position);

    // A reveal that cannot be made: nothing is proved for it.
    const proved = proofs().length;
    await assert.rejects(flow.summonReveal({ amount: "5", recipient: RECIPIENT }), /at most/);
    assert.equal(proofs().length, proved, "no proof, no stand-in proof either");

    // The reveal: no salt goes to the prover, and the stand-in verifies the
    // proof as version 1 once the salted check fails.
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    const made = proofs().filter((a) => !a.decoy);
    assert.equal(made.length, 1);
    assert.equal(made[0].salt, null);
    assert.equal(node.reveals.length, 1);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
    s = flow.state.summon;
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.number, 1n);
    // Its remainder is version 1 too.
    const records = concat(node.leaves.flatMap((l) => [l.commitment, l.note]));
    const found = ghost.restore({ chainId: node.chainId, key: OLD_KEY, records, markers: new Uint8Array(0) });
    assert.deepEqual(found.map((c) => c.salt), [null, null]);

    // And it claims to a new key of 24 words.
    node.foreignCommits(1);
    node.mineTo(76);
    const newKey = await flow.claimStart();
    const claimed = await flow.claimCheck(wordsOf(newKey, flow.claimSaved()));
    assert.equal(claimed.ok, true);
    assert.equal(proofs().filter((a) => !a.decoy).at(-1).salt, null);
    assert.equal(node.reveals.length, 2);
    assert.equal(flow.state.summon.status, "claimed");
    s = await flow.summonOpen(newKey);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.current.amount, claimed.amount);
  } finally {
    await done();
  }
});
