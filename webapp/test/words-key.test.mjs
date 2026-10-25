// A Phantom Key as 24 words: new keys are words, a typed key is read only by
// the client library's parse (any case, spaces or hyphens between words,
// whole words only, the check verified before anything is derived), a wrong
// or swapped word is refused with a message that names at most a position
// and holds no word of the key, and the digit keys of twelve or twenty-four
// groups issued before the words are refused.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow, normalKey, pickGroups, wrongWords } from "../src/flow.mjs";
import { loadModule, nodeProver } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const ghost = await loadModule();

// A fixed words key and its digit view (client/tests/word_key.rs, the
// words vector of the secret 0x00, 0x01, ... 0x1f). An example only.
const WORDS =
  "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey trip";
const DIGITS = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
// The retired twelve-group key of spec 01's vectors, refused now. An example
// only.
const OLD_KEY = "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417";
const GHOST = 10n ** 18n;

const list = WORDS.split(" ");
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

// A refusal of a typed key: it says the key is not valid, and holds no word
// of `words` nor any run of four digits.
function refusedWithout(words, pattern) {
  return (err) => {
    assert.match(err.message, /not a valid Phantom Key/);
    if (pattern) assert.match(err.message, pattern);
    for (const word of new Set(words)) {
      assert.doesNotMatch(err.message, new RegExp(`\\b${word}\\b`, "i"), `the refusal echoes "${word}"`);
    }
    assert.doesNotMatch(err.message, /\d{4}/, "the refusal holds digits of the key");
    return true;
  };
}

test("a new key is 24 words", () => {
  const seen = new Set();
  for (let i = 0; i < 8; i += 1) {
    const key = ghost.newKey(random(32));
    // 24 lower-case words of the list, separated by single spaces.
    assert.match(key, /^[a-z]{3,8}( [a-z]{3,8}){23}$/);
    assert.deepEqual(ghost.checkKey(key), { format: "words", groups: 21 });
    seen.add(key);
  }
  assert.equal(seen.size, 8, "each key is new");
  // Its digit view is 21 groups, which open the same key: shown as digits,
  // the words again.
  const key = ghost.newKey(random(32));
  const digits = ghost.keyDigits(key);
  assert.match(digits, /^\d{4}( \d{4}){20}$/);
  assert.deepEqual(ghost.checkKey(digits), { format: "words", groups: 21 });
  assert.equal(ghost.keyDigits(digits), digits);
  // The fixed vector, both ways.
  assert.equal(ghost.keyDigits(WORDS), DIGITS);
  assert.deepEqual(ghost.checkKey(DIGITS), { format: "words", groups: 21 });
  // The key commits and restores the same whether it was typed as words or
  // as digits.
  const commit = ghost.commit({ chainId: 7n, amount: GHOST, seed: random(32), key: WORDS });
  const records = concat([commit.commitment, commit.payload.slice(50)]);
  for (const typed of [WORDS, DIGITS]) {
    const found = ghost.restore({ chainId: 7n, key: typed, records, markers: new Uint8Array(0) });
    assert.equal(found.length, 1, typed === WORDS ? "as words" : "as digits");
    assert.equal(toHex(found[0].marker), toHex(commit.marker));
  }
});

test("words round-trip through the save check", () => {
  const key = ghost.newKey(random(32));
  const words = key.split(" ");
  for (let i = 0; i < 20; i += 1) {
    const positions = pickGroups(random);
    assert.equal(new Set(positions).size, 3);
    assert.ok(positions.every((p) => p >= 1 && p <= 24));
    const answers = positions.map((p) => words[p - 1]);
    assert.deepEqual(wrongWords(key, positions, answers), []);
    assert.deepEqual(wrongWords(key, positions, answers.map((w) => ` ${w.toUpperCase()} `)), [], "in any case");
    // A word typed short is wrong, never completed.
    const short = [...answers];
    short[2] = short[2].slice(0, -1);
    assert.deepEqual(wrongWords(key, positions, short), [positions[2]]);
  }
});

test("a typed key: any case, spaces or hyphens, whole words only", () => {
  const typed = [
    WORDS.toUpperCase(),
    list.map((w, i) => (i % 2 ? w.toUpperCase() : w)).join(" "),
    list.join("-"),
    list.map((w, i) => (i % 3 ? `${w} ` : `${w}--`)).join(" "),
    normalKey(`  ${list.slice(0, 12).join(" ")}\n${list.slice(12).join("\t")}  `),
  ];
  for (const text of typed) {
    assert.deepEqual(ghost.checkKey(text), { format: "words", groups: 21 }, text);
    assert.equal(ghost.keyDigits(text), DIGITS);
  }
  // A word cut short or run on is not a word: refused and named by its
  // position, never completed.
  for (const [at, typedWord] of [
    [5, list[4].slice(0, 4)],
    [10, `${list[9]}s`],
  ]) {
    const changed = [...list];
    changed[at - 1] = typedWord;
    assert.throws(() => ghost.checkKey(changed.join(" ")), refusedWithout([...list, typedWord], new RegExp(`word ${at} is not in the word list`)));
  }
  // Two words run together are one unknown word.
  const joined = [list[0] + list[1], ...list.slice(2)].join(" ");
  assert.throws(() => ghost.checkKey(joined), refusedWithout([...list, list[0] + list[1]], /word 1 is not in the word list/));
  // 23 or 25 words, and a word mixed with digits.
  assert.throws(() => ghost.checkKey(list.slice(1).join(" ")), refusedWithout(list, /24 words, not 23/));
  assert.throws(() => ghost.checkKey(`${WORDS} ${list[0]}`), refusedWithout(list, /24 words, not 25/));
  assert.throws(() => ghost.checkKey(`${WORDS} 7`), refusedWithout(list, /character/));
});

test("a swapped word is refused", () => {
  assert.deepEqual(ghost.checkKey(WORDS), { format: "words", groups: 21 });
  // Two neighbours swapped, the first and the last swapped: every word is
  // still in the list, the check fails, and the refusal names no word.
  for (const [a, b] of [
    [2, 3],
    [1, 24],
    [6, 7],
  ]) {
    const swapped = [...list];
    [swapped[a - 1], swapped[b - 1]] = [swapped[b - 1], swapped[a - 1]];
    assert.notEqual(swapped.join(" "), WORDS);
    assert.throws(() => ghost.checkKey(swapped.join(" ")), refusedWithout(list, /do not pass the check/), `words ${a} and ${b}`);
    // Nothing is derived from it: no restore, no commit, no digit view.
    assert.throws(() => ghost.keyDigits(swapped.join(" ")), refusedWithout(list));
    assert.throws(
      () => ghost.restore({ chainId: 7n, key: swapped.join(" "), records: new Uint8Array(0), markers: new Uint8Array(0) }),
      refusedWithout(list),
    );
    assert.throws(() => ghost.commit({ chainId: 7n, amount: GHOST, seed: random(32), key: swapped.join(" ") }), refusedWithout(list));
  }
  // A wrong word of the list in place of the right one fails the check too.
  const wrong = [...list];
  wrong[7] = list[7] === "zoo" ? "abandon" : "zoo";
  assert.throws(() => ghost.checkKey(wrong.join(" ")), refusedWithout([...list, "zoo"], /do not pass the check/));
  // A mistyped digit of the digit view fails its check group.
  const digit = `${DIGITS.slice(0, 5)}${(Number(DIGITS[5]) + 1) % 10}${DIGITS.slice(6)}`;
  assert.throws(() => ghost.checkKey(digit), refusedWithout(list, /group 21/));
});

test("an old 12- or 24-group digit key is refused", async () => {
  // In the module: refused by its count of digits, and nothing is derived
  // from it: no digit view, no commit, no restore.
  const LONG_KEY = `${OLD_KEY} ${OLD_KEY}`;
  for (const [typed, count] of [
    [OLD_KEY, 48],
    [OLD_KEY.replaceAll(" ", "-"), 48],
    [LONG_KEY, 96],
  ]) {
    const refusal = refusedWithout([], new RegExp(`has 84 digits, not ${count}`));
    assert.throws(() => ghost.checkKey(typed), refusal, typed);
    assert.throws(() => ghost.keyDigits(typed), refusal);
    assert.throws(() => ghost.commit({ version: 1, chainId: 7n, amount: GHOST, seed: random(32), key: typed }), refusal);
    assert.throws(() => ghost.restore({ chainId: 7n, key: typed, records: new Uint8Array(0), markers: new Uint8Array(0) }), refusal);
  }

  // Through the app: Summon refuses it before anything is asked of the
  // endpoint.
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  try {
    const flow = createFlow({ prover, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine() });
    const before = node.requests.length;
    for (const typed of [OLD_KEY, ` ${OLD_KEY.replaceAll(" ", "\n")} `, LONG_KEY]) {
      await assert.rejects(flow.summonOpen(typed), /has 84 digits, not (48|96)/);
    }
    assert.equal(node.requests.length, before);
  } finally {
    prover.terminate();
    await node.close();
  }
});

test("a version 1 coin of a words key still restores", async () => {
  // In the module: the coin-commit vector of client/tests/first_slice.rs,
  // under the example key as its digit view; its version 1 coin restores
  // without a salt.
  const v1 = ghost.commit({ version: 1, chainId: 7n, amount: GHOST, seed: random(32), key: DIGITS });
  assert.equal(toHex(v1.commitment), "0x9cadb00df6812a83ff2525fbaef0b634a020d600dc3bf3315efc3b20bfdb876c", "vector coin-commit of a words key");
  const found = ghost.restore({ chainId: 7n, key: WORDS, records: concat([v1.commitment, v1.payload.slice(34)]), markers: new Uint8Array(0) });
  assert.equal(found.length, 1);
  assert.equal(found[0].salt, null);
  assert.equal(found[0].amount, GHOST);

  // Through the app, against the stand-in: a version 1 commit of the key
  // sent before the salt, then Summon with the key as it was written down.
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  try {
    node.foreignCommits(2);
    const commit = ghost.commit({ version: 1, chainId: node.chainId, amount: GHOST, seed: random(32), key: DIGITS });
    const wallet = node.wallet("0x1111111111111111111111111111111111111111");
    await wallet.request({
      method: "eth_sendTransaction",
      params: [{ from: "0x1111111111111111111111111111111111111111", to: DEFAULT_COMMIT_ENTRY, value: "0xde0b6b3a7640000", data: toHex(commit.payload) }],
    });
    node.foreignCommits(1);
    node.mineTo(44);
    const flow = createFlow({ prover, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine() });
    for (const typed of [DIGITS, DIGITS.replaceAll(" ", "-"), ` ${DIGITS.replaceAll(" ", "\n")} `, WORDS]) {
      const s = await flow.summonOpen(typed);
      assert.equal(s.format, "words");
      assert.equal(s.groups, 21);
      assert.equal(s.status, "unclaimed");
      assert.equal(s.current.amount, GHOST);
      assert.equal(s.coins.length, 1);
    }
    // A typo in it is refused before anything is asked of the endpoint.
    const before = node.requests.length;
    await assert.rejects(flow.summonOpen(`${DIGITS.slice(0, -1)}8`), /group 21 does not match/);
    assert.equal(node.requests.length, before);
  } finally {
    prover.terminate();
    await node.close();
  }
});
