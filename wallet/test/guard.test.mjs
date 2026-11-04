// Ghost Guard in the pop-up wallet (wallet/src/wallet.mjs) on the built
// module, with the stand-ins of fakes.mjs: the Guard commit (a new Phantom
// Key made and shown in the wallet, the stop root typed from the stop card,
// the guard secret from the wallet seed), the two warnings, the normal spend,
// the words-only spend with the words alone, and a restore from the words
// that lists a Guard coin and the coin a cancelled slot re-committed.
//
// One chain is built as the tests go, in order: each test adds what the node
// would include. The Guard address and code hash are test values.

import assert from "node:assert/strict";
import { test } from "node:test";

import { concat, equalBytes, fromHex, toHex, toQuantity, word } from "../../webapp/src/bytes.mjs";
import { NOTE_BYTES } from "../../webapp/src/wasm.mjs";
import { TRUSTED_GUARD, WARN_COST_UNKNOWN, WARN_HANDED_OVER, WARN_SLOT_TOO_SMALL, createWallet, vaultStore } from "../src/wallet.mjs";
import { PASSWORD, fakeIndexedDB, loadTestGhost, scriptedUi, spyGhost, spySubtle, testRandom, until } from "./fakes.mjs";

const APP = "https://app.example";
const ghost = await loadTestGhost();

const CHAIN_ID = 7777001n;
const GENESIS = `0x${"ab".repeat(32)}`;
const COMMIT_ENTRY = "0x67686f7374000000000000000000000000000005";
const POLICY = { address: new Uint8Array(20).fill(0x47), codehash: new Uint8Array(32).fill(0x5a) };
// What the wallets of these tests trust on the test network: the commit
// entry and the test Guard policy. An app names neither.
const TRUST = {
  commitEntries: { 7777001: COMMIT_ENTRY },
  policies: { 7777001: { address: toHex(POLICY.address), codehash: toHex(POLICY.codehash) } },
};
// A policy an app might substitute: another frozen policy's address and code hash.
const APP_POLICY = { address: new Uint8Array(20).fill(0x66), codehash: new Uint8Array(32).fill(0x6c) };
const ATTACKER = `0x${"66".repeat(20)}`;
const STOP_ROOT = `0x${"a5".repeat(32)}`;
const OTHER_STOP_ROOT = new Uint8Array(32).fill(0xb5);
const COMMITTED = 1_000_000_000_000n;
const PAID = 100_000_000n;
const FEE = 21_000n;
const BASE_FEE = 3n;
const ACTION_COST = 15_905_968n * BASE_FEE;
const RECIPIENT = `0x${"99".repeat(20)}`;
const SLOT_HEIGHT = 5_000n;

const COMMIT_PARAMS = {
  chainId: "0x76aae9",
  genesisHash: GENESIS,
  nonce: "0x0",
  maxPriorityFeePerGas: "0x3b9aca00",
  maxFeePerGas: "0xb2d05e00",
  gasLimit: "0x30d40",
  to: COMMIT_ENTRY,
  value: toQuantity(COMMITTED),
  filledLeaves: "0x64",
  leavesPerBlock: "0x40",
  baseFee: toQuantity(BASE_FEE),
};
const guardCommit = (params = {}, id = 1) => ({ id, method: "ghost_guardCommit", params: { ...COMMIT_PARAMS, ...params } });

const SIGN_CALLS = ["ghost_wallet_sign", "ghost_wallet_sign_rescue_key", "ghost_wallet_sign_rescue"];

// A wallet with fresh stand-ins. `typed` is what the user types: the Phantom
// Key (`keys`, one per ask, then `key`), the stop root, and whether Approve
// or Reject is pressed. `advance` draws that many bytes first, so the
// wallet's seed is another one than a wallet set up without it.
function setUp({ idb = fakeIndexedDB(), advance = 0, guard = TRUST } = {}) {
  const random = testRandom();
  if (advance > 0) random(advance);
  const spy = spyGhost(ghost);
  const typed = { key: null, keys: [], stopRoot: STOP_ROOT, approve: true };
  const ui = scriptedUi({
    approve: () => (typed.approve ? { password: PASSWORD, stopRoot: typed.stopRoot } : null),
    guardKey: () => (typed.keys.length > 0 ? typed.keys.shift() : typed.key),
  });
  const opener = {
    sent: [],
    postMessage(data, origin) {
      opener.sent.push({ data: structuredClone(data), origin });
    },
  };
  const wallet = createWallet({ ghost: spy, store: vaultStore(idb), ui, subtle: spySubtle(), credentials: null, random, origins: [APP], opener, guard });
  async function ask(data) {
    const before = opener.sent.length;
    wallet.onMessage({ data, origin: APP, source: opener });
    await until(() => opener.sent.length > before);
    return opener.sent.at(-1).data;
  }
  // The module calls made while `run` ran.
  async function callsDuring(run) {
    const from = spy.calls.length;
    const result = await run();
    return { result, calls: spy.calls.slice(from) };
  }
  return { ask, ui, idb, random, spy, typed, callsDuring, words: () => ghost.walletNew(random.log[0]) };
}

// The chain as the node holds it, built as the tests go.
const tree = { records: [], salts: [], markers: [] };
const push = (commitment, note, salt) => {
  assert.equal(note.length, NOTE_BYTES);
  tree.records.push(concat([commitment, note]));
  tree.salts.push(salt);
  return tree.records.length - 1;
};
const treeParams = () => ({
  leaves: toHex(concat(tree.records)),
  salts: tree.salts.map((salt) => (salt === null ? null : toHex(salt))),
  markers: toHex(concat(tree.markers)),
});
const restore = (key) =>
  ghost.guardRestore({ chainId: CHAIN_ID, policy: POLICY, key, records: concat(tree.records), salts: tree.salts, markers: concat(tree.markers) });
const verify = (envelope) => ghost.accountTxVerify({ chainId: CHAIN_ID, genesis: fromHex(GENESIS), envelope: fromHex(envelope) });

// A plain coin of another key, so the Guard coins are not alone.
const stranger = ghost.commit({ chainId: CHAIN_ID, amount: 5_000n, seed: new Uint8Array(32).fill(0x21), key: ghost.newKey(new Uint8Array(32).fill(0x22)) });
push(stranger.commitment, stranger.payload.slice(50), stranger.payload.slice(34, 50));

const owner = setUp();
// What the scenario learns: the owner's Phantom Key, the wallet's words.
const state = {};

test("a Guard commit takes the stop root typed from the stop card, shows a new Phantom Key with the warning, and signs the commit", async () => {
  const { ask, ui, callsDuring } = owner;
  const { result: reply, calls } = await callsDuring(() => ask(guardCommit()));
  assert.equal(reply.id, 1);
  assert.equal(reply.error, undefined, reply.error?.message);
  const { result } = reply;
  assert.deepEqual(Object.keys(result).sort(), ["commitment", "envelope", "marker", "scheme", "sender", "txHash"]);
  assert.equal(result.scheme, "0x0003");

  // The approval named the commit, and warned that a Guard coin handed over
  // as words alone stays under the giver's stop key; the coin is above the
  // cost of a cancel, so no second warning.
  const summary = ui.approvals.at(-1);
  assert.equal(summary.kind, "guardCommit");
  assert.equal(summary.amount, "0.000001");
  assert.equal(summary.to, COMMIT_ENTRY);
  assert.equal(summary.guardAddress, toHex(POLICY.address));
  assert.deepEqual(summary.warnings, [WARN_HANDED_OVER]);
  // The new key was shown once, with the same warning, then checked.
  assert.equal(ui.key.length, 24);
  assert.deepEqual(ui.keyWarnings, [WARN_HANDED_OVER]);
  assert.deepEqual(ui.log.slice(-3), ["approve", "showKey", "checkKey"]);
  assert.ok(calls.includes("ghost_new_key") && calls.includes("ghost_guard_commit"));
  assert.ok(calls.indexOf("ghost_guard_commit") < calls.indexOf("ghost_wallet_sign_rescue_key"), "built before it is signed");

  // The signed transaction is the commit: to the commit entry, the amount as
  // value, the 430-byte Guard payload as data.
  const tx = verify(result.envelope);
  assert.equal(toHex(tx.to), COMMIT_ENTRY);
  assert.equal(tx.value, COMMITTED);
  assert.equal(toHex(tx.sender), result.sender);
  assert.equal(tx.data.length, 430);
  assert.deepEqual([...tx.data.slice(0, 2)], [0x00, 0x03]);
  assert.equal(toHex(ghost.coinCommitment(tx.data.slice(2, 34), COMMITTED, 2)), result.commitment);

  // Included, its leaf is a Guard coin of the shown key.
  state.key = ui.key.join(" ");
  state.walletWords = owner.words();
  state.commitPosition = push(fromHex(result.commitment), tx.data.slice(50), tx.data.slice(34, 50));
  const [coin] = restore(state.key);
  assert.equal(coin.rule, "guard");
  assert.equal(coin.amount, COMMITTED);
  assert.equal(toHex(coin.marker), result.marker);

  // Its guard secret is the wallet seed's (number 0), not the Phantom Key's:
  // a commit to another key with the same wallet words has the same
  // override hash, and one with another wallet's words another.
  const overrideOf = (walletWords) => {
    const made = ghost.guardCommit({
      chainId: CHAIN_ID,
      policy: POLICY,
      walletWords,
      stopRoot: fromHex(STOP_ROOT),
      amount: 7n,
      room: { filledLeaves: 100n, leavesPerBlock: 64n },
      seed: new Uint8Array(32).fill(9),
      key: ghost.newKey(new Uint8Array(32).fill(0x23)),
    });
    const [other] = ghost.guardRestore({
      chainId: CHAIN_ID,
      policy: POLICY,
      key: ghost.newKey(new Uint8Array(32).fill(0x23)),
      records: concat([made.commitment, made.payload.slice(50)]),
      salts: [made.payload.slice(34, 50)],
      markers: new Uint8Array(0),
    });
    return other.guard.overrideHash;
  };
  assert.ok(equalBytes(overrideOf(state.walletWords), coin.guard.overrideHash));
  assert.ok(!equalBytes(overrideOf(ghost.walletNew(new Uint8Array(32).fill(0x24))), coin.guard.overrideHash));
});

test("a Guard commit warns of a slot not above the action cost, and is refused before any screen or before anything is signed", async () => {
  const { ask, ui, typed, spy, callsDuring } = setUp();
  // A coin of exactly the action cost: the second warning, on the approval
  // and with the key.
  const small = await ask(guardCommit({ value: toQuantity(ACTION_COST) }));
  assert.equal(small.error, undefined, small.error?.message);
  assert.deepEqual(ui.approvals.at(-1).warnings, [WARN_HANDED_OVER, WARN_SLOT_TOO_SMALL]);
  assert.deepEqual(ui.keyWarnings, [WARN_HANDED_OVER, WARN_SLOT_TOO_SMALL]);
  assert.equal(ui.approvals.at(-1).actionCost, "0.000000000046757904");
  // A base fee of zero: the cost cannot be checked, and the wallet says so.
  const unknown = await ask(guardCommit({ baseFee: "0x0" }, 2));
  assert.equal(unknown.error, undefined, unknown.error?.message);
  assert.deepEqual(ui.approvals.at(-1).warnings, [WARN_HANDED_OVER, WARN_COST_UNKNOWN]);

  // Refused before any screen, and the module signs nothing.
  const shown = ui.log.length;
  const calls = spy.calls.length;
  for (const [params, said] of [
    [{ filledLeaves: toQuantity(2n ** 32n - 64n * 8_640n) }, /within the hold period of full/],
    [{ leavesPerBlock: "0x0" }, /room cannot be checked/],
    [{ value: "0x0" }, /value is zero/],
    [{ data: "0x" }, /unknown field data/],
    [{ stopRoot: STOP_ROOT }, /unknown field stopRoot/],
    [{ chainId: "0x1" }, /not a network this wallet signs for/],
    [{ to: "0x67" }, /to is not 20 bytes/],
  ]) {
    const reply = await ask(guardCommit(params, 3));
    assert.equal(reply.error?.code, -32602, said.source);
    assert.match(reply.error.message, said);
  }
  const missing = { ...COMMIT_PARAMS };
  delete missing.baseFee;
  assert.match((await ask({ id: 4, method: "ghost_guardCommit", params: missing })).error.message, /missing field baseFee/);
  assert.equal(ui.log.length, shown, "no screen for a refused commit");
  assert.ok(!spy.calls.slice(calls).some((c) => SIGN_CALLS.includes(c) || c === "ghost_guard_commit"));

  // After the approval: a stop root that is not 32 bytes of hex, or that is
  // zero, and a rejection. Nothing is signed and no key is shown.
  for (const [stopRoot, said] of [
    ["", /the stop root is not 32 bytes of hex/],
    [undefined, /the stop root is not 32 bytes of hex/],
    ["0x1234", /the stop root is not 32 bytes of hex/],
    [`0x${"zz".repeat(32)}`, /the stop root is not 32 bytes of hex/],
    [`0x${"00".repeat(32)}`, /only zero bytes/],
  ]) {
    typed.stopRoot = stopRoot;
    const keysShown = ui.log.filter((s) => s === "showKey").length;
    const { result: reply, calls: made } = await callsDuring(() => ask(guardCommit({}, 5)));
    assert.equal(reply.error?.code, -32602, String(stopRoot));
    assert.match(reply.error.message, said);
    assert.ok(!made.some((c) => SIGN_CALLS.includes(c)), "nothing signed");
    assert.equal(ui.log.filter((s) => s === "showKey").length, keysShown, "no key shown");
  }
  typed.stopRoot = STOP_ROOT;
  typed.approve = false;
  const { result: rejected, calls: made } = await callsDuring(() => ask(guardCommit({}, 6)));
  assert.equal(rejected.error?.code, 4001);
  assert.ok(!made.includes("ghost_guard_commit") && !made.some((c) => SIGN_CALLS.includes(c)));
});

test("a wrong word typed back from the new Phantom Key signs nothing until the key is checked", async () => {
  const wallet = setUp();
  let asked = 0;
  wallet.ui.checkKey = async (positions) => {
    wallet.ui.log.push("checkKey");
    asked += 1;
    return asked === 1 ? ["wrong", "words", "here"] : positions.map((p) => wallet.ui.key[p - 1]);
  };
  const reply = await wallet.ask(guardCommit());
  assert.equal(reply.error, undefined, reply.error?.message);
  assert.equal(asked, 2);
  assert.equal(wallet.ui.errors.at(-1), "Those words do not match your Phantom Key. Look at it again.");
  assert.equal(wallet.ui.log.filter((s) => s === "showKey").length, 2);
});

const spendRequest = (params = {}, id = 10) => ({
  id,
  method: "ghost_guardSpend",
  params: { chainId: "0x76aae9", genesisHash: GENESIS, ...treeParams(), recipient: RECIPIENT, out: toQuantity(PAID), fee: toQuantity(FEE), remainder: "guard", filledLeaves: "0x64", leavesPerBlock: "0x40", ...params },
});

test("the normal spend opens the override with this wallet's guard secret and keeps the rest under a new Guard rule", async () => {
  const { ask, ui, typed } = owner;
  assert.ok(state.key, "the commit ran");

  // Another wallet's seed cannot open this coin's override.
  const other = setUp({ advance: 7 });
  other.typed.key = state.key;
  const refused = await other.ask(spendRequest());
  assert.equal(refused.error?.code, -32602);
  assert.match(refused.error.message, /the guard secret does not open this coin's override/);
  assert.equal(refused.result, undefined);

  // A wrong key is asked again; Reject at the key refuses.
  typed.keys = ["not a phantom key"];
  typed.key = null;
  const rejected = await ask(spendRequest({}, 11));
  assert.equal(rejected.error?.code, 4001);
  assert.equal(ui.errors.at(-1), "These are not the words or digits of a Phantom Key. Check each word.");

  // A Guard remainder needs the stop root typed on approval.
  typed.key = state.key;
  typed.stopRoot = "";
  const noStop = await ask(spendRequest({}, 12));
  assert.match(noStop.error?.message ?? "", /the stop root is not 32 bytes of hex/);
  typed.stopRoot = STOP_ROOT;

  const reply = await ask(spendRequest({}, 13));
  assert.equal(reply.error, undefined, reply.error?.message);
  const summary = ui.approvals.at(-1);
  assert.equal(summary.kind, "guardSpend");
  assert.equal(summary.amount, "0.000001");
  assert.equal(summary.out, "0.0000000001");
  assert.equal(summary.remainderRule, "guard");
  assert.equal(ui.keyAsks.at(-1).kind, "guardSpend");
  const envelope = fromHex(reply.result.envelope);
  assert.equal(envelope.length, 1_311_291);
  assert.equal(envelope[0], 0x50);
  assert.deepEqual([...envelope.slice(1, 3)], [0x00, 0x02]);
  assert.equal(reply.result.remainder.number, "0x1");
  assert.equal(BigInt(reply.result.remainder.amount), COMMITTED - PAID - FEE);
  assert.equal(toHex(ghost.keccak256(envelope)), reply.result.txHash);

  // Included: the commit is spent and the remainder is the key's Guard coin.
  tree.markers.push(fromHex(reply.result.marker));
  push(fromHex(reply.result.remainder.commitment), envelope.slice(envelope.length - NOTE_BYTES), null);
  const coins = restore(state.key);
  assert.deepEqual(
    coins.map((c) => [c.number, c.rule, c.spent]),
    [
      [0n, "guard", true],
      [1n, "guard", false],
    ],
  );
});

const wordsOnlyRequest = (params = {}, id = 20) => ({
  id,
  method: "ghost_guardWordsOnlySpend",
  params: { chainId: "0x76aae9", genesisHash: GENESIS, ...treeParams(), recipient: RECIPIENT, fee: toQuantity(FEE), baseFee: toQuantity(BASE_FEE), ...params },
});

test("the words-only spend needs the Phantom Key's words alone: a wallet with no vault makes it, with the warnings", async () => {
  const idb = fakeIndexedDB();
  const { ask, ui, typed, callsDuring } = setUp({ idb });
  typed.key = state.key;

  // At a base fee where the cost of a cancel is above the slot: the second
  // warning. Rejected, nothing is proved.
  typed.approve = false;
  const { result: rejected, calls: none } = await callsDuring(() => ask(wordsOnlyRequest({ baseFee: toQuantity(10n ** 12n) })));
  assert.equal(rejected.error?.code, 4001);
  assert.deepEqual(ui.approvals.at(-1).warnings, [WARN_HANDED_OVER, WARN_SLOT_TOO_SMALL]);
  assert.ok(!none.includes("ghost_guard_words_only_spend"));

  typed.approve = true;
  const { result: reply, calls } = await callsDuring(() => ask(wordsOnlyRequest()));
  assert.equal(reply.error, undefined, reply.error?.message);
  const summary = ui.approvals.at(-1);
  assert.equal(summary.kind, "guardWordsOnly");
  assert.deepEqual(summary.warnings, [WARN_HANDED_OVER]);
  const left = COMMITTED - PAID - FEE;
  assert.equal(summary.slot, "0.000000999899958");
  assert.equal(BigInt(reply.result.slotAmount), left - FEE);

  // No wallet was made or unlocked, and nothing of a wallet seed was called.
  assert.ok(!ui.log.includes("start") && !ui.log.includes("chooseLock"));
  assert.equal(idb.data.has("vault"), false);
  assert.ok(!calls.some((c) => c.startsWith("ghost_wallet_")), calls.join());
  assert.ok(calls.includes("ghost_guard_words_only_spend"));

  const envelope = fromHex(reply.result.envelope);
  assert.equal(envelope.length, 1_311_451);
  assert.equal(envelope[0], 0x53);
  const [, coin] = restore(state.key);
  assert.equal(reply.result.marker, toHex(coin.marker), "it spends the unspent Guard coin");
  assert.equal(toHex(envelope.slice(1 + 318, 1 + 350)), `0x${"00".repeat(12)}${RECIPIENT.slice(2)}`);
  state.wordsOnly = { envelope, marker: fromHex(reply.result.marker), remainder: reply.result.remainder };

  // Included: the marker spent, the zero-value remainder appended.
  tree.markers.push(state.wordsOnly.marker);
  push(fromHex(reply.result.remainder.commitment), envelope.slice(envelope.length - NOTE_BYTES), null);
});

// The fifteen words of slot(marker) for the slot the words-only spend opened.
function slotWords(envelope) {
  const p = envelope.subarray(1);
  const words = Array.from({ length: 15 }, () => new Uint8Array(32));
  words[0].set(p.subarray(170, 190), 12);
  words[1][31] = 1;
  words[2].set(p.subarray(106, 138));
  words[3].set(p.subarray(106, 138));
  words[9] = word(SLOT_HEIGHT);
  words[10] = word(1_700_000_000n);
  for (const [w, from] of [[11, 222], [12, 254], [13, 286], [14, 318]]) words[w].set(p.subarray(from, from + 32));
  return words;
}

test("a restore from the words lists a Guard coin, and from the new key's words the coin a cancelled slot re-committed", async () => {
  assert.ok(state.wordsOnly, "the words-only spend ran");
  // The stop card cancels the words-only spend to a new key (the card's
  // side, through the module). Only the stop root typed at the spend opens
  // the slot.
  const rescueKey = ghost.newKey(new Uint8Array(32).fill(0x25));
  const cancel = (stopRoot) =>
    ghost.guardCancel({
      chainId: CHAIN_ID,
      domain: fromHex(GENESIS),
      policy: POLICY,
      marker: state.wordsOnly.marker,
      slot: slotWords(state.wordsOnly.envelope),
      stopRoot,
      walletWords: state.walletWords,
      newKey: rescueKey,
      debit: 2n * ACTION_COST,
      expiry: SLOT_HEIGHT + 100n,
      baseFee: BASE_FEE,
      headHeight: SLOT_HEIGHT + 10n,
      selector: Uint8Array.of(0xca, 0x11, 0xce, 0x1d),
      seed: new Uint8Array(32).fill(0x26),
      zk: new Uint8Array(32).fill(0x27),
    });
  assert.throws(() => cancel(null), /the words alone cannot cancel/);
  assert.throws(() => cancel(OTHER_STOP_ROOT), /the stop root does not open this slot/);
  const cancelled = cancel(fromHex(STOP_ROOT));
  const settled = COMMITTED - PAID - FEE - FEE - 2n * ACTION_COST;
  assert.equal(cancelled.newCoin.amount, settled);
  const leaf = ghost.coinCommitment(cancelled.calldata.slice(4, 36), settled, 2);
  const position = push(leaf, cancelled.calldata.slice(52), cancelled.calldata.slice(36, 52));

  // The owner's words: the committed coin, the spend's remainder (both
  // spent) and the zero-value remainder of the words-only spend.
  const { ask, ui, typed, idb } = setUp();
  typed.key = state.key;
  const reply = await ask({ id: 30, method: "ghost_guardRestore", params: { chainId: "0x76aae9", treeIndex: "0x0", ...treeParams() } });
  assert.equal(reply.error, undefined, reply.error?.message);
  assert.equal(ui.keyAsks.at(-1).kind, "guardRestore");
  assert.deepEqual(
    ui.coins.map((c) => [c.number, c.rule, c.spent, c.warnings]),
    [
      ["0", "guard", true, [WARN_HANDED_OVER]],
      ["1", "guard", true, [WARN_HANDED_OVER]],
      ["2", "empty", false, []],
    ],
  );
  assert.equal(ui.coins[0].amount, "0.000001");
  assert.equal(reply.result.coins[0].position, state.commitPosition);
  assert.deepEqual(
    reply.result.coins.map((c) => [c.number, c.rule, c.spent]),
    [
      ["0x0", "guard", true],
      ["0x1", "guard", true],
      ["0x2", "empty", false],
    ],
  );
  // The words alone restore: nothing was unlocked or stored.
  assert.ok(!ui.log.includes("approve") && !ui.log.includes("start"));
  assert.equal(idb.data.size, 0);

  // The new key's words: the cancelled slot's new coin, a Guard coin.
  typed.key = rescueKey;
  const rescued = await ask({ id: 31, method: "ghost_guardRestore", params: { chainId: "0x76aae9", treeIndex: "0x0", ...treeParams() } });
  assert.equal(rescued.error, undefined, rescued.error?.message);
  assert.deepEqual(ui.coins, [{ number: "0", amount: "0.000000999806442192", position, spent: false, rule: "guard", warnings: [WARN_HANDED_OVER] }]);
  assert.equal(BigInt(rescued.result.coins[0].amount), settled);
  assert.equal(rescued.result.coins[0].marker, toHex(cancelled.newCoin.marker));

  // Refused before any screen: tree data that is not whole records.
  const shown = ui.log.length;
  const bad = await ask({ id: 32, method: "ghost_guardRestore", params: { chainId: "0x76aae9", treeIndex: "0x0", ...treeParams(), leaves: "0x00" } });
  assert.match(bad.error?.message ?? "", /leaves is not whole records/);
  const salts = await ask({ id: 33, method: "ghost_guardRestore", params: { chainId: "0x76aae9", treeIndex: "0x0", ...treeParams(), salts: [] } });
  assert.match(salts.error?.message ?? "", /salts is not one entry per leaf/);
  assert.equal(ui.log.length, shown);
});

test("a Guard commit goes only to the chain's trusted commit entry: an attacker's account cannot receive the deposit", async () => {
  const { ask, ui, spy, callsDuring } = setUp();
  const shown = ui.log.length;
  for (const to of [ATTACKER, "0x67686f7374000000000000000000000000000007", `0x${"00".repeat(20)}`]) {
    const { result: reply, calls } = await callsDuring(() => ask(guardCommit({ to }, 40)));
    assert.equal(reply.error?.code, -32602, to);
    assert.equal(reply.error.message, "to is not the commit entry of chainId 7777001");
    assert.equal(reply.result, undefined);
    assert.deepEqual(calls, [], "nothing built or signed");
  }
  assert.equal(ui.log.length, shown, "no screen for a commit to another account");

  // The entry in capitals is the same address.
  const upper = await ask(guardCommit({ to: COMMIT_ENTRY.toUpperCase().replace("0X", "0x") }, 41));
  assert.equal(upper.error, undefined, upper.error?.message);
  assert.equal(toHex(verify(upper.result.envelope).to), COMMIT_ENTRY);

  // A wallet that trusts no commit entry for the chain commits nowhere.
  const none = setUp({ guard: { ...TRUST, commitEntries: {} } });
  const refused = await none.ask(guardCommit({}, 42));
  assert.equal(refused.error?.message, "this wallet has no trusted commit entry for chainId 7777001");
  assert.ok(!none.spy.calls.some((c) => SIGN_CALLS.includes(c)));
  assert.ok(spy.calls.length > 0);
});

test("the Guard policy is the wallet's own: an app cannot name one, and a coin of an app's policy gets no Guard screens", async () => {
  // Naming a policy in any Guard request is an unknown field, before any screen.
  const { ask, ui, typed, spy, callsDuring } = setUp();
  const named ={ guardAddress: toHex(APP_POLICY.address), guardCodeHash: toHex(APP_POLICY.codehash) };
  const requests = [
    guardCommit(named, 50),
    spendRequest(named, 51),
    wordsOnlyRequest(named, 52),
    { id: 53, method: "ghost_guardRestore", params: { chainId: "0x76aae9", treeIndex: "0x0", ...treeParams(), ...named } },
  ];
  const calls = spy.calls.length;
  for (const request of requests) {
    const reply = await ask(request);
    assert.equal(reply.error?.code, -32602, request.method);
    assert.match(reply.error.message, /^unknown field guard(Address|CodeHash)$/);
  }
  assert.deepEqual(ui.log, []);
  assert.equal(spy.calls.length, calls);

  // The wallet as shipped trusts no Guard policy yet (it is not final):
  // every Guard request is refused, naming the chain.
  const shipped = setUp({ guard: TRUSTED_GUARD });
  assert.deepEqual(TRUSTED_GUARD.policies, {});
  for (const request of [guardCommit({}, 54), spendRequest({}, 55), wordsOnlyRequest({}, 56), { id: 57, method: "ghost_guardRestore", params: { chainId: "0x76aae9", treeIndex: "0x0", ...treeParams() } }]) {
    const reply = await shipped.ask(request);
    assert.equal(reply.error?.message, "this wallet has no trusted Guard policy for chainId 7777001", request.method);
  }
  assert.deepEqual(shipped.ui.log, []);
  // A trusted policy at a reserved address is refused by the module's check.
  const reserved = setUp({ guard: { ...TRUST, policies: { 7777001: { address: `0x${"00".repeat(19)}05`, codehash: toHex(POLICY.codehash) } } } });
  assert.match((await reserved.ask(guardCommit({}, 58))).error?.message ?? "", /reserved/);

  // A coin committed under an app's own policy, the same wallet seed and stop
  // root: to this wallet it is no Guard coin. Restore names it "other" and
  // neither spend is offered for it.
  const key = ghost.newKey(new Uint8Array(32).fill(0x28));
  const made = ghost.guardCommit({
    chainId: CHAIN_ID,
    policy: APP_POLICY,
    walletWords: state.walletWords,
    stopRoot: fromHex(STOP_ROOT),
    amount: COMMITTED,
    room: { filledLeaves: 100n, leavesPerBlock: 64n },
    seed: new Uint8Array(32).fill(0x29),
    key,
  });
  push(made.commitment, made.payload.slice(50), made.payload.slice(34, 50));
  typed.key = key;
  const listed = await ask({ id: 60, method: "ghost_guardRestore", params: { chainId: "0x76aae9", treeIndex: "0x0", ...treeParams() } });
  assert.deepEqual(listed.result.coins.map((c) => c.rule), ["other"]);
  assert.equal(ui.coins[0].rule, "other");
  for (const request of [wordsOnlyRequest({}, 61), spendRequest({}, 62)]) {
    const { result: reply, calls: made } = await callsDuring(() => ask(request));
    assert.equal(reply.error?.message, "these words hold no unspent Guard coin of this policy in the tree given", request.method);
    assert.ok(!made.includes("ghost_guard_words_only_spend") && !made.includes("ghost_guard_spend"));
  }
  assert.equal(ui.approvals.length, 0, "no approval screen for a coin of an app's policy");
});
