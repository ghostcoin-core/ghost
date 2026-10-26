// Rescue-key accounts in the pop-up wallet (wallet/src/wallet.mjs) on the
// built module, with the stand-ins of fakes.mjs: new accounts are scheme
// 0x0003, a vault stored before rescue keys keeps its accounts as 0x0001,
// and ghost_rescue signs scheme 0x0004 with the SLH-DSA key alone, to a
// destination typed in the wallet, moving the balance less the maximum fee.

import assert from "node:assert/strict";
import { test } from "node:test";

import { fromHex, toHex } from "../../webapp/src/bytes.mjs";
import { checkRequest, createWallet, formatGhost, vaultStore } from "../src/wallet.mjs";
import { PASSWORD, fakeIndexedDB, loadTestGhost, scriptedUi, spyGhost, spySubtle, testRandom, until } from "./fakes.mjs";

const APP = "https://app.example";
const ghost = await loadTestGhost();

const PARAMS = {
  chainId: "0x76aae9",
  genesisHash: `0x${"ab".repeat(32)}`,
  nonce: "0x3",
  maxPriorityFeePerGas: "0x3b9aca00",
  maxFeePerGas: "0xb2d05e00",
  gasLimit: "0x1df78",
  to: `0x67686f7374${"0".repeat(28)}05`,
  value: "0xde0b6b3a7640000",
  data: "0x0002ab",
};
// ghost_rescue: no to, value or data; the balance instead (2 GHOST).
const RESCUE_PARAMS = {
  chainId: "0x76aae9",
  genesisHash: `0x${"ab".repeat(32)}`,
  nonce: "0x0",
  maxPriorityFeePerGas: "0x3b9aca00",
  maxFeePerGas: "0xb2d05e00",
  gasLimit: "0x3d090",
  balance: "0x1bc16d674ec80000",
};
const MAX_FEE = 0x3d090n * 0xb2d05e00n;
const BALANCE = 2n * 10n ** 18n;
const DESTINATION = `0x${"5a".repeat(20)}`;
const GENESIS = fromHex(PARAMS.genesisHash);
const CHAIN_ID = 7777001n;

const ACCOUNT = { id: 1, method: "ghost_getAccount" };
const RECEIVE = { id: 4, method: "ghost_newReceiveAddress" };
const signFrom = (from, id = 2) => ({ id, method: "ghost_signTransaction", params: from ? { ...PARAMS, from } : PARAMS });
const rescue = (params = {}, id = 6) => ({ id, method: "ghost_rescue", params: { ...RESCUE_PARAMS, ...params } });

const SIGN_CALLS = ["ghost_wallet_sign", "ghost_wallet_sign_rescue_key", "ghost_wallet_sign_rescue"];

// A wallet with fresh stand-ins; the approval screen answers the password
// and `typed.destination`, what the user typed in the wallet.
function setUp({ idb = fakeIndexedDB(), typed = { destination: DESTINATION } } = {}) {
  const random = testRandom();
  const spy = spyGhost(ghost);
  const ui = scriptedUi({ approve: () => ({ password: PASSWORD, destination: typed.destination }) });
  const opener = {
    sent: [],
    postMessage(data, origin) {
      opener.sent.push({ data: structuredClone(data), origin });
    },
  };
  const wallet = createWallet({ ghost: spy, store: vaultStore(idb), ui, subtle: spySubtle(), credentials: null, random, origins: [APP], opener });
  async function ask(data) {
    const before = opener.sent.length;
    wallet.onMessage({ data, origin: APP, source: opener });
    await until(() => opener.sent.length > before);
    return opener.sent.at(-1).data;
  }
  // The signing calls made while `run` ran.
  async function signsDuring(run) {
    const from = spy.calls.length;
    const result = await run();
    return { result, signs: spy.calls.slice(from).filter((c) => SIGN_CALLS.includes(c)) };
  }
  return { ask, ui, idb, random, spy, typed, signsDuring, words: () => ghost.walletNew(random.log[0]) };
}

function find(haystack, needle) {
  outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// The scheme an envelope carries: the 2-byte string before the account's
// public key and its RLP header.
function envelopeScheme(envelope, publicKey) {
  const header = publicKey.length === 1344 ? [0xb9, 0x05, 0x40] : [0xb9, 0x05, 0x20];
  const at = find(envelope, [...header, ...publicKey]);
  assert.ok(at > 3, "the envelope carries the account's public key");
  assert.equal(envelope[at - 3], 0x82);
  return `0x${toHex(envelope.slice(at - 2, at)).slice(2)}`;
}

const verify = (envelope) => ghost.accountTxVerify({ chainId: CHAIN_ID, genesis: GENESIS, envelope: fromHex(envelope) });

// A wallet whose vault was stored before rescue keys, with `issued` receive
// addresses handed out: a vault and its issued count, no "accounts" record.
async function oldWallet(issued) {
  const first = setUp();
  await first.ask(ACCOUNT);
  first.idb.data.delete("accounts");
  if (issued > 0) first.idb.data.set("issued", { count: issued });
  return { idb: first.idb, words: first.words() };
}

test("a new wallet answers ghost_getAccount with a 0x0003 account and says it has a rescue key", async () => {
  const { ask, idb, words, spy } = setUp();
  const reply = await ask(ACCOUNT);
  const expected = ghost.walletRescueAccount(words(), 0);
  assert.deepEqual(reply.result, { address: toHex(expected.address), publicKey: toHex(expected.publicKey), scheme: "0x0003", rescueKey: true });
  assert.equal(fromHex(reply.result.publicKey).length, 1344);
  assert.notEqual(reply.result.address, toHex(ghost.walletAccount(words(), 0).address));
  assert.ok(spy.calls.includes("ghost_wallet_rescue_account"));
  // Stored with the vault: every account of this wallet is scheme 0x0003.
  assert.deepEqual(idb.data.get("accounts"), { rescueFrom: 0 });
  assert.equal(await vaultStore(idb).getRescueFrom(), 0);

  const receive = await ask(RECEIVE);
  const one = ghost.walletRescueAccount(words(), 1);
  assert.deepEqual(receive.result, { address: toHex(one.address), publicKey: toHex(one.publicKey), scheme: "0x0003", rescueKey: true });
  assert.deepEqual(idb.data.get("accounts"), { rescueFrom: 0 });
});

test("ghost_signTransaction from a rescue-key account signs scheme 0x0003 and the node verifier accepts it", async () => {
  const { ask, ui, random, words, signsDuring } = setUp();
  const account = (await ask(ACCOUNT)).result;
  const { result: reply, signs } = await signsDuring(() => ask(signFrom(null)));
  assert.deepEqual(signs, ["ghost_wallet_sign_rescue_key"]);
  assert.equal(reply.result.scheme, "0x0003");
  assert.equal(reply.result.sender, account.address);

  // The approval screen named the scheme and the rescue key.
  const summary = ui.approvals.at(-1);
  assert.equal(summary.kind, "sign");
  assert.equal(summary.scheme, "0x0003");
  assert.equal(summary.rescueKey, true);

  const envelope = fromHex(reply.result.envelope);
  assert.equal(envelopeScheme(envelope, fromHex(account.publicKey)), "0x0003");
  const fields = checkRequest(signFrom(null)).fields;
  const expected = ghost.walletSignRescueKey({ words: words(), index: 0, ...fields, seed: random.log.at(-1) });
  assert.equal(reply.result.envelope, toHex(expected.envelope));
  const verified = verify(reply.result.envelope);
  assert.equal(toHex(verified.sender), account.address);
  assert.equal(toHex(verified.txHash), reply.result.txHash);
  assert.equal(toHex(verified.to), PARAMS.to);

  // From an issued receive address, the same.
  const issued = (await ask(RECEIVE)).result;
  const fromIssued = await ask(signFrom(issued.address, 3));
  assert.equal(fromIssued.result.scheme, "0x0003");
  assert.equal(toHex(verify(fromIssued.result.envelope).sender), issued.address);
  assert.equal(envelopeScheme(fromHex(fromIssued.result.envelope), fromHex(issued.publicKey)), "0x0003");
});

test("a wallet stored before the rescue key keeps its first accounts as 0x0001 with no rescue key and issues 0x0003 after", async () => {
  const { idb, words } = await oldWallet(2);
  const { ask, ui, signsDuring } = setUp({ idb });

  // Account 0 and the issued accounts 1 and 2 stay scheme 0x0001.
  const account = (await ask(ACCOUNT)).result;
  const zero = ghost.walletAccount(words, 0);
  assert.deepEqual(account, { address: toHex(zero.address), publicKey: toHex(zero.publicKey), scheme: "0x0001", rescueKey: false });
  // Written on the first request: the issued count plus one.
  assert.deepEqual(idb.data.get("accounts"), { rescueFrom: 3 });

  const one = toHex(ghost.walletAccount(words, 1).address);
  const { result: signed, signs } = await signsDuring(() => ask(signFrom(one)));
  assert.deepEqual(signs, ["ghost_wallet_sign"]);
  assert.equal(signed.result.scheme, "0x0001");
  assert.equal(ui.approvals.at(-1).scheme, "0x0001");
  assert.equal(ui.approvals.at(-1).rescueKey, false);
  assert.equal(toHex(verify(signed.result.envelope).sender), one);
  assert.equal(envelopeScheme(fromHex(signed.result.envelope), ghost.walletAccount(words, 1).publicKey), "0x0001");

  // The next receive address is a rescue-key account, and signs as one.
  const next = (await ask(RECEIVE)).result;
  const three = ghost.walletRescueAccount(words, 3);
  assert.deepEqual(next, { address: toHex(three.address), publicKey: toHex(three.publicKey), scheme: "0x0003", rescueKey: true });
  const fromNext = await signsDuring(() => ask(signFrom(next.address, 3)));
  assert.deepEqual(fromNext.signs, ["ghost_wallet_sign_rescue_key"]);
  assert.equal(fromNext.result.result.scheme, "0x0003");
  assert.equal(toHex(verify(fromNext.result.result.envelope).sender), next.address);

  // The record is written once: a reload keeps it.
  const after = setUp({ idb });
  assert.equal((await after.ask(ACCOUNT)).result.scheme, "0x0001");
  assert.deepEqual(idb.data.get("accounts"), { rescueFrom: 3 });

  // A vault from before with no issued address: only account 0 stays 0x0001.
  const lone = await oldWallet(0);
  const fresh = setUp({ idb: lone.idb });
  assert.equal((await fresh.ask(ACCOUNT)).result.scheme, "0x0001");
  assert.deepEqual(lone.idb.data.get("accounts"), { rescueFrom: 1 });
  assert.equal((await fresh.ask(RECEIVE)).result.address, toHex(ghost.walletRescueAccount(lone.words, 1).address));
});

test("ghost_rescue signs scheme 0x0004 to the destination typed in the wallet and never calls the ML-DSA signer", async () => {
  const { ask, ui, random, words, signsDuring } = setUp();
  const account = (await ask(ACCOUNT)).result;
  const { result: reply, signs } = await signsDuring(() => ask(rescue()));
  // Only the SLH-DSA signer: neither ML-DSA signing call.
  assert.deepEqual(signs, ["ghost_wallet_sign_rescue"]);
  assert.equal(reply.id, 6);
  assert.deepEqual(Object.keys(reply.result).sort(), ["envelope", "scheme", "sender", "txHash"]);
  assert.equal(reply.result.scheme, "0x0004");
  assert.equal(reply.result.sender, account.address);

  // The approval screen names the account and the amounts, and carries no
  // destination: the user types it there.
  const summary = ui.approvals.at(-1);
  assert.equal(summary.kind, "rescue");
  assert.equal(summary.from, account.address);
  assert.equal(summary.balance, "2");
  assert.equal(summary.maxFee, formatGhost(MAX_FEE));
  assert.ok(!Object.hasOwn(summary, "to"));

  const envelope = fromHex(reply.result.envelope);
  assert.equal(envelopeScheme(envelope, fromHex(account.publicKey)), "0x0004");
  const verified = verify(reply.result.envelope);
  assert.equal(toHex(verified.sender), account.address);
  assert.equal(toHex(verified.txHash), reply.result.txHash);
  assert.equal(toHex(verified.to), DESTINATION);
  assert.equal(verified.data.length, 0);

  // The module's own 0x0004 signature of the same fields and randomness.
  const fields = checkRequest(rescue()).fields;
  const expected = ghost.walletSignRescue({
    words: words(),
    index: 0,
    ...fields,
    to: fromHex(DESTINATION),
    value: BALANCE - MAX_FEE,
    data: new Uint8Array(0),
    seed: random.log.at(-1),
  });
  assert.equal(reply.result.envelope, toHex(expected.envelope));
  assert.equal(reply.result.txHash, toHex(expected.txHash));
});

test("ghost_rescue moves the balance less the maximum fee and refuses a balance that does not cover it", async () => {
  const { ask, ui, spy } = setUp();
  await ask(ACCOUNT);
  const issued = (await ask(RECEIVE)).result;

  const reply = await ask(rescue({ from: issued.address }));
  const verified = verify(reply.result.envelope);
  assert.equal(verified.value, BALANCE - MAX_FEE);
  assert.equal(verified.value + verified.gasLimit * verified.maxFeePerGas, BALANCE);
  assert.equal(verified.gasLimit, 0x3d090n);
  assert.equal(toHex(verified.sender), issued.address);
  assert.equal(ui.approvals.at(-1).amount, formatGhost(BALANCE - MAX_FEE));

  // A balance one wei above the maximum fee moves one wei.
  const small = await ask(rescue({ balance: `0x${(MAX_FEE + 1n).toString(16)}` }, 7));
  assert.equal(verify(small.result.envelope).value, 1n);

  // Equal to it or below: nothing to move, refused before any screen.
  const shown = ui.log.length;
  const calls = spy.calls.length;
  for (const balance of [MAX_FEE, MAX_FEE - 1n, 0n]) {
    const refused = await ask(rescue({ balance: `0x${balance.toString(16)}` }, 8));
    assert.equal(refused.error?.code, -32602);
    assert.match(refused.error.message, /^balance does not cover gasLimit \* maxFeePerGas/);
    assert.equal(refused.result, undefined);
  }
  assert.equal(ui.log.length, shown, "no screen for a refused rescue");
  assert.equal(spy.calls.length, calls, "the module was not called");
});

test("ghost_rescue is refused before any screen for an account with no rescue key", async () => {
  const { idb, words } = await oldWallet(1);
  const one = toHex(ghost.walletAccount(words, 1).address);

  // Account 0 is known to be 0x0001 without any unlock: refused at once.
  const fresh = setUp({ idb });
  const atOnce = await fresh.ask(rescue());
  assert.equal(atOnce.error?.code, -32602);
  assert.equal(atOnce.error.message, "this account has no rescue key");
  assert.deepEqual(fresh.ui.log, []);
  assert.ok(!fresh.spy.calls.some((c) => SIGN_CALLS.includes(c)));

  // An issued 0x0001 address not yet known in this window: checked once
  // unlocked, and still nothing is signed.
  const unknown = await fresh.signsDuring(() => fresh.ask(rescue({ from: one }, 7)));
  assert.equal(unknown.result.error?.message, "this account has no rescue key");
  assert.deepEqual(unknown.signs, []);

  // Known now: refused before any screen.
  const shown = fresh.ui.log.length;
  const known = await fresh.ask(rescue({ from: one }, 8));
  assert.equal(known.error?.message, "this account has no rescue key");
  assert.equal(fresh.ui.log.length, shown);

  // An account this wallet issued after the change has a rescue key.
  const next = (await fresh.ask(RECEIVE)).result;
  assert.equal(next.rescueKey, true);
  const rescued = await fresh.signsDuring(() => fresh.ask(rescue({ from: next.address }, 9)));
  assert.deepEqual(rescued.signs, ["ghost_wallet_sign_rescue"]);
  assert.equal(toHex(verify(rescued.result.result.envelope).sender), next.address);
});

test("ghost_rescue refuses a destination in the request and an invalid typed destination", async () => {
  const { ask, ui, spy, typed, signsDuring } = setUp();
  const account = (await ask(ACCOUNT)).result;

  // A destination, value or data in the request: unknown fields, refused
  // before any screen, so an app cannot choose where a rescue goes.
  const shown = ui.log.length;
  const calls = spy.calls.length;
  for (const [extra, said] of [
    [{ to: DESTINATION }, /unknown field to/],
    [{ value: "0x1" }, /unknown field value/],
    [{ data: "0x" }, /unknown field data/],
    [{ destination: DESTINATION }, /unknown field destination/],
  ]) {
    const reply = await ask(rescue(extra));
    assert.equal(reply.error?.code, -32602);
    assert.match(reply.error.message, said);
  }
  const missing = { ...RESCUE_PARAMS };
  delete missing.balance;
  const noBalance = await ask({ id: 9, method: "ghost_rescue", params: missing });
  assert.match(noBalance.error.message, /missing field balance/);
  assert.equal(ui.log.length, shown, "no screen for a refused rescue");
  assert.equal(spy.calls.length, calls, "the module was not called");

  // Typed after approval: not 20 bytes of 0x hex, or the account itself,
  // and nothing is signed.
  for (const [destination, said] of [
    ["", /destination is not 20 bytes of 0x hex/],
    ["0x12", /destination is not 20 bytes of 0x hex/],
    [`0x${"zz".repeat(20)}`, /destination is not 20 bytes of 0x hex/],
    [`0x${"5a".repeat(32)}`, /destination is not 20 bytes of 0x hex/],
    [undefined, /destination is not 20 bytes of 0x hex/],
    [account.address, /the destination is the account itself/],
    [account.address.toUpperCase().replace("0X", "0x"), /the destination is the account itself/],
  ]) {
    typed.destination = destination;
    const { result: reply, signs } = await signsDuring(() => ask(rescue({}, 10)));
    assert.equal(reply.error?.code, -32602, String(destination));
    assert.match(reply.error.message, said);
    assert.equal(reply.result, undefined);
    assert.deepEqual(signs, [], "nothing signed");
  }
  assert.equal(ui.approvals.at(-1).kind, "rescue");

  // Typed with spaces around and in capitals, it is read as the address.
  typed.destination = `  ${DESTINATION.toUpperCase().replace("0X", "0x")} `;
  const ok = await ask(rescue({}, 11));
  assert.equal(toHex(verify(ok.result.envelope).to), DESTINATION);
});
