// The pop-up wallet's logic (wallet/src/wallet.mjs) on the built module,
// with stand-ins for IndexedDB, the screens, passkeys and the opener: the
// backup check before use, the encrypted vault, the password and passkey
// unlock, the account and signatures against the module's own, the issued
// receive addresses and signing from them, reject, origin checks, and every
// refusal before any screen.

import assert from "node:assert/strict";
import { test } from "node:test";

import { fromHex, toHex } from "../../webapp/src/bytes.mjs";
import { PBKDF2_ITERATIONS, checkRequest, createWallet, formatGhost, vaultStore } from "../src/wallet.mjs";
import {
  PASSWORD,
  fakeIndexedDB,
  fakePasskeys,
  loadTestGhost,
  scriptedUi,
  settle,
  spyGhost,
  spySubtle,
  testRandom,
  until,
} from "./fakes.mjs";

const APP = "https://app.example";
const ghost = await loadTestGhost();
const encoder = new TextEncoder();

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
const SIGN = { id: 2, method: "ghost_signTransaction", params: PARAMS };
const ACCOUNT = { id: 1, method: "ghost_getAccount" };
const RECEIVE = { id: 4, method: "ghost_newReceiveAddress" };
const signFrom = (from, id = 2) => ({ id, method: "ghost_signTransaction", params: { ...PARAMS, from } });

// A wallet with fresh stand-ins; `ask(message)` posts it as the opener on
// APP and resolves with the reply.
function setUp({ ui = scriptedUi(), credentials = null, idb = fakeIndexedDB() } = {}) {
  const random = testRandom();
  const spy = spyGhost(ghost);
  const subtle = spySubtle();
  const opener = {
    sent: [],
    postMessage(data, origin) {
      opener.sent.push({ data: structuredClone(data), origin });
    },
  };
  const wallet = createWallet({ ghost: spy, store: vaultStore(idb), ui, subtle, credentials, random, origins: [APP], opener });
  async function ask(data, { origin = APP, source = opener } = {}) {
    const before = opener.sent.length;
    wallet.onMessage({ data, origin, source });
    await until(() => opener.sent.length > before);
    const reply = opener.sent.at(-1);
    assert.equal(reply.origin, APP, "the reply goes to the web app's origin only");
    return reply.data;
  }
  return { wallet, ask, opener, ui, idb, random, spy, subtle };
}

// Every string and byte array inside a stored value.
function leaves(value, strings = [], bytes = []) {
  if (typeof value === "string") strings.push(value);
  else if (value instanceof Uint8Array) bytes.push(value);
  else if (value && typeof value === "object") for (const v of Object.values(value)) leaves(v, strings, bytes);
  return { strings, bytes };
}

function contains(haystack, needle) {
  outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (haystack[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

test("create: the 24 words, then three typed back, before the wallet is stored or used", async () => {
  let checks = 0;
  const ui = scriptedUi({
    // The first check is wrong; the second right.
    checkWords: (positions, u) => (++checks === 1 ? ["wrong", "words", "here"] : positions.map((p) => u.words[p - 1])),
  });
  const { ask, idb, random } = setUp({ ui });
  const reply = await ask(ACCOUNT);
  assert.deepEqual(ui.log.slice(0, 6), ["start", "showWords", "checkWords", "error", "showWords", "checkWords"]);
  assert.match(ui.errors[0], /do not match/);
  // Nothing was stored, locked or approved until the check matched.
  assert.ok(ui.log.indexOf("chooseLock") > 5);
  assert.ok(ui.log.indexOf("approve") > ui.log.indexOf("chooseLock"));
  // The vault and the "accounts" record.
  assert.equal(idb.data.size, 2);

  // The words come from the 32 random bytes through the module.
  const words = ghost.walletNew(random.log[0]);
  assert.equal(ui.words.join(" "), words);
  assert.equal(ui.words.length, 24);
  // The account is the module's account 0 of those words.
  const expected = ghost.walletRescueAccount(words, 0);
  assert.deepEqual(reply, {
    id: 1,
    result: { address: toHex(expected.address), publicKey: toHex(expected.publicKey), scheme: "0x0003", rescueKey: true },
  });
  assert.equal(ui.approvals[0].kind, "connect");
  assert.equal(ui.approvals[0].origin, APP);
});

test("closing before the backup check stores nothing", async () => {
  const ui = scriptedUi({ checkWords: () => new Promise(() => {}) });
  const { wallet, opener, idb } = setUp({ ui });
  wallet.onMessage({ data: ACCOUNT, origin: APP, source: opener });
  await until(() => ui.log.includes("checkWords"), "check screen");
  await settle();
  assert.equal(idb.data.size, 0, "no vault until the check matches");
  assert.equal(opener.sent.length, 0);
  assert.ok(!ui.log.includes("approve"));
});

test("the vault holds only ciphertext, salt and parameters: no seed, words or key bytes", async () => {
  const { ask, idb, random } = setUp();
  const { result } = await ask(ACCOUNT);
  const record = idb.data.get("vault");
  assert.deepEqual(Object.keys(record).sort(), ["ciphertext", "iterations", "iv", "kind", "salt", "version"]);
  assert.equal(record.kind, "password");
  assert.ok(record.iterations >= 600_000);
  assert.equal(record.iterations, PBKDF2_ITERATIONS);
  assert.equal(record.salt.length, 16);
  assert.equal(record.iv.length, 12);
  // AES-GCM: the words' length plus a 16-byte tag.
  const words = ghost.walletNew(random.log[0]);
  assert.equal(record.ciphertext.length, encoder.encode(words).length + 16);

  const { strings, bytes } = leaves(record);
  assert.deepEqual(strings, ["password"]);
  const secrets = [
    random.log[0],
    encoder.encode(words),
    ...words.split(" ").map((w) => encoder.encode(` ${w} `)),
    encoder.encode(PASSWORD),
    fromHex(result.address),
    fromHex(result.publicKey).slice(0, 32),
  ];
  for (const b of bytes) for (const s of secrets) assert.ok(!contains(b, s), "a stored byte array holds a secret");
  // The vault is written once: a second wallet is never written over it.
  await assert.rejects(vaultStore(idb).add({ version: 1 }), /taken/);
});

test("a wrong password does not unlock; nothing is signed until the right one", async () => {
  const passwords = ["not the password", "also wrong", PASSWORD];
  const { ask, ui, spy } = setUp({ ui: scriptedUi() });
  await ask(ACCOUNT);
  ui.approve = async (summary) => {
    ui.log.push("approve");
    ui.approvals.push(summary);
    return { password: passwords.shift() };
  };
  const reply = await ask(SIGN);
  assert.deepEqual(ui.errors, ["Wrong password.", "Wrong password."]);
  assert.equal(spy.calls.filter((c) => c === "ghost_wallet_sign_rescue_key").length, 1, "signed once, after the right password");
  assert.ok(reply.result.envelope);

  // A wrong password then Reject: code 4001 and no signature.
  const again = setUp();
  await again.ask(ACCOUNT);
  let tries = 0;
  again.ui.approve = async () => (++tries === 1 ? { password: "wrong password!" } : null);
  const rejected = await again.ask(SIGN);
  assert.equal(rejected.error.code, 4001);
  assert.equal(rejected.result, undefined);
  assert.ok(!again.spy.calls.includes("ghost_wallet_sign_rescue_key"));
});

test("an approved signature is the module's for the same words, fields and randomness, and verifies", async () => {
  const { ask, ui, random, subtle } = setUp();
  const account = (await ask(ACCOUNT)).result;
  const reply = await ask(SIGN);
  assert.equal(reply.id, 2);

  // The approval screen showed the amount, the maximum fee, the full
  // destination and the chain id.
  const summary = ui.approvals.at(-1);
  assert.deepEqual(summary, {
    kind: "sign",
    origin: APP,
    from: account.address,
    scheme: "0x0003",
    rescueKey: true,
    amount: "1",
    maxFee: formatGhost(0x1df78n * 0xb2d05e00n),
    to: PARAMS.to,
    chainId: "7777001",
    dataBytes: 3,
  });
  assert.equal(summary.maxFee, "0.000368232");

  const words = ghost.walletNew(random.log[0]);
  const fields = checkRequest(SIGN).fields;
  const randomness = random.log.at(-1);
  assert.equal(randomness.length, 32);
  const expected = ghost.walletSignRescueKey({ words, index: 0, ...fields, seed: randomness });
  assert.deepEqual(reply.result, {
    sender: toHex(expected.sender),
    txHash: toHex(expected.txHash),
    envelope: toHex(expected.envelope),
    scheme: "0x0003",
  });
  assert.equal(reply.result.sender, account.address);

  const verified = ghost.accountTxVerify({ chainId: 7777001n, genesis: fields.genesis, envelope: fromHex(reply.result.envelope) });
  assert.equal(toHex(verified.sender), account.address);
  assert.equal(toHex(verified.txHash), reply.result.txHash);
  assert.equal(toHex(verified.to), PARAMS.to);
  assert.equal(verified.value, 10n ** 18n);
  assert.equal(verified.nonce, 3n);
  assert.deepEqual([...verified.data], [0x00, 0x02, 0xab]);

  // Every decrypted buffer was overwritten with zeros once used.
  assert.ok(subtle.decrypted.length >= 2);
  for (const buffer of subtle.decrypted) assert.ok(new Uint8Array(buffer).every((b) => b === 0));
});

test("Reject signs nothing and answers 4001", async () => {
  const { ask, ui, spy } = setUp();
  await ask(ACCOUNT);
  ui.approve = async () => null;
  const reply = await ask(SIGN);
  assert.deepEqual(reply.error.code, 4001);
  assert.equal(reply.id, 2);
  assert.ok(!spy.calls.includes("ghost_wallet_sign_rescue_key"));
  // Rejecting the connection gives no account either.
  const fresh = setUp({ ui: scriptedUi({ approve: () => null }) });
  const connect = await fresh.ask(ACCOUNT);
  assert.equal(connect.error.code, 4001);
  assert.equal(connect.result, undefined);
});

test("messages from another origin, or not from the opener, are ignored", async () => {
  const { wallet, opener, ui, spy } = setUp();
  wallet.onMessage({ data: ACCOUNT, origin: "https://evil.example", source: opener });
  wallet.onMessage({ data: ACCOUNT, origin: `${APP}.evil.example`, source: opener });
  wallet.onMessage({ data: ACCOUNT, origin: "null", source: opener });
  wallet.onMessage({ data: ACCOUNT, origin: APP, source: { postMessage: () => assert.fail("answered a stranger") } });
  wallet.onMessage({ data: ACCOUNT, origin: APP, source: null });
  await settle();
  assert.equal(opener.sent.length, 0);
  assert.deepEqual(ui.log, []);
  assert.deepEqual(spy.calls, []);

  // The ready message goes to the configured origins only.
  wallet.announce();
  assert.deepEqual(opener.sent, [{ data: { ready: true }, origin: APP }]);

  // A wallet with no opener answers nothing.
  const lone = createWallet({ ghost, store: vaultStore(fakeIndexedDB()), ui: scriptedUi(), subtle: null, credentials: null, random: testRandom(), origins: [APP], opener: null });
  lone.onMessage({ data: ACCOUNT, origin: APP, source: null });
  await settle();
});

test("every malformed request is refused, naming the field, before any screen", async () => {
  const sign = (params) => ({ id: 7, method: "ghost_signTransaction", params });
  const without = (name) => {
    const p = { ...PARAMS };
    delete p[name];
    return p;
  };
  const cases = [
    [{ id: 7, method: "eth_sign", params: PARAMS }, -32601, /unknown method eth_sign/],
    [{ id: 7, method: "ghost_getAccount", params: {} }, -32602, /unknown field params/],
    [{ id: 7, method: "ghost_getAccount", extra: 1 }, -32602, /unknown field extra/],
    [{ method: "ghost_getAccount" }, -32602, /^id /],
    [{ id: "7", method: "ghost_getAccount" }, -32602, /^id /],
    ["ghost_getAccount", -32602, /not an object/],
    [{ id: 7, method: "ghost_signTransaction" }, -32602, /missing field params/],
    [sign(null), -32602, /params is not an object/],
    [{ id: 7, method: "ghost_newReceiveAddress", params: {} }, -32602, /unknown field params/],
    [{ id: 7, method: "ghost_newReceiveAddress", extra: 1 }, -32602, /unknown field extra/],
    [{ method: "ghost_newReceiveAddress" }, -32602, /^id /],
    [sign({ ...PARAMS, sender: PARAMS.to }), -32602, /unknown field sender/],
    [sign({ ...PARAMS, from: null }), -32602, /from is not 20 bytes of 0x hex/],
    [sign({ ...PARAMS, from: "0x12" }), -32602, /from is not 20 bytes of 0x hex/],
    [sign({ ...PARAMS, from: `0x${"11".repeat(32)}` }), -32602, /from is not 20 bytes of 0x hex/],
    [sign({ ...PARAMS, chainId: "0x1" }), -32602, /chainId 1 is not a network/],
    [sign({ ...PARAMS, chainId: "0x76aae8" }), -32602, /chainId 7777000 is not a network/],
    [sign({ ...PARAMS, chainId: 7777001 }), -32602, /chainId is not a 0x quantity/],
    [sign({ ...PARAMS, to: null }), -32602, /to is not 20 bytes/],
    [sign({ ...PARAMS, to: "0x" }), -32602, /to is not 20 bytes/],
    [sign({ ...PARAMS, to: `0x${"11".repeat(19)}` }), -32602, /to is not 20 bytes/],
    [sign({ ...PARAMS, to: `0x${"11".repeat(32)}` }), -32602, /to is not 20 bytes/],
    [sign({ ...PARAMS, genesisHash: "0x12" }), -32602, /genesisHash is not 32 bytes/],
    [sign({ ...PARAMS, nonce: "0x03" }), -32602, /nonce is not a 0x quantity/],
    [sign({ ...PARAMS, nonce: "3" }), -32602, /nonce is not a 0x quantity/],
    [sign({ ...PARAMS, nonce: `0x1${"0".repeat(16)}` }), -32602, /nonce is too large/],
    [sign({ ...PARAMS, gasLimit: "0x" }), -32602, /gasLimit is not a 0x quantity/],
    [sign({ ...PARAMS, value: "-0x1" }), -32602, /value is not a 0x quantity/],
    [sign({ ...PARAMS, data: "0x0" }), -32602, /data is not 0x hex bytes/],
    [sign({ ...PARAMS, data: "zz" }), -32602, /data is not 0x hex bytes/],
    [sign({ ...PARAMS, maxPriorityFeePerGas: "0xb2d05e01" }), -32602, /maxPriorityFeePerGas is above maxFeePerGas/],
  ];
  for (const name of Object.keys(PARAMS)) cases.push([sign(without(name)), -32602, new RegExp(`missing field ${name}`)]);

  for (const withVault of [false, true]) {
    const { ask, ui, spy } = setUp();
    if (withVault) await ask(ACCOUNT);
    const shown = ui.log.length;
    const signs = spy.calls.length;
    for (const [message, code, said] of cases) {
      const reply = await ask(message);
      assert.equal(reply.error?.code, code, JSON.stringify(message));
      assert.match(reply.error.message, said, JSON.stringify(message));
      assert.equal(reply.result, undefined);
    }
    assert.equal(ui.log.length, shown, "no screen was shown for a refused request");
    assert.equal(spy.calls.length, signs, "the module was not called");
  }
  // The well-formed request still passes the same check.
  assert.equal(checkRequest(SIGN).fields.chainId, 7777001n);
  assert.equal(checkRequest({ ...SIGN, params: { ...PARAMS, maxPriorityFeePerGas: PARAMS.maxFeePerGas } }).id, 2);
});

test("ghost_newReceiveAddress answers the next account address and asks for approval", async () => {
  const { ask, ui, idb, random } = setUp();
  const account = (await ask(ACCOUNT)).result;
  const words = ghost.walletNew(random.log[0]);

  // Only { id, method }: anything more is refused before any screen.
  const shown = ui.log.length;
  for (const [message, said] of [
    [{ ...RECEIVE, params: {} }, /unknown field params/],
    [{ ...RECEIVE, params: [] }, /unknown field params/],
    [{ ...RECEIVE, extra: 1 }, /unknown field extra/],
    [{ method: RECEIVE.method }, /^id /],
  ]) {
    const reply = await ask(message);
    assert.equal(reply.error?.code, -32602, JSON.stringify(message));
    assert.match(reply.error.message, said);
    assert.equal(reply.result, undefined);
  }
  assert.equal(ui.log.length, shown, "no screen for a refused request");
  assert.ok(!idb.data.has("issued"));

  const first = await ask(RECEIVE);
  assert.deepEqual(ui.log.slice(shown), ["approve"]);
  assert.deepEqual(ui.approvals.at(-1), { kind: "receive", origin: APP });
  const one = ghost.walletRescueAccount(words, 1);
  assert.deepEqual(first, {
    id: 4,
    result: { address: toHex(one.address), publicKey: toHex(one.publicKey), scheme: "0x0003", rescueKey: true },
  });
  assert.deepEqual(idb.data.get("issued"), { count: 1 });

  const second = await ask({ ...RECEIVE, id: 5 });
  assert.deepEqual(ui.log.slice(shown), ["approve", "approve"]);
  const two = ghost.walletRescueAccount(words, 2);
  assert.deepEqual(second, {
    id: 5,
    result: { address: toHex(two.address), publicKey: toHex(two.publicKey), scheme: "0x0003", rescueKey: true },
  });
  assert.deepEqual(idb.data.get("issued"), { count: 2 });

  assert.equal(new Set([account.address, first.result.address, second.result.address]).size, 3);
  assert.equal(new Set([account.publicKey, first.result.publicKey, second.result.publicKey]).size, 3);
  // The record holds the count and nothing else.
  assert.deepEqual(Object.keys(idb.data.get("issued")), ["count"]);
  // The vault was not written over.
  assert.deepEqual(Object.keys(idb.data.get("vault")).sort(), ["ciphertext", "iterations", "iv", "kind", "salt", "version"]);
});

test("the issued counter survives a reload and never repeats an address", async () => {
  const before = setUp();
  const seen = [(await before.ask(ACCOUNT)).result.address];
  seen.push((await before.ask(RECEIVE)).result.address);
  seen.push((await before.ask({ ...RECEIVE, id: 5 })).result.address);
  const words = ghost.walletNew(before.random.log[0]);

  // A new window over the same IndexedDB: the same vault, no setup.
  const after = setUp({ idb: before.idb });
  assert.equal(await vaultStore(before.idb).getIssued(), 2);
  const third = await after.ask(RECEIVE);
  assert.deepEqual(after.ui.log, ["approve"]);
  const three = ghost.walletRescueAccount(words, 3);
  assert.equal(third.result.address, toHex(three.address));
  assert.equal(third.result.publicKey, toHex(three.publicKey));
  assert.ok(!seen.includes(third.result.address), "an address handed out again");
  assert.deepEqual(before.idb.data.get("issued"), { count: 3 });

  // Public data only: one whole number, no string or byte array.
  const record = before.idb.data.get("issued");
  assert.deepEqual(Object.keys(record), ["count"]);
  assert.ok(Number.isSafeInteger(record.count));
  const { strings, bytes } = leaves(record);
  assert.deepEqual(strings, []);
  assert.deepEqual(bytes, []);
  const text = JSON.stringify(record);
  for (const w of words.split(" ")) assert.ok(!text.includes(w), "the record holds a word");
});

test("signing from an issued address names it on the approval screen and verifies", async () => {
  const { ask, ui, idb, random } = setUp();
  const account = (await ask(ACCOUNT)).result;
  const issued = (await ask(RECEIVE)).result;
  const words = ghost.walletNew(random.log[0]);
  const fields = checkRequest(SIGN).fields;

  const reply = await ask(signFrom(issued.address));
  const summary = ui.approvals.at(-1);
  assert.equal(summary.kind, "sign");
  assert.equal(summary.from, issued.address);
  assert.equal(summary.to, PARAMS.to);
  const expected = ghost.walletSignRescueKey({ words, index: 1, ...fields, seed: random.log.at(-1) });
  assert.deepEqual(reply.result, {
    sender: toHex(expected.sender),
    txHash: toHex(expected.txHash),
    envelope: toHex(expected.envelope),
    scheme: "0x0003",
  });
  const verified = ghost.accountTxVerify({ chainId: 7777001n, genesis: fields.genesis, envelope: fromHex(reply.result.envelope) });
  assert.equal(toHex(verified.sender), issued.address);
  assert.equal(reply.result.sender, issued.address);
  assert.notEqual(reply.result.sender, account.address);
  assert.equal(toHex(verified.txHash), reply.result.txHash);

  // `from` set to account 0 signs for it.
  const zero = await ask(signFrom(account.address, 3));
  assert.equal(ui.approvals.at(-1).from, account.address);
  assert.equal(zero.result.sender, account.address);

  // No `from`: account 0, named on the screen.
  const plain = await ask(SIGN);
  assert.equal(ui.approvals.at(-1).from, account.address);
  assert.equal(plain.result.sender, account.address);
  const plainVerified = ghost.accountTxVerify({ chainId: 7777001n, genesis: fields.genesis, envelope: fromHex(plain.result.envelope) });
  assert.equal(toHex(plainVerified.sender), account.address);

  // After a reload the issued address still signs; it is checked once unlocked.
  const after = setUp({ idb });
  const again = await after.ask(signFrom(issued.address));
  assert.equal(after.ui.approvals[0].from, issued.address);
  assert.equal(again.result.sender, issued.address);
});

test("signing from an address the wallet never issued is refused", async () => {
  const { ask, ui, idb, spy, random } = setUp();
  await ask(ACCOUNT);
  await ask(RECEIVE);
  await ask({ ...RECEIVE, id: 5 });
  const words = ghost.walletNew(random.log[0]);
  const five = toHex(ghost.walletRescueAccount(words, 5).address);
  const three = toHex(ghost.walletRescueAccount(words, 3).address);

  const shown = ui.log.length;
  const calls = spy.calls.length;
  for (const from of [five, three, PARAMS.to]) {
    const reply = await ask(signFrom(from, 9));
    assert.equal(reply.id, 9);
    assert.equal(reply.error?.code, -32602);
    assert.match(reply.error.message, /^from is not an address this wallet issued/);
    assert.equal(reply.result, undefined);
  }
  assert.equal(ui.log.length, shown, "no approval screen");
  assert.equal(spy.calls.length, calls, "the module was not called");
  assert.deepEqual(idb.data.get("issued"), { count: 2 });

  // In a new window the addresses are not known before the unlock: the
  // address is checked then, and still nothing is signed.
  const after = setUp({ idb });
  const reply = await after.ask(signFrom(five));
  assert.equal(reply.error?.code, -32602);
  assert.match(reply.error.message, /^from is not an address this wallet issued/);
  assert.ok(!after.spy.calls.includes("ghost_wallet_sign_rescue_key"));
  // Known now: refused before any screen.
  const shownAfter = after.ui.log.length;
  assert.equal((await after.ask(signFrom(five, 3))).error?.code, -32602);
  assert.equal(after.ui.log.length, shownAfter);
});

test("rejecting ghost_newReceiveAddress answers 4001 and issues nothing", async () => {
  const { ask, ui, idb, random } = setUp();
  await ask(ACCOUNT);
  const words = ghost.walletNew(random.log[0]);
  ui.approve = async (summary) => {
    ui.log.push("approve");
    ui.approvals.push(summary);
    return null;
  };
  const reply = await ask(RECEIVE);
  assert.equal(reply.id, 4);
  assert.equal(reply.error?.code, 4001);
  assert.equal(reply.result, undefined);
  assert.equal(ui.approvals.at(-1).kind, "receive");
  assert.ok(!idb.data.has("issued"));
  assert.equal(await vaultStore(idb).getIssued(), 0);

  // The next approved ask still gets account 1.
  ui.approve = async (summary) => {
    ui.approvals.push(summary);
    return { password: PASSWORD };
  };
  const next = await ask({ ...RECEIVE, id: 5 });
  assert.equal(next.result.address, toHex(ghost.walletRescueAccount(words, 1).address));
  assert.deepEqual(idb.data.get("issued"), { count: 1 });
});

test("restore from the 24 words gives the same account; words that fail the check are refused", async () => {
  const words = ghost.walletNew(Uint8Array.from({ length: 32 }, (_, i) => 200 - i));
  const typed = [`  ${words.toUpperCase().split(" ").join("   ")} `, words];
  const swapped = words.split(" ");
  [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
  const answers = ["just a few words", swapped.join(" "), ...typed];
  const ui = scriptedUi({ start: () => "restore", restoreWords: () => answers.shift() });
  const { ask } = setUp({ ui });
  const reply = await ask(ACCOUNT);
  assert.equal(ui.errors.length, 2);
  for (const e of ui.errors) assert.match(e, /not the 24 words/);
  assert.ok(!ui.log.includes("showWords"), "restored words are not shown");
  const expected = ghost.walletRescueAccount(words, 0);
  assert.equal(reply.result.address, toHex(expected.address));
  assert.equal(reply.result.publicKey, toHex(expected.publicKey));
});

test("a passkey's PRF output protects the vault through HKDF; another passkey secret does not unlock", async () => {
  const passkeys = fakePasskeys();
  const ui = scriptedUi({ chooseLock: (passkey) => (assert.equal(passkey, true), { kind: "passkey" }), approve: () => ({}) });
  const { ask, idb, random, spy } = setUp({ ui, credentials: passkeys });
  const account = (await ask(ACCOUNT)).result;
  assert.deepEqual(passkeys.calls, ["create", "get", "get"]);
  const record = idb.data.get("vault");
  assert.deepEqual(Object.keys(record).sort(), ["ciphertext", "credentialId", "iv", "kind", "salt", "version"]);
  assert.equal(record.kind, "passkey");
  const words = ghost.walletNew(random.log[0]);
  assert.equal(account.address, toHex(ghost.walletRescueAccount(words, 0).address));
  const signed = await ask(SIGN);
  assert.equal(signed.result.sender, account.address);

  // The authenticator now answers another secret: the vault stays shut.
  passkeys.secret.fill(8);
  let tries = 0;
  ui.approve = async () => (++tries === 1 ? {} : null);
  const before = spy.calls.filter((c) => c === "ghost_wallet_sign_rescue_key").length;
  const reply = await ask({ ...SIGN, id: 3 });
  assert.equal(reply.error.code, 4001);
  assert.match(ui.errors.at(-1), /passkey did not unlock/);
  assert.equal(spy.calls.filter((c) => c === "ghost_wallet_sign_rescue_key").length, before);

  // An authenticator without PRF cannot protect a wallet; a password then can.
  const locks = [{ kind: "passkey" }, { kind: "password", password: PASSWORD, again: PASSWORD }];
  const plain = setUp({ ui: scriptedUi({ chooseLock: () => locks.shift() }), credentials: fakePasskeys({ prf: false }) });
  assert.ok((await plain.ask(ACCOUNT)).result.address);
  assert.match(plain.ui.errors[0], /cannot protect a wallet/);
  assert.equal(plain.idb.data.get("vault").kind, "password");
});

test("a short or mistyped password is refused when the wallet is protected", async () => {
  const locks = [
    { kind: "password", password: "short", again: "short" },
    { kind: "password", password: PASSWORD, again: `${PASSWORD}!` },
    { kind: "passkey" },
    { kind: "password", password: PASSWORD, again: PASSWORD },
  ];
  const { ask, ui } = setUp({ ui: scriptedUi({ chooseLock: () => locks.shift() }) });
  assert.ok((await ask(ACCOUNT)).result);
  assert.match(ui.errors[0], /12 characters or more/);
  assert.match(ui.errors[1], /differ/);
  assert.match(ui.errors[2], /12 characters or more/, "no passkey without WebAuthn");
});
