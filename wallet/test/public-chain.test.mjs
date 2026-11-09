// The pop-up wallet on the public test network, chain 6777972, the one the
// hosted web app runs on (webapp/src/rpc.mjs PUBLIC_CHAIN_ID, header.mjs
// NETWORKS): every per-chain table of the wallet covers it, it signs a
// Vanish-shaped ghost_signTransaction there (and still on 7777001), its
// rescue and receive-address paths work there, a request refused at its
// first check says so on the status line, and the web app's own connector
// gets a signature on the public chain id from the real wallet logic.

import assert from "node:assert/strict";
import { test } from "node:test";

import { concat, fromHex, toHex, toQuantity } from "../../webapp/src/bytes.mjs";
import { COMMIT_DATA_BYTES, COMMIT_DATA_VERSION, DEFAULT_COMMIT_ENTRY } from "../../webapp/src/flow.mjs";
import { NETWORKS } from "../../webapp/src/header.mjs";
import { popupConnector } from "../../webapp/src/popup-wallet.mjs";
import { PUBLIC_CHAIN_ID } from "../../webapp/src/rpc.mjs";
import { CHAIN_IDS, COMMIT_ENTRIES, GUARD_POLICIES } from "../src/config.mjs";
import { TRUSTED_GUARD, checkRequest, createWallet, vaultStore } from "../src/wallet.mjs";
import { buildModuleIfMissing, wasmPath } from "../../webapp/test/support/env.mjs";
import { PASSWORD, fakeIndexedDB, loadTestGhost, scriptedUi, settle, spyGhost, spySubtle, testRandom, until } from "./fakes.mjs";

// The module is built as webapp/README.md's "Test it" builds it, when no
// build is there yet, with the toolchain CI pins.
buildModuleIfMissing(wasmPath);

const APP = "https://app.example";
const WALLET = "https://wallet.example";
const ghost = await loadTestGhost();

const PUBLIC = 6_777_972n;
const INTERNAL = 7_777_001n;
// ghost-node params/ghost/privaccounts.go, CommitEntryAddress: one constant
// for every network ("ghost" in ASCII, then 5).
const GHOST_NODE_COMMIT_ENTRY = "0x67686f7374000000000000000000000000000005";
const PUBLIC_GENESIS = NETWORKS[String(PUBLIC)].genesisHash;
const DESTINATION = `0x${"5a".repeat(20)}`;
const REFUSED = "This request was refused. Nothing was signed.";
const WAITING = "Waiting for the Ghost app.";
const SIGN_CALLS = ["ghost_wallet_sign", "ghost_wallet_sign_rescue_key", "ghost_wallet_sign_rescue"];

// The data of a Vanish commit as the web app builds it: version 3, then the
// commitment, salt and note (COMMIT_DATA_BYTES in all).
const VANISH_DATA = concat([COMMIT_DATA_VERSION, Uint8Array.from({ length: COMMIT_DATA_BYTES - 2 }, (_, i) => (i * 7 + 3) & 0xff)]);

// A Vanish as the web app asks the wallet to sign it: to the commit entry,
// the amount, the commit data, on `chainId` with that network's genesis.
const vanish = (chainId = PUBLIC, genesisHash = PUBLIC_GENESIS, id = 2) => ({
  id,
  method: "ghost_signTransaction",
  params: {
    chainId: toQuantity(chainId),
    genesisHash,
    nonce: "0x0",
    maxPriorityFeePerGas: "0x77359400",
    maxFeePerGas: "0xb2d05e00",
    gasLimit: "0x2e7c8",
    to: DEFAULT_COMMIT_ENTRY,
    value: "0xde0b6b3a7640000",
    data: toHex(VANISH_DATA),
  },
});

const rescue = (chainId = PUBLIC, id = 6) => ({
  id,
  method: "ghost_rescue",
  params: {
    chainId: toQuantity(chainId),
    genesisHash: PUBLIC_GENESIS,
    nonce: "0x0",
    maxPriorityFeePerGas: "0x3b9aca00",
    maxFeePerGas: "0xb2d05e00",
    gasLimit: "0x3d090",
    balance: "0x1bc16d674ec80000",
  },
});

const ACCOUNT = { id: 1, method: "ghost_getAccount" };
const RECEIVE = { id: 4, method: "ghost_newReceiveAddress" };

function setUp() {
  const random = testRandom();
  const spy = spyGhost(ghost);
  const ui = scriptedUi({ approve: () => ({ password: PASSWORD, destination: DESTINATION }) });
  const opener = {
    sent: [],
    postMessage(data, origin) {
      opener.sent.push({ data: structuredClone(data), origin });
    },
  };
  const wallet = createWallet({ ghost: spy, store: vaultStore(fakeIndexedDB()), ui, subtle: spySubtle(), credentials: null, random, origins: [APP], opener });
  async function ask(data) {
    const before = opener.sent.length;
    wallet.onMessage({ data, origin: APP, source: opener });
    await until(() => opener.sent.length > before);
    return opener.sent.at(-1).data;
  }
  const signs = () => spy.calls.filter((c) => SIGN_CALLS.includes(c));
  return { wallet, ask, ui, spy, signs, random, words: () => ghost.walletNew(random.log[0]) };
}

test("every per-chain table of the wallet covers the web app's public test network, and still the internal one", () => {
  assert.equal(PUBLIC_CHAIN_ID, PUBLIC, "the web app's public chain id");
  assert.ok(Object.isFrozen(CHAIN_IDS));
  assert.ok(CHAIN_IDS.includes(PUBLIC), "the wallet signs on 6777972");
  assert.ok(CHAIN_IDS.includes(INTERNAL), "the wallet still signs on 7777001");
  assert.ok(CHAIN_IDS.includes(PUBLIC_CHAIN_ID), "the chain public nodes must answer is one the wallet signs for");
  // Every network the web app knows is one the wallet signs for and has a
  // commit entry for: a chain-list mismatch fails here.
  for (const chainId of Object.keys(NETWORKS)) {
    assert.ok(CHAIN_IDS.includes(BigInt(chainId)), `the wallet signs for the web app's network ${chainId}`);
    assert.ok(Object.hasOwn(COMMIT_ENTRIES, chainId), `the wallet has a commit entry for the web app's network ${chainId}`);
  }
  for (const chainId of CHAIN_IDS) assert.ok(Object.hasOwn(COMMIT_ENTRIES, String(chainId)), `a commit entry for ${chainId}`);
  assert.ok(Object.isFrozen(COMMIT_ENTRIES));
  assert.equal(COMMIT_ENTRIES[String(PUBLIC)], GHOST_NODE_COMMIT_ENTRY);
  assert.equal(COMMIT_ENTRIES[String(INTERNAL)], GHOST_NODE_COMMIT_ENTRY);
  // The web app sends a Vanish to its default commit entry: the wallet's
  // trusted entry for the public network is that same address.
  assert.equal(COMMIT_ENTRIES[String(PUBLIC_CHAIN_ID)], DEFAULT_COMMIT_ENTRY);
  assert.equal(TRUSTED_GUARD.commitEntries, COMMIT_ENTRIES);
  // No chain has a Guard policy yet.
  assert.deepEqual(GUARD_POLICIES, {});
});

test("the wallet signs a Vanish on chain 6777972 that the node verifier accepts there", async () => {
  const { ask, ui, signs, random, words } = setUp();
  const account = (await ask(ACCOUNT)).result;
  const reply = await ask(vanish());
  assert.equal(reply.error, undefined, JSON.stringify(reply.error));
  assert.equal(reply.id, 2);
  assert.equal(reply.result.sender, account.address);
  assert.deepEqual(signs(), ["ghost_wallet_sign_rescue_key"]);

  const summary = ui.approvals.at(-1);
  assert.equal(summary.kind, "sign");
  assert.equal(summary.chainId, "6777972");
  assert.equal(summary.to, DEFAULT_COMMIT_ENTRY);
  assert.equal(summary.dataBytes, COMMIT_DATA_BYTES);

  const fields = checkRequest(vanish()).fields;
  assert.equal(fields.chainId, PUBLIC);
  const expected = ghost.walletSignRescueKey({ words: words(), index: 0, ...fields, seed: random.log.at(-1) });
  assert.equal(reply.result.envelope, toHex(expected.envelope));

  const verified = ghost.accountTxVerify({ chainId: PUBLIC, genesis: fromHex(PUBLIC_GENESIS, 32), envelope: fromHex(reply.result.envelope) });
  assert.equal(toHex(verified.sender), account.address);
  assert.equal(toHex(verified.txHash), reply.result.txHash);
  assert.equal(toHex(verified.to), DEFAULT_COMMIT_ENTRY);
  assert.equal(verified.value, 10n ** 18n);
  assert.deepEqual(verified.data, VANISH_DATA);

  // The internal network still signs.
  const internal = await ask(vanish(INTERNAL, `0x${"ab".repeat(32)}`, 3));
  assert.equal(internal.error, undefined, JSON.stringify(internal.error));
  assert.equal(toHex(ghost.accountTxVerify({ chainId: INTERNAL, genesis: new Uint8Array(32).fill(0xab), envelope: fromHex(internal.result.envelope) }).sender), account.address);

  // A chain the wallet does not sign for is still refused before any screen.
  const shown = ui.log.length;
  const other = await ask(vanish(PUBLIC + 1n, PUBLIC_GENESIS, 5));
  assert.equal(other.error.code, -32602);
  assert.match(other.error.message, /chainId 6777973 is not a network this wallet signs for/);
  assert.equal(ui.log.length, shown);
  assert.equal(signs().length, 2);
});

test("rescue and receive addresses work on chain 6777972", async () => {
  const { ask, signs } = setUp();
  const account = (await ask(ACCOUNT)).result;
  const receive = await ask(RECEIVE);
  assert.match(receive.result.address, /^0x[0-9a-f]{40}$/);
  assert.notEqual(receive.result.address, account.address);

  // A Vanish from the issued receive address on the public network.
  const fromIssued = await ask({ ...vanish(PUBLIC, PUBLIC_GENESIS, 7), params: { ...vanish().params, from: receive.result.address } });
  assert.equal(fromIssued.error, undefined, JSON.stringify(fromIssued.error));
  const verifiedIssued = ghost.accountTxVerify({ chainId: PUBLIC, genesis: fromHex(PUBLIC_GENESIS, 32), envelope: fromHex(fromIssued.result.envelope) });
  assert.equal(toHex(verifiedIssued.sender), receive.result.address);

  const rescued = await ask(rescue());
  assert.equal(rescued.error, undefined, JSON.stringify(rescued.error));
  assert.equal(rescued.result.scheme, "0x0004");
  assert.equal(rescued.result.sender, account.address);
  assert.equal(signs().at(-1), "ghost_wallet_sign_rescue");
  const verified = ghost.accountTxVerify({ chainId: PUBLIC, genesis: fromHex(PUBLIC_GENESIS, 32), envelope: fromHex(rescued.result.envelope) });
  assert.equal(toHex(verified.sender), account.address);
  assert.equal(toHex(verified.to), DESTINATION);
  assert.equal(checkRequest(rescue()).fields.chainId, PUBLIC);
});

test("a Guard commit on chain 6777972 goes only to the wallet's trusted commit entry there", () => {
  const policy = { address: `0x${"47".repeat(20)}`, codehash: `0x${"5a".repeat(32)}` };
  // The wallet's own commit entries, with a test policy: no chain has one yet.
  const trust = { commitEntries: COMMIT_ENTRIES, policies: { [String(PUBLIC)]: policy } };
  const commit = (to) => ({
    id: 9,
    method: "ghost_guardCommit",
    params: {
      chainId: toQuantity(PUBLIC),
      genesisHash: PUBLIC_GENESIS,
      nonce: "0x0",
      maxPriorityFeePerGas: "0x3b9aca00",
      maxFeePerGas: "0xb2d05e00",
      gasLimit: "0x30d40",
      to,
      value: "0xe8d4a51000",
      filledLeaves: "0x64",
      leavesPerBlock: "0x40",
      baseFee: "0x3",
    },
  });
  const fields = checkRequest(commit(GHOST_NODE_COMMIT_ENTRY), trust).fields;
  assert.equal(fields.chainId, PUBLIC);
  assert.equal(toHex(fields.to), GHOST_NODE_COMMIT_ENTRY);
  assert.throws(() => checkRequest(commit(`0x${"66".repeat(20)}`), trust), /to is not the commit entry of chainId 6777972/);
  // With the wallet's own settings, the chain is known and has its commit
  // entry; only the Guard policy is missing, as on every chain.
  assert.throws(() => checkRequest(commit(GHOST_NODE_COMMIT_ENTRY)), /no trusted Guard policy for chainId 6777972/);
});

test("a request refused at its first check says so on the status line, not Waiting", async () => {
  const { wallet, ask, ui, signs } = setUp();
  wallet.announce();
  assert.equal(ui.statuses.at(-1), WAITING);
  const reply = await ask(vanish(1n, PUBLIC_GENESIS, 8));
  assert.equal(reply.error.code, -32602);
  assert.match(reply.error.message, /chainId 1 is not a network this wallet signs for/);
  assert.equal(ui.statuses.at(-1), REFUSED);
  assert.deepEqual(ui.log, [], "no screen was shown");
  assert.deepEqual(signs(), []);

  // A malformed request and an unknown method say the same.
  wallet.announce();
  await ask({ id: 9, method: "eth_sign" });
  assert.equal(ui.statuses.at(-1), REFUSED);
  wallet.announce();
  await ask("not a request");
  assert.equal(ui.statuses.at(-1), REFUSED);
});

// The web app's pop-up connector against the real wallet logic, with the
// browser's window.open and postMessage stood in, on the public chain id.
function fakePage() {
  const listeners = new Set();
  const spy = spyGhost(ghost);
  const ui = scriptedUi();
  const page = {
    popup: null,
    spy,
    ui,
    open() {
      const popup = {
        closed: false,
        close() {
          popup.closed = true;
        },
        postMessage(data, targetOrigin) {
          if (popup.closed || targetOrigin !== WALLET) return;
          const copy = structuredClone(data);
          setImmediate(() => wallet.onMessage({ data: copy, origin: APP, source: opener }));
        },
      };
      const opener = {
        postMessage(data, targetOrigin) {
          if (popup.closed || targetOrigin !== APP) return;
          const copy = structuredClone(data);
          setImmediate(() => listeners.forEach((h) => h({ data: copy, origin: WALLET, source: popup })));
        },
      };
      const wallet = createWallet({ ghost: spy, store: vaultStore(fakeIndexedDB()), ui, subtle: globalThis.crypto.subtle, credentials: null, random: testRandom(), origins: [APP], opener });
      page.popup = popup;
      setImmediate(() => wallet.announce());
      return popup;
    },
    addEventListener: (type, handler) => type === "message" && listeners.add(handler),
    removeEventListener: (type, handler) => listeners.delete(handler),
    setInterval: (fn, ms) => setInterval(fn, ms).unref(),
    clearInterval: (t) => clearInterval(t),
  };
  return page;
}

test("web app and wallet: a Vanish on the web app's public chain id is signed through the pop-up", async () => {
  const page = fakePage();
  const c = popupConnector({ win: page, origin: WALLET, pollMs: 5 });
  const { address } = await c.connect();
  const genesis = fromHex(NETWORKS[String(PUBLIC_CHAIN_ID)].genesisHash, 32);
  const fields = {
    chainId: PUBLIC_CHAIN_ID,
    genesis,
    nonce: 0n,
    maxPriorityFeePerGas: 2_000_000_000n,
    maxFeePerGas: 3_000_000_000n,
    gasLimit: 190_408n,
    to: fromHex(DEFAULT_COMMIT_ENTRY, 20),
    value: 10n ** 18n,
    data: VANISH_DATA,
  };
  const signed = await c.signTransaction(fields);
  assert.equal(toHex(signed.sender), address);
  assert.deepEqual(ghost.keccak256(signed.envelope), signed.txHash);
  const verified = ghost.accountTxVerify({ chainId: PUBLIC_CHAIN_ID, genesis, envelope: signed.envelope });
  assert.equal(toHex(verified.sender), address);
  assert.deepEqual(verified.to, fields.to);
  assert.deepEqual(verified.data, VANISH_DATA);
  assert.equal(page.ui.approvals.at(-1).chainId, String(PUBLIC_CHAIN_ID));
  assert.equal(page.ui.statuses.at(-1), "Done. Keep this window open for the app's next request, or close it.");

  // A chain the wallet does not sign for comes back as a refusal, and the
  // pop-up's status line says so.
  await assert.rejects(c.signTransaction({ ...fields, chainId: PUBLIC_CHAIN_ID + 1n }), /the wallet refused the transaction: chainId 6777973 is not a network/);
  await settle();
  assert.equal(page.ui.statuses.at(-1), REFUSED);
  c.disconnect();
});
