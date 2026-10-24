// The connected wallet: the Ghost Snap connector over an EIP-1193 provider
// (wallet-connect.mjs), driven against a stand-in MetaMask, then the flow
// controller with a connected wallet against the node stand-in. The
// stand-in MetaMask answers the Snap's two requests the way the Ghost Snap
// does, with the tests' account signing in the worker (support/env.mjs);
// the page side holds no seed and no key.

import assert from "node:assert/strict";
import test from "node:test";

import { fromHex, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow } from "../src/flow.mjs";
import {
  GHOST_SNAP,
  SNAP_WALLET,
  USER_REJECTED,
  WalletRejected,
  fieldsFromSnap,
  injectedProvider,
  snapConnector,
  snapTransaction,
} from "../src/wallet-connect.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, testAccount, testConnector, testSign } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
const SNAP_METHODS = new Set(["wallet_requestSnaps", "wallet_invokeSnap"]);

const rejection = () => Object.assign(new Error("User rejected the request."), { code: USER_REJECTED });

// A stand-in for MetaMask's window.ethereum with the Ghost Snap installed.
// Every request is logged. `account()` and `sign(params)` answer the Snap's
// two methods; `approve` false turns the next requests down as the user
// would; `snapInstalled` false answers wallet_requestSnaps without the Snap.
function fakeMetaMask({ account, sign, snapInstalled = true } = {}) {
  const provider = {
    isMetaMask: true,
    calls: [],
    approve: true,
    async request(args) {
      provider.calls.push(structuredClone(args));
      const { method, params } = args;
      if (method === "wallet_requestSnaps") {
        if (!provider.approve) throw rejection();
        return snapInstalled ? { [Object.keys(params)[0]]: { id: GHOST_SNAP, version: "0.1.0", enabled: true, blocked: false } } : {};
      }
      if (method === "wallet_invokeSnap") {
        assert.equal(params.snapId, GHOST_SNAP);
        if (!provider.approve) throw rejection();
        if (params.request.method === "ghost_getAccount") return account();
        if (params.request.method === "ghost_signTransaction") return sign(params.request.params);
        throw Object.assign(new Error("unknown method"), { code: -32601 });
      }
      throw Object.assign(new Error(`the stand-in has no ${method}`), { code: -32601 });
    },
  };
  return provider;
}

// The Ghost Snap's side of the protocol, with the tests' account: the
// account as { address, publicKey } and the signed transaction as 0x hex.
async function snapAccount() {
  const { address, publicKey } = await testAccount();
  return { address, publicKey: toHex(publicKey) };
}

async function snapSign(params) {
  const signed = await testSign(fieldsFromSnap(params));
  return { sender: toHex(signed.sender), txHash: toHex(signed.txHash), envelope: toHex(signed.envelope) };
}

const FIELDS = {
  chainId: 7_777_001n,
  genesis: Uint8Array.from({ length: 32 }, (_, i) => i),
  nonce: 3n,
  maxPriorityFeePerGas: 1_000_000_000n,
  maxFeePerGas: 3_000_000_000n,
  gasLimit: 122_744n,
  to: fromHex(DEFAULT_COMMIT_ENTRY, 20),
  value: GHOST,
  data: Uint8Array.of(0x00, 0x02, 0xab),
};

// --- The Snap connector against a stand-in MetaMask ---

test("connect installs the Ghost Snap and reads its account, asking nothing else", async () => {
  const address = "0x80992A5C983FC01CD9A0C16C4DFC47B9A750D022";
  const provider = fakeMetaMask({ account: () => ({ address, publicKey: "0x01" }) });
  const connector = snapConnector(provider);
  assert.equal(connector.id, SNAP_WALLET.id);
  assert.equal(connector.name, "MetaMask (Ghost Snap)");
  assert.equal(connector.available, true);
  assert.deepEqual(await connector.connect(), { address: address.toLowerCase() });
  assert.deepEqual(provider.calls, [
    { method: "wallet_requestSnaps", params: { "npm:@ghostcoin/ghost-snap": {} } },
    { method: "wallet_invokeSnap", params: { snapId: "npm:@ghostcoin/ghost-snap", request: { method: "ghost_getAccount" } } },
  ]);
  // Disconnecting asks the provider nothing.
  connector.disconnect();
  assert.equal(provider.calls.length, 2);
  await assert.rejects(connector.signTransaction(FIELDS), /connect the wallet first/);
  assert.equal(provider.calls.length, 2, "nothing is asked to sign once disconnected");
});

test("signTransaction sends every field as 0x hex and reads the answer as bytes", async () => {
  const answer = { sender: `0x${"11".repeat(20)}`, txHash: `0x${"22".repeat(32)}`, envelope: "0x52c0ffee" };
  let seen = null;
  const provider = fakeMetaMask({
    account: () => ({ address: `0x${"11".repeat(20)}` }),
    sign: (params) => {
      seen = params;
      return answer;
    },
  });
  const connector = snapConnector(provider);
  await connector.connect();
  const signed = await connector.signTransaction(FIELDS);
  assert.deepEqual(seen, {
    chainId: "0x76aae9",
    genesisHash: `0x${Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, "0")).join("")}`,
    nonce: "0x3",
    maxPriorityFeePerGas: "0x3b9aca00",
    maxFeePerGas: "0xb2d05e00",
    gasLimit: "0x1df78",
    to: DEFAULT_COMMIT_ENTRY,
    value: "0xde0b6b3a7640000",
    data: "0x0002ab",
  });
  assert.deepEqual(snapTransaction(FIELDS), seen);
  assert.deepEqual(fieldsFromSnap(seen), FIELDS, "the Snap reads back the fields the page signed");
  assert.equal(snapTransaction({ ...FIELDS, to: null }).to, null, "a contract creation has no to");
  assert.deepEqual(signed, { sender: fromHex(answer.sender), txHash: fromHex(answer.txHash), envelope: fromHex(answer.envelope) });
  assert.ok(signed.sender instanceof Uint8Array);
  for (const call of provider.calls) assert.ok(SNAP_METHODS.has(call.method), call.method);
  assert.deepEqual(provider.calls.at(-1).params.request.method, "ghost_signTransaction");
});

test("a rejection in the wallet is a clear error, at connect and at signing", async () => {
  const provider = fakeMetaMask({ account: () => ({ address: `0x${"11".repeat(20)}` }), sign: () => assert.fail("not signed") });
  provider.approve = false;
  const connector = snapConnector(provider);
  await assert.rejects(connector.connect(), (err) => err instanceof WalletRejected && /rejected in your wallet/.test(err.message));
  provider.approve = true;
  await connector.connect();
  provider.approve = false;
  await assert.rejects(connector.signTransaction(FIELDS), (err) => {
    assert.ok(err instanceof WalletRejected);
    assert.match(err.message, /^the transaction was rejected in your wallet; nothing was sent$/);
    return true;
  });
});

test("answers that are not what the Snap gives are refused", async () => {
  // No Snap installed.
  await assert.rejects(snapConnector(fakeMetaMask({ snapInstalled: false })).connect(), /did not install the Ghost Snap/);
  // No address, or not 20 bytes.
  for (const account of [{}, { address: "0x1234" }, { address: `0x${"zz".repeat(20)}` }, null]) {
    await assert.rejects(snapConnector(fakeMetaMask({ account: () => account })).connect(), /without a Ghost account address/);
  }
  // A signed answer that is not 0x hex of the right lengths.
  const good = { sender: `0x${"11".repeat(20)}`, txHash: `0x${"22".repeat(32)}`, envelope: "0x52" };
  for (const bad of [null, { ...good, sender: "0x11" }, { ...good, txHash: "22".repeat(32) }, { ...good, envelope: "0x" }, { ...good, envelope: "0xz" }]) {
    const connector = snapConnector(fakeMetaMask({ account: () => ({ address: `0x${"11".repeat(20)}` }), sign: () => bad }));
    await connector.connect();
    await assert.rejects(connector.signTransaction(FIELDS), /without a signed transaction/, JSON.stringify(bad));
  }
  // A wallet that cannot run Snaps.
  const plain = { request: async () => Promise.reject(Object.assign(new Error("no such method"), { code: -32601 })) };
  await assert.rejects(snapConnector(plain).connect(), /cannot run MetaMask Snaps/);
});

test("with no MetaMask, the connector says to install it and the page finds no provider", async () => {
  const connector = snapConnector(null);
  assert.equal(connector.available, false);
  await assert.rejects(connector.connect(), /install MetaMask/);
  assert.equal(injectedProvider({}), null);
  assert.equal(injectedProvider({ ethereum: {} }), null, "a provider must have request()");
  const provider = fakeMetaMask();
  assert.equal(injectedProvider({ ethereum: provider }), provider);
});

// --- The flow with a connected wallet, against the node stand-in ---

async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const prover = nodeProver();
  const flow = createFlow({ prover, endpoint: node.url, networks: node.networks(), pollMs: 5, sleep: async () => node.mine() });
  node.fund(TEST_WALLET_ADDRESS, 100n * GHOST);
  const done = async () => {
    prover.terminate();
    await node.close();
  };
  return { node, flow, done };
}

// Vanish up to the save check, the right words ready.
async function toCheck(flow, amount = "1") {
  const key = await flow.vanishStart(amount);
  const positions = flow.vanishSaved();
  const words = key.split(" ");
  return positions.map((p) => words[p - 1]);
}

const sentRaw = (node) => node.requests.filter((r) => r.method === "eth_sendRawTransaction").length;

test("Vanish through the Ghost Snap: the wallet approves, the page sends what it signed", async () => {
  const { node, flow, done } = await setUp();
  try {
    const provider = fakeMetaMask({ account: snapAccount, sign: snapSign });
    assert.equal(await flow.walletConnect(snapConnector(provider)), TEST_WALLET_ADDRESS);
    assert.deepEqual(flow.state.wallet, {
      id: SNAP_WALLET.id,
      name: SNAP_WALLET.name,
      address: TEST_WALLET_ADDRESS,
      balance: 100n * GHOST,
    });

    // The user turns the transaction down in MetaMask: nothing is sent, and
    // the key and its check stay, to try again.
    const answers = await toCheck(flow);
    provider.approve = false;
    await assert.rejects(flow.vanishCheck(answers), /rejected in your wallet; nothing was sent/);
    assert.equal(sentRaw(node), 0, "no transaction reached the endpoint");
    assert.equal(node.accountTxs.length, 0);
    assert.equal(flow.state.vanish.stage, "check");
    assert.ok(flow.state.vanish.key, "the key is still shown to the user");
    assert.match(flow.state.error, /rejected in your wallet/);

    // Approved: the commit goes out, from the connected account.
    provider.approve = true;
    const sent = await flow.vanishCheck(answers);
    assert.equal(sent.ok, true);
    assert.equal(flow.state.vanish.stage, "done");
    assert.equal(node.accountTxs.length, 1);
    const tx = node.accountTxs[0];
    assert.equal(tx.from, TEST_WALLET_ADDRESS);
    assert.equal(toHex(tx.to), DEFAULT_COMMIT_ENTRY);
    assert.equal(tx.value, GHOST);
    assert.equal(tx.hash, sent.txHash);
    assert.equal(flow.state.wallet.balance, 99n * GHOST);
    // MetaMask was asked to sign exactly that transaction, for this chain.
    const signs = provider.calls.filter((c) => c.method === "wallet_invokeSnap" && c.params.request.method === "ghost_signTransaction");
    assert.equal(signs.length, 2, "asked once per attempt");
    const params = signs[1].params.request.params;
    assert.equal(params.chainId, `0x${node.chainId.toString(16)}`);
    assert.equal(params.genesisHash, toHex(node.blocks[0].hash));
    assert.equal(params.to, DEFAULT_COMMIT_ENTRY);
    assert.equal(params.value, "0xde0b6b3a7640000");
    assert.equal(params.nonce, "0x0");
    assert.equal(params.data.length, 2 + 2 * 206, "the 206 bytes of a version 2 commit");
    // Only the Snap's two methods were ever asked of the provider.
    for (const call of provider.calls) assert.ok(SNAP_METHODS.has(call.method), call.method);
    // The endpoint never saw a request of a wallet.
    for (const r of node.requests) assert.ok(!r.method.startsWith("wallet_"), r.method);
  } finally {
    await done();
  }
});

test("an answer from another account, or whose hash is not its envelope's, is not sent", async () => {
  const { node, flow, done } = await setUp();
  try {
    let tamper = (signed) => ({ ...signed, sender: new Uint8Array(20).fill(0x11) });
    const connector = {
      ...testConnector(),
      async signTransaction(fields) {
        return tamper(await testSign(fields));
      },
    };
    await flow.walletConnect(connector);
    const answers = await toCheck(flow);
    await assert.rejects(flow.vanishCheck(answers), /not from the wallet's account; nothing was sent/);
    assert.equal(sentRaw(node), 0);

    tamper = (signed) => ({ ...signed, txHash: signed.txHash.map((b) => b ^ 1) });
    await assert.rejects(flow.vanishCheck(answers), /not the hash of its envelope; nothing was sent/);
    assert.equal(sentRaw(node), 0);

    tamper = () => ({ sender: "0x00", txHash: "0x00", envelope: "0x00" });
    await assert.rejects(flow.vanishCheck(answers), /without a signed transaction; nothing was sent/);
    assert.equal(sentRaw(node), 0);
    assert.equal(node.accountTxs.length, 0);

    // The same words, honestly signed, go out.
    tamper = (signed) => signed;
    assert.equal((await flow.vanishCheck(answers)).ok, true);
    assert.equal(node.accountTxs.length, 1);
  } finally {
    await done();
  }
});

test("disconnect lets the wallet go; Vanish then needs a wallet again", async () => {
  const { node, flow, done } = await setUp();
  try {
    const log = [];
    await flow.walletConnect(testConnector({ log }));
    assert.equal(flow.state.wallet.address, TEST_WALLET_ADDRESS);
    flow.walletDisconnect();
    assert.equal(flow.state.wallet, null);
    assert.deepEqual(log, ["connect", "disconnect"]);
    await assert.rejects(flow.vanishStart("1"), /connect a wallet first/);
    await assert.rejects(flow.walletConnect({ connect: async () => ({ address: "0x12" }), signTransaction() {} }), /without an account address/);
    assert.equal(flow.state.wallet, null, "a wallet without an address is not connected");
    await assert.rejects(flow.walletConnect({}), /not a wallet connector/);

    // While the wallet is asked to sign, it stays the connected one.
    let release;
    const asked = new Promise((resolve) => {
      release = resolve;
    });
    let signing;
    const signingStarted = new Promise((resolve) => {
      signing = resolve;
    });
    await flow.walletConnect(
      testConnector({
        approve: async () => {
          signing();
          await asked;
        },
      }),
    );
    const answers = await toCheck(flow);
    const check = flow.vanishCheck(answers);
    await signingStarted;
    // The flow is busy while the wallet is asked: the page cannot disconnect
    // or connect another wallet under it.
    assert.throws(() => flow.walletDisconnect(), /wait until/);
    await assert.rejects(flow.walletConnect(testConnector()), /wait until/);
    release();
    assert.equal((await check).ok, true, "the approved wallet's commit goes out");
    assert.equal(node.accountTxs.length, 1);
  } finally {
    await done();
  }
});
