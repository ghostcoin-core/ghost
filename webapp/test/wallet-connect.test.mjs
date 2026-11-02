// The connected wallet: the wallet module (wallet-connect.mjs) and its
// transaction fields as the wallets read them, then the flow controller with
// a connected wallet against the node stand-in. The stand-in wallet answers
// the requests the way the Ghost pop-up wallet does, with the tests' account
// signing in the worker (support/env.mjs); the page side holds no seed and
// no key.

import assert from "node:assert/strict";
import test from "node:test";

import { fromHex, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow } from "../src/flow.mjs";
import * as walletConnect from "../src/wallet-connect.mjs";
import { USER_REJECTED, WalletRejected, fieldsFromSnap, isWalletRejection, snapTransaction } from "../src/wallet-connect.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, testAccount, testConnector, testSign } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;

// A stand-in wallet that speaks the pop-up wallet's two requests with the
// tests' account: the account as { address, publicKey } and the signed
// transaction as 0x hex, read back as bytes. Every request is logged;
// `approve` false turns the next requests down as the user would.
function hexWallet() {
  let address = null;
  const wallet = {
    id: "test-hex-wallet",
    name: "Test hex wallet",
    calls: [],
    approve: true,
    async connect() {
      wallet.calls.push({ method: "ghost_getAccount" });
      if (!wallet.approve) throw new WalletRejected("the connection");
      const account = await testAccount();
      address = account.address;
      return { address };
    },
    async signTransaction(fields) {
      if (!address) throw new Error("connect the wallet first");
      const params = snapTransaction(fields);
      wallet.calls.push({ method: "ghost_signTransaction", params });
      if (!wallet.approve) throw new WalletRejected("the transaction");
      const signed = await testSign(fieldsFromSnap(params));
      return { sender: fromHex(toHex(signed.sender), 20), txHash: fromHex(toHex(signed.txHash), 32), envelope: fromHex(toHex(signed.envelope)) };
    },
    disconnect() {
      address = null;
    },
  };
  return wallet;
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

// --- The wallet module ---

test("the module offers no wallet but the Ghost pop-up wallet: no MetaMask connector", () => {
  assert.deepEqual(Object.keys(walletConnect).sort(), [
    "USER_REJECTED",
    "WalletRejected",
    "WalletSignFailed",
    "fieldsFromSnap",
    "isWalletRejection",
    "snapTransaction",
  ]);
  assert.equal(USER_REJECTED, 4001);
  assert.equal(isWalletRejection({ code: USER_REJECTED }), true);
  assert.equal(isWalletRejection(new WalletRejected("the connection")), true);
  assert.equal(isWalletRejection(new Error("no")), false);
});

test("the transaction fields go to the wallet as 0x hex and read back the same", () => {
  const seen = snapTransaction(FIELDS);
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
  assert.deepEqual(fieldsFromSnap(seen), FIELDS, "the wallet reads back the fields the page signed");
  assert.equal(snapTransaction({ ...FIELDS, to: null }).to, null, "a contract creation has no to");
  assert.equal(fieldsFromSnap(snapTransaction({ ...FIELDS, to: null })).to, null);
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

test("Vanish through a wallet speaking 0x hex: the wallet approves, the page sends what it signed", async () => {
  const { node, flow, done } = await setUp();
  try {
    const wallet = hexWallet();
    assert.equal(await flow.walletConnect(wallet), TEST_WALLET_ADDRESS);
    assert.deepEqual(flow.state.wallet, {
      id: wallet.id,
      name: wallet.name,
      address: TEST_WALLET_ADDRESS,
      balance: 100n * GHOST,
    });

    // The user turns the transaction down in the wallet: nothing is sent,
    // and the key and its check stay, to try again.
    const answers = await toCheck(flow);
    wallet.approve = false;
    await assert.rejects(flow.vanishCheck(answers), /rejected in your wallet; nothing was sent/);
    assert.equal(sentRaw(node), 0, "no transaction reached the endpoint");
    assert.equal(node.accountTxs.length, 0);
    assert.equal(flow.state.vanish.stage, "check");
    assert.ok(flow.state.vanish.key, "the key is still shown to the user");
    assert.match(flow.state.error, /rejected in your wallet/);

    // Approved: the commit goes out, from the connected account.
    wallet.approve = true;
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
    // The wallet was asked to sign exactly that transaction, for this chain.
    const signs = wallet.calls.filter((c) => c.method === "ghost_signTransaction");
    assert.equal(signs.length, 2, "asked once per attempt");
    const params = signs[1].params;
    assert.equal(params.chainId, `0x${node.chainId.toString(16)}`);
    assert.equal(params.genesisHash, toHex(node.blocks[0].hash));
    assert.equal(params.to, DEFAULT_COMMIT_ENTRY);
    assert.equal(params.value, "0xde0b6b3a7640000");
    assert.equal(params.nonce, "0x0");
    assert.equal(params.data.length, 2 + 2 * 206, "the 206 bytes of a version 2 commit");
    // Only the wallet's two requests were ever asked of it.
    assert.deepEqual(
      wallet.calls.map((c) => c.method),
      ["ghost_getAccount", "ghost_signTransaction", "ghost_signTransaction"],
    );
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
