// Shared set-up for the tests: where the built module is, and a prover that
// runs it in a worker_threads worker through the browser worker's message
// interface. Importing this file runs nothing.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import { toHex } from "../../src/bytes.mjs";
import { createProver } from "../../src/prover.mjs";
import { loadGhost } from "../../src/wasm.mjs";
import { createWorker } from "../../src/worker-core.mjs";

export const webappDir = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

// The module the acceptance build makes; GHOST_WEBAPP_WASM may point at
// another build, for instance dist/ghost_webapp_wasm.wasm.
export const wasmPath =
  process.env.GHOST_WEBAPP_WASM ||
  resolve(webappDir, "wasm/target/wasm32-unknown-unknown/release/ghost_webapp_wasm.wasm");

// The test-depth module: the same crate built with the test-tree-depth
// feature into a target directory of its own (lib.rs, test_depth), which
// only the tests and scripts/recovery-blackout.sh use.
// GHOST_WEBAPP_TEST_DEPTH_WASM may point at another build of it.
export const testDepthTargetDir = resolve(tmpdir(), "ghost-test-depth");
export const testDepthWasmPath =
  process.env.GHOST_WEBAPP_TEST_DEPTH_WASM ||
  resolve(testDepthTargetDir, "wasm32-unknown-unknown/release/ghost_webapp_wasm.wasm");

// Builds the module at `path`, when none is there yet, with the toolchain CI
// pins: the default module, or with `features` into `targetDir`.
export function buildModuleIfMissing(path, { features = null, targetDir = null } = {}) {
  if (existsSync(path)) return;
  const env = { ...process.env, RUSTUP_TOOLCHAIN: process.env.RUSTUP_TOOLCHAIN || "1.99.1" };
  if (!env.RUSTUP_HOME && existsSync("/usr/local/rustup")) env.RUSTUP_HOME = "/usr/local/rustup";
  const manifest = resolve(webappDir, "wasm/Cargo.toml");
  const args = ["build", "--release", "--locked", "--target", "wasm32-unknown-unknown", "--manifest-path", manifest];
  if (features) args.push("--features", features);
  if (targetDir) args.push("--target-dir", targetDir);
  execFileSync("cargo", args, { env, stdio: "inherit" });
  if (!existsSync(path)) throw new Error(`the build made no module at ${path}`);
}

export async function loadModule(path = wasmPath) {
  return loadGhost(await readFile(path));
}

// A prover over the module at `path` (the default module unless given).
export function nodeProver(path = wasmPath) {
  const worker = new Worker(new URL("./node-worker.mjs", import.meta.url), { workerData: { wasmPath: path } });
  let prover = null;
  prover = createProver({
    post: (message) => worker.postMessage(message),
    listen: (handler) => worker.on("message", handler),
    terminate: () => worker.terminate(),
  });
  worker.on("error", (err) => prover.fail(err.message));
  return prover;
}

// The tests' wallet: the seed of the bytes 0 to 31 as its 24 words, and its
// account 0, whose address ghost-node's own code gives for the key that seed
// derives (client/tests/accounts.rs). The page never holds a seed: this is
// the one place that does, standing in for the wallet the user connects
// (a MetaMask Snap that keeps the key in MetaMask, wallet-connect.mjs).
const TEST_WALLET_WORDS =
  "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware";
const TEST_ACCOUNT_INDEX = 0;
export const TEST_WALLET_ADDRESS = "0x80992a5c983fc01cd9a0c16c4dfc47b9a750d022";

// The worker's message interface (worker-core.mjs) run in this thread on
// the default module, for the tests' wallet only: one per test process,
// loaded at its first request.
let walletWorker = null;
function testWalletWorker() {
  if (walletWorker) return walletWorker;
  let deliver = () => {};
  const onMessage = createWorker(
    () => readFile(wasmPath),
    (reply) => deliver(reply),
  );
  walletWorker = createProver({
    post: (message) => onMessage(message),
    listen: (handler) => {
      deliver = handler;
    },
    terminate: () => {},
  });
  return walletWorker;
}

// The tests' account: its address and ML-DSA-44 public key, from the worker.
export async function testAccount() {
  const { address, publicKey } = await testWalletWorker().request("walletAccount", {
    words: TEST_WALLET_WORDS,
    index: TEST_ACCOUNT_INDEX,
  });
  return { address: toHex(address), publicKey };
}

// An account transaction (type 0x52) of `fields` (wallet-connect.mjs: chainId,
// genesis, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value,
// data) signed with the tests' account by the worker's walletSign:
// { txHash, sender, envelope } as byte arrays.
export function testSign(fields) {
  const { chainId, genesis, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data } = fields;
  return testWalletWorker().request("walletSign", {
    words: TEST_WALLET_WORDS,
    index: TEST_ACCOUNT_INDEX,
    chainId,
    genesis,
    nonce,
    maxPriorityFeePerGas,
    maxFeePerGas,
    gasLimit,
    to,
    value,
    data,
  });
}

// The tests' wallet as a connector of wallet-connect.mjs. `log` records each
// call; `approve(fields)`, when given, runs before each signature and may
// throw to stand for the user turning it down.
export function testConnector({ log = [], approve = null } = {}) {
  let connected = false;
  return {
    id: "test-wallet",
    name: "Test wallet",
    async connect() {
      log.push("connect");
      const { address } = await testAccount();
      connected = true;
      return { address };
    },
    async signTransaction(fields) {
      log.push("signTransaction");
      if (!connected) throw new Error("the test wallet is not connected");
      if (approve) await approve(fields);
      return testSign(fields);
    },
    disconnect() {
      log.push("disconnect");
      connected = false;
    },
  };
}

// Funds the tests' wallet on the stand-in `node` and connects it in `flow`.
// Returns its address.
export async function openTestWallet(flow, node, balance = 100n * 10n ** 18n) {
  node.fund(TEST_WALLET_ADDRESS, balance);
  return flow.walletConnect(testConnector());
}
