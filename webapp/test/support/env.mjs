// Shared set-up for the tests: where the built module is, and a prover that
// runs it in a worker_threads worker through the browser worker's message
// interface. Importing this file runs nothing.

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import { createProver } from "../../src/prover.mjs";
import { loadGhost } from "../../src/wasm.mjs";

export const webappDir = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

// The module the acceptance build makes; GHOST_WEBAPP_WASM may point at
// another build, for instance dist/ghost_webapp_wasm.wasm.
export const wasmPath =
  process.env.GHOST_WEBAPP_WASM ||
  resolve(webappDir, "wasm/target/wasm32-unknown-unknown/release/ghost_webapp_wasm.wasm");

export async function loadModule() {
  return loadGhost(await readFile(wasmPath));
}

export function nodeProver() {
  const worker = new Worker(new URL("./node-worker.mjs", import.meta.url), { workerData: { wasmPath } });
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
// derives (client/tests/accounts.rs).
export const TEST_WALLET_WORDS =
  "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware";
export const TEST_WALLET_ADDRESS = "0x80992a5c983fc01cd9a0c16c4dfc47b9a750d022";

// Funds the tests' wallet on the stand-in `node` and opens it in `flow`.
export async function openTestWallet(flow, node, balance = 100n * 10n ** 18n) {
  node.fund(TEST_WALLET_ADDRESS, balance);
  return flow.walletRestore(TEST_WALLET_WORDS);
}
