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
