// Node entry of the background worker for the headless tests: the same
// message interface as the browser worker (src/worker.mjs), in a
// worker_threads worker, with the module read from disk. Run on its own,
// outside a worker, it does nothing.

import { readFile } from "node:fs/promises";
import { parentPort, workerData } from "node:worker_threads";

import { createWorker } from "../../src/worker-core.mjs";

if (parentPort) {
  const onMessage = createWorker(
    () => readFile(workerData.wasmPath),
    (reply) => parentPort.postMessage(reply),
  );
  parentPort.on("message", onMessage);
}
