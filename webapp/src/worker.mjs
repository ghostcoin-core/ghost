// Browser entry of the background worker: loads the module from the same
// origin and answers the requests of worker-core.mjs.
//
// The threaded module (threads.mjs) when the page is cross-origin isolated
// and the device has more than one core; otherwise, or when it does not
// start, the single-thread module. Both prove the same statement with the
// same configuration.

import { Ghost, loadGhost } from "./wasm.mjs";
import { loadThreadedExports, threadCount } from "./threads.mjs";
import { createWorker } from "./worker-core.mjs";

// The two modules, as build.sh names them in dist.
const SINGLE_MODULE = "ghost_webapp_wasm.wasm";
const THREADED_MODULE = "ghost_webapp_wasm_threads.wasm";

async function fetchModule(name) {
  const response = await fetch(new URL(`../${name}`, import.meta.url));
  if (!response.ok) throw new Error(`the prover module did not load (HTTP ${response.status})`);
  return response.arrayBuffer();
}

const startThread = () => new Worker(new URL("./thread.mjs", import.meta.url), { type: "module" });

async function loadProver() {
  const count = threadCount(self);
  if (count > 1) {
    try {
      return new Ghost(await loadThreadedExports(await fetchModule(THREADED_MODULE), count, startThread));
    } catch {
      // The single-thread module below proves the same, more slowly.
    }
  }
  return loadGhost(await fetchModule(SINGLE_MODULE));
}

const onMessage = createWorker(
  loadProver,
  (reply) => self.postMessage(reply),
  (ghost) => ghost,
);

self.onmessage = (event) => onMessage(event.data);
