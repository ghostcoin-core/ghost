// Browser entry of the background worker: loads the module from the same
// origin and answers the requests of worker-core.mjs.

import { createWorker } from "./worker-core.mjs";

const onMessage = createWorker(
  async () => {
    const response = await fetch(new URL("../ghost_webapp_wasm.wasm", import.meta.url));
    if (!response.ok) throw new Error(`the prover module did not load (HTTP ${response.status})`);
    return response.arrayBuffer();
  },
  (reply) => self.postMessage(reply),
);

self.onmessage = (event) => onMessage(event.data);
