// The page's side of the worker interface (worker-core.mjs): one promise per
// request, with the worker's progress stages passed to a callback.

// `port`: { post(message), listen(handler), terminate() }.
export function createProver(port) {
  let next = 0;
  const pending = new Map();
  port.listen((reply) => {
    const entry = pending.get(reply && reply.id);
    if (!entry) return;
    if (reply.type === "progress") {
      entry.onProgress(reply.stage);
      return;
    }
    pending.delete(reply.id);
    if (reply.type === "result") entry.resolve(reply.result);
    else entry.reject(new Error(reply.message));
  });
  return {
    request(op, args = {}, onProgress = () => {}) {
      next += 1;
      const id = next;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject, onProgress });
        port.post({ id, op, args });
      });
    },
    // The worker died (the browser can stop one that runs out of memory):
    // every open request fails with this message.
    fail(message) {
      for (const entry of pending.values()) entry.reject(new Error(`the worker stopped: ${message}`));
      pending.clear();
    },
    terminate() {
      this.fail("closed");
      port.terminate();
    },
  };
}

// The browser worker, as a module worker from the same origin.
export function browserProver() {
  const worker = new Worker(new URL("./worker.mjs", import.meta.url), { type: "module" });
  const prover = createProver({
    post: (message) => worker.postMessage(message),
    listen: (handler) => {
      worker.onmessage = (event) => handler(event.data);
    },
    terminate: () => worker.terminate(),
  });
  worker.onerror = (event) => prover.fail(event.message || "worker error");
  return prover;
}
