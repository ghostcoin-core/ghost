// The page's side of the worker interface (worker-core.mjs): one promise per
// request, with the worker's progress stages passed to a callback.

// How long one request waits for the worker's answer, in milliseconds. A
// worker that errs without answering, or is stuck, fails the request after
// this instead of holding the page forever, as REQUEST_TIMEOUT_MS bounds
// every request to the node (rpc.mjs).
export const WORKER_TIMEOUT_MS = 120000;

// The message a request fails with when the worker did not answer in time.
export const WORKER_TIMEOUT = "the worker did not answer in time";

// Whether `err` is a request that failed because the worker did not answer
// in time: nothing is known of what it was asked, so it says nothing about
// the chain.
export function isWorkerTimeout(err) {
  return String((err && err.message) || "").startsWith(WORKER_TIMEOUT);
}

// `port`: { post(message), listen(handler), terminate() }. Every request
// fails after `timeoutMs` without the worker's answer; a progress reply is
// not an answer, and an answer after that is ignored.
export function createProver(
  port,
  { timeoutMs = WORKER_TIMEOUT_MS, setTimer = setTimeout, clearTimer = clearTimeout } = {},
) {
  let next = 0;
  const pending = new Map();
  const settle = (id) => {
    const entry = pending.get(id);
    if (!entry) return null;
    pending.delete(id);
    clearTimer(entry.timer);
    return entry;
  };
  port.listen((reply) => {
    const id = reply && reply.id;
    const open = pending.get(id);
    if (!open) return;
    if (reply.type === "progress") {
      open.onProgress(reply.stage);
      return;
    }
    const entry = settle(id);
    if (reply.type === "result") entry.resolve(reply.result);
    else entry.reject(new Error(reply.message));
  });
  return {
    request(op, args = {}, onProgress = () => {}) {
      next += 1;
      const id = next;
      return new Promise((resolve, reject) => {
        const timer = setTimer(() => {
          const entry = settle(id);
          if (entry) entry.reject(new Error(`${WORKER_TIMEOUT} (${op}, ${timeoutMs / 1000} s)`));
        }, timeoutMs);
        pending.set(id, { resolve, reject, onProgress, timer });
        port.post({ id, op, args });
      });
    },
    // The worker died (the browser can stop one that runs out of memory):
    // every open request fails with this message.
    fail(message) {
      for (const id of [...pending.keys()]) settle(id).reject(new Error(`the worker stopped: ${message}`));
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
