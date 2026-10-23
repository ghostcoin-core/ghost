// One prover thread of the threaded module (threads.mjs starts it from the
// background worker): its own instance of the module on the shared memory,
// with the stack and thread-local storage the background worker set aside,
// then the rayon thread it is handed, which runs until the page closes.
//
//   { op: "start", module, memory, stackTop, tls }  ->  { op: "ready" }
//   { op: "run", thread }                           ->  { op: "running" }
//   anything that fails                             ->  { op: "error", message }

import { threadImports } from "./threads.mjs";

let exports = null;

self.onmessage = (event) => {
  const message = event.data || {};
  try {
    if (message.op === "start" && exports === null) {
      // A prover thread starts no other thread.
      const instance = new WebAssembly.Instance(message.module, threadImports(message.memory, () => 1));
      exports = instance.exports;
      // Before any of the module's code runs: this thread's own stack and
      // thread-local storage, never the background worker's.
      exports.__stack_pointer.value = message.stackTop;
      exports.__wasm_init_tls(message.tls);
      self.postMessage({ op: "ready" });
    } else if (message.op === "run" && exports !== null) {
      self.postMessage({ op: "running" });
      exports.ghost_thread_run(message.thread);
    } else {
      throw new Error(`unexpected message ${message.op}`);
    }
  } catch (err) {
    self.postMessage({ op: "error", message: String((err && err.message) || err) });
  }
};
