// The threaded prover module (webapp/wasm, feature `threads`): one shared
// WebAssembly memory, the background worker's instance and one Web Worker
// per further prover thread (thread.mjs), each with its own instance of the
// same module, stack and thread-local storage. The proofs crate's parallel
// work runs on all of them; the statement and its configuration are the
// single-thread module's.
//
// Shared memory needs a cross-origin isolated page (Cross-Origin-Opener-Policy
// same-origin and Cross-Origin-Embedder-Policy require-corp, set in
// webapp/vercel/config.json). Without it, on a single core, or when anything
// here fails, worker.mjs loads the single-thread module instead.

// The memory build.sh links the threaded module with (--initial-memory and
// --max-memory): the module imports a shared memory of exactly these limits.
export const INITIAL_MEMORY_BYTES = 64 * 1024 * 1024;
export const MAXIMUM_MEMORY_BYTES = 4 * 1024 * 1024 * 1024;
const PAGE_BYTES = 64 * 1024;
// Each prover thread's stack, as the single-thread module's main stack is at
// most this.
export const THREAD_STACK_BYTES = 2 * 1024 * 1024;
const STACK_ALIGN = 16;
// The most threads the pool takes, the calling worker included.
export const MAX_THREADS = 8;

// How many prover threads `scope` (the worker's global) can run: 1, the
// single-thread module, unless the page is cross-origin isolated and the
// device reports more than one core.
export function threadCount(scope) {
  if (scope.crossOriginIsolated !== true || typeof scope.SharedArrayBuffer !== "function") return 1;
  const cores = Math.floor(Number(scope.navigator?.hardwareConcurrency) || 1);
  return Math.max(1, Math.min(MAX_THREADS, cores));
}

// The threaded module's imports: the shared memory, and how it hands a rayon
// thread to the Web Worker started for it (0 when handed over).
export function threadImports(memory, spawn) {
  return { env: { memory }, ghost: { ghost_thread_spawn: spawn } };
}

// The text of the module's last error.
function lastError(exports, memory) {
  const ptr = exports.ghost_error_ptr() >>> 0;
  return new TextDecoder().decode(new Uint8Array(memory.buffer, ptr, exports.ghost_error_len() >>> 0).slice());
}

// One prover thread's Web Worker, answered one message at a time.
class ThreadWorker {
  constructor(worker) {
    this.worker = worker;
    this.waiting = null;
    worker.onmessage = (event) => this.settle(event.data);
    worker.onerror = (event) => this.settle({ op: "error", message: event.message || "the thread worker stopped" });
  }

  settle(reply) {
    const waiting = this.waiting;
    if (!waiting) return;
    this.waiting = null;
    if (reply && reply.op === waiting.op) waiting.resolve();
    else waiting.reject(new Error((reply && reply.message) || "the thread worker answered out of turn"));
  }

  // Resolves when the worker replies `op`; posts `message` first if given.
  expect(op, message) {
    const reply = new Promise((resolve, reject) => {
      this.waiting = { op, resolve, reject };
    });
    if (message) this.worker.postMessage(message);
    return reply;
  }

  terminate() {
    this.worker.terminate();
  }
}

// Instantiates the threaded module from `bytes` with `count` prover threads:
// this worker and `count - 1` Web Workers from `startWorker()`. Returns the
// module's exports with its memory, as Ghost (wasm.mjs) reads them.
export async function loadThreadedExports(bytes, count, startWorker) {
  if (!(count > 1)) throw new Error("the threaded module needs more than one thread");
  const memory = new WebAssembly.Memory({
    initial: INITIAL_MEMORY_BYTES / PAGE_BYTES,
    maximum: MAXIMUM_MEMORY_BYTES / PAGE_BYTES,
    shared: true,
  });
  const module = await WebAssembly.compile(bytes);
  const threads = [];
  const spawn = (index, thread) => {
    const worker = threads[index - 1];
    if (!worker) return 1;
    worker.worker.postMessage({ op: "run", thread });
    return 0;
  };
  const { exports } = await WebAssembly.instantiate(module, threadImports(memory, spawn));
  const workers = [];
  try {
    const tlsSize = exports.__tls_size.value >>> 0;
    const tlsAlign = exports.__tls_align.value >>> 0;
    for (let i = 1; i < count; i += 1) {
      const stack = exports.ghost_thread_memory(THREAD_STACK_BYTES, STACK_ALIGN) >>> 0;
      const tls = exports.ghost_thread_memory(tlsSize, tlsAlign) >>> 0;
      if (stack === 0 || tls === 0) throw new Error("no memory left for a prover thread");
      const worker = new ThreadWorker(startWorker());
      workers.push(worker);
      await worker.expect("ready", { op: "start", module, memory, stackTop: stack + THREAD_STACK_BYTES, tls });
    }
    threads.push(...workers);
    const running = workers.map((worker) => worker.expect("running"));
    if (exports.ghost_threads_start(count) !== 0) throw new Error(lastError(exports, memory));
    await Promise.all(running);
  } catch (err) {
    for (const worker of workers) worker.terminate();
    throw err;
  }
  return { ...exports, memory };
}
