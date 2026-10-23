// Background worker for the web app's own prover modules (app-reveal.html):
// the module webapp/build.sh ships, threaded (wasm-threads) or single-thread
// (wasm-single), copied by `benchmarks/run.sh --app` into reveal-pkg/app. It
// runs one session (one cold run, then the warm runs) in the same worker.
//
// Each run is the web app's own `prove` call (webapp/src/wasm.mjs) for a
// decoy partial reveal: a throwaway key's coin of 1,000 GHOST revealed for
// 250 out and a fee of 0.001 GHOST, salted (version 2, `salted-coin-reveal`)
// or not (version 1, `coin-reveal`). A decoy is the same work as a real
// reveal: the same statement, configuration and proof. Proving time is
// taken with performance.now() around that call: the key and coin, the proof
// and its check in the worker (the module verifies every proof before it
// returns it) and the envelope. Module start-up (fetch, compile, and for the
// threaded module starting its thread workers) is recorded separately.

import { Ghost, loadGhost } from "./reveal-pkg/app/src/wasm.mjs";
import { loadThreadedExports, threadCount } from "./reveal-pkg/app/src/threads.mjs";

const MODULES = {
  "wasm-single": "./reveal-pkg/app/ghost_webapp_wasm.wasm",
  "wasm-threads": "./reveal-pkg/app/ghost_webapp_wasm_threads.wasm",
};
const STATEMENTS = ["coin-reveal", "salted-coin-reveal"];
// The configuration of spec 09, section 4.1 that the proofs crate ships
// (docs/benchmarks/reveal-parameters.md); the module has no other.
const CONFIGURATION = {
  hash_candidate: "keccak-256",
  log_blowup: 3,
  configuration: "keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk",
  zero_knowledge: true,
};
const GHOST = 10n ** 18n;

function outcomeOf(err) {
  const text = String(err && (err.message || err));
  if (err instanceof RangeError || /out of memory|memory access|allocation/i.test(text)) {
    return "out_of_memory";
  }
  return "failed";
}

async function load(build, threads) {
  const response = await fetch(new URL(MODULES[build], import.meta.url));
  if (!response.ok) throw new Error(`${MODULES[build]}: HTTP ${response.status}`);
  const bytes = await response.arrayBuffer();
  if (build === "wasm-single") return loadGhost(bytes);
  const startThread = () => new Worker(new URL("./reveal-pkg/app/src/thread.mjs", import.meta.url), { type: "module" });
  return new Ghost(await loadThreadedExports(bytes, threads, startThread));
}

self.onmessage = async (ev) => {
  const job = ev.data;
  if (job.type !== "run") return;
  const query = job.query || {};
  const build = query.build || "wasm-threads";
  const statement = query.statement || "coin-reveal";
  const threads = build === "wasm-threads" ? threadCount(self) : 1;
  const common = {
    ...CONFIGURATION,
    statement,
    prover: `the web app's module (webapp/build.sh), ${build}, decoy partial reveal`,
    build,
    threads_used: threads > 1,
    thread_count: threads,
    simd_used: true,
    witness: "a decoy's throwaway key and coin, drawn in the module from crypto.getRandomValues",
  };
  const refuse = (reason) =>
    self.postMessage({ type: "record", record: { ...common, run_index: 0, run_kind: "cold", outcome: "refused", reason } });
  if (!Object.hasOwn(MODULES, build)) return refuse(`unknown build ${build}`);
  if (!STATEMENTS.includes(statement)) return refuse(`unknown statement ${statement}`);
  if (build === "wasm-threads" && threads < 2) return refuse("the page is not cross-origin isolated or has one core");

  let ghost;
  const t0 = performance.now();
  try {
    ghost = await load(build, threads);
  } catch (err) {
    return refuse(`the module did not start: ${String(err && (err.message || err))}`);
  }
  const startupMs = performance.now() - t0;
  const random = (n) => crypto.getRandomValues(new Uint8Array(n));

  for (let run = 0; run <= job.warm; run += 1) {
    const record = {
      ...common,
      run_index: run,
      run_kind: run === 0 ? "cold" : "warm",
      start_time_unix_ms: Date.now(),
      // Recorded on the cold run only, as the plan asks.
      module_startup_ms: run === 0 ? startupMs : null,
    };
    try {
      const args = {
        decoy: true,
        salted: statement === "salted-coin-reveal",
        chainId: 1234,
        domain: random(32),
        kind: "partial",
        root: new Uint8Array(32),
        recipient: random(20),
        out: 250n * GHOST,
        fee: GHOST / 1000n,
        number: 0n,
        amount: 1000n * GHOST,
        position: 0,
        leaves: new Uint8Array(32),
        // Fresh randomness from the browser's secure source on every run.
        seed: random(32),
        zk: random(32),
        key: "",
      };
      const start = performance.now();
      const made = ghost.prove(args);
      record.proving_ms = performance.now() - start;
      record.peak_wasm_memory_bytes = ghost.w.memory.buffer.byteLength;
      record.verified = true;
      record.verification_ms = null;
      record.total_bytes = made.envelope.length;
      record.outcome = "completed";
    } catch (err) {
      record.outcome = outcomeOf(err);
      record.reason = String(err && (err.message || err));
      record.peak_wasm_memory_bytes = ghost.w.memory.buffer.byteLength;
    }
    self.postMessage({ type: "record", record, proof: null });
  }
};
