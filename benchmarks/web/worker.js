// Background worker: loads the WebAssembly module and runs one session (one
// cold run, then the warm runs) in the same worker.
//
// Proving time is taken here with performance.now(), from the call that
// receives the witness inputs to the return of the finished proof bytes. It
// excludes loading and compiling the module and moving the result to the
// page; module start-up is recorded separately.

import init, { BenchInstance, libraryRevision } from "./pkg/ghost_bench_wasm.js";

// The build in ./pkg is the single-thread SIMD build unless replaced with a
// threaded one; the page records which.
const BUILD = "wasm-single";

function outcomeOf(err) {
  const text = String(err && (err.message || err));
  if (err instanceof RangeError || /out of memory|memory access|allocation/i.test(text)) {
    return "out_of_memory";
  }
  return "failed";
}

self.onmessage = async (ev) => {
  const job = ev.data;
  if (job.type !== "run") return;

  const t0 = performance.now();
  const wasm = await init({ module_or_path: new URL("./pkg/ghost_bench_wasm_bg.wasm", import.meta.url) });
  const startupMs = performance.now() - t0;

  const common = {
    build: BUILD,
    threads_used: false,
    simd_used: true,
    module_startup_ms: startupMs,
    library_revision: libraryRevision(),
    hash_candidate: job.candidate,
    log_blowup: job.logBlowup,
  };

  let instance;
  try {
    instance = new BenchInstance(job.candidate, job.logBlowup, job.witnessSeed, job.sameKey);
  } catch (err) {
    self.postMessage({
      type: "record",
      record: { ...common, run_index: 0, run_kind: "cold", outcome: "refused", reason: String(err.message || err) },
    });
    return;
  }
  const fields = JSON.parse(instance.recordFields());

  for (let run = 0; run <= job.warm; run += 1) {
    const record = {
      ...common,
      ...fields,
      build: BUILD,
      run_index: run,
      run_kind: run === 0 ? "cold" : "warm",
      start_time_unix_ms: Date.now(),
      // Recorded on the cold run only, as the plan asks.
      module_startup_ms: run === 0 ? startupMs : null,
    };
    // Fresh zero-knowledge randomness from the browser's secure source on
    // every run; never seeded.
    const zkSeed = crypto.getRandomValues(new Uint8Array(32));
    try {
      const start = performance.now();
      const proof = instance.prove(zkSeed);
      record.proving_ms = performance.now() - start;
      record.peak_wasm_memory_bytes = wasm.memory.buffer.byteLength;

      const vstart = performance.now();
      const ok = instance.verify(proof);
      record.verification_ms = performance.now() - vstart;
      record.verified = ok;
      record.proof_bytes = proof.length;
      record.total_bytes = proof.length + instance.publicInputsBytes();
      record.outcome = ok ? "completed" : "failed";
      if (!ok) record.reason = "the proof did not verify";
    } catch (err) {
      record.outcome = outcomeOf(err);
      record.reason = String(err && (err.message || err));
      record.peak_wasm_memory_bytes = wasm.memory.buffer.byteLength;
    }
    self.postMessage({ type: "record", record });
  }
};
