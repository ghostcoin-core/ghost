// Background worker for the real coin reveal prover (benchmarks/reveal):
// loads the WebAssembly module with no bindings generator and runs one
// session (one cold run, then the warm runs) in the same worker.
//
// Proving time is taken here with performance.now() around ghost_prove: the
// real prover, from the call that receives the witness to the return of the
// finished proof, checks and trace generation included. It excludes loading
// and compiling the module, drawing the session's witness and moving the
// result to the page; module start-up is recorded separately.
//
// Every proof and its public fields go back to the page as hex, so they can
// be verified again natively (ghost-reveal-verify).

const BUILD = "wasm-single";

function outcomeOf(err) {
  const text = String(err && (err.message || err));
  if (err instanceof RangeError || /out of memory|memory access|allocation/i.test(text)) {
    return "out_of_memory";
  }
  return "failed";
}

function hex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

self.onmessage = async (ev) => {
  const job = ev.data;
  if (job.type !== "run") return;

  const t0 = performance.now();
  const { instance } = await WebAssembly.instantiateStreaming(
    fetch(new URL("./reveal-pkg/ghost_reveal_bench.wasm", import.meta.url)),
    {},
  );
  const startupMs = performance.now() - t0;
  const w = instance.exports;
  const bytesAt = (ptr, len) => new Uint8Array(w.memory.buffer, ptr, len).slice();
  const text = (ptr, len) => new TextDecoder().decode(bytesAt(ptr, len));
  const error = () => text(w.ghost_error_ptr(), w.ghost_error_len());

  const common = {
    build: BUILD,
    threads_used: false,
    simd_used: true,
    module_startup_ms: startupMs,
  };

  if (w.ghost_session(job.witnessSeed, job.sameKey ? 1 : 0) !== 0) {
    self.postMessage({
      type: "record",
      record: { ...common, run_index: 0, run_kind: "cold", outcome: "refused", reason: error() },
    });
    return;
  }
  const fields = JSON.parse(text(w.ghost_fields_ptr(), w.ghost_fields_len()));
  const zkPtr = w.ghost_alloc(32);

  for (let run = 0; run <= job.warm; run += 1) {
    const record = {
      ...common,
      ...fields,
      run_index: run,
      run_kind: run === 0 ? "cold" : "warm",
      start_time_unix_ms: Date.now(),
      // Recorded on the cold run only, as the plan asks.
      module_startup_ms: run === 0 ? startupMs : null,
    };
    let proof = null;
    try {
      // Fresh zero-knowledge randomness from the browser's secure source on
      // every run; never seeded.
      crypto.getRandomValues(new Uint8Array(w.memory.buffer, zkPtr, 32));
      const start = performance.now();
      const rc = w.ghost_prove(zkPtr);
      record.proving_ms = performance.now() - start;
      record.peak_wasm_memory_bytes = w.memory.buffer.byteLength;
      if (rc !== 0) throw new Error(error());

      const vstart = performance.now();
      const ok = w.ghost_verify() === 0;
      record.verification_ms = performance.now() - vstart;
      record.verified = ok;
      record.proof_bytes = w.ghost_proof_len();
      record.total_bytes = record.proof_bytes + w.ghost_reveal_len();
      record.outcome = ok ? "completed" : "failed";
      if (!ok) record.reason = `the proof did not verify: ${error()}`;
      proof = {
        reveal: hex(bytesAt(w.ghost_reveal_ptr(), w.ghost_reveal_len())),
        proof: hex(bytesAt(w.ghost_proof_ptr(), w.ghost_proof_len())),
      };
    } catch (err) {
      record.outcome = outcomeOf(err);
      record.reason = String(err && (err.message || err));
      record.peak_wasm_memory_bytes = w.memory.buffer.byteLength;
    }
    self.postMessage({ type: "record", record, proof });
  }
};
