// Page side of the real coin reveal benchmark (reveal.html): the same
// environment fields and records as main.js, for the prover of
// benchmarks/reveal in reveal-worker.js. It also keeps every proof and its
// public fields, as lines for ghost-reveal-verify, so each proof made here can
// be verified again natively. No dependencies.

const $ = (id) => document.getElementById(id);
// The worker the page runs: reveal-worker.js, or the one the page names
// (app-reveal.html runs the web app's modules), with the choices in the
// page's address, e.g. ?build=wasm-threads&statement=salted-coin-reveal.
const WORKER = document.body.dataset.worker || "./reveal-worker.js";
const QUERY = Object.fromEntries(new URLSearchParams(location.search));
const records = [];
// One line per proof: <label> TAB <public fields, hex> TAB <proof, hex>.
const proofLines = [];
self.revealProofLines = proofLines;
let env = null;
let pressure = null;

const DEVICE_LABELS = {
  "mac-studio": "Mac Studio (Apple M5 Max, 64 GB)",
  "emulated-phone": "emulated mid-range phone, not a real device",
};

// A minimal module that uses a v128 instruction: valid only with SIMD.
const SIMD_PROBE = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8, 0,
  65, 0, 253, 15, 253, 98, 11,
]);

async function collectEnvironment() {
  const out = {
    user_agent: navigator.userAgent,
    logical_cores: navigator.hardwareConcurrency ?? null,
    cross_origin_isolated: self.crossOriginIsolated === true,
    shared_array_buffer: typeof SharedArrayBuffer !== "undefined",
    simd_available: WebAssembly.validate(SIMD_PROBE),
    device_memory_gb: navigator.deviceMemory ?? null,
  };
  out.threads_available = out.cross_origin_isolated && out.shared_array_buffer;
  if (navigator.userAgentData?.getHighEntropyValues) {
    const hints = await navigator.userAgentData.getHighEntropyValues([
      "fullVersionList", "platform", "platformVersion", "architecture", "model",
    ]);
    const chrome = (hints.fullVersionList || []).find((b) => b.brand === "Google Chrome");
    out.chrome_build = chrome ? chrome.version : null;
    out.os = `${hints.platform} ${hints.platformVersion} (${hints.architecture})`;
  } else {
    out.chrome_build = null;
    out.os = navigator.platform;
  }
  return out;
}

// Chrome's Compute Pressure API is the closest thing to a thermal state a
// page can read; recorded when available.
async function watchPressure() {
  if (!("PressureObserver" in self)) return;
  try {
    const observer = new PressureObserver((changes) => {
      pressure = changes[changes.length - 1].state;
    });
    await observer.observe("cpu");
  } catch (_) {
    pressure = null;
  }
}

function bytes(n) {
  return n == null ? "-" : `${(n / (1 << 20)).toFixed(1)} MiB`;
}

function addRow(r) {
  const tr = document.createElement("tr");
  const cells = [
    `${r.run_kind} ${r.run_index}`,
    r.outcome,
    r.proving_ms == null ? "-" : `${(r.proving_ms / 1000).toFixed(3)} s`,
    r.verification_ms == null ? "-" : `${r.verification_ms.toFixed(1)} ms`,
    r.proof_bytes ?? "-",
    bytes(r.peak_wasm_memory_bytes),
  ];
  for (const c of cells) {
    const td = document.createElement("td");
    td.textContent = c;
    tr.appendChild(td);
  }
  $("runs").querySelector("tbody").appendChild(tr);
}

function render() {
  $("records").textContent = records.map((r) => JSON.stringify(r)).join("\n");
}

function sessionFields() {
  const device = $("device").value;
  return {
    device_class: device,
    device: DEVICE_LABELS[device],
    cpu_throttling: device === "emulated-phone" ? "DevTools CPU throttling 4x" : "none",
    session: Number($("session").value),
    repository_commit: $("commit").value || "unknown",
    counts_toward_target: true,
    ...env,
  };
}

function run() {
  const warm = Math.max(0, Number($("warm").value));
  const seed = Number($("seed").value) >>> 0;
  const base = sessionFields();
  const worker = new Worker(new URL(WORKER, import.meta.url), { type: "module" });
  let expected = warm + 1;
  $("run").disabled = true;
  $("status").textContent = "running…";
  $("status").className = "";

  const finish = (text, cls) => {
    $("status").textContent = text;
    $("status").className = cls;
    $("download").disabled = records.length === 0;
    $("download-proofs").disabled = proofLines.length === 0;
    worker.terminate();
  };

  worker.onmessage = (ev) => {
    const msg = ev.data;
    if (msg.type === "record") {
      const r = { ...base, ...msg.record, cpu_pressure: pressure };
      if (msg.proof) {
        r.proof_label = `${r.device_class}-session${r.session}-run${r.run_index}`;
        proofLines.push(`${r.proof_label}\t${msg.proof.reveal}\t${msg.proof.proof}`);
      }
      records.push(r);
      addRow(r);
      render();
      expected -= 1;
      if (r.outcome === "refused") {
        finish(`refused: ${r.reason}`, "warn");
      } else if (expected === 0) {
        finish("session complete", "ok");
      }
    }
  };
  worker.onerror = (ev) => {
    // The worker died (for instance the browser killed it); the remaining
    // runs of the session are recorded as killed.
    for (let i = warm + 1 - expected; i <= warm; i += 1) {
      const r = {
        ...base,
        statement: QUERY.statement || "coin-reveal",
        run_index: i,
        run_kind: i === 0 ? "cold" : "warm",
        outcome: "killed",
        reason: ev.message || "worker error",
      };
      records.push(r);
      addRow(r);
    }
    render();
    finish("worker stopped", "warn");
  };
  worker.postMessage({
    type: "run",
    witnessSeed: seed,
    sameKey: !$("newkey").checked,
    warm,
    query: QUERY,
  });
}

function save(text, type, name) {
  const blob = new Blob([text], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function download() {
  const footprint = Number($("footprint").value);
  const lines = records.map((r) => {
    const out = { ...r };
    if (footprint > 0) out.process_peak_memory_bytes = Math.round(footprint * (1 << 20));
    return JSON.stringify(out);
  });
  const first = records[0] || {};
  save(lines.join("\n") + "\n", "application/x-ndjson", `${first.device_class}-coin-reveal-session${first.session}.jsonl`);
}

function downloadProofs() {
  const first = records[0] || {};
  save(proofLines.join("\n") + "\n", "text/plain", `${first.device_class}-coin-reveal-session${first.session}.proofs`);
}

async function main() {
  $("seed").value = crypto.getRandomValues(new Uint32Array(1))[0];
  $("newkey").checked = Number($("session").value) % 2 === 1;
  $("session").addEventListener("change", () => {
    $("newkey").checked = Number($("session").value) % 2 === 1;
  });
  env = await collectEnvironment();
  await watchPressure();
  const warnings = [];
  if (!env.cross_origin_isolated) warnings.push("page is not cross-origin isolated: serve it with serve.py");
  if (!env.simd_available) warnings.push("WebAssembly SIMD is not available");
  $("env").textContent = JSON.stringify(env, null, 2) + (warnings.length ? `\n\n${warnings.join("\n")}` : "");
  $("run").addEventListener("click", run);
  $("download").addEventListener("click", download);
  $("download-proofs").addEventListener("click", downloadProofs);
}

main();
