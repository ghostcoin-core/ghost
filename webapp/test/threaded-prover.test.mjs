// The threaded prover: the hosting headers that make the page cross-origin
// isolated (so it can share WebAssembly memory between workers), the build
// of the threaded module beside the single-thread one, how the worker picks
// between them, and the browser results it is held to. Files are read as
// text and nothing is built; only threads.mjs's thread count is run.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  INITIAL_MEMORY_BYTES,
  MAXIMUM_MEMORY_BYTES,
  MAX_THREADS,
  THREAD_STACK_BYTES,
  threadCount,
} from "../src/threads.mjs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const config = JSON.parse(read("../vercel/config.json"));
const page = read("../index.html");
const build = read("../build.sh");
const worker = read("../src/worker.mjs");
const thread = read("../src/thread.mjs");
const cargo = read("../wasm/Cargo.toml");
const lock = read("../wasm/Cargo.lock");
const lib = read("../wasm/src/lib.rs");
const results = read("../../docs/benchmarks/reveal-results.md");

// Spelled in pieces so this file never carries the keywords themselves.
const UNSAFE_EVAL = "'unsafe-" + "eval'";
const UNSAFE_INLINE = "unsafe-" + "inline";

// The configuration the results must name: spec 09, section 4.1's.
const CONFIGURATION = "blowup-2^3/queries-43";
const PENDING = "pending browser measurement";
const TARGET_SECONDS = 10;

function allPathHeaders() {
  const route = config.routes.find((r) => r.src === "/(.*)");
  assert.ok(route, "config.json has a route for all paths");
  return route.headers;
}

function header(name) {
  const headers = allPathHeaders();
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  assert.ok(key, `config.json sets ${name} on all paths`);
  return headers[key];
}

test("every path is served cross-origin isolated", () => {
  assert.equal(header("Cross-Origin-Opener-Policy"), "same-origin");
  assert.equal(header("Cross-Origin-Embedder-Policy"), "require-corp");
  const route = config.routes.find((r) => r.src === "/(.*)");
  assert.equal(config.routes.indexOf(route), 0, "the header route comes first");
  assert.equal(route.continue, true);
});

test("the page's policy still allows no eval and no inline code", () => {
  const meta = page.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
  assert.ok(meta, "index.html carries a Content-Security-Policy");
  for (const policy of [header("Content-Security-Policy"), meta[1]]) {
    assert.ok(!policy.includes(UNSAFE_EVAL), policy);
    assert.ok(!policy.includes(UNSAFE_INLINE), policy);
    assert.match(policy, /script-src 'self' 'wasm-unsafe-eval';/);
    assert.match(policy, /worker-src 'self';/);
  }
  assert.ok(!page.includes(UNSAFE_INLINE));
});

test("build.sh builds the threaded module with threads, atomics and SIMD on a shared memory", () => {
  assert.match(build, /^toolchain="1\.99\.1"$/m, "the single-thread module stays on the pinned toolchain");
  const nightly = build.match(/^threads_toolchain="(nightly-\d{4}-\d{2}-\d{2})"$/m);
  assert.ok(nightly, "build.sh pins a dated nightly for the threaded module");
  // A 1.99 nightly (1.99 was master from 2026-07-03 until it branched for
  // beta in mid-August), the pinned stable's compiler line: the 1.101
  // nightlies panic while compiling p3-monty-31.
  const date = nightly[1].slice("nightly-".length);
  assert.ok(date >= "2026-07-03" && date <= "2026-08-14", `${nightly[1]} is a 1.99 nightly`);
  const flags = build.match(/threads_flags=\(\n([\s\S]*?)\n\)/);
  assert.ok(flags, "build.sh lists the threaded module's flags");
  for (const flag of [
    "-C target-feature=+simd128,+atomics,+bulk-memory,+mutable-globals",
    "-C link-arg=--shared-memory",
    "-C link-arg=--import-memory",
    "-C link-arg=--export=__stack_pointer",
    "-C link-arg=--export=__wasm_init_tls",
    "-C link-arg=--export=__tls_size",
    "-C link-arg=--export=__tls_align",
  ]) {
    assert.ok(flags[1].includes(`"${flag}"`), flag);
  }
  assert.match(
    build,
    /cargo "\+\$threads_toolchain" build --release --locked --offline --target wasm32-unknown-unknown \\\n\s+-Z build-std=std,panic_abort --features threads --target-dir "\$threads_target"/,
  );
  assert.match(build, /RUSTFLAGS="\$remap \$\{threads_flags\[\*\]\}"/);
  // The standard library's own crates are fetched before the offline build
  // rebuilds it.
  const fetchStd = build.search(
    /cargo "\+\$threads_toolchain" fetch --locked -Z build-std=std,panic_abort --target wasm32-unknown-unknown \\\n\s+--manifest-path "\$manifest"/,
  );
  assert.ok(fetchStd > 0, "build.sh fetches the standard library's crates with the nightly");
  assert.ok(fetchStd < build.indexOf("--offline --target wasm32-unknown-unknown \\\n"), "before the offline build");
  // The single-thread module keeps SIMD, as before.
  assert.match(build, /RUSTFLAGS="\$remap -C target-feature=\+simd128" \\\n\s+cargo "\+\$toolchain" build --release --locked --offline/);
});

test("build.sh ships both modules and the thread modules, and links the memory threads.mjs creates", () => {
  assert.match(build, /cp "\$module" "\$dist\/ghost_webapp_wasm\.wasm"/);
  assert.match(build, /cp "\$threads_module" "\$dist\/ghost_webapp_wasm_threads\.wasm"/);
  assert.match(build, /threads_module="\$threads_target\/wasm32-unknown-unknown\/release\/ghost_webapp_wasm\.wasm"/);
  const modules = build.match(/^modules=\(([^)]*)\)$/m)[1].split(/\s+/);
  for (const m of ["thread", "threads", "worker", "worker-core", "wasm"]) assert.ok(modules.includes(m), m);
  assert.equal(Number(build.match(/^threads_initial_memory=(\d+)$/m)[1]), INITIAL_MEMORY_BYTES);
  assert.equal(Number(build.match(/^threads_max_memory=(\d+)$/m)[1]), MAXIMUM_MEMORY_BYTES);
  assert.match(build, /--initial-memory=\$threads_initial_memory/);
  assert.match(build, /--max-memory=\$threads_max_memory/);
  assert.equal(INITIAL_MEMORY_BYTES % 65536, 0);
  assert.equal(MAXIMUM_MEMORY_BYTES, 2 ** 32, "the most a 32-bit memory can grow to");
  assert.equal(config.overrides?.["ghost_webapp_wasm_threads.wasm"]?.contentType, "application/wasm");
  assert.equal(THREAD_STACK_BYTES % 16, 0);
});

test("the threads feature is the proofs crate's parallel prover, locked", () => {
  assert.match(cargo, /^threads = \["dep:rayon", "ghost-proofs\/parallel"\]$/m);
  assert.match(cargo, /^rayon = \{ version = "1\.12\.0", optional = true \}$/m);
  assert.match(lock, /name = "p3-maybe-rayon"\n[^[]*dependencies = \[\n "rayon",\n\]/);
  assert.match(lock, /name = "rayon"\nversion = "1\.12\.0"/);
  assert.match(lock, /name = "rayon-core"\nversion = "1\.13\.0"/);
  assert.match(lock, /name = "ghost-webapp-wasm"\n[^[]*dependencies = \[[^\]]*"rayon",\n\]/);
  for (const name of ["ghost_threads_start", "ghost_thread_run", "ghost_thread_memory"]) {
    assert.match(lib, new RegExp(`#\\[cfg\\(feature = "threads"\\)\\]\\nmod threads \\{[\\s\\S]*pub (unsafe )?extern "C" fn ${name}\\(`));
  }
  assert.match(lib, /\.use_current_thread\(\)/);
});

test("the worker loads the threaded module only when it can share memory, else the single-thread one", () => {
  assert.match(worker, /const SINGLE_MODULE = "ghost_webapp_wasm\.wasm";/);
  assert.match(worker, /const THREADED_MODULE = "ghost_webapp_wasm_threads\.wasm";/);
  assert.match(worker, /new URL\("\.\/thread\.mjs", import\.meta\.url\), \{ type: "module" \}/);
  // Any failure of the threaded start falls back to the single-thread module.
  const load = worker.slice(worker.indexOf("async function loadProver"), worker.indexOf("const onMessage"));
  assert.match(load, /if \(count > 1\) \{\n\s+try \{[\s\S]*THREADED_MODULE[\s\S]*\} catch \{/);
  assert.match(load, /return loadGhost\(await fetchModule\(SINGLE_MODULE\)\);\n\}/);
  // A thread's instance gets its own stack and thread-local storage before
  // any of its code runs.
  const start = thread.indexOf("new WebAssembly.Instance");
  assert.ok(start > 0);
  assert.ok(thread.indexOf("__stack_pointer.value = message.stackTop") > start);
  assert.ok(thread.indexOf("__wasm_init_tls(message.tls)") > thread.indexOf("__stack_pointer.value"));
  assert.ok(thread.indexOf("ghost_thread_run(message.thread)") > thread.indexOf("__wasm_init_tls"));
});

test("threadCount uses threads only on a cross-origin isolated page with more than one core", () => {
  const scope = (isolated, cores, shared = true) => ({
    crossOriginIsolated: isolated,
    SharedArrayBuffer: shared ? SharedArrayBuffer : undefined,
    navigator: { hardwareConcurrency: cores },
  });
  assert.equal(threadCount(scope(false, 8)), 1);
  assert.equal(threadCount(scope(true, 8, false)), 1);
  assert.equal(threadCount(scope(true, 1)), 1);
  assert.equal(threadCount(scope(true, undefined)), 1);
  assert.equal(threadCount(scope(true, 2)), 2);
  assert.equal(threadCount(scope(true, 6)), 6);
  assert.equal(threadCount(scope(true, 18)), MAX_THREADS);
  assert.equal(MAX_THREADS, 8);
});

// The threaded build's section of the results and its table rows.
function threadedSection() {
  const start = results.indexOf("\n## Threaded build");
  assert.ok(start >= 0, "reveal-results.md has a section for the threaded build");
  const end = results.indexOf("\n## ", start + 1);
  return results.slice(start, end < 0 ? undefined : end);
}

function tableRows(section) {
  const lines = section.split("\n").filter((l) => l.startsWith("|") && !/^\|[\s:|-]+\|$/.test(l));
  const head = lines.findIndex((l) => /\| Statement \| Build \| Device \|/.test(l));
  assert.ok(head >= 0, "the section has a results table");
  const names = lines[head].split("|").slice(1, -1).map((c) => c.trim());
  return lines.slice(head + 1).map((line) => {
    const cells = line.split("|").slice(1, -1).map((c) => c.trim());
    return Object.fromEntries(names.map((name, i) => [name, cells[i]]));
  });
}

// A median cell's seconds, or null while it awaits the browser run. Anything
// else is neither and fails.
function seconds(cell, what) {
  if (cell === PENDING) return null;
  const m = cell.match(/^(\d+(?:\.\d+)?) s$/);
  assert.ok(m, `${what}: "${cell}" is neither a median in seconds nor "${PENDING}"`);
  return Number(m[1]);
}

// The browser run of the threaded build happens in Chrome on the Mac Studio
// after merge. Until then its four rows may read "pending browser
// measurement"; a median that is recorded must be under the target, and no
// row may claim the target without both medians.
function checkThreadedRow(row, what) {
  assert.ok(row, `a wasm-threads row for the ${what}`);
  assert.ok(row.Configuration.includes(CONFIGURATION), `${what}: ${row.Configuration}`);
  const cold = seconds(row["Cold median"], `${what} cold`);
  const warm = seconds(row["Warm median"], `${what} warm`);
  if (cold !== null) assert.ok(cold < TARGET_SECONDS, `${what}: cold median ${cold} s`);
  if (warm !== null) assert.ok(warm < TARGET_SECONDS, `${what}: warm median ${warm} s`);
  const meets = row["Meets target"];
  if (cold === null || warm === null) {
    assert.notEqual(meets, "yes", `${what}: meets the target without both medians`);
    assert.equal(meets, PENDING, `${what}: "${meets}" while a median is pending`);
  } else {
    assert.equal(meets, "yes", `${what}: both medians are under ${TARGET_SECONDS} s`);
  }
}

test("the results hold the four threaded rows of both reveals, pending or under 10 s", () => {
  const section = threadedSection();
  assert.ok(section.includes(CONFIGURATION), `the section names ${CONFIGURATION}`);
  const rows = tableRows(section).filter((r) => r.Build === "wasm-threads");
  assert.equal(rows.length, 4, "four wasm-threads rows");
  for (const statement of ["coin reveal", "salted coin reveal"]) {
    for (const device of [/^Mac Studio/, /^emulated mid-range phone/]) {
      const row = rows.find((r) => r.Statement === statement && device.test(r.Device));
      checkThreadedRow(row, `${statement} on ${device.source.slice(1)}`);
    }
  }
});

test("the threaded rows check fails on a median at or over 10 s, or a target met without medians", () => {
  const row = (cold, warm, meets) => ({
    Configuration: CONFIGURATION,
    "Cold median": cold,
    "Warm median": warm,
    "Meets target": meets,
  });
  checkThreadedRow(row(PENDING, PENDING, PENDING), "pending");
  checkThreadedRow(row("8.2 s", "7.9 s", "yes"), "measured");
  assert.throws(() => checkThreadedRow(row("8.2 s", "7.9 s", PENDING), "measured but not marked"));
  assert.throws(() => checkThreadedRow(row("10 s", "7.9 s", "yes"), "cold at 10 s"));
  assert.throws(() => checkThreadedRow(row("8.2 s", "10.4 s", "yes"), "warm over 10 s"));
  assert.throws(() => checkThreadedRow(row("10.4 s", PENDING, PENDING), "cold over, warm pending"));
  assert.throws(() => checkThreadedRow(row(PENDING, PENDING, "yes"), "yes without numbers"));
  assert.throws(() => checkThreadedRow(row("8.2 s", PENDING, "yes"), "yes with one number"));
  assert.throws(() => checkThreadedRow(row("fast", "fast", "yes"), "not a median"));
  assert.throws(() => checkThreadedRow({ ...row(PENDING, PENDING, PENDING), Configuration: "blowup-2^2/queries-43" }, "other configuration"));
});
