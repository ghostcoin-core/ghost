// build.sh copies into dist every module the page and its workers load. The
// unit tests import from src, never from dist, so a module the build leaves
// out only shows on the hosted page, as a 404 that stops app.mjs. Here the
// build's own list (build.sh --modules, which builds nothing) is checked
// against the relative imports in src, and the way build.sh follows them is
// run on a small fixture page.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const webapp = fileURLToPath(new URL("..", import.meta.url));
const buildPath = join(webapp, "build.sh");
const build = readFileSync(buildPath, "utf8");
const page = readFileSync(join(webapp, "index.html"), "utf8");
const sources = readdirSync(join(webapp, "src"))
  .filter((f) => f.endsWith(".mjs"))
  .sort();
const source = (file) => readFileSync(join(webapp, "src", file), "utf8");

// Runs `build.sh --modules`, only once build.sh is known to stop there,
// before any toolchain or cargo step: this test must never start a build.
function listModules(script) {
  const option = build.indexOf('"--modules"');
  assert.ok(option > 0, "build.sh has a --modules option that lists the modules it copies");
  assert.ok(option < build.indexOf("rustup run"), "build.sh --modules stops before the toolchain checks");
  assert.ok(option < build.indexOf("cargo "), "build.sh --modules stops before cargo");
  return spawnSync("bash", [script, "--modules"], { encoding: "utf8", timeout: 20000 });
}

function builtModules() {
  const run = listModules(buildPath);
  assert.equal(run.status, 0, run.stderr);
  return run.stdout.split("\n").filter(Boolean);
}

// Every relative module path a file names in a string: imports and exports
// from it, import() of it, and new URL() of it (a Worker's script), in any
// quote. Paths, relative to src, without .mjs.
function relativeModules(text, file) {
  const names = [];
  for (const m of text.matchAll(/(["'`])(\.{1,2}\/[^"'`\s$]*\.m?js)\1/g)) {
    const path = posix.normalize(posix.join(posix.dirname(file), m[2]));
    names.push(path.replace(/\.mjs$/, ""));
  }
  return names;
}

// The modules index.html loads itself.
function pageEntries(html) {
  return [...html.matchAll(/<script[^>]*\bsrc="([^"]+)"/g)].map((m) => {
    assert.match(m[1], /^src\/[\w-]+\.mjs$/, `index.html loads ${m[1]} from src`);
    return m[1].slice("src/".length, -".mjs".length);
  });
}

test("build.sh lists its modules without building anything", () => {
  const modules = builtModules();
  assert.ok(modules.length > 0);
  assert.equal(new Set(modules).size, modules.length, "each module once");
  for (const m of modules) assert.ok(sources.includes(`${m}.mjs`), `src/${m}.mjs exists`);
});

test("every relative import anywhere in webapp/src names a module build.sh copies", () => {
  const modules = new Set(builtModules());
  let imports = 0;
  for (const file of sources) {
    for (const name of relativeModules(source(file), file)) {
      imports += 1;
      assert.ok(modules.has(name), `src/${file} loads ./${name}.mjs, which build.sh does not copy into dist`);
    }
  }
  assert.ok(imports > 0, "src has relative imports");
});

test("build.sh copies the page's entry, both workers, and the modules the restore added", () => {
  const modules = builtModules();
  for (const entry of pageEntries(page)) assert.ok(modules.includes(entry), entry);
  for (const m of ["app", "worker", "thread", "buckets", "receipts-at", "header", "flow"]) {
    assert.ok(modules.includes(m), `build.sh copies src/${m}.mjs`);
  }
});

test("build.sh copies exactly the modules the page reaches from index.html", () => {
  const reached = [];
  const queue = pageEntries(page);
  while (queue.length > 0) {
    const name = queue.shift();
    if (reached.includes(name)) continue;
    reached.push(name);
    queue.push(...relativeModules(source(`${name}.mjs`), `${name}.mjs`));
  }
  assert.deepEqual([...builtModules()].sort(), reached.sort());
});

test("build.sh copies the modules it found, not a fixed list", () => {
  assert.doesNotMatch(build, /^modules=\([^)]/m, "no fixed module list");
  assert.match(build, /^page_modules$/m);
  assert.match(build, /for m in "\$\{modules\[@\]\}"; do\n\s+cp "\$here\/src\/\$m\.mjs" "\$dist\/src\/\$m\.mjs"\n\s*done/);
  assert.ok(build.indexOf("\npage_modules\n") < build.indexOf("rustup run"), "the modules are found before the long build");
});

// A copy of build.sh beside a fixture page, so the way it follows imports runs
// on files whose every form is known.
function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), "build-modules-"));
  mkdirSync(join(dir, "src"));
  copyFileSync(buildPath, join(dir, "build.sh"));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  return dir;
}

test("build.sh follows every form of relative import, and only from the page's entry", () => {
  const dir = fixture({
    "index.html": '<!doctype html>\n<script type="module" src="src/main.mjs"></script>\n',
    "src/main.mjs": [
      "// Comments naming other.mjs or flow.mjs load nothing.",
      'import { a } from "./a.mjs";',
      "import {",
      "  b,",
      "  c,",
      '} from "./multi-line.mjs";',
      'export { d } from "./re-export.mjs";',
      'import "./side-effect.mjs";',
      "const lazy = () => import('./dynamic.mjs');",
      'const w = new Worker(new URL("./page-worker.mjs", import.meta.url), { type: "module" });',
    ].join("\n"),
    "src/a.mjs": 'import { main } from "./main.mjs";\n',
    "src/multi-line.mjs": "export const b = 1, c = 2;\n",
    "src/re-export.mjs": 'export * from "./a.mjs";\n',
    "src/side-effect.mjs": "",
    "src/dynamic.mjs": "",
    "src/page-worker.mjs": 'import { t } from "./from-worker.mjs";\nnew Worker(new URL("./sub-thread.mjs", import.meta.url));\n',
    "src/from-worker.mjs": "",
    "src/sub-thread.mjs": "",
    "src/unused.mjs": 'import { x } from "./a.mjs";\n',
  });
  try {
    const run = listModules(join(dir, "build.sh"));
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(run.stdout.split("\n").filter(Boolean).sort(), [
      "a",
      "dynamic",
      "from-worker",
      "main",
      "multi-line",
      "page-worker",
      "re-export",
      "side-effect",
      "sub-thread",
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("build.sh stops when the page loads a module src does not have", () => {
  const dir = fixture({
    "index.html": '<script type="module" src="src/main.mjs"></script>\n',
    "src/main.mjs": 'import { gone } from "./gone.mjs";\n',
  });
  try {
    const run = listModules(join(dir, "build.sh"));
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /src\/gone\.mjs/);
    assert.equal(run.stdout, "");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
