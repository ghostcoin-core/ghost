// The hosted site: webapp/vercel/config.json sets the page's security
// headers and content types, and the deploy workflow builds with build.sh
// and deploys the result as a prebuilt site with a pinned Vercel CLI, only
// after a merge. Both files are read as text; nothing is built.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const config = JSON.parse(read("../vercel/config.json"));
const workflow = read("../../.github/workflows/deploy-webapp.yml");
const page = read("../index.html");
const buildScript = read("../build.sh");

// The route every path takes, with its headers.
function allPaths() {
  const route = config.routes.find((r) => r.src === "/(.*)");
  assert.ok(route, "config.json has a route for all paths");
  return route;
}

function header(name) {
  const headers = allPaths().headers;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  assert.ok(key, `config.json sets ${name}`);
  return headers[key];
}

function pagePolicy() {
  const match = page.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
  assert.ok(match, "index.html carries a Content-Security-Policy");
  return match[1];
}

const directives = (policy) =>
  policy
    .split(";")
    .map((d) => d.trim())
    .filter(Boolean);

test("config.json is a version 3 Build Output config whose headers route continues", () => {
  assert.equal(config.version, 3);
  const route = allPaths();
  assert.equal(route.continue, true);
  assert.equal(config.routes.indexOf(route), 0, "the header route comes first");
});

test("the Content-Security-Policy header is the page's policy plus frame-ancestors 'none'", () => {
  const served = directives(header("Content-Security-Policy"));
  const ancestors = served.filter((d) => d.startsWith("frame-ancestors"));
  assert.deepEqual(ancestors, ["frame-ancestors 'none'"]);
  // A meta tag cannot carry frame-ancestors; everything else is the page's text.
  assert.deepEqual(
    served.filter((d) => !d.startsWith("frame-ancestors")),
    directives(pagePolicy()),
  );
  assert.equal(header("Content-Security-Policy"), `${pagePolicy()}; frame-ancestors 'none'`);
  assert.ok(!header("Content-Security-Policy").includes("unsafe-" + "inline"));
});

test("the other security headers are set", () => {
  assert.equal(header("Referrer-Policy"), "no-referrer");
  assert.equal(header("X-Content-Type-Options"), "nosniff");
  // Pop-ups keep their opener: the pop-up wallet on its own origin answers
  // the page over postMessage, which a same-origin policy would cut.
  assert.equal(header("Cross-Origin-Opener-Policy"), "same-origin-allow-popups");
  // The embedder policy, for the threaded prover's shared memory.
  assert.equal(header("Cross-Origin-Embedder-Policy"), "require-corp");
  assert.equal(header("X-Frame-Options"), "DENY");
});

test("the WebAssembly modules are served as application/wasm and SHA256SUMS as text", () => {
  // The modules' names in dist, as build.sh copies them.
  const wasm = [...buildScript.matchAll(/"\$dist\/([\w.-]+\.wasm)"/g)].map((m) => m[1]);
  assert.deepEqual(wasm, ["ghost_webapp_wasm.wasm", "ghost_webapp_wasm_threads.wasm"]);
  for (const name of wasm) assert.equal(config.overrides?.[name]?.contentType, "application/wasm", name);
  assert.match(config.overrides?.SHA256SUMS?.contentType ?? "", /^text\/plain/);
});

test("the config injects nothing and rewrites no path", () => {
  const text = read("../vercel/config.json").toLowerCase();
  for (const word of ["analytics", "insights", "<script", "toolbar"]) {
    assert.ok(!text.includes(word), `config.json mentions ${word}`);
  }
  for (const route of config.routes) {
    assert.ok(!("dest" in route) && !("status" in route), JSON.stringify(route));
  }
});

test("the workflow runs after a merge to main or by hand, never on a proposed change", () => {
  const on = workflow.slice(workflow.indexOf("\non:"), workflow.indexOf("\npermissions:"));
  assert.match(on, /\n {2}push:\n {4}branches: \[main\]\n/);
  assert.match(on, /\n {2}workflow_dispatch:/);
  const triggers = [...on.matchAll(/^ {2}(\w+):/gm)].map((m) => m[1]);
  assert.deepEqual(triggers, ["push", "workflow_dispatch"]);
  assert.ok(!workflow.includes("pull_" + "request"));
  assert.match(workflow, /runs-on: ubuntu-/);
  assert.doesNotMatch(workflow, /self-hosted/);
});

test("every action is pinned by commit", () => {
  const uses = [...workflow.matchAll(/uses: (\S+)/g)].map((m) => m[1]);
  assert.ok(uses.length > 0);
  for (const use of uses) {
    assert.match(use, /@[0-9a-f]{40}$/, use);
  }
});

test("the workflow builds with build.sh's toolchain and lays out the prebuilt site", () => {
  const toolchain = buildScript.match(/^toolchain="([^"]+)"/m)[1];
  assert.match(workflow, new RegExp(`RUST_TOOLCHAIN: ${toolchain.replaceAll(".", "\\.")}\\n`));
  assert.match(workflow, /rustup toolchain install "\$RUST_TOOLCHAIN"/);
  assert.match(workflow, /run: webapp\/build\.sh\n/);
  assert.match(workflow, /cp -R webapp\/dist\/\. \.vercel\/output\/static\//);
  assert.match(workflow, /cp webapp\/vercel\/config\.json \.vercel\/output\/config\.json/);
});

test("the Vercel CLI is pinned to an exact version and deploys the prebuilt site to production", () => {
  const pin = workflow.match(/VERCEL_CLI_VERSION: (\S+)/);
  assert.ok(pin, "the workflow pins the Vercel CLI");
  assert.match(pin[1], /^\d+\.\d+\.\d+$/);
  assert.match(workflow, /npm install --global [^\n]*"vercel@\$VERCEL_CLI_VERSION"/);
  assert.doesNotMatch(workflow, /vercel@(?!\$VERCEL_CLI_VERSION)/);
  assert.doesNotMatch(workflow, /latest/);
  assert.match(workflow, /vercel deploy --prebuilt --prod/);
});

test("the workflow uses the three repository secrets", () => {
  for (const name of ["VERCEL_TOKEN", "VERCEL_ORG_ID", "VERCEL_PROJECT_ID"]) {
    assert.ok(workflow.includes(`${name}: \${{ secrets.${name} }}`), name);
  }
});
