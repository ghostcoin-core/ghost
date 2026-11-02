// The hosted site: webapp/vercel/config.json sets the page's security
// headers and content types, and the deploy workflow builds with build.sh
// and deploys the result as a prebuilt site with a pinned Vercel CLI, only
// after a merge. Both files are read as text; nothing is built.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

// The steps under jobs.deploy, by name, in order, each with its text.
function steps() {
  const body = workflow.slice(workflow.indexOf("\n    steps:\n"));
  return body
    .split(/\n {6}- /)
    .slice(1)
    .map((text) => ({ name: text.match(/^(?:uses: \S+[^\n]*\n {8})?name: ([^\n]+)/)?.[1] ?? text.split("\n")[0], text }));
}

test("only the head of main deploys, and a newer run never cancels one in progress", () => {
  assert.match(workflow, /\nconcurrency:\n {2}group: deploy-webapp\n {2}cancel-in-progress: false\n/);
  assert.doesNotMatch(workflow, /cancel-in-progress: true/);
  const all = steps();
  const names = all.map((s) => s.name);
  const check = names.indexOf("Skip if not the head of main");
  const deploy = names.indexOf("Deploy to production");
  const live = names.indexOf("Check the live site");
  assert.ok(check >= 0, "the workflow checks the head of main");
  assert.ok(deploy > check && live > deploy, names.join(", "));
  const head = all[check].text;
  assert.match(head, /\n {8}id: head\n/);
  assert.match(head, /git ls-remote origin refs\/heads\/main/);
  assert.match(head, /"\$head" = "\$GITHUB_SHA"/);
  assert.match(head, /current=false/);
  assert.match(head, /::notice /);
  for (const i of [deploy, live]) {
    assert.match(all[i].text, /\n {8}if: steps\.head\.outputs\.current == 'true'\n/, names[i]);
  }
});

// The head check's script, run with a stand-in git whose ls-remote prints the
// given head of main (or fails), for each kind of run.
function runHeadCheck({ event, ref, sha, head }) {
  const script = steps()
    .find((s) => s.name === "Skip if not the head of main")
    .text.split("\n        run: |\n")[1]
    .split("\n")
    .map((line) => line.replace(/^ {10}/, ""))
    .join("\n");
  const dir = mkdtempSync(join(tmpdir(), "head-check-"));
  try {
    const git = join(dir, "git");
    const out = head === null ? "exit 128" : `printf '%s\\trefs/heads/main\\n' ${head}`;
    writeFileSync(git, `#!/bin/sh\n[ "$1 $2 $3" = "ls-remote origin refs/heads/main" ] || exit 2\n${out}\n`);
    chmodSync(git, 0o755);
    const output = join(dir, "output");
    writeFileSync(output, "");
    const run = spawnSync("bash", ["-c", script], {
      encoding: "utf8",
      env: {
        PATH: `${dir}:${process.env.PATH}`,
        GITHUB_EVENT_NAME: event,
        GITHUB_REF: ref,
        GITHUB_SHA: sha,
        GITHUB_OUTPUT: output,
      },
    });
    return { status: run.status, stdout: run.stdout, output: readFileSync(output, "utf8") };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the head check deploys only main's current head, for pushes and manual runs", () => {
  const a = "a".repeat(40);
  const b = "b".repeat(40);
  for (const event of ["push", "workflow_dispatch"]) {
    const current = runHeadCheck({ event, ref: "refs/heads/main", sha: a, head: a });
    assert.equal(current.status, 0, event);
    assert.equal(current.output, "current=true\n", event);
    const stale = runHeadCheck({ event, ref: "refs/heads/main", sha: a, head: b });
    assert.equal(stale.status, 0, event);
    assert.equal(stale.output, "current=false\n", event);
    assert.match(stale.stdout, /^::notice /m, event);
  }
  const branch = runHeadCheck({ event: "workflow_dispatch", ref: "refs/heads/other", sha: a, head: a });
  assert.equal(branch.output, "current=false\n");
  const unreadable = runHeadCheck({ event: "push", ref: "refs/heads/main", sha: a, head: null });
  assert.notEqual(unreadable.status, 0);
  assert.doesNotMatch(unreadable.output, /current=true/);
});
