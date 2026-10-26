// get/vercel/config.json, read as text: curl, Wget and PowerShell at / get
// the sh script, everyone else gets the page, /win and /cmd serve their
// scripts whatever the user agent, and scripts are plain text that is
// neither sniffed nor cached. The routes are walked the way the Build
// Output API applies them, over a dist built from a signed fixture release.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { extname, join } from "node:path";
import { after, before, test } from "node:test";

import { build, releaseFromDir, WIN_STUB } from "../build.mjs";
import { FIXTURES, keyPair, makeRelease } from "./support/release.mjs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const configText = read("../vercel/config.json");
const config = JSON.parse(configText);
const page = read("../index.html");
const PLAIN = "text/plain; charset=utf-8";

const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".mjs": "text/javascript; charset=utf-8" };

// One request through the routes: headers collected along the way, the
// path rewritten by dest, then the file from the static folder.
function serve(dist, path, userAgent) {
  const headers = {};
  const reqHeaders = { "user-agent": userAgent };
  let current = path;
  for (const route of config.routes) {
    if (route.handle === "filesystem") break;
    if (!new RegExp(`^${route.src}$`).test(current)) continue;
    const has = route.has ?? [];
    const matches = has.every((h) => {
      assert.equal(h.type, "header");
      const value = reqHeaders[h.key.toLowerCase()];
      return value !== undefined && new RegExp(h.value).test(value);
    });
    if (!matches) continue;
    for (const [k, v] of Object.entries(route.headers ?? {})) headers[k.toLowerCase()] = v;
    if (route.dest) current = route.dest;
    if (!route.continue) break;
  }
  const file = current === "/" ? "index.html" : current.slice(1);
  const full = join(dist, file);
  if (!existsSync(full)) return { status: 404, headers, file };
  headers["content-type"] ??= config.overrides?.[file]?.contentType ?? TYPES[extname(file)];
  return { status: 200, headers, file, body: readFileSync(full, "utf8") };
}

const AGENTS = {
  curl: "curl/8.7.1",
  wget: "Wget/1.24.5",
  wget2: "wget2/2.1.0",
  powershell: "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22631; en-US) PowerShell/7.4.6",
  windowsPowershell: "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.4391",
  chrome: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  firefox: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
  edge: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
  none: undefined,
};

let full; // every script published
let shOnly; // only install.sh published

before(async () => {
  const keys = keyPair();
  full = makeRelease({ privateKey: keys.privateKey });
  await build({ release: releaseFromDir(full.dir), publicKey: keys.publicPem, out: full.out });
  shOnly = makeRelease({ privateKey: keys.privateKey, scripts: ["install.sh"] });
  await build({ release: releaseFromDir(shOnly.dir), publicKey: keys.publicPem, out: shOnly.out });
});

after(() => {
  full?.cleanup();
  shOnly?.cleanup();
});

function assertScript(res, body) {
  assert.equal(res.status, 200);
  assert.equal(res.body, body);
  assert.equal(res.headers["content-type"], PLAIN);
  assert.equal(res.headers["x-content-type-options"], "nosniff");
  assert.equal(res.headers["cache-control"], "no-store");
}

test("config.json is a version 3 Build Output config whose first route sets headers and continues", () => {
  assert.equal(config.version, 3);
  assert.equal(config.routes[0].src, "/(.*)");
  assert.equal(config.routes[0].continue, true);
  assert.deepEqual(config.routes.at(-1), { handle: "filesystem" });
});

for (const name of ["curl", "wget", "wget2", "powershell", "windowsPowershell"]) {
  test(`${name} at / gets the signed install.sh as plain text`, () => {
    const res = serve(full.out, "/", AGENTS[name]);
    assert.equal(res.file, "install.sh");
    assertScript(res, FIXTURES["install.sh"]);
  });
}

for (const name of ["chrome", "firefox", "edge", "none"]) {
  test(`${name} at / gets the page`, () => {
    const res = serve(full.out, "/", AGENTS[name]);
    assert.equal(res.file, "index.html");
    assert.equal(res.status, 200);
    assert.match(res.body, /<title>Run a Ghost node<\/title>/);
    assert.match(res.headers["content-type"], /^text\/html/);
    assert.equal(res.headers.vary, "User-Agent");
  });
}

test("/win and /cmd serve the signed scripts whatever the user agent", () => {
  for (const ua of Object.values(AGENTS)) {
    assertScript(serve(full.out, "/win", ua), FIXTURES["install.ps1"]);
    assertScript(serve(full.out, "/cmd", ua), FIXTURES["install.cmd"]);
    assertScript(serve(full.out, "/install.sh", ua), FIXTURES["install.sh"]);
  }
});

test("without the Windows scripts in the release, /win serves the stub as plain text", () => {
  assertScript(serve(shOnly.out, "/win", AGENTS.powershell), WIN_STUB);
  assert.match(serve(shOnly.out, "/", AGENTS.chrome).body, /data-ready="sh"/);
});

test("the page is served with a strict Content-Security-Policy: the page's own plus frame-ancestors 'none'", () => {
  const res = serve(full.out, "/", AGENTS.chrome);
  const csp = res.headers["content-security-policy"];
  const meta = page.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)[1];
  assert.equal(csp, `${meta}; frame-ancestors 'none'`);
  const directives = csp.split(";").map((d) => d.trim());
  assert.equal(directives[0], "default-src 'none'");
  assert.ok(directives.includes("script-src 'self'"));
  assert.doesNotMatch(csp, /unsafe-|\*|data:|http:/);
  assert.equal(res.headers["x-content-type-options"], "nosniff");
  assert.equal(res.headers["referrer-policy"], "no-referrer");
  assert.equal(res.headers["x-frame-options"], "DENY");
});

test("every script is typed as plain text in the overrides and on its route", () => {
  for (const file of ["install.sh", "win", "cmd"]) {
    assert.equal(config.overrides[file].contentType, PLAIN, file);
  }
  for (const route of config.routes.filter((r) => r.dest)) {
    assert.equal(route.dest, "/install.sh", "the only rewrite is / to install.sh");
    assert.equal(route.src, "/");
    assert.equal(route.headers["Content-Type"], PLAIN);
    assert.equal(route.headers["Cache-Control"], "no-store");
  }
});

test("the config injects nothing, sets no cookie and points nowhere else", () => {
  const text = configText.toLowerCase();
  for (const word of ["analytics", "insights", "<script", "toolbar", "set-cookie", "functions", "middleware", "http://", "https://"]) {
    assert.ok(!text.includes(word), `config.json mentions ${word}`);
  }
  for (const route of config.routes) assert.ok(!("status" in route), JSON.stringify(route));
});
