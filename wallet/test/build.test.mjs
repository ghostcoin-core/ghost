// The wallet's release: node wallet/build.mjs run twice into temporary
// folders gives the same bytes, a RELEASE.json whose hashes match every
// file, the CSP in the page and in headers.json, SRI on every script and
// stylesheet tag, every module preloaded with its hash, the module carried
// as base64, no opener policy, and nothing that reaches the network.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix, relative } from "node:path";
import { after, test } from "node:test";

import { repoDir, wasmPath } from "./fakes.mjs";

const temp = mkdtempSync(join(tmpdir(), "ghost-wallet-build-"));
after(() => rmSync(temp, { recursive: true, force: true }));

function build(name) {
  const out = join(temp, name);
  execFileSync(process.execPath, [join(repoDir, "wallet/build.mjs"), out], { stdio: "pipe" });
  return out;
}

function files(dir) {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => relative(dir, join(e.parentPath, e.name)).split("\\").join("/"))
    .sort();
}

const first = build("one");
const second = build("two");
const read = (path) => readFileSync(join(first, path));
const text = (path) => read(path).toString("utf8");
const html = text("index.html");
const headers = JSON.parse(text("wallet/headers.json"));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sri = (bytes) => `sha384-${createHash("sha384").update(bytes).digest("base64")}`;
const directives = (policy) =>
  policy
    .split(";")
    .map((d) => d.trim())
    .filter(Boolean);

test("two builds of the same commit are byte for byte the same", () => {
  assert.deepEqual(files(first), files(second));
  for (const path of files(first)) assert.ok(read(path).equals(readFileSync(join(second, path))), path);
});

test("RELEASE.json lists every file with its SHA-256", () => {
  const release = JSON.parse(text("RELEASE.json"));
  const listed = Object.keys(release.files);
  assert.deepEqual(listed, files(first).filter((f) => f !== "RELEASE.json"));
  for (const path of listed) assert.equal(release.files[path], sha256(read(path)), path);
  assert.deepEqual(listed, [
    "index.html",
    "wallet/headers.json",
    "wallet/src/config.mjs",
    "wallet/src/ghost-wasm.mjs",
    "wallet/src/main.mjs",
    "wallet/src/wallet.mjs",
    "wallet/style.css",
    "webapp/src/bytes.mjs",
    "webapp/src/wasm.mjs",
  ]);
  // The sources are copied as they are, under their repository paths.
  for (const path of listed.filter((p) => p !== "index.html" && p !== "wallet/src/ghost-wasm.mjs")) {
    assert.ok(read(path).equals(readFileSync(join(repoDir, path))), path);
  }
});

test("the page's CSP is strict, and headers.json serves it with frame-ancestors 'none'", () => {
  const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html);
  assert.ok(meta, "index.html carries a Content-Security-Policy");
  const page = directives(meta[1]);
  assert.equal(page[0], "default-src 'none'");
  assert.ok(page.includes("script-src 'self' 'wasm-unsafe-eval'"));
  assert.ok(page.includes("connect-src 'none'"));
  assert.ok(page.includes("style-src 'self'"));
  for (const d of page) assert.doesNotMatch(d.replace("'wasm-unsafe-eval'", ""), /unsafe|https?:|\*|data:|blob:/, d);
  assert.equal(headers["Content-Security-Policy"], `${meta[1]}; frame-ancestors 'none'`);
  assert.equal(headers["Referrer-Policy"], "no-referrer");
  assert.equal(headers["X-Content-Type-Options"], "nosniff");
  assert.match(html, /<meta name="referrer" content="no-referrer">/);
  // No opener policy: a pop-up with one of its own is cut off from the page
  // that opened it.
  const opener = ["Cross-Origin", "Opener-Policy"].join("-").toLowerCase();
  for (const name of Object.keys(headers)) assert.notEqual(name.toLowerCase(), opener);
  assert.ok(!html.toLowerCase().includes(opener));
  assert.deepEqual(JSON.parse(readFileSync(join(repoDir, "wallet/headers.json"), "utf8")), headers);
});

test("one script tag, and every script, preload and stylesheet carries its file's SRI hash", () => {
  const scripts = [...html.matchAll(/<script\b[^>]*>/g)].map((m) => m[0]);
  assert.equal(scripts.length, 1);
  assert.match(scripts[0], /^<script type="module" src="wallet\/src\/main\.mjs" integrity="sha384-[A-Za-z0-9+/=]+">$/);
  assert.doesNotMatch(html, /<script\b(?![^>]*\bsrc=)/, "no inline script");
  assert.doesNotMatch(html, /\son[a-z]+=|\sstyle=/i, "no inline handler or style");
  const tags = [...html.matchAll(/<(script|link)\b[^>]*>/g)].map((m) => m[0]);
  for (const tag of tags) {
    const path = /(?:src|href)="([^"]+)"/.exec(tag)[1];
    const integrity = /integrity="([^"]+)"/.exec(tag);
    assert.ok(integrity, `${tag} has an integrity attribute`);
    assert.equal(integrity[1], sri(read(path)), path);
  }

  // Every module main.mjs reaches is preloaded, and nothing else.
  const reached = new Set();
  const visit = (path) => {
    for (const m of text(path).matchAll(/^import\s[^;]*?from\s+"([^"]+)";/gm)) {
      const next = posix.normalize(posix.join(posix.dirname(path), m[1]));
      if (!reached.has(next)) {
        reached.add(next);
        visit(next);
      }
    }
  };
  visit("wallet/src/main.mjs");
  const preloads = [...html.matchAll(/<link rel="modulepreload" href="([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(preloads.sort(), [...reached].sort());
  assert.deepEqual(
    files(first).filter((f) => f.endsWith(".mjs")),
    [...reached, "wallet/src/main.mjs"].sort(),
  );
});

test("the module is carried as base64 in an ES module, the same bytes as the build's", () => {
  const source = text("wallet/src/ghost-wasm.mjs");
  const m = /^\/\/ [^\n]*\nexport const WASM = "([A-Za-z0-9+/=]+)";\n$/.exec(source);
  assert.ok(m, "one base64 export");
  assert.ok(Buffer.from(m[1], "base64").equals(readFileSync(wasmPath)));
});

test("nothing in the release reaches the network, evaluates text, or stores a secret in the clear", () => {
  const banned = [
    ["fet", "ch("],
    ["XMLHttp", "Request"],
    ["Web", "Socket"],
    ["send", "Beacon"],
    ["Event", "Source"],
    ["import", "Scripts"],
    ["import", "("],
    ["ev", "al("],
    ["new ", "Function"],
    ["local", "Storage"],
    ["session", "Storage"],
    ["document", ".cookie"],
    ["export", "Key("],
    ["Math", ".random"],
    ["unsafe", "-inline"],
    ["inner", "HTML"],
  ].map((parts) => parts.join(""));
  for (const path of files(first).filter((f) => f !== "wallet/src/ghost-wasm.mjs")) {
    const body = text(path);
    for (const word of banned) assert.ok(!body.includes(word), `${path} has ${word}`);
  }
  for (const path of ["index.html", "wallet/style.css"]) {
    assert.doesNotMatch(text(path), /https?:\/\/|url\(|@import/i, path);
  }
  // The only addresses in the code are the configured web app origins.
  for (const path of files(first).filter((f) => f.endsWith(".mjs") && f !== "wallet/src/ghost-wasm.mjs")) {
    const urls = text(path).match(/https?:\/\/[^\s"'`)]+/g) ?? [];
    if (path === "wallet/src/config.mjs") assert.ok(urls.length > 0);
    else assert.deepEqual(urls, [], path);
  }
});
