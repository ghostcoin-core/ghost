// get/build.mjs: every script is checked against the release key before it
// is served, install.sh must be there, and the Windows scripts fall back to
// a stub only when the release does not carry them. The release is a
// temporary folder of fixture scripts signed in the test; the URL release
// is driven by a fake fetch. Nothing touches the network.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { build, CMD_STUB, RELEASE_URL, releaseFromDir, releaseFromUrl, WIN_STUB } from "../build.mjs";
import { FIXTURES, keyPair, makeRelease, signature } from "./support/release.mjs";

const getDir = fileURLToPath(new URL("..", import.meta.url));
const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const keys = keyPair();
const other = keyPair();

async function buildFrom(options, publicKey = keys.publicPem) {
  const rel = makeRelease({ privateKey: keys.privateKey, ...options });
  const result = await build({ release: releaseFromDir(rel.dir), publicKey, out: rel.out }).then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  return { ...rel, ...result };
}

// A stale dist from an earlier build, which a failed build must not leave.
function staleDist(out) {
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "install.sh"), "stale\n");
}

test("release-key.pub is the ghost-node release key, an ed25519 public key", () => {
  const pem = read("../release-key.pub");
  assert.equal(
    pem,
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaXYrmAQBL2GOex7Gk5uAi/2q/0DxRZwTbYyVPGQVHfE=\n-----END PUBLIC KEY-----\n",
  );
  assert.equal(createPublicKey(pem).asymmetricKeyType, "ed25519");
});

test("a full signed release is served byte for byte and the page lists every script as ready", async (t) => {
  const r = await buildFrom({});
  t.after(r.cleanup);
  assert.ifError(r.error);
  assert.deepEqual(r.value.ready, ["sh", "win", "cmd"]);
  assert.equal(readFileSync(join(r.out, "install.sh"), "utf8"), FIXTURES["install.sh"]);
  assert.equal(readFileSync(join(r.out, "win"), "utf8"), FIXTURES["install.ps1"]);
  assert.equal(readFileSync(join(r.out, "cmd"), "utf8"), FIXTURES["install.cmd"]);
  const html = readFileSync(join(r.out, "index.html"), "utf8");
  assert.match(html, /<html lang="en" data-ready="sh win cmd">/);
  assert.equal(readFileSync(join(r.out, "src/page.mjs"), "utf8"), read("../src/page.mjs"));
  assert.equal(readFileSync(join(r.out, "style.css"), "utf8"), read("../style.css"));
  assert.ok(!existsSync(`${r.out}.partial`));
});

test("without install.ps1 and install.cmd the build succeeds and serves the not-published stubs", async (t) => {
  const r = await buildFrom({ scripts: ["install.sh"] });
  t.after(r.cleanup);
  assert.ifError(r.error);
  assert.deepEqual(r.value.ready, ["sh"]);
  assert.equal(readFileSync(join(r.out, "install.sh"), "utf8"), FIXTURES["install.sh"]);
  assert.equal(readFileSync(join(r.out, "win"), "utf8"), WIN_STUB);
  assert.equal(readFileSync(join(r.out, "cmd"), "utf8"), CMD_STUB);
  assert.match(readFileSync(join(r.out, "index.html"), "utf8"), /data-ready="sh"/);
});

test("the stubs only say the installer is not published yet and fail", () => {
  for (const stub of [WIN_STUB, CMD_STUB]) {
    assert.match(stub, /not published yet/);
    assert.ok(stub.length < 300, "the stub is tiny");
    for (const word of ["Invoke-", "iex", "irm", "iwr", "curl", "wget", "bitsadmin", "Start-Process", "powershell", "del "]) {
      assert.ok(!stub.toLowerCase().includes(word.toLowerCase()), `the stub runs ${word}`);
    }
  }
  // PowerShell under irm | iex: a throw fails the command without closing
  // the window the way exit would.
  assert.match(WIN_STUB, /^throw '/m);
  assert.doesNotMatch(WIN_STUB, /\bexit\b/);
  assert.match(CMD_STUB, /^@echo off\r\n/);
  assert.match(CMD_STUB, /\r\nexit \/b 1\r\n$/);
});

test("a Windows script without its signature is served as the stub", async (t) => {
  const r = await buildFrom({ sigs: { "install.ps1": null } });
  t.after(r.cleanup);
  assert.ifError(r.error);
  assert.deepEqual(r.value.ready, ["sh", "cmd"]);
  assert.equal(readFileSync(join(r.out, "win"), "utf8"), WIN_STUB);
  assert.equal(readFileSync(join(r.out, "cmd"), "utf8"), FIXTURES["install.cmd"]);
});

const failures = [
  ["install.sh is missing", { scripts: ["install.ps1", "install.cmd"] }, /install\.sh: not in the release/],
  ["install.sh has no signature", { sigs: { "install.sh": null } }, /install\.sh: no signature/],
  ["install.sh is signed by another key", { sigs: { "install.sh": signature(other.privateKey, FIXTURES["install.sh"]) } }, /install\.sh: the signature does not verify/],
  ["install.sh's signature is of other bytes", { sigs: { "install.sh": signature(keys.privateKey, "echo something else\n") } }, /install\.sh: the signature does not verify/],
  ["install.sh's signature is not 64 bytes", { sigs: { "install.sh": signature(keys.privateKey, FIXTURES["install.sh"]).subarray(0, 63) } }, /install\.sh: the signature does not verify/],
  ["install.ps1's signature is bad", { sigs: { "install.ps1": signature(other.privateKey, FIXTURES["install.ps1"]) } }, /install\.ps1: the signature does not verify/],
  ["install.cmd's signature is bad", { sigs: { "install.cmd": signature(other.privateKey, FIXTURES["install.cmd"]) } }, /install\.cmd: the signature does not verify/],
];

for (const [name, options, message] of failures) {
  test(`the build fails and leaves no dist when ${name}`, async (t) => {
    const rel = makeRelease({ privateKey: keys.privateKey, ...options });
    t.after(rel.cleanup);
    staleDist(rel.out);
    await assert.rejects(build({ release: releaseFromDir(rel.dir), publicKey: keys.publicPem, out: rel.out }), message);
    assert.ok(!existsSync(rel.out), "no dist is left");
    assert.ok(!existsSync(`${rel.out}.partial`), "no partial dist is left");
  });
}

test("a release signed with a key other than the one given fails", async (t) => {
  const r = await buildFrom({}, other.publicPem);
  t.after(r.cleanup);
  assert.match(r.error?.message ?? "", /install\.sh: the signature does not verify/);
  assert.ok(!existsSync(r.out));
});

function runCli(releaseDir, out) {
  return spawnSync(process.execPath, [join(getDir, "build.mjs"), out], {
    env: { ...process.env, GET_RELEASE_DIR: releaseDir },
    encoding: "utf8",
  });
}

test("the build command checks against release-key.pub and exits non-zero with no dist on a foreign signature", (t) => {
  // Signed with the test's key, not the release key's.
  const rel = makeRelease({ privateKey: keys.privateKey });
  t.after(rel.cleanup);
  staleDist(rel.out);
  const run = runCli(rel.dir, rel.out);
  assert.notEqual(run.status, 0, run.stdout);
  assert.match(run.stderr, /install\.sh: the signature does not verify/);
  assert.ok(!existsSync(rel.out));
});

test("the build command exits non-zero with no dist when install.sh is missing", (t) => {
  const rel = makeRelease({ privateKey: keys.privateKey, scripts: [] });
  t.after(rel.cleanup);
  const run = runCli(rel.dir, rel.out);
  assert.notEqual(run.status, 0, run.stdout);
  assert.match(run.stderr, /install\.sh: not in the release/);
  assert.ok(!existsSync(rel.out));
});

// A fake fetch over the fixture files, recording every URL asked for.
function fakeFetch(files, status = {}) {
  const asked = [];
  const fetchImpl = async (url) => {
    asked.push(url);
    const name = url.slice(url.lastIndexOf("/") + 1);
    if (status[name]) return new Response("error", { status: status[name] });
    if (!(name in files)) return new Response("Not Found", { status: 404 });
    return new Response(files[name], { status: 200 });
  };
  return { asked, fetchImpl };
}

test("without GET_RELEASE_DIR the scripts come from the latest release's download URLs only", async (t) => {
  assert.equal(RELEASE_URL, "https://github.com/ghostcoin-core/ghost-node/releases/latest/download");
  const files = {
    "install.sh": FIXTURES["install.sh"],
    "install.sh.sig": signature(keys.privateKey, FIXTURES["install.sh"]),
  };
  const { asked, fetchImpl } = fakeFetch(files);
  const rel = makeRelease({ privateKey: keys.privateKey, scripts: [] });
  t.after(rel.cleanup);
  const { ready } = await build({ release: releaseFromUrl(RELEASE_URL, fetchImpl), publicKey: keys.publicPem, out: rel.out });
  assert.deepEqual(ready, ["sh"]);
  assert.equal(readFileSync(join(rel.out, "install.sh"), "utf8"), FIXTURES["install.sh"]);
  assert.equal(readFileSync(join(rel.out, "win"), "utf8"), WIN_STUB);
  assert.deepEqual(
    asked.toSorted(),
    ["install.cmd", "install.cmd.sig", "install.ps1", "install.ps1.sig", "install.sh", "install.sh.sig"].map((n) => `${RELEASE_URL}/${n}`),
  );
});

test("a download error other than not found stops the build rather than serving a stub", async (t) => {
  const files = {
    "install.sh": FIXTURES["install.sh"],
    "install.sh.sig": signature(keys.privateKey, FIXTURES["install.sh"]),
  };
  const { fetchImpl } = fakeFetch(files, { "install.ps1": 503 });
  const rel = makeRelease({ privateKey: keys.privateKey, scripts: [] });
  t.after(rel.cleanup);
  await assert.rejects(
    build({ release: releaseFromUrl(RELEASE_URL, fetchImpl), publicKey: keys.publicPem, out: rel.out }),
    /install\.ps1: HTTP 503/,
  );
  assert.ok(!existsSync(rel.out));
  assert.throws(() => releaseFromUrl("http://github.com/x"), /must be https/);
});

test("the build reads no branch and no raw file host", () => {
  const source = read("../build.mjs");
  for (const word of ["raw.github" + "usercontent.com", "/bl" + "ob/", "/ra" + "w/", "refs/heads", "/main", "/master", "api.github.com"]) {
    assert.ok(!source.includes(word), `build.mjs mentions ${word}`);
  }
  const urls = [...source.matchAll(/https:\/\/[^\s"'`]+/g)].map((m) => m[0]);
  for (const url of urls) {
    assert.ok(
      url === RELEASE_URL || url.startsWith("https://get.ghostcoin.com"),
      `build.mjs names ${url}`,
    );
  }
});
