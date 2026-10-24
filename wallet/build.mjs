// Builds the pop-up wallet into a folder (wallet/dist unless given):
//
//   1. copies its files under their repository paths, so no import is
//      rewritten, and index.html to the folder's root;
//   2. writes the WebAssembly module as one base64 ES module,
//      wallet/src/ghost-wasm.mjs, since the wallet fetches nothing;
//   3. adds an SRI hash (sha384) to every script and stylesheet tag of
//      index.html, the module preloads included;
//   4. writes RELEASE.json with the SHA-256 of every file.
//
// Nothing depends on the time or the machine: the same commit and module
// give the same bytes.
//
// Usage: node wallet/build.mjs [out]   (GHOST_WEBAPP_WASM: another module)

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(process.argv[2] || join(repo, "wallet/dist"));
const wasm = process.env.GHOST_WEBAPP_WASM || join(repo, "webapp/wasm/target/wasm32-unknown-unknown/release/ghost_webapp_wasm.wasm");

const copied = [
  "wallet/headers.json",
  "wallet/style.css",
  "wallet/src/config.mjs",
  "wallet/src/main.mjs",
  "wallet/src/wallet.mjs",
  "webapp/src/bytes.mjs",
  "webapp/src/wasm.mjs",
];
const files = new Map(copied.map((path) => [path, readFileSync(join(repo, path))]));
const base64 = readFileSync(wasm).toString("base64");
files.set("wallet/src/ghost-wasm.mjs", Buffer.from(`// Written by wallet/build.mjs: ghost_webapp_wasm.wasm in base64.\nexport const WASM = "${base64}";\n`));

const sri = (bytes) => `sha384-${createHash("sha384").update(bytes).digest("base64")}`;
const page = readFileSync(join(repo, "wallet/index.html"), "utf8").replace(
  /<(script|link)\b([^>]*) (src|href)="([^"]+)"([^>]*)>/g,
  (tag, name, before, attr, path, after) => {
    if (!files.has(path)) throw new Error(`index.html names ${path}, which the build does not copy`);
    return `<${name}${before} ${attr}="${path}" integrity="${sri(files.get(path))}"${after}>`;
  },
);
files.set("index.html", Buffer.from(page));

rmSync(out, { recursive: true, force: true });
const release = {};
for (const path of [...files.keys()].sort()) {
  mkdirSync(dirname(join(out, path)), { recursive: true });
  writeFileSync(join(out, path), files.get(path));
  release[path] = createHash("sha256").update(files.get(path)).digest("hex");
}
writeFileSync(join(out, "RELEASE.json"), `${JSON.stringify({ files: release }, null, 2)}\n`);
console.log(`built ${out}`);
