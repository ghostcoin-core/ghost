// Builds get.ghostcoin.com into get/dist: the Run a node page and the three
// install scripts, taken from the latest signed release of
// ghostcoin-core/ghost-node and checked against get/release-key.pub.
//
//   dist/install.sh  the Mac and Linux script (curl -fsSL https://get.ghostcoin.com | sh)
//   dist/win         the PowerShell script (irm https://get.ghostcoin.com/win | iex)
//   dist/cmd         the CMD script
//   dist/favicon.svg the pixel-ghost logo's small cut, copied from get/favicon.svg
//   dist/fonts/      the self-hosted fonts, copied from get/fonts
//
// The release comes from GET_RELEASE_DIR (a local folder) or, when that is
// unset, from the release's latest/download URLs; never from a branch. Each
// script X has X.sig beside it: the raw 64-byte ed25519 signature of X's
// bytes, the way the release signs its archives.
//
// Fail closed: install.sh missing, unsigned or failing its check stops the
// build and leaves no dist. install.ps1 or install.cmd missing (or without a
// signature) is served as a stub that says the installer is not published
// yet and fails; a bad signature on any script stops the build.
//
// Usage: node get/build.mjs [out]   (out defaults to get/dist)

import { createPublicKey, verify } from "node:crypto";
import { mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const RELEASE_URL = "https://github.com/ghostcoin-core/ghost-node/releases/latest/download";

// Served when install.ps1 is not in the release. It downloads and runs
// nothing. It throws rather than calling exit, which would close the
// PowerShell window `irm | iex` runs in; the throw still fails the command.
export const WIN_STUB = `Write-Host 'The Ghost installer for Windows is not published yet. See https://get.ghostcoin.com'
throw 'The Ghost installer for Windows is not published yet.'
`;

// Served when install.cmd is not in the release. It downloads and runs nothing.
export const CMD_STUB =
  "@echo off\r\n" +
  "echo The Ghost installer for Windows is not published yet. See https://get.ghostcoin.com\r\n" +
  "exit /b 1\r\n";

// Each script of the release, the path the site serves it at, and the word
// for it in the page's data-ready.
export const SCRIPTS = [
  { name: "install.sh", serve: "install.sh", ready: "sh", stub: null },
  { name: "install.ps1", serve: "win", ready: "win", stub: WIN_STUB },
  { name: "install.cmd", serve: "cmd", ready: "cmd", stub: CMD_STUB },
];

// The page's own files, copied as they are; index.html also gets data-ready.
export const PAGE_FILES = ["index.html", "style.css", "favicon.svg", "src/page.mjs"];
// The self-hosted fonts and their licence, every file of fonts/ copied
// byte for byte.
export const FONT_DIR = "fonts";
const READY_PLACEHOLDER = 'data-ready="sh"';

// A release read from a local folder. A file that is not there is null.
export function releaseFromDir(dir) {
  return {
    where: dir,
    async get(name) {
      try {
        return new Uint8Array(await readFile(join(dir, name)));
      } catch (err) {
        if (err.code === "ENOENT") return null;
        throw err;
      }
    },
  };
}

// The latest release's assets over HTTPS. A 404 is a file that is not
// there; any other failure stops the build.
export function releaseFromUrl(base = RELEASE_URL, fetchImpl = globalThis.fetch) {
  if (!base.startsWith("https://")) throw new Error(`the release URL must be https: ${base}`);
  return {
    where: base,
    async get(name) {
      const url = `${base}/${name}`;
      const res = await fetchImpl(url, { redirect: "follow", signal: AbortSignal.timeout(60_000) });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
      return new Uint8Array(await res.arrayBuffer());
    },
  };
}

export function loadPublicKey(pem) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(`the release key is ${key.asymmetricKeyType}, not ed25519`);
  }
  return key;
}

// True when sig is the release key's signature of data. A signature that is
// not 64 bytes is a bad one.
export function signedBy(key, data, sig) {
  if (sig.length !== 64) return false;
  return verify(null, data, key, sig);
}

// Reads and checks every script, then writes the site. Nothing is written
// until every script has passed; on any failure out is removed.
export async function build({ release, publicKey, out, log = () => {} }) {
  const staging = `${out}.partial`;
  try {
    const key = typeof publicKey === "string" ? loadPublicKey(publicKey) : publicKey;
    const served = [];
    for (const script of SCRIPTS) {
      const data = await release.get(script.name);
      const sig = await release.get(`${script.name}.sig`);
      if (data && sig) {
        if (!signedBy(key, data, sig)) {
          throw new Error(`${script.name}: the signature does not verify against the release key`);
        }
        log(`${script.name}: signature verified, served at /${script.serve === "install.sh" ? "" : script.serve}`);
        served.push({ ...script, bytes: data, published: true });
      } else if (script.stub === null) {
        throw new Error(`${script.name}: ${data ? "no signature" : "not"} in the release at ${release.where}`);
      } else {
        log(`${script.name}: ${data ? "no signature" : "not"} in the release, /${script.serve} serves the not-published stub`);
        served.push({ ...script, bytes: new TextEncoder().encode(script.stub), published: false });
      }
    }

    const ready = served.filter((s) => s.published).map((s) => s.ready);
    await rm(staging, { recursive: true, force: true });
    await mkdir(join(staging, "src"), { recursive: true });
    for (const file of PAGE_FILES) {
      let text = await readFile(join(here, file), "utf8");
      if (file === "index.html") {
        if (text.split(READY_PLACEHOLDER).length !== 2) {
          throw new Error(`index.html must carry ${READY_PLACEHOLDER} exactly once`);
        }
        text = text.replace(READY_PLACEHOLDER, `data-ready="${ready.join(" ")}"`);
      }
      await writeFile(join(staging, file), text);
    }
    await mkdir(join(staging, FONT_DIR));
    for (const entry of await readdir(join(here, FONT_DIR), { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      await writeFile(join(staging, FONT_DIR, entry.name), await readFile(join(here, FONT_DIR, entry.name)));
    }
    for (const s of served) await writeFile(join(staging, s.serve), s.bytes);

    await rm(out, { recursive: true, force: true });
    await rename(staging, out);
    return { ready };
  } catch (err) {
    await rm(staging, { recursive: true, force: true });
    await rm(out, { recursive: true, force: true });
    throw err;
  }
}

async function main() {
  const out = process.argv[2] ? resolve(process.argv[2]) : join(here, "dist");
  const dir = process.env.GET_RELEASE_DIR;
  const release = dir ? releaseFromDir(resolve(dir)) : releaseFromUrl();
  try {
    const publicKey = await readFile(join(here, "release-key.pub"), "utf8");
    const { ready } = await build({ release, publicKey, out, log: (line) => console.log(line) });
    console.log(`built ${out} (published: ${ready.join(" ")})`);
  } catch (err) {
    await rm(out, { recursive: true, force: true });
    console.error(`get build failed: ${err.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
