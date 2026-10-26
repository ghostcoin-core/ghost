// A release folder for the tests: fixture scripts signed, in the test, with
// an ed25519 key pair node:crypto makes. Nothing touches the network.

import { generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const FIXTURES = {
  "install.sh": "#!/bin/sh\n# fixture install.sh for the get site tests\necho installing a test node\n",
  "install.ps1": "# fixture install.ps1 for the get site tests\nWrite-Host 'installing a test node'\n",
  "install.cmd": "@echo off\r\nrem fixture install.cmd for the get site tests\r\necho installing a test node\r\n",
};

export function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicPem: publicKey.export({ type: "spki", format: "pem" }) };
}

export const signature = (privateKey, text) => sign(null, Buffer.from(text), privateKey);

// A temporary folder `dir` holding the named scripts, each with its .sig,
// and a path `out` to build into. `sigs` replaces a script's signature
// bytes, or leaves it out with null.
export function makeRelease({ privateKey, scripts = Object.keys(FIXTURES), sigs = {} }) {
  const root = mkdtempSync(join(tmpdir(), "ghost-get-"));
  const dir = join(root, "release");
  mkdirSync(dir);
  for (const name of scripts) {
    writeFileSync(join(dir, name), FIXTURES[name]);
    const sig = name in sigs ? sigs[name] : signature(privateKey, FIXTURES[name]);
    if (sig !== null) writeFileSync(join(dir, `${name}.sig`), sig);
  }
  return { dir, out: join(root, "dist"), cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
