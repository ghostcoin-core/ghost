// Stand-ins for the browser around the pop-up wallet: IndexedDB, the
// screens, passkeys with the PRF extension, WebCrypto with its decrypted
// buffers kept for inspection, and the random source; and the built module.
// Importing this file runs nothing.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadGhost } from "../../webapp/src/wasm.mjs";

export const repoDir = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const wasmPath =
  process.env.GHOST_WEBAPP_WASM || resolve(repoDir, "webapp/wasm/target/wasm32-unknown-unknown/release/ghost_webapp_wasm.wasm");

export const PASSWORD = "correct horse battery";

export async function loadTestGhost() {
  return loadGhost(await readFile(wasmPath));
}

// The module with every call's name logged.
export function spyGhost(ghost) {
  const calls = [];
  return { calls, call: (name, input) => (calls.push(name), ghost.call(name, input)) };
}

// A fixed random source; every answer is logged as a copy (the wallet
// overwrites some with zeros once used).
export function testRandom() {
  let state = 12345;
  const random = (n) => {
    const out = Uint8Array.from({ length: n }, () => {
      state = (state * 1103515245 + 12345) % 2 ** 31;
      return (state >> 16) & 0xff;
    });
    random.log.push(out.slice());
    return out;
  };
  random.log = [];
  return random;
}

// WebCrypto, with the buffers decrypt returned kept.
export function spySubtle() {
  const s = globalThis.crypto.subtle;
  const decrypted = [];
  return {
    decrypted,
    importKey: (...a) => s.importKey(...a),
    deriveKey: (...a) => s.deriveKey(...a),
    encrypt: (...a) => s.encrypt(...a),
    decrypt: async (...a) => {
      const out = await s.decrypt(...a);
      decrypted.push(out);
      return out;
    },
  };
}

// IndexedDB with one database, enough for vaultStore: open with an upgrade
// the first time, and get and add in a transaction. `data` is what it holds.
export function fakeIndexedDB() {
  const data = new Map();
  const stores = new Set();
  const later = (fn) => setImmediate(fn);
  return {
    data,
    open() {
      const req = {};
      later(() => {
        req.result = {
          createObjectStore: (name) => stores.add(name),
          close() {},
          transaction(name, mode) {
            assert.ok(stores.has(name), `no object store ${name}`);
            const tx = {};
            const request = (act) => {
              const r = {};
              later(() => {
                try {
                  r.result = act();
                } catch (err) {
                  tx.error = err;
                  tx.onerror?.();
                  return;
                }
                later(() => tx.oncomplete?.());
              });
              return r;
            };
            tx.objectStore = () => ({
              get: (key) => request(() => structuredClone(data.get(key))),
              add: (value, key) =>
                request(() => {
                  assert.equal(mode, "readwrite");
                  if (data.has(key)) throw new Error("ConstraintError: the key is taken");
                  data.set(key, structuredClone(value));
                  return key;
                }),
            });
            return tx;
          },
        };
        if (stores.size === 0) req.onupgradeneeded?.();
        req.onsuccess?.();
      });
      return req;
    },
  };
}

// The screens of main.mjs, answered by `script` (one function per screen,
// given the screen's arguments and this object) or by the defaults: create,
// type the right check words, a password, approve with it. `log` lists the
// screens shown, `words` the words shown, `approvals` each approval's summary.
export function scriptedUi(script = {}) {
  const ui = { log: [], errors: [], statuses: [], words: null, approvals: [] };
  const defaults = {
    start: () => "create",
    showWords: () => {},
    checkWords: (positions) => positions.map((p) => ui.words[p - 1]),
    restoreWords: () => assert.fail("not restoring"),
    chooseLock: () => ({ kind: "password", password: PASSWORD, again: PASSWORD }),
    approve: () => ({ password: PASSWORD }),
  };
  for (const name of Object.keys(defaults)) {
    ui[name] = async (...args) => {
      ui.log.push(name);
      if (name === "showWords") ui.words = args[0].slice();
      if (name === "approve") ui.approvals.push(args[0]);
      return (script[name] ?? defaults[name])(...args, ui);
    };
  }
  ui.error = (text) => {
    ui.log.push("error");
    ui.errors.push(text);
  };
  ui.status = (text) => ui.statuses.push(text);
  return ui;
}

// navigator.credentials with one passkey whose PRF is HMAC-SHA-256 under
// `secret`; `prf` false is an authenticator without the extension.
export function fakePasskeys({ prf = true } = {}) {
  const passkeys = {
    calls: [],
    secret: new Uint8Array(32).fill(7),
    async create(options) {
      passkeys.calls.push("create");
      assert.ok(options.publicKey.extensions.prf, "the PRF extension is asked for");
      return { rawId: Uint8Array.of(9, 9, 9, 9).buffer, getClientExtensionResults: () => ({ prf: { enabled: prf } }) };
    },
    async get(options) {
      passkeys.calls.push("get");
      assert.deepEqual([...new Uint8Array(options.publicKey.allowCredentials[0].id)], [9, 9, 9, 9]);
      const s = globalThis.crypto.subtle;
      const key = await s.importKey("raw", passkeys.secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const first = await s.sign("HMAC", key, options.publicKey.extensions.prf.eval.first);
      return { getClientExtensionResults: () => ({ prf: { results: { first } } }) };
    },
  };
  return passkeys;
}

// Waits until `ready()` is true.
export async function until(ready, what = "the wallet's answer") {
  for (let i = 0; i < 12000; i += 1) {
    if (ready()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.fail(`no ${what}`);
}

// A few turns of the event loop, for a message that must stay unanswered.
export async function settle(n = 20) {
  for (let i = 0; i < n; i += 1) await new Promise((r) => setImmediate(r));
}
