// The background worker's message interface, shared by the browser worker
// (worker.mjs) and the Node worker the tests start: the same requests, the
// same replies, the same WebAssembly module.
//
//   request:  { id, op, args }
//   replies:  { id, type: "progress", stage }   zero or more
//             { id, type: "result", result }    or
//             { id, type: "error", message }
//
// Every random byte comes from crypto.getRandomValues. Nothing is kept
// between requests except the compiled module: a key's digits arrive with a
// request and are gone when it is answered.

import { loadGhost } from "./wasm.mjs";

const random = (n) => crypto.getRandomValues(new Uint8Array(n));

const OPS = {
  newKey(ghost) {
    return { key: ghost.newKey(random(32)) };
  },

  checkKey(ghost, { key }) {
    return { groups: ghost.checkKey(key) };
  },

  commit(ghost, { chainId, amount, key }) {
    return ghost.commit({ chainId, amount, seed: random(32), key });
  },

  treeCheck(ghost, args) {
    ghost.treeCheck(args);
    return { ok: true };
  },

  restore(ghost, args) {
    return { found: ghost.restore(args) };
  },

  prefixRoots(ghost, { leaves, from, to }) {
    return { roots: ghost.prefixRoots(leaves, from, to) };
  },

  chooseTreeState(ghost, args) {
    return { chosen: ghost.chooseTreeState(args) };
  },

  prove(ghost, args, progress) {
    progress("proving");
    const started = performance.now();
    const result = ghost.prove({ ...args, seed: random(32), zk: random(32) });
    progress("proved");
    return { ...result, provingMs: performance.now() - started };
  },
};

// `loadBytes` returns the module's bytes; `post` sends one reply.
export function createWorker(loadBytes, post) {
  let ghost = null;
  return async function onMessage(message) {
    const { id, op, args } = message || {};
    const progress = (stage) => post({ id, type: "progress", stage });
    try {
      if (!Object.hasOwn(OPS, op)) throw new Error(`unknown request ${op}`);
      if (!ghost) {
        progress("loading the prover");
        ghost = loadBytes().then(loadGhost);
      }
      const result = OPS[op](await ghost, args || {}, progress);
      post({ id, type: "result", result });
    } catch (err) {
      post({ id, type: "error", message: String((err && err.message) || err) });
    }
  };
}
