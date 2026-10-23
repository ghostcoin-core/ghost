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
// between requests except the compiled module and, in its memory, the page's
// header chain and the coin tree records of the block receipts it checked,
// which are public data only: a key's words or a wallet
// seed's words arrive with a request and are gone when it is answered.

import { Ghost, loadGhost } from "./wasm.mjs";

const random = (n) => crypto.getRandomValues(new Uint8Array(n));

const OPS = {
  newKey(ghost) {
    return { key: ghost.newKey(random(32)) };
  },

  checkKey(ghost, { key }) {
    return ghost.checkKey(key);
  },

  // The digit view of a key: 21 groups for a words key.
  keyDigits(ghost, { key }) {
    return { digits: ghost.keyDigits(key) };
  },

  // A version 2 commit, its salt drawn from the secure random seed. Only a
  // test asks for version 1.
  commit(ghost, { chainId, amount, key, version }) {
    return ghost.commit({ chainId, amount, seed: random(32), key, version });
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

  walletNew(ghost) {
    return { words: ghost.walletNew(random(32)) };
  },

  walletAccount(ghost, { words, index }) {
    return ghost.walletAccount(words, index);
  },

  walletSign(ghost, args) {
    return ghost.walletSign({ ...args, seed: random(32) });
  },

  keccak256(ghost, { bytes }) {
    return { hash: ghost.keccak256(bytes) };
  },

  chooseTreeState(ghost, args) {
    return { chosen: ghost.chooseTreeState(args) };
  },

  // The page's header chain (lib.rs, ghost_chain_*): started once from the
  // trusted start, then every header the endpoint returns is added to it.
  chainStart(ghost, args) {
    return { startHash: ghost.chainStart(args) };
  },

  chainAdd(ghost, args, progress) {
    progress("checking the proof of work of the endpoint's headers");
    return ghost.chainAdd(args);
  },

  chainView(ghost, args) {
    return ghost.chainView(args);
  },

  // The block receipts (lib.rs, ghost_receipts_*): each block's receipts
  // checked against its header's receiptsRoot and its coin tree records
  // kept, then a scan's leaves, notes, salts and markers checked against
  // those records. Public data only.
  receiptsRoot(ghost, { receipts }) {
    return { root: ghost.receiptsRoot(receipts) };
  },

  receiptsAdd(ghost, { blocks }, progress) {
    progress("checking the block receipts");
    ghost.receiptsAdd(blocks);
    return { ok: true };
  },

  receiptsCheck(ghost, args, progress) {
    progress("checking the coin tree and the spent markers against the block receipts");
    ghost.receiptsCheck(args);
    return { ok: true };
  },

  prove(ghost, args, progress) {
    progress("proving");
    const started = performance.now();
    const result = ghost.prove({ ...args, seed: random(32), zk: random(32) });
    progress("proved");
    return { ...result, provingMs: performance.now() - started };
  },

  // The levels of the coin trees the module's test-depth reveal is made for
  // (lib.rs, test_depth), or null: only a module built with the
  // test-tree-depth feature has one, never the one the page ships.
  testDepthProver(ghost) {
    const levels = ghost.w.ghost_test_depth_levels;
    return { depth: typeof levels === "function" && typeof ghost.w.ghost_prove_test_depth === "function" ? levels() : null };
  },

  // A reveal against a test node's smaller tree, with that node's stub proof
  // in place of a STARK (lib.rs, ghost_prove_test_depth): the input and the
  // result of `prove`, so it is read and written as `prove` is.
  proveTestDepth(ghost, args, progress) {
    if (typeof ghost.w.ghost_prove_test_depth !== "function") {
      throw new Error("this module has no test-depth reveal: it proves only against a coin tree of 32 levels");
    }
    progress("proving");
    const testDepth = new Ghost({ ...ghost.w, ghost_prove: ghost.w.ghost_prove_test_depth });
    const result = testDepth.prove({ ...args, decoy: false, seed: random(32), zk: random(32) });
    progress("proved");
    return { ...result, provingMs: 0 };
  },
};

// `loadBytes` returns the module's bytes; `post` sends one reply; `open`
// makes the Ghost from what `loadBytes` gave (the browser worker loads the
// threaded or the single-thread module itself and passes a Ghost).
export function createWorker(loadBytes, post, open = loadGhost) {
  let ghost = null;
  return async function onMessage(message) {
    const { id, op, args } = message || {};
    const progress = (stage) => post({ id, type: "progress", stage });
    try {
      if (!Object.hasOwn(OPS, op)) throw new Error(`unknown request ${op}`);
      if (!ghost) {
        progress("loading the prover");
        ghost = loadBytes().then(open);
      }
      const result = OPS[op](await ghost, args || {}, progress);
      post({ id, type: "result", result });
    } catch (err) {
      post({ id, type: "error", message: String((err && err.message) || err) });
    }
  };
}
