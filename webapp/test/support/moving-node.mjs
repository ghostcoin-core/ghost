// An in-process stand-in for a node whose tip moves on every poll, as the CI
// node's does at a block about every 20 ms, reached through the flow's
// `fetch`, with a stub prover. Nothing is built: header hashes are SHA-256
// of the header's RLP, which the stub's keccak256 also computes, and a
// proof is a record the stand-in looks up by its envelope.
//
// Importing this file runs nothing.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { concat, toHex } from "../../src/bytes.mjs";
import { SETTLE_DEPTH } from "../../src/chain.mjs";
import { HEAD_MOVED, STALE_ROOT_DEPTH, createFlow } from "../../src/flow.mjs";
import { readHeader } from "../../src/header.mjs";

export const GHOST = 10n ** 18n;
const NOTE_BYTES = 156;
// The holder's coin; strangers' coins come before and after it.
export const COIN_POSITION = 2;

const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(typeof p === "string" ? p : Buffer.from(p));
  return new Uint8Array(h.digest());
};
const q = (n) => `0x${BigInt(n).toString(16)}`;
// The coin root of a tree of `count` leaves; leaves are only ever appended.
const rootOf = (count) => sha256("root", String(count));
const fromHexBytes = (hex) => Uint8Array.from(Buffer.from(hex.slice(2), "hex"));

// The stand-in. Every eth_blockNumber first seals `step` blocks, so the tip
// has moved on whenever the flow looks; a proof seals `proveBlocks` more, as
// blocks keep coming while the worker proves. A send is refused with the
// node's head-moving error while `refuseFirst` sends remain to refuse, and
// whenever its proof's root is more than `deepest` blocks below the tip.
// With `refuseEnvelope`, the first envelope sent is refused on that send and
// on every later send of it (`stale.refused` counts them), while any other
// envelope is judged as above.
export function movingNode({ step, proveBlocks, refuseFirst = 0, deepest = STALE_ROOT_DEPTH, refuseEnvelope = false }) {
  const leaves = [];
  const blocks = [];
  const receipts = new Map();
  const requests = [];
  const sends = [];
  const proofs = [];
  const reveals = [];
  const balances = new Map();
  const byEnvelope = new Map();
  // The key's coins as restore finds them.
  const coins = [];
  const stale = refuseEnvelope ? { envelope: null, refused: 0 } : null;
  let refuse = refuseFirst;

  function mine() {
    const number = blocks.length;
    const json = {
      parentHash: number === 0 ? toHex(new Uint8Array(32)) : blocks[number - 1].json.hash,
      sha3Uncles: toHex(sha256("uncles")),
      miner: toHex(new Uint8Array(20)),
      stateRoot: toHex(sha256("state", String(number))),
      transactionsRoot: toHex(sha256("transactions", String(number))),
      receiptsRoot: toHex(sha256("receipts", String(number))),
      logsBloom: toHex(new Uint8Array(256)),
      difficulty: q(1),
      number: q(number),
      gasLimit: q(30_000_000),
      gasUsed: q(15_000_000),
      timestamp: q(1_798_767_600 + number),
      extraData: "0x",
      mixHash: toHex(sha256("mix", String(number))),
      nonce: toHex(new Uint8Array(8)),
      baseFeePerGas: q(1_000_000_000),
      coinTreeRoot: toHex(rootOf(leaves.length)),
      dataTreeRoot: toHex(sha256("data")),
    };
    json.hash = toHex(sha256(readHeader(json).rlp));
    blocks.push({ number, json, leafCount: leaves.length });
    return number;
  }
  const tip = () => blocks.length - 1;
  const commit = (leaf) => {
    leaves.push(leaf);
    return mine();
  };

  mine();
  commit(sha256("stranger", "0"));
  commit(sha256("stranger", "1"));
  commit(sha256("coin"));
  coins.push({ position: COIN_POSITION, number: 0n, amount: GHOST, spent: false });
  commit(sha256("stranger", "2"));
  while (tip() < 120) mine();

  const blockByHash = (hash) => {
    const block = blocks.find((b) => b.json.hash === String(hash).toLowerCase());
    if (!block) throw new Error("unknown anchor block");
    return block;
  };
  const headMoved = () => Object.assign(new Error(HEAD_MOVED), { code: -32000 });

  function sendRaw(hex) {
    const proof = byEnvelope.get(String(hex).toLowerCase());
    if (!proof) throw new Error("not a reveal");
    const depth = tip() - proof.rootHeight;
    const send = { envelope: proof.envelope, proof: proof.n, tip: tip(), depth, error: null };
    sends.push(send);
    if (stale && (stale.envelope === null || stale.envelope === proof.envelope)) {
      stale.envelope = proof.envelope;
      stale.refused += 1;
      send.error = HEAD_MOVED;
      throw headMoved();
    }
    if (refuse > 0 || depth > deepest) {
      if (refuse > 0) refuse -= 1;
      send.error = HEAD_MOVED;
      throw headMoved();
    }
    const coin = coins.find((c) => c.position === proof.position);
    if (coin.spent) throw new Error("marker already spent");
    coin.spent = true;
    const position = leaves.length;
    const number = commit(proof.remainder.commitment);
    coins.push({ position, number: proof.number + 1n, amount: proof.remainder.amount, spent: false });
    balances.set(proof.recipient, (balances.get(proof.recipient) ?? 0n) + proof.out);
    reveals.push({ proof: proof.n, block: number, hash: proof.txHash, fee: proof.fee });
    receipts.set(proof.txHash, { transactionHash: proof.txHash, blockNumber: q(number), blockHash: blocks[number].json.hash, status: "0x1" });
    return proof.txHash;
  }

  const methods = {
    eth_chainId: () => "0x1",
    eth_blockNumber: () => {
      for (let i = 0; i < step; i += 1) mine();
      return q(tip());
    },
    eth_getBlockByNumber: ([n]) => blocks[Number(BigInt(n))]?.json ?? null,
    eth_getTransactionReceipt: ([hash]) => receipts.get(String(hash).toLowerCase()) ?? null,
    eth_getTransactionByHash: ([hash]) => receipts.get(String(hash).toLowerCase()) ?? null,
    eth_sendRawTransaction: ([hex]) => sendRaw(hex),
    ghost_getPageRoots: ([, , anchor]) => [toHex(rootOf(blockByHash(anchor).leafCount))],
    ghost_getTreePage: ([kind, , , anchor]) => {
      const block = blockByHash(anchor);
      if (kind === "coin-markers") return { count: "0x0", markers: [] };
      const entries = leaves.slice(0, block.leafCount).map((leaf) => ({ leaf: toHex(leaf), note: toHex(new Uint8Array(NOTE_BYTES)) }));
      return { kind, treeIndex: "0x0", page: "0x0", filled: q(entries.length), entries };
    },
  };

  async function fetch(_url, init) {
    const call = JSON.parse(init.body);
    requests.push(call.method);
    let reply;
    try {
      reply = { jsonrpc: "2.0", id: call.id, result: methods[call.method](call.params ?? []) };
    } catch (err) {
      reply = { jsonrpc: "2.0", id: call.id, error: { code: err.code ?? -32000, message: err.message } };
    }
    return new Response(JSON.stringify(reply), { status: 200, headers: { "content-type": "application/json" } });
  }

  // The worker, stubbed: what the flow asks of it, in the stand-in's terms.
  const prover = {
    async request(op, args) {
      switch (op) {
        case "checkKey":
          return { groups: 12 };
        case "keccak256":
          return { hash: sha256(args.bytes) };
        case "treeCheck":
          return {};
        case "prefixRoots":
          return { roots: Array.from({ length: args.to + 1 }, (_, c) => rootOf(c)) };
        case "restore":
          return { found: coins.map((c) => ({ ...c })) };
        // choose_tree_state for one candidate (tree_state.rs).
        case "chooseTreeState": {
          const { tip: top, leafHeight, leafRoot, height, root } = args;
          return { chosen: height + SETTLE_DEPTH <= top && height > leafHeight && toHex(root) !== toHex(leafRoot) };
        }
        case "prove": {
          assert.ok(!args.decoy, "the coin can be proved each time");
          // The flow asks nothing between its scan and the proof, so the
          // proof's root is that of the block SETTLE_DEPTH below this tip.
          const n = proofs.length;
          const proof = {
            n,
            rootHeight: tip() - SETTLE_DEPTH,
            number: args.number,
            position: args.position,
            amount: args.amount,
            out: args.out,
            fee: args.fee,
            recipient: toHex(args.recipient),
            // A coin's marker depends on the coin alone, as the real one on
            // the key and the coin's number.
            marker: toHex(sha256("marker", String(args.position), String(args.number))),
            envelope: toHex(concat([sha256("envelope", String(n)), args.root])),
            txHash: toHex(sha256("tx", String(n))),
            remainder: { commitment: sha256("remainder", String(n)), amount: args.amount - args.out - args.fee },
          };
          assert.equal(toHex(args.root), toHex(rootOf(blocks[proof.rootHeight].leafCount)), "proved against the settled root");
          proofs.push(proof);
          byEnvelope.set(proof.envelope, proof);
          for (let i = 0; i < proveBlocks; i += 1) mine();
          return { envelope: fromHexBytes(proof.envelope), txHash: fromHexBytes(proof.txHash), remainder: proof.remainder };
        }
        default:
          throw new Error(`the stub prover has no ${op}`);
      }
    },
  };

  return { fetch, prover, requests, sends, proofs, reveals, balances, coins, stale, tip };
}

// A flow on the stand-in whose waits take no time and are recorded.
export function flowOn(node) {
  const waits = [];
  const stages = [];
  const flow = createFlow({
    prover: node.prover,
    fetch: node.fetch,
    endpoint: "http://127.0.0.1:1/",
    pollMs: 7,
    maxPolls: 50,
    sleep: async (ms) => {
      waits.push(ms);
    },
    onChange: (s) => {
      const stage = s.progress?.stage;
      if (stage && stages.at(-1) !== stage) stages.push(stage);
    },
  });
  return { flow, waits, stages };
}
