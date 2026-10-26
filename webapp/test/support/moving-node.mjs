// An in-process stand-in for a node whose tip moves on every poll, as the CI
// node's does at a block about every 20 ms, reached through the flow's
// `fetch`, with a stub prover. Nothing is proved: a proof is a record the
// stand-in looks up by its envelope, and coin roots are stand-in values.
// Header hashes are keccak256 of the header's RLP, and every block carries
// real receipts in the node's log layout (the client library's), whose
// root, computed by the built module's ghost_receipts_root, is the header's
// receiptsRoot; the stub prover checks the receipts, the leaves, notes and
// markers with the built module's own exports, as the worker does.
//
// Importing this file runs nothing.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { concat, fromHex, toHex, word } from "../../src/bytes.mjs";
import { SETTLE_DEPTH } from "../../src/chain.mjs";
import { HEAD_MOVED, STALE_ROOT_DEPTH, createFlow } from "../../src/flow.mjs";
import { readHeader, rlpList, rlpString } from "../../src/header.mjs";
import { Ghost } from "../../src/wasm.mjs";
import { wasmPath } from "./env.mjs";

export const GHOST = 10n ** 18n;
const NOTE_BYTES = 156;
const SALT_BYTES = 16;
// The coin tree account and the topics of its commit and reveal logs.
const COIN_TREE_ACCOUNT = "0x67686f7374000000000000000000000000000001";
const COMMIT_TAG = "ghost/commit-receipt/v1";
const REVEAL_TAG = "ghost/reveal-receipt/v1";

// The built module, compiled once and instantiated for each stand-in.
let compiled = null;
function loadGhostSync() {
  compiled ??= new WebAssembly.Module(readFileSync(wasmPath));
  return new Ghost(new WebAssembly.Instance(compiled, {}).exports);
}

const u32 = (n) => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
};

function bigEndian(n) {
  const out = [];
  for (let v = BigInt(n); v > 0n; v >>= 8n) out.unshift(Number(v & 0xffn));
  return Uint8Array.from(out);
}

// A receipt's consensus encoding, from its JSON: the type byte, then the
// RLP of [status, cumulativeGasUsed, logsBloom, logs]. Every receipt here
// is typed and succeeded.
function encodeReceipt(r) {
  const logs = r.logs.map((l) =>
    rlpList([rlpString(fromHex(l.address)), rlpList(l.topics.map((t) => rlpString(fromHex(t)))), rlpString(fromHex(l.data))]),
  );
  const body = rlpList([rlpString(Uint8Array.of(1)), rlpString(bigEndian(r.cumulativeGasUsed)), rlpString(fromHex(r.logsBloom)), rlpList(logs)]);
  return concat([fromHex(r.type), body]);
}
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
// envelope is judged as above. `clock.ms` is the flow's time (see flowOn); a
// proof moves it on by `proveMs`.
export function movingNode({ step, proveBlocks, proveMs = 0, refuseFirst = 0, deepest = STALE_ROOT_DEPTH, refuseEnvelope = false }) {
  const ghost = loadGhostSync();
  const topic = (tag) => ghost.keccak256(concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)]));
  const commitTopic = toHex(topic(COMMIT_TAG));
  const revealTopic = toHex(topic(REVEAL_TAG));
  const clock = { ms: 0 };
  const leaves = [];
  const blocks = [];
  const byHash = new Map();
  // Spent markers (hex), each with the block that holds its reveal.
  const spent = [];
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

  // A block holding `logs`, each the one log of its own transaction's
  // receipt: { topics, data } (hex).
  function mine(logs = []) {
    const number = blocks.length;
    const txReceipts = logs.map((log, i) => ({
      type: "0x50",
      status: "0x1",
      cumulativeGasUsed: q(100_000 * (i + 1)),
      logsBloom: toHex(new Uint8Array(256)),
      logs: [{ address: COIN_TREE_ACCOUNT, ...log }],
    }));
    const json = {
      parentHash: number === 0 ? toHex(new Uint8Array(32)) : blocks[number - 1].json.hash,
      sha3Uncles: toHex(sha256("uncles")),
      miner: toHex(new Uint8Array(20)),
      stateRoot: toHex(sha256("state", String(number))),
      transactionsRoot: toHex(sha256("transactions", String(number))),
      receiptsRoot: toHex(ghost.receiptsRoot(txReceipts.map(encodeReceipt))),
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
      dataMarkerRoot: toHex(sha256("data markers")),
    };
    json.hash = toHex(ghost.keccak256(readHeader(json).rlp));
    const block = { number, json, leafCount: leaves.length, receipts: txReceipts.map((r) => ({ ...r, blockHash: json.hash })) };
    blocks.push(block);
    byHash.set(json.hash, block);
    return number;
  }
  const tip = () => blocks.length - 1;
  // A block that appends `leaf` (with an all-zero note): a commit's log,
  // which ends with the coin's 16-byte salt, or with `reveal`
  // ({ marker, recipient, out }) a reveal's, whose marker it spends.
  const commit = (leaf, { reveal = null, salt = null } = {}) => {
    const position = leaves.length;
    leaves.push({ leaf, salt: reveal ? null : salt });
    const head = [u32(0), u32(position), leaf];
    const note = new Uint8Array(NOTE_BYTES);
    const log = reveal
      ? { topics: [revealTopic, reveal.marker], data: toHex(concat([...head, note, fromHex(reveal.recipient, 20), word(reveal.out)])) }
      : { topics: [commitTopic], data: toHex(concat([...head, word(GHOST), note, salt])) };
    if (reveal) spent.push({ marker: reveal.marker, block: blocks.length });
    return mine([log]);
  };
  const saltOf = (...parts) => sha256("salt", ...parts).slice(0, SALT_BYTES);

  mine();
  commit(sha256("stranger", "0"), { salt: saltOf("stranger", "0") });
  commit(sha256("stranger", "1"), { salt: saltOf("stranger", "1") });
  // A salted coin, as the app commits one; restore reads its salt.
  const coinSalt = saltOf();
  commit(sha256("coin"), { salt: coinSalt });
  coins.push({ position: COIN_POSITION, number: 0n, amount: GHOST, spent: false, salt: coinSalt });
  commit(sha256("stranger", "2"), { salt: saltOf("stranger", "2") });
  while (tip() < 120) mine();

  const blockByHash = (hash) => {
    const block = byHash.get(String(hash).toLowerCase());
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
    const number = commit(proof.remainder.commitment, { reveal: { marker: proof.marker, recipient: proof.recipient, out: proof.out } });
    // A salted coin's remainder is salted, its salt read from its note.
    coins.push({ position, number: proof.number + 1n, amount: proof.remainder.amount, spent: false, salt: saltOf(String(proof.n)) });
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
    eth_getBlockReceipts: ([hash]) => byHash.get(String(hash).toLowerCase())?.receipts ?? null,
    ghost_getTreePage: ([kind, , , anchor]) => {
      const block = blockByHash(anchor);
      if (kind === "coin-markers") {
        const markers = spent.filter((s) => s.block <= block.number).map((s) => s.marker);
        return { count: q(markers.length), markers };
      }
      // A commit's salt is served beside its leaf; a reveal's remainder has none.
      const entries = leaves.slice(0, block.leafCount).map(({ leaf, salt }) => ({
        leaf: toHex(leaf),
        note: toHex(new Uint8Array(NOTE_BYTES)),
        ...(salt ? { salt: toHex(salt) } : {}),
      }));
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

  // The worker's header chain, stubbed in the stand-in's terms: a header is
  // held when its keccak256 is the hash given and it is the stand-in's block
  // of that hash whose parent is held; the best chain is the longest. Its
  // checks of difficulty and seal are header-chain.test.mjs's, with the
  // real module.
  const chain = { held: new Map(), best: null };
  const blockOf = (hash) => byHash.get(hash);
  const hashOf = (rlp) => toHex(ghost.keccak256(rlp));
  const heightOf = (hash) => chain.held.get(hash).number;
  const bestAt = (height) => {
    let at = chain.best;
    while (at && heightOf(at) > height) at = chain.held.get(at).parent;
    return at && heightOf(at) === height ? at : null;
  };
  const bestView = () => ({ height: BigInt(heightOf(chain.best)), hash: fromHexBytes(chain.best), work: BigInt(heightOf(chain.best) + 1) });

  // The worker, stubbed: what the flow asks of it, in the stand-in's terms.
  const prover = {
    async request(op, args) {
      switch (op) {
        case "chainStart": {
          const hash = hashOf(args.start.header);
          chain.held = new Map([[hash, { number: blockOf(hash).number, parent: null }]]);
          chain.best = hash;
          return { startHash: fromHexBytes(hash) };
        }
        case "chainAdd": {
          let adopted = 0;
          for (const { hash, rlp } of args.headers) {
            const id = hashOf(rlp);
            const block = blockOf(id);
            if (id !== toHex(hash) || !block || !chain.held.has(block.json.parentHash)) {
              return { adopted, refused: { number: BigInt(block?.number ?? 0), why: "check", reason: "not the stand-in's block" }, best: bestView(), removed: 0n };
            }
            chain.held.set(id, { number: block.number, parent: block.json.parentHash });
            if (block.number > heightOf(chain.best)) chain.best = id;
            adopted += 1;
          }
          return { adopted, refused: null, best: bestView(), removed: 0n };
        }
        case "chainView": {
          const id = toHex(args.hash);
          const held = chain.held.has(id);
          const onBest = held && bestAt(heightOf(id)) === id;
          // One walk down from `to` by parents, as the module walks.
          const hashes = [];
          for (let at = args.from <= args.to ? bestAt(args.to) : null; hashes.length <= args.to - args.from; at = chain.held.get(at).parent) {
            hashes.unshift(fromHexBytes(at));
          }
          return {
            best: bestView(),
            held,
            work: held ? BigInt(heightOf(id) + 1) : 0n,
            confirmations: onBest ? BigInt(heightOf(chain.best) - heightOf(id) + 1) : 0n,
            hashes,
          };
        }
        case "checkKey":
          return { format: "words", groups: 21 };
        case "keccak256":
          return { hash: ghost.keccak256(args.bytes) };
        case "treeCheck":
          return {};
        // The block receipts, checked by the built module as the worker
        // checks them.
        case "receiptsAdd":
          ghost.receiptsAdd(args.blocks);
          return { ok: true };
        case "receiptsCheck":
          ghost.receiptsCheck(args);
          return { ok: true };
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
          const coin = coins.find((c) => c.position === args.position);
          assert.equal(toHex(args.salt), toHex(coin.salt), "the coin's salt is passed to the prover");
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
          clock.ms += proveMs;
          return { envelope: fromHexBytes(proof.envelope), txHash: fromHexBytes(proof.txHash), remainder: proof.remainder };
        }
        default:
          throw new Error(`the stub prover has no ${op}`);
      }
    },
  };

  // The table of networks the flow is given: chain 1, starting at this
  // stand-in's genesis.
  const networks = {
    1: {
      params: { blockTime: 30, halfLife: 3600, startDifficulty: 1, minDifficulty: 1, futureDrift: 30 },
      genesisTimestamp: 1_798_767_600,
      genesisHash: blocks[0].json.hash,
      pin: null,
    },
  };

  return { fetch, prover, networks, requests, sends, proofs, reveals, balances, coins, stale, tip, clock };
}

// A flow on the stand-in whose waits are recorded and pass at once, moving
// only the stand-in's clock, with any other createFlow options given.
export function flowOn(node, options = {}) {
  const waits = [];
  const stages = [];
  const flow = createFlow({
    prover: node.prover,
    fetch: node.fetch,
    networks: node.networks,
    endpoint: "http://127.0.0.1:1/",
    pollMs: 7,
    maxPolls: 50,
    now: () => node.clock.ms,
    sleep: async (ms) => {
      waits.push(ms);
      node.clock.ms += ms;
    },
    ...options,
    onChange: (s) => {
      const stage = s.progress?.stage;
      if (stage && stages.at(-1) !== stage) stages.push(stage);
    },
  });
  return { flow, waits, stages };
}
