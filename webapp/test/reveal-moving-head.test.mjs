// A Summon reveal against an endpoint whose tip moves on every poll, as the
// CI node's does at a block about every 20 ms: it never holds still, so a
// flow that waits for a still tip before a resend waits out every poll, sends
// an envelope whose root has fallen far below the tip, and runs out of sends
// and proofs ("chain head kept moving while the reveal was checked").
//
// The reveal must go through without the tip holding still: a resend after
// one short wait and one look at the tip, and a new proof against the settled
// root of the tip by then once the refused proof's root is far below it. The
// caps on sends and proofs hold, and every proof is of the first coin.
//
// Nothing is built: the endpoint is an in-process stand-in reached through
// the flow's `fetch`, and the prover a stub. Header hashes are SHA-256 of
// the header's RLP, which the stub's keccak256 also computes.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { concat, toHex } from "../src/bytes.mjs";
import { SETTLE_DEPTH } from "../src/chain.mjs";
import {
  HEAD_MOVED,
  HEAD_MOVED_PROOFS,
  HEAD_MOVED_SENDS,
  LEAF_WINDOW,
  STALE_ROOT_DEPTH,
  createFlow,
} from "../src/flow.mjs";
import { readHeader } from "../src/header.mjs";

const GHOST = 10n ** 18n;
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const NOTE_BYTES = 156;
// The holder's coin; strangers' coins come before and after it.
const COIN_POSITION = 2;

const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(typeof p === "string" ? p : Buffer.from(p));
  return new Uint8Array(h.digest());
};
const q = (n) => `0x${BigInt(n).toString(16)}`;
// The coin root of a tree of `count` leaves; leaves are only ever appended.
const rootOf = (count) => sha256("root", String(count));

// The stand-in. Every eth_blockNumber first seals `step` blocks, so the tip
// has moved on whenever the flow looks; a proof seals `proveBlocks` more, as
// blocks keep coming while the worker proves. A send is refused with the
// node's head-moving error while `refuseFirst` sends remain to refuse, and
// whenever its proof's root is more than `deepest` blocks below the tip.
function stand({ step, proveBlocks, refuseFirst, deepest = STALE_ROOT_DEPTH }) {
  const leaves = [];
  const blocks = [];
  const receipts = new Map();
  const requests = [];
  const sends = [];
  const proofs = [];
  const reveals = [];
  const byEnvelope = new Map();
  // The key's coins as restore finds them.
  const coins = [];
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
    if (refuse > 0 || depth > deepest) {
      if (refuse > 0) refuse -= 1;
      send.error = HEAD_MOVED;
      throw headMoved();
    }
    if (coins.find((c) => c.position === proof.position).spent) throw new Error("marker already spent");
    coins.find((c) => c.position === proof.position).spent = true;
    const position = leaves.length;
    const number = commit(proof.remainder.commitment);
    coins.push({ position, number: proof.number + 1n, amount: proof.remainder.amount, spent: false });
    reveals.push({ proof: proof.n, block: number });
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

  return { fetch, prover, requests, sends, proofs, reveals, coins, tip };
}

function fromHexBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
}

// A flow on the stand-in whose waits take no time and are recorded.
function flowOn(node) {
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

// The endpoint's requests from the first send on, split at each send.
function between(requests) {
  const first = requests.indexOf("eth_sendRawTransaction");
  const gaps = [];
  let gap = [];
  for (const method of requests.slice(first + 1)) {
    if (method === "eth_sendRawTransaction") {
      gaps.push(gap);
      gap = [];
    } else {
      gap.push(method);
    }
  }
  return gaps;
}

test("a reveal refused while the tip moves on every poll is sent again after one look at the tip, and goes through", async () => {
  const node = stand({ step: 1, proveBlocks: 2, refuseFirst: 3 });
  const { flow, stages } = flowOn(node);
  assert.equal((await flow.summonOpen("synthetic test key")).status, "unclaimed");
  const fromRequests = node.requests.length;

  const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

  assert.deepEqual(
    node.sends.map((s) => s.error),
    [HEAD_MOVED, HEAD_MOVED, HEAD_MOVED, null],
    "three refused sends, then the one the node takes",
  );
  assert.equal(node.proofs.length, 1, "proved once: the root stayed near the tip");
  assert.equal(new Set(node.sends.map((s) => s.envelope)).size, 1, "the same envelope each time");
  // No wait for a still tip: one look at the tip between a refusal and the
  // resend, though the tip moved every time.
  for (const [i, gap] of between(node.requests.slice(fromRequests)).entries()) {
    assert.equal(gap.filter((m) => m === "eth_blockNumber").length, 1, `one look at the tip before send ${i + 2}`);
  }
  assert.ok(node.sends.every((s, i) => i === 0 || s.tip > node.sends[i - 1].tip), "the tip moved before every resend");
  assert.ok(!stages.some((s) => /still/.test(s)), "the flow never waits for a still tip");

  assert.equal(node.reveals.length, 1, "one reveal in a block");
  assert.equal(reveal.block, node.reveals[0].block);
  assert.equal(flow.state.error, null);
  assert.equal(flow.state.summon.current.position, node.coins.at(-1).position, "the remainder is the key's coin now");
});

test("a refused proof whose root has fallen far below the moving tip is proved again for the tip, not sent again", async () => {
  // 12 blocks between two looks, as 20 ms blocks over a 250 ms wait.
  const node = stand({ step: 12, proveBlocks: 4, refuseFirst: 2 });
  const { flow, waits } = flowOn(node);
  const opened = await flow.summonOpen("synthetic test key");
  const coin = opened.current;

  const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

  assert.equal(node.proofs.length, 2, "proved again once");
  assert.deepEqual(node.sends.map((s) => [s.proof, s.error]), [[0, HEAD_MOVED], [0, HEAD_MOVED], [1, null]]);
  assert.ok(
    node.sends.every((s) => s.depth <= STALE_ROOT_DEPTH),
    `no envelope sent with its root more than ${STALE_ROOT_DEPTH} blocks below the tip (${node.sends.map((s) => s.depth)})`,
  );
  assert.equal(STALE_ROOT_DEPTH, SETTLE_DEPTH + LEAF_WINDOW);
  assert.ok(node.proofs[1].rootHeight > node.sends[1].tip, "the new proof is against the settled root of a later tip");
  assert.ok(
    node.proofs.every((p) => p.number === coin.number && p.position === coin.position && p.amount === coin.amount),
    "every proof is of the first proof's coin",
  );
  assert.equal(waits.filter((ms) => ms === 250).length, 2, "one fixed 250 ms wait before each resend or new proof");

  assert.equal(node.reveals.length, 1, "one reveal in a block, paid once");
  assert.equal(node.reveals[0].proof, 1);
  assert.equal(reveal.block, node.reveals[0].block);
  assert.equal(flow.state.error, null);
});

test("a reveal refused on every send while the tip keeps moving stops at the caps, with nothing asked after the last refusal", async () => {
  const node = stand({ step: 12, proveBlocks: 4, refuseFirst: Infinity });
  const { flow } = flowOn(node);
  const coin = (await flow.summonOpen("synthetic test key")).current;
  const fromRequests = node.requests.length;

  await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), (err) => {
    assert.equal(err.message, HEAD_MOVED);
    return true;
  });

  assert.equal(node.proofs.length, HEAD_MOVED_PROOFS, "at most 4 proofs");
  for (let p = 0; p < HEAD_MOVED_PROOFS; p += 1) {
    const own = node.sends.filter((s) => s.proof === p).length;
    assert.ok(own >= 1 && own <= HEAD_MOVED_SENDS, `proof ${p + 1} sent 1 to 5 times (${own})`);
  }
  assert.equal(node.sends.filter((s) => s.proof === HEAD_MOVED_PROOFS - 1).length, HEAD_MOVED_SENDS, "the last proof is sent 5 times");
  assert.ok(node.sends.length <= HEAD_MOVED_SENDS * HEAD_MOVED_PROOFS);
  assert.equal(node.requests.slice(fromRequests).at(-1), "eth_sendRawTransaction", "nothing is asked after the last refusal");
  assert.ok(node.proofs.every((p) => p.number === coin.number && p.position === coin.position), "every proof is of the same coin");
  assert.equal(node.reveals.length, 0);
  assert.equal(flow.state.error, HEAD_MOVED);
});
