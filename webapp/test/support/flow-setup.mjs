// Shared set-up of the flow tests (flow.test.mjs, flow-claim.test.mjs and
// the flow-head-moved*.test.mjs files): the spec fee, the stand-in node with
// a scripted wallet and a flow on it, and helpers that read what the
// endpoint saw.
// Importing this file runs nothing.

import assert from "node:assert/strict";

import { DEFAULT_COMMIT_ENTRY, createFlow } from "../../src/flow.mjs";
import { loadModule, nodeProver, openTestWallet } from "./env.mjs";
import { startFakeNode } from "./fake-node.mjs";

export const GHOST = 10n ** 18n;
// Spec 10, section 10, vector window-genesis-ordinary: the fee of a version 2
// ordinary reveal at a base fee of 1 gwei.
export const SPEC_FEE = 26_448_916_578_669_104n;
export const RECIPIENT = "0x2222222222222222222222222222222222222222";
export const ENDPOINT_METHODS = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getTransactionReceipt",
  "eth_getBlockReceipts",
  "eth_sendRawTransaction",
  "eth_getTransactionCount",
  "eth_getBalance",
  "eth_maxPriorityFeePerGas",
  "eth_estimateGas",
  "ghost_getPageRoots",
  "ghost_getTreePage",
  "ghost_getNoteBucket",
]);

export function answersFor(key, positions) {
  const words = key.split(" ");
  return positions.map((p) => words[p - 1]);
}

// A word that differs from the right one in its last letter.
export function mistype(word) {
  return word.slice(0, -1) + (word.at(-1) === "a" ? "b" : "a");
}

// Every run of three words of a key: no request may hold any of them, in any
// case.
export function wordRuns(key) {
  const words = key.split(" ");
  const runs = [];
  for (let i = 0; i + 3 <= words.length; i += 1) runs.push(words.slice(i, i + 3).join(" "));
  return runs;
}



// A stand-in node, a scripted wallet and a flow on them, with strangers'
// coins on the chain. While the app waits the chain grows by a block, unless
// `chain.mining` is set to false.
// How long the app waits before it sends a refused reveal again.
export const RESEND_MS = 3;
// Proofs of one reveal the app makes here before a head-moving refusal
// surfaces: a few, since each is a real proof (the app's own bound is
// generous, and reveal-moving-head.test.mjs covers it with a stub prover).
export const PROOFS = 4;

export async function setUp({ fetch = globalThis.fetch, now = () => Date.now() } = {}) {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const worker = nodeProver();
  // Every worker request, with how many endpoint requests came before it
  // started and after it ended, and how long it took.
  const work = [];
  // `hooks.prove(args)`, when set, runs before each proof and gives the
  // arguments the worker is sent.
  const hooks = { prove: null };
  const prover = {
    request(op, args, onProgress) {
      if (op === "prove" && hooks.prove) args = hooks.prove(args);
      const at = node.requests.length;
      const started = performance.now();
      return worker.request(op, args, onProgress).finally(() => {
        work.push({
          op,
          decoy: Boolean(args && args.decoy),
          position: args?.position,
          number: args?.number,
          at,
          end: node.requests.length,
          ms: performance.now() - started,
        });
      });
    },
  };
  const chain = { mining: true };
  // While the app waits for a block, the chain grows by one; while it waits
  // before a resend, time passes and only the stand-in's own miner moves it.
  const sleep = async (ms) => {
    if (ms === RESEND_MS) return new Promise((resolve) => setTimeout(resolve, ms));
    if (chain.mining) node.mine();
  };
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks: node.networks(),
    pollMs: 5,
    maxPolls: 20,
    resendMs: RESEND_MS,
    headMovedProofs: PROOFS,
    sleep,
    now,
    fetch,
  });
  await openTestWallet(flow, node);
  node.foreignCommits(2);
  const done = async () => {
    worker.terminate();
    await node.close();
  };
  return { node, flow, chain, work, hooks, done };
}

// The endpoint's requests since request `from`, with the worker requests
// since worker request `fromWork` in their place among them: what the
// endpoint can time.
export function timeline(node, work, from, fromWork) {
  const events = [];
  const ops = work.slice(fromWork);
  for (let i = from; i <= node.requests.length; i += 1) {
    for (const w of ops.filter((x) => x.at === i)) events.push(`worker:${w.op}`);
    if (i < node.requests.length) events.push(JSON.stringify([node.requests[i].method, node.requests[i].params]));
  }
  return events;
}

// A timeline with block hashes left out and block numbers (but genesis)
// counted from block `base`, so that runs from tips the same distance past
// the start of a fee window compare.
export function relative(events, base) {
  return events.map((e) =>
    e
      .replace(/0x[0-9a-f]{64}/g, "0xhash")
      .replace(/^\["eth_getBlockByNumber",\["(0x[0-9a-f]+)"/, (_, n) => {
        const number = Number(BigInt(n));
        return `["eth_getBlockByNumber",["${number === 0 ? "genesis" : `base${number - base >= 0 ? "+" : ""}${number - base}`}"`;
      }),
  );
}

// Vanish of `amount` GHOST with a right save check; the new key.
export async function vanish(flow, amount) {
  const key = await flow.vanishStart(amount);
  const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
  assert.equal(sent.ok, true);
  return key;
}

// What the endpoint saw since request `from`, without the JSON-RPC ids.
export const seen = (node, from) => node.requests.slice(from).map((r) => JSON.stringify([r.method, r.params]));

// Claims the coin of `key` from another device: a second flow, with its own
// worker, on the same stand-in, whose build pins a recent header (so it
// checks few seals). A page that opened `key` before still shows the coin,
// which its next scan finds spent.
export async function claimElsewhere(node, key) {
  const prover = nodeProver();
  // Below the settled block, so the coin, older than the pin, counts as
  // followed by the leaves the settled tree holds.
  const networks = node.networks({ pinAt: node.tip() - 4 });
  const elsewhere = createFlow({ prover, endpoint: node.url, networks, pollMs: 5, maxPolls: 20, sleep: async () => node.mine() });
  try {
    assert.equal((await elsewhere.summonOpen(key)).status, "unclaimed");
    const newKey = await elsewhere.claimStart();
    assert.equal((await elsewhere.claimCheck(answersFor(newKey, elsewhere.claimSaved()))).ok, true);
  } finally {
    prover.terminate();
  }
}

// A reveal of the open key, which holds no unspent coin any more, refused
// once: its scan reads the blocks added since the page last looked, so the
// next attempt starts from the same tip with the same receipts held.
export async function noCoinAttempt(flow) {
  await assert.rejects(flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }), /holds no unspent coin/);
}

// A reveal or claim sent (type 0x50), not the commit's account transaction.
export const isRevealSend = (call) => call.method === "eth_sendRawTransaction" && String(call.params?.[0]).startsWith("0x50");
