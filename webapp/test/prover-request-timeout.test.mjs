// No wait on the worker can hang forever. A Vanish whose commit a block
// already held stayed on its Sent line for hours: after the receipt, the
// settle path (waitSettled, and Check again through recheckDone) asks the
// worker for each step of the header chain and the coin trees (chainStart,
// chainAdd, chainView, treeCheck, prefixRoots...), and a worker that never
// answers (one that errs without replying, or is stuck) held that promise,
// and the card, for good. Every worker request now fails after a fixed
// 120 seconds with "the worker did not answer in time".
//
// The stand-in here has the same shape: a worker that takes the request and
// never answers, under the flow's settle check against the public test
// network's recorded chain (fixtures/public-testnet-headers.json, chain
// 6777972). Without the bound the check never returns and the test runs
// into its timeout. No module build is needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { createFlow } from "../src/flow.mjs";
import { WORKER_TIMEOUT, WORKER_TIMEOUT_MS, createProver, isWorkerTimeout } from "../src/prover.mjs";

const CHAIN_ID = 6_777_972;
const BLOCKS = JSON.parse(readFileSync(new URL("./fixtures/public-testnet-headers.json", import.meta.url), "utf8"));
const NOW = Number(BigInt(BLOCKS.at(-1).timestamp)) + 60;

// A worker port that takes every request and answers none of them, unless
// `answer` replies; `posted` is every message the page sent.
function silentPort(answer = () => {}) {
  const posted = [];
  let reply = () => {};
  return {
    posted,
    reply: (message) => reply(message),
    port: {
      post: (message) => {
        posted.push(message);
        answer(message, (r) => reply(r));
      },
      listen: (handler) => {
        reply = handler;
      },
      terminate() {},
    },
  };
}

test("every worker request is bounded by a fixed 120 seconds", () => {
  assert.equal(WORKER_TIMEOUT_MS, 120000);
  assert.equal(WORKER_TIMEOUT, "the worker did not answer in time");
  const timers = [];
  const { port } = silentPort();
  const prover = createProver(port, { setTimer: (fn, ms) => timers.push({ fn, ms }), clearTimer: () => {} });
  for (const op of ["chainAdd", "chainView", "treeCheck", "prefixRoots", "receiptsCheck"]) prover.request(op).catch(() => {});
  assert.deepEqual(
    timers.map((t) => t.ms),
    [120000, 120000, 120000, 120000, 120000],
    "each request gets its own timer of the default bound",
  );
});

test("a request the worker never answers fails with the plain timeout message", async () => {
  const { port, posted } = silentPort();
  const prover = createProver(port, { timeoutMs: 20 });
  const started = Date.now();
  await assert.rejects(prover.request("prefixRoots", { from: 0, to: 4 }), (err) => {
    assert.ok(err.message.includes("the worker did not answer in time"), err.message);
    assert.match(err.message, /prefixRoots/, "the message names the step");
    assert.ok(isWorkerTimeout(err));
    return true;
  });
  assert.ok(Date.now() - started < 5000, "it fails at the bound, not later");
  assert.equal(posted.length, 1, "the request was sent once");
  assert.ok(!isWorkerTimeout(new Error("the worker stopped: closed")));
});

test("progress is not an answer, an answer in time stops the timer, and a late answer is ignored", async () => {
  const cleared = [];
  const timers = [];
  const { port, reply } = silentPort();
  const prover = createProver(port, {
    setTimer: (fn, ms) => timers.push({ fn, ms }) - 1,
    clearTimer: (t) => cleared.push(t),
  });

  const stages = [];
  const answered = prover.request("chainAdd", {}, (stage) => stages.push(stage));
  reply({ id: 1, type: "progress", stage: "checking the proof of work of the endpoint's headers" });
  assert.deepEqual(cleared, [], "a progress reply leaves the bound in force");
  reply({ id: 1, type: "result", result: { adopted: 3 } });
  assert.deepEqual(await answered, { adopted: 3 });
  assert.deepEqual(stages, ["checking the proof of work of the endpoint's headers"]);
  assert.deepEqual(cleared, [0], "the answered request's timer is stopped");

  const late = prover.request("chainView");
  timers[1].fn();
  await assert.rejects(late, /the worker did not answer in time/);
  // The worker's answer after the bound changes nothing.
  reply({ id: 2, type: "result", result: { hashes: [] } });
  reply({ id: 2, type: "error", message: "too late" });

  // A worker that dies fails what is still open, once.
  const open = prover.request("treeCheck");
  prover.fail("out of memory");
  await assert.rejects(open, /the worker stopped: out of memory/);
  timers[2].fn();
});

// The public test network's recorded chain as a public endpoint serves it:
// headers only, every other method refused.
function publicEndpoint() {
  const answer = (method, params) => {
    if (method === "eth_chainId") return { result: `0x${CHAIN_ID.toString(16)}` };
    if (method === "eth_blockNumber") return { result: BLOCKS.at(-1).number };
    if (method === "eth_getBlockByNumber") {
      const n = params[0] === "latest" ? BLOCKS.length - 1 : Number(BigInt(params[0]));
      return { result: BLOCKS[n] ?? null };
    }
    return { error: { code: -32601, message: `the stand-in serves no ${method}` } };
  };
  return async (_url, { body }) => {
    const { id, method, params } = JSON.parse(body);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id, ...answer(method, params) }), {
      headers: { "content-type": "application/json" },
    });
  };
}

test("the settle check of a Sent commit ends when the worker never answers, and the commit stays Sent", async () => {
  const { port, posted } = silentPort();
  const prover = createProver(port, { timeoutMs: 50 });
  const flow = createFlow({ prover, fetch: publicEndpoint(), clock: () => NOW, sleep: async () => {} });
  // A commit the node took: shown Sent, with its transaction and new leaf.
  flow.state.vanish = {
    stage: "sent",
    amount: 10n ** 18n,
    txHash: "0x03a988bc9aef12bddfe8b3608df3b531e5a5e2473b2cf9bc24b3054ad595628b",
    commitment: new Uint8Array(32).fill(7),
    block: null,
    blockHash: null,
    dropped: null,
  };

  await assert.rejects(flow.vanishRecheck(), (err) => {
    assert.ok(err.message.includes("the worker did not answer in time"), err.message);
    return true;
  });
  assert.ok(posted.length >= 1, "the check reached the worker");
  assert.equal(posted[0].op, "chainStart", "the header chain's first step is the one that got no answer");
  assert.equal(flow.state.vanish.stage, "sent", "the commit is neither Done nor dropped");
  assert.equal(flow.state.busy, null, "the page is free to check again");
  assert.equal(flow.state.progress, null);
  assert.equal(flow.state.chainRefused, null, "a silent worker says nothing of the chain");

  // The check can be asked again, and again ends.
  await assert.rejects(flow.vanishRecheck(), /the worker did not answer in time/);
  assert.equal(flow.state.vanish.stage, "sent");
});

test("Check again is refused only when no commit was sent", async () => {
  const { port } = silentPort();
  const flow = createFlow({ prover: createProver(port, { timeoutMs: 50 }), fetch: publicEndpoint(), sleep: async () => {} });
  await assert.rejects(flow.vanishRecheck(), /no commit is shown Sent or Done/);
  flow.state.vanish = { stage: "check", amount: 1n };
  await assert.rejects(flow.vanishRecheck(), /no commit is shown Sent or Done/);
});
