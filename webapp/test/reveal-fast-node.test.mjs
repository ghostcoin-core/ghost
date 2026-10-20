// A Summon reveal against a stand-in that plays the CI node: a block about
// every 20 ms, the head-moving refusal of a send, a next-block fee that
// changes between that refusal and the resend (so the reveal is proved
// again), and a node that takes the new proof's first send and lets it go
// before any block holds it, as ghost-node's pool drops a held reveal whose
// check fails on a new head (ghostpool Reset). That last step is what hung the
// real-node job: the app waited for the receipt of a reveal the node no
// longer held until the job was cancelled.
//
// The flow runs with the real-node test's settings (a receipt asked every
// second, 1,800 times) and real time, and must finish within a bound with
// the reveal in a block, the recipient paid once and every proof of the same
// coin.

import assert from "node:assert/strict";
import test from "node:test";

import { fromHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, HEAD_MOVED_SENDS, createFlow } from "../src/flow.mjs";
import { loadModule, nodeProver } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
const GWEI = 10n ** 9n;
const ACCOUNT = "0x1111111111111111111111111111111111111111";
const RECIPIENT = "0x2222222222222222222222222222222222222222";
// The whole Summon, from the click to its settled block. Two proofs, a few
// still-tip waits and the 6 blocks on top take well under this; a wait for a
// block that never comes takes the 1,800 polls of a second each.
const BOUND_MS = 240_000;

test("a Summon reveal on a node that mines every 20 ms, refuses, changes its fee and drops a taken send completes, paid once", { timeout: 600_000 }, async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const wallet = node.wallet(ACCOUNT);
  const worker = nodeProver();
  const proofs = [];
  const prover = {
    request(op, args, onProgress) {
      if (op === "prove") proofs.push({ decoy: Boolean(args && args.decoy), number: args?.number, position: args?.position });
      return worker.request(op, args, onProgress);
    },
  };
  // Every send and the node's answer; the first refusal raises the base fee
  // of the blocks mined from then on, so the fee window changes before the
  // resend.
  const sends = [];
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    const response = await globalThis.fetch(url, init);
    if (call.method === "eth_sendRawTransaction") {
      const { error } = await response.clone().json();
      sends.push({ envelope: call.params[0], error: error?.message ?? null });
      if (error && sends.length === 1) node.setBaseFee(2n * GWEI);
    }
    return response;
  };
  const stages = [];
  const flow = createFlow({
    prover,
    wallet,
    endpoint: node.url,
    fetch,
    pollMs: 1000,
    maxPolls: 1800,
    onChange: (s) => {
      const stage = s.progress?.stage;
      if (stage && stages[stages.length - 1] !== stage) stages.push(stage);
    },
  });
  try {
    // A block every 20 ms throughout, a stranger's commit in every 8th, so
    // a settled block soon holds a commitment after the coin and a proof
    // made later can still be made.
    node.foreignCommits(2);
    node.startMining(20, { refuse: false, commitEvery: 8 });
    const key = await flow.vanishStart("1");
    const vanished = await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]));
    assert.equal(vanished.ok, true);
    // Until well past a settled block that holds the coin and a later
    // commitment.
    while (node.tip() < vanished.block + 3 * 32) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal((await flow.summonOpen(key)).status, "unclaimed");

    // The first send is refused as the head moved; the first send the node
    // takes after that is dropped at the next block.
    node.moveHeadOnReveal(1);
    node.dropTaken(1);

    const started = performance.now();
    let timer = null;
    const bound = new Promise((resolve) => {
      timer = setTimeout(() => resolve("bound"), BOUND_MS);
    });
    const outcome = await Promise.race([
      flow.summonReveal({ amount: "0.25", recipient: RECIPIENT }).then(
        (reveal) => ({ reveal }),
        (err) => ({ err }),
      ),
      bound,
    ]);
    clearTimeout(timer);
    const ms = performance.now() - started;
    assert.notEqual(
      outcome,
      "bound",
      `the reveal had not finished after ${BOUND_MS / 1000} s (sends: ${JSON.stringify(sends.map((s) => s.error))}; dropped: ${node.dropped.length}; last stage: ${stages.at(-1)})`,
    );
    if (outcome.err) throw outcome.err;
    const { reveal } = outcome;

    // Refused, proved again at the new fee, taken and dropped, taken.
    assert.equal(node.headMoving.refused, 1, "one send refused as the head moved");
    assert.equal(node.dropped.length, 1, "one taken send dropped before a block held it");
    assert.ok(sends.length >= 3, `a refused send, a dropped one and the one a block holds (${sends.length} sends)`);
    assert.ok(sends.length <= 2 * HEAD_MOVED_SENDS);
    assert.match(sends[0].error, /kept moving/);
    assert.equal(sends.at(-1).error, null);
    assert.notEqual(sends[0].envelope, sends.at(-1).envelope, "a new proof after the fee changed");

    // The reveal is in a block and settled.
    assert.equal(node.reveals.length, 1, "one reveal in a block");
    assert.ok(node.reveals[0].fee > node.fee(0), "it carries the raised fee");
    assert.equal(reveal.block, node.reveals[0].block);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n, "the recipient is paid exactly once");

    // Every proof is of the same coin, and every envelope spends the same
    // marker, so at most one of them could ever be executed.
    const real = proofs.filter((p) => !p.decoy);
    assert.equal(real.length, proofs.length, "no decoy: the coin could be proved each time");
    assert.ok(real.length >= 2);
    assert.ok(real.every((p) => p.number === real[0].number && p.position === real[0].position), "the same coin each time");
    const markers = new Set(
      sends.map((s) => toHexMarker(ghost.decodeEnvelope({ chainId: node.chainId, domain: node.blocks[0].hash, envelope: fromHex(s.envelope) }))),
    );
    assert.equal(markers.size, 1, "one marker across every send");

    assert.equal(flow.state.error, null);
    assert.equal(flow.state.summon.current.amount, GHOST - GHOST / 4n - node.reveals[0].fee);
    assert.ok(ms < BOUND_MS);
  } finally {
    node.stopMining();
    worker.terminate();
    await node.close();
  }
});

function toHexMarker(reveal) {
  return Buffer.from(reveal.marker).toString("hex");
}
