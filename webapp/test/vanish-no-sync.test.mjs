// The first Vanish of a session sends its commit without checking the
// header chain first: the floor for its receipt is the endpoint's raw
// eth_blockNumber and the base fee is read from the endpoint's tip header,
// so no header is checked (no seal, no chainAdd) before the wallet is asked.
// The commit is still confirmed afterwards through the verified header
// chain, so one sent onto a chain whose headers fail their checks is never
// shown Done. The flow runs against the node stand-in on a long chain with
// the tests' wallet connector (support/env.mjs).

import assert from "node:assert/strict";
import test from "node:test";

import { nextBaseFee } from "../src/chain.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow } from "../src/flow.mjs";
import { TEST_WALLET_ADDRESS, loadModule, nodeProver, testConnector } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
// Long enough that checking it would take many header reads and seal
// checks; the send needs one header read whatever the length.
const LONG_CHAIN = 60;

// A flow on the node stand-in whose chain is LONG_CHAIN blocks long. Every
// request to the worker is listed in `ops`, and `asked` holds what had
// happened when the wallet was asked to sign: the worker's requests and the
// endpoint's requests up to then, and the fields it was asked to sign.
async function setUp() {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  node.mineTo(LONG_CHAIN);
  const prover = nodeProver();
  const ops = [];
  const request = prover.request.bind(prover);
  prover.request = (op, args, onProgress) => {
    ops.push(op);
    return request(op, args, onProgress);
  };
  node.fund(TEST_WALLET_ADDRESS, 100n * GHOST);
  const asked = [];
  const connector = testConnector({
    approve: async (fields) => {
      asked.push({ ops: [...ops], requests: node.requests.map((r) => r.method), fields });
    },
  });
  const flow = createFlow({
    prover,
    endpoint: node.url,
    commitEntry: DEFAULT_COMMIT_ENTRY,
    networks: node.networks(),
    pollMs: 5,
    sleep: async () => node.mine(),
  });
  const done = async () => {
    prover.terminate();
    await node.close();
  };
  return { node, flow, connector, ops, asked, done };
}

const rightWords = (v) => {
  const words = v.key.split(" ");
  return v.groups.map((p) => words[p - 1]);
};

const HEADER_CHECKS = ["chainStart", "chainAdd", "chainView"];

test("the first Vanish of a session asks the wallet and sends before any header is checked", async () => {
  const { node, flow, connector, ops, asked, done } = await setUp();
  try {
    await flow.walletConnect(connector);
    await flow.vanishStart("1");
    flow.vanishSaved();
    const sent = await flow.vanishCheck(rightWords(flow.state.vanish));
    assert.equal(sent.ok, true);
    assert.equal(asked.length, 1, "the wallet was asked once");

    const before = asked[0];
    for (const op of HEADER_CHECKS) {
      assert.ok(!before.ops.includes(op), `no ${op} before the wallet is asked: ${before.ops.join(", ")}`);
    }
    // One header read, the tip's for its base fee, not one per block.
    const headerReads = before.requests.filter((m) => m === "eth_getBlockByNumber");
    assert.equal(headerReads.length, 1, before.requests.join(", "));
    assert.equal(before.requests.filter((m) => m === "eth_blockNumber").length, 1);

    // The base fee is the one the endpoint's tip at the send leads to.
    const tip = node.blocks[LONG_CHAIN];
    const priority = before.fields.maxPriorityFeePerGas;
    const header = { baseFee: tip.baseFee, gasUsed: BigInt(tip.json.gasUsed), gasLimit: BigInt(tip.json.gasLimit) };
    assert.equal(before.fields.maxFeePerGas, 2n * nextBaseFee(header) + priority);

    // The commit was then confirmed through the verified header chain.
    assert.ok(ops.includes("chainAdd"), "the header chain is checked after the send");
    assert.equal(flow.state.vanish.stage, "done");
    assert.ok(sent.block > LONG_CHAIN, `the commit is in block ${sent.block}, after the send`);
    assert.equal(node.accountTxs.length, 1);
  } finally {
    await done();
  }
});

test("a commit sent onto a chain whose headers fail their checks is never shown Done", async () => {
  const { node, flow, connector, ops, asked, done } = await setUp();
  try {
    await flow.walletConnect(connector);
    await flow.vanishStart("1");
    flow.vanishSaved();
    // Every block from here on carries a difficulty the schedule does not
    // require: the endpoint's chain, the one the commit lands in, fails.
    node.setDifficulty(1n << 200n);
    node.mine();
    await assert.rejects(flow.vanishCheck(rightWords(flow.state.vanish)));
    assert.equal(asked.length, 1, "the commit was sent without a header check");
    assert.ok(!asked[0].ops.includes("chainAdd"));
    assert.equal(node.accountTxs.length, 1);
    assert.ok(ops.includes("chainAdd"), "the header chain was checked after the send");
    assert.notEqual(flow.state.vanish.stage, "done");

    // That chain is now known to fail: the next Vanish checks it again
    // before anything is signed, and sends nothing while it still fails.
    assert.ok(flow.state.chainRefused, "the endpoint's chain is refused");
    await flow.vanishStart("1");
    flow.vanishSaved();
    await assert.rejects(flow.vanishCheck(rightWords(flow.state.vanish)), /difficulty/);
    assert.equal(asked.length, 1, "the wallet is not asked again");
    assert.equal(node.accountTxs.length, 1);
  } finally {
    await done();
  }
});
