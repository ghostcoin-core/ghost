// The pinned start of the public test network: scripts/make-pin.mjs takes a
// pin from a node's headers (each hash, parent link and difficulty, from
// genesis) and checks the other nodes agree; this build ships one for
// 6777972, and the deploy serves a fresher one as pin.json, which the page
// takes when it is newer (header.mjs, withServedPin and loadNetworks). From a
// pin the page seal-checks only the headers after it, and when it is far
// behind it says how many it has checked.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, createFlow, headersStage, readingStage } from "../src/flow.mjs";
import { EPOCH_BLOCKS, NETWORKS, SERVED_PIN_URL, loadNetworks, withServedPin } from "../src/header.mjs";
import { checkPin, makePin } from "../scripts/make-pin.mjs";
import { loadModule, nodeProver, openTestWallet } from "./support/env.mjs";
import { FAKE_CHAIN_ID, startFakeNode } from "./support/fake-node.mjs";

const ID = String(FAKE_CHAIN_ID);

function answersFor(key, positions) {
  const groups = key.split(" ");
  return positions.map((p) => groups[p - 1]);
}

async function vanish(flow, amount = "1") {
  const key = await flow.vanishStart(amount);
  const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
  return { key, sent };
}

// The pin `node.networks({ pinAt })` names, in make-pin's form.
function expectedPin(node, height) {
  const { pin } = node.networks({ pinAt: height })[ID];
  return {
    chainId: ID,
    hash: pin.hash.toLowerCase(),
    height,
    totalWork: String(pin.totalWork),
    keyBlocks: pin.keyBlocks.map(([h, hash]) => [h, hash.toLowerCase()]),
  };
}

// A prover that records the hash of every header given to the worker's
// chain with its seal checked (chainAdd), and each chainStart.
function recordingProver() {
  const inner = nodeProver();
  const sealed = [];
  const starts = [];
  return {
    sealed,
    starts,
    request(op, args, onProgress) {
      if (op === "chainAdd") for (const { hash } of args.headers) sealed.push(toHex(hash));
      if (op === "chainStart") starts.push(args.start);
      return inner.request(op, args, onProgress);
    },
    terminate: () => inner.terminate(),
  };
}

// A fetch that serves `pin` as the page's pin.json and passes every other
// request on.
const servingPin = (pin) => (url, init) =>
  String(url) === SERVED_PIN_URL.href
    ? Promise.resolve(new Response(JSON.stringify(pin), { headers: { "content-type": "application/json" } }))
    : fetch(url, init);

// --- make-pin against a node ---

test("make-pin walks the node's headers from genesis and gives the pin its table names", async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  try {
    node.foreignCommits(2);
    node.mineTo(20);
    const pin = await makePin({ endpoints: [node.url], networks: node.networks(), depth: 5 });
    assert.deepEqual(pin, expectedPin(node, 15));
    assert.deepEqual(await checkPin({ endpoints: [node.url], networks: node.networks(), pin, chainId: ID }), pin);
    await assert.rejects(
      checkPin({ endpoints: [node.url], networks: node.networks(), pin: { ...pin, totalWork: String(BigInt(pin.totalWork) + 1n) }, chainId: ID }),
      /the pin differs from the nodes' headers/,
    );
    await assert.rejects(
      checkPin({ endpoints: [node.url], networks: node.networks(), pin: { ...pin, hash: toHex(new Uint8Array(32).fill(1)) }, chainId: ID }),
      /the pin differs/,
    );
  } finally {
    await node.close();
  }
});

test("make-pin refuses a header that does not hash, another genesis, and a node that disagrees", async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, genesisTime: 1_760_000_000 });
  const other = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, genesisTime: 1_760_000_600 });
  try {
    node.mineTo(20);
    other.mineTo(20);
    const networks = node.networks();
    await assert.rejects(makePin({ endpoints: [node.url, other.url], networks, depth: 5 }), /disagrees: its block/);

    node.dishonest.header = (json) => (json.number === "0x7" ? { ...json, gasUsed: "0x1" } : json);
    await assert.rejects(makePin({ endpoints: [node.url], networks, depth: 5 }), /block 7 does not hash to the hash the node returned/);
    node.dishonest.header = null;

    // The other node's chain is not this build's genesis.
    await assert.rejects(makePin({ endpoints: [other.url], networks, depth: 5 }), /block 0 is not this build's genesis/);
  } finally {
    await node.close();
    await other.close();
  }
});

// --- The flow from a pin ---

test("from a served pin, only the headers after it are seal-checked, and a Vanish reaches Done", async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  node.foreignCommits(2);
  node.mineTo(30);
  const pin = await makePin({ endpoints: [node.url], networks: node.networks(), depth: 6 });
  const prover = recordingProver();
  // The build's table has no pin for this network: the served one is used.
  const flow = createFlow({
    prover,
    fetch: servingPin(pin),
    servedPin: true,
    endpoint: node.url,
    networks: node.networks(),
    pollMs: 5,
    maxPolls: 20,
    sleep: async () => node.mine(),
  });
  try {
    await openTestWallet(flow, node);
    const { sent } = await vanish(flow);
    assert.equal(sent.ok, true);
    assert.equal(flow.state.vanish.stage, "done");
    assert.deepEqual(
      prover.starts.map((s) => s.height),
      [pin.height],
      "the chain starts at the pin",
    );
    const numberOf = new Map(node.blocks.map((b, n) => [toHex(b.hash), n]));
    const numbers = prover.sealed.map((h) => numberOf.get(h));
    assert.deepEqual(
      numbers,
      Array.from({ length: node.tip() - pin.height }, (_, i) => pin.height + 1 + i),
      "every header after the pin, once each, and none at or below it",
    );
  } finally {
    prover.terminate();
    await node.close();
  }
});

test("far behind its pin, the sync says how many headers it has read and checked", async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  node.foreignCommits(2);
  node.mineTo(90);
  const prover = nodeProver();
  const stages = [];
  const flow = createFlow({
    prover,
    endpoint: node.url,
    networks: node.networks({ pinAt: 1 }),
    sealCheckBound: 40,
    pollMs: 5,
    maxPolls: 20,
    sleep: async () => node.mine(),
    onChange: (state) => {
      const stage = state.progress && state.progress.stage;
      if (stage && stages.at(-1) !== stage) stages.push(stage);
    },
  });
  try {
    await openTestWallet(flow, node);
    const { sent } = await vanish(flow);
    assert.equal(sent.ok, true);
    const total = stages.map((s) => /^checking headers: \d+ of (\d+)$/.exec(s)).find(Boolean);
    assert.ok(total, `a checking stage is shown: ${stages.join(" | ")}`);
    const n = Number(total[1]);
    assert.ok(n > 40, "only past the bound");
    for (let checked = 0; checked < n; checked += 32) assert.ok(stages.includes(headersStage(checked, n)), `${checked} of ${n}`);
    assert.ok(stages.includes(readingStage(64)), stages.join(" | "));
  } finally {
    prover.terminate();
    await node.close();
  }
});

test("the Vanish card says how many headers are checked, in fixed words", () => {
  const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");
  const fn = /^function sentCheckingLine\(stage\) \{[\s\S]*?^\}$/m.exec(source);
  assert.ok(fn, "app.mjs has sentCheckingLine");
  const sentCheckingLine = new Function(`${fn[0]}\nreturn sentCheckingLine;`)();
  assert.equal(sentCheckingLine(headersStage(1024, 2300)), "Sent. Checking block headers: 1,024 of 2,300…");
  assert.equal(sentCheckingLine(readingStage(640)), "Sent. Reading block headers: 640 so far…");
  assert.equal(sentCheckingLine("checking the block"), "Sent. Checking the block that holds it…");
});

// --- This build's pin and the served one ---

test("this build pins the public test network, and the page asks for the pin's block, not genesis", async () => {
  const net = NETWORKS["6777972"];
  const { pin } = net;
  assert.ok(pin, "6777972 has a pinned start");
  assert.match(pin.hash, /^0x[0-9a-f]{64}$/);
  assert.ok(Number.isSafeInteger(pin.height) && pin.height >= 39936);
  assert.match(pin.totalWork, /^[1-9][0-9]*$/);
  assert.deepEqual(
    pin.keyBlocks.map(([h]) => h),
    Array.from({ length: Math.ceil(pin.height / EPOCH_BLOCKS) }, (_, i) => i * EPOCH_BLOCKS),
    "every key block below the pin",
  );
  assert.equal(pin.keyBlocks[0][1], net.genesisHash);
  assert.equal(withServedPin(NETWORKS, { chainId: "6777972", ...pin }), NETWORKS, "the shipped pin is well formed");

  // A stand-in serving network 6777972: the page's first header request is
  // the pin's block (which the stand-in does not have), never genesis.
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY, chainId: 6777972n });
  const prover = nodeProver();
  const flow = createFlow({ prover, endpoint: node.url, networks: NETWORKS });
  try {
    await openTestWallet(flow, node);
    const key = await flow.vanishStart("1");
    const from = node.requests.length;
    await assert.rejects(flow.summonOpen(key), new RegExp(`the endpoint has no block ${pin.height}`));
    const asked = node.requests
      .slice(from)
      .filter((r) => r.method === "eth_getBlockByNumber")
      .map((r) => r.params[0]);
    assert.deepEqual(asked, [`0x${pin.height.toString(16)}`]);
  } finally {
    prover.terminate();
    await node.close();
  }
});

test("a served pin is taken only when well formed and newer than the build's", async () => {
  const base = NETWORKS["6777972"];
  const height = base.pin.height + 2 * EPOCH_BLOCKS + 5;
  const keyBlocks = Array.from({ length: Math.ceil(height / EPOCH_BLOCKS) }, (_, i) => [
    i * EPOCH_BLOCKS,
    i === 0 ? base.genesisHash : toHex(new Uint8Array(32).fill(i)),
  ]);
  const good = { chainId: "6777972", hash: toHex(new Uint8Array(32).fill(9)), height, totalWork: "123456789012", keyBlocks };
  const taken = withServedPin(NETWORKS, good);
  assert.notEqual(taken, NETWORKS);
  assert.equal(taken["6777972"].pin.height, height);
  assert.equal(taken["6777972"].genesisHash, base.genesisHash);
  assert.equal(NETWORKS["6777972"].pin.height, base.pin.height, "the build's table is left as it is");

  const refused = {
    "older": { ...good, height: base.pin.height - 1, keyBlocks: keyBlocks.slice(0, Math.ceil((base.pin.height - 1) / EPOCH_BLOCKS)) },
    "the same height": { ...good, height: base.pin.height, keyBlocks: keyBlocks.slice(0, Math.ceil(base.pin.height / EPOCH_BLOCKS)) },
    "another network": { ...good, chainId: "1" },
    "a short hash": { ...good, hash: "0x1234" },
    "no work": { ...good, totalWork: "0" },
    "a number for the work": { ...good, totalWork: 5 },
    "a missing key block": { ...good, keyBlocks: keyBlocks.slice(1) },
    "another genesis": { ...good, keyBlocks: [[0, toHex(new Uint8Array(32).fill(0xee))], ...keyBlocks.slice(1)] },
    "a key block off the epoch": { ...good, keyBlocks: [...keyBlocks.slice(0, -1), [keyBlocks.at(-1)[0] + 1, keyBlocks.at(-1)[1]]] },
    "not an object": "pin",
    "nothing": null,
  };
  for (const [what, served] of Object.entries(refused)) assert.equal(withServedPin(NETWORKS, served), NETWORKS, what);

  const respond = (status, body) => async () => new Response(body, { status });
  assert.equal((await loadNetworks({ fetch: respond(200, JSON.stringify(good)) }))["6777972"].pin.height, height);
  assert.equal(await loadNetworks({ fetch: respond(404, "") }), NETWORKS, "no pin.json");
  assert.equal(await loadNetworks({ fetch: respond(200, "not json") }), NETWORKS, "a malformed one");
  assert.equal(
    await loadNetworks({
      fetch: async () => {
        throw new Error("offline");
      },
    }),
    NETWORKS,
    "a failed fetch",
  );
});
