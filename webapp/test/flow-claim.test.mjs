// The flow controller against the node stand-in, continued from
// flow.test.mjs (split so each file fits a CI job): claims, altered
// headers, the next fee window, commit sends and the page's endpoint and
// scripts.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { toHex } from "../src/bytes.mjs";
import {
  COMMIT_GAS_CAP,
  DEFAULT_COMMIT_ENTRY,
  PRIORITY_FEE_CAP,
  ZERO_ADDRESS,
  createFlow,
} from "../src/flow.mjs";
import { DEFAULT_ENDPOINT } from "../src/rpc.mjs";
import { TEST_WALLET_ADDRESS, webappDir } from "./support/env.mjs";
import {
  GHOST,
  SPEC_FEE,
  RECIPIENT,
  answersFor,
  setUp,
  relative,
  vanish,
  isRevealSend,
} from "./support/flow-setup.mjs";

// A key with a coin old enough to claim, opened, and a new key whose save
// check is under way; the right answers for it.
async function readyToClaim(node, flow) {
  const key = await vanish(flow, "1");
  node.mineTo(40);
  node.foreignCommits(1);
  node.mineTo(80);
  assert.equal((await flow.summonOpen(key)).status, "unclaimed");
  const newKey = await flow.claimStart();
  return answersFor(newKey, flow.claimSaved());
}

test("headers whose coin root was altered under their real hash are refused", async () => {
  const { node, flow, done } = await setUp();
  try {
    const answers = await readyToClaim(node, flow);
    // The endpoint withholds the claim and serves, from a new block on, a
    // coin tree that holds the claim's new coin, with each header's
    // coinTreeRoot set to that tree's root and its hash left as it was.
    node.dishonest.withhold = (hash, reveal) => {
      const block = node.mine();
      node.dishonest.forge = { from: block, extra: [{ commitment: reveal.remainder, note: reveal.note }] };
      return { transactionHash: hash, status: "0x1", blockNumber: `0x${block.toString(16)}` };
    };
    await assert.rejects(flow.claimCheck(answers), /does not hash to/);
    assert.equal(node.withheld.length, 1);
    assert.equal(node.reveals.length, 0, "the claim was never executed");
    assert.notEqual(flow.state.summon.claim.stage, "done");
    assert.equal(flow.state.summon.status, "unclaimed");
    // A fresh look at the key refuses the altered tip header too.
    await assert.rejects(flow.summonRefresh(), /does not hash to/);
    assert.equal(flow.state.summon.status, "unclaimed");
  } finally {
    await done();
  }
});

test("a claim is Done, and the old key claimed, at the first block that holds it", async () => {
  const { node, flow, chain, done } = await setUp();
  try {
    const answers = await readyToClaim(node, flow);
    // No block is mined while the app waits: only the claim's own block.
    chain.mining = false;
    const claimed = await flow.claimCheck(answers);
    assert.equal(node.reveals.length, 1, "the claim is in a block");
    const block = node.reveals[0].block;
    assert.equal(node.tip(), block, "no block on top of the claim's");
    assert.equal(claimed.block, block);
    const s = flow.state.summon;
    assert.equal(s.claim.stage, "done");
    assert.equal(s.status, "claimed", "the old key shows claimed at the claim's own block");
    assert.equal((await flow.summonRefresh()).status, "claimed");
    assert.equal(node.tip(), block);
  } finally {
    await done();
  }
});

test("a coin nobody committed after is summoned once its own block is 2 deep", async () => {
  const { node, flow, chain, done } = await setUp();
  try {
    const lonely = await vanish(flow, "1");
    const block = node.leaves.at(-1).block;
    // Its block is not yet 2 deep: one plain line, no other commit asked for.
    chain.mining = false;
    let s = await flow.summonOpen(lonely);
    assert.equal(s.status, "unclaimed");
    assert.equal(s.cover, null);
    assert.equal(s.wait.from, block + 2);
    assert.match(s.wait.message, new RegExp(`block ${block}, is not yet 2 blocks deep`));

    // Two blocks later, with nobody else committing, it can be revealed
    // against its own block's tree.
    node.mineTo(block + 2);
    s = await flow.summonOpen(lonely);
    assert.equal(s.wait, null);
    assert.deepEqual(s.cover, { height: block, covers: node.leaves.length, total: node.leaves.length });
    chain.mining = true;
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.equal(node.reveals.length, 1);
    assert.equal(toHex(node.reveals[0].root), toHex(node.blocks[block].coinTreeRoot), "the root of the coin's own block");
    assert.ok(reveal.block > block + 2);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n);
  } finally {
    await done();
  }
});

// A Summon proves only when at least two blocks of the next block's window
// are left and that block's base fee is within the window fee's cover limit;
// otherwise it waits, a block at a time, for the next window's fee.
test("the reveal waits for the next fee window", async () => {
  const GWEI = 10n ** 9n;
  let node = null;
  // The node's tip at each reveal send.
  const sentAt = [];
  const fetch = async (url, init) => {
    if (isRevealSend(JSON.parse(init.body))) sentAt.push(node.tip());
    return globalThis.fetch(url, init);
  };
  const set = await setUp({ fetch });
  ({ node } = set);
  const { flow, hooks, done } = set;
  // The node's tip at each proof.
  const provedAt = [];
  hooks.prove = (args) => {
    provedAt.push(node.tip());
    return args;
  };
  try {
    const first = await vanish(flow, "1");
    const second = await vanish(flow, "1");
    node.foreignCommits(1);

    // Tip 78: the next block, 79, is the last of the window that starts at
    // block 76, so nothing is proved or sent until block 79 is the tip and
    // the next block starts window 20.
    node.mineTo(78);
    assert.equal((await flow.summonOpen(first)).status, "unclaimed");
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.deepEqual(provedAt, [79], "proved once, for the window that starts at block 80");
    assert.deepEqual(sentAt, [79]);
    assert.equal(node.reveals.length, 1);
    assert.equal(node.reveals[0].fee, node.fee(80));
    assert.equal(node.reveals[0].fee, SPEC_FEE);

    // Tip 85 in the window that starts at block 84 (b_ref 1 gwei), two of
    // its blocks left, but block 85 was mined at 2 gwei: the next block's
    // base fee is past the window fee's cover limit of 1,237,555,001 wei.
    // The app waits for block 88, the next window's start, and proves for its
    // fee, priced from 2 gwei.
    node.mineTo(84);
    node.setBaseFee(2n * GWEI);
    node.mine();
    assert.equal(node.tip(), 85);
    assert.equal((await flow.summonOpen(second)).status, "unclaimed");
    provedAt.length = 0;
    sentAt.length = 0;
    await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });
    assert.deepEqual(provedAt, [87], "proved once, for the window that starts at block 88");
    assert.deepEqual(sentAt, [87]);
    assert.equal(node.reveals.length, 2);
    assert.equal(node.reveals[1].fee, node.fee(88));
    assert.ok(node.reveals[1].fee > SPEC_FEE, "the fee of the next window, priced from 2 gwei");
  } finally {
    await done();
  }
});

test("a commit the node takes but answers with an error is shown Sent, and one it does not take is refused", async () => {
  const { node, flow, done } = await setUp();
  try {
    node.quirks.errorAfterAccountTx = true;
    const key = await flow.vanishStart("1");
    const sent = await flow.vanishCheck(answersFor(key, flow.vanishSaved()));
    assert.equal(sent.ok, true);
    assert.equal(sent.txHash, node.accountTxs[0].hash);
    assert.equal(flow.state.vanish.stage, "done");
    // A refusal the node means: nothing is held, the error stands.
    node.quirks.errorAfterAccountTx = false;
    node.quirks.refuseAccountTx = true;
    const again = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(again, flow.vanishSaved())), /txpool is full/);
    assert.equal(node.accountTxs.length, 1);
    // An endpoint that asks for a large priority fee or gas: the priority
    // fee is held at its cap, and gas above the cap is refused unsigned.
    node.quirks.refuseAccountTx = false;
    node.quirks.priorityFee = 1000n * PRIORITY_FEE_CAP;
    const capped = await flow.vanishStart("1");
    assert.equal((await flow.vanishCheck(answersFor(capped, flow.vanishSaved()))).ok, true);
    assert.equal(node.accountTxs[1].maxPriorityFeePerGas, PRIORITY_FEE_CAP);
    node.quirks.estimateGas = COMMIT_GAS_CAP;
    const heavy = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(heavy, flow.vanishSaved())), /more than the 500000 the app signs/);
    node.quirks.estimateGas = null;
    node.setBaseFee(10n ** 12n);
    node.mine();
    const pricey = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(pricey, flow.vanishSaved())), /more than the 0\.01 GHOST the app signs/);
    assert.equal(node.accountTxs.length, 2);
    // A balance that cannot pay: nothing is signed or sent.
    node.setBaseFee(10n ** 9n);
    node.mine();
    node.fund(TEST_WALLET_ADDRESS, 0n);
    const sends = node.requests.filter((r) => r.method === "eth_sendRawTransaction").length;
    const third = await flow.vanishStart("1");
    await assert.rejects(flow.vanishCheck(answersFor(third, flow.vanishSaved())), /less than the amount/);
    assert.equal(node.requests.filter((r) => r.method === "eth_sendRawTransaction").length, sends);
  } finally {
    await done();
  }
});

test("the built-in endpoint is the local internal network", () => {
  const flow = createFlow({ prover: { request: async () => ({}) } });
  assert.equal(flow.state.endpoint, new URL(DEFAULT_ENDPOINT).href);
  assert.match(DEFAULT_ENDPOINT, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.throws(() => flow.setEndpoint("ftp://example.org"), /http or https/);
  assert.throws(() => flow.setEndpoint("https://user:pw@example.org"), /user name/);
  assert.equal(flow.setEndpoint("https://node.example.org/rpc"), "https://node.example.org/rpc");
  assert.throws(() => flow.setCommitEntry(ZERO_ADDRESS), /zero address/);
  assert.equal(flow.state.commitEntry, DEFAULT_COMMIT_ENTRY, "a refused entry leaves the setting as it was");
  assert.equal(flow.setCommitEntry(RECIPIENT), RECIPIENT);
});

test("index.html loads only same-origin scripts and names no external URL", async () => {
  const html = await readFile(resolve(webappDir, "index.html"), "utf8");
  assert.doesNotMatch(html, /https?:\/\//i, "no absolute http URL");
  assert.doesNotMatch(html, /(src|href)\s*=\s*["']?\/\//i, "no protocol-relative URL");
  const scripts = [...html.matchAll(/<script\b([^>]*)>/gi)].map((m) => m[1]);
  assert.ok(scripts.length >= 1);
  for (const attrs of scripts) {
    const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs);
    assert.ok(src, "no inline script");
    assert.match(src[1], /^\.?\/?[\w./-]+\.mjs$/, `script ${src[1]} is not a same-origin module`);
  }
  for (const m of html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
    assert.doesNotMatch(m[1], /^[a-z][a-z0-9+.-]*:/i, `${m[1]} is not same-origin`);
  }
  const csp = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i.exec(html);
  assert.ok(csp, "a Content-Security-Policy");
  assert.match(csp[1], /script-src 'self'/);
  assert.match(csp[1], /default-src 'none'|default-src 'self'/);
});
