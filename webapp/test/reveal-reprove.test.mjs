// A Summon reveal against a stand-in that plays the CI node as it refused
// on main: a block about every 20 ms, and every send of the first proof's
// envelope refused with the head-moving error, the resends of that same
// envelope included, while the tip keeps advancing. Resending one envelope
// never gets the reveal through there; a new proof for the tip by then does.
// At a block every 20 ms the refused proof's root is far below the tip by
// its first refusal, so the app proves again then instead of sending the
// same envelope up to 5 times.
//
// The Summon must succeed with a reveal whose envelope differs from the
// refused one, the recipient paid once, and every proof made of the first
// proof's input coin, never of another coin.

import assert from "node:assert/strict";
import test from "node:test";

import { fromHex, toHex } from "../src/bytes.mjs";
import { DEFAULT_COMMIT_ENTRY, HEAD_MOVED_PROOFS, HEAD_MOVED_SENDS, STALE_ROOT_DEPTH, createFlow } from "../src/flow.mjs";
import { loadModule, nodeProver } from "./support/env.mjs";
import { startFakeNode } from "./support/fake-node.mjs";

const GHOST = 10n ** 18n;
const ACCOUNT = "0x1111111111111111111111111111111111111111";
const RECIPIENT = "0x2222222222222222222222222222222222222222";

test("a Summon whose first proof the node refuses on every send is proved again and goes through, from the first coin only", { timeout: 600_000 }, async () => {
  const ghost = await loadModule();
  const node = await startFakeNode({ ghost, commitEntry: DEFAULT_COMMIT_ENTRY });
  const wallet = node.wallet(ACCOUNT);
  const worker = nodeProver();
  const proofs = [];
  const prover = {
    request(op, args, onProgress) {
      if (op === "prove") {
        proofs.push({ decoy: Boolean(args && args.decoy), number: args?.number, position: args?.position, amount: args?.amount });
      }
      return worker.request(op, args, onProgress);
    },
  };
  const sends = [];
  const fetch = async (url, init) => {
    const call = JSON.parse(init.body);
    const response = await globalThis.fetch(url, init);
    if (call.method === "eth_sendRawTransaction") {
      const { error } = await response.clone().json();
      sends.push({ envelope: String(call.params[0]).toLowerCase(), error: error?.message ?? null, tip: node.tip() });
    }
    return response;
  };
  const flow = createFlow({ prover, wallet, endpoint: node.url, fetch, pollMs: 20, maxPolls: 3000, resendMs: 10 });
  try {
    // A block every 20 ms throughout, a stranger's commit in every 8th, so
    // a settled block soon holds a commitment after the coin.
    node.foreignCommits(2);
    node.startMining(20, { refuse: false, commitEvery: 8 });
    const key = await flow.vanishStart("1");
    const vanished = await flow.vanishCheck(flow.vanishSaved().map((p) => key.split(" ")[p - 1]));
    assert.equal(vanished.ok, true);
    while (node.tip() < vanished.block + 3 * 32) await new Promise((resolve) => setTimeout(resolve, 20));
    const opened = await flow.summonOpen(key);
    assert.equal(opened.status, "unclaimed");
    const coin = opened.current;

    // The first envelope sent is refused every time it is sent, two blocks
    // arriving during each check.
    node.refuseStaleEnvelope({ blocks: 2 });
    const fromProofs = proofs.length;
    const reveal = await flow.summonReveal({ amount: "0.25", recipient: RECIPIENT });

    const stale = node.headMoving.stale;
    assert.ok(stale.envelope, "the node refused an envelope");
    const refused = sends.filter((s) => s.error !== null);
    assert.ok(refused.length >= 1 && refused.length <= HEAD_MOVED_SENDS, `every send of the first proof refused, at most 5 of them (${refused.length})`);
    assert.ok(refused.every((s) => /kept moving/.test(s.error) && s.envelope === stale.envelope));
    assert.equal(stale.refused, refused.length);
    assert.ok(
      refused.every((s) => s.tip - refused[0].tip <= STALE_ROOT_DEPTH),
      "the refused envelope is not sent again once its root is far below the tip",
    );
    const landed = sends.at(-1);
    assert.equal(landed.error, null, "the last send is taken");
    assert.notEqual(landed.envelope, stale.envelope, "the reveal that lands is a different proof from the refused one");
    assert.ok(landed.tip > refused[0].tip, "proved again after the tip moved on");

    // The reveal is in a block, settled, and paid once.
    assert.equal(node.reveals.length, 1, "one reveal in a block");
    assert.equal(node.reveals[0].hash, String(reveal.txHash).toLowerCase(), "the block holds the fresh proof's reveal");
    assert.equal(reveal.block, node.reveals[0].block);
    assert.equal(node.balances.get(RECIPIENT), GHOST / 4n, "the recipient is paid exactly once");

    // Every proof is of the first input coin: no decoy, no other coin, and
    // every envelope spends the same marker.
    const made = proofs.slice(fromProofs);
    assert.ok(made.length >= 2 && made.length <= HEAD_MOVED_PROOFS, `proved again, within the bound (${made.length} proofs)`);
    assert.ok(made.every((p) => !p.decoy), "the coin could be proved each time");
    assert.ok(
      made.every((p) => p.number === coin.number && p.position === coin.position && p.amount === coin.amount),
      "every proof is of the first input coin",
    );
    const markers = new Set(
      sends.map((s) => toHex(ghost.decodeEnvelope({ chainId: node.chainId, domain: node.blocks[0].hash, envelope: fromHex(s.envelope) }).marker)),
    );
    assert.equal(markers.size, 1, "one marker across every send");

    assert.equal(flow.state.error, null);
    assert.equal(flow.state.summon.current.amount, GHOST - GHOST / 4n - node.reveals[0].fee);
  } finally {
    node.stopMining();
    worker.terminate();
    await node.close();
  }
});
