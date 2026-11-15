// Shared set-up of the head-moved reveal tests (flow-head-moved.test.mjs
// and flow-head-moved-resend.test.mjs). Importing this file runs nothing.

import assert from "node:assert/strict";

import { isRevealSend, vanish } from "./flow-setup.mjs";

// A key with a coin old enough to reveal, opened at block 80.
export async function readyToReveal(node, flow) {
  const key = await vanish(flow, "1");
  node.mineTo(40);
  node.foreignCommits(1);
  node.mineTo(80);
  assert.equal((await flow.summonOpen(key)).status, "unclaimed");
}

export const sendsIn = (requests) => requests.filter(isRevealSend);

// geth's own reply to a refused send, byte for byte: HTTP 200, code -32000
// and the pool's words unwrapped (ghost-node ghostpool errHeadMoving, through
// TxPool.Add, SendTx and SubmitTransaction), then a newline.
export const gethHeadMoved = (id) =>
  `{"jsonrpc":"2.0","id":${id},"error":{"code":-32000,"message":"chain head kept moving while the reveal was checked"}}\n`;
