// Sends a run of signed transactions to one node at a pace its RPC takes.
// The node verifies the signature of each eth_sendRawTransaction and refuses
// a send over its per-connection budget of 80 signature verifications a
// second (spec 09, RPC budgets). `sendPaced` sends at most `batch` (60) in a
// batch and starts batches at least `gapMs` (1.1 s) apart, so a connection
// never goes over 60 in any second.
//
// `sign(i)` returns `{ raw, hash }` for the i-th transaction (0-based), raw
// the envelope's hex; `rpc(method, params)` is the test's JSON-RPC call.
// A send the node answers with "already known" counts as sent; any other
// error stops the run with an error naming the index and the node's message.
// Resolves to the hashes, in order.
//
// Importing this file runs nothing.

export const FILLER_BATCH = 60;
export const FILLER_BATCH_GAP_MS = 1100;

const realSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function sendPaced({
  rpc,
  count,
  sign,
  batch = FILLER_BATCH,
  gapMs = FILLER_BATCH_GAP_MS,
  now = Date.now,
  sleep = realSleep,
}) {
  if (!Number.isSafeInteger(batch) || batch < 1) throw new Error(`batch is ${batch}`);
  const hashes = [];
  let batchStart = null;
  for (let i = 0; i < count; i += 1) {
    if (i % batch === 0) {
      if (batchStart !== null) {
        const wait = batchStart + gapMs - now();
        if (wait > 0) await sleep(wait);
      }
      batchStart = now();
    }
    const { raw, hash } = await sign(i);
    try {
      await rpc("eth_sendRawTransaction", [raw]);
    } catch (err) {
      const message = err?.message ?? String(err);
      if (!/already known/i.test(message)) {
        throw new Error(`filler send ${i} of ${count} refused: ${message}`, { cause: err });
      }
    }
    hashes.push(hash);
  }
  return hashes;
}

// Waits until the node's head (`eth_blockNumber`) is past `block`. The node
// refuses a commitment in the block in which a coin tree fills: the next
// tree starts in a later block (spec 05). A commit, or its gas estimate
// against the pending block, sent right after the filler would land in that
// block, so the test waits past the last filler's block first. Polls every
// `pollMs` (500 ms) and gives up after `timeoutMs` (120 s) with an error
// naming the block and the last head seen. Resolves to the head's number.
export const PAST_BLOCK_POLL_MS = 500;
export const PAST_BLOCK_TIMEOUT_MS = 120_000;

export async function waitPastBlock({
  rpc,
  block,
  pollMs = PAST_BLOCK_POLL_MS,
  timeoutMs = PAST_BLOCK_TIMEOUT_MS,
  now = Date.now,
  sleep = realSleep,
}) {
  if (!Number.isSafeInteger(block) || block < 0) throw new Error(`block is ${block}`);
  const deadline = now() + timeoutMs;
  for (;;) {
    const head = Number(BigInt(await rpc("eth_blockNumber", [])));
    if (head > block) return head;
    if (now() >= deadline) {
      throw new Error(`timed out after ${timeoutMs / 1000} s waiting for a block past ${block}; the head is still ${head}`);
    }
    await sleep(pollMs);
  }
}
