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
