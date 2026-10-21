// Seals a test node's blocks at a bounded pace, through the node's own
// miner_start / miner_stop RPC: each cycle starts the miner with 1 thread,
// polls eth_blockNumber every 5 ms until the head is above what it was before
// the start (at most 30 s), keeps it running while txpool_status reports
// pending transactions (at most 5 s or 20 blocks in the cycle), stops the
// miner, waits until eth_mining is false, then sleeps `intervalMs`. The node's
// miner seals an empty block first on every start, and on the test network
// that one wins the race against the block that would include a transaction
// slow to verify; mining on gives that block its chance. Left mining, the internal network's node seals a
// block about every 20 ms, far more headers than the page can check in its
// worker; paced, its chain grows by about one block (a few at most) per cycle.
//
// Before the paced cycles comes a warm-up: the miner runs unpaced until the
// latest block's baseFeePerGas (eth_getBlockByNumber) equals its parent's.
// The internal network starts at a base fee of 1 gwei and each empty block
// lowers it by an eighth, so for about 140 blocks the fee changes on every
// block; paced, that would be minutes in which every proof sees a new fee.
// The warm-up ends after at most `warmUpBlocks` blocks or `warmUpMs`, settled
// or not, and the pacer goes on pacing. The `warmUpMs` deadline holds while a
// call is awaited too: an RPC call still unanswered at the deadline ends the
// warm-up there, unsettled, and the miner is stopped (allowing that stop up to
// 5 s) before the paced cycles begin.
//
// `rpc(method, params)` is the test's JSON-RPC call. `warmUp` resolves once
// the warm-up is over, to `{ settled, blocks, ms, baseFee }` (`baseFee` is
// the latest block's, a bigint, or null if none was read). `stop()` ends the
// loop and resolves once the miner is stopped.
//
// Importing this file runs nothing.

const POLL_MS = 5;
const SEAL_LIMIT_MS = 30_000;
const WARM_UP_POLL_MS = 20;
const PENDING_LIMIT_MS = 5_000;
const PENDING_LIMIT_BLOCKS = 20;
const WARM_UP_STOP_MS = 5_000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const EXPIRED = Symbol("expired");

// `promise`'s outcome, or EXPIRED if it has none by `deadline` (a Date.now()
// time).
function until(deadline, promise) {
  let timer;
  const expiry = new Promise((resolve) => {
    timer = setTimeout(resolve, Math.max(0, deadline - Date.now()), EXPIRED);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

export function startBlockPacer({ rpc, intervalMs = 2000, warmUpBlocks = 1000, warmUpMs = 120_000 }) {
  let running = true;
  let wake = null;
  // A sleep that stop() cuts short.
  const pause = (ms) =>
    new Promise((resolve) => {
      const timer = setTimeout(done, ms);
      function done() {
        clearTimeout(timer);
        wake = null;
        resolve();
      }
      wake = done;
    });
  const head = async () => BigInt(await rpc("eth_blockNumber"));

  async function untilSealed(before) {
    const deadline = Date.now() + SEAL_LIMIT_MS;
    while (running && Date.now() < deadline) {
      if ((await head()) > before) return;
      await sleep(POLL_MS);
    }
  }

  async function minerStop() {
    await rpc("miner_stop");
    const deadline = Date.now() + SEAL_LIMIT_MS;
    while ((await rpc("eth_mining")) && Date.now() < deadline) await sleep(POLL_MS);
  }

  const pending = async () => Number(BigInt((await rpc("txpool_status")).pending ?? 0));

  // Keeps the miner running while the pool has pending transactions, up to
  // PENDING_LIMIT_MS from now or PENDING_LIMIT_BLOCKS above `before`.
  async function whilePending(before) {
    const deadline = Date.now() + PENDING_LIMIT_MS;
    while (running && Date.now() < deadline) {
      if ((await head()) - before >= BigInt(PENDING_LIMIT_BLOCKS)) return;
      if ((await pending()) === 0) return;
      await sleep(POLL_MS);
    }
  }

  async function cycle() {
    const before = await head();
    try {
      await rpc("miner_start", [1]);
      await untilSealed(before);
      await whilePending(before);
    } finally {
      await minerStop();
    }
  }

  // The latest block's number and base fee, and whether that fee equals its
  // parent's, read through `call`.
  async function baseFee(call) {
    const latest = await call("eth_getBlockByNumber", ["latest", false]);
    const number = BigInt(latest.number);
    const fee = latest.baseFeePerGas == null ? null : BigInt(latest.baseFeePerGas);
    if (number === 0n || fee === null) return { number, fee, settled: false };
    const parent = await call("eth_getBlockByNumber", [`0x${(number - 1n).toString(16)}`, false]);
    const parentFee = parent.baseFeePerGas == null ? null : BigInt(parent.baseFeePerGas);
    return { number, fee, settled: fee === parentFee };
  }

  async function warmUp() {
    const began = Date.now();
    const deadline = began + warmUpMs;
    let first = null;
    let seen = { number: null, fee: null, settled: false };
    let mining = false;
    let expired = false;
    // The warm-up's RPC call, given up on at the deadline.
    const call = async (method, params) => {
      const result = await until(deadline, rpc(method, params));
      if (result === EXPIRED) throw EXPIRED;
      return result;
    };
    try {
      while (running) {
        seen = await baseFee(call);
        first ??= seen.number;
        if (seen.settled) break;
        if (seen.number - first >= BigInt(warmUpBlocks) || Date.now() >= deadline) break;
        if (!mining) {
          mining = true;
          await call("miner_start", [1]);
        }
        await sleep(WARM_UP_POLL_MS);
      }
    } catch (err) {
      if (err !== EXPIRED) throw err;
      expired = true;
    } finally {
      // After a stalled call the miner may be running whatever `mining` says;
      // the paced cycles stop it again if this stop stalls too.
      if (mining || expired) {
        if ((await until(Date.now() + WARM_UP_STOP_MS, minerStop())) === EXPIRED && running) {
          console.error("block pacer: warm-up: miner_stop unanswered; pacing anyway");
        }
      }
    }
    return {
      settled: expired ? false : seen.settled,
      blocks: first === null ? 0 : Number(seen.number - first),
      ms: Date.now() - began,
      baseFee: seen.fee,
    };
  }

  const warmedUp = warmUp().catch((err) => {
    // Pacing goes on; the result says the fee was not seen to settle.
    if (running) console.error(`block pacer: warm-up: ${err.message}`);
    return { settled: false, blocks: 0, ms: 0, baseFee: null, error: err.message };
  });

  const loop = (async () => {
    await warmedUp;
    while (running) {
      try {
        await cycle();
      } catch (err) {
        // The node's failures show in the test itself; the next cycle tries
        // again.
        if (running) console.error(`block pacer: ${err.message}`);
      }
      if (running) await pause(intervalMs);
    }
  })();

  return {
    warmUp: warmedUp,
    async stop() {
      running = false;
      wake?.();
      await loop;
    },
  };
}
