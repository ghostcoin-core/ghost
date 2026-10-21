// Seals a test node's blocks at a bounded pace, through the node's own
// miner_start / miner_stop RPC: each cycle starts the miner with 1 thread,
// polls eth_blockNumber every 5 ms until the head is above what it was before
// the start (at most 30 s), stops the miner, waits until eth_mining is false,
// then sleeps `intervalMs`. Left mining, the internal network's node seals a
// block about every 20 ms, far more headers than the page can check in its
// worker; paced, its chain grows by about one block (a few at most) per cycle.
//
// `rpc(method, params)` is the test's JSON-RPC call. `stop()` ends the loop
// and resolves once the miner is stopped.
//
// Importing this file runs nothing.

const POLL_MS = 5;
const SEAL_LIMIT_MS = 30_000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function startBlockPacer({ rpc, intervalMs = 2000 }) {
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

  async function cycle() {
    const before = await head();
    try {
      await rpc("miner_start", [1]);
      await untilSealed(before);
    } finally {
      await minerStop();
    }
  }

  const loop = (async () => {
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
    async stop() {
      running = false;
      wake?.();
      await loop;
    },
  };
}
