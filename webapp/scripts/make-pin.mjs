#!/usr/bin/env node
// Makes the pinned start of a network (header.mjs, NETWORKS) from its nodes,
// or checks one against them.
//
//   node webapp/scripts/make-pin.mjs [--endpoint URL]... [--depth N | --height H] [--out FILE]
//   node webapp/scripts/make-pin.mjs --check [FILE] [--endpoint URL]...
//
// With no --endpoint, the public test nodes (rpc.mjs, PUBLIC_ENDPOINTS). The
// first endpoint that answers is walked from genesis to the pin: every
// header is re-encoded and must hash to the hash the node returned, follow
// the one before it and carry a difficulty, which is summed into the pin's
// total work (genesis counts its start difficulty, as the page's chain does);
// genesis must be this build's and the node's own totalDifficulty, when it
// gives one, must match the sum. Every other endpoint that holds the pin's
// height must agree on the pin and on each key block. The pin is the
// header `depth` blocks below the walked node's tip (32 by default) unless
// --height names it.
//
// The seals are not checked here (that is what the pin saves the page): the
// pin rests on the nodes it is taken from, which checked every seal when
// they took each block.
//
// Output, on stdout or in FILE: { chainId, hash, height, totalWork, keyBlocks },
// the form header.mjs and the deploy's pin.json hold. --check reads a pin
// (FILE, or this build's own for the network) and fails unless the nodes
// give the same pin at its height.

import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { quantity, toHex, toQuantity } from "../src/bytes.mjs";
import { keccak256 } from "../src/flow.mjs";
import { EPOCH_BLOCKS, NETWORKS, networkOf, readHeader } from "../src/header.mjs";
import { PUBLIC_ENDPOINTS } from "../src/rpc.mjs";

export const DEFAULT_DEPTH = 32;
// Headers asked for in one batched request, and requests in flight at once.
const BATCH = 500;
const IN_FLIGHT = 4;
const TRIES = 3;

// `calls` ([method, params]) sent to `url` as one JSON-RPC batch; their
// results in order. Throws on any error.
async function batchCall(fetch, url, calls) {
  const body = JSON.stringify(calls.map(([method, params], id) => ({ jsonrpc: "2.0", id, method, params })));
  let last;
  for (let attempt = 1; attempt <= TRIES; attempt += 1) {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(120_000),
      });
      if (!response.ok) throw new Error(`${url} answered HTTP ${response.status}`);
      const replies = await response.json();
      if (!Array.isArray(replies)) throw new Error(`${url} does not answer batched requests`);
      const byId = new Map(replies.map((r) => [r.id, r]));
      return calls.map(([method], id) => {
        const reply = byId.get(id);
        if (!reply) throw new Error(`${url} gave no answer to ${method}`);
        if (reply.error) throw new Error(`${url}: ${method}: ${reply.error.message}`);
        return reply.result;
      });
    } catch (err) {
      last = err;
    }
  }
  throw last;
}

const call = async (fetch, url, method, params = []) => (await batchCall(fetch, url, [[method, params]]))[0];

// The headers of blocks `numbers` from `url`, as the node's JSON.
const headersAt = (fetch, url, numbers) =>
  batchCall(
    fetch,
    url,
    numbers.map((n) => ["eth_getBlockByNumber", [toQuantity(n), false]]),
  );

// Walks `url`'s headers 0 to `height` and returns the pin at `height`.
async function walk({ fetch, url, network, height, log }) {
  let work = 0n;
  let previous = null;
  const keyBlocks = [];
  let pin = null;
  const ranges = [];
  for (let from = 0; from <= height; from += BATCH) {
    ranges.push(Array.from({ length: Math.min(BATCH, height - from + 1) }, (_, i) => from + i));
  }
  for (let r = 0; r < ranges.length; r += IN_FLIGHT) {
    const group = ranges.slice(r, r + IN_FLIGHT);
    const fetched = await Promise.all(group.map((numbers) => headersAt(fetch, url, numbers)));
    for (const [g, numbers] of group.entries()) {
      for (const [i, n] of numbers.entries()) {
        const raw = fetched[g][i];
        if (!raw) throw new Error(`${url} has no block ${n}`);
        const { values, rlp } = readHeader(raw);
        const hash = toHex(keccak256(rlp));
        if (hash !== String(raw.hash).toLowerCase()) throw new Error(`${url}: block ${n} does not hash to the hash the node returned`);
        if (values.number !== BigInt(n)) throw new Error(`${url} returned block ${values.number} for ${n}`);
        if (n === 0) {
          if (hash !== network.genesisHash.toLowerCase()) throw new Error(`${url}: block 0 is not this build's genesis`);
          if (values.difficulty !== BigInt(network.params.startDifficulty)) {
            throw new Error(`${url}: block 0 does not carry the start difficulty`);
          }
        } else if (toHex(values.parentHash) !== previous) {
          throw new Error(`${url}: block ${n} does not follow block ${n - 1}`);
        }
        if (values.difficulty === 0n) throw new Error(`${url}: block ${n} carries no difficulty`);
        work += values.difficulty;
        if (n % EPOCH_BLOCKS === 0 && n < height) keyBlocks.push([n, hash]);
        if (n === height) {
          if (raw.totalDifficulty != null && quantity(raw.totalDifficulty) !== work) {
            throw new Error(`${url}: block ${n}'s totalDifficulty is not the sum of the difficulties up to it`);
          }
          pin = { hash, height, totalWork: work.toString(), keyBlocks };
        }
        previous = hash;
      }
    }
    log(`walked ${Math.min(height, group.at(-1).at(-1))} of ${height}`);
  }
  return pin;
}

// Whether `url` holds `pin`'s header and key blocks. True when it agrees,
// false when it does not hold the pin's height yet; throws when it differs.
async function agrees({ fetch, url, pin }) {
  const numbers = [pin.height, ...pin.keyBlocks.map(([h]) => h)];
  const raws = await headersAt(fetch, url, numbers);
  if (!raws[0]) return false;
  const want = [pin.hash, ...pin.keyBlocks.map(([, hash]) => hash)];
  for (const [i, raw] of raws.entries()) {
    const hash = raw ? toHex(keccak256(readHeader(raw).rlp)) : null;
    if (hash !== want[i] || String(raw.hash).toLowerCase() !== hash) {
      throw new Error(`${url} disagrees: its block ${numbers[i]} is not ${want[i]}`);
    }
  }
  return true;
}

// The pin of the network the endpoints serve. `endpoints` are tried in
// order for the walk; every other one that answers must agree.
export async function makePin({
  endpoints = PUBLIC_ENDPOINTS,
  networks = NETWORKS,
  depth = DEFAULT_DEPTH,
  height = null,
  fetch = globalThis.fetch,
  log = () => {},
} = {}) {
  if (endpoints.length === 0) throw new Error("no endpoint to take the pin from");
  const failures = [];
  for (const [i, url] of endpoints.entries()) {
    let chainId;
    let network;
    let at;
    try {
      chainId = quantity(await call(fetch, url, "eth_chainId"));
      network = networkOf(networks, chainId);
      if (!network) throw new Error(`${url} serves network ${chainId}, which this build does not know`);
      const tip = Number(quantity(await call(fetch, url, "eth_blockNumber")));
      at = height ?? tip - depth;
      if (at < 1 || at > tip) throw new Error(`${url}'s tip is block ${tip}: no pin at block ${at}`);
    } catch (err) {
      failures.push(err.message);
      log(`skipping ${url}: ${err.message}`);
      continue;
    }
    log(`walking ${url} from genesis to block ${at}`);
    const pin = await walk({ fetch, url, network, height: at, log });
    let agreed = 1;
    for (const other of endpoints.filter((_, j) => j !== i)) {
      let otherChain;
      try {
        otherChain = quantity(await call(fetch, other, "eth_chainId"));
      } catch (err) {
        log(`not checked against ${other}: ${err.message}`);
        continue;
      }
      if (otherChain !== chainId) throw new Error(`${other} serves network ${otherChain}, not ${chainId}`);
      if (await agrees({ fetch, url: other, pin })) agreed += 1;
      else log(`not checked against ${other}: it does not hold block ${at} yet`);
    }
    log(`pin at block ${at}: ${pin.hash}, agreed by ${agreed} of ${endpoints.length} endpoints`);
    return { chainId: chainId.toString(), ...pin };
  }
  throw new Error(`no endpoint gave a pin: ${failures.join("; ")}`);
}

// Fails unless the endpoints give `pin` (of network `chainId`) at its height.
export async function checkPin({ pin, chainId, ...options }) {
  const made = await makePin({ ...options, height: pin.height });
  if (made.chainId !== String(chainId)) throw new Error(`the endpoints serve network ${made.chainId}, not ${chainId}`);
  const want = JSON.stringify({ hash: pin.hash.toLowerCase(), height: pin.height, totalWork: String(pin.totalWork), keyBlocks: pin.keyBlocks.map(([h, hash]) => [h, hash.toLowerCase()]) });
  const got = JSON.stringify({ hash: made.hash, height: made.height, totalWork: made.totalWork, keyBlocks: made.keyBlocks });
  if (want !== got) throw new Error(`the pin differs from the nodes' headers:\n  pin:   ${want}\n  nodes: ${got}`);
  return made;
}

async function main(argv) {
  const endpoints = [];
  let depth = DEFAULT_DEPTH;
  let height = null;
  let out = null;
  let check = null;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new Error(`${arg} needs a value`);
      return argv[++i];
    };
    if (arg === "--endpoint") endpoints.push(value());
    else if (arg === "--depth") depth = Number(value());
    else if (arg === "--height") height = Number(value());
    else if (arg === "--out") out = value();
    else if (arg === "--check") check = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : "";
    else throw new Error(`unknown argument ${arg}`);
  }
  const log = (line) => process.stderr.write(`${line}\n`);
  const options = { endpoints: endpoints.length > 0 ? endpoints : PUBLIC_ENDPOINTS, log };
  if (check !== null) {
    let pin;
    let chainId = "6777972";
    if (check) {
      ({ chainId, ...pin } = JSON.parse(await readFile(check, "utf8")));
    } else {
      pin = NETWORKS[chainId].pin;
    }
    await checkPin({ pin, chainId, ...options });
    log("the pin matches the nodes' headers");
    return;
  }
  const pin = await makePin({ ...options, depth, height });
  const text = `${JSON.stringify(pin)}\n`;
  if (out) await writeFile(out, text);
  else process.stdout.write(text);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`make-pin: ${err.message}\n`);
    process.exit(1);
  });
}
