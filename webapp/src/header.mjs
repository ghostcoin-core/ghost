// A block header as the endpoint returns it, re-encoded so its hash can be
// recomputed: the RLP list of the 23 fields of spec 05, section 10, and
// decision 0004 (fields 0 to 14 of the base header, the base fee,
// coinTreeRoot, dataTreeRoot, dataMarkerRoot, then the lookup fields
// coinLookupRoot, dataLookupRoot, coinMarkerRoot and lookupDigest), whose
// keccak256 is the block hash. A header without the four lookup fields (the
// 19 items of the chain before decision 0004) is refused. The worker's header chain adopts a
// header only when that hash is the one the endpoint returned and its
// difficulty and proof-of-work seal check (lib.rs, ghost_chain_add).
//
// It also holds the networks this build knows (where the header chain of
// each one starts) and the page's store of the headers it checked.

import { concat, fromHex, quantity } from "./bytes.mjs";

// The networks of this build, keyed by chain identifier (a decimal string).
// An entry holds:
//
// - `params`: the chain constants of spec 06, section 4.2 (`blockTime`,
//   `halfLife`, `startDifficulty`, `minDifficulty`, `futureDrift`);
// - `genesisTimestamp`: the zero of the difficulty schedule;
// - `genesisHash`: the hash of block 0, also the reveal domain and the
//   chain the wallet signs for;
// - `pin`: null, so the chain starts at genesis, or the pinned start
//   header `{ hash, height, totalWork, keyBlocks: [[height, hash]] }`, its
//   total work up to and including it and the key blocks below it that the
//   headers after it use.
//
// The page fetches the start header from the endpoint and keeps it only if
// its hash is the one here; that start is the one assumption the chain
// rests on. With a pin, that includes its `totalWork`: it is taken as given,
// never checked, and every header after the pin adds its difficulty to it,
// so a wrong value moves which of two competing chains the page calls the
// heavier. Headers below the pin are not authenticated. A pin is
// made by scripts/make-pin.mjs, which walks the node's headers from genesis
// to the pin (each hash, parent link and difficulty) and checks the other
// public nodes agree; each deploy also serves a fresh one as pin.json next to
// the page (loadNetworks), so a new visitor seal-checks only the headers since
// that deploy. The headers the page saved in its own storage are kept per
// chain and start, so a new pin starts them afresh. The table lists the
// public test network, the one the one-line installer joins; the launch
// network is still to come. createFlow takes another table (the tests add
// their own network).
export const NETWORKS = Object.freeze({
  // The public test network (ghost-node params/ghost/testnet.go): chain id
  // 6777972, the 30-second launch preset with its own start and minimum
  // difficulty. Its genesis is the one with the lookup fields of decision
  // 0004, so the chain before them is not this network. No pin is built in:
  // the page checks the chain from genesis unless the deploy's pin.json
  // (scripts/make-pin.mjs) gives a newer start.
  "6777972": Object.freeze({
    params: Object.freeze({ blockTime: 30, halfLife: 3600, startDifficulty: 16384, minDifficulty: 4096, futureDrift: 30 }),
    genesisTimestamp: 1793124000,
    genesisHash: "0x1beeb3088d741bdde1f5285fec7fea05b2d598237657e37741099d3e82867176",
    pin: null,
  }),
});

// A RandomX key block is at 0 or a multiple of this (client/src/seal.rs,
// EPOCH_BLOCKS). A pin names every key block below it.
export const EPOCH_BLOCKS = 8192;

const HASH = /^0x[0-9a-f]{64}$/;

// `served` (the deploy's pin.json, `{ chainId, hash, height, totalWork,
// keyBlocks }`) checked for shape: a network of `networks`, a 32-byte hash,
// a height above the pin `networks` already holds for it, a positive decimal
// total work and every key block below the height, in order. Returns the
// table with that pin in place, or `networks` unchanged when `served` is
// missing, malformed, for another network or not newer. Nothing here is
// trusted beyond the page's own origin, which serves the page's code too:
// the start header is still fetched and kept only if its hash is this one.
export function withServedPin(networks, served) {
  try {
    if (!served || typeof served !== "object") return networks;
    const id = String(served.chainId);
    const entry = networkOf(networks, id);
    if (!entry) return networks;
    const hash = String(served.hash).toLowerCase();
    const { height, keyBlocks } = served;
    if (!HASH.test(hash) || !Number.isSafeInteger(height) || height <= 0) return networks;
    if (entry.pin && height <= entry.pin.height) return networks;
    if (typeof served.totalWork !== "string" || !/^[1-9][0-9]*$/.test(served.totalWork)) return networks;
    if (!Array.isArray(keyBlocks) || keyBlocks.length !== Math.ceil(height / EPOCH_BLOCKS)) return networks;
    const keys = [];
    for (const [i, pair] of keyBlocks.entries()) {
      if (!Array.isArray(pair) || pair.length !== 2 || pair[0] !== i * EPOCH_BLOCKS) return networks;
      const keyHash = String(pair[1]).toLowerCase();
      if (!HASH.test(keyHash)) return networks;
      keys.push(Object.freeze([pair[0], keyHash]));
    }
    if (keys[0][1] !== entry.genesisHash.toLowerCase()) return networks;
    const pin = Object.freeze({ hash, height, totalWork: served.totalWork, keyBlocks: Object.freeze(keys) });
    return Object.freeze({ ...networks, [id]: Object.freeze({ ...entry, pin }) });
  } catch {
    return networks;
  }
}

// The deploy's pin, served as pin.json beside the page.
export const SERVED_PIN_URL = new URL("../pin.json", import.meta.url);

// This build's networks with the deploy's pin in place when the page's own
// origin serves a newer one (withServedPin), else `networks` as they are.
// Never throws: a missing, slow or malformed pin.json leaves the built-in pin.
export async function loadNetworks({ fetch = globalThis.fetch, url = SERVED_PIN_URL, networks = NETWORKS, timeoutMs = 5000 } = {}) {
  try {
    const response = await fetch(url, { cache: "no-cache", signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) return networks;
    return withServedPin(networks, await response.json());
  } catch {
    return networks;
  }
}

// The entry of `chainId` in `networks`, or null.
export function networkOf(networks, chainId) {
  return Object.hasOwn(networks, String(chainId)) ? networks[String(chainId)] : null;
}

// In RLP order, with the base client's JSON-RPC names: a "fixed" field has
// exactly `size` bytes, a "bytes" field at most `size`, an "int" field is
// below 2^size.
export const HEADER_FIELDS = [
  ["parentHash", "fixed", 32],
  ["sha3Uncles", "fixed", 32],
  ["miner", "fixed", 20],
  ["stateRoot", "fixed", 32],
  ["transactionsRoot", "fixed", 32],
  ["receiptsRoot", "fixed", 32],
  ["logsBloom", "fixed", 256],
  ["difficulty", "int", 256],
  ["number", "int", 64],
  ["gasLimit", "int", 64],
  ["gasUsed", "int", 64],
  ["timestamp", "int", 64],
  ["extraData", "bytes", 32],
  ["mixHash", "fixed", 32],
  ["nonce", "fixed", 8],
  ["baseFeePerGas", "int", 256],
  ["coinTreeRoot", "fixed", 32],
  ["dataTreeRoot", "fixed", 32],
  ["dataMarkerRoot", "fixed", 32],
  ["coinLookupRoot", "fixed", 32],
  ["dataLookupRoot", "fixed", 32],
  ["coinMarkerRoot", "fixed", 32],
  ["lookupDigest", "fixed", 32],
];

// The big-endian bytes of an integer, with no leading zero byte; zero is empty.
function intBytes(value) {
  const out = [];
  for (let v = value; v > 0n; v >>= 8n) out.unshift(Number(v & 0xffn));
  return Uint8Array.from(out);
}

function lengthPrefix(length, base) {
  if (length < 56) return Uint8Array.of(base + length);
  const size = intBytes(BigInt(length));
  return concat([Uint8Array.of(base + 55 + size.length), size]);
}

export function rlpString(bytes) {
  if (bytes.length === 1 && bytes[0] < 0x80) return Uint8Array.from(bytes);
  return concat([lengthPrefix(bytes.length, 0x80), bytes]);
}

export function rlpList(encodedItems) {
  const payload = concat(encodedItems);
  return concat([lengthPrefix(payload.length, 0xc0), payload]);
}

// The header's fields read from the endpoint's JSON, checked for size, and
// its RLP. Throws on a missing or malformed field.
export function readHeader(raw) {
  if (!raw || typeof raw !== "object") throw new Error("the endpoint returned no header");
  const values = {};
  const items = HEADER_FIELDS.map(([name, kind, size]) => {
    const text = raw[name];
    if (text === undefined || text === null) throw new Error(`the header has no ${name}`);
    if (kind === "int") {
      const value = quantity(text);
      if (value >= 1n << BigInt(size)) throw new Error(`the header's ${name} is out of range`);
      values[name] = value;
      return rlpString(intBytes(value));
    }
    const bytes = fromHex(text, kind === "fixed" ? size : undefined);
    if (bytes.length > size) throw new Error(`the header's ${name} is longer than ${size} bytes`);
    values[name] = bytes;
    return rlpString(bytes);
  });
  return { values, rlp: rlpList(items) };
}

// --- The headers the page checked, kept between sessions ---
//
// Kept in the page's own IndexedDB so that the next session does not check
// every seal again (flow.mjs, loadSaved). header-store.mjs is this part's
// module name; the code lives here, in a module the build already ships.
// Public data only: each record is one header of the best chain as the
// endpoint's JSON gave it, the fields of HEADER_FIELDS and the hash, never a
// key, an address or anything else.
//
// One database, `ghost-headers`, with one object store whose keys are
// [entry, block number]; an entry is the chain identifier and start hash
// the flow names. The store's interface is the flow's `headerStore`:
//
// - load(entry): the records of that entry in block number order ([] when
//   none);
// - save(entry, records): each record written at its block number, in
//   place of what was there, and every record above the last one dropped,
//   in one transaction;
// - clear(entry): every record of that entry dropped.
//
// Browser storage may be missing, refused or blocked: createHeaderStore then
// returns null, or the store's calls throw, and the flow checks every header
// from the start as on a first visit. Nothing else depends on it.

export const HEADER_DATABASE = "ghost-headers";
const HEADER_RECORDS = "headers";

// The request's result, or its error.
function requestDone(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("the browser storage refused the request"));
  });
}

// A transaction's end.
function committed(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error("the browser storage refused the write"));
    tx.onabort = () => reject(tx.error || new Error("the browser storage dropped the write"));
  });
}

// The keys of `entry` from block `from` up (above it when `open`).
function recordsFrom(entry, from, open = false) {
  return IDBKeyRange.bound([entry, from], [entry, Number.MAX_SAFE_INTEGER], open, false);
}

const recordNumber = (record) => Number(BigInt(record.number));

// The store over `indexedDB`, or null when the page has none or opening it
// throws at once. Opening it later failing or being blocked (another tab
// holds an older version) makes each call throw instead.
export function createHeaderStore(indexedDB = globalThis.indexedDB) {
  if (!indexedDB || typeof indexedDB.open !== "function") return null;
  let opened;
  try {
    const request = indexedDB.open(HEADER_DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(HEADER_RECORDS)) request.result.createObjectStore(HEADER_RECORDS);
    };
    opened = new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("the browser storage could not be opened"));
      request.onblocked = () => reject(new Error("the browser storage is blocked"));
    });
  } catch {
    return null;
  }
  // A failed open is reported by each call, not as an unhandled rejection.
  opened.catch(() => {});

  return {
    async load(entry) {
      const db = await opened;
      return requestDone(db.transaction(HEADER_RECORDS, "readonly").objectStore(HEADER_RECORDS).getAll(recordsFrom(entry, 0)));
    },

    async save(entry, records) {
      if (records.length === 0) return;
      const db = await opened;
      const tx = db.transaction(HEADER_RECORDS, "readwrite");
      const store = tx.objectStore(HEADER_RECORDS);
      for (const record of records) store.put(record, [entry, recordNumber(record)]);
      store.delete(recordsFrom(entry, recordNumber(records.at(-1)), true));
      await committed(tx);
    },

    async clear(entry) {
      const db = await opened;
      const tx = db.transaction(HEADER_RECORDS, "readwrite");
      tx.objectStore(HEADER_RECORDS).delete(recordsFrom(entry, 0));
      await committed(tx);
    },
  };
}
