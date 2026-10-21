// The app's flow controller: Vanish with the save check, Summon and Claim.
// It touches no DOM, so the headless test drives exactly what the page
// drives; app.mjs only renders its state and forwards the user's input.
//
// What it talks to:
//
// - the chosen node endpoint, by JSON-RPC: headers, which the worker's header
//   chain adopts only once their difficulty and proof-of-work seal check,
//   from the start this build pins for the network; the coin tree in whole
//   pages, the spent markers in whole pages, receipts, and the reveal
//   transaction. No request names a key, a commitment, a position or a
//   marker; the reveal itself carries only public fields;
// - the background worker (prover.mjs), which holds the WebAssembly module
//   and receives a key's words (or the digits of a key issued before the
//   words) or the words of the wallet's seed for the length of one request.
//
// A new Phantom Key is 24 words, the client library's default: a 256-bit
// secret, so it stays strong even against a quantum search. Its coin's
// commit is version 2 with a fresh per-coin salt in the clear beside `F`
// (206 bytes); the node serves that salt beside the leaf, the app hands it
// to restore, and the reveal and the claim pass the coin's salt to the
// prover. Keys already issued as twelve groups of digits still restore,
// reveal and claim.
//
// The wallet is built in (spec 09, section 9): a 256-bit seed shown as 24
// words, which derives a quantum-safe account key (ML-DSA-44). The commit is
// an account transaction (type 0x52) the worker signs and the app sends with
// eth_sendRawTransaction; no browser wallet and no elliptic-curve key is
// used. Summon pays to any 20-byte address and needs no wallet.
//
// A key or a seed lives only in this object's memory: it is never written to
// browser storage, a file, a cookie or a server. A Phantom Key is dropped as
// soon as the step that needs it is done; the seed is kept while the wallet
// is open and dropped when it is closed.

import { concat, fromHex, quantity, toHex, toQuantity } from "./bytes.mjs";
import {
  CONFIRMATIONS,
  SETTLE_DEPTH,
  feeForNextBlock,
  formatGhost,
  nextBaseFee,
  parseAddress,
  parseGhost,
  settledHeight,
} from "./chain.mjs";
import { NETWORKS, networkOf, readHeader } from "./header.mjs";
import { DEFAULT_ENDPOINT, SERVER_ERROR, createRpc } from "./rpc.mjs";

// The coin commit entry address of the internal network ("ghost" in ASCII,
// then 5; ghost-node params/ghost/privaccounts.go). It stays a setting next
// to the endpoint.
export const DEFAULT_COMMIT_ENTRY = "0x67686f7374000000000000000000000000000005";
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// Leaves (or markers) per page of wallet tree data (spec 05, section 8).
export const PAGE_LEAVES = 4096;
// Every scan reads the headers from this many blocks below the settled
// block S (SETTLE_DEPTH below the tip) up to the tip, to find a leaf's block.
export const LEAF_WINDOW = 32;
const NOTE_BYTES = 156;
const SALT_BYTES = 16;
// The commit the app sends: version 0x0002, F, the salt and the note (the
// node's ghostpriv.SaltedCommitDataSize).
export const COMMIT_DATA_BYTES = 2 + 32 + SALT_BYTES + NOTE_BYTES;
// Words the user re-types before a new key is used, out of its 24.
export const SAVE_CHECK_GROUPS = 3;
export const KEY_WORDS = 24;
// Words of a wallet seed, of which the user re-types SAVE_CHECK_GROUPS.
export const SEED_WORDS = 24;
// The account of the seed the app uses.
export const ACCOUNT_INDEX = 0;
// What an account transaction adds to the intrinsic gas of a type 0x02
// transaction, which eth_estimateGas counts: 16 gas for each of the 2 + 1,312
// + 2,420 bytes of scheme, public key and signature, and 3,000 for the
// ML-DSA-44 check (ghost-node params/ghost/accounttx.go).
export const ACCOUNT_EXTRA_GAS = 62_744n;
// Local bounds on what the endpoint's answers can make the wallet sign, so
// a dishonest endpoint cannot turn a commit into a large fee: the gas limit
// of a commit, the priority fee per gas, and the most a commit's gas can
// cost in all (0.01 GHOST by default, a setting of createFlow). The app
// refuses to sign above them.
export const COMMIT_GAS_CAP = 500_000n;
export const PRIORITY_FEE_CAP = 2_000_000_000n;
export const MAX_COMMIT_FEE = 10n ** 16n;
// Times a reveal is proved again when the fee window changes meanwhile.
const FEE_ATTEMPTS = 3;
// The node's refusal of a reveal it could not check while new blocks kept
// arriving (ghost-node's ghostpool): a transient, not a verdict on the
// reveal. One proof's envelope is sent at most HEAD_MOVED_SENDS times while
// the node answers only that; before each resend the app waits a fixed
// `resendMs` and reads the tip once. It never waits for the tip to hold
// still: a node that seals a block every few milliseconds never does.
export const HEAD_MOVED = "chain head kept moving while the reveal was checked";
export const HEAD_MOVED_SENDS = 5;
// A node whose head keeps moving can refuse every send of one proof: the
// same envelope then never lands. Once a proof's HEAD_MOVED_SENDS sends are
// all refused (or taken and let go), the reveal is proved again, of the same
// coin, for the tree state and fee of the tip by then. The app keeps going so
// for up to HEAD_MOVED_MS from the first proof, and at most HEAD_MOVED_PROOFS
// proofs, before the last refusal surfaces: a node that seals a block every
// 20 ms can refuse dozens of sends in a row and still take a later one, so
// the bound is a generous wait, not a few seconds.
export const HEAD_MOVED_PROOFS = 200;
export const HEAD_MOVED_MS = 600_000;
const RESEND_MS = 250;
// A refused proof is proved again at once, rather than sent again, when the
// block whose root it proves against is more than this many blocks below the
// tip: that root is no longer among the headers a new scan reads (the
// settled block and LEAF_WINDOW blocks below it), so a new proof is made
// against the settled root of the tip by then. The last proof allowed is
// sent its HEAD_MOVED_SENDS times whatever its root.
export const STALE_ROOT_DEPTH = SETTLE_DEPTH + LEAF_WINDOW;
// The node can also take a reveal and let it go before any block holds it:
// its pool checks every reveal it holds again on each new head and drops one
// that fails (ghostpool Reset). Once the tip is this many blocks past a taken
// send with no receipt, the app asks whether the node still holds it.
const HELD_BLOCKS = 2;
// Times a receipt that names a replaced block is read again before the
// transaction counts as dropped by a reorganisation.
const REREADS = 3;

// Headers the worker's chain is given in one request at most.
const CHAIN_BATCH = 256;
// Times a header dated ahead of the page's clock is offered again, and the
// longest wait before each, in seconds.
const AHEAD_WAITS = 3;
const AHEAD_WAIT_S = 30;

// What the page says when the endpoint's chain does not pass the header
// chain's check: a seal that is not valid, a wrong difficulty, a start that
// is not the pinned one, a header the chain cannot place. Uncertain means
// refused: the app then shows no confirmation and takes no step that
// depends on the headers.
export const POW_FAILED = "the endpoint's chain failed the proof-of-work check";
const NO_CONFIRMATIONS = "so the app shows no confirmations from it and takes no step that depends on its blocks";

export class ChainRefused extends Error {}

export function noPinMessage(chainId) {
  return (
    `this build has no pinned start for network ${chainId}: without one the app cannot check the endpoint's chain, ` +
    "so it shows no confirmations and takes no step that depends on its blocks"
  );
}

function powFailed(detail) {
  return new ChainRefused(`${POW_FAILED} (${detail}), ${NO_CONFIRMATIONS}`);
}

// That refusal as it arrives over JSON-RPC: code -32000 and the node's
// words. It is told by its shape on the wire, not by the class of the error
// object, so a second copy of rpc.mjs (a bundle, a test) still matches.
export function isHeadMoved(err) {
  return Number(err?.code) === SERVER_ERROR && String(err?.message ?? "").includes(HEAD_MOVED);
}

// The reveal cannot be made yet; the message says what it waits for.
// `alone` is set when nobody has committed a coin since the holder's.
export class WaitError extends Error {
  constructor(message, { alone = false } = {}) {
    super(message);
    this.alone = alone;
  }
}

// A transaction a block held is no longer in the chain: a reorganisation
// replaced that block. Nothing the transaction did stands, so the holder can
// send it again; a reveal or claim sent again spends the same coin marker as
// the one dropped, so at most one of them is ever executed.
export class DroppedError extends Error {
  constructor(block) {
    super(droppedMessage("transaction", block));
    this.block = block;
  }
}

export function droppedMessage(what, block) {
  return (
    `the chain was reorganised and block ${block} no longer holds the ${what}, nor does any other block: ` +
    `nothing it did stands. You can send it again`
  );
}

// The plain warning for a coin no later leaf follows yet. The only tree that
// holds it then ends with its own block, and a reveal against that root would
// tie the reveal to its commit, so the app waits instead.
export const ALONE_WARNING =
  "nobody has committed a coin since this one. A reveal now could only prove against the coin tree that ends with " +
  "this coin's own block, which ties the reveal to its commit, so the app waits: this coin can be revealed " +
  `${SETTLE_DEPTH} blocks after anyone else commits one`;

// Three distinct word positions (1 to 24), drawn without bias from the
// secure random source and returned in order.
export function pickGroups(random, total = KEY_WORDS, count = SAVE_CHECK_GROUPS) {
  const limit = 256 - (256 % total);
  const chosen = new Set();
  while (chosen.size < count) {
    for (const byte of random(16)) {
      if (byte >= limit) continue;
      chosen.add((byte % total) + 1);
      if (chosen.size === count) break;
    }
  }
  return [...chosen].sort((a, b) => a - b);
}

// The positions whose typed word does not match the key's or the seed's, in
// any case. A word must be typed whole: a prefix or a near word is wrong.
export function wrongWords(words, positions, answers) {
  const list = normalWords(words).split(" ");
  return positions.filter((position, i) => String(answers[i] ?? "").trim().toLowerCase() !== list[position - 1]);
}

// Seed words as the module reads them: lower case, single spaces.
export function normalWords(text) {
  return String(text).trim().toLowerCase().split(/\s+/).join(" ");
}

// A typed Phantom Key as the module is given it: words or digits with any
// run of white space (a line break of a pasted key included) made one
// space. Case, hyphens and the words themselves are left to the module's
// parse, which checks the key's check before anything is derived.
export function normalKey(text) {
  return String(text).trim().split(/\s+/).join(" ");
}

// The key's state from what restore found: no coin yet, a coin to claim,
// or nothing left unspent.
export function keyStatus(found) {
  if (found.length === 0) return { status: "not-found", current: null };
  const unspent = found.filter((coin) => !coin.spent).sort((a, b) => b.position - a.position);
  if (unspent.length === 0) return { status: "claimed", current: null };
  return { status: "unclaimed", current: unspent[0] };
}

// Whether two coins restore found are the same coin: the same leaf position,
// number and amount.
function sameCoin(a, b) {
  return a.position === b.position && a.number === b.number && a.amount === b.amount;
}

// Every leaf and note of coin tree 0 as of `anchor` (a verified header), in
// the node's shape: the page roots as an array, then every page in order as
// `{ kind, treeIndex, page, filled, entries: [{ leaf, note, salt? }] }`.
// `salt` is the 16-byte salt a version 2 commit published beside its leaf;
// the node leaves it out for a version 1 commit and for a reveal's
// remainder. Every page but the last is full and the last holds 1 to 4,096
// leaves; the page roots and leaves are checked against the anchor's coin
// root. Anything else, a salt that is not 16 bytes of hex among it, is
// refused, never guessed at. `salts` holds each leaf's salt or null.
export async function fetchTree(rpc, prover, anchor) {
  const anchorHash = toHex(anchor.hash);
  const list = await rpc.call("ghost_getPageRoots", ["coin", "0x0", anchorHash]);
  if (!Array.isArray(list)) throw new Error("the endpoint's page roots are not a list");
  const pageRoots = list.map((root) => fromHex(root, 32));
  const leaves = [];
  const records = [];
  const salts = [];
  for (let p = 0; p < pageRoots.length; p += 1) {
    const page = await rpc.call("ghost_getTreePage", ["coin", "0x0", toQuantity(p), anchorHash]);
    const filled = Number(quantity(page?.filled));
    const whole = p === pageRoots.length - 1 ? filled >= 1 && filled <= PAGE_LEAVES : filled === PAGE_LEAVES;
    if (!whole || !Array.isArray(page.entries) || page.entries.length !== filled) {
      throw new Error(`page ${p} from the endpoint is not a whole page`);
    }
    for (const entry of page.entries) {
      const leaf = fromHex(entry?.leaf, 32);
      leaves.push(leaf);
      records.push(leaf, fromHex(entry.note, NOTE_BYTES));
      salts.push(entry.salt === undefined ? null : saltOf(entry.salt, p));
    }
  }
  const leafBytes = concat(leaves);
  await prover.request("treeCheck", { pageRoots: concat(pageRoots), leaves: leafBytes, root: anchor.coinTreeRoot });
  return { count: leaves.length, leaves: leafBytes, records: concat(records), salts };
}

// The `salt` of an entry of page `p`: 16 bytes of hex, or the page is
// refused as malformed.
function saltOf(hex, p) {
  try {
    return fromHex(hex, SALT_BYTES);
  } catch {
    throw new Error(`page ${p} from the endpoint is malformed: a salt is not ${SALT_BYTES} bytes`);
  }
}

// A leaf's block, `{ height, root, count }`, as chooseTreeState is asked
// about it, from what a scan reads for every key: headers of blocks S - 32
// to the tip (S the settled block), each one's leaf count and a root for
// every prefix of coin tree 0. Null when a leaf is past the tip's tree. A
// leaf in S - 32 to the tip takes its first header holding it, and `count`
// is that header's leaf count. A leaf older than S - 32 has no header here:
// it takes block S - 32's height and a root of a tree ending at it (a count
// of position + 1). Its real block's tree holds at least that many leaves,
// so S's tree follows such a coin when it holds a later leaf, even if no
// commitment came in S - 32 to S.
export function leafBlock({ rootHeaders: headers, rootCounts: counts, prefixRoots }, position) {
  const at = counts.findIndex((count) => count > position);
  if (at === -1) return null;
  if (at > 0) return { height: headers[at].number, root: headers[at].coinTreeRoot, count: counts[at] };
  return { height: headers[0].number, root: prefixRoots[position + 1], count: position + 1 };
}

// The tree state to prove `coin` against (spec 02, section 8): the root of
// the settled block S, SETTLE_DEPTH below the tip, if the shared rule
// (tree_state.rs, through the worker) picks it, that is if S's tree holds a
// leaf added after the coin's block. There is no forced wait beyond that:
// the plan says how many coins S's tree covers (`covers`), and whether to
// reveal now or wait for more is the holder's choice. It sends no request:
// the scan fetched everything it reads.
//
// When S's tree holds no later leaf, it throws a WaitError: one that names
// the block from which the coin can be revealed when a later leaf is not
// settled yet, or the plain warning ALONE_WARNING (`alone`) when nobody has
// committed since the coin. It never proves against the coin's own block
// root.
export async function planReveal(prover, scan, coin, progress = () => {}) {
  const { chain, rootHeaders: headers, rootCounts: counts, settledAt } = scan;
  if (settledAt === null) {
    throw new WaitError(`no block is ${SETTLE_DEPTH} blocks deep yet; wait until the chain passes block ${SETTLE_DEPTH}`);
  }
  progress("choosing the tree state");
  const settled = headers[settledAt];
  const leaf = leafBlock(scan, coin.position);
  if (!leaf) throw new Error("the coin is not in the tip's coin tree; refresh");
  scan.askedRule = true;
  const { chosen } = await prover.request("chooseTreeState", {
    tip: chain.tip.number,
    leafHeight: leaf.height,
    leafRoot: leaf.root,
    height: settled.number,
    root: settled.coinTreeRoot,
  });
  if (!chosen) {
    const later = counts.findIndex((count) => count > leaf.count);
    if (later === -1) throw new WaitError(ALONE_WARNING, { alone: true });
    const block = headers[later].number;
    throw new WaitError(
      `a coin was committed after this one in block ${block}; this coin can be revealed from block ${block + SETTLE_DEPTH}, once that block is ${SETTLE_DEPTH} deep`,
    );
  }
  return {
    root: settled.coinTreeRoot,
    leaves: scan.settledLeaves,
    fee: scan.fee,
    domain: chain.genesis.hash,
    height: settled.number,
    covers: counts[settledAt],
  };
}

// The rule asked once for a scan that proves a decoy, as it is asked for a
// coin, so the worker's work does not depend on what restore found.
async function askRuleForDecoy(prover, scan) {
  const { chain, rootHeaders: headers, settledAt } = scan;
  if (settledAt === null || scan.askedRule) return;
  scan.askedRule = true;
  const settled = headers[settledAt];
  await prover.request("chooseTreeState", {
    tip: chain.tip.number,
    leafHeight: headers[0].number,
    leafRoot: headers[0].coinTreeRoot,
    height: settled.number,
    root: settled.coinTreeRoot,
  });
}

export function createFlow({
  prover,
  fetch = globalThis.fetch,
  random = (n) => crypto.getRandomValues(new Uint8Array(n)),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
  pollMs = 3000,
  maxPolls = 600,
  resendMs = RESEND_MS,
  headMovedMs = HEAD_MOVED_MS,
  headMovedProofs = HEAD_MOVED_PROOFS,
  endpoint = DEFAULT_ENDPOINT,
  commitEntry = DEFAULT_COMMIT_ENTRY,
  maxCommitFee = MAX_COMMIT_FEE,
  // The networks whose header chain the app can check (header.mjs).
  networks = NETWORKS,
  // The page's clock in Unix seconds, against which a header's timestamp
  // may run at most the network's future drift ahead.
  clock = () => Math.floor(Date.now() / 1000),
  onChange = () => {},
} = {}) {
  let rpc = createRpc(endpoint, { fetch });
  // The open wallet's seed words, never in `state`.
  let walletWords = null;
  // The page's header chain, held in the worker: the network it is of, the
  // endpoint it was last read from, its start height, and every header the
  // worker adopted, by hash. One per page session; another network starts
  // it again.
  let headerChain = null;
  const state = {
    endpoint: rpc.url,
    commitEntry,
    // Why the endpoint's chain is refused, while it is: no confirmation is
    // shown from it.
    chainRefused: null,
    // The wallet: null, or { stage, words, groups, wrong, address, balance }.
    // `words` is set only while a new seed is shown and checked.
    wallet: null,
    busy: null,
    progress: null,
    error: null,
    vanish: null,
    summon: null,
  };

  const emit = () => onChange(state);
  const progress = (stage) => {
    state.progress = { stage, since: now() };
    emit();
  };

  async function run(label, task) {
    if (state.busy) throw new Error(`wait until "${state.busy}" is done`);
    state.busy = label;
    state.error = null;
    emit();
    try {
      return await task();
    } catch (err) {
      state.error = err.message;
      if (err instanceof ChainRefused) state.chainRefused = err.message;
      throw err;
    } finally {
      state.busy = null;
      state.progress = null;
      emit();
    }
  }

  // --- The chain, from the endpoint ---

  // Block `number` as the endpoint returns it: its fields, its 18-field RLP
  // (spec 05, section 10) and the hash it claims. Nothing here is trusted
  // yet: the worker's chain checks the hash, the difficulty and the seal.
  async function fetchHeader(number) {
    const raw = await rpc.call("eth_getBlockByNumber", [toQuantity(number), false]);
    if (!raw) throw new Error(`the endpoint has no block ${number}`);
    const { values, rlp } = readHeader(raw);
    const header = {
      number: Number(values.number),
      hash: fromHex(raw.hash, 32),
      parentHash: values.parentHash,
      baseFee: values.baseFeePerGas,
      gasUsed: values.gasUsed,
      gasLimit: values.gasLimit,
      coinTreeRoot: values.coinTreeRoot,
      timestamp: values.timestamp,
    };
    if (header.number !== number) throw new Error(`the endpoint returned block ${header.number} for ${number}`);
    return { header, rlp };
  }

  const notTheHash = (number) => new Error(`the endpoint's header of block ${number} does not hash to the block hash it returned`);

  // The page's header chain for network `chainId`, started from this
  // build's start for it the first time: the start header is fetched from
  // the endpoint and kept only if its hash is the pinned one (genesis on a
  // network with no pin). A network with no entry is refused.
  async function chainFor(chainId) {
    if (headerChain && headerChain.chainId === chainId) {
      headerChain.endpoint = rpc.url;
      return headerChain;
    }
    const network = networkOf(networks, chainId);
    if (!network) throw new ChainRefused(noPinMessage(chainId));
    const { pin } = network;
    const height = pin ? pin.height : 0;
    const startHash = String(pin ? pin.hash : network.genesisHash).toLowerCase();
    const { header, rlp } = await fetchHeader(height);
    if (toHex(header.hash) !== startHash) {
      throw powFailed(`its block ${height} is not the start this build pins for network ${chainId}`);
    }
    const start = pin
      ? {
          header: rlp,
          height,
          totalWork: BigInt(pin.totalWork),
          genesisTimestamp: network.genesisTimestamp,
          keyBlocks: pin.keyBlocks.map(([h, hash]) => [h, fromHex(hash, 32)]),
        }
      : { header: rlp };
    let started;
    try {
      started = await prover.request("chainStart", { params: network.params, start });
    } catch (err) {
      throw powFailed(err.message);
    }
    if (toHex(started.startHash) !== startHash) throw notTheHash(height);
    headerChain = {
      chainId,
      network,
      endpoint: rpc.url,
      startHeight: height,
      known: new Map([[startHash, { ...header, rlpHex: toHex(rlp) }]]),
    };
    return headerChain;
  }

  // The chain of the current endpoint; its chain identifier is asked once
  // per endpoint.
  async function currentChain() {
    if (headerChain && headerChain.endpoint === rpc.url) return headerChain;
    return chainFor(quantity(await rpc.call("eth_chainId")));
  }

  // The endpoint's tip, adopted through the page's header chain. The
  // endpoint's headers are read from its tip down to the first one the
  // chain holds, then added to the chain from there up: each is adopted
  // only if it hashes to the hash returned with it, follows a header the
  // chain holds, carries the difficulty the schedule requires and has a
  // valid seal (lib.rs, ghost_chain_add). The tip must then be on the chain
  // with the most work the page has seen; on a lighter branch it is refused
  // and the heavier chain kept. A reorganisation is followed as soon as the
  // endpoint's tip is on the heavier branch. Which blocks are asked for
  // depends on the tip and on what the chain already holds, never on a key.
  async function syncTip(hc = null) {
    hc ??= await currentChain();
    const top = Number(quantity(await rpc.call("eth_blockNumber")));
    if (top < hc.startHeight) {
      throw powFailed(`its tip, block ${top}, is below the start this build pins, block ${hc.startHeight}`);
    }
    const pending = [];
    let tipHash = null;
    for (let n = top; ; n -= 1) {
      const fetched = await fetchHeader(n);
      const id = toHex(fetched.header.hash);
      tipHash ??= id;
      const held = hc.known.get(id);
      if (held) {
        if (held.rlpHex !== toHex(fetched.rlp)) throw notTheHash(n);
        break;
      }
      if (n <= hc.startHeight) throw powFailed(`its block ${n} does not descend from the start this build pins`);
      if (pending.length > 0 && toHex(pending[0].header.parentHash) !== id) {
        throw new Error(`block ${n + 1} does not follow block ${n}`);
      }
      pending.unshift(fetched);
    }
    let waits = 0;
    for (let i = 0; i < pending.length; ) {
      const part = pending.slice(i, i + CHAIN_BATCH);
      const added = await prover.request("chainAdd", {
        now: clock(),
        headers: part.map(({ header, rlp }) => ({ hash: header.hash, rlp })),
      });
      for (const { header, rlp } of part.slice(0, added.adopted)) {
        hc.known.set(toHex(header.hash), { ...header, rlpHex: toHex(rlp) });
      }
      i += added.adopted;
      const { refused } = added;
      if (!refused) continue;
      if (refused.why === "hash") throw notTheHash(Number(refused.number));
      // A header that passes every check but is dated more than the drift
      // ahead of this clock is offered again once the clock has caught up,
      // a few times; past that it is refused like any other.
      if (refused.why === "ahead" && waits < AHEAD_WAITS) {
        waits += 1;
        const ahead = Number(pending[i].header.timestamp) - hc.network.params.futureDrift - clock();
        progress(`waiting for this device's clock to reach block ${refused.number}'s time`);
        await sleep(Math.min(Math.max(ahead, 0) + 1, AHEAD_WAIT_S) * 1000);
        continue;
      }
      throw powFailed(`block ${refused.number}: ${refused.reason}`);
    }
    const view = await prover.request("chainView", { hash: fromHex(tipHash, 32), from: 1, to: 0 });
    if (view.confirmations === 0n) {
      throw new ChainRefused(
        `the endpoint's chain, with its tip at block ${top}, has less proof of work than the chain this page has already checked ` +
          `(tip at block ${view.best.height}): the app keeps the heavier chain and ${NO_CONFIRMATIONS}`,
      );
    }
    state.chainRefused = null;
    return hc.known.get(tipHash);
  }

  async function blockNumber() {
    return (await syncTip()).number;
  }

  // The headers of the page's best chain at heights `from` to `to`, which
  // the last syncTip reached.
  async function chainRange(from, to, hc = headerChain) {
    if (!hc) throw new Error("the page holds no header chain yet");
    if (from < hc.startHeight) throw new Error(`block ${from} is below the start this build pins, block ${hc.startHeight}`);
    const { hashes } = await prover.request("chainView", { hash: new Uint8Array(32), from, to });
    return hashes.map((hash) => hc.known.get(toHex(hash)));
  }

  // Block `number`'s header on the page's best chain.
  async function headerAt(number) {
    return (await chainRange(number, number))[0];
  }

  // The chain as of its tip: headers of the page's best chain, each the
  // parent of the next, from LEAF_WINDOW blocks below the settled block (or
  // from the start) up to the tip, which covers the settled block, the fee
  // window and the block the markers are read at.
  async function readChain() {
    const chainId = quantity(await rpc.call("eth_chainId"));
    const hc = await chainFor(chainId);
    const tip = await syncTip(hc);
    const top = tip.number;
    const settled = settledHeight(top);
    const low = Math.max(settled === null || settled < LEAF_WINDOW ? 0 : settled - LEAF_WINDOW, hc.startHeight);
    const headers = await chainRange(low, top, hc);
    const at = (n) => {
      if (n < low || n > top) throw new Error(`block ${n} is outside the headers read`);
      return headers[n - low];
    };
    const genesis = { hash: fromHex(hc.network.genesisHash, 32) };
    return { chainId, settled, low, headers, at, tip, genesis };
  }

  // Every spent coin marker as of `anchor`, in whole marker pages. They are
  // hints, not checked against a header (spec 05, section 8).
  async function fetchSpent(anchor) {
    const markers = [];
    for (let p = 0; ; p += 1) {
      const page = await rpc.call("ghost_getTreePage", ["coin-markers", "0x0", toQuantity(p), toHex(anchor.hash)]);
      const count = Number(quantity(page.count));
      if (count > PAGE_LEAVES || page.markers.length !== count) throw new Error(`marker page ${p} is malformed`);
      for (const marker of page.markers) markers.push(fromHex(marker, 32));
      if (count < PAGE_LEAVES) return concat(markers);
    }
  }

  // Everything the endpoint is asked for a key is asked before the key is
  // tried on a note: the headers, the tree and the markers, all fixed by the
  // tip alone. Notes are not checked against the tree (an endpoint can alter
  // them), so no request may follow from what restore found; on every path,
  // found or not, the requests are the same.
  //
  // The markers are those as of the tip (CONFIRMATIONS blocks, the tip's own
  // included), so a key shows claimed as soon as a block holds its coin's
  // spend.
  //
  // The work in the worker is the same whatever the key finds too: the leaf
  // count of each header read, from the roots of every prefix of the
  // fetched leaves, is computed here for every key, not only for one with a
  // coin to reveal. The headers are always blocks S - 32 to the tip,
  // verified and linked to the tip, whatever the coin, so the requests say
  // nothing about where the coin is; leafBlock picks a leaf's block from
  // those headers.
  async function scanKey(key) {
    const chain = await readChain();
    progress("reading the coin tree");
    const tree = await fetchTree(rpc, prover, chain.tip);
    const spent = await fetchSpent(chain.at(Math.max(0, chain.tip.number - (CONFIRMATIONS - 1))));
    const fee = (await feeForNextBlock(chain.tip, async (n) => chain.at(n))).fee;
    const { roots: prefixRoots } = await prover.request("prefixRoots", { leaves: tree.leaves, from: 0, to: tree.count });
    const countOf = new Map(prefixRoots.map((root, count) => [toHex(root), count]));
    const rootHeaders = chain.headers;
    const rootCounts = rootHeaders.map((header) => {
      const count = countOf.get(toHex(header.coinTreeRoot));
      if (count === undefined) throw new Error(`the endpoint's tree does not match the header of block ${header.number}`);
      return count;
    });
    const settledAt = chain.settled === null ? null : chain.settled - chain.low;
    const settledLeaves = settledAt === null ? tree.leaves : tree.leaves.slice(0, rootCounts[settledAt] * 32);
    progress("looking for the key's coins");
    const { found } = await prover.request("restore", {
      chainId: chain.chainId,
      key,
      records: tree.records,
      salts: tree.salts,
      markers: spent,
    });
    return { chain, tree, rootHeaders, rootCounts, prefixRoots, settledAt, settledLeaves, fee, found };
  }

  // The receipt of `hash`, or null while no block holds it.
  async function receiptOf(hash) {
    const receipt = await rpc.call("eth_getTransactionReceipt", [hash]);
    if (!receipt) return null;
    if (receipt.transactionHash != null && String(receipt.transactionHash).toLowerCase() !== String(hash).toLowerCase()) {
      throw new Error("the endpoint returned the receipt of another transaction");
    }
    if (quantity(receipt.status) !== 1n) throw new Error("the transaction failed in its block");
    return {
      blockNumber: Number(quantity(receipt.blockNumber)),
      blockHash: receipt.blockHash == null ? null : fromHex(receipt.blockHash, 32),
    };
  }

  async function waitReceipt(hash) {
    for (let i = 0; i < maxPolls; i += 1) {
      const receipt = await receiptOf(hash);
      if (receipt) return receipt;
      await sleep(pollMs);
    }
    throw new Error("no block holds the transaction yet; refresh later");
  }

  // The receipt of a reveal the node took when its tip was block
  // `sentAfter`, or null once the node no longer holds it and no block
  // does: its pool dropped it, so nothing was spent and it can be sent
  // again. A reveal the node still holds is waited for, as any transaction.
  async function waitTaken(hash, sentAfter) {
    for (let i = 0; i < maxPolls; i += 1) {
      const receipt = await receiptOf(hash);
      if (receipt) return receipt;
      if ((await blockNumber()) >= sentAfter + HELD_BLOCKS && !(await rpc.call("eth_getTransactionByHash", [hash]))) {
        // A block may have taken it between the two questions.
        return receiptOf(hash);
      }
      await sleep(pollMs);
    }
    throw new Error("no block holds the transaction yet; refresh later");
  }

  // A receipt is the endpoint's word only. A transaction sent when the
  // endpoint's tip was block `sentAfter` can only be in a later block. It
  // counts as settled when the chain shows what it did: the coin tree as
  // of the tip, checked against the tip's coin root, holds `commitment` (the
  // new leaf every commit, reveal and claim appends) at a position the
  // receipt's block added, read from the coin roots of that block and its
  // parent on the page's header chain, the one with the most work, that
  // leads to the tip. The first
  // block that holds it is enough (CONFIRMATIONS counts the transaction's own
  // block): no block on top is waited for. `receipt`, when given, is the one
  // already read for `hash`. The result carries the block's number and hash.
  //
  // A receipt whose block hash is not the chain's block of that number is
  // from a block a reorganisation replaced. Neither that receipt nor a
  // missing one says the transaction is gone: only the chain does. When the
  // tip's verified coin tree does not hold `commitment`, that is a
  // DroppedError; when it does, the receipt is read again to find the block
  // that holds it now, a bounded number of times.
  async function waitSettled(hash, commitment, sentAfter, receipt = null, reread = 0) {
    receipt ??= await waitReceipt(hash);
    progress("checking the block");
    let top = await blockNumber();
    if (receipt.blockNumber <= sentAfter) {
      throw new Error(`the receipt names block ${receipt.blockNumber}, which was in the chain before the transaction was sent`);
    }
    if (receipt.blockNumber > top) {
      throw new Error(`the receipt names block ${receipt.blockNumber}, not a block of the chain`);
    }
    const needed = receipt.blockNumber + CONFIRMATIONS - 1;
    for (let i = 0; top < needed; i += 1) {
      if (i >= maxPolls) throw new Error(`the chain has not reached block ${needed} yet; refresh later`);
      progress(`waiting for block ${needed}`);
      await sleep(pollMs);
      top = await blockNumber();
    }
    const headers = await chainRange(receipt.blockNumber - 1, top);
    const [parent, block] = headers;
    const tip = headers[headers.length - 1];
    if (receipt.blockHash && toHex(receipt.blockHash) !== toHex(block.hash)) {
      if (!(await treeHolds(commitment))) throw new DroppedError(block.number);
      const again = reread < REREADS ? await receiptOf(hash) : null;
      if (!again) {
        throw new Error(`the transaction's new coin is in the chain, but the endpoint names no block of the chain for it; refresh later`);
      }
      return waitSettled(hash, commitment, sentAfter, again, reread + 1);
    }
    const tree = await fetchTree(rpc, prover, tip);
    const { roots } = await prover.request("prefixRoots", { leaves: tree.leaves, from: 0, to: tree.count });
    const countOf = new Map(roots.map((root, count) => [toHex(root), count]));
    const before = countOf.get(toHex(parent.coinTreeRoot));
    const after = countOf.get(toHex(block.coinTreeRoot));
    if (before === undefined || after === undefined) {
      throw new Error(`the endpoint's tree does not match the header of block ${block.number}`);
    }
    const leaf = toHex(commitment);
    for (let position = before; position < after; position += 1) {
      if (toHex(tree.leaves.slice(position * 32, position * 32 + 32)) === leaf) {
        return { blockNumber: block.number, blockHash: block.hash, position };
      }
    }
    throw new Error(`block ${block.number} does not hold the transaction's new coin; it has not settled`);
  }

  // Whether the coin tree as of the tip, checked against the tip's verified
  // header, holds `commitment`. The whole tree is read, so no request names
  // the leaf.
  async function treeHolds(commitment) {
    const tip = await syncTip();
    const tree = await fetchTree(rpc, prover, tip);
    const leaf = toHex(commitment);
    for (let position = 0; position < tree.count; position += 1) {
      if (toHex(tree.leaves.slice(position * 32, position * 32 + 32)) === leaf) return true;
    }
    return false;
  }

  // Asks again whether the transaction of a step shown Sent, Done or
  // dropped (`record`, with its `txHash`, `block`, `blockHash` and
  // `commitment`) is in the chain, since Done comes at the first block and a
  // reorganisation can still replace it. The receipt is not the evidence: an
  // endpoint can answer null for a transaction that went through. While the
  // chain's verified header at `block` is still the one Done was shown in, it
  // stays Done. Otherwise a Done step shows dropped only when the tip's
  // verified coin tree no longer holds the transaction's new coin (a Sent
  // one stays Sent); when the tree does hold it (moved to another block, or
  // back after a drop) it shows Done, in the block its receipt names if that
  // block is the chain's. Returns the stage before.
  async function recheckDone(record, what) {
    if (!record || !["sent", "done", "dropped"].includes(record.stage) || !record.commitment) return null;
    const was = record.stage;
    const top = await blockNumber();
    if (was === "done" && record.block <= top && toHex((await headerAt(record.block)).hash) === toHex(record.blockHash)) {
      return was;
    }
    if (!(await treeHolds(record.commitment))) {
      if (was === "done") {
        record.stage = "dropped";
        record.dropped = droppedMessage(what, record.block);
      }
      return was;
    }
    record.stage = "done";
    record.dropped = null;
    const receipt = await receiptOf(record.txHash).catch(() => null);
    if (receipt && receipt.blockHash && receipt.blockNumber <= top) {
      const header = await headerAt(receipt.blockNumber);
      if (toHex(header.hash) === toHex(receipt.blockHash)) {
        record.block = receipt.blockNumber;
        record.blockHash = header.hash;
      }
    }
    return was;
  }

  // The worker's input for a reveal of the key's current coin; throws when
  // there is nothing to prove. With `pinned`, the coin a proof of this
  // reveal was already made for, only that coin may be proved: once it is
  // spent or no longer the key's current coin, the reveal sent before may
  // have gone through, and its remainder must not pay the same reveal again.
  async function revealArgs(scan, { key, kind, out, recipient, newKey }, pinned = null) {
    const { current } = keyStatus(scan.found);
    if (!current) throw new Error("this key holds no unspent coin");
    if (pinned && !sameCoin(current, pinned)) {
      throw new Error("the coin this reveal spends is no longer unspent: the reveal sent before may have gone through; refresh");
    }
    const plan = await planReveal(prover, scan, current, progress);
    const paid = (kind === "claim" ? 0n : out) + plan.fee;
    if (paid > current.amount) {
      throw new Error(
        `the coin holds ${formatGhost(current.amount)} GHOST; with the fee of ${formatGhost(plan.fee)} GHOST at most ${formatGhost(current.amount > plan.fee ? current.amount - plan.fee : 0n)} can go out`,
      );
    }
    return {
      chainId: scan.chain.chainId,
      domain: plan.domain,
      kind,
      root: plan.root,
      recipient: fromHex(kind === "claim" ? ZERO_ADDRESS : recipient, 20),
      out: kind === "claim" ? 0n : out,
      fee: plan.fee,
      number: current.number,
      amount: current.amount,
      position: current.position,
      // The coin's salt as restore found it (null for a version 1 coin): the
      // prover opens the coin with it, and a salted coin's remainder is
      // salted too.
      salt: current.salt ?? null,
      leaves: plan.leaves,
      key,
      newKey,
    };
  }

  // The worker's input for a decoy of the same kind over the same leaves
  // (lib.rs, ghost_prove): a throwaway key's coin of the fee plus 1 wei at
  // the last position, proved as a real reveal would be. It is salted, as a
  // new coin is, unless the key's current coin is of version 1: the decoy
  // mirrors the coin's version, so the work does not depend on the coin. The
  // tree-state rule is asked once too, as it is for a coin, whenever the
  // scan has a settled block.
  async function decoyArgs(scan, { kind, recipient }) {
    const { chain, settledLeaves } = scan;
    await askRuleForDecoy(prover, scan);
    const claim = kind === "claim";
    const { current } = keyStatus(scan.found);
    return {
      decoy: true,
      salted: !current || current.salt != null,
      chainId: chain.chainId,
      domain: chain.genesis.hash,
      kind: claim ? "claim" : "partial",
      root: new Uint8Array(32),
      recipient: fromHex(claim ? ZERO_ADDRESS : recipient, 20),
      out: claim ? 0n : 1n,
      fee: scan.fee,
      number: 0n,
      amount: scan.fee + (claim ? 1n : 2n),
      position: Math.max(settledLeaves.length / 32 - 1, 0),
      leaves: settledLeaves,
      key: "",
      newKey: "",
    };
  }

  // Proves a reveal of the key's current coin and sends it. A proof whose
  // fee window lapsed while it was being made is made again.
  //
  // After restore, every path, the one where the key holds no coin
  // included, does the same work and then asks the endpoint the same thing
  // in the same order before anything depends on the outcome. The work is a
  // proof: of the coin when there is one to reveal, otherwise of a decoy
  // (`decoyArgs`), so the time before the next request is a proof's time on
  // every path, the fee retries included. A coin's proof the worker refuses
  // takes a proof's time too: the worker proves a decoy before it answers
  // with the refusal (lib.rs, ghost_prove). The requests are eth_blockNumber,
  // the tip's header and the fee for the next block. Only then does a
  // failure surface, or the reveal go out; sending the reveal is what links
  // the connection to the coin.
  //
  // A send the node refuses because its head kept moving while it checked
  // the reveal (HEAD_MOVED) is the only one followed by more requests: after
  // a fixed `resendMs`, the tip once, its header and the fee for the next
  // block, then the same envelope while that fee is still the proof's and
  // its root has not gone stale (STALE_ROOT_DEPTH), or a new proof
  // otherwise. The tip need not hold still. After a proof's
  // HEAD_MOVED_SENDS-th refused send the reveal is proved again for the tip
  // by then, since a node that refused one envelope that often may never
  // take it. A refusal surfaces, with nothing asked after it, only once
  // `headMovedMs` has passed since the first proof or on the last send of
  // the `headMovedProofs`-th proof. Any other refusal is final. Every
  // proof after the first is of the first proof's input coin (`pinned`), so
  // an endpoint that took a send and still answered with the refusal cannot
  // have the remainder pay the same reveal again.
  //
  // A send the node takes is reported at once through `request.onSent({
  // hash, fee, remainder, coin })`, so the page shows it Sent, and then waited for here until a
  // block holds it (`waitTaken`). When the node lets it go first, as its pool does with a
  // held reveal that fails its check on a new head, that send counts as
  // refused: the same envelope again, or a new proof of the same coin, whose
  // marker is the same, so at most one of them can ever be executed. The
  // result carries the receipt.
  async function revealAndSend(request) {
    // `request.pinned`, when set, is the input coin of a send of this key
    // that may still go through (a step shown Sent or dropped): this send
    // may only spend that same coin, so its marker stops a second payment.
    let pinned = request.pinned ?? null;
    // Proofs whose every send the node refused or let go, and the sends it
    // took and let go, across all proofs.
    let refusedProofs = 0;
    let letGo = 0;
    let feeChanges = 0;
    const started = now();
    const outOfTime = () => now() - started >= headMovedMs;
    attempts: for (;;) {
      if (feeChanges >= FEE_ATTEMPTS) throw new Error("the fee changed every time a proof was ready; try again");
      const scan = await scanKey(request.key);
      let args = null;
      let failure = null;
      try {
        args = await revealArgs(scan, request, pinned);
        pinned ??= { number: args.number, position: args.position, amount: args.amount };
      } catch (err) {
        failure = err;
      }
      let proved = null;
      progress("proving in the background worker");
      try {
        const result = await prover.request("prove", args ?? (await decoyArgs(scan, request)), (stage) =>
          progress(stage === "proving" ? "proving in the background worker" : stage),
        );
        if (args) proved = result;
      } catch (err) {
        failure ??= err;
      }
      let tip = await syncTip();
      const { fee } = await feeForNextBlock(tip, headerAt);
      if (fee !== scan.fee) {
        feeChanges += 1;
        continue;
      }
      if (failure) throw failure;
      progress("sending the reveal");
      for (let sends = 1; ; sends += 1) {
        let hash;
        let refusal = null;
        try {
          hash = await rpc.call("eth_sendRawTransaction", [toHex(proved.envelope)]);
        } catch (err) {
          if (!isHeadMoved(err)) throw err;
          refusal = err;
        }
        if (!refusal) {
          if (String(hash).toLowerCase() !== toHex(proved.txHash)) {
            throw new Error("the endpoint returned another transaction hash");
          }
          request.onSent?.({ hash, fee: scan.fee, remainder: proved.remainder, coin: pinned });
          progress("waiting for a block");
          const receipt = await waitTaken(hash, tip.number);
          if (receipt) return { hash, fee: scan.fee, remainder: proved.remainder, sentAfter: tip.number, receipt };
          letGo += 1;
        }
        const giveUp = () =>
          refusal ?? new Error(`the node took the reveal and let it go before a block held it, ${letGo} times; nothing was spent; try again`);
        if (outOfTime()) throw giveUp();
        if (sends >= HEAD_MOVED_SENDS) {
          refusedProofs += 1;
          if (refusedProofs >= headMovedProofs) throw giveUp();
          progress(
            refusal
              ? "the node kept refusing this proof; proving again for its new tip"
              : "the node kept letting this proof go; proving again for its new tip",
          );
          continue attempts;
        }
        progress(refusal ? "the node's chain moved on; sending again" : "the node let the reveal go; sending again");
        await sleep(resendMs);
        tip = await syncTip();
        if ((await feeForNextBlock(tip, headerAt)).fee !== scan.fee) {
          feeChanges += 1;
          continue attempts;
        }
        if (tip.number - scan.chain.settled > STALE_ROOT_DEPTH && refusedProofs + 1 < headMovedProofs) {
          refusedProofs += 1;
          progress("the proof's tree state is far below the node's tip; proving again for its new tip");
          continue attempts;
        }
        progress("sending the reveal again");
      }
    }
  }

  // Opens the wallet of `words`: its account's address, read by the worker.
  async function openWallet(words) {
    const text = normalWords(words);
    const { address } = await prover.request("walletAccount", { words: text, index: ACCOUNT_INDEX });
    walletWords = text;
    state.wallet = { stage: "open", words: null, groups: null, wrong: [], address: toHex(address), balance: null };
    emit();
    await readBalance();
    return state.wallet;
  }

  async function readBalance() {
    const w = state.wallet;
    if (!w || w.stage !== "open") return null;
    w.balance = quantity(await rpc.call("eth_getBalance", [w.address, "latest"]));
    emit();
    return w.balance;
  }

  // Signs and sends an account transaction (type 0x52) from the open
  // wallet's account: the nonce, fee and gas from the endpoint, the genesis
  // hash from this build's entry for the network (the signature binds the
  // chain), the base fee from the tip the page's header chain adopted,
  // signed in the worker. Returns the transaction hash.
  async function sendFromWallet({ chainId, to, value, data }) {
    if (!walletWords || !state.wallet || state.wallet.stage !== "open") {
      throw new Error("open a wallet first: create one, or restore it from its 24 words");
    }
    const from = state.wallet.address;
    const hc = await chainFor(chainId);
    const genesis = fromHex(hc.network.genesisHash, 32);
    const nonce = quantity(await rpc.call("eth_getTransactionCount", [from, "pending"]));
    const tip = await syncTip(hc);
    // The endpoint's priority fee, at most PRIORITY_FEE_CAP.
    const asked = quantity(await rpc.call("eth_maxPriorityFeePerGas"));
    const priority = asked < PRIORITY_FEE_CAP ? asked : PRIORITY_FEE_CAP;
    const maxFee = 2n * nextBaseFee(tip) + priority;
    const call = { from, to, value: toQuantity(value), data: toHex(data) };
    const gasLimit = quantity(await rpc.call("eth_estimateGas", [call])) + ACCOUNT_EXTRA_GAS;
    if (gasLimit > COMMIT_GAS_CAP) {
      throw new Error(`the endpoint asks for ${gasLimit} gas for the commit, more than the ${COMMIT_GAS_CAP} the app signs`);
    }
    if (gasLimit * maxFee > maxCommitFee) {
      throw new Error(
        `the commit's gas could cost up to ${formatGhost(gasLimit * maxFee)} GHOST at the endpoint's fees, more than the ${formatGhost(maxCommitFee)} GHOST the app signs`,
      );
    }
    const balance = await readBalance();
    if (balance < value + gasLimit * maxFee) {
      throw new Error(`the wallet holds ${formatGhost(balance)} GHOST, less than the amount and the most the gas can cost`);
    }
    progress("signing with the wallet's quantum-safe key");
    const signed = await prover.request("walletSign", {
      words: walletWords,
      index: ACCOUNT_INDEX,
      chainId,
      genesis,
      nonce,
      maxPriorityFeePerGas: priority,
      maxFeePerGas: maxFee,
      gasLimit,
      to: fromHex(to, 20),
      value,
      data,
    });
    if (toHex(signed.sender) !== from) throw new Error("the signed transaction is not from the wallet's account");
    const txHash = toHex(signed.txHash);
    let answered;
    try {
      answered = await rpc.call("eth_sendRawTransaction", [toHex(signed.envelope)]);
    } catch (err) {
      // A node can take the transaction and still answer with an error:
      // ghost-node's eth_sendRawTransaction does for type 0x52 once its pool
      // has it. The commit counts as sent only if the node then holds it;
      // whether a block holds it is checked against the chain as for any
      // commit.
      if (!(await rpc.call("eth_getTransactionByHash", [txHash]))) throw err;
      answered = txHash;
    }
    if (String(answered).toLowerCase() !== txHash) throw new Error("the endpoint answered with another transaction's hash");
    return txHash;
  }

  async function refreshSummon() {
    const s = state.summon;
    let scan;
    try {
      scan = await scanKey(s.key);
    } catch (err) {
      // A chain the page refused shows nothing of the key: no coin, no
      // status, no tip.
      if (err instanceof ChainRefused) {
        Object.assign(s, {
          status: "refused",
          refusal: err.message,
          coins: [],
          current: null,
          cover: null,
          wait: null,
          tip: null,
          fee: null,
          available: 0n,
        });
        emit();
      }
      throw err;
    }
    const { status, current } = keyStatus(scan.found);
    const { fee } = scan;
    s.coins = scan.found.map(({ number, amount, position, spent }) => ({ number, amount, position, spent }));
    s.status = status;
    s.current = current ? { number: current.number, amount: current.amount, position: current.position } : null;
    s.fee = fee;
    s.available = current && current.amount > fee ? current.amount - fee : 0n;
    s.tip = scan.chain.tip.number;
    // What a reveal now would prove against, for the holder to choose: the
    // block and how many coins its tree covers, or why the app waits. The
    // rule is asked for every key, a coin or not.
    s.cover = null;
    s.wait = null;
    if (current) {
      try {
        const plan = await planReveal(prover, scan, current);
        s.cover = { height: plan.height, covers: plan.covers, total: scan.tree.count };
      } catch (err) {
        if (!(err instanceof WaitError)) throw err;
        s.wait = { message: err.message, alone: err.alone };
      }
    }
    await askRuleForDecoy(prover, scan);
    emit();
    return s;
  }

  // Waits (`wait`) for the first block that holds a Sent step's transaction
  // and marks `record` Done in it, or dropped when a reorganisation took it
  // out first. `commitment` is the transaction's new leaf, which a later
  // recheck looks for in the chain.
  async function settle(record, what, commitment, wait) {
    record.commitment = commitment;
    try {
      const receipt = await wait();
      record.stage = "done";
      record.block = receipt.blockNumber;
      record.blockHash = receipt.blockHash;
      return receipt;
    } catch (err) {
      if (err instanceof DroppedError) {
        record.stage = "dropped";
        record.dropped = droppedMessage(what, err.block);
      }
      throw err;
    }
  }

  // `settle` for a reveal or claim of the open key, keeping its pin: the
  // input coin of a send that may still go through (`s.pinned`, set when the
  // node takes it) is cleared once the send is Done, and kept when it is
  // dropped, so a send again can only spend that same coin.
  async function settleSummon(s, record, what, commitment, wait) {
    const receipt = await settle(record, what, commitment, wait);
    s.pinned = null;
    return receipt;
  }

  // Refresh's second look at the open key's last reveal and claim. A step
  // the chain shows dropped keeps its input coin pinned; one the chain shows
  // Done after all releases the pin, as its coin is then spent for good.
  async function recheckSummon(s) {
    for (const [record, what] of [
      [s.lastReveal, "reveal"],
      [s.claim, "claim"],
    ]) {
      const was = await recheckDone(record, what);
      if (was === null) continue;
      if (record.stage === "dropped") s.pinned ??= record.coin;
      if (record.stage === "done" && was !== "done" && s.pinned && sameCoin(s.pinned, record.coin)) s.pinned = null;
    }
  }

  function saveCheckStep(holder) {
    if (!holder || holder.stage !== "shown") throw new Error("show the key first");
    holder.groups = pickGroups(random);
    holder.wrong = [];
    holder.stage = "check";
    emit();
    return holder.groups;
  }

  // The save check stays on the key's words, whichever view is shown.
  function requireCheck(holder, answers) {
    if (!holder || holder.stage !== "check") throw new Error("the save check has not started");
    const wrong = wrongWords(holder.key, holder.groups, answers);
    holder.wrong = wrong;
    emit();
    return wrong;
  }

  // Shows the key of Vanish or Claim (`holder`) as its words or as its digit
  // view, 21 groups of four digits, which the worker writes from the words.
  // The digits are dropped with the key.
  async function keyView(holder, view) {
    if (!holder || !holder.key || (holder.stage !== "shown" && holder.stage !== "check")) {
      throw new Error("show the key first");
    }
    if (view !== "words" && view !== "digits") throw new Error("a key is shown as words or as digits");
    if (view === "digits" && !holder.digits) {
      const { digits } = await prover.request("keyDigits", { key: holder.key });
      holder.digits = digits;
    }
    holder.view = view;
    emit();
    return view === "digits" ? holder.digits : holder.key;
  }

  // The key leaves the holder: its words and its digit view.
  function dropKey(holder) {
    holder.key = null;
    holder.digits = null;
    holder.view = "words";
  }

  return {
    state,

    setEndpoint(text) {
      if (state.busy) throw new Error("wait until the current step is done");
      rpc = createRpc(text, { fetch });
      state.endpoint = rpc.url;
      // The page's header chain stays: a new endpoint's chain is checked
      // against it, and the heavier one is kept.
      state.chainRefused = null;
      emit();
      return state.endpoint;
    },

    setCommitEntry(text) {
      const address = parseAddress(text);
      if (address === ZERO_ADDRESS) throw new Error("the commit entry cannot be the zero address: the value would be burned");
      state.commitEntry = address;
      emit();
      return state.commitEntry;
    },

    // Wallet, new: a new seed, shown as 24 words to write down.
    walletCreate() {
      return run("creating a wallet", async () => {
        const { words } = await prover.request("walletNew");
        walletWords = null;
        state.wallet = { stage: "shown", words, groups: null, wrong: [], address: null, balance: null };
        emit();
        return words;
      });
    },

    // Wallet, new: the user says the words are saved; three to re-type.
    walletSaved() {
      const w = state.wallet;
      if (!w || w.stage !== "shown") throw new Error("show the wallet's words first");
      w.groups = pickGroups(random, SEED_WORDS);
      w.wrong = [];
      w.stage = "check";
      emit();
      return w.groups;
    },

    // Wallet, new: the re-typed words. The wallet opens only if all match.
    walletCheck(answers) {
      return run("opening the wallet", async () => {
        const w = state.wallet;
        if (!w || w.stage !== "check") throw new Error("the save check has not started");
        const wrong = wrongWords(w.words, w.groups, answers);
        w.wrong = wrong;
        emit();
        if (wrong.length > 0) return { ok: false, wrong };
        const opened = await openWallet(w.words);
        return { ok: true, address: opened.address };
      });
    },

    // Wallet, restore: the 24 words of a seed saved before.
    walletRestore(text) {
      return run("restoring the wallet", async () => {
        const opened = await openWallet(text);
        return opened.address;
      });
    },

    walletRefresh() {
      return run("reading the wallet's balance", readBalance);
    },

    // Drops the seed from memory.
    walletClose() {
      if (state.busy) throw new Error(`wait until "${state.busy}" is done`);
      walletWords = null;
      state.wallet = null;
      emit();
    },

    // Vanish, step 1: a new key of 24 words for `amountText` GHOST, shown
    // to the user to write down; copying it or downloading its image is a
    // convenience beside that, never the only backup.
    vanishStart(amountText) {
      return run("creating a key", async () => {
        if (!walletWords) throw new Error("open a wallet first: create one, or restore it from its 24 words");
        const amount = parseGhost(amountText);
        if (amount === 0n) throw new Error("enter an amount above zero");
        const { key } = await prover.request("newKey");
        state.vanish = {
          stage: "shown",
          key,
          view: "words",
          digits: null,
          amount,
          groups: null,
          wrong: [],
          txHash: null,
          block: null,
        };
        return key;
      });
    },

    // Vanish: the new key shown as its words or as its digit view.
    vanishView(view) {
      return keyView(state.vanish, view);
    },

    // Vanish, step 2: the user says the key is saved; three words to re-type.
    vanishSaved() {
      return saveCheckStep(state.vanish);
    },

    // Vanish, step 3: the re-typed words. Nothing is sent unless all match.
    vanishCheck(answers) {
      return run("sending the commit", async () => {
        const v = state.vanish;
        const wrong = requireCheck(v, answers);
        if (wrong.length > 0) return { ok: false, wrong };
        if (!walletWords) throw new Error("open a wallet first: create one, or restore it from its 24 words");
        const chainId = quantity(await rpc.call("eth_chainId"));
        progress("building the commit");
        const sentAfter = await blockNumber();
        // Version 2: the worker draws the coin's salt from its secure random
        // source and the payload carries it beside F (206 bytes).
        const commit = await prover.request("commit", { chainId, amount: v.amount, key: v.key });
        if (commit.payload.length !== COMMIT_DATA_BYTES || commit.payload[0] !== 0 || commit.payload[1] !== 2) {
          throw new Error(`the commit is not ${COMMIT_DATA_BYTES} bytes of version 2; nothing was sent`);
        }
        const txHash = await sendFromWallet({ chainId, to: state.commitEntry, value: v.amount, data: commit.payload });
        // The user has the key; the app no longer needs it. The node took
        // the commit: the page shows it Sent at once.
        dropKey(v);
        v.stage = "sent";
        v.txHash = txHash;
        emit();
        progress("waiting for a block");
        const receipt = await settle(v, "commit", commit.commitment, () => waitSettled(txHash, commit.commitment, sentAfter));
        await readBalance();
        return { ok: true, txHash, block: receipt.blockNumber };
      });
    },

    // Vanish: whether the commit shown Done is still in the chain; it shows
    // dropped, with the reason, when a reorganisation took it out.
    vanishRecheck() {
      return run("checking the commit", async () => {
        if (!state.vanish || (state.vanish.stage !== "done" && state.vanish.stage !== "dropped")) {
          throw new Error("no commit is shown Done");
        }
        await recheckDone(state.vanish, "commit");
        return state.vanish;
      });
    },

    vanishCancel() {
      state.vanish = null;
      emit();
    },

    // Summon: enter any valid key: its 24 words, in any case, separated by
    // spaces or hyphens, or its digits (21 groups for a words key, or the 12
    // or 24 groups of a key issued before the words). The worker checks the
    // key's check before anything is derived; a key that fails is refused
    // with a message that names a position at most, never a word or digit.
    summonOpen(keyText) {
      return run("opening the key", async () => {
        const key = normalKey(keyText);
        const { format, groups } = await prover.request("checkKey", { key });
        state.summon = {
          key,
          format,
          groups,
          status: "scanning",
          coins: [],
          current: null,
          cover: null,
          wait: null,
          claim: null,
          lastReveal: null,
          pinned: null,
        };
        return refreshSummon();
      });
    },

    summonRefresh() {
      return run("reading the key's coins", async () => {
        if (!state.summon) throw new Error("enter a key first");
        // A reveal or claim shown Sent or Done is asked about again: a
        // reorganisation since can have dropped its block. The scan then
        // shows the coin unspent again, so it can be sent again, pinned to
        // that coin.
        await recheckSummon(state.summon);
        return refreshSummon();
      });
    },

    // Summon: reveal `amount` GHOST of the current coin to `recipient`; the
    // rest, minus the fee, stays under the same key.
    summonReveal({ amount, recipient }) {
      return run("revealing", async () => {
        const s = state.summon;
        if (!s || !s.current) throw new Error("this key holds no coin to reveal");
        const out = parseGhost(amount);
        if (out === 0n) throw new Error("enter an amount above zero");
        const to = parseAddress(recipient);
        // A reveal credits its recipient, and nobody can spend what the zero
        // address is credited.
        if (to === ZERO_ADDRESS) throw new Error("the zero address cannot receive a reveal: the amount would be lost");
        // Shown Sent, with the amount and hash, as soon as the node takes it.
        // From then on its input coin is pinned until it is Done.
        const onSent = ({ hash, fee, remainder, coin }) => {
          s.pinned = coin;
          s.lastReveal = {
            stage: "sent",
            txHash: hash,
            out,
            recipient: to,
            fee,
            block: null,
            dropped: null,
            coin,
            commitment: remainder.commitment,
          };
          emit();
        };
        const sent = await revealAndSend({ key: s.key, kind: "partial", out, recipient: to, onSent, pinned: s.pinned });
        progress("checking the block");
        await settleSummon(s, s.lastReveal, "reveal", sent.remainder.commitment, () =>
          waitSettled(sent.hash, sent.remainder.commitment, sent.sentAfter, sent.receipt),
        );
        await refreshSummon();
        return s.lastReveal;
      });
    },

    // Claim, step 1: a new key of 24 words for the remaining value, to be
    // saved first.
    claimStart() {
      return run("creating a key", async () => {
        const s = state.summon;
        if (!s || !s.current) throw new Error("this key holds no coin to claim");
        const { key } = await prover.request("newKey");
        s.claim = {
          stage: "shown",
          key,
          view: "words",
          digits: null,
          groups: null,
          wrong: [],
          txHash: null,
          block: null,
          amount: null,
        };
        return key;
      });
    },

    // Claim: the new key shown as its words or as its digit view.
    claimView(view) {
      return keyView(state.summon && state.summon.claim, view);
    },

    claimSaved() {
      return saveCheckStep(state.summon && state.summon.claim);
    },

    // Claim, step 3: with three of the new key's words re-typed, move the coin's
    // value minus the fee to the new key, and wait for its block. The old
    // key stays unclaimed until the chain shows the new key's coin.
    claimCheck(answers) {
      return run("claiming", async () => {
        const s = state.summon;
        const c = s && s.claim;
        const wrong = requireCheck(c, answers);
        if (wrong.length > 0) return { ok: false, wrong };
        // Shown Sent, with the amount and hash, as soon as the node takes it.
        // From then on its input coin is pinned until it is Done.
        const onSent = ({ hash, remainder, coin }) => {
          s.pinned = coin;
          dropKey(c);
          c.stage = "sent";
          c.txHash = hash;
          c.amount = remainder.amount;
          c.coin = coin;
          c.commitment = remainder.commitment;
          emit();
        };
        const sent = await revealAndSend({ key: s.key, kind: "claim", out: 0n, newKey: c.key, onSent, pinned: s.pinned });
        progress("checking the block");
        const receipt = await settleSummon(s, c, "claim", sent.remainder.commitment, () =>
          waitSettled(sent.hash, sent.remainder.commitment, sent.sentAfter, sent.receipt),
        );
        await refreshSummon();
        return { ok: true, txHash: sent.hash, block: receipt.blockNumber, amount: sent.remainder.amount };
      });
    },

    summonClose() {
      state.summon = null;
      emit();
    },
  };
}
