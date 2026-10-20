// The app's flow controller: Vanish with the save check, Summon and Claim.
// It touches no DOM, so the headless test drives exactly what the page
// drives; app.mjs only renders its state and forwards the user's input.
//
// What it talks to:
//
// - the chosen node endpoint, by JSON-RPC: headers, the coin tree in whole
//   pages, the spent markers in whole pages, receipts, and the reveal
//   transaction. No request names a key, a commitment, a position or a
//   marker; the reveal itself carries only public fields;
// - the injected EIP-1193 wallet, only to send the commit;
// - the background worker (prover.mjs), which holds the WebAssembly module
//   and receives a key's digits for the length of one request.
//
// A key lives only in this object's memory: it is never written to browser
// storage, a file, a cookie or a server, and it is dropped as soon as the
// step that needs it is done.

import { concat, equalBytes, fromHex, quantity, toHex, toQuantity } from "./bytes.mjs";
import {
  CONFIRMATIONS,
  SETTLE_DEPTH,
  feeForNextBlock,
  formatGhost,
  parseAddress,
  parseGhost,
  settledHeight,
} from "./chain.mjs";
import { readHeader } from "./header.mjs";
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
// Groups the user re-types before a key is used, out of a key's twelve.
export const SAVE_CHECK_GROUPS = 3;
const KEY_GROUPS = 12;
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
// coin, for the tree state and fee of the tip by then; at most
// HEAD_MOVED_PROOFS proofs are made so before the last refusal surfaces.
export const HEAD_MOVED_PROOFS = 4;
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

// The plain warning for a coin no later leaf follows yet. The only tree that
// holds it then ends with its own block, and a reveal against that root would
// tie the reveal to its commit, so the app waits instead.
export const ALONE_WARNING =
  "nobody has committed a coin since this one. A reveal now could only prove against the coin tree that ends with " +
  "this coin's own block, which ties the reveal to its commit, so the app waits: this coin can be revealed " +
  `${SETTLE_DEPTH} blocks after anyone else commits one`;

// Three distinct group positions (1 to 12), drawn without bias from the
// secure random source and returned in order.
export function pickGroups(random, total = KEY_GROUPS, count = SAVE_CHECK_GROUPS) {
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

// The positions whose typed group does not match the key.
export function wrongGroups(keyText, positions, answers) {
  const groups = keyText.trim().split(/[\s-]+/);
  return positions.filter((position, i) => String(answers[i] ?? "").replace(/[\s-]/g, "") !== groups[position - 1]);
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
// `{ kind, treeIndex, page, filled, entries: [{ leaf, note }] }`. Every page
// but the last is full and the last holds 1 to 4,096 leaves; the page roots
// and leaves are checked against the anchor's coin root. Anything else is
// refused, never guessed at.
export async function fetchTree(rpc, prover, anchor) {
  const anchorHash = toHex(anchor.hash);
  const list = await rpc.call("ghost_getPageRoots", ["coin", "0x0", anchorHash]);
  if (!Array.isArray(list)) throw new Error("the endpoint's page roots are not a list");
  const pageRoots = list.map((root) => fromHex(root, 32));
  const leaves = [];
  const records = [];
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
    }
  }
  const leafBytes = concat(leaves);
  await prover.request("treeCheck", { pageRoots: concat(pageRoots), leaves: leafBytes, root: anchor.coinTreeRoot });
  return { count: leaves.length, leaves: leafBytes, records: concat(records) };
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
  wallet = null,
  fetch = globalThis.fetch,
  random = (n) => crypto.getRandomValues(new Uint8Array(n)),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
  pollMs = 3000,
  maxPolls = 600,
  resendMs = RESEND_MS,
  endpoint = DEFAULT_ENDPOINT,
  commitEntry = DEFAULT_COMMIT_ENTRY,
  onChange = () => {},
} = {}) {
  let rpc = createRpc(endpoint, { fetch });
  const state = {
    endpoint: rpc.url,
    commitEntry,
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
      throw err;
    } finally {
      state.busy = null;
      state.progress = null;
      emit();
    }
  }

  // --- The chain, from the endpoint ---

  async function blockNumber() {
    return Number(quantity(await rpc.call("eth_blockNumber")));
  }

  // Block `number`'s header, kept only if keccak256 of its 18-field RLP
  // (spec 05, section 10) is the hash the endpoint returned with it, so no
  // field, a coin root included, can be changed under a real hash. The
  // proof-of-work seal is not checked: the endpoint is trusted for it.
  async function headerAt(number) {
    const raw = await rpc.call("eth_getBlockByNumber", [toQuantity(number), false]);
    if (!raw) throw new Error(`the endpoint has no block ${number}`);
    const { values, rlp } = readHeader(raw);
    const hash = fromHex(raw.hash, 32);
    const { hash: computed } = await prover.request("keccak256", { bytes: rlp });
    if (!equalBytes(computed, hash)) {
      throw new Error(`the endpoint's header of block ${number} does not hash to the block hash it returned`);
    }
    const header = {
      number: Number(values.number),
      hash,
      parentHash: values.parentHash,
      baseFee: values.baseFeePerGas,
      gasUsed: values.gasUsed,
      gasLimit: values.gasLimit,
      coinTreeRoot: values.coinTreeRoot,
    };
    if (header.number !== number) throw new Error(`the endpoint returned block ${header.number} for ${number}`);
    return header;
  }

  // The chain as of its tip: verified headers, each the parent of the next,
  // from LEAF_WINDOW blocks below the settled block (or from genesis) up to
  // the tip, which covers the settled block, the fee window and the block 6
  // below the tip. Which blocks are asked for depends on the tip alone.
  async function readChain() {
    const chainId = quantity(await rpc.call("eth_chainId"));
    const top = await blockNumber();
    const settled = settledHeight(top);
    const low = settled === null || settled < LEAF_WINDOW ? 0 : settled - LEAF_WINDOW;
    const headers = await headerRange(low, top);
    const at = (n) => {
      if (n < low || n > top) throw new Error(`block ${n} is outside the headers read`);
      return headers[n - low];
    };
    const genesis = low === 0 ? headers[0] : await headerAt(0);
    return { chainId, settled, low, headers, at, tip: headers[headers.length - 1], genesis };
  }

  // Consecutive verified headers, each the parent of the next.
  async function headerRange(from, to) {
    const headers = [];
    for (let n = from; n <= to; n += 1) {
      const header = await headerAt(n);
      const parent = headers[headers.length - 1];
      if (parent && toHex(header.parentHash) !== toHex(parent.hash)) {
        throw new Error(`block ${n} does not follow block ${n - 1}`);
      }
      headers.push(header);
    }
    return headers;
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
  // The markers are those as of 6 blocks below the tip, so a key shows
  // claimed only once its coin's spend has 6 blocks on top.
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
    const spent = await fetchSpent(chain.at(Math.max(0, chain.tip.number - CONFIRMATIONS)));
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
  // counts as settled when the chain shows what it did, with 6 blocks on
  // top: the coin tree as
  // of the tip, checked against the tip's coin root, holds `commitment` (the
  // new leaf every commit, reveal and claim appends) at a position the
  // receipt's block added, read from the coin roots of that block and its
  // parent in the verified header chain that leads to the tip. `receipt`,
  // when given, is the one already read for `hash`.
  async function waitSettled(hash, commitment, sentAfter, receipt = null) {
    receipt ??= await waitReceipt(hash);
    progress("checking the block");
    let top = await blockNumber();
    if (receipt.blockNumber <= sentAfter) {
      throw new Error(`the receipt names block ${receipt.blockNumber}, which was in the chain before the transaction was sent`);
    }
    if (receipt.blockNumber > top) {
      throw new Error(`the receipt names block ${receipt.blockNumber}, not a block of the chain`);
    }
    if (top < receipt.blockNumber + CONFIRMATIONS) progress(`waiting for ${CONFIRMATIONS} blocks on top`);
    for (let i = 0; top < receipt.blockNumber + CONFIRMATIONS; i += 1) {
      if (i >= maxPolls) {
        throw new Error(
          `block ${receipt.blockNumber} has ${top - receipt.blockNumber} of the ${CONFIRMATIONS} blocks on top it needs; refresh later`,
        );
      }
      await sleep(pollMs);
      top = await blockNumber();
    }
    const headers = await headerRange(receipt.blockNumber - 1, top);
    const [parent, block] = headers;
    const tip = headers[headers.length - 1];
    if (receipt.blockHash && toHex(receipt.blockHash) !== toHex(block.hash)) {
      throw new Error(`the receipt's block is not block ${block.number} of the chain`);
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
        return { blockNumber: block.number, position };
      }
    }
    throw new Error(`block ${block.number} does not hold the transaction's new coin; it has not settled`);
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
      leaves: plan.leaves,
      key,
      newKey,
    };
  }

  // The worker's input for a decoy of the same kind over the same leaves
  // (lib.rs, ghost_prove): a throwaway key's coin of the fee plus 1 wei at
  // the last position, proved as a real reveal would be. The tree-state rule
  // is asked once too, as it is for a coin, whenever the scan has a settled
  // block.
  async function decoyArgs(scan, { kind, recipient }) {
    const { chain, settledLeaves } = scan;
    await askRuleForDecoy(prover, scan);
    const claim = kind === "claim";
    return {
      decoy: true,
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
  // its root is at most STALE_ROOT_DEPTH blocks below the tip, or a new
  // proof otherwise. The tip need not hold still. After a proof's
  // HEAD_MOVED_SENDS-th refused send the reveal is proved again for the tip
  // by then, since a node that refused one envelope that often may never
  // take it; the refusal of the last send of the HEAD_MOVED_PROOFS-th proof
  // surfaces, with nothing asked after it. Any other refusal is final. Every
  // proof after the first is of the first proof's input coin (`pinned`), so
  // an endpoint that took a send and still answered with the refusal cannot
  // have the remainder pay the same reveal again.
  //
  // A send the node takes is waited for here until a block holds it
  // (`waitTaken`). When the node lets it go first, as its pool does with a
  // held reveal that fails its check on a new head, that send counts as
  // refused: the same envelope again, or a new proof of the same coin, whose
  // marker is the same, so at most one of them can ever be executed. The
  // result carries the receipt.
  async function revealAndSend(request) {
    let pinned = null;
    // Proofs whose every send the node refused or let go, and the sends it
    // took and let go, across all proofs.
    let refusedProofs = 0;
    let letGo = 0;
    let feeChanges = 0;
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
      let tip = await headerAt(await blockNumber());
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
          progress("waiting for a block");
          const receipt = await waitTaken(hash, tip.number);
          if (receipt) return { hash, fee: scan.fee, remainder: proved.remainder, sentAfter: tip.number, receipt };
          letGo += 1;
        }
        if (sends >= HEAD_MOVED_SENDS) {
          refusedProofs += 1;
          if (refusedProofs >= HEAD_MOVED_PROOFS) {
            throw (
              refusal ??
              new Error(`the node took the reveal and let it go before a block held it, ${letGo} times; nothing was spent; try again`)
            );
          }
          progress(
            refusal
              ? "the node kept refusing this proof; proving again for its new tip"
              : "the node kept letting this proof go; proving again for its new tip",
          );
          continue attempts;
        }
        progress(refusal ? "the node's chain moved on; sending again" : "the node let the reveal go; sending again");
        await sleep(resendMs);
        tip = await headerAt(await blockNumber());
        if ((await feeForNextBlock(tip, headerAt)).fee !== scan.fee) {
          feeChanges += 1;
          continue attempts;
        }
        if (tip.number - scan.chain.settled > STALE_ROOT_DEPTH && refusedProofs + 1 < HEAD_MOVED_PROOFS) {
          refusedProofs += 1;
          progress("the proof's tree state is far below the node's tip; proving again for its new tip");
          continue attempts;
        }
        progress("sending the reveal again");
      }
    }
  }

  async function connect() {
    if (!wallet) throw new Error("no browser wallet found: the app needs one that injects window.ethereum");
    const accounts = await wallet.request({ method: "eth_requestAccounts" });
    if (!Array.isArray(accounts) || accounts.length === 0) throw new Error("the wallet shared no account");
    const chainId = quantity(await wallet.request({ method: "eth_chainId" }));
    state.wallet = { account: String(accounts[0]).toLowerCase(), chainId };
    emit();
    return state.wallet;
  }

  async function refreshSummon() {
    const s = state.summon;
    const scan = await scanKey(s.key);
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

  function saveCheckStep(holder) {
    if (!holder || holder.stage !== "shown") throw new Error("show the key first");
    holder.groups = pickGroups(random);
    holder.wrong = [];
    holder.stage = "check";
    emit();
    return holder.groups;
  }

  function requireCheck(holder, answers) {
    if (!holder || holder.stage !== "check") throw new Error("the save check has not started");
    const wrong = wrongGroups(holder.key, holder.groups, answers);
    holder.wrong = wrong;
    emit();
    return wrong;
  }

  return {
    state,

    setEndpoint(text) {
      if (state.busy) throw new Error("wait until the current step is done");
      rpc = createRpc(text, { fetch });
      state.endpoint = rpc.url;
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

    connectWallet() {
      return run("connecting the wallet", connect);
    },

    // Vanish, step 1: a new standard key for `amountText` GHOST, shown to
    // the user to copy, write down or download.
    vanishStart(amountText) {
      return run("creating a key", async () => {
        const amount = parseGhost(amountText);
        if (amount === 0n) throw new Error("enter an amount above zero");
        const { key } = await prover.request("newKey");
        state.vanish = { stage: "shown", key, amount, groups: null, wrong: [], txHash: null, block: null };
        return key;
      });
    },

    // Vanish, step 2: the user says the key is saved; three groups to re-type.
    vanishSaved() {
      return saveCheckStep(state.vanish);
    },

    // Vanish, step 3: the re-typed groups. Nothing is sent unless all match.
    vanishCheck(answers) {
      return run("sending the commit", async () => {
        const v = state.vanish;
        const wrong = requireCheck(v, answers);
        if (wrong.length > 0) return { ok: false, wrong };
        const account = state.wallet ? state.wallet.account : (await connect()).account;
        const chainId = quantity(await rpc.call("eth_chainId"));
        const walletChain = quantity(await wallet.request({ method: "eth_chainId" }));
        if (walletChain !== chainId) {
          throw new Error(`the wallet is on chain ${walletChain}, the endpoint on chain ${chainId}`);
        }
        progress("building the commit");
        const sentAfter = await blockNumber();
        const commit = await prover.request("commit", { chainId, amount: v.amount, key: v.key });
        progress("waiting for the wallet");
        const txHash = await wallet.request({
          method: "eth_sendTransaction",
          params: [{ from: account, to: state.commitEntry, value: toQuantity(v.amount), data: toHex(commit.payload) }],
        });
        // The user has the key; the app no longer needs it.
        v.key = null;
        v.stage = "pending";
        v.txHash = txHash;
        progress("waiting for a block");
        const receipt = await waitSettled(txHash, commit.commitment, sentAfter);
        v.stage = "confirmed";
        v.block = receipt.blockNumber;
        return { ok: true, txHash, block: receipt.blockNumber };
      });
    },

    vanishCancel() {
      state.vanish = null;
      emit();
    },

    // Summon: enter any valid standard or long key.
    summonOpen(keyText) {
      return run("opening the key", async () => {
        const key = String(keyText).trim();
        const { groups } = await prover.request("checkKey", { key });
        state.summon = {
          key,
          groups,
          status: "scanning",
          coins: [],
          current: null,
          cover: null,
          wait: null,
          claim: null,
          lastReveal: null,
        };
        return refreshSummon();
      });
    },

    summonRefresh() {
      return run("reading the key's coins", async () => {
        if (!state.summon) throw new Error("enter a key first");
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
        const sent = await revealAndSend({ key: s.key, kind: "partial", out, recipient: to });
        s.status = "pending";
        s.lastReveal = { txHash: sent.hash, out, recipient: to, fee: sent.fee, block: null };
        progress("waiting for a block");
        const receipt = await waitSettled(sent.hash, sent.remainder.commitment, sent.sentAfter, sent.receipt);
        s.lastReveal.block = receipt.blockNumber;
        await refreshSummon();
        return s.lastReveal;
      });
    },

    // Claim, step 1: a new key for the remaining value, to be saved first.
    claimStart() {
      return run("creating a key", async () => {
        const s = state.summon;
        if (!s || !s.current) throw new Error("this key holds no coin to claim");
        const { key } = await prover.request("newKey");
        s.claim = { stage: "shown", key, groups: null, wrong: [], txHash: null, block: null, amount: null };
        return key;
      });
    },

    claimSaved() {
      return saveCheckStep(state.summon && state.summon.claim);
    },

    // Claim, step 3: with the new key's groups re-typed, move the coin's
    // value minus the fee to the new key, and wait for its block. The old
    // key stays unclaimed until the chain shows the new key's coin.
    claimCheck(answers) {
      return run("claiming", async () => {
        const s = state.summon;
        const c = s && s.claim;
        const wrong = requireCheck(c, answers);
        if (wrong.length > 0) return { ok: false, wrong };
        const sent = await revealAndSend({ key: s.key, kind: "claim", out: 0n, newKey: c.key });
        c.key = null;
        c.stage = "pending";
        c.txHash = sent.hash;
        c.amount = sent.remainder.amount;
        progress("waiting for a block");
        const receipt = await waitSettled(sent.hash, sent.remainder.commitment, sent.sentAfter, sent.receipt);
        c.stage = "confirmed";
        c.block = receipt.blockNumber;
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
