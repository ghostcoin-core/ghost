// The app's flow controller: Vanish with the save check, Summon and Claim.
// It touches no DOM, so the headless test drives exactly what the page
// drives; app.mjs only renders its state and forwards the user's input.
//
// What it talks to:
//
// - the chosen node endpoint, by JSON-RPC: headers, which the worker's header
//   chain adopts only once their difficulty and proof-of-work seal check,
//   from the start this build pins for the network; the coin tree in whole
//   pages, the spent markers in whole pages, the block receipts of every
//   block of the page's header chain (eth_getBlockReceipts by block hash),
//   transaction receipts, and the reveal transaction. No request names a
//   key, a commitment, a position or a marker; the reveal itself carries
//   only public fields. Every leaf, note, salt and spent marker a scan reads
//   is checked against the block receipts, and those against the
//   receiptsRoot of the headers the page's chain holds, before the key is
//   tried on a note;
// - the background worker (prover.mjs), which holds the WebAssembly module
//   and receives a key's words (or their 21 digit groups) for the length of
//   one request;
// - the connected wallet (wallet-connect.mjs), which holds the account's
//   key and signs the commit's account transaction when the user approves
//   it there.
//
// A new Phantom Key is 24 words, the client library's default: a 256-bit
// secret, so it stays strong even against a quantum search. Its coin's
// commit is version 2 with a fresh per-coin salt in the clear beside `F`
// (206 bytes); the node serves that salt beside the leaf, the app hands it
// to restore, and the reveal and the claim pass the coin's salt to the
// prover. A key is only ever words or their 21 digit groups: the digit keys
// of twelve or twenty-four groups are refused.
//
// The wallet is connected, not built in: a connector (wallet-connect.mjs)
// whose wallet holds a quantum-safe account key (ML-DSA-44, spec 09,
// section 9). The commit is an account transaction (type 0x52) the wallet
// signs and the app sends with eth_sendRawTransaction; the app never sees a
// seed or an account key, and no elliptic-curve key is used. Summon pays to
// any 20-byte address and needs no wallet.
//
// A Phantom Key lives only in this object's memory: it is never written to
// browser storage, a file, a cookie or a server, and it is dropped as soon
// as the step that needs it is done. The connection is not remembered
// either.

import { concat, fromHex, quantity, toHex, toQuantity } from "./bytes.mjs";
import {
  CONFIRMATIONS,
  MIN_VANISH_FEES,
  SETTLE_DEPTH,
  feeForNextBlock,
  feeStillAccepted,
  formatGhost,
  minVanishFor,
  nextBaseFee,
  parseAddress,
  parseGhost,
  settledHeight,
} from "./chain.mjs";
import { HEADER_FIELDS, NETWORKS, networkOf, readHeader, rlpList, rlpString } from "./header.mjs";
import { DEFAULT_ENDPOINT, SERVER_ERROR, createRpc } from "./rpc.mjs";
import { WalletRejected, WalletSignFailed, isWalletRejection } from "./wallet-connect.mjs";

// The coin commit entry address of the internal network ("ghost" in ASCII,
// then 5; ghost-node params/ghost/privaccounts.go). It stays a setting next
// to the endpoint.
export const DEFAULT_COMMIT_ENTRY = "0x67686f7374000000000000000000000000000005";
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// Leaves (or markers) per page of wallet tree data (spec 05, section 8).
export const PAGE_LEAVES = 4096;
// Leaves of one coin tree (spec 05, section 3): 2^32. A full tree is final
// and the next leaf goes to position 0 of the next tree index. createFlow
// takes another count, and another depth (treeDepth, TREE_DEPTH below), only
// to talk to a node whose trees are smaller, as a recovery test of a
// rollover needs; the release never sets either.
export const LEAVES_PER_TREE = 2 ** 32;
// The coin tree logs of a block's receipts (client/src/receipts.rs, after
// ghost-node docs/private-transactions.md, "Receipts"): the coin tree
// account as address; a commit log has the topic K("ghost/commit-receipt/v1")
// and the tree index (4), position (4), leaf (32), `v` (32), note and the
// commit's salt (16); a reveal log has K("ghost/reveal-receipt/v1")
// and the marker as topics and the tree index, position, remainder (32),
// note, recipient (20) and amount out (32). The scan of a chain whose coin
// tree has rolled over reads them here (checkTreesAgainstReceipts).
const COIN_TREE_ACCOUNT = "0x67686f7374000000000000000000000000000001";
const COMMIT_RECEIPT_TAG = "ghost/commit-receipt/v1";
const REVEAL_RECEIPT_TAG = "ghost/reveal-receipt/v1";
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
// The progress while the connected wallet shows the commit for the user to
// approve; the page's waiting screen reads it.
export const WALLET_APPROVAL = "approve the Vanish in your wallet";
// The JSON-RPC code of a request the wallet does not know: a wallet without
// ghost_newReceiveAddress answers it so.
const METHOD_NOT_FOUND = -32601;
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

// What the page says when the endpoint's coin tree or spent markers do not
// match the block receipts of the page's header chain: a leaf, note, salt or
// marker the receipts do not show, a missing, repeated or reordered page, a
// receipts root that differs, a block whose receipts cannot be fetched, or a
// start the page cannot place in the tree. Uncertain means refused: the scan
// stops before the key is tried on any note, so nothing the endpoint sees
// afterwards depends on the key.
export const RECEIPTS_FAILED = "the endpoint's coin tree or spent markers do not match the block receipts";
const KEY_UNUSED = "so the app takes nothing from it and uses the key for nothing";

function receiptsRefused(detail) {
  return new ChainRefused(`${RECEIPTS_FAILED} (${detail}), ${KEY_UNUSED}`);
}

// The big-endian bytes of an integer, with no leading zero byte.
function intBytes(value) {
  const out = [];
  for (let v = value; v > 0n; v >>= 8n) out.unshift(Number(v & 0xffn));
  return Uint8Array.from(out);
}

// A receipt as eth_getBlockReceipts returns it, in its consensus encoding
// (the one its block's receiptsRoot covers): the type byte for a typed
// receipt, then the RLP of [status, cumulativeGasUsed, logsBloom, logs],
// each log [address, topics, data]. Anything not in that shape is refused;
// whether the bytes are the block's is the receipts root's to say.
export function receiptBytes(receipt) {
  if (!receipt || typeof receipt !== "object") throw new Error("a receipt is not an object");
  const type = quantity(receipt.type);
  if (type > 0x7fn) throw new Error("a receipt's type is out of range");
  const status = quantity(receipt.status);
  if (status > 1n) throw new Error("a receipt's status is not 0 or 1");
  if (!Array.isArray(receipt.logs)) throw new Error("a receipt's logs are not a list");
  const logs = receipt.logs.map((log) => {
    if (!log || !Array.isArray(log.topics)) throw new Error("a log's topics are not a list");
    return rlpList([
      rlpString(fromHex(log.address, 20)),
      rlpList(log.topics.map((topic) => rlpString(fromHex(topic, 32)))),
      rlpString(fromHex(log.data)),
    ]);
  });
  const body = rlpList([
    rlpString(status === 1n ? Uint8Array.of(1) : new Uint8Array(0)),
    rlpString(intBytes(quantity(receipt.cumulativeGasUsed))),
    rlpString(fromHex(receipt.logsBloom, 256)),
    rlpList(logs),
  ]);
  return type === 0n ? body : concat([Uint8Array.of(Number(type)), body]);
}

// That refusal as it arrives over JSON-RPC: code -32000 and the node's
// words. It is told by its shape on the wire, not by the class of the error
// object, so a second copy of rpc.mjs (a bundle, a test) still matches.
export function isHeadMoved(err) {
  return Number(err?.code) === SERVER_ERROR && String(err?.message ?? "").includes(HEAD_MOVED);
}

// The reveal cannot be made yet; the message says what it waits for.
// `from` is the first tip at which it can be. A Summon does not wait for
// that block in particular: every Summon waits the same SETTLE_DEPTH blocks
// first (settleFirst), which covers it.
export class WaitError extends Error {
  constructor(message, { from }) {
    super(message);
    this.from = from;
  }
}

// The plain line for a coin whose block, `height`, is not yet SETTLE_DEPTH
// deep. The wait is about reorganisations, not privacy.
export function settleWait(height) {
  return `the block that holds this coin, block ${height}, is not yet ${SETTLE_DEPTH} blocks deep; the Summon goes on by itself at block ${height + SETTLE_DEPTH}`;
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

// The positions whose typed word does not match the key's, in any case. A
// word must be typed whole: a prefix or a near word is wrong.
export function wrongWords(words, positions, answers) {
  const list = normalWords(words).split(" ");
  return positions.filter((position, i) => String(answers[i] ?? "").trim().toLowerCase() !== list[position - 1]);
}

// Key words as the module reads them: lower case, single spaces.
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
// or nothing left unspent. The current coin is the unspent one appended
// last: in the latest coin tree index (`treeIndex`, 0 when not given), then
// at the highest position in it.
export function keyStatus(found) {
  if (found.length === 0) return { status: "not-found", current: null };
  const unspent = found
    .filter((coin) => !coin.spent)
    .sort((a, b) => (b.treeIndex ?? 0) - (a.treeIndex ?? 0) || b.position - a.position);
  if (unspent.length === 0) return { status: "claimed", current: null };
  return { status: "unclaimed", current: unspent[0] };
}

// Whether two coins restore found are the same coin: the same tree index,
// leaf position, number and amount.
function sameCoin(a, b) {
  return (
    (a.treeIndex ?? 0) === (b.treeIndex ?? 0) && a.position === b.position && a.number === b.number && a.amount === b.amount
  );
}

// Every leaf and note of coin tree `treeIndex` (0 unless given) as of
// `anchor` (a verified header), checked against the anchor's coin root: the
// tree the anchor's header holds. fetchTrees reads the full trees before it.
// `treeDepth` is the tree's levels (TREE_DEPTH, fewer only on a test node).
export async function fetchTree(rpc, prover, anchor, treeIndex = 0, { treeDepth = TREE_DEPTH } = {}) {
  const tree = await readTree(rpc, anchor, treeIndex);
  await checkTree(prover, treeDepth, { pageRoots: tree.pageRoots, leaves: tree.leaves, root: anchor.coinTreeRoot });
  return { count: tree.count, leaves: tree.leaves, records: tree.records, salts: tree.salts };
}

// Coin tree `treeIndex` as of `anchor`, read but not yet checked against a
// root, in the node's shape: the page roots as an array, then every page in
// order as `{ kind, treeIndex, page, filled, entries: [{ leaf, note, salt? }] }`.
// `salt` is the 16-byte salt a commit published beside its leaf; the node
// leaves it out for a reveal's remainder. Every page but the last is full and the last holds 1 to 4,096
// leaves, and each page is the one asked for (its kind, tree index and page
// number), so no page is missing, repeated or out of order. Anything else, a
// salt that is not 16 bytes of hex among it, is refused, never guessed at.
// `salts` holds each leaf's salt or null. The notes and salts are checked
// against the block receipts by the scan (scanKey), not here.
async function readTree(rpc, anchor, treeIndex) {
  const anchorHash = toHex(anchor.hash);
  const index = toQuantity(treeIndex);
  const list = await rpc.call("ghost_getPageRoots", ["coin", index, anchorHash]);
  if (!Array.isArray(list)) throw new Error(`the endpoint's page roots${ofTree(treeIndex)} are not a list`);
  const pageRoots = list.map((root) => fromHex(root, 32));
  const leaves = [];
  const records = [];
  const salts = [];
  for (let p = 0; p < pageRoots.length; p += 1) {
    const which = `page ${p}${ofTree(treeIndex)}`;
    const page = await rpc.call("ghost_getTreePage", ["coin", index, toQuantity(p), anchorHash]);
    const filled = Number(quantity(page?.filled));
    const whole = p === pageRoots.length - 1 ? filled >= 1 && filled <= PAGE_LEAVES : filled === PAGE_LEAVES;
    if (!whole || !Array.isArray(page.entries) || page.entries.length !== filled) {
      throw new Error(`${which} from the endpoint is not a whole page`);
    }
    if (page.kind !== "coin" || !sameQuantity(page.treeIndex, treeIndex) || !sameQuantity(page.page, p)) {
      throw new Error(`${which} from the endpoint is not the page asked for: a page is missing, repeated or out of order`);
    }
    for (const entry of page.entries) {
      const leaf = fromHex(entry?.leaf, 32);
      leaves.push(leaf);
      records.push(leaf, fromHex(entry.note, NOTE_BYTES));
      salts.push(entry.salt === undefined ? null : saltOf(entry.salt, which));
    }
  }
  return { pageRoots: concat(pageRoots), count: leaves.length, leaves: concat(leaves), records: concat(records), salts };
}

// How an error names a tree past tree 0; tree 0 keeps its old words.
function ofTree(treeIndex) {
  return treeIndex === 0 ? "" : ` of coin tree ${treeIndex}`;
}

// Every coin tree as of `anchor` (a verified header), from tree 0 up to the
// anchor's own tree (spec 05, section 3 and section 8, RT-5), in order, each
// `{ treeIndex, root, count, leaves, records, salts }`. A tree holds
// `treeLeaves` leaves at most (LEAVES_PER_TREE). Tree k is read only once
// tree k - 1 is shown full and is not the anchor's tree, so no index past
// the anchor's tree is asked for:
//
// - A tree with fewer leaves than a full one is the anchor's: its page roots
//   and leaves must give the anchor's coin root.
// - A full tree is final. Its root, computed from its leaves and checked
//   against its page roots, is either the anchor's coin root (nothing has
//   gone into the next tree yet, and the read ends) or the tree's final
//   root, which must be the coin root of a header of the page's chain
//   (`headerWithRoot(root)`, true when one carries it) and differ from every
//   earlier tree's; the next tree is read after it.
//
// Anything else, a tree with more leaves than a tree holds, a full tree
// whose final root no header carries, a tree served twice, is refused. The
// roots are of trees of `treeDepth` levels (TREE_DEPTH unless a test node's
// trees are smaller), each holding at most 2^treeDepth leaves.
export async function fetchTrees(rpc, prover, anchor, { headerWithRoot, treeDepth = TREE_DEPTH, treeLeaves = 2 ** treeDepth }) {
  checkDepth(treeDepth);
  if (!(treeLeaves >= 1 && treeLeaves <= 2 ** treeDepth)) throw new Error(`a tree of ${treeDepth} levels cannot hold ${treeLeaves} leaves`);
  const trees = [];
  for (let k = 0; ; k += 1) {
    const tree = await readTree(rpc, anchor, k);
    if (tree.count > treeLeaves) {
      throw new Error(`coin tree ${k} from the endpoint holds ${tree.count} leaves, more than a tree holds (${treeLeaves})`);
    }
    if (tree.count < treeLeaves) {
      await checkTree(prover, treeDepth, { pageRoots: tree.pageRoots, leaves: tree.leaves, root: anchor.coinTreeRoot });
      trees.push({ treeIndex: k, root: anchor.coinTreeRoot, ...tree });
      return trees;
    }
    const [root] = await prefixRootsOf(prover, treeDepth, tree.leaves, tree.count, tree.count);
    await checkTree(prover, treeDepth, { pageRoots: tree.pageRoots, leaves: tree.leaves, root });
    trees.push({ treeIndex: k, root, ...tree });
    if (toHex(root) === toHex(anchor.coinTreeRoot)) return trees;
    if (trees.slice(0, -1).some((earlier) => toHex(earlier.root) === toHex(root))) {
      throw new Error(`coin tree ${k} from the endpoint is a tree it served before`);
    }
    if (!(await headerWithRoot(root))) {
      throw new Error(`coin tree ${k} from the endpoint is full, but no header of the page's chain carries its final root`);
    }
  }
}

// Whether `text` is a hex quantity of value `n`.
function sameQuantity(text, n) {
  return typeof text === "string" && /^0x[0-9a-fA-F]+$/.test(text) && BigInt(text) === BigInt(n);
}

// The `salt` of an entry of a page (`which`, as an error names it): 16 bytes
// of hex, or the page is refused as malformed.
function saltOf(hex, which) {
  try {
    return fromHex(hex, SALT_BYTES);
  } catch {
    throw new Error(`${which} from the endpoint is malformed: a salt is not ${SALT_BYTES} bytes`);
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
// (tree_state.rs, through the worker) picks it, that is if S is at or above
// the coin's block, so S's tree holds the coin. No other commit is waited
// for: the plan says how many coins S's tree covers (`covers`), shown as
// information only. It sends no request: the scan fetched everything it
// reads.
//
// When the coin's block is not yet SETTLE_DEPTH deep, it throws a WaitError
// with the plain line settleWait and `from`, the tip at which it will be.
//
// A coin in a full earlier coin tree (its `treeIndex` below the tip's tree
// in `scan.trees`) is proven against that tree's final root, which every
// leaf of the tree shares and a header of the page's chain carries (spec 05,
// section 5, item 5, and section 13, item 4): no later root of the next tree
// holds it, and no wait applies. The rule is still asked once, as for a key
// with no coin (askRuleForDecoy), so the worker's work does not depend on the
// coin's tree.
export async function planReveal(prover, scan, coin, progress = () => {}) {
  const { chain, rootHeaders: headers, rootCounts: counts, settledAt } = scan;
  const trees = scan.trees ?? [scan.tree];
  const treeIndex = coin.treeIndex ?? 0;
  if (treeIndex < trees.length - 1) {
    progress("choosing the tree state");
    await askRuleForDecoy(prover, scan);
    const full = trees[treeIndex];
    return {
      root: full.root,
      leaves: full.leaves,
      fee: scan.fee,
      domain: chain.genesis.hash,
      height: full.finalHeight,
      covers: full.count,
    };
  }
  if (settledAt === null) {
    throw new WaitError(`no block is ${SETTLE_DEPTH} blocks deep yet; the Summon goes on by itself at block ${SETTLE_DEPTH}`, {
      from: SETTLE_DEPTH,
    });
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
  if (!chosen) throw new WaitError(settleWait(leaf.height), { from: leaf.height + SETTLE_DEPTH });
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

// Data bytes of a commit log (tree index, position, leaf, `v`, note, salt)
// and of a reveal log (tree index, position, remainder, note, recipient,
// out).
const COMMIT_LOG_BYTES = 4 + 4 + 32 + 32 + NOTE_BYTES + SALT_BYTES;
const REVEAL_LOG_BYTES = 4 + 4 + 32 + NOTE_BYTES + 20 + 32;

// The coin tree logs of a block's receipts (eth_getBlockReceipts, each
// receipt already put through receiptBytes), in receipt and log order: the
// same address, topics and data the bytes the receipts root covers are made
// of, with whether the log's receipt succeeded.
function coinLogsOf(list) {
  const logs = [];
  for (const receipt of list) {
    const succeeded = quantity(receipt.status) === 1n;
    for (const log of receipt.logs) {
      if (toHex(fromHex(log.address, 20)) !== COIN_TREE_ACCOUNT) continue;
      logs.push({ succeeded, topics: log.topics.map((topic) => fromHex(topic, 32)), data: fromHex(log.data) });
    }
  }
  return logs;
}

// The leaf a coin tree log appended, `{ treeIndex, position, leaf, note,
// salt, marker, v }` (`salt` null but for a commit, `marker` null but for a
// reveal, `v` the committed amount of a commit, null for a
// reveal), read exactly as client/src/receipts.rs reads it. `topics`
// are the hex first topics of a commit and a reveal log. A log that is not
// exactly a commit or a reveal log is refused.
export function coinRecord(log, topics) {
  if (!log.succeeded) throw new Error("a failed receipt has a coin tree log");
  const { data } = log;
  const first = log.topics.length > 0 ? toHex(log.topics[0]) : null;
  const head = () => {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    return { treeIndex: view.getUint32(0), position: view.getUint32(4), leaf: data.slice(8, 40) };
  };
  if (first === topics.commit) {
    if (log.topics.length !== 1) throw new Error("a commit log does not have exactly one topic");
    if (data.length !== COMMIT_LOG_BYTES) throw new Error("a commit log's data is not its length");
    const salt = data.slice(COMMIT_LOG_BYTES - SALT_BYTES);
    const v = BigInt(toHex(data.slice(40, 72)));
    return { ...head(), note: data.slice(72, 72 + NOTE_BYTES), salt, marker: null, v };
  }
  if (first === topics.reveal) {
    if (log.topics.length !== 2) throw new Error("a reveal log does not have exactly two topics");
    if (data.length !== REVEAL_LOG_BYTES) throw new Error("a reveal log's data is not its length");
    return { ...head(), note: data.slice(40, 40 + NOTE_BYTES), salt: null, marker: log.topics[1], v: null };
  }
  throw new Error("a coin tree log's first topic is neither a commit nor a reveal");
}

// Checks every coin tree of a scan whose tree has rolled over (`trees`, as
// fetchTrees reads them, tree k at index k) and its spent markers against the
// coin tree records of the receipts of the page's chain from its start to the
// tip (`blockRecords`, one list per block in chain order, coinRecord), as the
// worker's receiptsCheck does for coin tree 0 (client/src/receipts.rs), with
// a tree of `treeLeaves` leaves:
//
// - every record appends right after the one before: the next position in
//   the same tree, or position 0 of the next tree once a tree holds
//   `treeLeaves`;
// - from `start` (`{ treeIndex, count }`, where the first block's coin root
//   is) on, the leaves, notes and salts of each tree are exactly those the
//   records appended to it, none missing, repeated, reordered or invented,
//   and no record is of a tree past those read. The leaves before `start`
//   no receipt of the chain covers, as for tree 0 from a pinned start;
// - the markers are exactly those of the reveal records of the first
//   `markerBlocks` blocks, in order: the whole list when the chain starts at
//   genesis (`fromGenesis`), its last ones otherwise.
//
// Any difference throws, naming the tree and position.
export function checkTreesAgainstReceipts({ trees, blockRecords, start, treeLeaves, markerBlocks, fromGenesis, markers }) {
  const records = blockRecords.flat();
  let last = null;
  for (const record of records) {
    const { treeIndex, position } = record;
    const next = last && (last.position + 1 < treeLeaves ? [last.treeIndex, last.position + 1] : [last.treeIndex + 1, 0]);
    if (position >= treeLeaves || (next && (next[0] !== treeIndex || next[1] !== position))) {
      throw new Error(`the record of coin tree ${treeIndex}, position ${position} is out of sequence`);
    }
    last = record;
  }
  const expected = trees.map((tree) => (tree.treeIndex === start.treeIndex ? start.count : 0));
  for (const { treeIndex, position, leaf, note, salt } of records) {
    if (treeIndex < start.treeIndex || (treeIndex === start.treeIndex && position < start.count)) continue;
    const where = `position ${position} of coin tree ${treeIndex}`;
    const tree = trees[treeIndex];
    if (!tree) throw new Error(`the receipts hold the leaf at ${where}, a tree past those read`);
    if (position !== expected[treeIndex]) {
      throw new Error(`the receipts hold ${where} where the tree holds position ${expected[treeIndex]}`);
    }
    if (position >= tree.count) throw new Error(`the leaf at ${where} is missing`);
    const at = position * (32 + NOTE_BYTES);
    if (toHex(tree.records.slice(at, at + 32)) !== toHex(leaf)) throw new Error(`the leaf at ${where} differs from its receipt`);
    if (toHex(tree.records.slice(at + 32, at + 32 + NOTE_BYTES)) !== toHex(note)) {
      throw new Error(`the note at ${where} differs from its receipt`);
    }
    const beside = tree.salts[position];
    if ((beside === null) !== (salt === null) || (salt !== null && toHex(beside) !== toHex(salt))) {
      throw new Error(`the salt at ${where} differs from its receipt`);
    }
    expected[treeIndex] += 1;
  }
  for (const tree of trees) {
    if (tree.treeIndex < start.treeIndex || expected[tree.treeIndex] === tree.count) continue;
    throw new Error(`the leaf at position ${expected[tree.treeIndex]} of coin tree ${tree.treeIndex} is not in the receipts`);
  }
  const held = blockRecords
    .slice(0, markerBlocks)
    .flat()
    .filter((record) => record.marker)
    .map((record) => toHex(record.marker));
  const listed = [];
  for (let i = 0; i < markers.length; i += 32) listed.push(toHex(markers.slice(i, i + 32)));
  if (!fromGenesis && listed.length < held.length) throw new Error(`spent marker ${listed.length} is missing`);
  const compared = fromGenesis ? listed : listed.slice(listed.length - held.length);
  const offset = listed.length - compared.length;
  for (let i = 0; i < compared.length; i += 1) {
    if (i >= held.length) throw new Error(`spent marker ${offset + i} is not in the receipts`);
    if (compared[i] !== held[i]) throw new Error(`spent marker ${offset + i} differs from its receipt`);
  }
  if (held.length > compared.length) throw new Error(`spent marker ${listed.length} is missing`);
}

// --- Coin trees of fewer levels, for a test node ---
//
// The release's coin tree has 32 levels (proofs/src/hash.rs, TREE_DEPTH),
// and the worker hashes only that depth. A test node whose trees are smaller
// so that a rollover is reachable (spec 05, RT-1 Part B: 14 levels, 16,384
// leaves) carries roots of its own depth in its headers, so for any other
// depth the page checks trees and computes prefix roots itself, with the
// same hash: an inner node at `level` is K("ghost/coin-tree-node/v1", level,
// left, right) and an empty leaf K("ghost/empty-leaf/v1"), K being
// Keccak-256 over the tag's length byte, the tag and the parts. A page is
// the subtree of height 12 under each page root whatever the depth, so a
// depth below 12 is refused.
export const TREE_DEPTH = 32;
const PAGE_LEVELS = 12;
// The worker proves a coin only against the root of a tree of TREE_DEPTH
// levels (lib.rs, ghost_prove), which no header of a test node of smaller
// trees carries, so a reveal there is refused before it is proved, as any
// reveal that cannot be made: nothing is proved.
//
// TEST_DEPTH_REVEAL: the one exception is a module built with the
// test-tree-depth feature, for the tests and scripts/recovery-blackout.sh
// only. Its worker answers `testDepthProver` with the depth it builds reveals
// for (14), and for a coin of a tree of that depth the flow asks it for
// `proveTestDepth`: the same reveal, with the stub proof the test node's
// verifier takes (spec 05, RT-8 Part B) in place of a STARK. The module the
// page ships has no such reveal, so there the refusal stands. A flow of
// TREE_DEPTH never asks for either.
export const SMALL_TREE_REVEAL =
  "this build proves a coin only against a coin tree of 32 levels; a test node of smaller trees needs a prover of that depth " +
  "(spec 05, RT-8 Part B)";

// Keccak-256 with the original padding (0x01 ... 0x80), over 64-bit lanes
// held as two 32-bit halves (low, high).
const KECCAK_ROUNDS = [
  "0x0000000000000001", "0x0000000000008082", "0x800000000000808a", "0x8000000080008000",
  "0x000000000000808b", "0x0000000080000001", "0x8000000080008081", "0x8000000000008009",
  "0x000000000000008a", "0x0000000000000088", "0x0000000080008009", "0x000000008000000a",
  "0x000000008000808b", "0x800000000000008b", "0x8000000000008089", "0x8000000000008003",
  "0x8000000000008002", "0x8000000000000080", "0x000000000000800a", "0x800000008000000a",
  "0x8000000080008081", "0x8000000000008080", "0x0000000080000001", "0x8000000080008008",
].map((hex) => [Number(BigInt(hex) & 0xffffffffn), Number(BigInt(hex) >> 32n)]);
// The rotation of lane x + 5y.
const KECCAK_ROTATIONS = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const KECCAK_RATE = 136;

function keccakF(s) {
  const c = new Uint32Array(10);
  const b = new Uint32Array(50);
  for (const [roundLow, roundHigh] of KECCAK_ROUNDS) {
    for (let x = 0; x < 5; x += 1) {
      c[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
      c[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
    }
    for (let x = 0; x < 5; x += 1) {
      const l = (x + 4) % 5;
      const r = (x + 1) % 5;
      const low = c[2 * l] ^ ((c[2 * r] << 1) | (c[2 * r + 1] >>> 31));
      const high = c[2 * l + 1] ^ ((c[2 * r + 1] << 1) | (c[2 * r] >>> 31));
      for (let y = 0; y < 25; y += 5) {
        s[2 * (x + y)] ^= low;
        s[2 * (x + y) + 1] ^= high;
      }
    }
    // B[y][2x + 3y] is A[x][y] rotated.
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const i = x + 5 * y;
        const j = y + 5 * ((2 * x + 3 * y) % 5);
        const n = KECCAK_ROTATIONS[i];
        let low = s[2 * i];
        let high = s[2 * i + 1];
        if (n >= 32) [low, high] = [high, low];
        const m = n % 32;
        b[2 * j] = m === 0 ? low : (low << m) | (high >>> (32 - m));
        b[2 * j + 1] = m === 0 ? high : (high << m) | (low >>> (32 - m));
      }
    }
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x += 1) {
        const i = x + y;
        const i1 = ((x + 1) % 5) + y;
        const i2 = ((x + 2) % 5) + y;
        s[2 * i] = b[2 * i] ^ (~b[2 * i1] & b[2 * i2]);
        s[2 * i + 1] = b[2 * i + 1] ^ (~b[2 * i1 + 1] & b[2 * i2 + 1]);
      }
    }
    s[0] ^= roundLow;
    s[1] ^= roundHigh;
  }
}

export function keccak256(msg) {
  const padded = new Uint8Array((Math.floor(msg.length / KECCAK_RATE) + 1) * KECCAK_RATE);
  padded.set(msg);
  padded[msg.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const view = new DataView(padded.buffer);
  const s = new Uint32Array(50);
  for (let at = 0; at < padded.length; at += KECCAK_RATE) {
    for (let i = 0; i < KECCAK_RATE / 4; i += 1) s[i] ^= view.getUint32(at + 4 * i, true);
    keccakF(s);
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i += 1) outView.setUint32(4 * i, s[i], true);
  return out;
}

const tagBytes = (tag) => concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)]);
const NODE_TAG = tagBytes("ghost/coin-tree-node/v1");
const treeNode = (level, left, right) => keccak256(concat([NODE_TAG, Uint8Array.of(level), left, right]));

// Z_0 to Z_depth: the empty subtree of each height.
const zerosCache = new Map();
function zerosOf(depth) {
  if (!zerosCache.has(depth)) {
    const z = [keccak256(tagBytes("ghost/empty-leaf/v1"))];
    for (let level = 0; level < depth; level += 1) z.push(treeNode(level, z[level], z[level]));
    zerosCache.set(depth, z);
  }
  return zerosCache.get(depth);
}

// The nodes of height `to` above `nodes` of height `from`, filled to the
// right with empty subtrees.
function climb(nodes, from, to, z) {
  let list = nodes;
  for (let level = from; level < to; level += 1) {
    const next = [];
    for (let i = 0; i < list.length; i += 2) next.push(treeNode(level, list[i], list[i + 1] ?? z[level]));
    list = next;
  }
  return list;
}

const split32 = (bytes) => Array.from({ length: bytes.length / 32 }, (_, i) => bytes.slice(32 * i, 32 * i + 32));

function checkDepth(depth) {
  if (!Number.isInteger(depth) || depth < PAGE_LEVELS || depth > TREE_DEPTH) {
    throw new Error(`a coin tree of ${depth} levels is not supported: from ${PAGE_LEVELS} to ${TREE_DEPTH}`);
  }
}

// The root of a coin tree of `depth` levels holding exactly `leaves`
// (32 bytes each, concatenated) from position 0, and its page roots.
export function treeRootsAt(depth, leaves) {
  checkDepth(depth);
  const z = zerosOf(depth);
  const pageRoots = climb(split32(leaves), 0, PAGE_LEVELS, z);
  return { root: climb(pageRoots, PAGE_LEVELS, depth, z)[0] ?? z[depth], pageRoots };
}

// The worker's tree check (lib.rs, ghost_tree_check) for a tree of `depth`
// levels, in its words: the page roots must be those of the leaves, and
// give `root`.
export function treeCheckAt(depth, { pageRoots, leaves, root }) {
  checkDepth(depth);
  const z = zerosOf(depth);
  const listed = split32(pageRoots);
  const count = leaves.length / 32;
  if (Math.ceil(count / PAGE_LEAVES) !== listed.length) {
    throw new Error(`${count} leaves do not fill the ${listed.length} pages of the page-root list`);
  }
  const computed = climb(split32(leaves), 0, PAGE_LEVELS, z);
  const page = computed.findIndex((r, i) => toHex(r) !== toHex(listed[i]));
  if (page !== -1) throw new Error(`page ${page} does not match its page root`);
  const top = climb(listed, PAGE_LEVELS, depth, z)[0] ?? z[depth];
  if (toHex(top) !== toHex(root)) throw new Error("the page-root list does not give the header's coin root");
}

// The roots of a tree of `depth` levels after each number of leaves from
// `from` to `to` (lib.rs, prefix_roots), with an incremental frontier. A
// tree that holds 2^depth leaves keeps its root at level `depth`.
export function prefixRootsAt(depth, leaves, from, to) {
  checkDepth(depth);
  if (from > to || to > leaves.length / 32 || to > 2 ** depth) throw new Error("the prefix range is outside the leaves");
  const z = zerosOf(depth);
  const branch = new Array(depth + 1);
  const roots = [];
  for (let count = 0; count <= to; count += 1) {
    if (count >= from) {
      let node = z[0];
      if (count === 2 ** depth) node = branch[depth];
      else {
        for (let level = 0, size = count; level < depth; level += 1, size = Math.floor(size / 2)) {
          node = size % 2 === 1 ? treeNode(level, branch[level], node) : treeNode(level, node, z[level]);
        }
      }
      roots.push(node);
    }
    if (count === to) break;
    let node = leaves.slice(32 * count, 32 * count + 32);
    for (let level = 0, size = count + 1; level <= depth; level += 1, size = Math.floor(size / 2)) {
      if (size % 2 === 1 || level === depth) {
        branch[level] = node;
        break;
      }
      node = treeNode(level, branch[level], node);
    }
  }
  return roots;
}

// The tree check and the prefix roots of a tree of `depth` levels: the
// worker's for the release's 32, the page's own for a test node's.
async function checkTree(prover, depth, args) {
  if (depth === TREE_DEPTH) await prover.request("treeCheck", args);
  else treeCheckAt(depth, args);
}

async function prefixRootsOf(prover, depth, leaves, from, to) {
  if (depth === TREE_DEPTH) return (await prover.request("prefixRoots", { leaves, from, to })).roots;
  return prefixRootsAt(depth, leaves, from, to);
}

// A block header as the endpoint's JSON gives it (or as the page saved it):
// its fields, its 18-field RLP (spec 05, section 10), the hash it claims,
// and its record, the fields of HEADER_FIELDS and the hash only, which is
// all the page saves of a header. Throws on a missing or malformed field.
function parseHeader(raw) {
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
  const record = { hash: toHex(header.hash) };
  for (const [name] of HEADER_FIELDS) record[name] = String(raw[name]);
  return { header, rlp, record };
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
  // Where the headers this page checked are kept between sessions
  // (header-store.mjs, IndexedDB in the page): { load(key), save(key,
  // entries), clear(key) }, async, or null for none. Public header fields
  // only; a store that fails or holds a header that does not re-link only
  // costs the full check.
  headerStore = null,
  // Levels of a coin tree (TREE_DEPTH; fewer only for a test node, whose
  // headers carry roots of that depth) and the leaves one holds
  // (LEAVES_PER_TREE, 2^treeDepth; fewer only for a test node).
  treeDepth = TREE_DEPTH,
  treeLeaves = 2 ** treeDepth,
  onChange = () => {},
} = {}) {
  checkDepth(treeDepth);
  if (!(treeLeaves >= 1 && treeLeaves <= 2 ** treeDepth)) throw new Error(`a tree of ${treeDepth} levels cannot hold ${treeLeaves} leaves`);
  let rpc = createRpc(endpoint, { fetch });
  // The connected wallet's connector, never in `state`.
  let connector = null;
  // The page's header chain, held in the worker: the network it is of, the
  // endpoint it was last read from, its start height, every header the
  // worker adopted, by hash, and the hashes of the blocks whose receipts the
  // worker checked and keeps. One per page session; another network starts
  // it again.
  let headerChain = null;
  // The records of the transactions this page sent that a block held: its
  // Vanish commits, reveals and claims, each kept up to date by its recheck
  // (a reorganisation can make one dropped). settleFirst waits on them.
  const ownSent = [];
  const state = {
    endpoint: rpc.url,
    commitEntry,
    // Why the endpoint's chain is refused, while it is: no confirmation is
    // shown from it.
    chainRefused: null,
    // The connected wallet: null, or { id, name, address, balance }.
    wallet: null,
    // The addresses this page sent a Vanish commit from in this session,
    // lower case: a Summon paid to one of them puts the same address on both
    // sides. Kept in memory only.
    vanishedFrom: [],
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
  // `number` "latest" is the endpoint's tip, whatever its number.
  async function fetchHeader(number) {
    const latest = number === "latest";
    const raw = await rpc.call("eth_getBlockByNumber", [latest ? "latest" : toQuantity(number), false]);
    if (!raw) throw new Error(`the endpoint has no block ${number}`);
    const { header, rlp, record } = parseHeader(raw);
    if (!latest && header.number !== number) throw new Error(`the endpoint returned block ${header.number} for ${number}`);
    return { header, rlp, record };
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
    const startChain = async () => {
      let started;
      try {
        started = await prover.request("chainStart", { params: network.params, start });
      } catch (err) {
        throw powFailed(err.message);
      }
      if (toHex(started.startHash) !== startHash) throw notTheHash(height);
      return {
        chainId,
        network,
        endpoint: rpc.url,
        startHeight: height,
        known: new Map([[startHash, { ...header, rlpHex: toHex(rlp) }]]),
        receipts: new Set(),
        // The coin tree logs of those blocks' receipts, by block hash
        // (coinLogsOf), read when a scan's coin tree has rolled over.
        coinLogs: new Map(),
        // The page's header store: its entry for this chain and start, the
        // record of each header adopted (what a save writes), and the hash
        // the store holds at each height.
        storeKey: `${chainId}:${startHash}`,
        records: new Map(),
        saved: new Map(),
      };
    };
    let hc = await startChain();
    if (headerStore && !(await loadSaved(hc))) {
      // The entry is dropped and the chain started again: the headers are
      // then all checked from the start, seals included.
      try {
        await headerStore.clear(hc.storeKey);
      } catch {
        // Storage that fails is storage the page does without.
      }
      hc = await startChain();
    }
    headerChain = hc;
    return headerChain;
  }

  // The headers this page saved of `hc`'s chain and start in an earlier
  // session, added to the worker's chain with every check but the seal
  // (lib.rs, ghost_chain_add_saved): they must run from the height after
  // the start, one per height, each the parent of the next, from the start's
  // hash, and pass every other check of ghost_chain_add again, the
  // difficulty and so the total work included. True when there are none or
  // all are adopted; false when the store fails or any is refused, and the
  // caller discards the entry. The headers above the saved tip are then
  // read and checked in full by syncTip.
  async function loadSaved(hc) {
    let entries;
    try {
      entries = await headerStore.load(hc.storeKey);
    } catch {
      return false;
    }
    if (entries == null) return true;
    if (!Array.isArray(entries)) return false;
    const read = [];
    try {
      for (const [i, entry] of entries.entries()) {
        const parsed = parseHeader(entry);
        if (parsed.header.number !== hc.startHeight + 1 + i) return false;
        read.push(parsed);
      }
    } catch {
      return false;
    }
    for (let i = 0; i < read.length; i += CHAIN_BATCH) {
      const part = read.slice(i, i + CHAIN_BATCH);
      let added;
      try {
        added = await prover.request("chainAddSaved", {
          now: clock(),
          headers: part.map(({ header, rlp }) => ({ hash: header.hash, rlp })),
        });
      } catch {
        return false;
      }
      if (added.refused || added.adopted !== part.length) return false;
      for (const { header, rlp, record } of part) {
        hc.known.set(record.hash, { ...header, rlpHex: toHex(rlp) });
        hc.records.set(record.hash, record);
        hc.saved.set(header.number, record.hash);
      }
    }
    return true;
  }

  // Saves the headers of the page's best chain, up to its tip `best`, that
  // the store does not hold at their height yet: those newly adopted, and
  // after a reorganisation every height that changed. The store drops what
  // it held above the last one. A failed save is ignored: the next one
  // writes from the last height it holds.
  async function saveAdopted(hc, best) {
    if (!headerStore) return;
    const newer = [];
    for (let id = toHex(best.hash); ; ) {
      const held = hc.known.get(id);
      if (!held || held.number <= hc.startHeight || hc.saved.get(held.number) === id) break;
      const record = hc.records.get(id);
      if (!record) return;
      newer.unshift({ number: held.number, record });
      id = toHex(held.parentHash);
    }
    if (newer.length === 0) return;
    try {
      await headerStore.save(hc.storeKey, newer.map(({ record }) => record));
    } catch {
      return;
    }
    const top = newer.at(-1).number;
    for (const number of hc.saved.keys()) if (number > top) hc.saved.delete(number);
    for (const { number, record } of newer) hc.saved.set(number, record.hash);
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
  // Headers saved by an earlier session (loadSaved) are held already, so
  // only those above the saved tip are read and sealed-checked; the newly
  // adopted ones are saved after (saveAdopted).
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
      for (const { header, rlp, record } of part.slice(0, added.adopted)) {
        hc.known.set(record.hash, { ...header, rlpHex: toHex(rlp) });
        hc.records.set(record.hash, record);
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
    await saveAdopted(hc, view.best);
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

  // Every coin tree as of `tip` (a header syncTip adopted), from tree 0 to
  // the tip's (fetchTrees). A full earlier tree's final root must be the
  // coin root of a header of the page's best chain from its start to the
  // tip. Only a chain whose tree has rolled over asks for those headers.
  // Each full earlier tree carries `finalHeight`, the first block of that
  // chain whose header carries its final root (null for the tip's tree).
  async function readTrees(tip) {
    const finalAt = new Map();
    const headerWithRoot = async (root) => {
      const blocks = await chainRange(headerChain.startHeight, tip.number);
      const block = blocks.find((b) => b && toHex(b.coinTreeRoot) === toHex(root));
      if (block) finalAt.set(toHex(root), block.number);
      return Boolean(block);
    };
    const trees = await fetchTrees(rpc, prover, tip, { headerWithRoot, treeDepth, treeLeaves });
    for (const tree of trees) tree.finalHeight = tree === trees.at(-1) ? null : finalAt.get(toHex(tree.root));
    return trees;
  }

  // The hex first topics of a commit and a reveal log, K(tag) of their tags
  // (client/src/hash.rs: Keccak-256 of the tag's length byte and the tag),
  // asked of the worker once per page session.
  let logTopics = null;
  // The same topics hashed in the page (commitAmounts).
  let logTopicsHere = null;
  const tagBytes = (tag) => concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)]);
  async function coinLogTopics() {
    const topic = async (tag) => toHex((await prover.request("keccak256", { bytes: tagBytes(tag) })).hash);
    logTopics ??= { commit: await topic(COMMIT_RECEIPT_TAG), reveal: await topic(REVEAL_RECEIPT_TAG) };
    return logTopics;
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
    return { hc, chainId, settled, low, headers, at, tip, genesis };
  }

  // Every spent coin marker as of `anchor`, in whole marker pages. No header
  // root covers them (spec 05, section 8), so the scan checks them against
  // the reveal receipts of the blocks up to `anchor` before they are used.
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

  // Checks a scan's tree and markers against the block receipts (spec 05,
  // section 8, item 5 and "Marker status"). The blocks are those of the
  // page's header chain from its start (genesis, or the pinned header) to
  // the tip, each the parent of the next. The receipts of each block the
  // worker does not hold yet are asked for by its hash, one block after
  // another in chain order, whatever the key; a block's receipts are fixed by
  // its header's receiptsRoot, so each block is asked for once per page
  // session and a later scan asks only for the blocks added since. The
  // worker checks each block's receipts against the receiptsRoot of the
  // header the page's chain holds for that hash, then the leaves, notes and
  // salts from the start's leaf count (placed by its coin root among the
  // prefix roots of the leaves, 0 at genesis) to the tip against the leaves
  // and notes the receipts appended, and the markers against the reveal
  // receipts of the blocks up to the block they were read at. Any mismatch
  // is refused.
  //
  // `trees` are the scan's coin trees (readTrees) and `placeOf` gives the
  // tree index and leaf count of each of their prefix roots. The worker's
  // check covers coin tree 0 alone and rolls over only at 2^32 leaves, so
  // once the tree has rolled over the same checks are made here, over every
  // tree, from the coin tree logs of the receipts the worker has just checked
  // against their receiptsRoot (checkTreesAgainstReceipts).
  //
  // Returns how many commits of each amount those checked receipts hold
  // (commitAmounts), which a Summon's amount warning reads.
  async function checkReceipts(chain, trees, spent, placeOf, markerAnchor) {
    const { hc, tip } = chain;
    progress("checking the coin tree against the block receipts");
    const blocks = await chainRange(hc.startHeight, tip.number, hc);
    if (blocks.length === 0 || blocks.some((block) => !block)) {
      throw receiptsRefused("the page's chain does not hold every block from its start to the tip");
    }
    for (let i = 1; i < blocks.length; i += 1) {
      if (toHex(blocks[i].parentHash) !== toHex(blocks[i - 1].hash)) {
        throw receiptsRefused(`block ${hc.startHeight + i} of the page's chain does not follow the one before`);
      }
    }
    if (toHex(blocks.at(-1).hash) !== toHex(tip.hash)) throw receiptsRefused("the page's chain does not end at the tip read");
    const start = placeOf.get(toHex(blocks[0].coinTreeRoot));
    if (start === undefined) {
      throw receiptsRefused(`the start of the page's chain, block ${hc.startHeight}, cannot be placed in the endpoint's coin tree`);
    }
    const missing = blocks.filter((block) => !hc.receipts.has(toHex(block.hash)));
    for (let i = 0; i < missing.length; i += CHAIN_BATCH) {
      const part = missing.slice(i, i + CHAIN_BATCH);
      const fetched = [];
      const logs = [];
      for (const block of part) {
        let list;
        try {
          list = await rpc.call("eth_getBlockReceipts", [toHex(block.hash)]);
        } catch (err) {
          throw receiptsRefused(`the endpoint did not return the receipts of block ${block.number}: ${err.message}`);
        }
        if (!Array.isArray(list)) throw receiptsRefused(`the endpoint did not return the receipts of block ${block.number}`);
        let receipts;
        try {
          receipts = list.map(receiptBytes);
        } catch (err) {
          throw receiptsRefused(`a receipt of block ${block.number} is malformed: ${err.message}`);
        }
        fetched.push({ header: fromHex(block.rlpHex), receipts });
        logs.push(coinLogsOf(list));
      }
      try {
        await prover.request("receiptsAdd", { blocks: fetched });
      } catch (err) {
        throw receiptsRefused(err.message);
      }
      part.forEach((block, j) => {
        hc.receipts.add(toHex(block.hash));
        hc.coinLogs.set(toHex(block.hash), logs[j]);
      });
    }
    const markerBlocks = markerAnchor.number - hc.startHeight + 1;
    if (markerBlocks < 1) throw receiptsRefused(`the markers were read at block ${markerAnchor.number}, below the chain's start`);
    const fromGenesis = hc.startHeight === 0;
    if (trees.length === 1) {
      const [tree] = trees;
      try {
        await prover.request("receiptsCheck", {
          hashes: blocks.map((block) => block.hash),
          fromGenesis,
          start: start.count,
          records: tree.records.slice(start.count * (32 + NOTE_BYTES)),
          salts: tree.salts.slice(start.count),
          markerBlocks,
          markers: spent,
        });
      } catch (err) {
        throw receiptsRefused(err.message);
      }
      return commitAmounts(hc, blocks);
    }
    const topics = await coinLogTopics();
    try {
      const blockRecords = blocks.map((block) => hc.coinLogs.get(toHex(block.hash)).map((log) => coinRecord(log, topics)));
      checkTreesAgainstReceipts({ trees, blockRecords, start, treeLeaves, markerBlocks, fromGenesis, markers: spent });
    } catch (err) {
      throw receiptsRefused(err.message);
    }
    return commitAmounts(hc, blocks);
  }

  // How many commits of each amount `v` the coin tree logs of `blocks`' receipts
  // hold, as a Map from `v` to its count. The receipts are those checkReceipts
  // has just checked against each block's receiptsRoot, so this asks nothing
  // of the endpoint or the worker: the topics are hashed here (keccak256).
  function commitAmounts(hc, blocks) {
    logTopicsHere ??= { commit: toHex(keccak256(tagBytes(COMMIT_RECEIPT_TAG))), reveal: toHex(keccak256(tagBytes(REVEAL_RECEIPT_TAG))) };
    const counts = new Map();
    try {
      for (const block of blocks) {
        for (const log of hc.coinLogs.get(toHex(block.hash))) {
          const { v } = coinRecord(log, logTopicsHere);
          if (v !== null) counts.set(v, (counts.get(v) ?? 0) + 1);
        }
      }
    } catch (err) {
      throw receiptsRefused(err.message);
    }
    return counts;
  }

  // Everything the endpoint is asked for a key is asked before the key is
  // tried on a note: the headers, the tree, the markers and the block
  // receipts, all fixed by the tip and by what the page already holds, never
  // by the key. The page roots and leaves are checked against the tip's coin
  // root; no header root covers the notes, salts and markers, so the leaves,
  // notes and salts from the chain's start on, and the markers, are checked
  // against the block receipts (checkReceipts). An endpoint that altered,
  // dropped, reordered, hid or invented any of them is refused there, before
  // restore, so nothing it sees depends on the key; on every path after
  // restore, found or not, the requests are the same too.
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
  //
  // Every coin tree index up to the tip's is read and checked against its
  // root (readTrees), and every tree's leaves, notes and salts against the
  // receipts. A header's coin root is placed by the roots of every prefix of
  // every tree: the tree index and leaf count it is of. `tree` is the tip's
  // tree, and `rootCounts` each header's leaf count in it (0 for a header of
  // an earlier tree), so a coin of the tip's tree is planned as before; a
  // coin of a full earlier tree is proven against that tree's final root
  // (planReveal). The settled leaves are those of the settled block's tree
  // up to its count. The key is tried on every tree's notes, one restore per
  // tree, and each coin found carries its `treeIndex`.
  async function scanKey(key) {
    const chain = await readChain();
    progress("reading the coin tree");
    const trees = await readTrees(chain.tip);
    const tree = trees.at(-1);
    const markerAnchor = chain.at(Math.max(0, chain.tip.number - (CONFIRMATIONS - 1)));
    const spent = await fetchSpent(markerAnchor);
    const fee = (await feeForNextBlock(chain.tip, async (n) => chain.at(n))).fee;
    let prefixRoots = null;
    const placeOf = new Map();
    for (const t of trees) {
      const roots = await prefixRootsOf(prover, treeDepth, t.leaves, 0, t.count);
      roots.forEach((root, count) => {
        // The empty root is tree 0's before its first leaf: no header
        // carries a later tree with no leaf.
        if ((count > 0 || t.treeIndex === 0) && !placeOf.has(toHex(root))) placeOf.set(toHex(root), { treeIndex: t.treeIndex, count });
      });
      prefixRoots = roots;
    }
    const rootHeaders = chain.headers;
    const places = rootHeaders.map((header) => {
      const place = placeOf.get(toHex(header.coinTreeRoot));
      if (place === undefined) throw new Error(`the endpoint's tree does not match the header of block ${header.number}`);
      return place;
    });
    const rootCounts = places.map((place) => (place.treeIndex === tree.treeIndex ? place.count : 0));
    const commitsByAmount = await checkReceipts(chain, trees, spent, placeOf, markerAnchor);
    const settledAt = chain.settled === null ? null : chain.settled - chain.low;
    const settledPlace = settledAt === null ? null : places[settledAt];
    const settledLeaves = settledPlace === null ? tree.leaves : trees[settledPlace.treeIndex].leaves.slice(0, settledPlace.count * 32);
    progress("looking for the key's coins");
    const found = [];
    for (const t of trees) {
      const restored = await prover.request("restore", {
        chainId: chain.chainId,
        key,
        records: t.records,
        salts: t.salts,
        markers: spent,
        treeIndex: t.treeIndex,
      });
      found.push(...restored.found);
    }
    return { chain, trees, tree, rootHeaders, rootCounts, prefixRoots, settledAt, settledLeaves, fee, found, commitsByAmount };
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

  // The page's tip once it reaches block `needed`, from `top`, the tip last
  // read: one poll every `pollMs`, `maxPolls` at most, showing `stage`
  // meanwhile.
  async function untilBlock(needed, top, stage = `waiting for block ${needed}`) {
    for (let i = 0; top < needed; i += 1) {
      if (i >= maxPolls) throw new Error(`the chain has not reached block ${needed} yet; refresh later`);
      progress(stage);
      await sleep(pollMs);
      top = await blockNumber();
    }
    return top;
  }

  // Before a Summon is scanned and proved: the tip once, then a poll every
  // `pollMs` until the newest block holding a transaction this page sent
  // and shows Done (a Vanish commit, a reveal or a claim, in `ownSent`) is
  // SETTLE_DEPTH deep, then the Summon goes on with no step from the holder.
  // The page sent each of those transactions through the endpoint, so the
  // endpoint already knows their blocks, and the wait is the same whichever
  // key is summoned and whatever block holds its coin: it does not tell
  // the endpoint whether the key's coin is new or where it is. A coin this
  // page committed or left as a remainder is then settled; one from another
  // device whose block is not yet 2 deep fails as any reveal that cannot be
  // made does. `stage` is shown meanwhile, only on the page.
  async function settleFirst(stage) {
    const top = await blockNumber();
    const own = ownSent.filter((r) => r.stage === "done").map((r) => r.block);
    return untilBlock(own.length === 0 ? top : Math.max(...own) + SETTLE_DEPTH, top, stage);
  }

  // A receipt is the endpoint's word only. A transaction sent when the
  // endpoint's tip was block `sentAfter` can only be in a later block. It
  // counts as settled when the chain shows what it did: the coin trees as
  // of the tip, each checked against its root (readTrees), hold `commitment`
  // (the new leaf every commit, reveal and claim appends) at a position the
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
    top = await untilBlock(needed, top);
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
    const added = await appendedBy(await readTrees(tip), parent, block);
    if (!added) throw new Error(`the endpoint's tree does not match the header of block ${block.number}`);
    const { tree, before, after } = added;
    const leaf = toHex(commitment);
    for (let position = before; position < after; position += 1) {
      if (toHex(tree.leaves.slice(position * 32, position * 32 + 32)) === leaf) {
        return { blockNumber: block.number, blockHash: block.hash, position };
      }
    }
    throw new Error(`block ${block.number} does not hold the transaction's new coin; it has not settled`);
  }

  // The tree `block` (whose parent is `parent`) appended to and the leaf
  // counts of that tree before and after it, `{ tree, before, after }`, read
  // from the two headers' coin roots among the prefix roots of `trees`
  // (readTrees): the block's root is a prefix root of one tree, and its
  // parent's a prefix root of the same tree, or the final root of the tree
  // before when the block started this one. Null when the trees do not show
  // it.
  async function appendedBy(trees, parent, block) {
    for (let t = trees.length - 1; t >= 0; t -= 1) {
      const tree = trees[t];
      const roots = await prefixRootsOf(prover, treeDepth, tree.leaves, 0, tree.count);
      const countOf = new Map(roots.map((root, count) => [toHex(root), count]));
      const after = countOf.get(toHex(block.coinTreeRoot));
      if (after === undefined) continue;
      const started = t > 0 && toHex(parent.coinTreeRoot) === toHex(trees[t - 1].root);
      const before = started ? 0 : countOf.get(toHex(parent.coinTreeRoot));
      return before === undefined ? null : { tree, before, after };
    }
    return null;
  }

  // Whether the coin trees as of the tip, each checked against its root
  // (readTrees), hold `commitment`. Every tree is read whole, so no request
  // names the leaf.
  async function treeHolds(commitment) {
    const tip = await syncTip();
    const leaf = toHex(commitment);
    for (const tree of await readTrees(tip)) {
      for (let position = 0; position < tree.count; position += 1) {
        if (toHex(tree.leaves.slice(position * 32, position * 32 + 32)) === leaf) return true;
      }
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
    if (!ownSent.includes(record)) ownSent.push(record);
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
    if (treeDepth !== TREE_DEPTH && (await prover.request("testDepthProver")).depth !== treeDepth) {
      throw new Error(SMALL_TREE_REVEAL);
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
      // The coin's salt as restore found it: the prover opens the coin with
      // it and salts the remainder too; it refuses a coin without one.
      salt: current.salt ?? null,
      leaves: plan.leaves,
      key,
      newKey,
    };
  }

  // Proves a reveal of the key's current coin and sends it. A proof whose
  // fee lapsed while it was being made is made again; a fee of the previous
  // window still counts while the next block's base fee is within its cover
  // limit (spec 07, section 5). Before each proof, when fewer than two blocks
  // of the next block's window are left or that block's base fee is already
  // above the window fee's cover limit, it waits a block at a time for the
  // next window's fee.
  //
  // After restore, every path, the one where the key holds no coin
  // included, asks the endpoint the same thing in the same order before
  // anything depends on the outcome: eth_blockNumber, the tip's header and
  // the fee for the next block. Only then does a failure surface, or the
  // reveal go out; sending the reveal is what links the connection to the
  // coin. A reveal that cannot be made is not proved at all: no stand-in
  // proof is made in its place, since a full proof only to say "no coin"
  // costs hundreds of megabytes and hides almost nothing. (A coin's proof
  // the worker itself refuses still takes a proof's time in the worker,
  // lib.rs, ghost_prove.)
  //
  // A Summon comes here only after settleFirst, so a coin this page
  // committed or left as a remainder is already SETTLE_DEPTH deep. A coin
  // that is not (planReveal's WaitError: one from another device, or after a
  // reorganisation) fails as above, its wait never shown to the endpoint.
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
      // A proof for a window that is about to close, or whose fee no longer
      // covers the next block's base fee, would likely lapse: wait for the
      // next window's fee, one poll every `pollMs`. At a window's first block
      // the base fee is b_ref, within the cover limit, so this ends within 3
      // blocks. A fee that still covers the next block is also taken in the
      // window after (spec 07, section 5), so when the chain does not move
      // for `maxPolls` polls only a fee past its cover limit stops the
      // reveal.
      for (let polls = 0; ; polls += 1) {
        const tip = await syncTip();
        const next = await feeForNextBlock(tip, headerAt);
        if (!next.wait) break;
        if (polls >= maxPolls) {
          if (nextBaseFee(tip) > next.coverLimit) {
            throw new Error(`the chain has not reached block ${tip.number + 1} yet; refresh later`);
          }
          break;
        }
        progress("waiting for the next fee window");
        await sleep(pollMs);
      }
      const scan = await scanKey(request.key);
      let args = null;
      let failure = null;
      try {
        args = await revealArgs(scan, request, pinned);
        // A coin of a later coin tree than tree 0 also keeps its tree index.
        const { treeIndex = 0 } = keyStatus(scan.found).current;
        pinned ??= { ...(treeIndex > 0 ? { treeIndex } : {}), number: args.number, position: args.position, amount: args.amount };
      } catch (err) {
        failure = err;
      }
      let proved = null;
      if (args) {
        progress("proving in the background worker");
        try {
          // A coin of a test node's smaller tree carries that node's stub
          // proof (TEST_DEPTH_REVEAL).
          const op = treeDepth !== TREE_DEPTH ? "proveTestDepth" : "prove";
          proved = await prover.request(op, args, (stage) =>
            progress(stage === "proving" ? "proving in the background worker" : stage),
          );
        } catch (err) {
          failure = err;
        }
      }
      let tip = await syncTip();
      if (!(await feeStillAccepted(scan.fee, tip, headerAt))) {
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
        if (!(await feeStillAccepted(scan.fee, tip, headerAt))) {
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

  // Connects the wallet of connector `c` (wallet-connect.mjs): its account's
  // address, as the wallet gives it, then its balance from the endpoint.
  async function connectWallet(c) {
    if (!c || typeof c.connect !== "function" || typeof c.signTransaction !== "function") {
      throw new Error("not a wallet connector");
    }
    const answer = await c.connect();
    const address = String((answer && answer.address) || "");
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error("the wallet answered without an account address");
    const previous = connector;
    connector = c;
    state.wallet = { id: c.id ?? null, name: c.name ?? null, address: address.toLowerCase(), balance: null };
    emit();
    if (previous && previous !== c) forget(previous);
    await readBalance();
    return state.wallet;
  }

  // Lets a connector go; a wallet that fails to let go is gone all the same.
  function forget(c) {
    try {
      if (typeof c.disconnect === "function") Promise.resolve(c.disconnect()).catch(() => {});
    } catch {
      // Nothing to do: the page no longer uses it.
    }
  }

  async function readBalance() {
    const w = state.wallet;
    if (!w) return null;
    const balance = quantity(await rpc.call("eth_getBalance", [w.address, "latest"]));
    // The wallet may have been disconnected meanwhile.
    if (state.wallet !== w) return null;
    w.balance = balance;
    emit();
    return w.balance;
  }

  // Has the connected wallet sign an account transaction (type 0x52) from
  // its account, then sends it: the nonce, fee and gas from the endpoint,
  // the genesis hash from this build's entry for the network (the signature
  // binds the chain), the base fee from the endpoint's header of block `at`,
  // its tip when the send began. That header is not checked against the
  // page's header chain: sending needs none of it, a wrong base fee can
  // only cost at most what the caps below allow or leave the commit
  // unmined, and whether a block holds the commit is checked afterwards
  // through the verified header chain. The wallet asks the user to approve
  // it. Its answer is sent only if it is from the connected account and its
  // hash is the envelope's. Returns the transaction hash.
  async function sendFromWallet({ chainId, to, value, data, at }) {
    if (!connector || !state.wallet) throw new Error("connect a wallet first");
    const signer = connector;
    const from = state.wallet.address;
    const network = networkOf(networks, chainId);
    if (!network) throw new ChainRefused(noPinMessage(chainId));
    const genesis = fromHex(network.genesisHash, 32);
    const nonce = quantity(await rpc.call("eth_getTransactionCount", [from, "pending"]));
    const { header: tip } = await fetchHeader(at);
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
    if (balance === null || connector !== signer) throw new Error("connect a wallet first");
    if (balance < value + gasLimit * maxFee) {
      throw new Error(`the wallet holds ${formatGhost(balance)} GHOST, less than the amount and the most the gas can cost`);
    }
    progress(WALLET_APPROVAL);
    let signed;
    try {
      signed = await signer.signTransaction({
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
    } catch (err) {
      // Turned down in the wallet, or the wallet failed to sign: either way
      // nothing is sent.
      if (isWalletRejection(err)) throw new WalletRejected("the transaction");
      throw new WalletSignFailed(err);
    }
    if (connector !== signer || !state.wallet || state.wallet.address !== from) {
      throw new Error("the wallet was disconnected before the transaction was sent; nothing was sent");
    }
    if (!signed || !(signed.sender instanceof Uint8Array) || !(signed.txHash instanceof Uint8Array) || !(signed.envelope instanceof Uint8Array)) {
      throw new Error("the wallet answered without a signed transaction; nothing was sent");
    }
    if (toHex(signed.sender) !== from) throw new Error("the signed transaction is not from the wallet's account; nothing was sent");
    const txHash = toHex(signed.txHash);
    if (toHex(keccak256(signed.envelope)) !== txHash) {
      throw new Error("the wallet's transaction hash is not the hash of its envelope; nothing was sent");
    }
    progress("sending the commit");
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
          amountMatches: null,
          cover: null,
          wait: null,
          tip: null,
          fee: null,
          smallestCoin: null,
          available: 0n,
        });
        emit();
      }
      throw err;
    }
    const { status, current } = keyStatus(scan.found);
    const { fee } = scan;
    s.coins = scan.found.map(({ number, amount, treeIndex, position, spent }) => ({ number, amount, treeIndex, position, spent }));
    s.status = status;
    s.current = current
      ? { number: current.number, amount: current.amount, treeIndex: current.treeIndex, position: current.position }
      : null;
    s.fee = fee;
    // A coin below this could not be summoned again for long at this fee:
    // the level of the page's warning for a partial Summon's remainder.
    s.smallestCoin = MIN_VANISH_FEES * fee;
    s.available = current && current.amount > fee ? current.amount - fee : 0n;
    s.tip = scan.chain.tip.number;
    // How many commits in the receipts the page checked are of the coin's
    // amount, the key's own commit included: a full Summon publishes
    // `out + fee`, which is that amount (null with no coin).
    s.amountMatches = current ? (scan.commitsByAmount.get(current.amount) ?? 0) : null;
    // What a reveal now would prove against, as information: the block and
    // how many coins its tree covers, or why the app waits. The rule is
    // asked for every key, a coin or not.
    s.cover = null;
    s.wait = null;
    if (current) {
      try {
        const plan = await planReveal(prover, scan, current);
        s.cover = { height: plan.height, covers: plan.covers, total: scan.trees[current.treeIndex ?? 0].count };
      } catch (err) {
        if (!(err instanceof WaitError)) throw err;
        s.wait = { message: err.message, from: err.from };
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
      if (!ownSent.includes(record)) ownSent.push(record);
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

    // Connects the wallet of `c`, a connector of wallet-connect.mjs, in
    // place of any connected before. Returns its account's address.
    walletConnect(c) {
      return run("connecting the wallet", async () => (await connectWallet(c)).address);
    },

    walletRefresh() {
      return run("reading the wallet's balance", readBalance);
    },

    // Lets the connected wallet go; the next Vanish needs a wallet again.
    walletDisconnect() {
      if (state.busy) throw new Error(`wait until "${state.busy}" is done`);
      const c = connector;
      connector = null;
      state.wallet = null;
      emit();
      if (c) forget(c);
    },

    // A fresh receive address of the connected wallet, one that never sent
    // or received anything, for a Summon to pay (the connector's optional
    // newReceiveAddress, wallet-connect.mjs), lower case. Null when no wallet
    // is connected, when the wallet has no such request (the connector has
    // no newReceiveAddress, answers null, or the wallet answers "method not
    // found", -32601) or when another wallet was connected meanwhile. The
    // wallet hands out a new address each time; nothing is stored here.
    async newReceiveAddress() {
      const c = connector;
      if (!c || !state.wallet || typeof c.newReceiveAddress !== "function") return null;
      let answer;
      try {
        answer = await c.newReceiveAddress();
      } catch (err) {
        if (err && err.code === METHOD_NOT_FOUND) return null;
        throw err;
      }
      if (connector !== c || answer == null) return null;
      const text = typeof answer === "string" ? answer : answer.address;
      if (!/^0x[0-9a-fA-F]{40}$/.test(String(text))) throw new Error("the wallet answered without a receive address");
      const address = parseAddress(text);
      if (address === ZERO_ADDRESS) throw new Error("the wallet answered with the zero address");
      return address;
    },

    // Vanish, step 1: a new key of 24 words for `amountText` GHOST, shown
    // to the user to write down; copying it or downloading its image is a
    // convenience beside that, never the only backup.
    vanishStart(amountText) {
      return run("creating a key", async () => {
        if (!connector) throw new Error("connect a wallet first");
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

    // The smallest Vanish the page sends now (chain.mjs, minVanishFor), from
    // the endpoint's tip header as the commit send reads it: one header,
    // unchecked, and no header chain. A wrong base fee there only moves
    // this advice; nothing is sent on it.
    async minVanish() {
      const { header } = await fetchHeader("latest");
      return minVanishFor(header);
    },

    // Vanish: the new key shown as its words or as its digit view.
    vanishView(view) {
      return keyView(state.vanish, view);
    },

    // Vanish, step 2: the user says the key is saved; three words to re-type.
    vanishSaved() {
      return saveCheckStep(state.vanish);
    },

    // Vanish, step 3: the re-typed words. Nothing is sent unless all match
    // and the wallet approves the commit. Turned down there (WalletRejected)
    // or failing to sign (WalletSignFailed), nothing is sent and the step
    // stays as it was; the page drops the key after a rejection.
    vanishCheck(answers) {
      return run("sending the commit", async () => {
        const v = state.vanish;
        const wrong = requireCheck(v, answers);
        if (wrong.length > 0) return { ok: false, wrong };
        if (!connector) throw new Error("connect a wallet first");
        const chainId = quantity(await rpc.call("eth_chainId"));
        progress("building the commit");
        // The endpoint's tip as it says, unchecked: no header is checked
        // before the send, so the first Vanish of a session does not wait
        // for the whole header chain. It is only the floor below which a
        // receipt is refused as old; the commit is confirmed afterwards
        // through the verified header chain (waitSettled), so an endpoint
        // that lies here cannot make the page take a commit that chain does
        // not hold. Only when the page has already refused this endpoint's
        // chain is it checked again first: nothing is sent onto a chain
        // known to fail until it passes.
        if (state.chainRefused) await syncTip();
        const sentAfter = Number(quantity(await rpc.call("eth_blockNumber")));
        // Version 2: the worker draws the coin's salt from its secure random
        // source and the payload carries it beside F (206 bytes).
        const commit = await prover.request("commit", { chainId, amount: v.amount, key: v.key });
        if (commit.payload.length !== COMMIT_DATA_BYTES || commit.payload[0] !== 0 || commit.payload[1] !== 2) {
          throw new Error(`the commit is not ${COMMIT_DATA_BYTES} bytes of version 2; nothing was sent`);
        }
        const from = state.wallet && state.wallet.address;
        const txHash = await sendFromWallet({ chainId, to: state.commitEntry, value: v.amount, data: commit.payload, at: sentAfter });
        // sendFromWallet sends only what the account `from` signed.
        if (!state.vanishedFrom.includes(from)) state.vanishedFrom.push(from);
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
    // spaces or hyphens, or its digit view of 21 groups. Digits of any other
    // count, the 12 or 24 groups of the old digit keys among them, are
    // refused. The worker checks the
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
          amountMatches: null,
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
        // The same wait for every key (settleFirst); while the coin's block
        // is not yet 2 deep the page shows its plain line.
        await settleFirst(s.wait ? s.wait.message : "waiting for the chain to move on");
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
