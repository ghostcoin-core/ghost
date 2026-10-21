// A scripted stand-in for the node's JSON-RPC, for the headless tests: a
// local HTTP server that keeps a chain of headers with the coin tree root,
// the coin tree's leaves and notes, the spent coin markers and receipts, and
// records every request it is sent.
//
// Every block carries real receipts, one per transaction it holds, in the
// node's log layout (as the client library reads it, after ghost-node
// docs/private-transactions.md, "Receipts"): a commit's log has the coin
// tree account as address, the topic K("ghost/commit-receipt/v1") and the
// tree index, position, leaf, value and note, then the salt of a version 2
// commit; a reveal's log has K("ghost/reveal-receipt/v1") and the marker as
// topics and the tree index, position, remainder, note, recipient and amount
// out. The header's receiptsRoot is computed from their consensus encoding
// (written here apart from the app's) by the module's ghost_receipts_root,
// and eth_getBlockReceipts serves them by block hash, as geth does.
//
// It follows the specifications of this repository: whole pages of 4,096
// leaves with their notes and the page-root list (spec 05, section 8), the
// header roots of spec 05, section 4, the header encoding and hash of spec 05,
// section 10, the private transaction envelope and fee of spec 07, sections 3
// to 5, and the commit of spec 03, section 6. Its tree page methods answer in
// exactly the node's shape and refuse what the node refuses, in its words
// (ghost-node docs/trees-and-headers.md, "Tree page methods").
// A reveal is decoded and its proof verified with the real verifier, then
// checked as a node admits it: fee in force, root of an earlier canonical
// block, marker unused. Commits arrive as account transactions (type 0x52,
// ghost-node docs/account-transactions.md), decoded and their ML-DSA-44
// signature checked by the client library against this chain's identifier
// and genesis hash, with the sender's nonce and balance checked as the node
// checks them; `fund` gives an account its balance. A scripted sender of
// plain commits (`wallet` below) is kept for the stand-in's own checks of a
// commit's fields.
//
// Importing this file runs nothing; the tests start the server.

import { createHash } from "node:crypto";
import { createServer } from "node:http";

import { concat, fromHex, quantity, toHex, word } from "../../src/bytes.mjs";

const PAGE = 4096;
const NOTE_BYTES = 156;
const GWEI = 1_000_000_000n;
// Spec 05, vector empty-data-tree: no data commitment is ever made here.
const EMPTY_DATA_ROOT = "0x3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03";
// Spec 05, section 10: the hash of the empty list.
const EMPTY_LIST_HASH = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";
// The internal network's test constants (spec 06, section 4.2, with
// D_START = D_MIN = 1): a header stamped on the 30-second schedule, or behind
// it, requires difficulty 1, so any nonce seals it; one stamped a whole
// number k of half-lives ahead of it requires 2^k.
export const TEST_CHAIN_PARAMS = Object.freeze({
  blockTime: 30,
  halfLife: 3600,
  startDifficulty: 1,
  minDifficulty: 1,
  futureDrift: 30,
});
export const FAKE_CHAIN_ID = 7_777_001n;
// The commit data the node takes (ghost-node core/ghostpriv/commit.go):
// version 0x0002, F, the coin's salt and the note (206 bytes,
// SaltedCommitDataSize), or version 0x0001, F and the note (190 bytes,
// CommitDataSize), and the node's words for anything else, which it follows
// with the length (`: N bytes`).
export const SALT_BYTES = 16;
export const SALTED_COMMIT_VERSION = Uint8Array.of(0x00, 0x02);
export const SALTED_COMMIT_DATA_BYTES = 2 + 32 + SALT_BYTES + NOTE_BYTES;
export const COMMIT_VERSION = Uint8Array.of(0x00, 0x01);
export const COMMIT_DATA_BYTES = 2 + 32 + NOTE_BYTES;
export const COMMIT_DATA_ERROR = "commit data is not 190 bytes of version 1 or 206 bytes of version 2";
// The node's refusal of a reveal whose checks saw a new head every time
// (ghost-node core/txpool/ghostpool): a transient bound on work per reveal.
export const HEAD_MOVED_ERROR = "chain head kept moving while the reveal was checked";
// An account transaction's intrinsic gas: a type 0x02 transfer's 21,000 and
// the 62,744 of its scheme, key, signature and check (ghost-node
// docs/account-transactions.md), and the gas the stand-in's eth_estimateGas
// answers for a commit, which leaves out the 62,744 as the node's does.
export const ACCOUNT_INTRINSIC_GAS = 21_000n + 62_744n;
export const COMMIT_ESTIMATE_GAS = 60_000n;
export const PRIORITY_FEE = 1_000_000_000n;

const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(typeof p === "string" ? p : Buffer.from(p));
  return new Uint8Array(h.digest());
};

const q = (n) => `0x${BigInt(n).toString(16)}`;

// The tree kinds the node knows (ghost-node docs/trees-and-headers.md, "Tree
// page methods"), and its page bound: a page number of 0x100000 or more is
// beyond any tree.
const TREE_KINDS = new Set(["coin", "data", "coin-markers", "data-markers"]);
const MARKER_KINDS = new Set(["coin-markers", "data-markers"]);
const MAX_PAGES = 0x100000;
const INVALID_PARAMS = -32602;
// geth's code for an error a method returned (rpc package, errcodeDefault).
export const SERVER_ERROR = -32000;

// A refusal of a parameter, as the node words it: `invalid argument <i>: …`
// with code -32602 (or without the argument for a wrong parameter count).
function invalid(index, reason) {
  const message = index === null ? reason : `invalid argument ${index}: ${reason}`;
  return Object.assign(new Error(message), { code: INVALID_PARAMS });
}

// The header RLP of spec 05, section 10, written apart from the app's: the
// 18 fields in order, as the base client's JSON-RPC names them.
const HEADER_ORDER = [
  "parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom",
  "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "nonce",
  "baseFeePerGas", "coinTreeRoot", "dataTreeRoot",
];
const HEADER_INTS = new Set(["difficulty", "number", "gasLimit", "gasUsed", "timestamp", "baseFeePerGas"]);

function bigEndian(n) {
  const out = [];
  for (let v = BigInt(n); v > 0n; v >>= 8n) out.unshift(Number(v & 0xffn));
  return Uint8Array.from(out);
}

function prefixed(payload, short) {
  if (payload.length < 56) return concat([Uint8Array.of(short + payload.length), payload]);
  const size = bigEndian(payload.length);
  return concat([Uint8Array.of(short + 55 + size.length), size, payload]);
}

const rlpBytes = (bytes) => (bytes.length === 1 && bytes[0] < 0x80 ? bytes : prefixed(bytes, 0x80));
const rlpItems = (items) => prefixed(concat(items), 0xc0);

function headerRlp(json) {
  const items = HEADER_ORDER.map((name) => rlpBytes(HEADER_INTS.has(name) ? bigEndian(BigInt(json[name])) : fromHex(json[name])));
  return rlpItems(items);
}

// The coin tree account, the address of every commit and reveal log.
export const COIN_TREE_ACCOUNT = "0x67686f7374000000000000000000000000000001";
// Gas each transaction of a block adds to the receipts' cumulative gas.
const RECEIPT_GAS = 100_000n;

const u32 = (n) => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
};

// A receipt's consensus encoding: the type byte (none for type 0), then the
// RLP of [status, cumulativeGasUsed, logsBloom, logs].
function receiptRlp({ type, status, cumulativeGasUsed, logsBloom, logs }) {
  const body = rlpItems([
    rlpBytes(status ? Uint8Array.of(1) : new Uint8Array(0)),
    rlpBytes(bigEndian(cumulativeGasUsed)),
    rlpBytes(logsBloom),
    rlpItems(logs.map((log) => rlpItems([rlpBytes(log.address), rlpItems(log.topics.map(rlpBytes)), rlpBytes(log.data)]))),
  ]);
  return type === 0 ? body : concat([Uint8Array.of(type), body]);
}

// A receipt as geth's JSON-RPC returns it.
function receiptJson(receipt, { index, blockNumber, blockHash }) {
  const where = { blockNumber: q(blockNumber), blockHash: toHex(blockHash), transactionHash: receipt.hash, transactionIndex: q(index) };
  return {
    ...where,
    type: q(receipt.type),
    status: receipt.status ? "0x1" : "0x0",
    cumulativeGasUsed: q(receipt.cumulativeGasUsed),
    gasUsed: q(RECEIPT_GAS),
    logsBloom: toHex(receipt.logsBloom),
    contractAddress: null,
    logs: receipt.logs.map((log, i) => ({
      ...where,
      address: toHex(log.address),
      topics: log.topics.map(toHex),
      data: toHex(log.data),
      logIndex: q(i),
      removed: false,
    })),
  };
}

// The node's own fee of spec 07, section 4, written apart from the app's.
function nodeFee(blocks, height) {
  const start = height - (height % 4);
  const tip = blocks[blocks.length - 1];
  // Every block here is half full, so a child's base fee equals its parent's.
  let price = start < blocks.length ? blocks[start].baseFee : tip.baseFee;
  for (let j = 0; j < 3; j += 1) price = price + price / 8n + price / 20000n + 1n;
  // g_priv of spec 07, section 4: the reveal gas the node charges.
  const base = 21_090_372n * price;
  return base + (base + 9n) / 10n;
}

// The stand-in's headers follow the internal network's test constants: block
// n is stamped `genesisTime + 30 n`, on the schedule, so it requires
// difficulty 1 and carries it, with an all-zero mix digest, and any nonce
// seals it. The genesis time is in the past (400 days ago by default), so no
// header runs ahead of the page's clock. With `earlyHalfLives` k, every
// block after genesis is stamped k half-lives ahead of the schedule and
// carries the 2^k it then requires, while its nonce is still not mined: its
// seal fails (a header chain must start above genesis for such a chain,
// `pinnedNetwork`). `setDifficulty(d)` makes the blocks mined from then on
// carry difficulty `d` whatever the schedule requires.
//
// With `treeLeaves`, a coin tree holds that many leaves and the next leaf
// goes to position 0 of the next tree index (spec 05, section 3), as a node
// whose trees are smaller than the release's 2^32 would roll over. Each
// tree's root is still the depth-32 root of its leaves, and a header carries
// the root of the tree its block's last leaf is in, so a full tree's final
// root stays in the headers until the next tree's first leaf. Tree page
// requests take any index up to the anchor's tree, and the receipts carry
// each leaf's tree index and position in it. Without it there is one tree.
export async function startFakeNode({
  ghost,
  chainId = FAKE_CHAIN_ID,
  commitEntry,
  genesisTime = Math.floor(Date.now() / 1000) - 400 * 86_400,
  earlyHalfLives = 0,
  treeLeaves = Infinity,
}) {
  const early = BigInt(earlyHalfLives) * BigInt(TEST_CHAIN_PARAMS.halfLife);
  const scheduled = 1n << BigInt(earlyHalfLives);
  let difficultyOverride = null;
  const leaves = []; // { commitment, note, salt, block }; salt null but for a version 2 commit
  const spent = []; // { marker, block }
  const blocks = [];
  const receipts = new Map();
  const balances = new Map();
  const requests = [];
  const reveals = [];
  const commits = [];
  // Account transactions taken, and the next nonce of each sender.
  const accountTxs = [];
  const nonces = new Map();
  // What a dishonest endpoint does, for the tests that play one:
  // `note(position, note)` replaces each note it serves; with `withhold`
  // set a reveal is not executed: its hash is returned and its receipt
  // lookup answered with `withhold(hash, reveal)`; with `forge` set to
  // { from, extra } the coin tree it serves as of block `from` and later
  // also holds the `extra` leaves ({ commitment, note }), and those blocks'
  // headers carry that tree's root but keep their real hash; `salt(position,
  // salt)` replaces the salt it serves beside each leaf (bytes, a hex text
  // as it is sent, or null to leave it out).
  // `pageRoots(roots, k)` replaces the page-root list it serves of coin tree
  // k, and `page(p, honest, honestPage, k)` the coin page `p` of tree k
  // (`honestPage(q, j = k)` is the honest page q of tree j), to drop or
  // reorder pages; `markers(list)` replaces the
  // spent markers (hex) it serves as of an anchor, before they are cut into
  // pages; `receipts(number, list)` replaces the receipts (JSON) it serves
  // for block `number`, null for none.
  const dishonest = {
    note: null,
    withhold: null,
    forge: null,
    salt: null,
    pageRoots: null,
    page: null,
    markers: null,
    receipts: null,
  };
  const withheld = [];
  // With `errorAfterAccountTx` set, an account transaction is taken and
  // answered with an error, as ghost-node answers one; with
  // `refuseAccountTx` set, it is refused and not taken.
  // `priorityFee` and `estimateGas`, when set, replace the answers of
  // eth_maxPriorityFeePerGas and eth_estimateGas.
  const quirks = { errorAfterAccountTx: false, refuseAccountTx: false, priorityFee: null, estimateGas: null };
  // A fast-mining node, for the tests that play one: the next `count` sends
  // of a valid reveal are refused with HEAD_MOVED_ERROR, each after
  // `blocks` empty blocks are mined, as the node's head moves meanwhile.
  // With `miner` set, an empty block is mined on a timer, and every send of
  // a valid reveal is refused the same way while it runs, as a node that
  // seals blocks faster than it checks a reveal refuses each one.
  // `refuseWhileMining` false lets the miner run without refusing sends.
  // With `drops` above 0, the next `drops` valid reveals the node takes are
  // held and then dropped at the next block, as the node's pool drops a held
  // reveal that fails its check on a new head (ghostpool Reset): no block
  // holds them and their lookup finds nothing.
  // With `stale` set, the first valid reveal sent from then on becomes the
  // stale envelope: that send and every later send of the same envelope is
  // refused the same way, each after `stale.blocks` empty blocks, while any
  // other valid reveal (a fresh proof) is taken. `stale.refused` counts them.
  const headMoving = { count: 0, blocks: 0, refused: 0, miner: null, refuseWhileMining: true, drops: 0, stale: null };
  const held = new Map();
  const dropped = [];
  // With `pool.on` set, a commit from the wallet or a valid reveal the node
  // takes waits in the pool, its hash returned and no block mined, and the
  // next block holds it, as a node that seals blocks on its own schedule.
  // `pool.entries` are those waiting: `{ hash, marker, apply(n), after(n) }`.
  const pool = { on: false, entries: [] };
  // Transactions a reorganisation took out of the chain (reorg below).
  const reorged = [];
  // Raised on each reorganisation, so a replacing block never has the hash
  // of the block it replaces.
  let fork = 0;
  let nonce = 0;
  // The base fee of the blocks mined from now on.
  let baseFee = GWEI;
  // The receipts of the block being mined, one per transaction it holds, in
  // order: { hash, type, logs }.
  const blockReceipts = [];
  const tagTopic = (tag) => ghost.keccak256(concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)]));
  const COMMIT_TOPIC = tagTopic("ghost/commit-receipt/v1");
  const REVEAL_TOPIC = tagTopic("ghost/reveal-receipt/v1");
  const coinTreeAccount = fromHex(COIN_TREE_ACCOUNT, 20);

  // The tree index and the position in it of the leaf at `index` of
  // `leaves` (every tree's leaves, in the order they were appended).
  const treeOf = (index) => Math.floor(index / treeLeaves);
  const positionOf = (index) => index % treeLeaves;
  // `list` (leaves in append order) cut into its trees, the last one the
  // tree a header of that many leaves carries: a full tree stays the
  // current one until a leaf goes into the next.
  const treesOf = (list) => {
    const trees = [];
    for (let start = 0; start < list.length; start += treeLeaves) trees.push(list.slice(start, start + treeLeaves));
    return trees.length === 0 ? [[]] : trees;
  };
  const rootOf = (list) => ghost.treeRoots(concat(treesOf(list).at(-1).map((l) => l.commitment))).root;

  // A commit's log: tree index, position, leaf, value and note, then the
  // salt of a version 2 commit (228 or 244 bytes). `index` is the leaf's
  // index in `leaves`.
  const commitLog = (index, commitment, value, note, salt) => ({
    address: coinTreeAccount,
    topics: [COMMIT_TOPIC],
    data: concat([u32(treeOf(index)), u32(positionOf(index)), commitment, word(value), note, ...(salt ? [salt] : [])]),
  });
  // A reveal's log: the marker as second topic; tree index, position,
  // remainder, note, recipient and amount out (248 bytes).
  const revealLog = (index, reveal) => ({
    address: coinTreeAccount,
    topics: [REVEAL_TOPIC, reveal.marker],
    data: concat([u32(treeOf(index)), u32(positionOf(index)), reveal.remainder, reveal.note, reveal.recipient, word(reveal.out)]),
  });

  // A block's header fields, with the names of the base client's JSON-RPC.
  function headerFields(number, parentHash, coinTreeRoot, receiptsRoot) {
    return {
      parentHash: toHex(parentHash),
      sha3Uncles: EMPTY_LIST_HASH,
      miner: toHex(new Uint8Array(20)),
      stateRoot: toHex(fork === 0 ? sha256("state", String(number)) : sha256("state", String(number), `fork ${fork}`)),
      transactionsRoot: toHex(sha256("transactions", String(number))),
      receiptsRoot: toHex(receiptsRoot),
      logsBloom: toHex(new Uint8Array(256)),
      difficulty: q(number === 0 ? 1n : (difficultyOverride ?? scheduled)),
      number: q(number),
      gasLimit: q(30_000_000n),
      gasUsed: q(15_000_000n),
      timestamp: q(BigInt(genesisTime) + 30n * BigInt(number) - (number === 0 ? 0n : early)),
      extraData: "0x",
      // Spec 08: a sealed header's mix digest is all zero.
      mixHash: toHex(new Uint8Array(32)),
      nonce: toHex(sha256("nonce", String(number), `fork ${fork}`).slice(0, 8)),
      baseFeePerGas: q(baseFee),
      coinTreeRoot: toHex(coinTreeRoot),
      dataTreeRoot: EMPTY_DATA_ROOT,
    };
  }

  const forged = (block) => dishonest.forge && block.number >= dishonest.forge.from;

  // The leaves served as of `block`.
  function served(block) {
    const real = leaves.slice(0, block.leafCount);
    return forged(block) ? [...real, ...dishonest.forge.extra] : real;
  }

  // The leaves of tree `treeIndex` served as of `block`, null for a tree
  // past the block's.
  function servedTree(block, treeIndex) {
    const trees = treesOf(served(block));
    return treeIndex < trees.length ? trees[treeIndex] : null;
  }

  function header(block) {
    const json = { ...block.json, hash: toHex(block.hash) };
    if (forged(block)) json.coinTreeRoot = toHex(rootOf(served(block)));
    return json;
  }

  // One new block holding `apply`'s changes and every transaction waiting
  // in the pool.
  function mine(apply = () => {}) {
    const number = blocks.length;
    apply(number);
    const pooled = pool.entries.splice(0);
    for (const entry of pooled) entry.apply(number);
    const leafCount = leaves.length;
    const coinTreeRoot = rootOf(leaves);
    const parentHash = number === 0 ? new Uint8Array(32) : blocks[number - 1].hash;
    const txReceipts = blockReceipts.splice(0).map((r, i) => ({
      ...r,
      status: true,
      cumulativeGasUsed: RECEIPT_GAS * BigInt(i + 1),
      logsBloom: new Uint8Array(256),
    }));
    const receiptsRoot = ghost.receiptsRoot(txReceipts.map(receiptRlp));
    const json = headerFields(number, parentHash, coinTreeRoot, receiptsRoot);
    const hash = ghost.keccak256(headerRlp(json));
    blocks.push({
      number,
      parentHash,
      json,
      hash,
      baseFee,
      coinTreeRoot,
      leafCount,
      spentCount: spent.length,
      receipts: txReceipts.map((r, index) => receiptJson(r, { index, blockNumber: number, blockHash: hash })),
    });
    for (const hash of held.keys()) dropped.push(hash);
    held.clear();
    for (const entry of pooled) entry.after(number);
    return number;
  }

  // Takes the last `depth` blocks out of the chain, with every commit and
  // reveal they held, and mines `length` empty blocks in their place
  // (`depth + 1` by default): a reorganisation onto a chain that holds none
  // of those transactions, heavier than the old one, or lighter with a
  // `length` of `depth` or less. Nothing taken out comes back. Returns the
  // first height replaced.
  function reorg(depth = 1, { length = depth + 1 } = {}) {
    const cut = blocks.length - depth;
    if (cut < 1) throw new Error("cannot replace genesis");
    blocks.length = cut;
    while (leaves.length > 0 && leaves[leaves.length - 1].block >= cut) leaves.pop();
    while (spent.length > 0 && spent[spent.length - 1].block >= cut) spent.pop();
    for (const [hash, receipt] of receipts) {
      if (receipt.blockNumber !== undefined && Number(BigInt(receipt.blockNumber)) >= cut) {
        receipts.delete(hash);
        reorged.push(hash);
      }
    }
    for (let i = reveals.length - 1; i >= 0; i -= 1) {
      const reveal = reveals[i];
      if (reveal.block < cut) continue;
      const recipient = toHex(reveal.recipient);
      if (reveal.out > 0n) balances.set(recipient, balances.get(recipient) - reveal.out);
      reveals.splice(i, 1);
    }
    fork += 1;
    for (let i = 0; i < length; i += 1) mine();
    return cut;
  }

  mine();

  function blockByHash(hash) {
    const block = blocks.find((b) => toHex(b.hash) === String(hash).toLowerCase());
    if (!block) throw new Error("unknown anchor block");
    return block;
  }

  // A commit in a new block, or, with `pooled`, in the pool until the next.
  // A version 2 commit's salt is stored with its leaf.
  function appendCommit(fingerprint, value, note, { pooled = false, txHash = null, salt = null } = {}) {
    const commitment = ghost.coinCommitment(fingerprint, value, salt ? 2 : 1);
    const hash = txHash ?? toHex(sha256("fake commit", String((nonce += 1))));
    const entry = {
      hash,
      marker: null,
      apply: (n) => {
        leaves.push({ commitment, note, salt, block: n });
        blockReceipts.push({ hash, type: txHash ? 0x52 : 0x02, logs: [commitLog(leaves.length - 1, commitment, value, note, salt)] });
      },
      after: (n) =>
        receipts.set(hash, {
          transactionHash: hash,
          blockNumber: q(n),
          blockHash: toHex(blocks[n].hash),
          status: "0x1",
          type: txHash ? "0x52" : "0x2",
        }),
    };
    if (pooled) pool.entries.push(entry);
    else entry.after(mine((n) => entry.apply(n)));
    return { hash, commitment };
  }

  // A commit by a stranger: a random fingerprint and salt and a note no key
  // opens, of version 2 as the app's are.
  // With `pooled`, it waits in the pool for the next block.
  function foreignCommit(value = 10n ** 18n, { pooled = false } = {}) {
    nonce += 1;
    return appendCommit(sha256("stranger", String(nonce)), value, concat([sha256("n1", String(nonce)), new Uint8Array(NOTE_BYTES - 32)]), {
      salt: sha256("stranger salt", String(nonce)).slice(0, SALT_BYTES),
      pooled,
    });
  }

  // A commit sent by the wallet to the commit entry address (spec 03,
  // section 6, in the layout of the node's ghostpriv commit data): version
  // 0x0002 (2 bytes), F (32), the salt (16), the note (156); or version
  // 0x0001, F and the note. The amount is the value. It refuses what the
  // real node refuses, in its words where it has them, and anything it
  // cannot read as a commit.
  function walletCommit({ to, value, data }, txHash = null) {
    if (typeof to !== "string" || to.toLowerCase() !== String(commitEntry).toLowerCase()) {
      throw new Error("not the commit entry address");
    }
    let payload;
    try {
      payload = fromHex(data);
    } catch {
      throw new Error(COMMIT_DATA_ERROR);
    }
    const is = (version, bytes) => payload.length === bytes && payload[0] === version[0] && payload[1] === version[1];
    let salt = null;
    if (is(SALTED_COMMIT_VERSION, SALTED_COMMIT_DATA_BYTES)) salt = payload.slice(34, 34 + SALT_BYTES);
    else if (!is(COMMIT_VERSION, COMMIT_DATA_BYTES)) throw new Error(`${COMMIT_DATA_ERROR}: ${payload.length} bytes`);
    let v;
    try {
      v = BigInt(value);
    } catch {
      throw new Error("commit amount out of range");
    }
    if (v < 1n || v >= 1n << 96n) throw new Error("commit amount out of range");
    const fingerprint = payload.slice(2, 34);
    if (fingerprint.every((b) => b === 0)) throw new Error("all-zero fingerprint");
    const note = payload.slice(salt ? 34 + SALT_BYTES : 34);
    const result = appendCommit(fingerprint, v, note, { pooled: pool.on, txHash, salt });
    commits.push({ ...result, value: v });
    return result.hash;
  }

  // An account transaction to the commit entry address: the signature
  // checked for this chain and its genesis hash, then the sender's nonce,
  // intrinsic gas and balance as the node checks them, then the commit.
  function accountTx(envelope) {
    if (quirks.refuseAccountTx) throw Object.assign(new Error("txpool is full"), { code: SERVER_ERROR });
    const tx = ghost.accountTxVerify({ chainId, genesis: blocks[0].hash, envelope });
    const from = toHex(tx.sender);
    const next = nonces.get(from) || 0n;
    if (tx.nonce < next) throw new Error(`nonce too low: address ${from}, tx: ${tx.nonce} state: ${next}`);
    if (tx.nonce > next) throw new Error(`nonce too high: address ${from}, tx: ${tx.nonce} state: ${next}`);
    if (tx.gasLimit < ACCOUNT_INTRINSIC_GAS) throw new Error("intrinsic gas too low");
    const balance = balances.get(from) || 0n;
    if (balance < tx.value + tx.gasLimit * tx.maxFeePerGas) throw new Error("insufficient funds for gas * price + value");
    const hash = walletCommit({ to: tx.to ? toHex(tx.to) : null, value: q(tx.value), data: toHex(tx.data) }, toHex(tx.txHash));
    nonces.set(from, next + 1n);
    balances.set(from, balance - tx.value);
    accountTxs.push({ ...tx, hash, from });
    if (quirks.errorAfterAccountTx) {
      // As ghost-node answers eth_sendRawTransaction of type 0x52 after its
      // pool took it: its log line recovers the sender with the plain signer.
      throw Object.assign(new Error("transaction type not supported"), { code: SERVER_ERROR });
    }
    return hash;
  }

  function sendRaw(hex) {
    const raw = fromHex(hex);
    if (raw[0] === 0x52) return accountTx(raw);
    const tip = blocks.length - 1;
    const reveal = ghost.decodeEnvelope({ chainId, domain: blocks[0].hash, envelope: fromHex(hex) });
    const fee = nodeFee(blocks, tip + 1);
    if (reveal.fee !== fee) throw new Error(`fee ${reveal.fee} is not the fee in force, ${fee}`);
    if (!blocks.some((b) => toHex(b.coinTreeRoot) === toHex(reveal.root))) throw new Error("root not eligible");
    if (spent.some((s) => toHex(s.marker) === toHex(reveal.marker))) throw new Error("marker already spent");
    const { stale } = headMoving;
    if (stale && (stale.envelope === null || stale.envelope === String(hex).toLowerCase())) {
      stale.envelope = String(hex).toLowerCase();
      stale.refused += 1;
      headMoving.refused += 1;
      for (let i = 0; i < stale.blocks; i += 1) mine();
      throw Object.assign(new Error(HEAD_MOVED_ERROR), { code: SERVER_ERROR });
    }
    if (headMoving.count > 0 || (headMoving.miner && headMoving.refuseWhileMining)) {
      if (headMoving.count > 0) headMoving.count -= 1;
      headMoving.refused += 1;
      for (let i = 0; i < headMoving.blocks; i += 1) mine();
      // As geth answers it over HTTP: status 200, error code -32000 and the
      // pool's words unwrapped (ghostpool errHeadMoving, through
      // TxPool.Add, SendTx and SubmitTransaction).
      throw Object.assign(new Error(HEAD_MOVED_ERROR), { code: SERVER_ERROR });
    }
    const hash = toHex(reveal.txHash);
    if (held.has(hash)) throw new Error("already known");
    if (headMoving.drops > 0) {
      headMoving.drops -= 1;
      held.set(hash, reveal);
      return hash;
    }
    if (dishonest.withhold) {
      withheld.push({ ...reveal, hash });
      receipts.set(hash, dishonest.withhold(hash, reveal));
      return hash;
    }
    if (pool.entries.some((e) => e.hash === hash)) throw new Error("already known");
    if (pool.entries.some((e) => e.marker && toHex(e.marker) === toHex(reveal.marker))) throw new Error("marker already pending");
    let position = null;
    const entry = {
      hash,
      marker: reveal.marker,
      apply: (n) => {
        // A remainder's salt, if any, is only in its note: none is served.
        leaves.push({ commitment: reveal.remainder, note: reveal.note, salt: null, block: n });
        spent.push({ marker: reveal.marker, block: n });
        position = leaves.length - 1;
        blockReceipts.push({ hash, type: 0x50, logs: [revealLog(position, reveal)] });
      },
      after: (number) => {
        const recipient = toHex(reveal.recipient);
        if (reveal.out > 0n) balances.set(recipient, (balances.get(recipient) || 0n) + reveal.out);
        receipts.set(hash, {
          transactionHash: hash,
          blockNumber: q(number),
          blockHash: toHex(blocks[number].hash),
          status: "0x1",
          type: "0x50",
          marker: toHex(reveal.marker),
          remainder: toHex(reveal.remainder),
          treeIndex: q(treeOf(position)),
          position: q(positionOf(position)),
          note: toHex(reveal.note),
        });
        reveals.push({ ...reveal, hash, block: number });
      },
    };
    if (pool.on) pool.entries.push(entry);
    else entry.after(mine((n) => entry.apply(n)));
    return hash;
  }

  const methods = {
    eth_chainId: () => q(chainId),
    eth_blockNumber: () => q(blocks.length - 1),
    eth_getBlockByNumber: ([tag]) => {
      const n = tag === "latest" ? blocks.length - 1 : Number(BigInt(tag));
      return n < blocks.length ? header(blocks[n]) : null;
    },
    eth_getTransactionReceipt: ([hash]) => receipts.get(String(hash).toLowerCase()) || null,
    // A transaction the node holds (no block yet) or one a block holds; null
    // for one it never took or let go.
    eth_getTransactionByHash: ([hash]) => {
      const h = String(hash).toLowerCase();
      if (held.has(h) || pool.entries.some((e) => e.hash === h)) return { hash: h, blockNumber: null };
      const receipt = receipts.get(h);
      return receipt ? { hash: h, blockNumber: receipt.blockNumber } : null;
    },
    eth_sendRawTransaction: ([hex]) => sendRaw(hex),
    eth_getTransactionCount: ([address]) => q(nonces.get(String(address).toLowerCase()) || 0n),
    eth_getBalance: ([address]) => q(balances.get(String(address).toLowerCase()) || 0n),
    eth_maxPriorityFeePerGas: () => q(quirks.priorityFee ?? PRIORITY_FEE),
    eth_estimateGas: () => q(quirks.estimateGas ?? COMMIT_ESTIMATE_GAS),
    // The page roots of a tree as a plain array of 32-byte roots, `[]` for an
    // empty tree. No data commitment is made here, so `data` has none.
    ghost_getPageRoots: (params) => {
      const [kind, block, treeIndex] = treeArgs(params, 3, 2);
      if (MARKER_KINDS.has(kind)) throw invalid(0, "no page roots for a marker kind");
      if (kind === "data") return [];
      const tree = servedTree(block, treeIndex);
      const roots = ghost.treeRoots(concat(tree.map((l) => l.commitment))).pageRoots.map(toHex);
      return dishonest.pageRoots ? dishonest.pageRoots(roots, treeIndex) : roots;
    },
    // The receipts of the block of that hash, in transaction order, as
    // geth's eth_getBlockReceipts returns them; null for a block it does not
    // know.
    eth_getBlockReceipts: ([hash]) => {
      const block = blocks.find((b) => toHex(b.hash) === String(hash).toLowerCase());
      if (!block) return null;
      return dishonest.receipts ? dishonest.receipts(block.number, structuredClone(block.receipts)) : block.receipts;
    },
    // A coin or data page as `{ kind, treeIndex, page, filled, entries }`; a
    // marker page as `{ count, markers }`. An entry is `{ leaf, note }`, with
    // `salt` (16 bytes of hex) for a version 2 commit's leaf, as the node
    // serves it.
    ghost_getTreePage: (params) => {
      const [kind, block, treeIndex] = treeArgs(params, 4, 3);
      let page;
      try {
        page = Number(quantity(params[2]));
      } catch (err) {
        throw invalid(2, err.message);
      }
      if (page >= MAX_PAGES) throw new Error("page number beyond the tree");
      const start = page * PAGE;
      if (kind === "coin" || kind === "data") {
        const honest = treePage(kind, block, page, treeIndex);
        if (!dishonest.page || kind !== "coin") return honest;
        return dishonest.page(page, honest, (p, k = treeIndex) => treePage(kind, block, p, k), treeIndex);
      }
      let listed = kind === "coin-markers" ? spent.slice(0, block.spentCount).map((s) => toHex(s.marker)) : [];
      if (dishonest.markers && kind === "coin-markers") listed = dishonest.markers(listed);
      const part = listed.slice(start, start + PAGE);
      return { count: q(part.length), markers: part };
    },
  };

  // Coin or data page `page` of tree `treeIndex` as of `block`, with the
  // dishonest notes and salts, if any; those are given the leaf's index in
  // `leaves` (its position, in tree 0).
  function treePage(kind, block, page, treeIndex = 0) {
    const start = page * PAGE;
    const part = kind === "coin" ? (servedTree(block, treeIndex) ?? []).slice(start, start + PAGE) : [];
    const first = (treeIndex === 0 ? 0 : treeIndex * treeLeaves) + start;
    const note = (l, i) => (dishonest.note ? dishonest.note(first + i, l.note) : l.note);
    const entries = part.map((l, i) => {
      const entry = { leaf: toHex(l.commitment), note: toHex(note(l, i)) };
      const salt = dishonest.salt ? dishonest.salt(first + i, l.salt) : l.salt;
      if (salt) entry.salt = typeof salt === "string" ? salt : toHex(salt);
      return entry;
    });
    return { kind, treeIndex: q(treeIndex), page: q(page), filled: q(entries.length), entries };
  }

  // The checks the node makes on a tree page request, in its words: the
  // number of parameters, the kind, the tree index (a coin tree up to the
  // anchor's, 0 for the other kinds) and the anchor, which must be the
  // 32-byte hash of a known block. Returns the kind, the anchor's block and
  // the tree index.
  function treeArgs(params, count, anchorAt) {
    if (params.length < count) throw invalid(null, `missing value for required argument ${params.length}`);
    if (params.length > count) throw invalid(null, `too many arguments, want at most ${count}`);
    const kind = params[0];
    if (!TREE_KINDS.has(kind)) throw invalid(0, "unknown tree kind");
    const anchor = params[anchorAt];
    if (typeof anchor !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(anchor)) {
      throw invalid(anchorAt, "not a 32-byte block hash");
    }
    let treeIndex;
    try {
      treeIndex = quantity(params[1]);
    } catch (err) {
      throw invalid(1, err.message);
    }
    const block = blockByHash(anchor);
    const last = kind === "coin" ? treesOf(served(block)).length - 1 : 0;
    if (treeIndex > BigInt(last)) throw new Error("tree index does not exist at the anchor");
    return [kind, block, Number(treeIndex)];
  }

  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      let id = null;
      let reply;
      try {
        const call = JSON.parse(body);
        id = call.id;
        requests.push({ method: call.method, params: call.params, body });
        if (!Object.hasOwn(methods, call.method)) {
          reply = { jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } };
        } else {
          reply = { jsonrpc: "2.0", id, result: methods[call.method](call.params || []) };
        }
      } catch (err) {
        reply = { jsonrpc: "2.0", id, error: { code: err.code ?? SERVER_ERROR, message: String(err.message || err) } };
      }
      res.writeHead(200, { "content-type": "application/json" });
      // geth ends each reply with a newline.
      res.end(`${JSON.stringify(reply)}\n`);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;

  return {
    url,
    chainId,
    requests,
    reveals,
    commits,
    accountTxs,
    quirks,
    // Gives `address` a balance of `wei`.
    fund(address, wei) {
      balances.set(String(address).toLowerCase(), wei);
    },
    dishonest,
    withheld,
    balances,
    leaves,
    spent,
    blocks,
    tip: () => blocks.length - 1,
    // One more block, with nothing in it.
    mine: () => mine(),
    headMoving,
    // The next `count` sends of a valid reveal are refused as the node does
    // when its head keeps moving, each after `blocks` new empty blocks.
    moveHeadOnReveal(count, { blocks = 0 } = {}) {
      headMoving.count = count;
      headMoving.blocks = blocks;
    },
    // The next valid reveal sent, and every resend of that same envelope, is
    // refused as the node does when its head keeps moving, each after
    // `blocks` new empty blocks; a freshly proved reveal is taken.
    refuseStaleEnvelope({ blocks = 0 } = {}) {
      headMoving.stale = { envelope: null, blocks, refused: 0 };
    },
    // An empty block every `everyMs` ms until stopMining(); meanwhile every
    // send of a valid reveal is refused as the node does when its head keeps
    // moving, unless `refuse` is false. With `commitEvery` set, every
    // `commitEvery`-th block holds a stranger's commit instead, so a settled
    // block soon holds a commitment after any older coin.
    startMining(everyMs, { refuse = true, commitEvery = 0 } = {}) {
      clearInterval(headMoving.miner);
      headMoving.refuseWhileMining = refuse;
      let n = 0;
      headMoving.miner = setInterval(() => {
        n += 1;
        if (commitEvery > 0 && n % commitEvery === 0) foreignCommit();
        else mine();
      }, everyMs);
    },
    stopMining() {
      clearInterval(headMoving.miner);
      headMoving.miner = null;
      headMoving.refuseWhileMining = true;
    },
    // The next `count` valid reveals the node takes are dropped at the next
    // block, before any block holds them.
    dropTaken(count) {
      headMoving.drops = count;
    },
    dropped,
    // With `on`, a commit or reveal waits in the pool for the next block
    // (`pool.entries`) instead of a block of its own at once.
    pool,
    // The last `depth` blocks replaced by `depth + 1` empty ones; the hashes
    // of the transactions taken out are in `reorged`.
    reorg,
    reorged,
    // Blocks mined from now on carry base fee `wei` (each still half full).
    setBaseFee(wei) {
      baseFee = wei;
    },
    // Blocks mined from now on carry difficulty `d` (null: what the
    // schedule requires).
    setDifficulty(d) {
      difficultyOverride = d === null ? null : BigInt(d);
    },
    // The table of networks createFlow takes, with this chain's entry: its
    // constants, genesis and, with `pinAt`, the pinned start at that height
    // (its total work and genesis, the key block of every header here).
    networks({ pinAt = null } = {}) {
      const genesisHash = toHex(blocks[0].hash);
      const pin =
        pinAt === null
          ? null
          : {
              hash: toHex(blocks[pinAt].hash),
              height: pinAt,
              totalWork: 1n + BigInt(pinAt) * scheduled,
              keyBlocks: [[0, genesisHash]],
            };
      const entry = { params: TEST_CHAIN_PARAMS, genesisTimestamp: genesisTime, genesisHash, pin };
      return { [String(chainId)]: entry };
    },
    mineTo(height) {
      while (blocks.length - 1 < height) mine();
    },
    foreignCommits(count) {
      for (let i = 0; i < count; i += 1) foreignCommit();
    },
    // `count` strangers' commits in one new block, one receipt each.
    foreignCommitsInOneBlock(count) {
      for (let i = 0; i < count; i += 1) foreignCommit(10n ** 18n, { pooled: true });
      return mine();
    },
    fee: (height) => nodeFee(blocks, height),
    // A scripted sender of plain commits from one account, for the stand-in's
    // own checks of a commit's fields; the app sends account transactions.
    wallet(account) {
      const calls = [];
      return {
        calls,
        async request({ method, params }) {
          calls.push({ method, params, body: JSON.stringify({ method, params }) });
          if (method === "eth_requestAccounts" || method === "eth_accounts") return [account];
          if (method === "eth_chainId") return q(chainId);
          if (method === "eth_sendTransaction") {
            const [tx] = params;
            if (String(tx.from).toLowerCase() !== account.toLowerCase()) throw new Error("unknown account");
            return walletCommit(tx);
          }
          throw Object.assign(new Error("unsupported"), { code: 4200 });
        },
      };
    },
    close: () => {
      clearInterval(headMoving.miner);
      return new Promise((resolve) => server.close(resolve));
    },
    word,
  };
}
