// A scripted stand-in for the node's JSON-RPC, for the headless tests: a
// local HTTP server that keeps a chain of headers with the coin tree root,
// the coin tree's leaves and notes, the spent coin markers and receipts, and
// records every request it is sent.
//
// It follows the specifications of this repository: whole pages of 4,096
// leaves with their notes and the page-root list (spec 05, section 8), the
// header roots of spec 05, section 4, the header encoding and hash of spec 05,
// section 10, the private transaction envelope and fee of spec 07, sections 3
// to 5, and the commit of spec 03, section 6.
// A reveal is decoded and its proof verified with the real verifier, then
// checked as a node admits it: fee in force, root of an earlier canonical
// block, marker unused. Commits arrive through the scripted wallet below.
//
// Importing this file runs nothing; the tests start the server.

import { createHash } from "node:crypto";
import { createServer } from "node:http";

import { concat, fromHex, toHex, word } from "../../src/bytes.mjs";

const PAGE = 4096;
const NOTE_BYTES = 156;
const GWEI = 1_000_000_000n;
// Spec 05, vector empty-data-tree: no data commitment is ever made here.
const EMPTY_DATA_ROOT = "0x3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03";
// Spec 05, section 10: the hash of the empty list, and the start difficulty.
const EMPTY_LIST_HASH = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";
const D_START = 1n << 24n;
export const FAKE_CHAIN_ID = 7_777_001n;
// The commit data the node takes (spec 07; ghostpriv.CommitData): version
// 0x0001, F and the note, and the node's words for anything else.
export const COMMIT_VERSION = Uint8Array.of(0x00, 0x01);
export const COMMIT_DATA_BYTES = 2 + 32 + NOTE_BYTES;
export const COMMIT_DATA_ERROR = "commit data is not 190 bytes of version 1";

const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(typeof p === "string" ? p : Buffer.from(p));
  return new Uint8Array(h.digest());
};

const q = (n) => `0x${BigInt(n).toString(16)}`;

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

function headerRlp(json) {
  const items = HEADER_ORDER.map((name) => {
    const bytes = HEADER_INTS.has(name) ? bigEndian(BigInt(json[name])) : fromHex(json[name]);
    return bytes.length === 1 && bytes[0] < 0x80 ? bytes : prefixed(bytes, 0x80);
  });
  return prefixed(concat(items), 0xc0);
}

// The node's own fee of spec 07, section 4, written apart from the app's.
function nodeFee(blocks, height) {
  const start = height - (height % 4);
  const tip = blocks[blocks.length - 1];
  // Every block here is half full, so a child's base fee equals its parent's.
  let price = start < blocks.length ? blocks[start].baseFee : tip.baseFee;
  for (let j = 0; j < 3; j += 1) price = price + price / 8n + price / 20000n + 1n;
  const base = 16_569_156n * price;
  return base + (base + 9n) / 10n;
}

export async function startFakeNode({ ghost, chainId = FAKE_CHAIN_ID, commitEntry }) {
  const leaves = []; // { commitment, note, block }
  const spent = []; // { marker, block }
  const blocks = [];
  const receipts = new Map();
  const balances = new Map();
  const requests = [];
  const reveals = [];
  const commits = [];
  // What a dishonest endpoint does, for the tests that play one:
  // `note(position, note)` replaces each note it serves; with `withhold`
  // set a reveal is not executed: its hash is returned and its receipt
  // lookup answered with `withhold(hash, reveal)`; with `forge` set to
  // { from, extra } the coin tree it serves as of block `from` and later
  // also holds the `extra` leaves ({ commitment, note }), and those blocks'
  // headers carry that tree's root but keep their real hash.
  const dishonest = { note: null, withhold: null, forge: null };
  const withheld = [];
  let nonce = 0;
  // The base fee of the blocks mined from now on.
  let baseFee = GWEI;

  // A block's header fields, with the names of the base client's JSON-RPC.
  function headerFields(number, parentHash, coinTreeRoot) {
    return {
      parentHash: toHex(parentHash),
      sha3Uncles: EMPTY_LIST_HASH,
      miner: toHex(new Uint8Array(20)),
      stateRoot: toHex(sha256("state", String(number))),
      transactionsRoot: toHex(sha256("transactions", String(number))),
      receiptsRoot: toHex(sha256("receipts", String(number))),
      logsBloom: toHex(new Uint8Array(256)),
      difficulty: q(D_START),
      number: q(number),
      gasLimit: q(30_000_000n),
      gasUsed: q(15_000_000n),
      timestamp: q(1_798_767_600 + number * 30),
      extraData: "0x",
      mixHash: toHex(sha256("mix", String(number))),
      nonce: toHex(sha256("nonce", String(number)).slice(0, 8)),
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

  const servedLeaves = (block) => concat(served(block).map((l) => l.commitment));

  function header(block) {
    const json = { ...block.json, hash: toHex(block.hash) };
    if (forged(block)) json.coinTreeRoot = toHex(ghost.treeRoots(servedLeaves(block)).root);
    return json;
  }

  // One new block holding `apply`'s changes.
  function mine(apply = () => {}) {
    const number = blocks.length;
    apply(number);
    const leafCount = leaves.length;
    const coinTreeRoot = ghost.treeRoots(concat(leaves.map((l) => l.commitment))).root;
    const parentHash = number === 0 ? new Uint8Array(32) : blocks[number - 1].hash;
    const json = headerFields(number, parentHash, coinTreeRoot);
    blocks.push({
      number,
      parentHash,
      json,
      hash: ghost.keccak256(headerRlp(json)),
      baseFee,
      coinTreeRoot,
      leafCount,
      spentCount: spent.length,
    });
    return number;
  }

  mine();

  function blockByHash(hash) {
    const block = blocks.find((b) => toHex(b.hash) === String(hash).toLowerCase());
    if (!block) throw new Error("unknown anchor block");
    return block;
  }

  function appendCommit(fingerprint, value, note) {
    const commitment = ghost.coinCommitment(fingerprint, value);
    const hash = toHex(sha256("fake commit", String((nonce += 1))));
    const number = mine((n) => leaves.push({ commitment, note, block: n }));
    receipts.set(hash, { transactionHash: hash, blockNumber: q(number), status: "0x1", type: "0x2" });
    return { hash, commitment };
  }

  // A commit by a stranger: a random fingerprint and a note no key opens.
  function foreignCommit(value = 10n ** 18n) {
    return appendCommit(sha256("stranger", String((nonce += 1))), value, concat([sha256("n1", String(nonce)), new Uint8Array(NOTE_BYTES - 32)]));
  }

  // A commit sent by the wallet to the commit entry address (spec 03,
  // section 6, in the layout of spec 07 and the node's ghostpriv.CommitData):
  // version 0x0001 (2 bytes), F (32), the note (156); the amount is the
  // value. It refuses what the real node refuses, in its words where it has
  // them, and anything it cannot read as a commit.
  function walletCommit({ to, value, data }) {
    if (typeof to !== "string" || to.toLowerCase() !== String(commitEntry).toLowerCase()) {
      throw new Error("not the commit entry address");
    }
    let payload;
    try {
      payload = fromHex(data);
    } catch {
      throw new Error(COMMIT_DATA_ERROR);
    }
    if (payload.length !== COMMIT_DATA_BYTES || payload[0] !== COMMIT_VERSION[0] || payload[1] !== COMMIT_VERSION[1]) {
      throw new Error(COMMIT_DATA_ERROR);
    }
    let v;
    try {
      v = BigInt(value);
    } catch {
      throw new Error("commit amount out of range");
    }
    if (v < 1n || v >= 1n << 96n) throw new Error("commit amount out of range");
    const fingerprint = payload.slice(2, 34);
    if (fingerprint.every((b) => b === 0)) throw new Error("all-zero fingerprint");
    const result = appendCommit(fingerprint, v, payload.slice(34));
    commits.push({ ...result, value: v });
    return result.hash;
  }

  function sendRaw(hex) {
    const tip = blocks.length - 1;
    const reveal = ghost.decodeEnvelope({ chainId, domain: blocks[0].hash, envelope: fromHex(hex) });
    const fee = nodeFee(blocks, tip + 1);
    if (reveal.fee !== fee) throw new Error(`fee ${reveal.fee} is not the fee in force, ${fee}`);
    if (!blocks.some((b) => toHex(b.coinTreeRoot) === toHex(reveal.root))) throw new Error("root not eligible");
    if (spent.some((s) => toHex(s.marker) === toHex(reveal.marker))) throw new Error("marker already spent");
    const hash = toHex(reveal.txHash);
    if (dishonest.withhold) {
      withheld.push({ ...reveal, hash });
      receipts.set(hash, dishonest.withhold(hash, reveal));
      return hash;
    }
    const number = mine((n) => {
      leaves.push({ commitment: reveal.remainder, note: reveal.note, block: n });
      spent.push({ marker: reveal.marker, block: n });
    });
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
      treeIndex: "0x0",
      position: q(leaves.length - 1),
      note: toHex(reveal.note),
    });
    reveals.push({ ...reveal, hash, block: number });
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
    eth_sendRawTransaction: ([hex]) => sendRaw(hex),
    ghost_getPageRoots: ([tree, treeIndex, anchor]) => {
      if (tree !== "coin" || treeIndex !== "0x0") throw new Error("only coin tree 0 exists");
      const { pageRoots } = ghost.treeRoots(servedLeaves(blockByHash(anchor)));
      return { pageRoots: pageRoots.map(toHex) };
    },
    ghost_getTreePage: ([tree, treeIndex, page, anchor]) => {
      if (treeIndex !== "0x0") throw new Error("only tree 0 exists");
      const block = blockByHash(anchor);
      const start = Number(BigInt(page)) * PAGE;
      if (tree === "coin") {
        const part = served(block).slice(start, start + PAGE);
        const note = (l, i) => (dishonest.note ? dishonest.note(start + i, l.note) : l.note);
        return { count: q(part.length), leaves: part.map((l) => toHex(l.commitment)), notes: part.map((l, i) => toHex(note(l, i))) };
      }
      if (tree === "coin-markers") {
        const part = spent.slice(start, Math.min(start + PAGE, block.spentCount));
        return { count: q(part.length), markers: part.map((s) => toHex(s.marker)) };
      }
      throw new Error("unknown tree");
    },
  };

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
        reply = { jsonrpc: "2.0", id, error: { code: -32000, message: String(err.message || err) } };
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(reply));
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
    dishonest,
    withheld,
    balances,
    leaves,
    spent,
    blocks,
    tip: () => blocks.length - 1,
    // One more block, with nothing in it.
    mine: () => mine(),
    // Blocks mined from now on carry base fee `wei` (each still half full).
    setBaseFee(wei) {
      baseFee = wei;
    },
    mineTo(height) {
      while (blocks.length - 1 < height) mine();
    },
    foreignCommits(count) {
      for (let i = 0; i < count; i += 1) foreignCommit();
    },
    fee: (height) => nodeFee(blocks, height),
    // A scripted EIP-1193 provider holding one account on this chain.
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
    close: () => new Promise((resolve) => server.close(resolve)),
    word,
  };
}
