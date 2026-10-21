// The plain exports of webapp/wasm (the client library built for
// wasm32-unknown-unknown), with no bindings generator: inputs are copied
// into linear memory, results read back, and both overwritten with zeros
// once used, because they can hold a key's words or digits.

import { concat, fromWord, word } from "./bytes.mjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Builds one input buffer in the layout lib.rs reads: big-endian integers,
// texts as a 4-byte length and their UTF-8 bytes, records as a 4-byte count
// and their bytes.
class Input {
  constructor() {
    this.parts = [];
  }

  bytes(b, length) {
    if (length !== undefined && b.length !== length) throw new Error(`expected ${length} bytes`);
    this.parts.push(Uint8Array.from(b));
    return this;
  }

  u8(n) {
    return this.bytes([n]);
  }

  u32(n) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, n);
    return this.bytes(out);
  }

  u64(n) {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(n));
    return this.bytes(out);
  }

  text(t) {
    const b = encoder.encode(t);
    this.u32(b.length);
    this.parts.push(b);
    return this;
  }

  // `flat` holds `size`-byte records back to back.
  records(flat, size) {
    if (flat.length % size !== 0) throw new Error(`records of ${size} bytes expected`);
    this.u32(flat.length / size);
    return this.bytes(flat);
  }

  build() {
    const out = concat(this.parts);
    for (const p of this.parts) p.fill(0);
    return out;
  }
}

// Reads a result in order.
class Output {
  constructor(bytes) {
    this.bytes = bytes;
    this.at = 0;
  }

  take(n) {
    if (this.at + n > this.bytes.length) throw new Error("the module returned too few bytes");
    const part = this.bytes.slice(this.at, this.at + n);
    this.at += n;
    return part;
  }

  u32() {
    return new DataView(this.take(4).buffer).getUint32(0);
  }

  u64() {
    return new DataView(this.take(8).buffer).getBigUint64(0);
  }

  rest() {
    return this.take(this.bytes.length - this.at);
  }

  // A salt record: 0 and zeros for none, 1 and the 16 bytes.
  salt() {
    const record = this.take(SALT_RECORD_BYTES);
    if (record[0] > 1) throw new Error("the module returned an unknown salt kind");
    return record[0] === 1 ? record.slice(1) : null;
  }
}

// Bytes of a salt beside a leaf, and of a salt record (lib.rs).
export const SALT_BYTES = 16;
const SALT_RECORD_BYTES = 1 + SALT_BYTES;
// A leaf with its note.
export const LEAF_RECORD_BYTES = 32 + 156;
// The commit versions: 2, salted, is what the app sends; 1 only for tests
// that need a coin made before the salt.
export const COMMIT_VERSION = 2;

// The salt record of `salt`, a 16-byte salt or null.
export function saltRecord(salt) {
  const record = new Uint8Array(SALT_RECORD_BYTES);
  if (salt == null) return record;
  if (salt.length !== SALT_BYTES) throw new Error(`a salt is ${SALT_BYTES} bytes`);
  record[0] = 1;
  record.set(salt, 1);
  return record;
}

// The key formats ghost_check_key names by their code.
const KEY_FORMATS = new Map([
  [0x0c, "standard"],
  [0x18, "long"],
  [0x20, "words"],
]);

export class Ghost {
  constructor(exports) {
    this.w = exports;
  }

  call(name, input) {
    const w = this.w;
    const len = input.length;
    const ptr = w.ghost_alloc(Math.max(len, 1));
    new Uint8Array(w.memory.buffer, ptr, len).set(input);
    input.fill(0);
    let rc;
    try {
      rc = w[name](ptr, len);
    } finally {
      new Uint8Array(w.memory.buffer, ptr, len).fill(0);
      w.ghost_free(ptr, Math.max(len, 1));
    }
    if (rc !== 0) {
      const message = decoder.decode(new Uint8Array(w.memory.buffer, w.ghost_error_ptr(), w.ghost_error_len()));
      throw new Error(message);
    }
    const out = new Uint8Array(w.memory.buffer, w.ghost_out_ptr(), w.ghost_out_len()).slice();
    w.ghost_clear();
    return out;
  }

  constants() {
    const out = new Output(this.call("ghost_constants", new Uint8Array(0)));
    return { envelopeBytes: out.u32(), commitPayloadBytes: out.u32(), commitV1PayloadBytes: out.u32() };
  }

  // A new key in the default format: 24 words separated by single spaces.
  newKey(seed) {
    return this.text("ghost_new_key", new Input().bytes(seed, 32).build());
  }

  // A typed key, words or digits, checked with its check before anything
  // is derived: its format ("words", "standard" or "long") and the groups
  // of its digit view (21, 12 or 24). A refusal names no word or digit.
  checkKey(text) {
    const [code, groups] = this.call("ghost_check_key", encoder.encode(text));
    const format = KEY_FORMATS.get(code);
    if (!format) throw new Error("the module returned an unknown key format");
    return { format, groups };
  }

  // A key's digit view: 21 groups of four digits for a words key.
  keyDigits(text) {
    return this.text("ghost_key_digits", encoder.encode(text));
  }

  // The commit of a key's first coin: version 2 (206 bytes, a fresh salt
  // from `seed`) unless a test asks for version 1 (190 bytes).
  commit({ chainId, amount, seed, key, version = COMMIT_VERSION }) {
    const input = new Input().u8(version).u64(chainId).bytes(word(amount)).bytes(seed, 32).text(key).build();
    const out = new Output(this.call("ghost_commit", input));
    return { commitment: out.take(32), marker: out.take(32), payload: out.rest() };
  }

  // `records`: leaves with their notes (188 bytes each) from position 0;
  // `salts`: the salt read beside each leaf (16 bytes, or null), one per
  // leaf, all null when not given; `markers`: spent markers (32 bytes each).
  // Each coin found carries its salt, null for a version 1 coin.
  restore({ chainId, key, records, salts = null, markers }) {
    const count = records.length / LEAF_RECORD_BYTES;
    if (salts !== null && salts.length !== count) throw new Error("one salt (or null) is expected per leaf");
    const saltRecords = concat(Array.from({ length: count }, (_, i) => saltRecord(salts?.[i] ?? null)));
    const input = new Input()
      .u64(chainId)
      .text(key)
      .records(records, LEAF_RECORD_BYTES)
      .records(saltRecords, SALT_RECORD_BYTES)
      .records(markers, 32)
      .build();
    const out = new Output(this.call("ghost_restore", input));
    const found = [];
    for (let n = out.u32(); n > 0; n -= 1) {
      found.push({
        number: out.u64(),
        amount: fromWord(out.take(32)),
        position: out.u32(),
        commitment: out.take(32),
        marker: out.take(32),
        spent: out.take(1)[0] === 1,
        salt: out.salt(),
      });
    }
    return found;
  }

  treeCheck({ pageRoots, leaves, root }) {
    this.call("ghost_tree_check", new Input().records(pageRoots, 32).records(leaves, 32).bytes(root, 32).build());
  }

  treeRoots(leaves) {
    const out = new Output(this.call("ghost_tree_roots", new Input().records(leaves, 32).build()));
    const root = out.take(32);
    const pageRoots = [];
    while (out.at < out.bytes.length) pageRoots.push(out.take(32));
    return { root, pageRoots };
  }

  prefixRoots(leaves, from, to) {
    const out = new Output(this.call("ghost_prefix_roots", new Input().u32(from).u32(to).records(leaves, 32).build()));
    const roots = [];
    while (out.at < out.bytes.length) roots.push(out.take(32));
    return roots;
  }

  chooseTreeState({ tip, leafHeight, leafRoot, height, root }) {
    const input = new Input().u64(tip).u64(leafHeight).bytes(leafRoot, 32).u64(height).bytes(root, 32).build();
    return this.call("ghost_choose_tree_state", input)[0] === 1;
  }

  // kind: "partial" or "claim". `leaves`: the tree under `root`. `salt`: the
  // coin's salt from restore, null for a version 1 coin. With `decoy`, the
  // same work for a throwaway key (lib.rs, ghost_prove), of a salted coin
  // unless `salted` is false.
  prove(a) {
    const salt = a.decoy ? (a.salted === false ? null : new Uint8Array(SALT_BYTES)) : (a.salt ?? null);
    const input = new Input()
      .u64(a.chainId)
      .bytes(a.domain, 32)
      .u8((a.kind === "claim" ? 1 : 0) + (a.decoy ? 2 : 0))
      .bytes(a.root, 32)
      .bytes(a.recipient, 20)
      .bytes(word(a.out))
      .bytes(word(a.fee))
      .u64(a.number)
      .bytes(word(a.amount))
      .u32(a.position)
      .bytes(saltRecord(salt))
      .records(a.leaves, 32)
      .bytes(a.seed, 32)
      .bytes(a.zk, 32)
      .text(a.key);
    if (a.kind === "claim") input.text(a.newKey);
    const out = new Output(this.call("ghost_prove", input.build()));
    return {
      txHash: out.take(32),
      marker: out.take(32),
      remainder: { commitment: out.take(32), number: out.u64(), amount: fromWord(out.take(32)) },
      envelope: out.rest(),
    };
  }

  decodeEnvelope({ chainId, domain, envelope }) {
    const out = new Output(
      this.call("ghost_decode_envelope", new Input().u64(chainId).bytes(domain, 32).bytes(envelope).build()),
    );
    return {
      txHash: out.take(32),
      marker: out.take(32),
      root: out.take(32),
      remainder: out.take(32),
      recipient: out.take(20),
      out: fromWord(out.take(32)),
      fee: fromWord(out.take(32)),
      note: out.take(156),
    };
  }

  // `C` as the node computes it from a commit's `F`, amount and version.
  coinCommitment(fingerprint, amount, version) {
    if (version !== 1 && version !== 2) throw new Error("the commit version is 1 or 2");
    return this.call("ghost_coin_commitment", new Input().bytes(fingerprint, 32).bytes(word(amount)).u8(version).build());
  }

  // A new wallet seed's 24 words from 32 random bytes.
  walletNew(seed) {
    return this.text("ghost_wallet_new", new Input().bytes(seed, 32).build());
  }

  // A text result, its bytes overwritten with zeros once decoded.
  text(name, input) {
    const out = this.call(name, input);
    const text = decoder.decode(out);
    out.fill(0);
    return text;
  }

  // Account `index` of a wallet seed: its address and ML-DSA-44 public key.
  walletAccount(words, index) {
    const out = new Output(this.call("ghost_wallet_account", new Input().text(words).u32(index).build()));
    return { address: out.take(20), publicKey: out.rest() };
  }

  // An account transaction (type 0x52) signed with account `index`; `to`
  // null is a contract creation. Returns its hash, sender and envelope.
  walletSign(a) {
    const input = new Input()
      .text(a.words)
      .u32(a.index)
      .u64(a.chainId)
      .bytes(a.genesis, 32)
      .u64(a.nonce)
      .bytes(word(a.maxPriorityFeePerGas))
      .bytes(word(a.maxFeePerGas))
      .u64(a.gasLimit);
    if (a.to === null) input.u8(0);
    else input.u8(1).bytes(a.to, 20);
    input.bytes(word(a.value)).u32(a.data.length).bytes(a.data).bytes(a.seed, 32);
    const out = new Output(this.call("ghost_wallet_sign", input.build()));
    return { txHash: out.take(32), sender: out.take(20), envelope: out.rest() };
  }

  // An account transaction decoded and checked as the node's signer does.
  accountTxVerify({ chainId, genesis, envelope }) {
    const input = new Input().u64(chainId).bytes(genesis, 32).bytes(envelope).build();
    const out = new Output(this.call("ghost_account_tx_verify", input));
    const txHash = out.take(32);
    const sender = out.take(20);
    const nonce = out.u64();
    const gasLimit = out.u64();
    const maxPriorityFeePerGas = fromWord(out.take(32));
    const maxFeePerGas = fromWord(out.take(32));
    const hasTo = out.take(1)[0] === 1;
    const to = out.take(20);
    return {
      txHash,
      sender,
      nonce,
      gasLimit,
      maxPriorityFeePerGas,
      maxFeePerGas,
      to: hasTo ? to : null,
      value: fromWord(out.take(32)),
      data: out.rest(),
    };
  }

  keccak256(bytes) {
    return this.call("ghost_keccak256", Uint8Array.from(bytes));
  }

  // Starts the module's header chain, replacing any chain it held. `params`:
  // the chain constants; `start`: { header } for genesis, or { header,
  // height, totalWork, genesisTimestamp, keyBlocks: [[height, hash]] } for a
  // pinned header. Returns the start's hash.
  chainStart({ params, start }) {
    const input = new Input()
      .u64(params.blockTime)
      .u64(params.halfLife)
      .u64(params.startDifficulty)
      .u64(params.minDifficulty)
      .u64(params.futureDrift);
    if (start.height === undefined) {
      input.u8(0);
    } else {
      input.u8(1).u64(start.height).bytes(word(start.totalWork)).u64(start.genesisTimestamp);
      input.u32(start.keyBlocks.length);
      for (const [height, hash] of start.keyBlocks) input.u64(height).bytes(hash, 32);
    }
    return this.call("ghost_chain_start", input.bytes(start.header).build());
  }

  // Adds `headers` ([{ hash, rlp }], in order) to the chain, with the
  // page's clock `now` in Unix seconds; stops at the first one refused.
  chainAdd({ now, headers }) {
    const input = new Input().u64(now).u32(headers.length);
    for (const { hash, rlp } of headers) input.bytes(hash, 32).u32(rlp.length).bytes(rlp);
    const out = new Output(this.call("ghost_chain_add", input.build()));
    const adopted = out.u32();
    let refused = null;
    if (out.take(1)[0] === 1) {
      const number = out.u64();
      const why = ["", "hash", "ahead", "check"][out.take(1)[0]];
      refused = { number, why, reason: decoder.decode(out.take(out.u32())) };
    }
    return { adopted, refused, best: readBest(out), removed: out.u64() };
  }

  // The chain seen from header `hash`: the best tip, whether `hash` is held,
  // its total work and its confirmations on the best chain (0 when it is
  // not on it), and the best chain's hashes at heights `from` to `to`.
  chainView({ hash, from, to }) {
    const out = new Output(this.call("ghost_chain_view", new Input().bytes(hash, 32).u64(from).u64(to).build()));
    const best = readBest(out);
    const held = out.take(1)[0] === 1;
    const work = fromWord(out.take(32));
    const confirmations = out.u64();
    const hashes = [];
    while (out.at < out.bytes.length) hashes.push(out.take(32));
    return { best, held, work, confirmations, hashes };
  }
}

// The best chain's tip as the module writes it.
function readBest(out) {
  return { height: out.u64(), hash: out.take(32), work: fromWord(out.take(32)) };
}

export async function loadGhost(bytes) {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return new Ghost(instance.exports);
}
