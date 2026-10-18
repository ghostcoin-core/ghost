// The plain exports of webapp/wasm (the client library built for
// wasm32-unknown-unknown), with no bindings generator: inputs are copied
// into linear memory, results read back, and both overwritten with zeros
// once used, because they can hold a key's digits.

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
}

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
    return { envelopeBytes: out.u32(), commitPayloadBytes: out.u32() };
  }

  newKey(seed) {
    const out = this.call("ghost_new_key", new Input().bytes(seed, 32).build());
    const text = decoder.decode(out);
    out.fill(0);
    return text;
  }

  checkKey(text) {
    return this.call("ghost_check_key", encoder.encode(text))[0];
  }

  commit({ chainId, amount, seed, key }) {
    const input = new Input().u64(chainId).bytes(word(amount)).bytes(seed, 32).text(key).build();
    const out = new Output(this.call("ghost_commit", input));
    return { commitment: out.take(32), marker: out.take(32), payload: out.rest() };
  }

  // `records`: leaves with their notes (188 bytes each) from position 0;
  // `markers`: spent markers (32 bytes each).
  restore({ chainId, key, records, markers }) {
    const input = new Input().u64(chainId).text(key).records(records, 188).records(markers, 32).build();
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

  // kind: "partial" or "claim". `leaves`: the tree under `root`.
  prove(a) {
    const input = new Input()
      .u64(a.chainId)
      .bytes(a.domain, 32)
      .u8(a.kind === "claim" ? 1 : 0)
      .bytes(a.root, 32)
      .bytes(a.recipient, 20)
      .bytes(word(a.out))
      .bytes(word(a.fee))
      .u64(a.number)
      .bytes(word(a.amount))
      .u32(a.position)
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

  coinCommitment(fingerprint, amount) {
    return this.call("ghost_coin_commitment", new Input().bytes(fingerprint, 32).bytes(word(amount)).build());
  }

  keccak256(bytes) {
    return this.call("ghost_keccak256", Uint8Array.from(bytes));
  }
}

export async function loadGhost(bytes) {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return new Ghost(instance.exports);
}
