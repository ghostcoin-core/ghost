// A block header as the endpoint returns it, re-encoded so its hash can be
// recomputed: the RLP list of the 18 fields of spec 05, section 10 (fields
// 0 to 14 of the base header, the base fee, coinTreeRoot, dataTreeRoot),
// whose keccak256 is the block hash. The app hashes it in the worker and
// keeps a header only when that hash is the one the endpoint returned.

import { concat, fromHex, quantity } from "./bytes.mjs";

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
