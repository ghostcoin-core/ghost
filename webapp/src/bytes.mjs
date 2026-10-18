// Byte, hex and amount-word helpers shared by the page, the worker and the
// tests. No dependencies.

export function toHex(bytes) {
  let out = "0x";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

// Hex with or without 0x to bytes; `length`, when given, is enforced.
export function fromHex(text, length) {
  if (typeof text !== "string" || !/^(0x)?([0-9a-fA-F]{2})*$/.test(text)) {
    throw new Error("expected hex bytes");
  }
  const hex = text.startsWith("0x") ? text.slice(2) : text;
  if (length !== undefined && hex.length !== length * 2) {
    throw new Error(`expected ${length} bytes of hex, got ${hex.length / 2}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// A JSON-RPC quantity ("0x1a") to a BigInt.
export function quantity(text) {
  if (typeof text !== "string" || !/^0x[0-9a-fA-F]+$/.test(text)) {
    throw new Error("expected a hex quantity");
  }
  return BigInt(text);
}

export function toQuantity(value) {
  return `0x${BigInt(value).toString(16)}`;
}

// An integer as a 32-byte big-endian word.
export function word(value) {
  let v = BigInt(value);
  if (v < 0n || v >= 1n << 256n) throw new Error("value does not fit a word");
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function fromWord(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

export function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
