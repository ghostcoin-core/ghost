// Chain arithmetic the wallet does from headers alone: the private
// transaction fee of spec 07, sections 4 and 5, the base client's EIP-1559
// base fee, the settled height of spec 02, section 8, and GHOST amounts.

// Gas of every private transaction (spec 07, sections 2 and 4), the node's
// GhostRevealGas: BYTE_GAS * ENVELOPE_BYTES + BASE_TX_GAS + VERIFY_GAS.
export const G_PRIV = 21_090_372n;
// Blocks for which one fee is in force.
export const FEE_WINDOW = 4;
// The tip is the base-fee part divided by this, rounded up.
export const TIP_DIVISOR = 10n;
// A root a reveal proves against is at least this many blocks below the tip
// (spec 02, section 8; client/src/tree_state.rs SETTLE_DEPTH).
export const SETTLE_DEPTH = 2;
// Blocks on top of a transaction's block before the app shows it confirmed,
// and on top of a spent marker before a key shows claimed.
export const CONFIRMATIONS = 6;
// Base units in one GHOST.
export const DECIMALS = 18;
const ONE = 10n ** BigInt(DECIMALS);
// The largest amount, 2^96 - 1 wei.
export const V_MAX = (1n << 96n) - 1n;

// U_(W-1), the ceiling started from the base fee of the window's first block.
export function windowPrice(bRef) {
  let u = BigInt(bRef);
  for (let j = 0; j < FEE_WINDOW - 1; j += 1) u = u + u / 8n + u / 20000n + 1n;
  return u;
}

// The fee of every private transaction in a window with this price.
export function feeForPrice(price) {
  const basePart = G_PRIV * BigInt(price);
  const tip = (basePart + TIP_DIVISOR - 1n) / TIP_DIVISOR;
  return { basePart, tip, fee: basePart + tip };
}

// The base fee of a child of `parent` ({ baseFee, gasUsed, gasLimit }).
export function nextBaseFee({ baseFee, gasUsed, gasLimit }) {
  const b = BigInt(baseFee);
  const u = BigInt(gasUsed);
  const t = BigInt(gasLimit) / 2n;
  if (t === 0n || u === t) return b;
  if (u > t) {
    const step = ((u - t) * b) / t / 8n;
    return b + (step > 1n ? step : 1n);
  }
  return b - ((t - u) * b) / t / 8n;
}

// The first block of the window that holds block `height`.
export function windowStart(height) {
  return height - (height % FEE_WINDOW);
}

// The fee a reveal must carry to be included in block `tip + 1`. The base
// fee of the window's first block is read from its header, or computed from
// the tip's header when that block is the next one.
export async function feeForNextBlock(tipHeader, headerAt) {
  const next = tipHeader.number + 1;
  const start = windowStart(next);
  const bRef = start === next ? nextBaseFee(tipHeader) : (await headerAt(start)).baseFee;
  return { window: start / FEE_WINDOW, ...feeForPrice(windowPrice(bRef)) };
}

// The height of the newest settled block for this tip, the one whose root a
// reveal proves against, or null when there is none yet.
export function settledHeight(tip) {
  return tip < SETTLE_DEPTH ? null : tip - SETTLE_DEPTH;
}

// "1.25" GHOST to wei. Up to 18 decimals; no exponent, no sign.
export function parseGhost(text) {
  const t = String(text).trim();
  const m = /^(\d+)(?:\.(\d{1,18}))?$/.exec(t);
  if (!m) throw new Error("enter an amount in GHOST, for example 1.5");
  const wei = BigInt(m[1]) * ONE + BigInt((m[2] || "").padEnd(DECIMALS, "0"));
  if (wei > V_MAX) throw new Error("the amount is above the largest amount a coin can hold");
  return wei;
}

export function formatGhost(wei) {
  const v = BigInt(wei);
  const whole = v / ONE;
  const frac = (v % ONE).toString().padStart(DECIMALS, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}

// A 20-byte address as 0x and 40 hex digits.
export function parseAddress(text) {
  const t = String(text).trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(t)) throw new Error("enter an address as 0x followed by 40 hex digits");
  return t.toLowerCase();
}
