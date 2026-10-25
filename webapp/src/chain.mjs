// Chain arithmetic the wallet does from headers alone: the private
// transaction fee of spec 07, sections 4 and 5, the base client's EIP-1559
// base fee, the settled height of spec 02, section 8, and GHOST amounts.

// Gas of every private transaction (spec 07, sections 2 and 4), the node's
// GhostRevealGas: BYTE_GAS * ENVELOPE_BYTES + BASE_TX_GAS + VERIFY_GAS.
export const G_PRIV = 21_090_372n;
// Blocks for which one fee is in force.
export const FEE_WINDOW = 4;
// Growth steps of headroom in the window price (spec 07, sections 4 and 5).
export const FEE_STEPS = 1;
// The tip is the base-fee part divided by this, rounded up.
export const TIP_DIVISOR = 10n;
// A root a reveal proves against is at least this many blocks below the tip
// (spec 02, section 8; client/src/tree_state.rs SETTLE_DEPTH).
export const SETTLE_DEPTH = 2;
// Blocks, the transaction's own block included, before the app shows a
// commit, reveal or claim Done: the first block that holds it is enough, and
// no block on top is waited for. Spent markers are read at the same depth,
// the tip itself, so a key shows claimed once a block holds its spend.
export const CONFIRMATIONS = 1;
// The smallest Vanish the app sends, in Summon fees (spec 07, section 5,
// "The smallest Vanish"): a wallet rule, the protocol takes 1 wei. A coin
// below the fee has no valid proof, and the base fee can rise before the
// coin is summoned; four fees leave about 12 blocks of 12.5 percent rises.
// It is also the level under which a partial Summon's remainder is warned of.
export const MIN_VANISH_FEES = 4n;
// Base units in one GHOST.
export const DECIMALS = 18;
const ONE = 10n ** BigInt(DECIMALS);
// The largest amount, 2^96 - 1 wei.
export const V_MAX = (1n << 96n) - 1n;

// U_FEE_STEPS, the base fee of the window's first block plus FEE_STEPS
// worst-case growth steps.
export function windowPrice(bRef) {
  let u = BigInt(bRef);
  for (let j = 0; j < FEE_STEPS; j += 1) u = u + u / 8n + u / 20000n + 1n;
  return u;
}

// The largest base fee of an including block for which a reveal with this
// fee passes the cover rule (spec 07, section 5): G_PRIV times that base fee
// is at most the fee.
export function coverLimit(fee) {
  return BigInt(fee) / G_PRIV;
}

// The fee of every private transaction in a window with this price.
export function feeForPrice(price) {
  const basePart = G_PRIV * BigInt(price);
  const tip = (basePart + TIP_DIVISOR - 1n) / TIP_DIVISOR;
  return { basePart, tip, fee: basePart + tip };
}

// The smallest Vanish for the next block after `tipHeader` ({ baseFee,
// gasUsed, gasLimit }): MIN_VANISH_FEES times the fee of a window whose
// first block is that next block.
export function minVanishFor(tipHeader) {
  return MIN_VANISH_FEES * feeForPrice(windowPrice(nextBaseFee(tipHeader))).fee;
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
//
// The result also says whether to `wait` for the next window's fee instead
// of proving for this one: when the next block's base fee is already above
// the fee's cover limit, or fewer than two blocks of the window are left
// (`remaining` counts the next block), a proof made now is likely to lapse
// before a block takes it.
export async function feeForNextBlock(tipHeader, headerAt) {
  const next = tipHeader.number + 1;
  const start = windowStart(next);
  const bRef = start === next ? nextBaseFee(tipHeader) : (await headerAt(start)).baseFee;
  const fee = feeForPrice(windowPrice(bRef));
  const limit = coverLimit(fee.fee);
  const remaining = start + FEE_WINDOW - next;
  const wait = remaining < 2 || nextBaseFee(tipHeader) > limit;
  return { window: start / FEE_WINDOW, ...fee, coverLimit: limit, remaining, wait };
}

// Whether a reveal carrying `fee` is still accepted in block `tip + 1`
// (spec 07, section 5, "Fee of the previous window"): it is the fee of that
// block's window or of the window before it (none before window 0), and the
// block's base fee is within the fee's cover limit.
export async function feeStillAccepted(fee, tipHeader, headerAt) {
  const f = BigInt(fee);
  if (nextBaseFee(tipHeader) > coverLimit(f)) return false;
  const current = await feeForNextBlock(tipHeader, headerAt);
  if (current.fee === f) return true;
  if (current.window === 0) return false;
  const start = current.window * FEE_WINDOW;
  return feeForPrice(windowPrice((await headerAt(start - FEE_WINDOW)).baseFee)).fee === f;
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
