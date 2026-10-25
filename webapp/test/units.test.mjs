// The flow's pure parts: the fee of spec 07 against its worked examples, the
// base client's base fee, the settled height, amounts and the save check on
// a key's words.

import assert from "node:assert/strict";
import test from "node:test";

import {
  coverLimit,
  FEE_STEPS,
  feeForNextBlock,
  feeForPrice,
  feeStillAccepted,
  formatGhost,
  G_PRIV,
  nextBaseFee,
  parseAddress,
  parseGhost,
  SETTLE_DEPTH,
  settledHeight,
  windowPrice,
} from "../src/chain.mjs";
import { keyStatus, normalKey, pickGroups, wrongWords } from "../src/flow.mjs";

test("window fees match spec 07, section 4", () => {
  assert.equal(G_PRIV, 21_090_372n, "g_priv of the worked examples");
  // [window-genesis]
  assert.equal(windowPrice(1_000_000_000n), 1_125_050_001n);
  assert.deepEqual(feeForPrice(1_125_050_001n), {
    basePart: 23_727_723_039_690_372n,
    tip: 2_372_772_303_969_038n,
    fee: 26_100_495_343_659_410n,
  });
  assert.equal(coverLimit(26_100_495_343_659_410n), 1_237_555_001n);
  // [window-next]
  assert.equal(windowPrice(1_100_000_000n), 1_237_555_001n);
  assert.deepEqual(feeForPrice(1_237_555_001n), {
    basePart: 26_100_495_341_550_372n,
    tip: 2_610_049_534_155_038n,
    fee: 28_710_544_875_705_410n,
  });
  assert.equal(coverLimit(28_710_544_875_705_410n), 1_361_310_501n);
});

test("the window price is one growth step above b_ref", () => {
  assert.equal(FEE_STEPS, 1);
  assert.equal(windowPrice(1_000_000_000n), 1_125_050_001n);
  assert.equal(windowPrice(1_100_000_000n), 1_237_555_001n);
  assert.equal(windowPrice(7n), 8n);
  assert.equal(windowPrice(0n), 1n);
});

test("the window fee is the node's: GhostRevealGas times U1, plus a tenth rounded up", () => {
  // ghost-node core/ghostpriv WindowFee, written apart from the app's.
  const nodeWindowFee = (bRef) => {
    let u = bRef;
    for (let j = 0; j < 1; j += 1) u = u + u / 8n + u / 20000n + 1n;
    const base = 21_090_372n * u;
    return base + (base + 9n) / 10n;
  };
  for (const bRef of [0n, 1n, 7n, 8n, 875n, 1_000_000_000n, 123_456_789_012n]) {
    assert.equal(feeForPrice(windowPrice(bRef)).fee, nodeWindowFee(bRef), `b_ref ${bRef}`);
  }
  // At b_ref 7 wei the window price is 8 wei.
  assert.equal(windowPrice(7n), 8n);
  assert.equal(feeForPrice(8n).fee, 185_595_274n);
});

// A half-full header: its child's base fee equals its own.
const half = (number, baseFee) => ({ number, baseFee, gasUsed: 15_000_000n, gasLimit: 30_000_000n });

test("the wallet waits when the cover limit is passed", async () => {
  const GENESIS_FEE = 26_100_495_343_659_410n;
  const headers = new Map([[4, half(4, 1_000_000_000n)]]);
  const at = async (n) => headers.get(n);
  // At a window start the base fee is b_ref, well within the cover limit.
  const start = await feeForNextBlock(half(3, 1_000_000_000n), at);
  assert.equal(start.fee, GENESIS_FEE);
  assert.equal(start.coverLimit, 1_237_555_001n);
  assert.equal(start.remaining, 4);
  assert.equal(start.wait, false);
  // Next block 5: the window's fee is still b_ref's, but the next block's
  // base fee is already past its cover limit.
  const at5 = (baseFee) => feeForNextBlock(half(4, baseFee), at);
  const high = await at5(1_237_555_002n);
  assert.equal(high.fee, GENESIS_FEE);
  assert.equal(high.remaining, 3);
  assert.equal(high.wait, true);
  assert.equal((await at5(1_237_555_001n)).wait, false, "at the cover limit itself the fee still covers");
  // A full tip whose child's base fee passes the limit.
  const full = { number: 5, baseFee: 1_200_000_000n, gasUsed: 30_000_000n, gasLimit: 30_000_000n };
  assert.ok(nextBaseFee(full) > 1_237_555_001n);
  assert.equal((await feeForNextBlock(full, at)).wait, true);
  // At a low base fee: two blocks left is enough, one is not.
  const two = await feeForNextBlock(half(5, 1_000_000_000n), at);
  assert.equal(two.remaining, 2);
  assert.equal(two.wait, false);
  const one = await feeForNextBlock(half(6, 1_000_000_000n), at);
  assert.equal(one.remaining, 1);
  assert.equal(one.wait, true);
});

test("a fee of the previous window is still accepted while the cover limit holds", async () => {
  const GENESIS_FEE = 26_100_495_343_659_410n;
  const NEXT_FEE = 28_710_544_875_705_410n;
  const headers = new Map([
    [0, half(0, 1_000_000_000n)],
    [4, half(4, 1_000_000_000n)],
    [8, half(8, 1_100_000_000n)],
    [12, half(12, 1_100_000_000n)],
  ]);
  const at = async (n) => headers.get(n);
  // [lapse-previous-window]: window 1's fee in window 2, at a base fee above
  // its price but within its cover limit.
  assert.equal((await feeForNextBlock(half(8, 1_150_000_000n), at)).fee, NEXT_FEE);
  assert.equal(await feeStillAccepted(GENESIS_FEE, half(8, 1_150_000_000n), at), true);
  assert.equal(await feeStillAccepted(GENESIS_FEE, half(8, 1_237_555_001n), at), true);
  // [lapse-cover-fails]: the same fee above its cover limit.
  assert.equal(await feeStillAccepted(GENESIS_FEE, half(8, 1_250_000_000n), at), false);
  assert.equal(await feeStillAccepted(GENESIS_FEE, half(8, 1_237_555_002n), at), false);
  // The current window's fee, held to the cover rule as well.
  assert.equal(await feeStillAccepted(NEXT_FEE, half(8, 1_150_000_000n), at), true);
  assert.equal(await feeStillAccepted(NEXT_FEE, half(8, 1_361_310_502n), at), false);
  // [lapse-two-windows]: two windows on, neither fee matches.
  assert.equal(await feeStillAccepted(GENESIS_FEE, half(12, 1_100_000_000n), at), false);
  assert.equal(await feeStillAccepted(NEXT_FEE, half(12, 1_100_000_000n), at), true);
  // Window 0 has no window before it: only its own fee is accepted.
  const lower = feeForPrice(windowPrice(900_000_000n)).fee;
  assert.equal(await feeStillAccepted(GENESIS_FEE, half(1, 1_000_000_000n), at), true);
  assert.equal(await feeStillAccepted(lower, half(1, 1_000_000_000n), at), false);
  // Any other fee is refused.
  assert.equal(await feeStillAccepted(GENESIS_FEE + 1n, half(8, 1_000_000_000n), at), false);
  assert.equal(await feeStillAccepted(GENESIS_FEE - 1n, half(5, 1_000_000_000n), at), false);
});

test("the base fee follows the base client's rule (spec 07, growth example)", () => {
  // [growth-genesis-full-blocks]: every block full at a gas limit of 30,000,001.
  const fees = [1_000_000_000n];
  for (let i = 0; i < 3; i += 1) {
    fees.push(nextBaseFee({ baseFee: fees[i], gasUsed: 30_000_001n, gasLimit: 30_000_001n }));
  }
  assert.deepEqual(fees, [1_000_000_000n, 1_125_000_008n, 1_265_625_018n, 1_423_828_155n]);
  assert.equal(nextBaseFee({ baseFee: 1000n, gasUsed: 15n, gasLimit: 30n }), 1000n);
  assert.equal(nextBaseFee({ baseFee: 1000n, gasUsed: 0n, gasLimit: 30n }), 875n);
  assert.equal(nextBaseFee({ baseFee: 7n, gasUsed: 16n, gasLimit: 30n }), 8n, "at least one wei up");
});

test("the fee uses the window's first block", async () => {
  const headers = new Map([
    [4, { number: 4, baseFee: 1_000_000_000n }],
    [8, { number: 8, baseFee: 1_100_000_000n }],
  ]);
  const at = async (n) => headers.get(n);
  // Next block 6 is in window 1, which starts at block 4.
  const in1 = await feeForNextBlock({ number: 5, baseFee: 1_000_000_000n, gasUsed: 15_000_000n, gasLimit: 30_000_000n }, at);
  assert.equal(in1.fee, 26_100_495_343_659_410n);
  assert.equal(in1.window, 1);
  // Next block 8 starts window 2: its base fee comes from the tip, block 7.
  const tip = { number: 7, baseFee: 1_100_000_000n, gasUsed: 15_000_000n, gasLimit: 30_000_000n };
  const fee = await feeForNextBlock(tip, async () => assert.fail("no header is needed"));
  assert.equal(fee.fee, 28_710_544_875_705_410n);
  assert.equal(fee.window, 2);
});

test("the settled height is 2 below the tip, at any height", () => {
  assert.equal(SETTLE_DEPTH, 2);
  assert.equal(settledHeight(1), null);
  assert.equal(settledHeight(2), 0);
  assert.equal(settledHeight(43), 41);
  assert.equal(settledHeight(44), 42);
  assert.equal(settledHeight(77), 75);
});

test("GHOST amounts and addresses", () => {
  assert.equal(parseGhost("1"), 10n ** 18n);
  assert.equal(parseGhost(" 0.25 "), 25n * 10n ** 16n);
  assert.equal(parseGhost("0.000000000000000001"), 1n);
  assert.throws(() => parseGhost("1e3"), /amount in GHOST/);
  assert.throws(() => parseGhost("-1"), /amount in GHOST/);
  assert.throws(() => parseGhost("0.0000000000000000001"), /amount in GHOST/);
  assert.throws(() => parseGhost("80000000000"), /largest amount/);
  assert.equal(formatGhost(1_250_000_000_000_000_000n), "1.25");
  assert.equal(formatGhost(10n ** 18n), "1");
  assert.equal(parseAddress(" 0xABCDEFabcdef0123456789abcdef0123456789aB "), "0xabcdefabcdef0123456789abcdef0123456789ab");
  assert.throws(() => parseAddress("0x1234"), /40 hex digits/);
});

test("the save check picks three distinct words of 24 without bias and checks them", () => {
  // Bytes at or above 240 are discarded; the rest give 1 + byte mod 24.
  const script = [255, 241, 240, 23, 47, 23, 0, 7];
  const fixed = (n) => Uint8Array.from({ length: n }, (_, i) => script[i] ?? 0);
  assert.deepEqual(pickGroups(fixed), [1, 8, 24]);
  const seen = new Set();
  for (let i = 0; i < 400; i += 1) {
    const words = pickGroups((n) => crypto.getRandomValues(new Uint8Array(n)));
    assert.equal(new Set(words).size, 3);
    assert.ok(words.every((g) => g >= 1 && g <= 24));
    assert.deepEqual([...words].sort((a, b) => a - b), words);
    for (const w of words) seen.add(w);
  }
  assert.equal(seen.size, 24, "every word can be asked");
  // The words of the wallet's seed, the same rule.
  assert.deepEqual(pickGroups(fixed, 24), [1, 8, 24]);
  const key = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth various";
  assert.deepEqual(wrongWords(key, [2, 5, 24], ["winner", "wave", "various"]), []);
  assert.deepEqual(wrongWords(key, [2, 5, 24], [" WINNER ", "Wave", "VARIOUS"]), [], "in any case");
  assert.deepEqual(wrongWords(key, [2, 5, 24], ["winner", "wav", "various"]), [5], "a word typed whole");
  assert.deepEqual(wrongWords(key, [2, 5, 24], ["winner", "wave"]), [24], "a missing word is wrong");
});

test("a typed key is passed on with its white space made single spaces", () => {
  assert.equal(normalKey("  Legal\nWINNER\t thank-year  "), "Legal WINNER thank-year");
  assert.equal(normalKey("1111 2222\n3333"), "1111 2222 3333");
});

test("a key's status: not found, unclaimed or claimed", () => {
  assert.equal(keyStatus([]).status, "not-found");
  const spent = { position: 3, spent: true };
  const live = { position: 9, spent: false };
  assert.deepEqual(keyStatus([spent, live]), { status: "unclaimed", current: live });
  assert.deepEqual(keyStatus([spent]), { status: "claimed", current: null });
});
