// The flow's pure parts: the fee of spec 07 against its worked examples, the
// base client's base fee, the epoch height, amounts and the save check.

import assert from "node:assert/strict";
import test from "node:test";

import {
  epochHeight,
  feeForNextBlock,
  feeForPrice,
  formatGhost,
  G_PRIV,
  nextBaseFee,
  parseAddress,
  parseGhost,
  windowPrice,
} from "../src/chain.mjs";
import { keyStatus, pickGroups, wrongGroups } from "../src/flow.mjs";

test("window fees match spec 07, section 4", () => {
  assert.equal(G_PRIV, 21_090_372n, "g_priv of the worked examples");
  // [window-genesis]
  assert.equal(windowPrice(1_000_000_000n), 1_424_017_979n);
  assert.deepEqual(feeForPrice(1_424_017_979n), {
    basePart: 30_033_068_911_798_188n,
    tip: 3_003_306_891_179_819n,
    fee: 33_036_375_802_978_007n,
  });
  // [window-next]
  assert.equal(windowPrice(1_100_000_000n), 1_566_419_776n);
  assert.deepEqual(feeForPrice(1_566_419_776n), {
    basePart: 33_036_375_783_996_672n,
    tip: 3_303_637_578_399_668n,
    fee: 36_340_013_362_396_340n,
  });
});

test("the window fee is the node's: GhostRevealGas times U3, plus a tenth rounded up", () => {
  // ghost-node core/ghostpriv WindowFee, written apart from the app's.
  const nodeWindowFee = (bRef) => {
    let u = bRef;
    for (let j = 0; j < 3; j += 1) u = u + u / 8n + u / 20000n + 1n;
    const base = 21_090_372n * u;
    return base + (base + 9n) / 10n;
  };
  for (const bRef of [0n, 1n, 7n, 8n, 875n, 1_000_000_000n, 123_456_789_012n]) {
    assert.equal(feeForPrice(windowPrice(bRef)).fee, nodeWindowFee(bRef), `b_ref ${bRef}`);
  }
  // The real node's refusal "reveal fee is not the window fee: have
  // 218712860, want 278392911" was at a window price of 12 wei.
  assert.equal(windowPrice(7n), 12n);
  assert.equal(feeForPrice(12n).fee, 278_392_911n);
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
  assert.equal((await feeForNextBlock({ number: 5 }, at)).fee, 33_036_375_802_978_007n);
  // Next block 8 starts window 2: its base fee comes from the tip, block 7.
  const tip = { number: 7, baseFee: 1_100_000_000n, gasUsed: 15_000_000n, gasLimit: 30_000_000n };
  const fee = await feeForNextBlock(tip, async () => assert.fail("no header is needed"));
  assert.equal(fee.fee, 36_340_013_362_396_340n);
  assert.equal(fee.window, 2);
});

test("the epoch height is a multiple of 32 at least 12 below the tip", () => {
  assert.equal(epochHeight(11), null);
  assert.equal(epochHeight(12), 0);
  assert.equal(epochHeight(43), 0);
  assert.equal(epochHeight(44), 32);
  assert.equal(epochHeight(75), 32);
  assert.equal(epochHeight(76), 64);
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

test("the save check picks three distinct groups without bias and checks them", () => {
  // Bytes at or above 252 are discarded; the rest give 1 + byte mod 12.
  const script = [255, 253, 252, 11, 23, 11, 0, 7];
  const fixed = (n) => Uint8Array.from({ length: n }, (_, i) => script[i] ?? 0);
  assert.deepEqual(pickGroups(fixed), [1, 8, 12]);
  for (let i = 0; i < 200; i += 1) {
    const groups = pickGroups((n) => crypto.getRandomValues(new Uint8Array(n)));
    assert.equal(new Set(groups).size, 3);
    assert.ok(groups.every((g) => g >= 1 && g <= 12));
    assert.deepEqual([...groups].sort((a, b) => a - b), groups);
  }
  const key = "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417";
  assert.deepEqual(wrongGroups(key, [2, 5, 12], ["2222", "5555", "0417"]), []);
  assert.deepEqual(wrongGroups(key, [2, 5, 12], ["2222", "5556", "0417"]), [5]);
  assert.deepEqual(wrongGroups(key, [2, 5, 12], ["22 22", "5555"]), [12], "a missing group is wrong");
});

test("a key's status: not found, unclaimed or claimed", () => {
  assert.equal(keyStatus([]).status, "not-found");
  const spent = { position: 3, spent: true };
  const live = { position: 9, spent: false };
  assert.deepEqual(keyStatus([spent, live]), { status: "unclaimed", current: live });
  assert.deepEqual(keyStatus([spent]), { status: "claimed", current: null });
});
