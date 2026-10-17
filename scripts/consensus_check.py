#!/usr/bin/env python3
"""Reproduces the numbers in docs/spec/06-consensus-and-emission.md.

Python standard library only. Written from the formulas in the specification
and independent of any node code. It prints:

  1. the emission schedule (cumulative issuance at 30 and 60 second blocks),
     checked against a high-precision decimal evaluation of the same curve;
  2. the ASERT test vectors, checked against a decimal evaluation of 2^x;
  3. the miner-departure and starting-difficulty tables (closed form), with a
     seeded Monte Carlo cross-check;
  4. the half-life comparison.

Usage:
    python3 scripts/consensus_check.py              # everything (about a minute)
    python3 scripts/consensus_check.py --skip-emission
    python3 scripts/consensus_check.py --section emission   # one section

Sections: emission, alternatives, asert, blocktime, departure, start, halflife, mc.
Exit status is non-zero if any internal check fails.
"""

import argparse
import math
import random
import sys
from decimal import Decimal, getcontext

getcontext().prec = 90

# ---------------------------------------------------------------------------
# Constants (specification sections 3, 6 and 8)
# ---------------------------------------------------------------------------

WEI = 10**18
SECONDS_PER_YEAR = 365 * 86400                  # 31,536,000
HALF_LIFE_SECONDS = 2 * SECONDS_PER_YEAR        # emission half-life: 2 years

# Emission, stated for 30-second blocks. A 60-second chain doubles the reward
# and the tail and halves the number of blocks per half-life.
R0_30 = 6_923_560_000_000_000_000               # 6.92356 GHOST
TAIL_30 = 200_000_000_000_000_000               # 0.2 GHOST
MAIN_TARGET = 21_000_000 * WEI

F = 128                                         # fixed-point fraction bits
ONE = 1 << F
TERMS = 24                                      # Taylor terms for e^-u
LN2_FIXED = 0xB17217F7D1CF79ABC9E3B39803F2F6AF  # floor(ln 2 * 2^128)

# Difficulty (specification section 3)
BLOCK_TIME = 30
HALF_LIFE_ASERT = 3600                          # tau, seconds
RADIX = 1 << 16
D_START = 1 << 24
D_MIN = 1 << 17
M256 = (1 << 256) - 1
MAX_TARGET = M256 // D_MIN
FUTURE_DRIFT = 30                               # seconds

checks_failed = []


def check(ok, message):
    if not ok:
        checks_failed.append(message)
        print("CHECK FAILED: " + message)


def ghost(wei, places=6):
    """Format wei as GHOST, truncated (never rounded) to `places` decimals."""
    whole, frac = divmod(wei, WEI)
    return f"{whole:,}.{frac // 10 ** (18 - places):0{places}d}"


def pct(num, den, places=2):
    scaled = num * 10 ** (places + 2) // den
    return f"{scaled // 10 ** places}.{scaled % 10 ** places:0{places}d}"


def table(header, rows):
    out = ["| " + " | ".join(header) + " |",
           "|" + "|".join("---" for _ in header) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

def params(block_time):
    """(half-life in blocks, blocks per year, first reward, tail) for a block time."""
    if block_time not in (30, 60):
        raise ValueError("block time must be 30 or 60 seconds")
    half = HALF_LIFE_SECONDS // block_time
    return half, half // 2, R0_30 * block_time // 30, TAIL_30 * block_time // 30


def exp_neg_fixed(r, half):
    """e^(-(r/half) ln 2) = 2^(-r/half) as an integer scaled by 2^F, r < half."""
    u = (r * LN2_FIXED) // half
    s = ONE
    for k in range(TERMS, 0, -1):
        s = ONE - ((u * s) >> F) // k
    return s


def reward(height, block_time=30):
    """Block reward in wei for the block at `height` (height 0 has none)."""
    if height < 1:
        return 0
    half, _, r0, tail = params(block_time)
    q, r = divmod(height - 1, half)
    q = min(q, 255)
    decayed = (r0 * exp_neg_fixed(r, half)) >> (F + q)
    return decayed if decayed > tail else tail


def reward_decimal(height, block_time=30):
    """Independent check: floor(R0 * 2^(-(h-1)/half)) with 90-digit decimals."""
    half, _, r0, tail = params(block_time)
    value = Decimal(r0) * (Decimal(2) ** (-Decimal(height - 1) / Decimal(half)))
    return max(int(value), tail)


def era_sums(block_time):
    """Per half-life era q (0..5) and half (first or second year of the era):
    the sum of rewards, plus the first height where the tail applies and the
    decayed-curve issuance before it."""
    half, year, r0, tail = params(block_time)
    sums = [[0, 0] for _ in range(6)]
    cross_r = None
    before_cross_q5 = 0
    for r in range(half):
        p = r0 * exp_neg_fixed(r, half)
        h = 0 if r < year else 1
        for q in range(6):
            v = p >> (F + q)
            sums[q][h] += v if v > tail else tail
        if cross_r is None:
            if (p >> (F + 5)) < tail:
                cross_r = r
            else:
                before_cross_q5 += p >> (F + 5)
    return sums, cross_r, before_cross_q5


def emission_report():
    lines = []
    results = {}
    for bt in (30, 60):
        half, year, r0, tail = params(bt)
        sums, cross_r, before_q5 = era_sums(bt)
        yearly = []
        for y in range(1, 15):
            q, h = divmod(y - 1, 2)
            yearly.append(sums[q][h] if q <= 5 else year * tail)
        cum, total = [], 0
        for v in yearly:
            total += v
            cum.append(total)
        decay_before = sum(sums[q][0] + sums[q][1] for q in range(5)) \
            - 0  # eras 0..4 never touch the tail (checked below)
        decay_before += before_q5
        cross_height = 5 * half + cross_r + 1          # first block paying the tail
        results[bt] = dict(yearly=yearly, cum=cum, cross_height=cross_height,
                           decay_before=decay_before, year=year, tail=tail, r0=r0)

        # Checks against a decimal evaluation of the same curve.
        ideal = Decimal(r0) * Decimal(half) / Decimal(2).ln()
        for y in range(1, 13):
            if y <= 10:
                lo = Decimal(2) ** (-Decimal(y - 1) / 2)
                hi = Decimal(2) ** (-Decimal(y) / 2)
                expect = ideal * (lo - hi)
                dev = abs(Decimal(yearly[y - 1]) - expect) / expect
                check(dev < Decimal("1e-6"),
                      f"year {y} at {bt}s deviates from the continuous curve by {dev}")
        check(reward(cross_height, bt) == tail and reward(cross_height - 1, bt) > tail,
              f"tail start at {bt}s is not the first tail block")
        check(reward(1, bt) == r0, f"first reward at {bt}s")
        rng = random.Random(7)
        heights = [1, 2, year, year + 1, half, half + 1, 3 * year, cross_height - 1,
                   cross_height, cross_height + 1, 10**9]
        heights += [rng.randrange(1, 6 * half) for _ in range(300)]
        for h in heights:
            check(abs(reward(h, bt) - reward_decimal(h, bt)) <= 1,
                  f"reward({h}) at {bt}s differs from decimal reference")
        prev = None
        for h in range(cross_height - 3000, cross_height + 3000):
            v = reward(h, bt)
            check(prev is None or v <= prev, f"reward not non-increasing at {h}")
            prev = v

    r30, r60 = results[30], results[60]
    ideal_total = Decimal(r30["r0"]) * Decimal(params(30)[0]) / Decimal(2).ln()
    cx = r30["decay_before"]
    blocks_to_21m = (MAIN_TARGET - cx + r30["tail"] - 1) // r30["tail"]
    year_of_21m = Decimal(r30["cross_height"] - 1 + blocks_to_21m) / Decimal(r30["year"])

    rows = []
    for y in range(1, 15):
        h30 = (y - 1) * r30["year"] + 1
        h60 = (y - 1) * r60["year"] + 1
        rows.append((y, ghost(reward(h30, 30), 5), ghost(reward(h60, 60), 5),
                     ghost(r30["yearly"][y - 1], 2), ghost(r30["cum"][y - 1], 2),
                     pct(r30["cum"][y - 1], MAIN_TARGET) + "%",
                     ghost(r60["cum"][y - 1], 2),
                     ghost(r60["cum"][y - 1] - r30["cum"][y - 1], 2)))
    lines.append(table(
        ["Year", "First reward, 30 s", "First reward, 60 s", "Issued in year (30 s)",
         "Cumulative (30 s)", "Share of 21M", "Cumulative (60 s)", "60 s minus 30 s"],
        rows))
    lines.append("")
    lines.append("Reward parameters (wei): "
                 f"R0(30 s) = {R0_30:,}; tail(30 s) = {TAIL_30:,}; "
                 f"R0(60 s) = {r60['r0']:,}; tail(60 s) = {r60['tail']:,}.")
    lines.append(f"Blocks per year: {r30['year']:,} at 30 s, {r60['year']:,} at 60 s. "
                 f"Half-life: {params(30)[0]:,} blocks at 30 s, {params(60)[0]:,} at 60 s.")
    lines.append(f"Area under the whole decaying curve (R0 x half-life / ln 2): "
                 f"{ghost(int(ideal_total), 2)} GHOST.")
    lines.append(f"Tail starts at height {r30['cross_height']:,} (30 s), "
                 f"year {Decimal(r30['cross_height'] - 1) / r30['year']:.3f}; "
                 f"height {r60['cross_height']:,} (60 s), "
                 f"year {Decimal(r60['cross_height'] - 1) / r60['year']:.3f}.")
    lines.append(f"Issued before the tail starts: {ghost(cx, 2)} GHOST at 30 s "
                 f"({pct(cx, MAIN_TARGET)}% of 21,000,000); "
                 f"{ghost(r60['decay_before'], 2)} GHOST at 60 s.")
    lines.append(f"Total issuance first passes 21,000,000 GHOST at about year "
                 f"{year_of_21m:.2f}; it is then {ghost(r30['tail'] * r30['year'], 2)} "
                 "GHOST per year (1% of 21,000,000 is 210,000).")
    lines.append(f"Reward at the start of year 9 is {ghost(reward(8 * r30['year'] + 1), 5)} "
                 "GHOST (outline: tail begins around year 8).")
    vec_rows = []
    for bt, y in ((30, r30), (60, r60)):
        half, year = params(bt)[0], y["year"]
        for h in (1, 2, year, year + 1, half, half + 1, 2 * half + 1, 4 * half + 1,
                  5 * half + 1, y["cross_height"] - 1, y["cross_height"], 10**9):
            vec_rows.append((f"{bt} s", f"{h:,}", f"{reward(h, bt):,}"))
    lines.append("")
    lines.append(table(["Block time", "Height", "Reward (wei)"], vec_rows))
    check(abs(r30["yearly"][0] * 10000 // MAIN_TARGET - 2929) <= 2, "year one share")
    check(abs(r30["cum"][3] * 10000 // MAIN_TARGET - 7500) <= 2, "year four share")
    return "\n".join(lines)


def alternatives_report():
    """Analysis only (floating point, not consensus): the ways to reconcile the outline."""
    ln2 = math.log(2)
    year_blocks = SECONDS_PER_YEAR // 30
    tail = 0.2
    area = 21e6
    rows = []

    def shares(r0, hl_years, tail_phase="max"):
        """Share of 21M issued in year 1 and by year 4, and tail start (years)."""
        blocks_hl = hl_years * year_blocks
        def cum(years):
            t = years * year_blocks
            if tail_phase == "max":
                cross = blocks_hl * math.log2(r0 / tail)
                if t <= cross:
                    return r0 * blocks_hl / ln2 * (1 - 2 ** (-t / blocks_hl))
                c = r0 * blocks_hl / ln2 * (1 - tail / r0)
                return c + (t - cross) * tail
            return r0 * blocks_hl / ln2 * (1 - 2 ** (-t / blocks_hl)) + t * tail
        return cum(1) / area, cum(4) / area

    r0_a = area * ln2 / (2 * year_blocks)
    y1, y4 = shares(r0_a, 2)
    rows.append(("A. Keep 6.92 GHOST and a 2-year half-life; tail starts where the "
                 "curve reaches 0.2 (proposed)", f"{r0_a:.3f}", "2.00",
                 f"{2 * math.log2(r0_a / tail):.2f}", f"{y1 * 100:.1f}%", f"{y4 * 100:.1f}%"))

    lo, hi = 0.5, 2.0
    for _ in range(80):
        mid = (lo + hi) / 2
        r0 = area * ln2 / (mid * year_blocks)
        if mid * math.log2(r0 / tail) > 8:
            hi = mid
        else:
            lo = mid
    r0_b = area * ln2 / (lo * year_blocks)
    y1, y4 = shares(r0_b, lo)
    rows.append(("B. Force the tail at year 8 by shortening the half-life",
                 f"{r0_b:.3f}", f"{lo:.2f}", "8.00", f"{y1 * 100:.1f}%", f"{y4 * 100:.1f}%"))

    r0_c = tail * 16
    rows.append(("C. Force the tail at year 8 by lowering the start reward "
                 "(2-year half-life)", f"{r0_c:.3f}", "2.00", "8.00",
                 f"{r0_c * 2 * year_blocks / ln2 * (1 - 2 ** -0.5) / area * 100:.1f}%",
                 f"{r0_c * 2 * year_blocks / ln2 * 0.75 / area * 100:.1f}%"))

    r0_d = area * ln2 / (2 * year_blocks)
    y1, y4 = shares(r0_d, 2, "additive")
    rows.append(("D. Add the 0.2 tail on top of the decaying curve from block one",
                 f"{r0_d + tail:.3f}", "2.00", "none (no switch)",
                 f"{y1 * 100:.1f}%", f"{y4 * 100:.1f}%"))

    r0_e = tail + area * ln2 / (2 * year_blocks)
    y1, y4 = shares(r0_e, 2)
    rows.append(("E. Raise the start reward so the decaying part alone sums to 21M",
                 f"{r0_e:.3f}", "2.00", f"{2 * math.log2(r0_e / tail):.2f}",
                 f"{y1 * 100:.1f}%", f"{y4 * 100:.1f}%"))
    out = [table(["Option", "Start reward", "Half-life (years)", "Tail starts (year)",
                  "Issued in year 1", "Issued by year 4"], rows)]
    out.append("")
    out.append(f"Outline check: 6.92 x 2^(-8/2) = {6.92 / 16:.4f} GHOST at year 8; "
               f"the curve reaches 0.2 at year {2 * math.log2(6.92 / 0.2):.2f}.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# ASERT
# ---------------------------------------------------------------------------

def target_from_difficulty(d):
    return M256 // d


def difficulty_from_target(t):
    return max(D_MIN, M256 // t)


T_START = target_from_difficulty(D_START)


def asert_target(lag, tau=HALF_LIFE_ASERT, anchor_target=T_START):
    """Next target = anchor_target * 2^(lag/tau), integer arithmetic (floor semantics).

    Returns (target, exponent, shifts, frac, factor)."""
    exponent = (lag * RADIX) // tau                 # floor division, also for lag < 0
    shifts = exponent >> 16                         # arithmetic shift (floor)
    frac = exponent - (shifts << 16)                # 0 <= frac < 65536
    factor = RADIX + ((195766423245049 * frac + 971821376 * frac ** 2
                       + 5127 * frac ** 3 + (1 << 47)) >> 48)
    if shifts >= 256:
        return MAX_TARGET, exponent, shifts, frac, factor
    product = anchor_target * factor
    shift = shifts - 16
    target = product << shift if shift >= 0 else product >> -shift
    target = max(1, min(MAX_TARGET, target))
    return target, exponent, shifts, frac, factor


def block_difficulty(height, ts_minus_genesis, block_time=BLOCK_TIME):
    """Difficulty required of block `height` (>= 1) stamped ts_minus_genesis seconds
    after the genesis timestamp."""
    lag = ts_minus_genesis - block_time * height
    target = asert_target(lag)[0]
    return difficulty_from_target(target)


def asert_report():
    lines = []
    cases = [
        ("on schedule, block 1", 1, 30),
        ("on schedule, block 1000", 1000, 30000),
        ("one second late", 1000, 30001),
        ("one second early (floor of a negative)", 1000, 29999),
        ("a quarter half-life late", 1000, 30900),
        ("half a half-life late", 1000, 31800),
        ("half a half-life early", 1000, 28200),
        ("one half-life late", 1000, 33600),
        ("one half-life early", 1000, 26400),
        ("two half-lives late", 1000, 37200),
        ("three half-lives early", 1000, 19200),
        ("odd lag, late", 123456, 123456 * 30 + 777),
        ("odd lag, early", 123456, 123456 * 30 - 2501),
        ("24 hours late: clamps to the minimum difficulty", 1000, 30000 + 86400),
        ("48 hours early", 10000, 300000 - 172800),
        ("lag so large the shift overflows", 1000, 30000 + 10_000_000),
        ("lag so negative the target reaches 1", 1_000_000, 30_000_000 - 10_000_000),
    ]
    rows = []
    worst = Decimal(0)
    for name, n, ts in cases:
        lag = ts - 30 * n
        target, exponent, shifts, frac, factor = asert_target(lag)
        d = difficulty_from_target(target)
        ideal = Decimal(T_START) * (Decimal(2) ** (Decimal(lag) / Decimal(HALF_LIFE_ASERT)))
        if 1 <= ideal <= MAX_TARGET:
            dev = abs(Decimal(target) - ideal) / ideal
            worst = max(worst, dev)
            check(dev < Decimal("0.00013") + Decimal(1) / Decimal(target),
                  f"ASERT vector '{name}' off by {dev}")
        rows.append((name, n, ts, lag, exponent, shifts, frac, factor, f"{d:,}"))
    lines.append(table(
        ["Case", "n", "ts - genesis (s)", "lag (s)", "exponent", "shifts", "frac",
         "factor", "difficulty"], rows))
    lines.append("")
    lines.append(f"Anchor: D_START = {D_START:,}, T_START = floor((2^256 - 1) / D_START) = "
                 f"0x{T_START:064x}")
    lines.append(f"D_MIN = {D_MIN:,}; MAX_TARGET = floor((2^256 - 1) / D_MIN) = "
                 f"0x{MAX_TARGET:064x}")
    lines.append(f"Worst relative error of the target against 2^x in decimals "
                 f"(non-clamped vectors): {float(worst) * 100:.4f}%")
    # Properties
    check(asert_target(0)[0] == T_START, "lag 0 must return the anchor target")
    check(asert_target(3600)[0] == 2 * T_START, "lag +tau must double the target")
    check(asert_target(-3600)[0] == T_START // 2, "lag -tau must halve the target")
    check(asert_target(-1)[1] == -19 and asert_target(1)[1] == 18, "floor rounding of exponent")
    prev = None
    for lag in range(-200000, 200000, 7):
        t = asert_target(lag)[0]
        check(prev is None or t >= prev, f"target not monotone at lag {lag}")
        prev = t
    check(block_difficulty(1, 30) == D_START, "block 1 on schedule has D_START")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Miner departure, starting difficulty, half-life
# ---------------------------------------------------------------------------

LN2 = math.log(2)


def p_lever(w, f, tau=HALF_LIFE_ASERT, b=BLOCK_TIME):
    """P(no block within w seconds) when a fraction f of the hashrate remains and the
    difficulty of the candidate follows the candidate's own timestamp."""
    k = f * tau / (b * LN2)
    return math.exp(-k * (2 ** (w / tau) - 1))


def p_plain(w, f, b=BLOCK_TIME):
    return math.exp(-w * f / b)


def mean_wait(p, upper):
    """Integral of P(W > w) dw by Simpson's rule on [0, upper]."""
    n = 20000
    h = upper / n
    total = p(0) + p(upper)
    for i in range(1, n):
        total += (4 if i % 2 else 2) * p(i * h)
    return total * h / 3


def q99_lever(f, tau=HALF_LIFE_ASERT, b=BLOCK_TIME):
    k = f * tau / (b * LN2)
    return tau * math.log2(1 + math.log(100) / k)


def hm(seconds):
    if seconds < 120:
        return f"{seconds:.0f} s"
    if seconds < 7200:
        return f"{seconds / 60:.0f} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} days"


def sci(x):
    return "<1e-12" if x < 1e-12 else (f"{x * 100:.2f}%" if x >= 1e-4 else f"{x:.1e}")


def departure_report():
    rows = []
    for f in (0.10, 0.01, 0.001, 0.0001):
        mean_plain = BLOCK_TIME / f
        mean_lev = mean_wait(lambda w: p_lever(w, f), 40 * HALF_LIFE_ASERT)
        rows.append((f"{f * 100:g}%", hm(mean_plain), hm(4.605 * mean_plain),
                     sci(p_plain(7200, f)), hm(mean_lev), hm(q99_lever(f)),
                     sci(p_lever(3600, f)), sci(p_lever(7200, f)), sci(p_lever(14400, f))))
    t = table(["Hashrate left", "Mean wait, parent timestamp", "99th pct, parent timestamp",
               "P(over 2 h), parent timestamp", "Mean wait, candidate timestamp",
               "99th pct, candidate timestamp", "P(over 1 h)", "P(over 2 h)",
               "P(over 4 h)"], rows)
    f = 0.01
    full = HALF_LIFE_ASERT * math.log2(1 / f)
    note = (f"With 1% left the difficulty is back at the right level after "
            f"tau x log2(100) = {hm(full)}; the candidate-timestamp rule needs no block "
            "to arrive for the difficulty to fall.")
    return t + "\n\n" + note


def start_report():
    rows = []
    # Assumption, not a measurement: one desktop CPU does about 10,000 hashes per second.
    for name, hps in (("1 desktop CPU", 10_000), ("10 desktop CPUs", 100_000),
                      ("50 desktop CPUs", 500_000), ("300 desktop CPUs", 3_000_000),
                      ("A large pool or redirected hashrate", 25_000_000)):
        rate0 = hps / D_START
        k = rate0 * HALF_LIFE_ASERT / LN2

        def p(w, k=k):
            return math.exp(-k * (2 ** (w / HALF_LIFE_ASERT) - 1))
        mean = mean_wait(p, 40 * HALF_LIFE_ASERT)
        # blocks issued while the difficulty is too low: about tau*log2(ratio)/B
        ratio = hps * BLOCK_TIME / D_START
        excess = HALF_LIFE_ASERT * math.log2(ratio) / BLOCK_TIME if ratio > 1 else 0
        rows.append((name, f"{hps:,}", f"{ratio:.2f}", hm(mean),
                     f"{excess:,.0f}" if excess else "0"))
    return table(["Network at launch", "Hashes per second", "Hashrate / D_START x 30 s",
                  "Mean wait for block 1", "Extra blocks before difficulty catches up (about)"],
                 rows)


def halflife_report():
    rows = []
    for tau in (900, 1800, 3600, 7200, 21600):
        sd = math.sqrt(BLOCK_TIME * LN2 / (2 * tau))
        f = 0.01
        k = f * tau / (BLOCK_TIME * LN2)
        p2 = math.exp(-k * (2 ** (7200 / tau) - 1))
        mean = mean_wait(lambda w: math.exp(-k * (2 ** (w / tau) - 1)), 40 * tau)
        gain = 100 * (2 ** (FUTURE_DRIFT / tau) - 1)
        rows.append((f"{tau} s ({tau // BLOCK_TIME} blocks)", f"{sd * 100:.1f}%",
                     f"{gain:.2f}%", hm(mean), sci(p2)))
    return table(["Half-life", "Steady-state spread of difficulty (1 sd)",
                  "Most a 30 s forward stamp can ease one block", "Mean first wait, 1% left",
                  "P(over 2 h), 1% left"], rows)


def mc_report():
    """Monte Carlo of the candidate-timestamp rule in continuous time (no integer
    rounding), seeded. Checks the closed forms above."""
    rng = random.Random(20261017)
    tau, b = HALF_LIFE_ASERT, BLOCK_TIME

    def next_wait(lag_prev, c):
        # intensity (c/b) * 2^((lag_prev + w - b)/tau); integrate and invert
        scale = c * tau / (b * LN2) * 2 ** ((lag_prev - b) / tau)
        e = rng.expovariate(1.0)
        return tau * math.log2(1 + e / scale)

    # steady state at full hashrate
    lag, samples, waits = 0.0, [], []
    for i in range(300_000):
        w = next_wait(lag, 1.0)
        lag += w - b
        if i > 5000:
            samples.append(lag * LN2 / tau)
            waits.append(w)
    mean = sum(samples) / len(samples)
    sd = math.sqrt(sum((x - mean) ** 2 for x in samples) / len(samples))
    mean_w = sum(waits) / len(waits)
    check(abs(mean_w - b) < 0.5, "Monte Carlo mean block time should be near 30 s")
    # departure to 1%
    trials = 200_000
    over2h = sum(1 for _ in range(trials) if next_wait(0.0, 0.01) > 7200)
    over1h = sum(1 for _ in range(trials) if next_wait(0.0, 0.01) > 3600)
    check(abs(over2h / trials - p_lever(7200, 0.01)) < 0.002, "Monte Carlo P(over 2 h)")
    return "\n".join([
        f"Steady state, full hashrate: mean block time {mean_w:.2f} s; spread of ln(difficulty) "
        f"{sd * 100:.1f}% (formula {math.sqrt(b * LN2 / (2 * tau)) * 100:.1f}%).",
        f"Departure to 1%, {trials:,} trials: P(first wait over 1 h) = "
        f"{over1h / trials * 100:.1f}% (formula {p_lever(3600, 0.01) * 100:.1f}%); "
        f"over 2 h = {over2h / trials * 100:.2f}% (formula {p_lever(7200, 0.01) * 100:.2f}%).",
    ])


def blocktime_report():
    rows = []
    for delay in (0.5, 1.0, 1.5, 2.0, 3.0, 5.0):
        rows.append((f"{delay:g} s", f"{(1 - math.exp(-delay / 30)) * 100:.2f}%",
                     f"{(1 - math.exp(-delay / 60)) * 100:.2f}%"))
    return table(["Average time for a block to reach every miner and be verified",
                  "Stale rate at 30 s blocks", "Stale rate at 60 s blocks"], rows)


SECTIONS = {
    "emission": ("Emission schedule", emission_report),
    "alternatives": ("Reconciling the outline's figures (analysis, floating point)",
                     alternatives_report),
    "asert": ("ASERT test vectors", asert_report),
    "blocktime": ("Stale rate against delay (the 60 second test)", blocktime_report),
    "departure": ("Miner departure", departure_report),
    "start": ("Starting difficulty", start_report),
    "halflife": ("Half-life comparison", halflife_report),
    "mc": ("Monte Carlo cross-check", mc_report),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--skip-emission", action="store_true")
    ap.add_argument("--section", choices=sorted(SECTIONS))
    args = ap.parse_args()
    names = [args.section] if args.section else list(SECTIONS)
    if args.skip_emission and "emission" in names:
        names.remove("emission")
    for name in names:
        title, fn = SECTIONS[name]
        print(f"## {title}\n")
        print(fn())
        print()
    if checks_failed:
        print(f"{len(checks_failed)} CHECKS FAILED")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
