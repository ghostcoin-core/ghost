# Specification 06: consensus parameters and emission

Status: draft for the founder's review, 2026-10-17. Nothing here is built. The
numbers marked **proposed** are choices this document makes and the founder can
change; everything else follows from the outline, the base client plan or
decision 0001.

This document fixes the consensus rules that the outline lists as "to specify":
how difficulty adjusts, what a valid timestamp is, what happens when most miners
leave, the block time, the exact block reward, and how the genesis block is
derived from a Bitcoin block. It is written so that two teams could implement it
separately and get the same chain. Every number in the tables below is produced
by [scripts/consensus_check.py](../../scripts/consensus_check.py), which uses the
formulas in this document and no node code (section 9).

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Block time | 30 seconds; fall back to 60 seconds only if the test in section 3 fails | Outline; test proposed |
| Difficulty | ASERT, absolutely scheduled, anchored at genesis | Base client plan |
| ASERT half-life | 3,600 seconds (120 blocks at 30 seconds) | **Proposed** |
| ASERT input | The timestamp of the block being validated (BCH uses its parent's) | **Proposed** (section 5) |
| Starting difficulty | 2^24 = 16,777,216 for 30-second blocks | **Proposed**, confirm from launch hashrate |
| Minimum difficulty | 2^17 = 131,072 | **Proposed** |
| Timestamp rule | Strictly greater than the parent's; at most 30 seconds ahead of the node's clock | **Proposed** |
| Departure scenario | 99% of hashrate leaves at once; first block after takes over 2 hours with probability 0.56% | **Proposed** |
| Emission | 6.92356 GHOST at the start, half-life 2 years, tail 0.2 GHOST; the tail starts at year 10.2, not year 8 | **Proposed fix** (section 6) |
| Reward recipient | The whole reward and the priority fees go to the block finder; no uncles | Outline |
| Genesis | Derived from the first Bitcoin block at or after a stated time, once it has 6 confirmations | **Proposed** |

## 2. Conventions

- All consensus arithmetic is on integers. No floating point, no rounding mode
  other than the floors written here. Implementations use arbitrary-precision
  integers or at least 256-bit unsigned integers; the places where this matters
  are named.
- `a // b` is floor division for any sign. This is **not** Go's `/`, which
  truncates toward zero. `a >> n` on a negative `a` is an arithmetic shift
  (floor). The test vectors in section 4 include negative cases for this reason.
- Times are whole seconds (Unix time, UTC). A year is 365 days = 31,536,000
  seconds. "Year" in the emission schedule means this many scheduled seconds of
  blocks, not calendar time; difficulty keeps the real average close to it.
- Amounts are in wei, 10^18 per GHOST.
- `M = 2^256 - 1`. A seal is valid if its RandomX hash, read as a big-endian
  256-bit integer, is at most `target(D) = M // D`, where `D` is the block's
  difficulty. (The RandomX engine specification must use the same byte order.)
- `B` is the block time in seconds, 30 or 60, fixed at genesis. A chain does not
  change `B` after launch.

## 3. Block time

The target is 30 seconds. It is a genesis parameter: changing it later is a
hard fork. The fallback is therefore decided before the software is frozen, from
a measurement on the internal test network, not after launch.

**Why a test is needed.** With no uncle rewards (section 7), a block that loses
a race is wasted work. If a block takes on average `t` seconds to reach every
miner and be verified, the stale rate is about `1 - exp(-t / B)`:

| Average time for a block to reach every miner and be verified | Stale rate at 30 s blocks | Stale rate at 60 s blocks |
|---|---|---|
| 0.5 s | 1.65% | 0.83% |
| 1 s | 3.28% | 1.65% |
| 1.5 s | 4.88% | 2.47% |
| 2 s | 6.45% | 3.28% |
| 3 s | 9.52% | 4.88% |
| 5 s | 15.35% | 8.00% |

**The test** (part of the phase 2 gate in the base client plan):

1. Run at least 12 mining nodes on the minimum supported hardware, in at least
   three regions, with at least 150 ms of round-trip time between regions
   (emulated if needed). No node holds more than 20% of the hashrate.
2. Run at least 10,000 consecutive blocks at the 30-second target (about 3.5
   days), difficulty at steady state, with blocks filled to the maximum valid
   size and the hostile transaction load from the plan's phase 4 gate.
3. Measure the stale rate: blocks found but not on the final chain, divided by
   blocks found, counted from every node's log.
4. Measure, on the minimum-hardware node, the 99th percentile of the time from
   receiving a block to having it fully verified (every seal checked) and
   imported.

**Trigger.** Switch to 60-second blocks if the stale rate is **5% or more**
(about 1.5 seconds of average delay), or if the 99th percentile in step 4 is
**3 seconds or more** (a tenth of the target). The second condition catches a
node that cannot keep up even when the network is fast. Before switching, repeat
the run at 60 seconds: if the stale rate is still 5% or more, the cause is not
the block time, and the choice goes back to the founder.

**What changes at 60 seconds.** Only constants, all stated in section 6 and
section 4: the reward and tail double, the half-life in blocks halves, and
`D_START` doubles. The ASERT half-life in seconds, the drift limit and the
yearly emission stay the same.

## 4. Difficulty: ASERT anchored at genesis

### 4.1 What is being adapted

Ghost uses ASERT as deployed on Bitcoin Cash since November 2020, in its
`aserti3-2d` form:

- Specification: "Bitcoin Cash Node: ASERT difficulty adjustment algorithm
  (aserti3-2d)", published with the 2020-11-15 upgrade at
  `upgradespecs.bitcoincashnode.org/2020-11-15-asert/`. The reference
  implementation is `CalculateASERT` in Bitcoin Cash Node's `src/pow.cpp`.
- Design: Mark Lundeberg, "Static difficulty adjustments, with absolutely
  scheduled exponentially rising targets (DA-ASERT)", 2020.

ASERT sets the target of each block directly from how far the chain is ahead of
or behind a fixed schedule, with no memory of earlier targets:

```text
target = anchor_target * 2^((time - ideal_time) / half_life)
```

BCH's specification assumes an anchor block above genesis (a block whose own
target is known and whose parent's timestamp is the zero of the schedule). Ghost
has no such history, so this document makes two changes, and only these two.

1. **The anchor is the genesis block.** Its timestamp `G` is the zero of the
   schedule, as if the genesis block had arrived exactly on time. BCH's
   `anchor_parent_time` is set to `G - B` and `anchor_height` to 0. The anchor
   target is `T_START`, derived from `D_START` (section 4.4). Block 1, if
   stamped `G + B`, has exactly `T_START`.
2. **The block being validated supplies its own timestamp.** BCH evaluates the
   formula with the parent's height and timestamp. Ghost evaluates it with the
   height and timestamp of the block under validation. This is a deliberate
   choice for the miner-departure case; section 5 explains it and analyses the
   attack surface. It is one substitution, and the parent-timestamp variant is
   given there for comparison.

### 4.2 Constants

| Name | 30-second chain | 60-second chain | Notes |
|---|---|---|---|
| `B` | 30 | 60 | Block time, seconds |
| `TAU` | 3,600 | 3,600 | Half-life, seconds (120 blocks at 30 s, 60 at 60 s) |
| `RADIX` | 65,536 | 65,536 | 2^16 fixed point, as BCH |
| `D_START` | 16,777,216 (2^24) | 33,554,432 (2^25) | Genesis difficulty |
| `D_MIN` | 131,072 (2^17) | 131,072 | Difficulty never goes below this |
| `T_START` | `M // D_START` | `M // D_START` | Anchor target |
| `MAX_TARGET` | `M // D_MIN` | `M // D_MIN` | Largest allowed target |
| `FUTURE_DRIFT` | 30 | 30 | Seconds, section 5 |

The script prints `T_START` and `MAX_TARGET` in full (section 4.6). The ASERT
vectors in this document are for the 30-second chain.

### 4.3 The algorithm

For a block at height `n >= 1` with timestamp `ts`, and genesis timestamp `G`:

```python
def required_difficulty(n, ts):
    lag = ts - G - B * n                    # seconds behind schedule; may be negative
    exponent = (lag * RADIX) // TAU         # floor division
    shifts = exponent >> 16                 # arithmetic shift (floor)
    frac = exponent - (shifts << 16)        # 0 <= frac < 65536
    factor = 65536 + ((195766423245049 * frac
                       + 971821376 * frac * frac
                       + 5127 * frac * frac * frac
                       + (1 << 47)) >> 48)  # cubic fit of 2^(frac/65536), as BCH
    if shifts >= 256:
        target = MAX_TARGET
    else:
        product = T_START * factor
        shift = shifts - 16
        target = product << shift if shift >= 0 else product >> -shift
        target = max(1, min(MAX_TARGET, target))
    return max(D_MIN, M // target)          # target-to-difficulty, section 4.4
```

The polynomial and its constants are BCH's. They approximate `2^x` on `[0, 1)`
to within 0.013% (the script measures 0.0085% on the vectors below). The result
depends only on `n`, `ts`, `G` and the constants. It does not depend on the
parent or on any earlier target, so a node can verify a header's difficulty
without its parent's difficulty, and rounding errors cannot accumulate.

Intermediate sizes: `lag * RADIX` fits in 64 bits for any `|lag|` below 2^47
seconds. `T_START * factor` is below 2^249 (`T_START` is below 2^232 and `factor`
below 2^17). The code compares `shifts` with 256 first, so the left shift is at
most 239 bits and the product below 2^488. Implementations must use 512-bit or
arbitrary-precision integers for it, and only then clamp.

### 4.4 Target and difficulty

- Difficulty to target: `target(D) = M // D`. A seal is valid when the hash,
  read as a big-endian integer, is `<= target(D)`.
- Target to difficulty: `D = max(D_MIN, M // target)`. With `D_MIN` and the
  target clamp together, `D` is always between `D_MIN` and `M`.
- A header is valid only if its difficulty field **equals** `required_difficulty`
  exactly. It is not "at least".
- `T_START = M // D_START`, so `M // T_START` is `D_START` (the vector for an
  on-schedule block returns it).
- The rounding between `M // D` and the ASERT target is not an issue: the chain
  only ever uses `D` (in the header, in the work sum) and `target(D)` (in the
  seal check). The probability that a hash passes is `(M // D + 1) / 2^256`,
  which is at least `1 / D` and exceeds it by at most 2^-256.

### 4.5 Minimum difficulty, starting difficulty and cumulative work

**Minimum difficulty** is 2^17 (131,072), the same as the base client's floor.
Below that, one weak CPU could mine a block every few seconds, so a floor is
needed. It is low enough that the chain recovers from a very deep hashrate loss
(131,072 hashes is about 13 seconds for a machine doing 10,000 hashes a second).

**Starting difficulty** is `D_START = 2^24` for 30-second blocks, **proposed**.
It means the chain starts at 30-second blocks if about 560,000 hashes per second
are mining, roughly fifty desktop CPUs at an assumed 10,000 hashes a second
each. The rule behind the value is:
`D_START = 30 s x (conservative estimate of launch hashrate)`, rounded to a
power of two, with the estimate recorded before the software is frozen. Err
high, not low:

- A start that is too high costs only waiting. Because difficulty eases with the
  candidate's timestamp (section 5), it falls by half every hour with no block
  needed.
- A start that is too low issues blocks faster than scheduled, at the highest
  rewards, to whoever is mining first. The number of extra blocks before
  difficulty catches up is about `TAU x log2(ratio) / B`.

| Network at launch | Hashes per second | Hashrate / D_START x 30 s | Mean wait for block 1 | Extra blocks before difficulty catches up (about) |
|---|---|---|---|---|
| 1 desktop CPU | 10,000 | 0.02 | 22 min | 0 |
| 10 desktop CPUs | 100,000 | 0.18 | 3 min | 0 |
| 50 desktop CPUs | 500,000 | 0.89 | 33 s | 0 |
| 300 desktop CPUs | 3,000,000 | 5.36 | 6 s | 291 |
| A large pool or redirected hashrate | 25,000,000 | 44.70 | 2 s | 658 |

(The wait in the table is for the first block, in the idealised model of
section 5. "Hashes per second" is an assumption about the launch network, not a
measurement. Replace it with the real figure from the lined-up miners before the
freeze; the rule above gives `D_START`.)

**Cumulative work.** The work of a block is its difficulty `D`. The total
difficulty of a chain is the sum of `D` over all its blocks, with the genesis
block counting `D_START`, as in the base client. Fork choice is the greatest total
difficulty, with the base client's existing tie rule. The expected number of
hashes for a block is `2^256 / (M // D + 1)`, which is `D` to within a relative
error of about `D / 2^256`; this is negligible and is not corrected. Total
difficulty fits in 256 bits for any realistic chain.

### 4.6 Test vectors

These vectors are produced by the script's own integer implementation of
section 4.3. Each unclamped vector is also checked against `T_START x 2^(lag /
TAU)` evaluated with 90-digit decimals; the worst difference is stated below the
table. They are written independently of any node code and are the expected
results for the node's difficulty tests.

| Case | n | ts - genesis (s) | lag (s) | exponent | shifts | frac | factor | difficulty |
|---|---|---|---|---|---|---|---|---|
| on schedule, block 1 | 1 | 30 | 0 | 0 | 0 | 0 | 65536 | 16,777,216 |
| on schedule, block 1000 | 1000 | 30000 | 0 | 0 | 0 | 0 | 65536 | 16,777,216 |
| one second late | 1000 | 30001 | 1 | 18 | 0 | 18 | 65549 | 16,773,888 |
| one second early (floor of a negative) | 1000 | 29999 | -1 | -19 | -1 | 65517 | 131046 | 16,780,544 |
| a quarter half-life late | 1000 | 30900 | 900 | 16384 | 0 | 16384 | 77938 | 14,107,516 |
| half a half-life late | 1000 | 31800 | 1800 | 32768 | 0 | 32768 | 92674 | 11,864,294 |
| half a half-life early | 1000 | 28200 | -1800 | -32768 | -1 | 32768 | 92674 | 23,728,588 |
| one half-life late | 1000 | 33600 | 3600 | 65536 | 1 | 0 | 65536 | 8,388,608 |
| one half-life early | 1000 | 26400 | -3600 | -65536 | -1 | 0 | 65536 | 33,554,432 |
| two half-lives late | 1000 | 37200 | 7200 | 131072 | 2 | 0 | 65536 | 4,194,304 |
| three half-lives early | 1000 | 19200 | -10800 | -196608 | -3 | 0 | 65536 | 134,217,728 |
| odd lag, late | 123456 | 3704457 | 777 | 14144 | 0 | 14144 | 76115 | 14,445,400 |
| odd lag, early | 123456 | 3701179 | -2501 | -45530 | -1 | 20006 | 80978 | 27,155,810 |
| 24 hours late: clamps to the minimum difficulty | 1000 | 116400 | 86400 | 1572864 | 24 | 0 | 65536 | 131,072 |
| 48 hours early | 10000 | 127200 | -172800 | -3145728 | -48 | 0 | 65536 | 4,722,366,482,869,645,213,696 |
| lag so large the shift overflows | 1000 | 10030000 | 10000000 | 182044444 | 2777 | 50972 | 112370 | 131,072 |
| lag so negative the target reaches 1 | 1000000 | 20000000 | -10000000 | -182044445 | -2778 | 14563 | 76453 | 115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,935 |

Anchor: D_START = 16,777,216, T_START = floor((2^256 - 1) / D_START) = 0x000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
D_MIN = 131,072; MAX_TARGET = floor((2^256 - 1) / D_MIN) = 0x00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
Worst relative error of the target against 2^x in decimals (non-clamped vectors): 0.0085%

Things the vectors pin down:

- The one-second-early case has exponent -19, not -18: floor division, not
  truncation toward zero.
- "One half-life late" doubles the target exactly (difficulty 8,388,608 =
  2^23), and "one half-life early" halves it exactly (2^25). Whole-multiple lags
  have `frac = 0`, so the polynomial is not used.
- A lag of 24 hours would drive difficulty to 1; the floor returns `D_MIN`.
- When the shift is 256 or more, the result is `MAX_TARGET` without computing
  the product.

### 4.7 Half-life

The half-life is 3,600 seconds, **proposed**. The trade-off:

| Half-life | Steady-state spread of difficulty (1 sd) | Most a 30 s forward stamp can ease one block | Mean first wait, 1% left | P(over 2 h), 1% left |
|---|---|---|---|---|
| 900 s (30 blocks) | 10.7% | 2.34% | 22 min | <1e-12 |
| 1800 s (60 blocks) | 7.6% | 1.16% | 28 min | 2.3e-06 |
| 3600 s (120 blocks) | 5.4% | 0.58% | 35 min | 0.56% |
| 7200 s (240 blocks) | 3.8% | 0.29% | 40 min | 3.14% |
| 21600 s (720 blocks) | 2.2% | 0.10% | 46 min | 6.72% |

A longer half-life gives a steadier difficulty and a smaller timestamp
advantage, but a worse outage tail. A shorter one has the opposite. One hour
keeps the difficulty spread near 5% (which costs almost nothing in average block
time), caps the timestamp advantage under 0.6%, and puts the accepted outage
risk (section 5) at the level stated there. The founder can move the half-life
to 1,800 seconds for a thousandfold lower outage risk at the cost of a 7.6%
spread; the rest of the document does not depend on the value.

## 5. Timestamps and miner departure

### 5.1 The timestamp rule

Replaces the base client's "strictly greater than the parent's" check. A header
with timestamp `ts` at height `n >= 1` is valid only if:

1. **Lower bound:** `ts > parent.ts` (at least one second after the parent).
2. **Upper bound (drift):** `ts <= local_clock + 30`, where `local_clock` is the
   node's own UTC clock in whole seconds. A header that fails only this check is
   not invalid for ever: the node holds it and retries when its clock catches
   up, as the base client does for future blocks. The check applies when a block
   is first received; a node re-validating old history does not apply it.
3. `ts < 2^63`, so signed arithmetic cannot overflow.

This is **not Bitcoin's rule**. Bitcoin's lower bound is the median of the
previous 11 blocks, and its upper bound is network-adjusted time plus two hours.
Ghost keeps the strictly increasing lower bound for a reason specific to the
EVM: contracts routinely assume `block.timestamp` never goes backwards, and a
median-time-past rule would let it. The 30-second drift limit is one block time,
tight enough to keep the timestamp advantage in section 5.4 small, and wide
enough to absorb ordinary clock error. Miners run a synchronised clock; the
installer checks it.

Blocks found less than a second apart need `ts = parent.ts + 1`, a second ahead
of the clock at most. The chain's clock cannot run ahead of real time by more
than the drift limit in normal operation, because a block ahead of every honest
node's clock plus 30 seconds is not accepted.

### 5.2 The scenario Ghost is designed for

A hashrate collapse is the case ASERT cannot fix by itself. With the previous
block's timestamp as input, difficulty cannot fall until a block arrives, so the
first block after a departure waits as long as the remaining hashrate takes to
find one at the old difficulty. The mean wait is `B` divided by the fraction of
hashrate left, and the 99th percentile is about 4.6 times the mean.

**Designed for:** at an instant when the chain is on schedule, 99% of the
hashrate leaves and the rest stays constant. This is roughly the loss of a large
share of redirected Monero hashrate (the base client plan accepts that
hashrate, and with it this risk).

**Accepted:** the first block after such a departure takes more than 2 hours
with probability **0.56%**, more than 3 hours with probability under 6 in a
million, and more than 4 hours with probability about 5 in 10^12. The mean wait
is 35 minutes. After the first block, blocks come faster than the first one
did, and difficulty is back at its equilibrium after about 6.6 hours.

**Not designed for:** a loss of 99.9% or more. At 99.9% the mean wait is 2.3
hours and a 4-hour outage has a 7.5% chance; at 99.99% the mean is 5.1 hours.
No rule can guarantee a maximum outage with arbitrarily little hashrate left.

| Hashrate left | Mean wait, parent timestamp | 99th pct, parent timestamp | P(over 2 h), parent timestamp | Mean wait, candidate timestamp | 99th pct, candidate timestamp | P(over 1 h) | P(over 2 h) | P(over 4 h) |
|---|---|---|---|---|---|---|---|---|
| 10% | 5 min | 23 min | 3.8e-11 | 5 min | 20 min | 3.0e-08 | <1e-12 | <1e-12 |
| 1% | 50 min | 3.8 h | 9.07% | 35 min | 112 min | 17.71% | 0.56% | 5.3e-12 |
| 0.1% | 8.3 h | 38.4 h | 78.66% | 2.3 h | 4.8 h | 84.10% | 59.49% | 7.45% |
| 0.01% | 3.5 days | 16.0 days | 97.63% | 5.1 h | 8.1 h | 98.28% | 94.94% | 77.13% |

With 1% left the difficulty is back at the right level after tau x log2(100) = 6.6 h; the candidate-timestamp rule needs no block to arrive for the difficulty to fall.

The left-hand group of columns is BCH's rule (difficulty keyed to the parent's
timestamp); it reproduces the base client plan's table. The right-hand group is
the rule below. Both assume the chain was on schedule when the hashrate left.

### 5.3 The lever: the candidate block's timestamp

Section 4.3 gives the difficulty of a block as a function of its own timestamp.
While nobody finds a block, a miner builds candidates with a later timestamp
(limited by the drift rule to the real time plus 30 seconds), so the target
rises by a factor of `2^(1/3600)` every second. Waiting itself lowers
difficulty. No block needs to arrive first.

With a fraction `f` of the hashrate left and the old difficulty, the chance
that no block has been found after `w` seconds is `exp(-K x (2^(w/TAU) - 1))`
with `K = f x TAU / (B x ln 2)`. The mean wait falls from `B / f` to roughly
`TAU x log2(1 + 1/K)` (exact values in the table): from 50 minutes to 35 minutes at 1% left, and from 8.3
hours to 2.3 hours at 0.1% left. Changing only the half-life, without using the
candidate's timestamp, does not shorten the first wait at all; this is why the
timestamp is the lever.

**Decision: use the candidate's timestamp.** The benefit is largest in exactly
the cases that matter (the 99th percentile falls by half at 1% left, by a factor
of 8 at 0.1% left and by more below that). The cost is an attack surface, analysed next. The alternative, BCH's
parent-timestamp rule, is `lag = parent.ts - G - B x (n - 1)` in section 4.3;
if the founder prefers it, that single change is all that differs, and the
left-hand columns above are its outage figures.

The same rule also protects the launch: a starting difficulty set too high
eases itself at the same rate.

### 5.4 Attack analysis of the candidate-timestamp rule

The only new freedom is that a miner chooses `ts` for their own block, between
`parent.ts + 1` and the clock plus 30 seconds, and that choice moves the
required difficulty of that block.

1. **Forward-dating gains at most 0.58% on one block.** Stamping 30 seconds
   ahead eases the miner's own block by `2^(30/3600) - 1 = 0.58%`. The gain
   cannot be stacked: the difficulty depends only on `n` and `ts`, and `ts`
   cannot exceed real time plus 30 seconds. After the next block it is gone.
   Every miner can do the same, so the equilibrium is that all blocks run 30
   seconds ahead of real time and the difficulty holds the schedule on that
   shifted clock; nothing is lost except that `block.timestamp` leads real time
   by up to 30 seconds. The reference miner stamps `max(parent.ts + 1, now)`; a
   miner that deviates gains at most the 0.58%.
2. **Backdating only hurts the backdater.** A lower `ts` raises the required
   difficulty of that block. The lower bound `parent.ts + 1` stops timestamps
   going backwards.
3. **A forward-dated block does not harm the next miner.** The next block must
   exceed it, which at most pushes its stamp up to 30 seconds ahead of the
   clock, and a later stamp only eases it.
4. **A hidden fork gains nothing from timestamps.** Fork choice is total
   difficulty, and each block's difficulty equals the expected hashes needed to
   find it. A fork stamped later has lower difficulty per block and so less
   weight for the same work. A private chain cannot be stamped later than the
   real time at which it is published plus 30 seconds, so its blocks cannot
   require less work than the honest chain's blocks at the same height and
   time, apart from the 0.58% in item 1.
5. **A majority miner can set any timestamp in the allowed range.** Stamping at
   the lower bound for many blocks makes the chain look fast, which raises
   difficulty and slows the real chain; stamping forward lowers difficulty by at
   most the factor above per block. A majority miner has stronger attacks
   already (reordering and double-spending), and the rule does not let them
   exceed the schedule: the schedule is absolute, so a long run of early blocks
   is paid back by higher difficulty.
6. **No time-warp.** Bitcoin's time-warp attack exploits a window that resets
   every 2,016 blocks. ASERT has no window, so there is no boundary to exploit.
7. **Mining software must refresh the timestamp.** The target changes by 0.019%
   every second. Miners and pool work packages must refresh `ts` at least every
   10 seconds (losing up to 0.19% of the ease otherwise) and carry the target
   that matches the `ts` in the header. A submitted block is valid at the `ts`
   it carries; stale work does not become invalid.
8. **Clock error.** A node whose clock is more than 30 seconds slow holds valid
   blocks until its clock catches up; a node more than 30 seconds fast accepts
   blocks stamped further ahead of true time than 30 seconds, by its error.
   Neither splits the chain for long: a block held for being too far ahead is
   accepted once the node's clock reaches it, and a block that most of the
   network accepts is accepted by the rest within 30 seconds of its stamp.

A surge in hashrate (the opposite of departure) is handled by the same rule in
the other direction: difficulty rises on the schedule, and the extra blocks
issued before it catches up are the "extra blocks" column in section 4.5.

## 6. Emission

### 6.1 The inconsistency in the outline

The outline gives four figures: about 6.92 GHOST per block at the start, a
two-year halving, a tail of 0.2 GHOST per block "after about eight years", and
21 million GHOST of main emission with 29% in year one and 75% by year four.

The last three of those are the same fact. A smooth per-block decline whose
total area is 21 million and whose half-life is two years starts at
`21,000,000 x ln 2 / 2,102,400 = 6.92356` GHOST per block (2,102,400 blocks is
two years at 30 seconds), issues `1 - 2^(-1/2) = 29.3%` in year one, and
`1 - 2^(-2) = 75%` by year four. So 6.92 and the 29% and 75% fix each other.

The fourth does not fit. At that start and half-life, the reward at year eight
is 6.92 / 16 = 0.43 GHOST, not 0.2, and it reaches 0.2 only at year 10.23.

### 6.2 Options

The script evaluates each way of making them agree (analysis in floating point,
not consensus):

| Option | Start reward | Half-life (years) | Tail starts (year) | Issued in year 1 | Issued by year 4 |
|---|---|---|---|---|---|
| A. Keep 6.92 GHOST and a 2-year half-life; tail starts where the curve reaches 0.2 (proposed) | 6.924 | 2.00 | 10.23 | 29.3% | 75.0% |
| B. Force the tail at year 8 by shortening the half-life | 9.690 | 1.43 | 8.00 | 38.4% | 85.6% |
| C. Force the tail at year 8 by lowering the start reward (2-year half-life) | 3.200 | 2.00 | 8.00 | 13.5% | 34.7% |
| D. Add the 0.2 tail on top of the decaying curve from block one | 7.124 | 2.00 | none (no switch) | 30.3% | 79.0% |
| E. Raise the start reward so the decaying part alone sums to 21M | 7.124 | 2.00 | 10.31 | 30.1% | 77.2% |

Options B and C break the 29% and 75% targets (and C cannot reach 21 million at
all: its curve sums to 9.7 million). Options D and E keep the tail but move
year one to 30%, year four to 77% to 79%, and E needs a start reward of 7.12.
Option A changes none of the numbers the outline cares about; it changes only
the sentence "the tail begins after about eight years".

### 6.3 Proposal for the founder

**Keep 6.92356 GHOST at the start and the two-year half-life, and let the tail
begin when the curve reaches 0.2 GHOST, which is at year 10.23** (block
10,750,502 at 30 seconds). The outline's "after about eight years" becomes
"after about ten years". Nothing else in the outline changes. This is the
smallest change that keeps the pace (29.28% in year one, 75.00% by year four)
and the 0.2 GHOST tail.

Consequences the founder should know about:

- **"21 million" is the area of the curve, not a total reached before the tail.**
  The schedule follows the decaying curve until it equals 0.2, and by then it
  has issued 20,393,381 GHOST (97.11% of 21 million). From then the tail adds
  0.2 per block, so total issuance passes 21 million at about year 13.1 and
  keeps rising. This matches the outline's statement that 21 million is never
  described as a cap.
- **The tail is 210,240 GHOST per scheduled year**, which is 1.001% of 21
  million, not exactly 1% (0.2 x 1,051,200 blocks). "About 1% a year" is the
  accurate wording.
- If the founder wants the decaying part alone to reach exactly 21 million before
  the tail, option E does it with a start reward of 7.12 GHOST and 30.1% in year
  one, 77.2% by year four. This document does not propose it.

### 6.4 The reward function

Define for height `h >= 1` (the genesis block has no reward):

```python
LN2   = 0xB17217F7D1CF79ABC9E3B39803F2F6AF        # floor(ln 2 * 2^128)
ONE   = 1 << 128

def reward(h):                                     # wei
    H = 63_072_000 // B                            # half-life in blocks
    e = h - 1                                      # the first block has e = 0
    q = min(e // H, 255)                           # completed half-lives
    r = e % H                                      # position inside this half-life
    u = (r * LN2) // H                             # r/H * ln 2, scaled by 2^128
    s = ONE
    for k in range(24, 0, -1):                     # Horner form of e^(-u), 24 terms
        s = ONE - ((u * s) >> 128) // k            # s ends near 2^(-r/H) * 2^128
    decayed = (R0 * s) >> (128 + q)                # floor(R0 * 2^(-e/H))
    return decayed if decayed > TAIL else TAIL
```

| Constant | 30-second chain | 60-second chain |
|---|---|---|
| `R0` | 6,923,560,000,000,000,000 (6.92356 GHOST) | 13,847,120,000,000,000,000 |
| `TAIL` | 200,000,000,000,000,000 (0.2 GHOST) | 400,000,000,000,000,000 |
| Half-life `H` | 2,102,400 blocks | 1,051,200 blocks |
| Blocks per year | 1,051,200 | 525,600 |

Notes for implementers:

- `R0` is chosen so that the curve's area, `R0 x H / ln 2`, is within 0.00002%
  of 21 million GHOST (21,000,002.5).
- The e^(-u) series stops at 24 terms: the omitted term is below 2^-90, so the
  reward is the floor of the true curve except possibly by one wei in rare
  cases. The algorithm as written, not the true curve, is the rule. The script
  checks the algorithm against 90-digit decimals at 300 random heights and at
  both ends of every boundary, and requires a difference of at most one wei.
- **Rounding:** a single floor, in the final shift. There is no rounding up.
- **Size:** `u < 0.7 x 2^128` and `s <= 2^128`, so `u x s` stays below 2^256; `R0
  x s` is below 2^192. Implementations must use at least 256-bit integers, and
  the multiplication `u x s` must not overflow a 256-bit register. The reward
  itself needs 64 bits unsigned (the 60-second `R0` exceeds 2^63).
- **Tail transition:** there is no separate switch height. The tail applies when
  the decayed value is not larger than `TAIL`, so the reward never drops below
  0.2 GHOST and never has a discontinuity. The first block that pays the tail is
  the first whose floor is at most `TAIL`: block 10,750,502 at 30 seconds, block
  5,375,252 at 60 seconds. The reward is non-increasing in `h` (the script
  checks 6,000 heights around the boundary).
- `q` is capped at 255 so the shift stays small; far beyond that the decayed
  value is zero and the tail applies.

### 6.5 Scaling with the block time

The yearly amounts must not depend on the block time. At 60 seconds there are
half as many blocks per year, so the half-life in blocks halves and the reward
and tail double. In the formula this is only `H = 63,072,000 // B` and the
60-second constants. No other term depends on `B`. The `60 s minus 30 s` column
below is the difference in cumulative issuance between the two schedules: about 3
GHOST in 20 million, which comes from the one-block discretisation (a 60-second
block pays the reward at its start for twice as long), not from the parameters.

### 6.6 Emission table and checks

Script output. "Issued in year" is the sum of rewards for the 1,051,200 blocks
of that scheduled year at 30 seconds.

| Year | First reward, 30 s | First reward, 60 s | Issued in year (30 s) | Cumulative (30 s) | Share of 21M | Cumulative (60 s) | 60 s minus 30 s |
|---|---|---|---|---|---|---|---|
| 1 | 6.92356 | 13.84712 | 6,150,759.34 | 6,150,759.34 | 29.28% | 6,150,760.36 | 1.01 |
| 2 | 4.89569 | 9.79139 | 4,349,243.64 | 10,500,002.99 | 50.00% | 10,500,004.72 | 1.73 |
| 3 | 3.46178 | 6.92356 | 3,075,379.67 | 13,575,382.66 | 64.64% | 13,575,384.90 | 2.23 |
| 4 | 2.44784 | 4.89569 | 2,174,621.82 | 15,750,004.49 | 75.00% | 15,750,007.08 | 2.59 |
| 5 | 1.73089 | 3.46178 | 1,537,689.83 | 17,287,694.32 | 82.32% | 17,287,697.17 | 2.84 |
| 6 | 1.22392 | 2.44784 | 1,087,310.91 | 18,375,005.24 | 87.50% | 18,375,008.27 | 3.02 |
| 7 | 0.86544 | 1.73089 | 768,844.91 | 19,143,850.15 | 91.16% | 19,143,853.31 | 3.15 |
| 8 | 0.61196 | 1.22392 | 543,655.45 | 19,687,505.61 | 93.75% | 19,687,508.86 | 3.24 |
| 9 | 0.43272 | 0.86544 | 384,422.45 | 20,071,928.07 | 95.58% | 20,071,931.38 | 3.30 |
| 10 | 0.30598 | 0.61196 | 271,827.72 | 20,343,755.80 | 96.87% | 20,343,759.15 | 3.35 |
| 11 | 0.21636 | 0.43272 | 212,165.52 | 20,555,921.32 | 97.88% | 20,555,924.69 | 3.36 |
| 12 | 0.20000 | 0.40000 | 210,240.00 | 20,766,161.32 | 98.88% | 20,766,164.69 | 3.36 |
| 13 | 0.20000 | 0.40000 | 210,240.00 | 20,976,401.32 | 99.88% | 20,976,404.69 | 3.36 |
| 14 | 0.20000 | 0.40000 | 210,240.00 | 21,186,641.32 | 100.88% | 21,186,644.69 | 3.36 |

Reward parameters (wei): R0(30 s) = 6,923,560,000,000,000,000; tail(30 s) = 200,000,000,000,000,000; R0(60 s) = 13,847,120,000,000,000,000; tail(60 s) = 400,000,000,000,000,000.
Blocks per year: 1,051,200 at 30 s, 525,600 at 60 s. Half-life: 2,102,400 blocks at 30 s, 1,051,200 at 60 s.
Area under the whole decaying curve (R0 x half-life / ln 2): 21,000,002.52 GHOST.
Tail starts at height 10,750,502 (30 s), year 10.227; height 5,375,252 (60 s), year 10.227.
Issued before the tail starts: 20,393,381.52 GHOST at 30 s (97.11% of 21,000,000); 20,393,385.09 GHOST at 60 s.
Total issuance first passes 21,000,000 GHOST at about year 13.11; it is then 210,240.00 GHOST per year (1% of 21,000,000 is 210,000).
Reward at the start of year 9 is 0.43272 GHOST (outline: tail begins around year 8).

The pace targets hold: 29.28% in year one, 75.00% by year four. Rows for years
12 to 14 show the tail: 0.2 per block, 210,240 per year.

Reward vectors for the node's tests, from the same function:

| Block time | Height | Reward (wei) |
|---|---|---|
| 30 s | 1 | 6,923,560,000,000,000,000 |
| 30 s | 2 | 6,923,557,717,349,076,136 |
| 30 s | 1,051,200 | 4,895,697,840,030,412,474 |
| 30 s | 1,051,201 | 4,895,696,225,951,932,978 |
| 30 s | 2,102,400 | 3,461,781,141,325,838,219 |
| 30 s | 2,102,401 | 3,461,780,000,000,000,000 |
| 30 s | 4,204,801 | 1,730,890,000,000,000,000 |
| 30 s | 8,409,601 | 432,722,500,000,000,000 |
| 30 s | 10,512,001 | 216,361,250,000,000,000 |
| 30 s | 10,750,501 | 200,000,049,462,428,603 |
| 30 s | 10,750,502 | 200,000,000,000,000,000 |
| 30 s | 1,000,000,000 | 200,000,000,000,000,000 |
| 60 s | 1 | 13,847,120,000,000,000,000 |
| 60 s | 2 | 13,847,110,869,397,809,694 |
| 60 s | 525,600 | 9,791,398,908,218,848,244 |
| 60 s | 525,601 | 9,791,392,451,903,865,956 |
| 60 s | 1,051,200 | 6,923,564,565,304,105,452 |
| 60 s | 1,051,201 | 6,923,560,000,000,000,000 |
| 60 s | 2,102,401 | 3,461,780,000,000,000,000 |
| 60 s | 4,204,801 | 865,445,000,000,000,000 |
| 60 s | 5,256,001 | 432,722,500,000,000,000 |
| 60 s | 5,375,251 | 400,000,098,924,857,207 |
| 60 s | 5,375,252 | 400,000,000,000,000,000 |
| 60 s | 1,000,000,000 | 400,000,000,000,000,000 |

These are issuance, not circulating supply. The base fee is burned (decision
0001) and Vanish removes coins from the supply (outline), so circulating supply
is lower than cumulative issuance.

## 7. Who receives the reward

- The whole block reward, `reward(h)`, and the priority fees of the block's
  transactions go to the block's `coinbase` address. Nothing is diverted to a
  treasury, a developer address or any other account.
- The base fee is burned, as decision 0001 specifies. It is not part of the
  reward.
- **No uncles.** The header's uncle hash must equal the hash of the empty list
  (Keccak-256 of `0xc0`), and a block that carries any uncle is invalid. There
  is no uncle reward, no nephew reward, and the difficulty formula has no uncle
  term (geth's EIP-100 adjustment is removed with the rest of its difficulty
  code). Blocks that lose a race earn nothing, which is why section 3 measures
  the stale rate.
- The genesis block has no reward and its allocation is empty.

## 8. Genesis and the Bitcoin anchor

### 8.1 What the claim is

The outline says the first block embeds the hash of a recent Bitcoin block. The
base client plan asks for this to be a fixed procedure, so that two independent
operators, with the frozen software and public Bitcoin data, derive
byte-identical genesis blocks, and no announcement decides which chain is real.

The claim it supports is worded exactly:

> No Ghost block was mined before Bitcoin block B was found.

It does not say that nobody mined between B and launch, or that nobody holds
Ghost coins before launch day. Ghost's rules allow no allocation, so the claim
about holding follows from "no premine", which is a property of the genesis
allocation (empty) and of the absence of any other mint path, not of the Bitcoin
hash. Embedding a hash of an unpredictable block shows that the chain was not
started before that block existed, because nobody could have included its hash
earlier.

### 8.2 Constants in the frozen software

| Name | Value |
|---|---|
| `T_L` | The launch time, Unix seconds, announced at least 30 days ahead and fixed in the frozen release at least two weeks ahead |
| `CONFIRMATIONS` | 6 |

### 8.3 The rule

All data is Bitcoin mainnet, on the best chain (most accumulated work) as seen by
the operator's own fully validating node. `MTP(b)` is Bitcoin's median time
past: the median of the header timestamps of block `b` and its 10 predecessors.

1. **Selection.** `B` is the Bitcoin block of lowest height with `MTP(B) >= T_L`.
   (Median time past never decreases along a chain, so the lowest such block is
   well defined, and a block's own timestamp, which a miner can push forward by
   hours, does not decide it.)
2. **Confirmation.** The derivation is made only when the best chain's tip is at
   height `h(B) + 5` or higher, so that `B` has 6 confirmations counting itself.
3. **Confirmation block.** `C` is the block at height `h(B) + 5` on the same
   chain.
4. **Genesis fields.**
   - `timestamp` = the header timestamp of `C`.
   - `extraData` = the 32 bytes of `B`'s hash, in the byte order of the 64
     hexadecimal characters Bitcoin Core prints for it (`getblockhash`).
   - `difficulty` = `D_START`.
   - `number` = 0, `parentHash` = 32 zero bytes, `coinbase` = 20 zero bytes,
     `nonce` and `mixDigest` = zero, `alloc` = empty, uncle hash = the empty
     list's hash (section 7).
   - Every other header field is a constant of the frozen chain configuration,
     defined in the header specification, with no operator input.

The genesis timestamp is that of `C`, not `B`, so that the difficulty schedule
starts when mining can actually start. Block 1 can only be mined after `C`
exists, because that is when the genesis hash exists.

The expected time from `T_L` to a derivable genesis is one to two hours (median
time past trails real time by about an hour, and `C` follows `B` by five blocks).
Miners run their software ahead of `T_L` and start when the tool reports a
genesis.

### 8.4 Bitcoin reorganisations

- **Before the confirmation depth.** If `B` leaves the best chain before the tip
  reaches `h(B) + 5`, the candidate is discarded and the selection in step 1 is
  run again on the new best chain. This is a pure function of the best chain, so
  the new `B` may be the same height with a different hash. No genesis exists
  until step 2 is satisfied.
- **After the confirmation depth.** The first derivation that satisfies step 2
  is final. A later Bitcoin reorganisation that removes `B` does not change
  Ghost's genesis; Ghost nodes never read Bitcoin. The embedded hash still
  proves what it proved: `B` existed when the genesis was derived with 6
  confirmations.
- **A reorganisation of six or more blocks that crosses `B` after some operators
  derived genesis and before others did** is outside the model. It has not
  happened in normal Bitcoin operation for over a decade, to our knowledge. If it
  is observed before Ghost's first block, Ghost is not launched on that genesis
  and the project announces a new `T_L` with the usual 30 days' notice. After the
  first block exists, nothing changes.

### 8.5 Checking it

Everything needed is 17 consecutive Bitcoin headers: the 11 before `B`, `B`, and
the 5 after. That is enough to compute `MTP(B)` and `MTP` of the block before
it (to show `B` is the lowest, since median time past never decreases), to read
the timestamp of `C` and the hash of `B`, and to check Bitcoin's proof of work
on each header against a minimum-work constant in the tool. The release includes a
tool that derives the genesis from such a file, and an announcement of the
derived genesis hash is a convenience only: a node and an operator trust their
own derivation, and if it differs from any announcement, the derivation wins.

## 9. Reproducing the numbers

```sh
python3 scripts/consensus_check.py            # about 10 seconds
python3 scripts/consensus_check.py --section asert
```

The script uses only the Python standard library, implements sections 4.3 and
6.4 from the text above and not from any node code, and cross-checks them with
decimal arithmetic, closed forms and a seeded Monte Carlo run. It exits
non-zero if any check fails. The tables in sections 3 to 6 are its output,
copied unchanged. The Monte Carlo check (section 5.3, continuous time, no
integer rounding) printed:

```text
Steady state, full hashrate: mean block time 30.00 s; spread of ln(difficulty) 5.4% (formula 5.4%).
Departure to 1%, 200,000 trials: P(first wait over 1 h) = 17.8% (formula 17.7%); over 2 h = 0.60% (formula 0.56%).
```

and the run ended with `All checks passed.`

## 10. Follow-ups outside this document

- The founder's decision on section 6.3. If it is accepted, the outline's line
  "It begins after about eight years" changes to "about ten years". This
  document does not edit the outline.
- The RandomX engine specification must use the big-endian comparison in
  section 2 and the genesis hash as the first-epoch key (as the RandomX survey
  recommends).
- The header specification must list every genesis field that section 8.3 leaves
  to it.
- The node's difficulty, reward and genesis tests take their expected values
  from the script's vectors, not from the node's own output.
- `D_START` is confirmed from the real launch hashrate before the software
  freeze (section 4.5), and the block-time test (section 3) runs in phase 2.
