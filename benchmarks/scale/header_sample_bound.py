"""The written sampling bound for Ghost's difficulty rule, in numbers.

docs/scale/stage2-design.md, "Written sampling bound for Ghost's difficulty
rule", proves the bound the wallet's sampled header check rests on. This script
evaluates the proof's own quantities, apart from the closed form of the first
slice's script (benchmarks/scale/header_sample_bits.py), so that a test can
hold the two against each other:

- the hit chance of one sample (the theorem): the sampler's density
  1 / ((1 - x) ln(1/delta)) integrated numerically, by Simpson's rule, over the
  worst invalid stretch the theorem allows, the leftmost one after the fork,
  the least over several fork points;
- the bits a sample, -log2(1 - hit), at one and five years of chain;
- the luck bound of Lemma C: the bits of assurance that an attacker of a given
  hashrate does not reach the work ratio `c` along a chain linked from its
  fork, where Ghost's rule lets difficulty rise at most RISE a block (Lemma B);
- the lone raised header of the difficulty-raising attack, without the parent
  check: the chance that one header of the honest work after the fork is
  sealed with the attacker's hashes;
- the header proof bytes of the stage 2 model, at one and five years.

The chain inputs (blocks a day, days a year, the tail, the target and the
ratio) are those of benchmarks/scale/stage2.py. The measured byte counts of the
client's proof are client/tests/header_sample_bound.rs's.

Usage: python3 benchmarks/scale/header_sample_bound.py
"""

import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import stage2  # noqa: E402

RATIOS = (0.25, 0.5, 0.75, 0.9)
YEARS = (1, 5)
# Lemma B: the most one header's required difficulty can exceed its parent's
# under spec 06, section 4.3, on the 30-second chain: 2^(29/3600) times the
# cubic's error both ways, 1.00013 / 0.99987, rounded up.
RISE = 1.0059
BLOCK_SECONDS = 30
HALF_LIFE_SECONDS = 3600
CUBIC_ERROR = 0.00013
# Attacker hashrate against the honest hashrate, for the luck table.
HASH_RATIOS = (0.25, 1 / 3, 0.4, 0.5)
SIMPSON_STEPS = 2000

BOUND_HEADER = (
    "| Valid work after the fork against the honest work, `c` (all modeled) "
    "| Hit chance a sample, one year | Bits a sample, one year | Bits a sample, five years |",
    "|---|---|---|---|",
)
LUCK_HEADER = (
    "| Attacker's hashrate against the honest hashrate, at `c` = 0.5 (all modeled) "
    "| Luck bound, fork of one day | Luck bound, fork of one year |",
    "|---|---|---|",
)
BYTES_START = "| Modeled: the stage 2 model's header proof"


def _inputs(inputs):
    return stage2.INPUTS if inputs is None else inputs


def delta(days, inputs=None):
    """The tail's share of the work after `days` of chain at the target."""
    i = _inputs(inputs)
    return i["tail_headers"] / (i["blocks_per_day"] * days)


def density(x, tail_share):
    """The sampler's density over the share `x` of the claimed work."""
    return 1 / ((1 - x) * math.log(1 / tail_share))


def integrate(f, a, b, steps=SIMPSON_STEPS):
    """Simpson's rule for f over [a, b] with an even number of steps."""
    if b <= a:
        return 0.0
    h = (b - a) / steps
    total = f(a) + f(b)
    for k in range(1, steps):
        total += (4 if k % 2 else 2) * f(a + k * h)
    return total * h / 3


def hit_of_set(intervals, tail_share):
    """The chance one sample lands in a union of disjoint intervals of the
    claimed work's share, each clipped to the sampled span [0, 1 - delta]."""
    top = 1 - tail_share
    total = 0.0
    for a, b in intervals:
        a, b = max(0.0, a), min(b, top)
        total += integrate(lambda x: density(x, tail_share), a, b)
    return total


def worst_stretch(ratio, fork):
    """The leftmost invalid stretch after a fork at share `fork`: the share
    1 - c of the work after the fork, starting at the fork."""
    return (fork, fork + (1 - ratio) * (1 - fork))


def fork_points(ratio, tail_share):
    """Fork shares from genesis to the latest one the theorem allows, where the
    valid tail is the whole of the attacker's valid work: 1 - delta / c."""
    latest = 1 - tail_share / ratio
    return sorted({0.0, 0.5 * latest, 0.9 * latest, 0.999 * latest, latest})


def hit_chance(ratio, tail_share):
    """The theorem's least hit chance of one sample, by numerical integration
    over the worst stretch, the least over the fork points; 1 when one sample
    always hits (c at most delta)."""
    if ratio <= tail_share:
        return 1.0
    return min(hit_of_set([worst_stretch(ratio, fork)], tail_share) for fork in fork_points(ratio, tail_share))


def bits(hit):
    """Bits of assurance of a sample that hits with this chance."""
    return math.inf if hit >= 1 else -math.log2(1 - hit)


def bound_table(inputs=None):
    """The lines of the written bound's table, as the design page carries them."""
    i = _inputs(inputs)
    lines = list(BOUND_HEADER)
    for ratio in RATIOS:
        year = hit_chance(ratio, delta(i["days_per_year"], i))
        five = hit_chance(ratio, delta(5 * i["days_per_year"], i))
        lines.append(f"| {ratio:.2f} (modeled) | {year:.4f} | {bits(year):.4f} | {bits(five):.4f} |")
    return lines


def rise_bound():
    """Lemma B's bound on one header's rise over its parent, before rounding up."""
    step = (BLOCK_SECONDS - 1) / HALF_LIFE_SECONDS
    return 2 ** step * (1 + CUBIC_ERROR) / (1 - CUBIC_ERROR)


def rate(ratio, hash_ratio):
    """c ln(c/q) - c + q: the Chernoff rate of Lemma C, zero unless q < c."""
    if hash_ratio >= ratio:
        return 0.0
    return ratio * math.log(ratio / hash_ratio) - ratio + hash_ratio


def luck_bits(ratio, hash_ratio, blocks, rise=RISE):
    """Lemma C's bound in bits: an attacker of hashrate q times the honest one,
    whose valid leaves after a fork of `blocks` honest headers form a chain
    linked from the fork, reaches valid work c times the honest work with
    probability at most exp(-(H / cap) rate), cap = rise D_a + (rise - 1) c H,
    the honest difficulty steady at D_a so that H = blocks D_a."""
    cap = rise / blocks + (rise - 1) * ratio
    return rate(ratio, hash_ratio) / cap / math.log(2)


def luck_table(inputs=None):
    """The lines of Lemma C's table, as the design page carries them."""
    i = _inputs(inputs)
    ratio = i["attacker_work_ratio"]
    day = i["blocks_per_day"]
    year = i["blocks_per_day"] * i["days_per_year"]
    lines = list(LUCK_HEADER)
    for q in HASH_RATIOS:
        share = q / (1 + q)
        lines.append(
            f"| {q:.3f}, {share:.1%} of all hashrate (modeled) "
            f"| {luck_bits(ratio, q, day):.1f} bits | {luck_bits(ratio, q, year):.1f} bits |"
        )
    return lines


def lone_raised_header(hash_ratio):
    """Without the parent check: the chance that the attacker's hashes, q times
    the honest work after the fork, seal one header that carries that work, so
    that every leaf of its range is valid: 1 - exp(-q)."""
    return -math.expm1(-hash_ratio)


def modeled_proof_bytes(days, inputs=None):
    """The stage 2 model's header proof bytes after `days` of chain."""
    return stage2.header_proof(stage2.chain(days, inputs)["blocks"], inputs=inputs)["bytes"]


def modeled_bytes_row(inputs=None):
    i = _inputs(inputs)
    cells = [
        f"{modeled_proof_bytes(years * i['days_per_year'], i):,} bytes "
        f"({modeled_proof_bytes(years * i['days_per_year'], i) / stage2.MB:.1f} MB)"
        for years in YEARS
    ]
    return f"{BYTES_START}, the figure of the table above | {cells[0]} | {cells[1]} |"


def main(argv=None):
    print("\n".join(bound_table()))
    print()
    print("\n".join(luck_table()))
    print()
    print(modeled_bytes_row())
    return 0


if __name__ == "__main__":
    sys.exit(main())
