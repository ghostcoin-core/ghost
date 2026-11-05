"""Bits of assurance a sampled header gives against the attacker's ratio.

The wallet checks the header chain by sampling (docs/scale/stage2-design.md,
"Wallet restore volume", step 2; the client's header_sample module): the last
64 headers in full and headers drawn by cumulative work with density
1 / ((1 - x) ln(1/delta)) on [0, 1 - delta], delta the share of the 64-header
tail. Against an attacker whose valid work after its fork is at most a ratio c
of the honest work, one sample hits the invalid stretch with probability at
least ln(1/c) / ln(1/delta), so a sample gives

    bits per sample = -log2(1 - ln(1/c) / ln(1/delta))

bits (the FlyClient argument; the bound for Ghost's difficulty rule is not yet
established). This script prints the page's table of those bits against the
attacker ratios 0.25, 0.5, 0.75 and 0.9 at one year of chain, and the assurance
of the samples the page's 64-bit target needs at its input ratio of one half.
The chain inputs (blocks a day, days a year, the tail, the target and the
ratio) are those of benchmarks/scale/stage2.py.

Usage: python3 benchmarks/scale/header_sample_bits.py
"""

import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import stage2  # noqa: E402

RATIOS = (0.25, 0.5, 0.75, 0.9)

HEADER = (
    "| Attacker's valid work against the honest chain's (all modeled) "
    "| Bits a sample, one year | Assurance of the restore's samples, one year |",
    "|---|---|---|",
)


def _inputs(inputs):
    return stage2.INPUTS if inputs is None else inputs


def bits_per_sample(ratio, delta):
    """-log2(1 - ln(1/c) / ln(1/delta)); infinite when one sample always hits."""
    hit = math.log(1 / ratio) / math.log(1 / delta)
    if hit >= 1:
        return math.inf
    return -math.log2(1 - hit)


def sample_count(ratio, bits, delta):
    """The samples that reach `bits`: the target over the bits a sample, rounded up."""
    if delta >= 1:
        return 0
    per_sample = bits_per_sample(ratio, delta)
    if math.isinf(per_sample):
        return 1
    return max(1, math.ceil(bits / per_sample))


def delta(days, inputs=None):
    """The tail's share of the headers after `days` of chain at the target."""
    i = _inputs(inputs)
    return i["tail_headers"] / (i["blocks_per_day"] * days)


def one_year_delta(inputs=None):
    return delta(_inputs(inputs)["days_per_year"], inputs)


def table(inputs=None):
    """The table's lines, as the design page carries them."""
    i = _inputs(inputs)
    year = one_year_delta(i)
    samples = sample_count(i["attacker_work_ratio"], i["sampling_bits"], year)
    lines = list(HEADER)
    for ratio in RATIOS:
        bits = bits_per_sample(ratio, year)
        lines.append(f"| {ratio:.2f} (modeled) | {bits:,.4f} | {samples * bits:,.1f} bits |")
    return lines


def main(argv=None):
    print("\n".join(table()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
