"""Tests for the written sampling bound for Ghost's difficulty rule.

docs/scale/stage2-design.md, "Written sampling bound for Ghost's difficulty
rule", proves the bound the wallet's sampled header check rests on, and
benchmarks/scale/header_sample_bound.py evaluates it. These tests hold:

- the first slice's table of bits a sample, as benchmarks/scale/header_sample_bits.py
  prints it (run as a script and called as a module), against the written
  bound's table on the page: the bits a sample at one year must be the bound's,
  ratio for ratio and figure for figure, and a changed figure on either side or
  a broken formula in the first slice fails;
- the bound's table, its luck table and the modeled bytes row on the page
  against the script;
- the theorem against its closed form at every fork point, the leftmost
  invalid stretch against other placements of the same work, and the
  sampler's own draw rule against the bound's hit chance;
- Lemma C against a simulated attacker that raises its difficulty as fast as
  the rule allows.

The byte counts of the client's proof and Lemma B on the client's rule are
client/tests/header_sample_bound.rs's.
"""

import math
import random
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import header_sample_bits  # noqa: E402
import header_sample_bound  # noqa: E402
import stage2  # noqa: E402

DOC = REPO / "docs" / "scale" / "stage2-design.md"
FIRST_SLICE = REPO / "benchmarks" / "scale" / "header_sample_bits.py"
SCRIPT = REPO / "benchmarks" / "scale" / "header_sample_bound.py"
FIRST_SLICE_START = "| Attacker's valid work against the honest chain's"
BOUND_START = header_sample_bound.BOUND_HEADER[0]
LUCK_START = header_sample_bound.LUCK_HEADER[0]


def page_text():
    return DOC.read_text(encoding="utf-8")


def table_at(lines, start):
    """The rows of the one table whose header row starts with `start`."""
    starts = [i for i, line in enumerate(lines) if line.startswith(start)]
    if len(starts) != 1:
        raise ValueError(f"expected one table starting {start!r}, found {len(starts)}")
    out = []
    for line in lines[starts[0]:]:
        if not line.startswith("|"):
            break
        out.append(line)
    return out


def cells(line):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def body(table):
    return [cells(line) for line in table[2:]]


def mismatches(first_slice, bound):
    """Every way the first slice's table differs from the written bound's: the
    same ratios in the same order, and the same bits a sample at one year."""
    first_rows, bound_rows = body(first_slice), body(bound)
    out = []
    if [row[0] for row in first_rows] != [row[0] for row in bound_rows]:
        out.append(f"ratios {[r[0] for r in first_rows]} against {[r[0] for r in bound_rows]}")
    for first, written in zip(first_rows, bound_rows):
        if first[1] != written[2]:
            out.append(f"{first[0]}: the first slice gives {first[1]} bits a sample, the bound {written[2]}")
    return out


def page_bound(text=None):
    return table_at((page_text() if text is None else text).splitlines(), BOUND_START)


def first_slice_output():
    run = subprocess.run(
        [sys.executable, "-I", str(FIRST_SLICE)], capture_output=True, text=True, check=True, cwd=REPO
    )
    return table_at(run.stdout.splitlines(), FIRST_SLICE_START)


class FirstSliceAgainstTheBound(unittest.TestCase):
    def test_the_printed_table_is_the_bound(self):
        self.assertEqual(mismatches(first_slice_output(), page_bound()), [])

    def test_the_module_table_is_the_bound(self):
        self.assertEqual(mismatches(header_sample_bits.table(), page_bound()), [])

    def test_the_page_carries_both_with_every_ratio(self):
        lines = page_text().splitlines()
        first, bound = table_at(lines, FIRST_SLICE_START), page_bound()
        self.assertEqual(len(body(first)), len(header_sample_bits.RATIOS))
        self.assertEqual(len(body(bound)), len(header_sample_bound.RATIOS))
        self.assertEqual(header_sample_bits.RATIOS, header_sample_bound.RATIOS)
        self.assertEqual(mismatches(first, bound), [])

    def test_a_changed_first_slice_figure_fails(self):
        changed = [line.replace("| 0.1069 |", "| 0.1070 |") for line in first_slice_output()]
        self.assertEqual(len(mismatches(changed, page_bound())), 1)
        dropped = first_slice_output()[:-1]
        self.assertNotEqual(mismatches(dropped, page_bound()), [])

    def test_a_changed_bound_figure_fails(self):
        text = page_text().replace("| 0.0714 | 0.1069 | 0.0912 |", "| 0.0714 | 0.1068 | 0.0912 |")
        self.assertEqual(len(mismatches(first_slice_output(), page_bound(text))), 1)

    def test_a_broken_first_slice_formula_fails(self):
        def log2_hit(ratio, delta):
            return -math.log2(1 - math.log2(1 / ratio) / math.log2(1 / delta) / 2)

        with mock.patch.object(header_sample_bits, "bits_per_sample", log2_hit):
            self.assertNotEqual(mismatches(header_sample_bits.table(), page_bound()), [])
        changed = dict(stage2.INPUTS, tail_headers=32)
        self.assertNotEqual(mismatches(header_sample_bits.table(changed), page_bound()), [])


class TheBoundOnThePage(unittest.TestCase):
    def test_the_bound_table_is_the_scripts(self):
        self.assertEqual(page_bound(), header_sample_bound.bound_table())

    def test_the_luck_table_is_the_scripts(self):
        self.assertEqual(table_at(page_text().splitlines(), LUCK_START), header_sample_bound.luck_table())

    def test_the_modeled_bytes_row_is_the_models(self):
        row = header_sample_bound.modeled_bytes_row()
        self.assertIn(row, page_text().splitlines())
        year = stage2.header_proof(stage2.chain(365)["blocks"])["bytes"]
        five = stage2.header_proof(stage2.chain(5 * 365)["blocks"])["bytes"]
        self.assertEqual((year, five), (1_247_246, 1_667_534))
        self.assertIn("| Header proof bytes (modeled) | 1.2 MB | 1.7 MB | none |", page_text().splitlines())

    def test_the_script_prints_every_table(self):
        run = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True, check=True, cwd=REPO)
        lines = run.stdout.splitlines()
        self.assertEqual(table_at(lines, BOUND_START), page_bound())
        self.assertEqual(table_at(lines, LUCK_START), table_at(page_text().splitlines(), LUCK_START))
        self.assertIn(header_sample_bound.modeled_bytes_row(), lines)

    def test_the_stated_figures(self):
        text = page_text()
        self.assertIn(f"`rho = {header_sample_bound.RISE}`", text)
        self.assertIn(f"= {header_sample_bound.rise_bound():.5f}`", text)
        self.assertIn(f"{header_sample_bound.lone_raised_header(0.5):.1%} at a third of the hashrate", text)
        ratio = stage2.INPUTS["attacker_work_ratio"]
        self.assertIn(f"some {1 / ((header_sample_bound.RISE - 1) * ratio):.0f} at `c` = 0.5", text)
        quarter = header_sample_bound.luck_bits(ratio, 1 / 3, stage2.INPUTS["blocks_per_day"])
        self.assertIn(f"at a quarter the luck bound is {quarter:.1f} bits on a fork of one day", text)
        self.assertIn("### Written sampling bound for Ghost's difficulty rule", text.splitlines())

    def test_rho_rounds_the_proved_rise_up(self):
        proved = header_sample_bound.rise_bound()
        self.assertLessEqual(proved, header_sample_bound.RISE)
        self.assertLess(header_sample_bound.RISE - proved, 1e-4)
        self.assertGreater(proved, 2 ** (29 / 3600))


class Theorem(unittest.TestCase):
    def test_the_hit_chance_is_the_closed_form_at_every_fork(self):
        for days in (365, 5 * 365):
            tail = header_sample_bound.delta(days)
            for ratio in header_sample_bound.RATIOS:
                closed = math.log(1 / ratio) / math.log(1 / tail)
                for fork in header_sample_bound.fork_points(ratio, tail):
                    stretch = header_sample_bound.worst_stretch(ratio, fork)
                    self.assertAlmostEqual(header_sample_bound.hit_of_set([stretch], tail), closed, places=10)
                self.assertAlmostEqual(header_sample_bound.hit_chance(ratio, tail), closed, places=10)
                self.assertEqual(
                    f"{header_sample_bound.bits(closed):.4f}",
                    f"{header_sample_bits.bits_per_sample(ratio, tail):.4f}",
                )

    def test_the_general_form(self):
        tail = header_sample_bound.delta(365)
        for iota in (0.01, 0.1, 0.4, 0.75):
            fork = 0.3
            stretch = (fork, fork + iota * (1 - fork))
            expected = math.log(1 / (1 - iota)) / math.log(1 / tail)
            self.assertAlmostEqual(header_sample_bound.hit_of_set([stretch], tail), expected, places=10)

    def test_the_leftmost_stretch_is_the_least_likely(self):
        rng = random.Random(4322)
        tail = header_sample_bound.delta(365)
        for _ in range(300):
            ratio = rng.choice(header_sample_bound.RATIOS)
            fork = rng.uniform(0, 1 - tail / ratio)
            length = (1 - ratio) * (1 - fork)
            room = (1 - tail) - fork - length
            pieces = rng.randint(1, 6)
            cuts = sorted(rng.uniform(0, length) for _ in range(pieces - 1))
            sizes = [b - a for a, b in zip([0.0] + cuts, cuts + [length])]
            gaps = [rng.random() for _ in range(pieces + 1)]
            gaps = [room * g / sum(gaps) for g in gaps]
            intervals, at = [], fork
            for gap, size in zip(gaps, sizes):
                at += gap
                intervals.append((at, at + size))
                at += size
            least = header_sample_bound.hit_of_set([header_sample_bound.worst_stretch(ratio, fork)], tail)
            self.assertGreaterEqual(header_sample_bound.hit_of_set(intervals, tail), least - 1e-9)

    def test_the_samplers_draw_rule_hits_at_the_bound(self):
        rng = random.Random(7)
        tail = header_sample_bound.delta(365)
        draws = 200_000
        for ratio in (0.5, 0.9):
            fork = 0.4
            low, high = header_sample_bound.worst_stretch(ratio, fork)
            hits = sum(1 for _ in range(draws) if low <= 1 - tail ** rng.random() < high)
            expected = header_sample_bound.hit_chance(ratio, tail)
            sigma = math.sqrt(expected * (1 - expected) / draws)
            self.assertLess(abs(hits / draws - expected), 5 * sigma, ratio)

    def test_the_samples_reach_the_target(self):
        for days, samples in ((365, 599), (5 * 365, 702)):
            tail = header_sample_bound.delta(days)
            per_sample = header_sample_bound.bits(header_sample_bound.hit_chance(0.5, tail))
            self.assertEqual(header_sample_bits.sample_count(0.5, 64, tail), samples)
            self.assertGreaterEqual(samples * per_sample, 64)
            self.assertLess((samples - 1) * per_sample, 64)

    def test_one_sample_always_hits_when_c_is_the_tail(self):
        self.assertEqual(header_sample_bound.hit_chance(0.001, 0.01), 1.0)
        self.assertEqual(header_sample_bound.bits(1.0), math.inf)


class LemmaC(unittest.TestCase):
    def test_no_bound_at_or_above_the_ratio(self):
        for q in (0.5, 0.6, 1.0):
            self.assertEqual(header_sample_bound.luck_bits(0.5, q, 2880), 0.0)

    def test_the_bound_grows_with_the_fork_and_falls_with_the_hashrate(self):
        bits = [header_sample_bound.luck_bits(0.5, q, 2880) for q in header_sample_bound.HASH_RATIOS]
        self.assertEqual(bits, sorted(bits, reverse=True))
        for q in (0.25, 0.4):
            self.assertLess(header_sample_bound.luck_bits(0.5, q, 2880), header_sample_bound.luck_bits(0.5, q, 10**6))
        # A long fork tends to the bunched work of 1 / ((rho - 1) c) headers.
        limit = header_sample_bound.rate(0.5, 0.25) / ((header_sample_bound.RISE - 1) * 0.5) / math.log(2)
        self.assertAlmostEqual(header_sample_bound.luck_bits(0.5, 0.25, 10**12), limit, places=6)

    def test_a_raising_attacker_stays_under_the_bound(self):
        """An attacker that stamps its headers a second apart, raising its
        difficulty 2^(29/3600) a header from the fork point's, against a fork
        of one day; each header takes an exponential number of hashes."""
        rng = random.Random(4334)
        blocks, ratio, q = 2880, 0.5, 0.4
        rise = 2 ** (29 / 3600)
        trials, wins = 4000, 0
        for _ in range(trials):
            budget, work, difficulty = q * blocks, 0.0, 1.0
            while work < ratio * blocks:
                difficulty *= rise
                budget -= rng.expovariate(1 / difficulty)
                if budget < 0:
                    break
                work += difficulty
            wins += work >= ratio * blocks
        bound = 2 ** -header_sample_bound.luck_bits(ratio, q, blocks)
        sigma = math.sqrt(bound * (1 - bound) / trials)
        self.assertLess(wins / trials, bound + 4 * sigma)

    def test_a_steady_attacker_never_reaches_the_ratio(self):
        rng = random.Random(1)
        blocks, ratio, q = 2880, 0.5, 0.4
        for _ in range(200):
            budget, work = q * blocks, 0.0
            while work < ratio * blocks:
                budget -= rng.expovariate(1.0)
                if budget < 0:
                    break
                work += 1.0
            self.assertLess(work, ratio * blocks)

    def test_the_lone_raised_header(self):
        self.assertAlmostEqual(header_sample_bound.lone_raised_header(0.5), 1 - math.exp(-0.5), places=15)
        self.assertEqual(f"{header_sample_bound.lone_raised_header(0.5):.1%}", "39.3%")


if __name__ == "__main__":
    unittest.main()
