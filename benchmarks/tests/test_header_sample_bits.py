"""Tests for benchmarks/scale/header_sample_bits.py.

The script's table of bits a sample against the attacker's ratio must be the
table docs/scale/stage2-design.md prints under "Header sampling against a
stronger attacker", line for line, at the page's one-year delta (64 tail
headers of 2,880 a day for 365 days). The written bound for Ghost's difficulty
rule is not in the repository yet, so the page is the reference. The negative
cases change the page text or an input here; neither is the design.
"""

import math
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import header_sample_bits  # noqa: E402
import stage2  # noqa: E402

DOC = REPO / "docs" / "scale" / "stage2-design.md"
SCRIPT = REPO / "benchmarks" / "scale" / "header_sample_bits.py"
TABLE_START = "| Attacker's valid work against the honest chain's"


def page_table(text):
    """The lines of the page's table: its header row to the last row."""
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith(TABLE_START)]
    if len(starts) != 1:
        raise ValueError(f"expected one table, found {len(starts)}")
    out = []
    for line in lines[starts[0]:]:
        if not line.startswith("|"):
            break
        out.append(line)
    return out


class ScriptTableTest(unittest.TestCase):
    def setUp(self):
        self.page = page_table(DOC.read_text(encoding="utf-8"))

    def test_page_has_the_table(self):
        self.assertEqual(len(self.page), 2 + len(header_sample_bits.RATIOS))

    def test_script_prints_the_page_table(self):
        run = subprocess.run(
            [sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True, check=True, cwd=REPO
        )
        self.assertEqual(run.stdout.splitlines(), self.page)

    def test_table_matches_the_page(self):
        self.assertEqual(header_sample_bits.table(), self.page)

    def test_a_changed_page_figure_differs(self):
        text = DOC.read_text(encoding="utf-8").replace("| 0.1069 |", "| 0.1070 |")
        self.assertNotEqual(header_sample_bits.table(), page_table(text))
        text = DOC.read_text(encoding="utf-8").replace("| 9.4 bits |", "| 9.5 bits |")
        self.assertNotEqual(header_sample_bits.table(), page_table(text))

    def test_a_changed_input_differs(self):
        for change in ({"tail_headers": 32}, {"sampling_bits": 80}, {"attacker_work_ratio": 0.6}):
            inputs = dict(stage2.INPUTS, **change)
            self.assertNotEqual(header_sample_bits.table(inputs), self.page, change)


class FormulaTest(unittest.TestCase):
    def test_one_year_delta(self):
        self.assertEqual(header_sample_bits.one_year_delta(), 64 / (2880 * 365))

    def test_bits_per_sample_is_the_formula(self):
        delta = header_sample_bits.one_year_delta()
        for ratio in header_sample_bits.RATIOS:
            expected = -math.log2(1 - math.log(1 / ratio) / math.log(1 / delta))
            self.assertEqual(header_sample_bits.bits_per_sample(ratio, delta), expected)

    def test_agrees_with_the_stage2_model(self):
        blocks = stage2.chain(365)["blocks"]
        for ratio in header_sample_bits.RATIOS:
            model, _ = stage2.sample_bits(blocks, dict(stage2.INPUTS, attacker_work_ratio=ratio))
            ours = header_sample_bits.bits_per_sample(ratio, header_sample_bits.one_year_delta())
            self.assertAlmostEqual(ours, model, places=12)

    def test_sample_counts_of_the_page(self):
        year = header_sample_bits.one_year_delta()
        five = header_sample_bits.delta(5 * 365)
        self.assertEqual(header_sample_bits.sample_count(0.5, 64, year), 599)
        self.assertEqual(header_sample_bits.sample_count(0.5, 64, five), 702)
        self.assertEqual(stage2.samples_needed(stage2.chain(365)["blocks"]), 599)

    def test_edges(self):
        self.assertEqual(header_sample_bits.bits_per_sample(0.001, 0.01), math.inf)
        self.assertEqual(header_sample_bits.sample_count(0.001, 64, 0.01), 1)
        self.assertEqual(header_sample_bits.sample_count(0.5, 64, 1.0), 0)
        delta = header_sample_bits.one_year_delta()
        bits = [header_sample_bits.bits_per_sample(r, delta) for r in header_sample_bits.RATIOS]
        self.assertEqual(bits, sorted(bits, reverse=True))


if __name__ == "__main__":
    unittest.main()
