"""Tests for scripts/check_chain_figures.py, against docs/benchmarks/results.md."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_chain_figures as ccf  # noqa: E402

RESULTS = (HERE.parent / "docs" / "benchmarks" / "results.md").read_text(encoding="utf-8")


def replaced(old, new):
    assert RESULTS.count(old) == 1, old
    return RESULTS.replace(old, new)


class Committed(unittest.TestCase):
    def test_results_agree(self):
        self.assertEqual(ccf.check_text(RESULTS), [])

    def test_constants(self):
        self.assertEqual(ccf.BLOCKS_PER_YEAR, 1_051_200)
        self.assertEqual(ccf.BUDGET_MS, 3_000)


class Mismatches(unittest.TestCase):
    def assertFails(self, text, fragment):
        failures = ccf.check_text(text)
        self.assertTrue(failures, "expected a mismatch")
        self.assertTrue(any(fragment in f for f in failures), failures)

    def test_blocks_per_year(self):
        self.assertFails(replaced("| Blocks per year | 1,051,200 |", "| Blocks per year | 1,051,000 |"),
                         "Blocks per year")

    def test_proofs_in_budget(self):
        self.assertFails(replaced("| keccak-256 | 2^2 | median | 8.51 | 3,000 | 352 |",
                                  "| keccak-256 | 2^2 | median | 8.51 | 3,000 | 353 |"),
                         "verification budget 2^2 median")

    def test_stated_proof_size_drives_the_tables(self):
        # A different stated proof size leaves every derived figure out of date.
        text = replaced("| 8.51 | 9.23 | 1,023,438 | 1,028,144 |",
                        "| 8.51 | 9.23 | 1,023,438 | 1,028,145 |")
        failures = ccf.check_text(text)
        self.assertTrue(any(f.startswith("capacity 2^2") for f in failures), failures)
        self.assertTrue(any(f.startswith("growth 2^2") for f in failures), failures)
        self.assertTrue(any(f.startswith("padding 2^2") for f in failures), failures)

    def test_stated_verification_time_drives_the_tables(self):
        text = replaced("| 8.51 | 9.23 | 1,023,438 |", "| 8.61 | 9.23 | 1,023,438 |")
        self.assertFails(text, "verification budget 2^2 median")

    def test_transactions_per_block(self):
        self.assertFails(replaced("| 1,028,308 | 4 MB | 4,000,000 | 3 | 352 | 3 | 0.100 |",
                                  "| 1,028,308 | 4 MB | 4,000,000 | 4 | 352 | 4 | 0.133 |"),
                         "capacity 2^2 4 MB")

    def test_fit_verdict(self):
        self.assertFails(replaced("| 3 | 3,084,924 | 25.53 | no | yes | yes | yes |",
                                  "| 3 | 3,084,924 | 25.53 | yes | yes | yes | yes |"),
                         "Fits 1 MB")

    def test_growth_per_year(self):
        self.assertFails(replaced("| 31,536,000 | 32,428,721,088,000 | 32.43 |",
                                  "| 31,536,000 | 32,428,721,088,000 | 32.42 |"),
                         "TB per year")

    def test_missing_growth_row(self):
        row = "| keccak-256 | 2^3 | 10 | none | 300 | 315,360,000 | 236,790,894,240,000 | 236.79 |\n"
        self.assertFails(replaced(row, ""), "chain growth: missing rows")

    def test_padding_per_year(self):
        self.assertFails(replaced("| 148,408,416,000 | 148.41 |", "| 148,408,416,000 | 148.40 |"),
                         "padding per year 2^2 1/s")

    def test_missing_section(self):
        self.assertFails(replaced("## Chain growth per year", "## Chain growth"),
                         "Chain growth per year")


if __name__ == "__main__":
    unittest.main()
