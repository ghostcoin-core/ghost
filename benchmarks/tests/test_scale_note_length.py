"""The 380-byte note (spec 10, section 3.2) carried from the restore model to the pages that quote it.

Every figure checked here is computed by benchmarks/scale/restore_sim.py and
benchmarks/scale/budget.py and looked up, formatted as the pages print it, in
docs/scale/workload.md, designs.md, phone-results.md and stage1-verdict.md. A
page left at the 156-byte note, or a model input changed without its pages,
fails here.
"""

import sys
import unittest
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import budget  # noqa: E402
import restore_sim as rs  # noqa: E402

SCALE = REPO / "docs" / "scale"
YEAR = rs.leaves_after(365)
FIVE_YEARS = rs.leaves_after(5 * 365)


def page(name):
    return (SCALE / name).read_text(encoding="utf-8")


def row(text, start):
    for line in text.splitlines():
        if line.startswith(f"| {start} |"):
            return line
    raise AssertionError(f"no row {start!r}")


def gb(nbytes):
    return f"{nbytes / 1e9:,.1f} GB"


class Inputs(unittest.TestCase):
    def test_the_models_agree_on_the_note(self):
        self.assertEqual(rs.NOTE_BYTES, 380)
        self.assertEqual(rs.LEAF_AND_NOTE_BYTES, 412)
        self.assertEqual(budget.INPUTS["leaf_and_note_bytes"], rs.LEAF_AND_NOTE_BYTES)
        self.assertEqual(rs.NOTE_REST_BYTES, rs.NOTE_BYTES - rs.TAG_BYTES)


class Workload(unittest.TestCase):
    def test_restore_volume_rows(self):
        text = page("workload.md")
        day = row(text, "Leaves and notes a wallet downloads per day")
        self.assertIn(f"| {budget.restore_bytes_per_day():,} (", day)
        self.assertIn(f"x {rs.LEAF_AND_NOTE_BYTES} |", day)
        self.assertIn(f"| {budget.restore_bytes_per_year():,} (", row(text, "Per year"))

    def test_designs_quotes_the_same_volume(self):
        text = page("designs.md")
        self.assertIn(f"{rs.LEAF_AND_NOTE_BYTES} bytes each", text)
        self.assertIn(f"{budget.restore_bytes_per_day():,} bytes a day", text)
        self.assertIn(f"{budget.restore_bytes_per_year():,} bytes a year", text)


class PhoneResults(unittest.TestCase):
    def setUp(self):
        self.text = page("phone-results.md")

    def check(self, name, c):
        line = row(self.text, name)
        self.assertIn(f"| {c['leaf_and_note_bytes']:,}", line)
        self.assertIn(f"| {c['download_bytes']:,} (", line)
        self.assertIn(f"| {c['trial_decryptions']:,} |", line)
        if c["elapsed_seconds"] >= 1_000:
            self.assertIn(f"| {c['elapsed_seconds']:,.0f} s (", line)
        else:
            self.assertIn(f"| {c['elapsed_seconds']:.2f} s |", line)
        digits = 2 if c["peak_memory_bytes"] < 10 ** 7 else 1
        self.assertIn(f"| {c['peak_memory_bytes'] / 1e6:.{digits}f} MB |", line)

    def test_one_year(self):
        self.check("Baseline, one year (modeled)", rs.analytic(rs.BASELINE, YEAR, 52))
        self.check("Buckets, one year (modeled)", rs.analytic(rs.BUCKETS, YEAR, 52))
        self.check("Checkpoint, one year, key made at genesis (modeled)", rs.analytic(rs.CHECKPOINT, YEAR, 52, 0))

    def test_five_years(self):
        self.check("Baseline, five years (modeled)", rs.analytic(rs.BASELINE, FIVE_YEARS, 52))
        self.check("Buckets, five years (modeled)", rs.analytic(rs.BUCKETS, FIVE_YEARS, 52))
        birth = rs.leaves_after(4 * 365)
        self.check("Checkpoint, five years, key one year old (modeled)",
                   rs.analytic(rs.CHECKPOINT, FIVE_YEARS, 52, birth))

    def test_simulated_chain(self):
        self.check("Baseline, simulated 100,000 leaves (modeled)",
                   rs.analytic(rs.BASELINE, rs.TEST_LEAVES, len(rs.TEST_OWNED)))
        checkpoint = replace(rs.CHECKPOINT, epoch_leaves=rs.TEST_EPOCH_LEAVES)
        self.check("Checkpoint, simulated (modeled)",
                   rs.analytic(checkpoint, rs.TEST_LEAVES, len(rs.TEST_OWNED), rs.TEST_KEY_BIRTH))

    def test_catch_up(self):
        line = row(self.text, "Keeping up for 30 days: leaf and note bytes (modeled)")
        self.assertIn(f"| {rs.catch_up_bytes(rs.BASELINE, 30, 5)['leaf_and_note_bytes']:,} (", line)
        self.assertIn(f"| {rs.catch_up_bytes(rs.BUCKETS, 30, 5)['leaf_and_note_bytes']:,} (", line)

    def test_the_buckets_design_fetches_the_rest_of_the_note(self):
        self.assertIn(f"the other {rs.NOTE_REST_BYTES} bytes of the notes", self.text)
        self.assertIn(f"| 32 + {rs.NOTE_BYTES} = {rs.LEAF_AND_NOTE_BYTES} bytes |", self.text)


class Verdict(unittest.TestCase):
    def test_the_year_one_restore_figures(self):
        text = page("stage1-verdict.md")
        base = rs.analytic(rs.BASELINE, YEAR, 52)
        buckets = rs.analytic(rs.BUCKETS, YEAR, 52)
        self.assertIn(f"Full-restore download {gb(base['download_bytes'])} for the baseline, "
                      f"{gb(buckets['download_bytes'])} for buckets", text)
        self.assertIn(f"{gb(budget.restore_bytes_per_year())} a year of leaves", text)


class NoStaleFigures(unittest.TestCase):
    def test_no_page_quotes_the_188_byte_volume_as_current(self):
        # The day and year volumes and the year-one baseline download at the
        # 156-byte note.
        for name in ("workload.md", "designs.md", "phone-results.md", "stage1-verdict.md", "stage2-design.md"):
            text = page(name)
            for stale in ("1,880,000,000", "686,200,000,000", "803,028,515,648", "803.0 GB", "248.8 GB"):
                with self.subTest(page=name, figure=stale):
                    self.assertNotIn(stale, text)


if __name__ == "__main__":
    unittest.main()
