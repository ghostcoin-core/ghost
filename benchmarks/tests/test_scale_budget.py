"""Tests for benchmarks/scale/budget.py: the budgets at the scale target."""

import contextlib
import io
import runpy
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scale"))

import budget  # noqa: E402


def changed(**values):
    inputs = dict(budget.INPUTS)
    inputs.update(values)
    return inputs


class Target(unittest.TestCase):
    def test_target_inputs_are_unchanged(self):
        # 1 million a day in total; the private row is the worst case of all
        # of them being private reveals, the public row the same total.
        self.assertEqual(budget.INPUTS["private_per_day"], 1_000_000)
        self.assertEqual(budget.INPUTS["public_per_day"], 1_000_000)
        self.assertEqual(budget.INPUTS["private_per_block"], 350)
        self.assertEqual(budget.INPUTS["public_per_block"], 350)
        self.assertEqual(budget.blocks_per_day(), 2_880)
        # About 347.2 a block, taken as 350.
        per_block = budget.INPUTS["private_per_day"] / budget.blocks_per_day()
        self.assertEqual(round(per_block, 1), 347.2)
        self.assertGreaterEqual(budget.INPUTS["private_per_block"], per_block)
        self.assertEqual(budget.INPUTS["new_leaves_per_day"], budget.INPUTS["private_per_day"])


class Private(unittest.TestCase):
    def test_non_proof_bytes(self):
        self.assertEqual(budget.private_non_proof_bytes(), 347)
        self.assertEqual(budget.private_non_proof_bytes_per_block(), 121_450)

    def test_proof_bytes(self):
        self.assertEqual(budget.private_proof_bytes_per_block(), 350 * 1_310_720)
        self.assertEqual(budget.private_proof_bytes_per_block(), 458_752_000)
        self.assertEqual(budget.private_proof_bytes_per_day(), 1_310_720_000_000)
        self.assertEqual(budget.private_envelope_bytes_per_day(), 1_311_067_000_000)

    def test_gas_under_todays_rule(self):
        self.assertEqual(budget.gas_per_block_today(), 7_381_630_200)
        self.assertEqual(budget.gas_limit_multiple(), 246.05434)
        self.assertEqual(budget.private_per_block_today(), 1)

    def test_changing_an_input_changes_the_output(self):
        inputs = changed(private_per_block=100, private_proof_field_bytes=1_000_000)
        self.assertEqual(budget.private_proof_bytes_per_block(inputs), 100_000_000)
        self.assertEqual(budget.private_non_proof_bytes(inputs), 311_067)
        self.assertEqual(budget.gas_per_block_today(changed(private_gas=1_000)), 350_000)
        self.assertEqual(budget.gas_limit_multiple(changed(block_gas_limit=7_381_630_200)), 1)
        self.assertEqual(budget.private_proof_bytes_per_day(changed(private_per_day=1)), 1_310_720)


class Public(unittest.TestCase):
    def test_signature_bytes(self):
        self.assertEqual(budget.public_signature_bytes_per_block(), 1_306_900)

    def test_against_the_message_cap(self):
        self.assertEqual(budget.INPUTS["message_cap_bytes"], 10_485_760)
        self.assertEqual(budget.public_and_private_non_proof_bytes_per_block(), 1_428_350)
        self.assertEqual(budget.bytes_over_message_cap(), -9_057_410)
        self.assertTrue(budget.fits_message_cap())

    def test_changing_an_input_changes_the_output(self):
        inputs = changed(public_auth_bytes=100)
        self.assertEqual(budget.public_signature_bytes_per_block(inputs), 35_000)
        self.assertEqual(budget.public_and_private_non_proof_bytes_per_block(inputs), 156_450)
        self.assertTrue(budget.fits_message_cap(inputs))
        self.assertFalse(budget.fits_message_cap(changed(message_cap_bytes=156_449, public_auth_bytes=100)))


class RestoreAndState(unittest.TestCase):
    def test_restore_volume(self):
        # A 32-byte leaf and its 380-byte note (spec 10, section 3.2).
        self.assertEqual(budget.INPUTS["leaf_and_note_bytes"], 32 + 380)
        self.assertEqual(budget.restore_bytes_per_day(), 412_000_000)
        self.assertEqual(budget.restore_bytes_per_year(), 150_380_000_000)

    def test_markers_and_trees(self):
        self.assertEqual(budget.marker_bytes_per_year(), 11_680_000_000)
        self.assertEqual(budget.days_to_fill_tree(), 4294.967296)

    def test_changing_an_input_changes_the_output(self):
        self.assertEqual(budget.restore_bytes_per_day(changed(new_leaves_per_day=1)), 412)
        self.assertEqual(budget.restore_bytes_per_year(changed(days_per_year=1)), 412_000_000)
        self.assertEqual(budget.restore_bytes_per_day(changed(leaf_and_note_bytes=188)), 188_000_000)
        self.assertEqual(budget.days_to_fill_tree(changed(new_leaves_per_day=2 ** 31)), 2)


class Merging(unittest.TestCase):
    def test_batch_of_merges(self):
        self.assertEqual(budget.merges_per_block(), 349)
        self.assertEqual(budget.machine_seconds(349, "0.3"), 104.7)
        self.assertEqual(budget.min_wall_seconds(349, "0.3", 40), 2.6175)
        self.assertEqual(budget.min_wall_seconds(349, 0.3, 40), 2.6175)

    def test_block_budget(self):
        self.assertEqual(
            budget.block_merge_budget(),
            {
                "merges": 349,
                "machine_seconds": 104.7,
                "min_wall_seconds": 2.6175,
                "tree_levels": 9,
                "critical_path_seconds": 2.7,
                "level_schedule_wall_seconds": 4.8,
            },
        )

    def test_tree_schedule(self):
        self.assertEqual(budget.merge_tree_levels(1), 0)
        self.assertEqual(budget.merge_tree_levels(2), 1)
        self.assertEqual(budget.merge_tree_levels(4), 2)
        self.assertEqual(budget.merge_tree_levels(5), 3)
        self.assertEqual(budget.level_schedule_wall_seconds(4, 1, 1), 3)
        self.assertEqual(budget.level_schedule_wall_seconds(4, 1, 2), 2)

    def test_changing_an_input_changes_the_output(self):
        more = budget.block_merge_budget(changed(machines=80))
        self.assertEqual(more["min_wall_seconds"], 1.30875)
        self.assertEqual(more["machine_seconds"], 104.7)
        slower = budget.block_merge_budget(changed(merge_seconds="0.5", private_per_block=1_001))
        self.assertEqual(slower["merges"], 1_000)
        self.assertEqual(slower["machine_seconds"], 500)
        self.assertEqual(slower["min_wall_seconds"], 12.5)


class Command(unittest.TestCase):
    def test_report_names_the_figures(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            runpy.run_path(str(HERE.parent / "scale" / "budget.py"), run_name="__main__")
        text = out.getvalue()
        self.assertIn("Modeled", text)
        self.assertIn("7,381,630,200", text)
        self.assertIn("1,428,350", text)
        self.assertIn("2.6175", text)

    def test_workload_page_matches_the_model(self):
        text = (HERE.parent.parent / "docs" / "scale" / "workload.md").read_text(encoding="utf-8")
        for figure in (
            "| Private reveals a day | 1,000,000 |",
            "| Public transactions a day | 1,000,000 |",
            "| Blocks a day | 2,880 |",
            f"{budget.private_proof_bytes_per_block():,}",
            f"{budget.private_proof_bytes_per_day():,}",
            f"{budget.private_envelope_bytes_per_day():,}",
            f"{budget.public_signature_bytes_per_block():,}",
            f"{budget.public_and_private_non_proof_bytes_per_block():,}",
            f"{-budget.bytes_over_message_cap():,}",
            f"{budget.gas_per_block_today():,}",
            f"{budget.restore_bytes_per_day():,}",
            f"{budget.restore_bytes_per_year():,}",
            f"{budget.marker_bytes_per_year():,}",
        ):
            with self.subTest(figure=figure):
                self.assertIn(figure, text)


if __name__ == "__main__":
    unittest.main()
