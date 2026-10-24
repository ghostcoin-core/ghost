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
        self.assertEqual(budget.INPUTS["private_per_day"], 10_000_000)
        self.assertEqual(budget.INPUTS["public_per_day"], 10_000_000)
        self.assertEqual(budget.INPUTS["private_per_block"], 3_500)
        self.assertEqual(budget.INPUTS["public_per_block"], 3_500)
        self.assertEqual(budget.blocks_per_day(), 2_880)


class Private(unittest.TestCase):
    def test_non_proof_bytes(self):
        self.assertEqual(budget.private_non_proof_bytes(), 347)
        self.assertEqual(budget.private_non_proof_bytes_per_block(), 1_214_500)

    def test_proof_bytes(self):
        self.assertEqual(budget.private_proof_bytes_per_block(), 3_500 * 1_310_720)
        self.assertEqual(budget.private_proof_bytes_per_block(), 4_587_520_000)
        self.assertEqual(budget.private_proof_bytes_per_day(), 13_107_200_000_000)
        self.assertEqual(budget.private_envelope_bytes_per_day(), 13_110_670_000_000)

    def test_gas_under_todays_rule(self):
        self.assertEqual(budget.gas_per_block_today(), 73_816_302_000)
        self.assertEqual(budget.gas_limit_multiple(), 2460.5434)
        self.assertEqual(budget.private_per_block_today(), 1)

    def test_changing_an_input_changes_the_output(self):
        inputs = changed(private_per_block=100, private_proof_field_bytes=1_000_000)
        self.assertEqual(budget.private_proof_bytes_per_block(inputs), 100_000_000)
        self.assertEqual(budget.private_non_proof_bytes(inputs), 311_067)
        self.assertEqual(budget.gas_per_block_today(changed(private_gas=1_000)), 3_500_000)
        self.assertEqual(budget.gas_limit_multiple(changed(block_gas_limit=73_816_302_000)), 1)
        self.assertEqual(budget.private_proof_bytes_per_day(changed(private_per_day=1)), 1_310_720)


class Public(unittest.TestCase):
    def test_signature_bytes(self):
        self.assertEqual(budget.public_signature_bytes_per_block(), 13_069_000)

    def test_against_the_message_cap(self):
        self.assertEqual(budget.INPUTS["message_cap_bytes"], 10_485_760)
        self.assertEqual(budget.public_and_private_non_proof_bytes_per_block(), 14_283_500)
        self.assertEqual(budget.bytes_over_message_cap(), 3_797_740)
        self.assertFalse(budget.fits_message_cap())

    def test_changing_an_input_changes_the_output(self):
        inputs = changed(public_auth_bytes=100)
        self.assertEqual(budget.public_signature_bytes_per_block(inputs), 350_000)
        self.assertEqual(budget.public_and_private_non_proof_bytes_per_block(inputs), 1_564_500)
        self.assertTrue(budget.fits_message_cap(inputs))
        self.assertFalse(budget.fits_message_cap(changed(message_cap_bytes=1_564_499, public_auth_bytes=100)))


class RestoreAndState(unittest.TestCase):
    def test_restore_volume(self):
        self.assertEqual(budget.restore_bytes_per_day(), 1_880_000_000)
        self.assertEqual(budget.restore_bytes_per_year(), 686_200_000_000)

    def test_markers_and_trees(self):
        self.assertEqual(budget.marker_bytes_per_year(), 116_800_000_000)
        self.assertEqual(budget.days_to_fill_tree(), 429.4967296)

    def test_changing_an_input_changes_the_output(self):
        self.assertEqual(budget.restore_bytes_per_day(changed(new_leaves_per_day=1)), 188)
        self.assertEqual(budget.restore_bytes_per_year(changed(days_per_year=1)), 1_880_000_000)
        self.assertEqual(budget.days_to_fill_tree(changed(new_leaves_per_day=2 ** 31)), 2)


class Merging(unittest.TestCase):
    def test_batch_of_merges(self):
        self.assertEqual(budget.merges_per_block(), 3_499)
        self.assertEqual(budget.machine_seconds(3_499, "0.3"), 1049.7)
        self.assertEqual(budget.min_wall_seconds(3_499, "0.3", 40), 26.2425)
        self.assertEqual(budget.min_wall_seconds(3_499, 0.3, 40), 26.2425)

    def test_block_budget(self):
        self.assertEqual(
            budget.block_merge_budget(),
            {
                "merges": 3_499,
                "machine_seconds": 1049.7,
                "min_wall_seconds": 26.2425,
                "tree_levels": 12,
                "critical_path_seconds": 3.6,
                "level_schedule_wall_seconds": 28.2,
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
        self.assertEqual(more["min_wall_seconds"], 13.12125)
        self.assertEqual(more["machine_seconds"], 1049.7)
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
        self.assertIn("73,816,302,000", text)
        self.assertIn("14,283,500", text)
        self.assertIn("26.2425", text)


if __name__ == "__main__":
    unittest.main()
