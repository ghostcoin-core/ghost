"""Tests for benchmarks/scale/throughput.py: the aggregator fleet's throughput and inclusion delay.

Every run here uses stated illustrative seconds (0.3 s a merge, the ceiling of workload.md,
whose figure for Ghost is not yet established), not the recursion records, so the tests are
fast and do not depend on a measurement.
"""

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import labels  # noqa: E402
import throughput as tp  # noqa: E402

DOC = REPO / "docs" / "scale" / "throughput.md"

# 500 reveals a block at 0.3 s a conversion and 0.3 s a merge: about 300 machine-seconds a
# block, so 10 machines are the work bound and 40 machines four times the arrivals.
BASE = dict(
    tp.INPUTS,
    reveals_per_block=500,
    public_per_block=0,
    conversion_seconds=0.3,
    merge_seconds=0.3,
    check_seconds=0.0,
    blocks=30,
    drain_limit_blocks=200,
)


def run(**changes):
    return tp.simulate(BASE, **changes)


class BatchArithmetic(unittest.TestCase):
    def test_the_rule_of_finite_resources(self):
        self.assertEqual(tp.batch_machine_seconds(3_499, "0.3"), 1049.7)
        self.assertEqual(tp.batch_min_wall_seconds(3_499, "0.3", 40), 26.2425)

    def test_a_simulated_batch_never_beats_the_work_bound(self):
        wall, busy = tp.fold_batch(3_500, 40, "0.3")
        self.assertAlmostEqual(busy, 1049.7, places=6)
        self.assertGreaterEqual(wall, 26.2425)
        # A greedy schedule is no worse than merging level by level (28.2 s, workload.md).
        self.assertLessEqual(wall, 28.2 + 1e-9)

    def test_critical_path_bounds_a_large_fleet(self):
        wall, _ = tp.fold_batch(3_500, 10_000, "0.3")
        self.assertAlmostEqual(wall, 12 * 0.3)
        self.assertEqual(tp.bundle_floor_seconds(3_500, 40, 0.0, 0.3), 26.2425)
        self.assertAlmostEqual(tp.bundle_floor_seconds(3_500, 10_000, 0.0, 0.3), 3.6)

    def test_delay_is_never_below_the_batch_minimum_wall_time(self):
        r = tp.simulate(
            BASE, reveals_per_block=3_500, conversion_seconds=0.0, machines=40, blocks=1,
            aggregator_shares=(1.0,), arrival_window_seconds=0, random_block_times=False,
        )
        self.assertEqual(r["included"], 3_500)
        self.assertGreaterEqual(r["min_delay"], tp.batch_min_wall_seconds(3_499, "0.3", 40))
        # Spread arrivals: every reveal waits at least for its conversion and one merge.
        spread = run(machines=40)
        self.assertGreaterEqual(spread["min_delay"], 0.3 + 0.3)

    def test_work_bound_machines(self):
        self.assertEqual(tp.work_bound_machines(tp.resolved(BASE)), 10)
        self.assertEqual(tp.split_machines(40, (0.4, 0.35, 0.25)), [16, 14, 10])
        self.assertEqual(sum(tp.split_machines(41, (0.5, 0.3, 0.2))), 41)


class Backlog(unittest.TestCase):
    def test_bounded_when_capacity_exceeds_arrivals(self):
        # The backlog counts reveals in flight, so a long gap between random blocks lifts it
        # for a while; it does not climb with the length of the run.
        short, long = run(machines=40, blocks=30), run(machines=40, blocks=60)
        self.assertLess(short["max_backlog"], 10 * 500)
        self.assertLess(long["max_backlog"], 10 * 500)
        values = [b for _, t, b in long["backlog"] if t <= 1800]
        first, second = values[: len(values) // 2], values[len(values) // 2:]
        self.assertLess(sum(second) / len(second), 2 * sum(first) / len(first))
        self.assertEqual(long["not_included"], 0)
        self.assertAlmostEqual(long["sustained_per_block"], 500, delta=100)

    def test_grows_without_bound_when_it_does_not(self):
        short, long = run(machines=5, blocks=30, drain_limit_blocks=5), run(machines=5, blocks=60, drain_limit_blocks=5)
        self.assertGreater(short["backlog_at_window_end"], 5 * 500)
        self.assertGreater(long["backlog_at_window_end"], 1.8 * short["backlog_at_window_end"])
        self.assertLess(long["sustained_per_block"], 0.6 * 500)

    def test_halving_the_fleet_at_least_doubles_drain_time(self):
        burst = dict(blocks=80, burst_factor=6.0, burst_start_block=10, burst_blocks=10)
        full, half = run(machines=40, **burst), run(machines=20, **burst)
        self.assertIsNotNone(full["drain_seconds"])
        self.assertIsNotNone(half["drain_seconds"])
        self.assertGreater(full["drain_seconds"], 0)
        self.assertGreaterEqual(half["drain_seconds"], 2 * full["drain_seconds"])


class Delay(unittest.TestCase):
    def test_a_burst_raises_the_p99_above_the_p50(self):
        calm = run(machines=40, blocks=60)
        burst = run(machines=40, blocks=60, burst_factor=6.0, burst_start_block=20, burst_blocks=10)
        self.assertGreater(burst["p99_delay"], burst["p50_delay"])
        self.assertGreater(burst["p99_delay"], calm["p99_delay"])

    def test_delay_is_reported_apart_from_throughput(self):
        r = run(machines=40)
        for key in ("sustained_per_block", "p50_delay", "p99_delay", "backlog", "drain_seconds"):
            self.assertIn(key, r)
        self.assertLessEqual(r["p50_delay"], r["p99_delay"])


class Adversarial(unittest.TestCase):
    def test_invalid_proofs_consume_capacity_and_raise_delay(self):
        clean = run(machines=15)
        attacked = run(machines=15, invalid_per_block=5_000, check_seconds=0.05)
        self.assertEqual(clean["work"]["invalid"], 0)
        self.assertAlmostEqual(attacked["work"]["invalid"], 30 * 5_000 * 0.05, places=3)
        self.assertGreater(attacked["p99_delay"], clean["p99_delay"])
        self.assertEqual(attacked["included"], attacked["arrived"])

    def test_late_failures_cost_conversion_and_merges_and_are_never_included(self):
        r = run(machines=40, invalid_per_block=50, late_failure_fraction=1.0)
        self.assertGreater(r["work"]["late"], 30 * 50 * 0.3)
        self.assertGreater(r["late_dropped"], 0)
        self.assertEqual(r["included"], r["arrived"])
        self.assertGreater(r["p99_delay"], run(machines=40)["p99_delay"])

    def test_a_queue_limit_bounds_what_an_aggregator_holds(self):
        r = run(machines=10, invalid_per_block=20_000, check_seconds=0.01, queue_limit=2_000)
        self.assertGreater(r["queue_dropped"]["invalid"], 0)


class Failures(unittest.TestCase):
    def test_machine_failures_waste_work_and_raise_delay(self):
        calm = run(machines=12, blocks=40)
        failed = run(machines=12, blocks=40, machine_failures=((150.0, 0, 3),))
        self.assertGreater(failed["work"]["wasted"], 0)
        self.assertGreaterEqual(failed["p99_delay"], calm["p99_delay"])

    def test_removing_the_largest_aggregator_keeps_inclusion_at_reduced_capacity(self):
        # Full fleet: 2,000 a block. Without the largest (half the machines): 1,000 a block.
        shares = (0.5, 0.3, 0.2)
        r = run(reveals_per_block=1_500, machines=40, blocks=60, aggregator_shares=shares, disappear=(600.0, 0))
        before = tp.included_rate(r, 150, 600) * 30
        after = tp.included_rate(r, 900, 1800) * 30
        self.assertAlmostEqual(before, 1_500, delta=300)
        self.assertGreater(after, 0.7 * 1_000)
        self.assertLess(after, 1.1 * 1_000)
        self.assertLess(after, 1_500)
        # Every five minutes after failover still include private reveals.
        for start in (700, 1000, 1300, 1600):
            self.assertGreater(tp.included_rate(r, start, start + 300), 0)
        # The largest aggregator includes nothing after it disappears.
        calm = run(reveals_per_block=1_500, machines=40, blocks=60, aggregator_shares=shares)
        self.assertLess(r["per_aggregator"][0], calm["per_aggregator"][0])


class Fleet(unittest.TestCase):
    def test_fleet_search(self):
        fleet = tp.fleet_needed(BASE, steps=(0.5, 1.5, 3.0))
        self.assertEqual(fleet["work_bound"], 10)
        self.assertEqual([m for m, _ in fleet["tried"]][:2], [5, 15])
        self.assertFalse(tp.keeps_up(fleet["tried"][0][1]))
        self.assertEqual(fleet["throughput"], 15)
        self.assertEqual(fleet["delay"], 15)
        # A ceiling below the critical path is held by no fleet.
        none = tp.fleet_needed(BASE, steps=(1.5, 3.0), delay_ceiling_seconds=2.0)
        self.assertIsNone(none["delay"])
        self.assertEqual(len(none["tried"]), 2)

    def test_delay_floor_and_cost(self):
        inputs = tp.resolved(BASE)
        # The largest aggregator holds 40 percent: 200 reveals, 8 levels.
        self.assertAlmostEqual(tp.delay_floor_seconds(inputs), 0.3 + 8 * 0.3)
        self.assertAlmostEqual(tp.machine_seconds_per_reveal(inputs), 0.6)
        self.assertAlmostEqual(tp.break_even_price(inputs), 0.001 * 3600 / 0.6)
        r = run(machines=40)
        self.assertAlmostEqual(r["cost_per_reveal"], 2.0 * 40 * r["elapsed_seconds"] / 3600 / r["included"])
        self.assertGreater(run(machines=80)["cost_per_reveal"], r["cost_per_reveal"])


class Determinism(unittest.TestCase):
    def test_the_same_seed_gives_the_same_result(self):
        a, b = run(machines=20, seed=7), run(machines=20, seed=7)
        self.assertEqual(a["included_by_block"], b["included_by_block"])
        self.assertEqual((a["p50_delay"], a["p99_delay"]), (b["p50_delay"], b["p99_delay"]))
        c = run(machines=20, seed=8)
        self.assertNotEqual(a["included_by_block"], c["included_by_block"])


class Inputs(unittest.TestCase):
    def test_costs_come_from_the_records_when_present(self):
        costs = tp.layer_costs()
        self.assertIn("modeled", costs["merge"]["label"])
        self.assertAlmostEqual(costs["merge"]["seconds"], 462.040838 / 32, places=6)
        self.assertAlmostEqual(costs["conversion"]["seconds"], 231.020419 / 32, places=6)

    def test_without_records_the_input_is_illustrative(self):
        with tempfile.TemporaryDirectory() as d:
            costs = tp.layer_costs(Path(d) / "missing.jsonl")
        for layer in ("conversion", "merge"):
            self.assertEqual(costs[layer]["seconds"], 0.3)
            self.assertIn("illustrative", costs[layer]["label"])
            self.assertIn("not yet established", costs[layer]["label"])

    def test_the_target_is_the_default(self):
        self.assertEqual(tp.INPUTS["reveals_per_block"], 3_500)
        self.assertEqual(tp.INPUTS["public_per_block"], 3_500)
        self.assertEqual(tp.INPUTS["delay_ceiling_seconds"], 300)

    def test_public_capacity_follows_the_encoding(self):
        raw = run(machines=40, public_per_block=3_500, blocks=10)
        proof = run(machines=40, public_per_block=3_500, blocks=10, public_encoding="proof")
        self.assertEqual(raw["public_capacity"], 1_429)
        self.assertLess(raw["public_sustained_per_block"], 3_500)
        self.assertGreater(raw["public_backlog_at_window_end"], 3_500)
        self.assertGreater(proof["public_sustained_per_block"], raw["public_sustained_per_block"])


class Document(unittest.TestCase):
    def test_document(self):
        text = DOC.read_text(encoding="utf-8")
        for heading in ("## Model", "## Results at 500 and 3,500 per block", "## Bursts and failures",
                        "## Adversarial traffic", "## Fleet size and cost"):
            self.assertIn(heading, text)
        self.assertIn("python3 benchmarks/scale/throughput.py", text)
        self.assertEqual(labels.check_text(text), [])

    def test_document_quotes_the_analytic_figures(self):
        # The simulated tables take about a minute to print; these figures need no run.
        text = DOC.read_text(encoding="utf-8")
        inputs = tp.resolved()
        for per_block, floor, delay in ((500, "361", "122.7"), (3_500, "2,527", "166.0")):
            sized = dict(inputs, reveals_per_block=per_block)
            self.assertEqual(f"{tp.work_bound_machines(sized):,}", floor)
            self.assertEqual(f"{tp.delay_floor_seconds(sized):,.1f}", delay)
            self.assertIn(f"- work bound: {floor} machines (modeled)", text)
            self.assertIn(f"before the waits for blocks: {delay} s (modeled", text)
        self.assertEqual(f"{tp.machine_seconds_per_reveal(inputs):.4f}", "21.6585")
        self.assertEqual(f"{tp.break_even_price(inputs):.4f}", "0.1662")
        self.assertEqual(f"{inputs['conversion_seconds']:.4f}", "7.2194")
        self.assertEqual(f"{inputs['merge_seconds']:.4f}", "14.4388")
        for figure in ("21.6585", "0.1662", "7.2194 s", "14.4388 s", "0.000288 s"):
            self.assertIn(figure, text)


if __name__ == "__main__":
    unittest.main()
