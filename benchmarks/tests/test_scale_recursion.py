"""Tests for benchmarks/scale/recursion_costs.py: the recursion proxy records and their fleet cost.

The committed records are read and checked, never written. Every other record here is a
synthetic sample written in the test; none is a measurement.
"""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import budget  # noqa: E402
import recursion_costs as rc  # noqa: E402

A = "keccak-leaves-keccak-aggregation"
B = "keccak-leaves-poseidon2-aggregation"
C = "poseidon2-leaves-poseidon2-aggregation"
PARAMETERS = ("keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk; "
              "p3-keccak-air (2633 columns, 24 rows a permutation) over BabyBear (synthetic test record)")


def sample(**changes):
    record = {
        "architecture": A,
        "layer": "merge",
        "permutation_count": 170,
        "trace_rows": 4096,
        "trace_width": 2633,
        "label": "measured (proxy)",
        "quick": False,
        "cpu_model": "Sample CPU 9 (synthetic test record)",
        "threads": 16,
        "prover_threads": 1,
        "parameters": PARAMETERS,
        "proof_bytes": 729_881,
        "median_seconds": 1.75,
        "slowest_seconds": 1.8,
        "repeats": 5,
    }
    record.update(changes)
    return record


def modeled(**changes):
    base = dict(label="modeled", proof_bytes=None, repeats=0, model="synthetic per-row model")
    base.update(changes)
    return sample(**base)


class Arithmetic(unittest.TestCase):
    def test_merge_budget_at_the_ceiling(self):
        self.assertEqual(budget.machine_seconds(3_499, "0.3"), 1049.7)
        self.assertEqual(budget.min_wall_seconds(3_499, "0.3", 40), 26.2425)
        self.assertEqual(budget.merges_per_block({"private_per_block": rc.INPUTS["reveals_per_block"]}), 3_499)

    def test_a_merge_at_the_ceiling_on_the_fleet(self):
        # 9.6 s on one thread of a 32-core machine is 0.3 s on the machine, at best.
        record = sample(median_seconds=9.6, slowest_seconds=9.6)
        self.assertEqual(rc.per_machine_seconds(record), 0.3)
        figures = rc.layer_figures(record, 3_499)
        self.assertEqual(figures["machine_seconds"], 1049.7)
        self.assertEqual(figures["min_wall_seconds"], 26.2425)
        self.assertEqual(rc.per_machine_seconds(sample(prover_threads=32, median_seconds=0.3, slowest_seconds=0.3)), 0.3)

    def test_trace_memory(self):
        # 2^20 rows doubled, blown up 8 times, 2,638 columns of 4 bytes.
        self.assertEqual(rc.lde_bytes(2 ** 20, 2633), 2 ** 24 * 2638 * 4)
        self.assertEqual(rc.gib(rc.lde_bytes(2 ** 20, 2633)), 164.875)
        self.assertEqual(rc.gib(rc.lde_bytes(2 ** 19, 2633)), 82.4375)

    def test_inputs_match_workload(self):
        text = (REPO / "docs" / "scale" / "workload.md").read_text(encoding="utf-8")
        self.assertIn("| Machines | 40 proving machines |", text)
        self.assertIn("| CPU per machine | 32 cores |", text)
        self.assertIn("| Memory per machine | 128 GiB |", text)
        self.assertIn("| Time for one merge | 0.3 s |", text)
        self.assertEqual((rc.INPUTS["machines"], rc.INPUTS["cores_per_machine"]), (40, 32))
        self.assertEqual((rc.INPUTS["memory_per_machine_gib"], rc.INPUTS["merge_seconds_ceiling"]), (128, "0.3"))
        self.assertEqual(rc.INPUTS["reveals_per_block"], 3_500)


class Validate(unittest.TestCase):
    def test_samples_are_valid(self):
        self.assertEqual(rc.problems(sample()), [])
        self.assertEqual(rc.problems(modeled(trace_rows=2 ** 20, permutation_count=26_140)), [])

    def test_every_required_field(self):
        for name in rc.REQUIRED:
            with self.subTest(field=name):
                record = sample()
                del record[name]
                self.assertIn(f"missing field {name}", rc.problems(record))

    def test_measured_without_a_cpu_model_is_rejected(self):
        for label in rc.MEASURED_LABELS:
            for cpu in ("", "   ", None, 7):
                with self.subTest(label=label, cpu=cpu):
                    self.assertIn("a measured record must name the CPU model", rc.problems(sample(label=label, cpu_model=cpu)))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "records.jsonl"
            path.write_text(json.dumps(sample(cpu_model="")) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                rc.load(path)

    def test_labels_and_kinds(self):
        self.assertTrue(rc.problems(sample(label="estimated")))
        self.assertTrue(rc.problems(sample(label="measured proxy")))
        self.assertTrue(rc.problems(sample(layer="wrap")))
        self.assertTrue(rc.problems(sample(architecture="keccak-to-sha3")))
        self.assertTrue(rc.problems(sample(repeats=2)))
        self.assertTrue(rc.problems(sample(proof_bytes=None)))
        self.assertTrue(rc.problems(modeled(repeats=3)))
        self.assertTrue(rc.problems(modeled(model="")))
        self.assertTrue(rc.problems(sample(quick="no")))

    def test_numbers(self):
        for bad in ("1.75", None, True, float("nan"), float("inf"), 0, -1.0):
            with self.subTest(value=bad):
                self.assertTrue(rc.problems(sample(median_seconds=bad)))
        self.assertIn("median_seconds is above slowest_seconds", rc.problems(sample(median_seconds=2.0)))
        self.assertTrue(rc.problems(sample(permutation_count=170.0)))
        self.assertTrue(rc.problems(sample(trace_rows=4000)))
        # 171 permutations of 24 rows need 8,192 rows, not 4,096.
        self.assertTrue(rc.problems(sample(permutation_count=171)))

    def test_exact_primitive(self):
        self.assertTrue(rc.problems(sample(parameters=PARAMETERS.replace("keccak-256", "sha3-256"))))
        self.assertTrue(rc.problems(sample(parameters=PARAMETERS + "; Poseidon1 KoalaBear t=16")))
        self.assertTrue(rc.problems(sample(architecture=C)))
        self.assertTrue(rc.problems(sample(architecture=B)))
        self.assertEqual(rc.problems(sample(architecture=B, parameters=PARAMETERS + "; poseidon2-babybear-w24")), [])


class Verdict(unittest.TestCase):
    def test_a_proxy_over_the_ceiling_is_missed(self):
        result = rc.fleet([sample(median_seconds=10.0, slowest_seconds=10.0)])
        self.assertEqual(result[A]["verdict"], rc.MISSED)

    def test_a_proxy_under_every_ceiling_establishes_nothing(self):
        result = rc.fleet([sample(median_seconds=1.0, slowest_seconds=1.0)])
        self.assertEqual(result[A]["merge"]["single_proof_seconds"], 0.03125)
        self.assertEqual(result[A]["verdict"], rc.NOT_ESTABLISHED)

    def test_memory_over_the_ceiling_is_missed(self):
        big = modeled(permutation_count=26_140, trace_rows=2 ** 20, median_seconds=1.0, slowest_seconds=1.0)
        self.assertEqual(rc.fleet([big])[A]["verdict"], rc.MISSED)

    def test_only_a_real_measurement_can_meet(self):
        real = sample(label="measured", parameters="keccak-256 recursive verifier (synthetic test record)",
                      prover_threads=32, median_seconds=0.25, slowest_seconds=0.28)
        self.assertEqual(rc.fleet([real])[A]["verdict"], rc.MET)
        slow = dict(real, median_seconds=0.35, slowest_seconds=0.4)
        self.assertEqual(rc.fleet([slow])[A]["verdict"], rc.MISSED)

    def test_quick_records_do_not_stand_for_a_layer(self):
        result = rc.fleet([sample(quick=True, median_seconds=10.0, slowest_seconds=10.0)])
        self.assertIsNone(result[A]["merge"])
        self.assertEqual(result[A]["verdict"], rc.NOT_ESTABLISHED)

    def test_a_full_proxy_is_preferred_to_a_model(self):
        proxy = sample(median_seconds=5.0, slowest_seconds=5.5)
        model = modeled(median_seconds=50.0, slowest_seconds=50.0)
        self.assertEqual(rc.fleet([model, proxy])[A]["merge"]["label"], "measured (proxy)")

    def test_no_records_is_not_established(self):
        result = rc.fleet([])
        for arch in (A, B, C):
            self.assertEqual(result[arch]["verdict"], rc.NOT_ESTABLISHED)
            self.assertIsNone(result[arch]["merge"])


class CommittedRecords(unittest.TestCase):
    def test_records_are_valid_and_unchanged(self):
        before = rc.RECORDS.read_bytes()
        records = rc.load(rc.RECORDS)
        snapshot = copy.deepcopy(records)
        result = rc.fleet(records)
        self.assertEqual(records, snapshot)
        self.assertEqual(rc.RECORDS.read_bytes(), before)
        self.assertTrue(records)
        for record in records:
            self.assertIn(record["label"], rc.LABELS)
        # The conversion and merge layers of (a) both stand for the counted size.
        self.assertIsNotNone(result[A]["conversion"])
        self.assertIsNotNone(result[A]["merge"])
        self.assertIsNone(result[B]["merge"])
        self.assertIsNone(result[C]["merge"])

    def test_document_quotes_the_computed_fleet(self):
        text = (REPO / "docs" / "scale" / "recursion.md").read_text(encoding="utf-8")
        for line in rc.render(rc.fleet(rc.load(rc.RECORDS))).splitlines():
            if line.startswith("| (") or line.startswith("("):
                with self.subTest(line=line):
                    self.assertIn(line, text)

    def test_command_line(self):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rc.main([str(rc.RECORDS)]), 0)
        self.assertIn("(a) Keccak leaves, Keccak aggregation", out.getvalue())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.jsonl"
            path.write_text("{not json\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(rc.main([str(path)]), 1)


if __name__ == "__main__":
    unittest.main()
