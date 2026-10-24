"""Tests for benchmarks/scale/security_budget.py: the bundle's error terms."""

import contextlib
import io
import math
import runpy
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scale"))

import security_budget as sb  # noqa: E402


class Combine(unittest.TestCase):
    def test_two_equal_terms_lose_one_bit(self):
        self.assertEqual(sb.combine([130, 130]), 129)

    def test_four_equal_terms_lose_two_bits(self):
        self.assertEqual(sb.combine([100, 100, 100, 100]), 98)

    def test_one_term_is_itself(self):
        self.assertEqual(sb.combine([80]), 80)

    def test_the_weakest_term_dominates(self):
        self.assertAlmostEqual(sb.combine([128, 150]), 128 - math.log2(1 + 2.0 ** -22), places=12)
        self.assertLess(sb.combine([128, 150]), 128)
        self.assertGreater(sb.combine([128, 150]), 127.999)

    def test_infinite_and_empty(self):
        self.assertEqual(sb.combine([math.inf, 90]), 90)
        self.assertEqual(sb.combine([]), math.inf)

    def test_large_exponents_do_not_underflow(self):
        self.assertEqual(sb.combine([2000, 2000]), 1999)


class Grinding(unittest.TestCase):
    def test_sixteen_bits_count_as_eight(self):
        self.assertEqual(sb.grinding_at_half(16), 8)
        self.assertEqual(sb.classical_bits(120, 16), 128)

    def test_quantum_counts_grinding_at_half_too(self):
        self.assertEqual(sb.quantum_bits(114, 16), 65)
        self.assertEqual(sb.quantum_bits(128), 64)


class Conversion(unittest.TestCase):
    def test_decision_0003_proven_figures(self):
        self.assertEqual(sb.SHIPPED_CONFIGURATION, "keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk")
        self.assertEqual(sb.DECISION_0003["proven_classical_bits"], 80)
        self.assertEqual(sb.DECISION_0003["proven_quantum_bits"], 40)
        self.assertEqual(sb.DECISION_0003["earlier_proven_classical_bits"], 72)
        self.assertEqual(sb.quantum_bits(sb.DECISION_0003["proven_classical_bits"]), 40)

    def test_todays_proven_figures_miss_the_requirement(self):
        short = sb.shortfall(sb.DECISION_0003["proven_classical_bits"], sb.DECISION_0003["proven_quantum_bits"])
        self.assertEqual(short, {"classical": 48, "quantum": 24, "meets": False})

    def test_conjectured_figures_are_not_proven_figures(self):
        self.assertEqual(sb.conjectured_query_bits(3, 43), sb.DECISION_0003["queries_alone_conjectured_bits"])
        self.assertEqual(sb.johnson_query_bits(3, 43), 64.5)
        # The estimator's 80 matches the Johnson query term with the 16
        # grinding bits in full; at half it is 72.5.
        self.assertEqual(sb.johnson_query_bits(3, 43) + 16, 80.5)
        self.assertEqual(sb.classical_bits(sb.johnson_query_bits(3, 43), 16), 72.5)
        self.assertEqual(sb.quantum_bits(sb.johnson_query_bits(3, 43), 16), 40.25)

    def test_hash_terms(self):
        self.assertEqual(sb.collision_bits(256), 128)
        self.assertAlmostEqual(sb.quantum_hash_bits(256), 85.333, places=3)
        self.assertEqual(sb.collision_bits(279), 139.5)
        self.assertEqual(sb.quantum_hash_bits(279), 93)

    def test_shortfall_is_zero_when_met(self):
        self.assertEqual(sb.shortfall(130, 70), {"classical": 0.0, "quantum": 0.0, "meets": True})
        self.assertFalse(sb.shortfall(130, 63.9)["meets"])


class Bundle(unittest.TestCase):
    def test_adding_layers_lowers_the_total(self):
        one = sb.whole_bundle_bits([130], 1)
        two = sb.whole_bundle_bits([130], 2)
        twelve = sb.whole_bundle_bits([130], 12)
        self.assertEqual(one, 130)
        self.assertEqual(two, 129)
        self.assertLess(twelve, two)
        self.assertAlmostEqual(twelve, 130 - math.log2(12), places=12)

    def test_once_terms_are_not_repeated(self):
        self.assertAlmostEqual(sb.whole_bundle_bits([200], 4, [100]), 100, places=9)
        self.assertEqual(sb.whole_bundle_bits([math.inf], 4, [100, 100]), 99)
        self.assertAlmostEqual(sb.whole_bundle_bits([100], 3, [100]), 98, places=12)

    def test_tree_of_the_target_bundle(self):
        layers = sb.tree_layers(3_500)
        self.assertEqual(len(layers), 12)
        self.assertEqual(layers[0], 1_750)
        self.assertEqual(sum(layers), 3_499)
        self.assertEqual(sb.total_proofs(3_500), 6_999)
        self.assertEqual(sb.tree_layers(1), [])
        self.assertEqual(sb.tree_layers(5), [2, 1, 1])

    def test_tree_bound_is_the_sum_over_every_proof(self):
        self.assertAlmostEqual(sb.tree_bundle_bits(140, 140, 3_500), 140 - math.log2(6_999), places=9)
        self.assertAlmostEqual(sb.tree_bundle_bits(100, 100, 2), 100 - math.log2(3), places=12)
        self.assertEqual(sb.tree_bundle_bits(100, 100, 1), 100)
        self.assertLess(sb.tree_bundle_bits(140, 140, 3_500), sb.tree_bundle_bits(140, 140, 1_000))
        with self.assertRaises(ValueError):
            sb.tree_bundle_bits(140, [140, 140], 3_500)

    def test_a_weak_conversion_layer_binds(self):
        layers = [100] + [200] * 11
        self.assertAlmostEqual(sb.tree_bundle_bits(200, layers, 3_500), 100 - math.log2(1_750), places=6)


class Parameters(unittest.TestCase):
    def test_bits_each_proof_needs(self):
        self.assertAlmostEqual(sb.per_proof_bits_needed(128, 6_999), 140.7729, places=4)
        self.assertAlmostEqual(sb.per_proof_bits_needed(64, 6_999), 76.7729, places=4)

    def test_queries_needed(self):
        self.assertEqual(sb.johnson_queries_needed(3, 6_999, 16), 92)
        self.assertEqual(sb.johnson_queries_needed(3, 1, 16), 80)
        self.assertEqual(sb.query_phase_bits(sb.CANDIDATE_LAYER), (146, 77))

    def test_architectures(self):
        kk = sb.architecture_bounds("keccak-keccak")
        kp = sb.architecture_bounds("keccak-poseidon2")
        pp = sb.architecture_bounds("poseidon2-poseidon2")
        self.assertAlmostEqual(kk["classical"], 127.96, places=2)
        self.assertAlmostEqual(kk["quantum"], 64.23, places=2)
        self.assertAlmostEqual(kp["classical"], 127.96, places=2)
        self.assertAlmostEqual(kp["quantum"], 64.23, places=2)
        self.assertAlmostEqual(pp["classical"], 133.21, places=2)
        self.assertAlmostEqual(pp["quantum"], 64.23, places=2)
        self.assertFalse(kk["shortfall"]["meets"])
        self.assertAlmostEqual(kk["shortfall"]["classical"], 0.04, places=2)
        self.assertEqual(kk["shortfall"]["quantum"], 0)
        self.assertFalse(kp["shortfall"]["meets"])
        self.assertTrue(pp["shortfall"]["meets"])

    def test_todays_leaf_in_a_bundle_falls_further_short(self):
        today = {"log_blowup": 3, "queries": 43, "grinding_bits": 16}
        bounds = sb.architecture_bounds("keccak-keccak", leaf=today, layer=today)
        self.assertAlmostEqual(bounds["classical"], 72.5 - math.log2(6_999), places=6)
        self.assertGreater(bounds["shortfall"]["classical"], 48)


class Command(unittest.TestCase):
    def test_report_says_modeled(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            runpy.run_path(str(HERE.parent / "scale" / "security_budget.py"), run_name="__main__")
        text = out.getvalue()
        self.assertIn("Modeled", text)
        self.assertIn("6,999", text)
        self.assertIn("keccak-keccak: whole bundle, classical", text)


if __name__ == "__main__":
    unittest.main()
