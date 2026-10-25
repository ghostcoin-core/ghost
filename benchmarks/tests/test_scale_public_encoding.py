"""Tests for benchmarks/scale/public_encoding.py: public transaction bytes against the message cap."""

import contextlib
import io
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import labels  # noqa: E402
import public_encoding as pe  # noqa: E402

CAP = 10_485_760
DOC = REPO / "docs" / "scale" / "public-encoding.md"


def changed(**changes):
    inputs = dict(pe.INPUTS)
    inputs.update(changes)
    return inputs


class Raw(unittest.TestCase):
    def test_raw_bytes_at_the_target(self):
        r = pe.raw()
        self.assertEqual(r["public_bytes"], 13_069_000)
        self.assertEqual(r["with_private_non_proof"], 14_283_500)
        self.assertGreater(r["with_private_non_proof"], CAP)
        self.assertEqual(r["message_cap_bytes"], CAP)
        self.assertFalse(r["fits"])
        self.assertEqual(r["with_aggregate_proofs"], 14_283_500 + 3 * 1_310_720)
        self.assertEqual(r["headroom_bytes"], CAP - r["with_aggregate_proofs"])
        self.assertEqual(r["body_bytes_per_transaction"], 0.0)

    def test_raw_does_not_fit_even_without_aggregate_proofs(self):
        r = pe.raw(changed(private_bundles_per_block=0))
        self.assertEqual(r["with_aggregate_proofs"], 14_283_500)
        self.assertFalse(r["fits"])
        self.assertEqual(r["headroom_bytes"], -3_797_740)

    def test_raw_capacity(self):
        room = CAP - 3_500 * 347 - 3 * 1_310_720
        self.assertEqual(pe.public_capacity("raw"), room // 3_734)
        self.assertEqual(pe.public_capacity("raw"), 1_429)
        self.assertLess(pe.public_capacity("raw"), 3_500)


class Proof(unittest.TestCase):
    def test_proof_variant_at_the_target(self):
        p = pe.proof()
        self.assertEqual(p["binding_bytes"], 20 + 32 + 32)
        self.assertEqual(p["public_bytes"], 3_500 * 84 + 1_310_720)
        self.assertEqual(p["with_aggregate_proofs"], 3_500 * 84 + 1_310_720 + 3_500 * 347 + 3 * 1_310_720)
        self.assertEqual(p["with_aggregate_proofs"], 6_751_380)
        self.assertTrue(p["fits"])
        self.assertEqual(p["headroom_bytes"], 3_734_380)
        self.assertAlmostEqual(p["body_bytes_per_transaction"], 3_734_380 / 3_500)
        self.assertEqual(p["verifications_per_block"], 3_500)
        self.assertEqual(p["proofs_per_block"], 1)
        self.assertIsNone(p["proving_seconds"])

    def test_more_proofs_cost_bytes(self):
        one = pe.proof()
        seven = pe.proof(changed(verifications_per_proof=500))
        self.assertEqual(seven["proofs_per_block"], 7)
        self.assertEqual(seven["verifications_per_block"], 3_500)
        self.assertEqual(seven["public_bytes"] - one["public_bytes"], 6 * 1_310_720)
        self.assertFalse(seven["fits"])

    def test_binding_bytes_are_inputs(self):
        wide = pe.proof(changed(account_bytes=32, key_identity_bytes=64, transaction_hash_bytes=64))
        self.assertEqual(wide["binding_bytes"], 160)
        self.assertEqual(wide["public_bytes"], 3_500 * 160 + 1_310_720)

    def test_a_large_proof_can_break_the_fit(self):
        # The largest proof that fits is the headroom plus the stated proof size.
        self.assertTrue(pe.proof(changed(verification_proof_bytes=5_045_100))["fits"])
        self.assertEqual(pe.proof(changed(verification_proof_bytes=5_045_100))["headroom_bytes"], 0)
        self.assertFalse(pe.proof(changed(verification_proof_bytes=5_045_101))["fits"])

    def test_proof_capacity(self):
        self.assertEqual(pe.public_capacity("proof"), 10_500)
        self.assertGreaterEqual(pe.public_capacity("proof"), 3_500)
        # A capacity is never more than fits: one more transaction overflows.
        n = pe.public_capacity("proof", changed(verifications_per_proof=100))
        self.assertTrue(pe.proof(changed(verifications_per_proof=100, public_per_block=n))["fits"])
        self.assertFalse(pe.proof(changed(verifications_per_proof=100, public_per_block=n + 1))["fits"])


class Document(unittest.TestCase):
    def test_command_line_prints_the_table(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(pe.main([]), 0)
        self.assertIn("13,069,000 (modeled)", out.getvalue())
        self.assertIn("not yet established", out.getvalue())

    def test_document_quotes_the_computed_table(self):
        text = DOC.read_text(encoding="utf-8")
        for line in pe.report().splitlines():
            if line.startswith("| raw") or line.startswith("| signature"):
                with self.subTest(line=line):
                    self.assertIn(line, text)
        for heading in ("## Raw encoding", "## Signature replaced by a proof", "## What is not yet established"):
            self.assertIn(heading, text)
        self.assertIn("python3 benchmarks/scale/public_encoding.py", text)
        self.assertEqual(labels.check_text(text), [])


if __name__ == "__main__":
    unittest.main()
