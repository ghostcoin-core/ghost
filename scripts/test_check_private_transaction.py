"""Tests for check_private_transaction.py: it passes on the specification and
fails when a section, the parameters, the payload, the binding, a worked
example, a property or the conflicts are damaged."""

import importlib.util
import random
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = HERE.parent / "docs" / "spec" / "07-private-transaction.md"

_spec = importlib.util.spec_from_file_location("check_private_transaction",
                                               HERE / "check_private_transaction.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


class CheckerTest(unittest.TestCase):
    def setUp(self):
        self.text = SPEC.read_text(encoding="utf-8")

    def damaged(self, old, new, count=1):
        self.assertIn(old, self.text)
        return self.text.replace(old, new, count)

    def damaged_after(self, anchor, old, new):
        """Replace the first `old` after `anchor`."""
        start = self.text.index(anchor)
        at = self.text.index(old, start)
        return self.text[:at] + new + self.text[at + len(old):]

    def assert_gap(self, text, fragment):
        errors = checker.check_text(text)
        self.assertTrue(any(fragment in e for e in errors), f"no '{fragment}' in {errors}")

    def test_specification_passes(self):
        self.assertEqual(checker.check_text(self.text), [])
        self.assertEqual(checker.main(["x", str(SPEC)]), 0)

    def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertNotEqual(checker.main(["x", str(Path(tmp) / "absent.md")]), 0)

    def test_damaged_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "07.md"
            path.write_text(self.damaged("## 6. Transaction pool", "## 6. Pool"), encoding="utf-8")
            self.assertNotEqual(checker.main(["x", str(path)]), 0)

    # Sections

    def test_each_required_section_is_required(self):
        for heading, word in (("## 3. Encoding and hashing", "Encoding and hashing"),
                              ("## 4. Fee formula", "Fee formula"),
                              ("## 5. Fee is current", "Fee is current"),
                              ("## 6. Transaction pool", "Transaction pool"),
                              ("## 7. Boundary cases", "Boundary cases"),
                              ("## 8. Properties", "Properties"),
                              ("## 10. Conflicts with other chapters", "Conflicts")):
            with self.subTest(word=word):
                number = heading.split(".")[0]
                self.assert_gap(self.damaged(heading, f"{number}. Elsewhere"), f"contains '{word}'")

    def test_unnumbered_heading(self):
        self.assert_gap(self.damaged("## 7. Boundary cases", "## Boundary cases"),
                        "is not numbered")

    def test_section_numbering_gap(self):
        self.assert_gap(self.damaged("## 8. Properties", "## 9. Properties"),
                        "sections are numbered")

    # Parameters

    def test_parameter_missing(self):
        text = self.damaged("| `FEE_WINDOW` | 4 |", "| `WINDOW` | 4 |")
        self.assert_gap(text, "parameter table lacks ['FEE_WINDOW']")

    def test_parameter_not_integer(self):
        self.assert_gap(self.damaged("| `TIP_DIVISOR` | 10 |", "| `TIP_DIVISOR` | ten |"),
                        "parameter TIP_DIVISOR: value")

    def test_taken_type_byte(self):
        for value in ("`0x02`", "`0x7e`", "`0x04`"):
            with self.subTest(value=value):
                self.assert_gap(self.damaged("| `TYPE_BYTE` | `0x50` |", f"| `TYPE_BYTE` | {value} |"),
                                "is taken or outside")

    def test_wrong_g_priv(self):
        text = self.damaged("| `G_PRIV` | 21,090,372 |", "| `G_PRIV` | 21,090,373 |")
        self.assert_gap(text, "parameter G_PRIV is 21090373, recomputed 21090372")

    def test_wrong_verify_gas_moves_g_priv(self):
        text = self.damaged("| `VERIFY_GAS` | 92,300 |", "| `VERIFY_GAS` | 92,000 |")
        self.assert_gap(text, "parameter G_PRIV is 21090372, recomputed 21090072")

    def test_wrong_envelope_and_pool_bytes(self):
        text = self.damaged("| `ENVELOPE_BYTES` | 1,311,067 |", "| `ENVELOPE_BYTES` | 1,311,066 |")
        self.assert_gap(text, "parameter ENVELOPE_BYTES is 1311066, recomputed 1311067")
        text = self.damaged("| `POOL_MAX_BYTES` | 20,977,072 |", "| `POOL_MAX_BYTES` | 16,000,000 |")
        self.assert_gap(text, "parameter POOL_MAX_BYTES is 16000000")

    def test_proof_width_is_version_1(self):
        # Any other width is refused, the old one included: a change of width
        # is a new version.
        text = self.damaged("| `PROOF_BYTES` | 1,310,720 |", "| `PROOF_BYTES` | 1,310,721 |")
        self.assert_gap(text, "PROOF_BYTES is 1310721, version 1 fixes 1310720")
        old = "| `PROOF_BYTES` | 1,028,144 |"
        text = self.damaged("| `PROOF_BYTES` | 1,310,720 |", old)
        self.assert_gap(text, "PROOF_BYTES is 1028144, version 1 fixes 1310720")

    def test_wrong_note_size(self):
        self.assert_gap(self.damaged("| `NOTE_BYTES` | 156 |", "| `NOTE_BYTES` | 128 |"),
                        "NOTE_BYTES is 128")

    # Payload

    def test_payload_widths_must_add_up(self):
        text = self.damaged("Total: 1,311,066 bytes of payload; 1,311,067 bytes",
                            "Total: 1,311,065 bytes of payload; 1,311,066 bytes")
        errors = checker.check_text(text)
        self.assertTrue(any("total says 1311065 bytes of payload, fields sum to 1311066" in e
                            for e in errors), errors)
        self.assertTrue(any("total says 1311066 bytes with the type byte" in e for e in errors), errors)

    def test_payload_field_width_changed(self):
        text = self.damaged("| 106 | 20 | `recipient` |", "| 106 | 32 | `recipient` |")
        errors = checker.check_text(text)
        self.assertTrue(any("'recipient' is 32 bytes, expected 20" in e for e in errors), errors)
        self.assertTrue(any("'out' at offset 126, expected 138" in e for e in errors), errors)

    def test_payload_proof_width_changed(self):
        text = self.damaged("| 190 | 1310720 | `proof` |", "| 190 | 1310000 | `proof` |")
        self.assert_gap(text, "'proof' is 1310000 bytes, expected 1310720")

    def test_payload_field_missing(self):
        text = self.damaged("| 0 | 2 | `version` | `TX_VERSION`, `0x0001` |\n", "")
        self.assert_gap(text, "payload fields are")

    def test_sender_field_rejected(self):
        for name in ("signature", "nonce", "gas_limit", "sender", "rule"):
            with self.subTest(name=name):
                text = self.damaged("| 1310910 | 156 | `note` |",
                                    f"| 1310910 | 156 | `{name}` |")
                self.assert_gap(text, f"payload field '{name}' is not allowed")

    def test_no_payload_table(self):
        self.assert_gap(self.damaged("**Payload.**", "**Layout.**"), "no Offset/Width/Field payload table")

    # Binding

    def test_binding_field_unmapped(self):
        self.assert_gap(self.damaged("| `domain` | Node: the genesis block hash |\n", ""),
                        "binding table does not map ['domain']")

    def test_payload_field_unbound(self):
        self.assert_gap(self.damaged("| `remainder_note` | `note` |", "| `remainder_note` | Node |"),
                        "payload fields not bound by the proof: ['note']")

    def test_binding_from_wrong_field(self):
        self.assert_gap(self.damaged("| `out` | `out` |", "| `out` | `fee` |"),
                        "binding field 'out' comes from payload field 'fee'")

    # Worked examples

    def test_window_fee_wrong(self):
        text = self.damaged_after("[window-genesis]", "tip = 3003306891179819", "tip = 3003306891179818")
        self.assert_gap(text, "example window-genesis: tip is 3003306891179818")
        text = self.damaged_after("[window-genesis]", "price = 1424017979", "price = 1424017978")
        self.assert_gap(text, "example window-genesis: price is 1424017978")

    def test_window_fee_tracks_parameters(self):
        text = self.damaged("| `FEE_WINDOW` | 4 |", "| `FEE_WINDOW` | 5 |")
        self.assert_gap(text, "example window-genesis: price is 1424017979")
        text = self.damaged("| `TIP_DIVISOR` | 10 |", "| `TIP_DIVISOR` | 20 |")
        self.assert_gap(text, "example window-genesis: tip is")

    def test_window_length_table(self):
        text = self.damaged("| 4 | 1.424 |", "| 4 | 1.425 |")
        self.assert_gap(text, "window length 4: ceiling is 1.425")
        text = self.damaged("| 4 | 1.424 |", "| 3 | 1.266 |")
        self.assert_gap(text, "no row for FEE_WINDOW")

    def test_growth_wrong(self):
        start = self.text.index("[growth-genesis-full-blocks]")
        line_start = self.text.index("base_fees = ", start)
        line_end = self.text.index("\n", line_start)
        fees = self.text[line_start:line_end].split(" = ")[1].split()
        fees[2] = str(int(fees[2]) + 1)
        text = self.text[:line_start] + "base_fees = " + " ".join(fees) + self.text[line_end:]
        self.assert_gap(text, "example growth-genesis-full-blocks: base fee 2 is")

    def test_growth_above_ceiling_fails(self):
        # A ceiling with only Ethereum's 1/8 step is below an odd gas limit's growth.
        original = checker.ceiling_step
        checker.ceiling_step = lambda u: u + u // 8
        try:
            errors = checker.check_text(self.text)
        finally:
            checker.ceiling_step = original
        self.assertTrue(any("charges more than the window's base part" in e for e in errors), errors)

    def test_lapse_wrong(self):
        text = self.damaged_after("[lapse-window-change]", "valid = no", "valid = yes")
        self.assert_gap(text, "example lapse-window-change: valid = yes")
        text = self.damaged_after("[lapse-fee-unchanged]", "valid = yes", "valid = no")
        self.assert_gap(text, "example lapse-fee-unchanged: valid = no")

    def test_each_boundary_case_is_required(self):
        for name in checker.REQUIRED_EXAMPLES:
            with self.subTest(name=name):
                text = self.damaged(f"[{name}]", "[renamed]")
                self.assert_gap(text, f"boundary case example {name}")

    def test_full_reveal_wrong(self):
        text = self.damaged_after("[full-reveal]", "out = 966963624197021993", "out = 966963624197021994")
        errors = checker.check_text(text)
        self.assertTrue(any("example full-reveal: valid = yes, recomputed no" in e for e in errors), errors)

    def test_full_reveal_minted_wrong(self):
        text = self.damaged_after("[full-reveal]", "minted = 966963624197021993", "minted = 1")
        self.assert_gap(text, "example full-reveal: minted is 1")

    def test_zero_amount_claim_shape(self):
        text = self.damaged_after("[zero-amount-claim]", "out = 0\nremainder = 966963624197021993",
                                  "out = 966963624197021993\nremainder = 0")
        errors = checker.check_text(text)
        self.assertTrue(any("zero-amount-claim: the amounts do not have the shape" in e
                            for e in errors), errors)

    def test_whole_balance_burn_wrong(self):
        text = self.damaged_after("[fee-uses-whole-balance]", "burned = 30033068911798188",
                                  "burned = 33036375802978007")
        self.assert_gap(text, "example fee-uses-whole-balance: burned is 33036375802978007")

    def test_fee_above_balance_marked_valid(self):
        text = self.damaged_after("[fee-above-balance]", "valid = no", "valid = yes")
        self.assert_gap(text, "example fee-above-balance: valid = yes, recomputed no")

    def test_boundary_fee_not_window_fee(self):
        text = self.damaged_after("[zero-amount-claim]", "fee = 33036375802978007",
                                  "fee = 33036375802978006")
        self.assert_gap(text, "example zero-amount-claim: fee 33036375802978006 is not the window fee")

    def test_competing_reveals_wrong(self):
        text = self.damaged_after("[competing-reveals]", "rejected = b", "rejected = a")
        self.assert_gap(text, "the first reveal must be included")
        text = self.damaged_after("[competing-reveals]", "marker_b = m", "marker_b = n")
        self.assert_gap(text, "must carry the same marker")
        text = self.damaged_after("[competing-reveals]", "total_out_change = 533036375802978007",
                                  "total_out_change = 500000000000000000")
        self.assert_gap(text, "total_out_change is 500000000000000000")
        text = self.damaged_after("[competing-reveals]", "remainder_b = 666963624197021993",
                                  "remainder_b = 666963624197021994")
        self.assert_gap(text, "reveal b does not conserve value")

    def test_unknown_example_kind(self):
        text = self.damaged_after("[full-reveal]", "kind = reveal", "kind = refund")
        self.assert_gap(text, "example full-reveal: unknown kind 'refund'")

    # Properties and conflicts

    def test_property_numbering_gap(self):
        self.assert_gap(self.damaged("- **PT-3. ", "- **PT-30. "), "properties are numbered")

    def test_property_without_check(self):
        start = self.text.index("- **PT-7.")
        at = self.text.index("Check:", start)
        text = self.text[:at] + "Test:" + self.text[at + len("Check:"):]
        self.assert_gap(text, "PT-7 does not say how a test checks it")

    def test_undefined_property_cited(self):
        self.assert_gap(self.damaged("(spec 02, PS-7).", "(spec 02, PS-7; PT-99)."),
                        "PT-99 is cited but not defined")

    def test_conflicts_name_each_spec(self):
        start = self.text.index("## 10. Conflicts")
        end = self.text.index("## 11.")
        for spec in ("spec 02", "spec 03", "spec 04"):
            with self.subTest(spec=spec):
                body = self.text[start:end]
                for variant in (spec, spec.capitalize()):
                    body = body.replace(variant, "a chapter")
                self.assert_gap(self.text[:start] + body + self.text[end:],
                                f"does not name {spec}")

    # The arithmetic itself

    def test_ceiling_bounds_the_base_client_rule(self):
        rng = random.Random(7)
        for _ in range(3000):
            gas_limit = rng.randint(checker.MIN_GAS_LIMIT, 60_000_000)
            base_fee = rng.choice((1, 7, 8, 9, rng.randint(1, 10**15)))
            gas_used = rng.choice((gas_limit, rng.randint(0, gas_limit)))
            nxt = checker.next_base_fee(base_fee, gas_limit, gas_used)
            self.assertLessEqual(nxt, checker.ceiling_step(base_fee), (base_fee, gas_limit, gas_used))

    def test_next_base_fee_matches_eip_1559(self):
        self.assertEqual(checker.next_base_fee(10**9, 30_000_000, 15_000_000), 10**9)
        self.assertEqual(checker.next_base_fee(10**9, 30_000_000, 30_000_000), 1_125_000_000)
        self.assertEqual(checker.next_base_fee(10**9, 30_000_000, 0), 875_000_000)
        self.assertEqual(checker.next_base_fee(7, 30_000_000, 30_000_000), 8)

    def test_ratio_text(self):
        self.assertEqual(checker.ratio_text(1_424_017_979, 10**9), "1.424")
        self.assertEqual(checker.ratio_text(1_000_500_000, 10**9), "1.001")
        self.assertEqual(checker.ratio_text(10**9, 10**9), "1.000")


if __name__ == "__main__":
    unittest.main()
