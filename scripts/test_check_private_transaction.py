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

    def test_parameter_fee_steps_missing(self):
        text = self.damaged("| `FEE_STEPS` | 1 |", "| `STEPS` | 1 |")
        self.assert_gap(text, "parameter table lacks ['FEE_STEPS']")

    def test_fee_steps_below_window(self):
        self.assert_gap(self.damaged("| `FEE_STEPS` | 1 |", "| `FEE_STEPS` | 4 |"),
                        "FEE_STEPS is 4; it must be at least 0 and below FEE_WINDOW")

    def test_window_fee_wrong(self):
        text = self.damaged_after("[window-genesis]", "tip = 2372772303969038", "tip = 2372772303969037")
        self.assert_gap(text, "example window-genesis: tip is 2372772303969037")
        text = self.damaged_after("[window-genesis]", "price = 1125050001", "price = 1125050000")
        self.assert_gap(text, "example window-genesis: price is 1125050000")
        text = self.damaged_after("[window-next]", "fee = 28710544875705410", "fee = 28710544875705411")
        self.assert_gap(text, "example window-next: fee is 28710544875705411")
        text = self.damaged_after("[window-genesis]", "cover_limit = 1237555001",
                                  "cover_limit = 1237555002")
        self.assert_gap(text, "example window-genesis: cover_limit is 1237555002")

    def test_window_fee_matches_the_decision(self):
        # The figures of the front desk decision at b_ref = 1 gwei.
        price = checker.window_price(10**9, 1)
        self.assertEqual(price, 1_125_050_001)
        self.assertEqual(checker.window_fee(price, 21_090_372, 10),
                         (23_727_723_039_690_372, 2_372_772_303_969_038, 26_100_495_343_659_410))

    def test_window_fee_tracks_parameters(self):
        text = self.damaged("| `FEE_STEPS` | 1 |", "| `FEE_STEPS` | 2 |")
        self.assert_gap(text, "example window-genesis: price is 1125050001, recomputed 1265737504")
        text = self.damaged("| `FEE_STEPS` | 1 |", "| `FEE_STEPS` | 0 |")
        self.assert_gap(text, "example window-genesis: price is 1125050001, recomputed 1000000000")
        text = self.damaged("| `TIP_DIVISOR` | 10 |", "| `TIP_DIVISOR` | 20 |")
        self.assert_gap(text, "example window-genesis: tip is")
        text = self.damaged("| `FEE_WINDOW` | 4 |", "| `FEE_WINDOW` | 5 |")
        self.assert_gap(text, "one base fee, valid flag and tip per block of the window")

    def test_window_length_table(self):
        text = self.damaged("| 4 | 1.125 | 2 |", "| 4 | 1.424 | 2 |")
        self.assert_gap(text, "window length 4: price is 1.424, recomputed 1.125")
        text = self.damaged("| 4 | 1.125 | 2 |", "| 4 | 1.125 | 4 |")
        self.assert_gap(text, "window length 4: 4 blocks valid at any load, recomputed 2")
        text = self.damaged("| 1 | 1.125 | 1 |", "| 1 | 1.125 | 2 |")
        self.assert_gap(text, "window length 1: 2 blocks valid at any load, recomputed 1")
        text = self.damaged("| 4 | 1.125 | 2 | 120 s", "| 4 | 1.125 | 2 | 240 s")
        self.assert_gap(text, "window length 4: open for '240 s")
        text = self.damaged("| 4 | 1.125 | 2 | 120 s", "| 3 | 1.125 | 2 | 90 s")
        self.assert_gap(text, "no row for FEE_WINDOW")
        text = self.damaged("| Window length | Price over b_ref |", "| Window | Price over b_ref |")
        self.assert_gap(text, "no table with columns")

    def test_window_length_tracks_fee_steps(self):
        # Two steps of headroom make block 2 valid at any load too.
        text = self.damaged("| `FEE_STEPS` | 1 |", "| `FEE_STEPS` | 2 |")
        self.assert_gap(text, "window length 4: 2 blocks valid at any load, recomputed 3")

    def test_subsections_required(self):
        for heading in checker.REQUIRED_SUBSECTIONS:
            with self.subTest(heading=heading):
                self.assert_gap(self.damaged(heading + "\n", "### Elsewhere\n"),
                                f"no subsection '{heading}'")

    def test_smallest_vanish_subsection_required(self):
        self.assertIn("### The smallest Vanish", checker.REQUIRED_SUBSECTIONS)
        self.assert_gap(self.damaged("### The smallest Vanish\n", "### Elsewhere\n"),
                        "no subsection '### The smallest Vanish'")
        # Moved out of section 5, it is missing there too.
        text = self.damaged("### The smallest Vanish\n", "## 6. Smallest Vanish\n")
        self.assert_gap(text, "no subsection '### The smallest Vanish'")

    def test_smallest_vanish_multiple_wrong(self):
        for line in ("MIN_VANISH_FEES = 1\n", "MIN_VANISH_FEES = 0\n", "MIN_VANISH_FEES = four\n", ""):
            with self.subTest(line=line):
                self.assert_gap(self.damaged("MIN_VANISH_FEES = 4\n", line), "MIN_VANISH_FEES")
        # A worked number that is not MIN_VANISH_FEES times the fee of
        # window-genesis, one fee more or the number of another multiple.
        for number in ("130502476718297050", "104401981374637641"):
            with self.subTest(number=number):
                text = self.damaged("the smallest Vanish is 104401981374637640 wei",
                                    f"the smallest Vanish is {number} wei")
                self.assert_gap(text, "recomputed MIN_VANISH_FEES * fee of window-genesis")
        # A changed multiple with the worked number left as it was.
        text = self.damaged("MIN_VANISH_FEES = 4\n", "MIN_VANISH_FEES = 5\n")
        self.assert_gap(text, "recomputed MIN_VANISH_FEES * fee of window-genesis = 130502476718297050")
        # No worked number at all.
        text = self.damaged("the smallest Vanish is 104401981374637640 wei", "the smallest Vanish is about")
        self.assert_gap(text, "worked number 'the smallest Vanish is N wei' for MIN_VANISH_FEES")
        self.assertEqual(4 * 26_100_495_343_659_410, 104_401_981_374_637_640)

    def growth_line(self, name, key):
        start = self.text.index(f"[{name}]")
        line_start = self.text.index(f"{key} = ", start)
        line_end = self.text.index("\n", line_start)
        return line_start, line_end, self.text[line_start:line_end].split(" = ")[1].split()

    def with_growth_item(self, name, key, j, value):
        line_start, line_end, items = self.growth_line(name, key)
        items[j] = value
        return self.text[:line_start] + f"{key} = " + " ".join(items) + self.text[line_end:]

    def test_growth_wrong(self):
        _, _, fees = self.growth_line("growth-genesis-full-blocks", "base_fees")
        text = self.with_growth_item("growth-genesis-full-blocks", "base_fees", 2, str(int(fees[2]) + 1))
        self.assert_gap(text, "example growth-genesis-full-blocks: base fee 2 is")
        _, _, fees = self.growth_line("growth-genesis-private-load", "base_fees")
        text = self.with_growth_item("growth-genesis-private-load", "base_fees", 3, str(int(fees[3]) - 1))
        self.assert_gap(text, "example growth-genesis-private-load: base fee 3 is")

    def test_growth_cover_verdict_wrong(self):
        text = self.with_growth_item("growth-genesis-full-blocks", "valid", 2, "yes")
        self.assert_gap(text, "example growth-genesis-full-blocks: block 2 valid = yes, recomputed no")
        text = self.with_growth_item("growth-genesis-private-load", "valid", 3, "no")
        self.assert_gap(text, "example growth-genesis-private-load: block 3 valid = no, recomputed yes")

    def test_growth_tip_wrong(self):
        # Above the price the tip falls; below it, it is the nominal tip.
        text = self.with_growth_item("growth-genesis-private-load", "tips", 3, "2372772303969038")
        self.assert_gap(text, "example growth-genesis-private-load: block 3 tip is 2372772303969038, "
                              "recomputed 1633182225038030")
        text = self.with_growth_item("growth-genesis-full-blocks", "tips", 3, "0")
        self.assert_gap(text, "example growth-genesis-full-blocks: block 3 tip is 0, recomputed -")

    def test_growth_examples_required(self):
        text = self.damaged_after("[growth-genesis-full-blocks]", "gas_used = 30000001",
                                  "gas_used = 30000000")
        self.assert_gap(text, "no worst-case growth example with every block full")
        text = self.damaged_after("[growth-genesis-private-load]", "kind = growth", "kind = window")
        self.assert_gap(text, "no growth example under private-reveal load")

    def test_growth_without_burn_floor_fails(self):
        # Burning only the window's base part, without the cover rule, burns
        # less than G_PRIV times the base fee above the price.
        original = checker.cover_split
        checker.cover_split = lambda fee, price, base_fee, g_priv: (g_priv * price, fee - g_priv * price)
        try:
            errors = checker.check_text(self.text)
        finally:
            checker.cover_split = original
        self.assertTrue(any("burns less than G_PRIV times its base fee" in e for e in errors), errors)

    def test_lapse_wrong(self):
        text = self.damaged_after("[lapse-two-windows]", "valid = no", "valid = yes")
        self.assert_gap(text, "example lapse-two-windows: valid = yes, recomputed no")
        text = self.damaged_after("[lapse-fee-unchanged]", "valid = yes", "valid = no")
        self.assert_gap(text, "example lapse-fee-unchanged: valid = no, recomputed yes")
        text = self.damaged_after("[lapse-cover-fails]", "valid = no", "valid = yes")
        self.assert_gap(text, "example lapse-cover-fails: valid = yes, recomputed no")
        text = self.damaged_after("[lapse-previous-window]", "tip = 1846567543659410", "tip = 2372772303969038")
        self.assert_gap(text, "example lapse-previous-window: tip is 2372772303969038")

    def test_lapse_matched_window(self):
        # The current window is read first; the previous one only when it does not match.
        text = self.damaged_after("[lapse-fee-unchanged]", "matched = current", "matched = previous")
        self.assert_gap(text, "example lapse-fee-unchanged: matched = previous, recomputed current")
        text = self.damaged_after("[lapse-two-windows]", "matched = none", "matched = previous")
        self.assert_gap(text, "example lapse-two-windows: matched = previous, recomputed none")

    def test_lapse_no_window_before_the_first(self):
        text = self.damaged_after("[lapse-previous-window]", "fee_previous = 26100495343659410",
                                  "fee_previous = none")
        errors = checker.check_text(text)
        self.assertTrue(any("lapse-previous-window: matched = previous, recomputed none" in e
                            for e in errors), errors)
        self.assertTrue(any("lapse-previous-window: valid = yes, recomputed no" in e
                            for e in errors), errors)

    def test_lapse_fee_must_be_a_window_fee(self):
        text = self.damaged_after("[lapse-two-windows]", "fee_current = 28710544875705410",
                                  "fee_current = 28710544875705411")
        self.assert_gap(text, "example lapse-two-windows: fee_current 28710544875705411 is no window")

    def test_each_lapse_outcome_is_required(self):
        for name, what in (("lapse-previous-window", "a valid fee of the previous window"),
                           ("lapse-two-windows", "a fee of neither window"),
                           ("lapse-cover-fails", "a matched fee that fails the cover rule")):
            with self.subTest(name=name):
                start = self.text.index(f"[{name}]")
                end = self.text.index("tip = ", start)
                end = self.text.index("\n", end) + 1
                text = self.text[:start] + self.text[end:]
                self.assert_gap(text, f"no lapse example of {what}")

    def test_each_boundary_case_is_required(self):
        for name in checker.REQUIRED_EXAMPLES:
            with self.subTest(name=name):
                text = self.damaged(f"[{name}]", "[renamed]")
                self.assert_gap(text, f"boundary case example {name}")

    def test_full_reveal_wrong(self):
        text = self.damaged_after("[full-reveal]", "out = 973899504656340590", "out = 973899504656340591")
        errors = checker.check_text(text)
        self.assertTrue(any("example full-reveal: valid = yes, recomputed no" in e for e in errors), errors)

    def test_full_reveal_minted_wrong(self):
        text = self.damaged_after("[full-reveal]", "minted = 973899504656340590", "minted = 1")
        self.assert_gap(text, "example full-reveal: minted is 1")

    def test_zero_amount_claim_shape(self):
        text = self.damaged_after("[zero-amount-claim]", "out = 0\nremainder = 973899504656340590",
                                  "out = 973899504656340590\nremainder = 0")
        errors = checker.check_text(text)
        self.assertTrue(any("zero-amount-claim: the amounts do not have the shape" in e
                            for e in errors), errors)

    def test_whole_balance_burn_wrong(self):
        text = self.damaged_after("[fee-uses-whole-balance]", "burned = 23727723039690372",
                                  "burned = 26100495343659410")
        self.assert_gap(text, "example fee-uses-whole-balance: burned is 26100495343659410")

    def test_boundary_burn_follows_the_base_fee(self):
        # Above the price the burn is G_PRIV times the block's base fee and the
        # tip falls; above the cover limit the reveal is rejected.
        text = self.damaged_after("[full-reveal]", "base_fee = 1000000000", "base_fee = 1200000000")
        errors = checker.check_text(text)
        self.assertTrue(any("example full-reveal: burned is 23727723039690372, recomputed "
                            "25308446400000000" in e for e in errors), errors)
        self.assertTrue(any("example full-reveal: tip is 2372772303969038, recomputed "
                            "792048943659410" in e for e in errors), errors)
        text = self.damaged_after("[full-reveal]", "base_fee = 1000000000", "base_fee = 1237555002")
        self.assert_gap(text, "example full-reveal: valid = yes, recomputed no")
        text = self.damaged_after("[full-reveal]", "base_fee = 1000000000\n", "")
        self.assert_gap(text, "example full-reveal: 'base_fee' is missing")

    def test_fee_above_balance_marked_valid(self):
        text = self.damaged_after("[fee-above-balance]", "valid = no", "valid = yes")
        self.assert_gap(text, "example fee-above-balance: valid = yes, recomputed no")

    def test_boundary_fee_not_window_fee(self):
        text = self.damaged_after("[zero-amount-claim]", "fee = 26100495343659410",
                                  "fee = 26100495343659409")
        self.assert_gap(text, "example zero-amount-claim: fee 26100495343659409 is not the window fee")

    def test_competing_reveals_wrong(self):
        text = self.damaged_after("[competing-reveals]", "rejected = b", "rejected = a")
        self.assert_gap(text, "the first reveal must be included")
        text = self.damaged_after("[competing-reveals]", "marker_b = m", "marker_b = n")
        self.assert_gap(text, "must carry the same marker")
        text = self.damaged_after("[competing-reveals]", "total_out_change = 526100495343659410",
                                  "total_out_change = 500000000000000000")
        self.assert_gap(text, "total_out_change is 500000000000000000")
        text = self.damaged_after("[competing-reveals]", "remainder_b = 673899504656340590",
                                  "remainder_b = 673899504656340591")
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

    def test_growth_step_bounds_the_base_client_rule(self):
        rng = random.Random(7)
        for _ in range(3000):
            gas_limit = rng.randint(checker.MIN_GAS_LIMIT, 60_000_000)
            base_fee = rng.choice((1, 7, 8, 9, rng.randint(1, 10**15)))
            gas_used = rng.choice((gas_limit, rng.randint(0, gas_limit)))
            nxt = checker.next_base_fee(base_fee, gas_limit, gas_used)
            self.assertLessEqual(nxt, checker.growth_step(base_fee), (base_fee, gas_limit, gas_used))

    def test_cover_rule_guarantee_randomised(self):
        # PT-7: over random gas limits, loads and starting base fees, for the
        # current window's fee and the previous window's, every reveal the
        # cover rule accepts burns at least G_PRIV times the block's base fee,
        # tips no more than the nominal tip, and splits the fee exactly; blocks
        # 0 and 1 of the window always accept the window's fee.
        rng = random.Random(11)
        g_priv = 21_090_372
        for _ in range(500):
            gas_limit = rng.randint(checker.MIN_GAS_LIMIT, 60_000_000)
            b_ref = rng.choice((1, 7, 10**9, rng.randint(1, 10**12)))
            price = checker.window_price(b_ref, 1)
            base, tip, fee = checker.window_fee(price, g_priv, 10)
            base_fee = b_ref
            for j in range(8):  # the window and the one after it
                split = checker.cover_split(fee, price, base_fee, g_priv)
                if j < 2:
                    self.assertIsNotNone(split, (b_ref, gas_limit, j))
                    self.assertEqual(split, (base, tip))
                if split is None:
                    self.assertGreater(g_priv * base_fee, fee)
                else:
                    burn, paid = split
                    self.assertGreaterEqual(burn, g_priv * base_fee)
                    self.assertGreaterEqual(burn, base)
                    self.assertTrue(0 <= paid <= tip)
                    self.assertEqual(burn + paid, fee)
                    if base_fee <= price:
                        self.assertEqual(paid, tip)
                gas_used = rng.choice((gas_limit, rng.randint(0, gas_limit)))
                base_fee = checker.next_base_fee(base_fee, gas_limit, gas_used)

    def test_cover_limit_is_the_boundary(self):
        g_priv = 21_090_372
        price = checker.window_price(10**9, 1)
        fee = checker.window_fee(price, g_priv, 10)[2]
        limit = checker.cover_limit(fee, g_priv)
        self.assertEqual(limit, 1_237_555_001)
        self.assertEqual(checker.cover_split(fee, price, limit, g_priv),
                         (g_priv * limit, fee - g_priv * limit))
        self.assertIsNone(checker.cover_split(fee, price, limit + 1, g_priv))

    def test_matched_fee(self):
        self.assertEqual(checker.matched_fee(5, 5, 5), "current")
        self.assertEqual(checker.matched_fee(5, 6, 5), "previous")
        self.assertEqual(checker.matched_fee(5, 6, 7), "none")
        self.assertEqual(checker.matched_fee(5, 6, None), "none")
        self.assertEqual(checker.matched_fee(5, 5, None), "current")

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
