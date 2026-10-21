"""Tests for check_proof_statements.py: it passes on the specification and
fails when a statement, a binding layout, a property, an adversarial vector or
a vector is damaged."""

import importlib.util
import random
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = HERE.parent / "docs" / "spec" / "02-proof-statements.md"
TAGS = HERE.parent / "docs" / "spec" / "01-commitments-and-keys.md"

_spec = importlib.util.spec_from_file_location("check_proof_statements", HERE / "check_proof_statements.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


class CheckerTest(unittest.TestCase):
    def setUp(self):
        self.text = SPEC.read_text(encoding="utf-8")
        self.tags = TAGS.read_text(encoding="utf-8")

    def errors(self, text):
        return checker.check_text(text, self.tags)

    def damaged(self, old, new, count=1):
        self.assertIn(old, self.text)
        return self.text.replace(old, new, count)

    def assert_gap(self, text, fragment):
        errors = self.errors(text)
        self.assertTrue(any(fragment in e for e in errors), f"no '{fragment}' in {errors}")

    def test_specification_passes(self):
        self.assertEqual(self.errors(self.text), [])
        self.assertEqual(checker.main(["x", str(SPEC)]), 0)

    def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertNotEqual(checker.main(["x", str(Path(tmp) / "absent.md")]), 0)

    def test_missing_tag_table_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "02.md"
            path.write_text(self.text, encoding="utf-8")
            self.assertNotEqual(checker.main(["x", str(path)]), 0)

    def test_required_section_missing(self):
        for heading, word in (("## 8. Shared tree state", "Shared tree state"),
                              ("## 10. Range and encoding of amounts", "Range"),
                              ("## 12. Adversarial vectors", "Adversarial vectors")):
            with self.subTest(word=word):
                self.assert_gap(self.damaged(heading, "## Elsewhere"), f"contains '{word}'")

    def test_statement_without_private_inputs(self):
        start = self.text.index("## 5. Statement S2")
        at = self.text.index("**Private inputs.**", start)
        text = self.text[:at] + "**Secret inputs.**" + self.text[at + len("**Private inputs.**"):]
        self.assert_gap(text, "statement S2: no private inputs table")

    def test_statement_without_public_inputs(self):
        start = self.text.index("## 6. Statement S3")
        at = self.text.index("**Public inputs.**", start)
        text = self.text[:at] + "**Inputs.**" + self.text[at + len("**Public inputs.**"):]
        self.assert_gap(text, "statement S3: no public inputs table")

    def test_public_input_without_reason(self):
        row = "| `fee` | 32 | Node's fee formula for the block | "
        start = self.text.index(row)
        end = self.text.index("\n", start)
        text = self.text[:start] + row + " |" + self.text[end:]
        self.assert_gap(text, "public input 'fee' gives no reason")

    def test_secret_made_public(self):
        row = "| `rule` | 32 | Transaction, must be the empty rule | The empty rule is the only"
        text = self.damaged(row, "| `r` | 32 | Transaction | none |\n" + row)
        errors = self.errors(text)
        self.assertTrue(any("both public and private" in e for e in errors), errors)

    def test_salt_must_be_private_in_every_statement(self):
        for heading, row in (
                ("## 4. Statement S1", "| `salt` | 16 | Salt of the input commitment"),
                ("## 5. Statement S2", "| `salt` | 16 | Salt of the data commitment"),
                ("## 6. Statement S3", "| `salt` | 16 | Salt of the commitment;")):
            with self.subTest(statement=heading):
                start = self.text.index(heading)
                at = self.text.index(row, start)
                end = self.text.index("\n", at) + 1
                text = self.text[:at] + self.text[end:]
                n = heading.split("Statement ")[1]
                self.assert_gap(text, f"statement {n}: 'salt' is not a private input")

    def test_salt_made_public(self):
        row = "| `rule` | 32 | Transaction, must be the empty rule | The empty rule is the only"
        start = self.text.index("## 4. Statement S1")
        priv = self.text.index("| `salt` | 16 | Salt of the input commitment", start)
        end = self.text.index("\n", priv) + 1
        text = self.text[:priv] + self.text[end:]
        text = text.replace(row, "| `salt` | 16 | Transaction | It is public anyway |\n" + row, 1)
        errors = self.errors(text)
        self.assertTrue(any("statement S1: 'salt' is a public input" in e for e in errors), errors)
        self.assertTrue(any("public inputs not in ghost/coin-reveal-binding/v1: ['salt']" in e
                            for e in errors), errors)

    def test_salted_tags_must_be_named(self):
        for tag in checker.SALTED_TAGS:
            with self.subTest(tag=tag):
                text = self.text.replace(tag, tag[:-1] + "1")
                self.assert_gap(text, f"salted tag {tag} is not named")

    def test_salt_and_unknown_version_vectors_are_listed(self):
        self.assertIn("- **PS-25. The salt is a private witness", self.text)
        self.assertIn("- **AV-13. Salt substitution", self.text)
        start = self.text.index("- **PS-25.")
        at = self.text.index("Check:", start)
        text = self.text[:at] + "Test:" + self.text[at + len("Check:"):]
        self.assert_gap(text, "PS-25 does not say how a test checks it")

    def test_public_input_not_bound(self):
        row = "| `rule` | 32 | Transaction, must be the empty rule | The empty rule is the only"
        text = self.damaged(row, "| `memo` | 32 | Transaction | A free text |\n" + row)
        self.assert_gap(text, "public inputs not in ghost/coin-reveal-binding/v1: ['memo']")

    def test_layout_missing_recipient(self):
        text = self.damaged("| 143 | 20 | `recipient` | Address credited with `out` |\n", "")
        errors = self.errors(text)
        self.assertTrue(any("does not bind ['recipient']" in e for e in errors), errors)
        self.assertTrue(any("offset 163, expected 143" in e for e in errors), errors)

    def test_layout_missing_chain_id(self):
        start = self.text.index("### Hold binding")
        row = "| 0 | 8 | `chain_id` | The verifier's chain |\n"
        at = self.text.index(row, start)
        text = self.text[:at] + self.text[at + len(row):]
        self.assert_gap(text, "binding ghost/hold-binding/v1: does not bind ['chain_id']")

    def test_layout_width_mismatch(self):
        text = self.damaged("| 143 | 20 | `recipient` |", "| 143 | 32 | `recipient` |")
        self.assert_gap(text, "'recipient' is 20 bytes in the public inputs and 32")

    def test_wrong_total_and_permutations(self):
        text = self.damaged("Total: 415 bytes after the tag; 444 bytes with the tag; 4 Keccak",
                            "Total: 415 bytes after the tag; 444 bytes with the tag; 3 Keccak")
        self.assert_gap(text, "says 3 permutations, recomputed 4")
        text = self.damaged("Total: 207 bytes after the tag", "Total: 208 bytes after the tag")
        self.assert_gap(text, "total says 208 bytes, fields sum to 207")

    def test_unknown_tag(self):
        text = self.damaged("`ghost/hold-binding/v1`.", "`ghost/hold-binding/v1`. See `ghost/made-up/v1`.")
        self.assert_gap(text, "tag ghost/made-up/v1 is not in the tag table")

    def test_property_numbering_gap(self):
        self.assert_gap(self.damaged("- **PS-3. One commitment", "- **PS-30. One commitment"),
                        "properties are numbered")

    def test_property_without_check(self):
        start = self.text.index("- **PS-15.")
        at = self.text.index("Check:", start)
        text = self.text[:at] + "Test:" + self.text[at + len("Check:"):]
        self.assert_gap(text, "PS-15 does not say how a test checks it")

    def test_undefined_property_cited(self):
        self.assert_gap(self.damaged("(PS-6, PS-7; spec 03, CR-8)", "(PS-6, PS-99; spec 03, CR-8)"),
                        "PS-99 is cited but not defined")

    def test_named_vector_missing(self):
        start = self.text.index("- **AV-2. Fee substitution.**")
        end = self.text.index("- **AV-3.", start)
        text = self.text[:start] + self.text[end:]
        errors = self.errors(text)
        self.assertTrue(any("'fee substitution': expected one entry, found 0" in e for e in errors), errors)
        self.assertTrue(any("adversarial vectors are numbered" in e for e in errors), errors)

    def test_each_named_vector_is_required(self):
        for name in checker.REQUIRED_VECTORS:
            with self.subTest(name=name):
                start = self.text.index("## 12. Adversarial vectors")
                lower = self.text.lower()
                at = lower.index(name, start)
                text = self.text[:at] + "renamed" + self.text[at + len(name):]
                self.assert_gap(text, f"'{name}': expected one entry, found 0")

    def test_vector_without_property(self):
        self.assert_gap(self.damaged("nothing applies (PS-7, PS-24).", "nothing applies."),
                        "AV-8 cites no property")

    def test_wrong_amount_vector(self):
        text = self.damaged("limbs = 0000 0000 0de0 b6b3 a764 0000", "limbs = 0000 0000 0de0 b6b3 a764 0001")
        self.assert_gap(text, "vector amount-one-ghost: limbs")
        start = self.text.index("[amount-two-to-96]")
        at = self.text.index("valid = no", start)
        text = self.text[:at] + "valid = yes" + self.text[at + len("valid = no"):]
        self.assert_gap(text, "vector amount-two-to-96: valid = yes")

    def test_wrong_conservation_vector(self):
        start = self.text.index("[conservation-field-wrap]")
        at = self.text.index("valid = no", start)
        text = self.text[:at] + "valid = yes" + self.text[at + len("valid = no"):]
        self.assert_gap(text, "vector conservation-field-wrap: valid = yes, recomputed no")

    def test_full_reveal_vector_required(self):
        text = self.damaged("[conservation-full-reveal]", "[conservation-other]")
        self.assert_gap(text, "conservation vector conservation-full-reveal is missing")

    def test_limb_rule_matches_integer_rule(self):
        rng = random.Random(1234)
        v_max = checker.V_MAX
        for _ in range(2000):
            parts = [rng.randint(0, v_max // 3) for _ in range(3)]
            v = sum(parts) + rng.choice((0, 0, 1, -1))
            for args in ((v, *parts), (v_max, v_max, 0, 0), (5, v_max, 6, 0)):
                self.assertEqual(checker.limb_conservation(*args),
                                 checker.integer_conservation(*args), args)

    def test_limb_rule_rejects_wraps(self):
        p = 2**64 - 2**32 + 1
        self.assertFalse(checker.limb_conservation(10, 20, p - 10, 0))
        self.assertFalse(checker.limb_conservation(5, checker.V_MAX, 6, 0))
        self.assertFalse(checker.limb_conservation(0, checker.V_MAX + 1, 0, 0))
        self.assertTrue(checker.limb_conservation(checker.V_MAX, checker.V_MAX, 0, 0))


if __name__ == "__main__":
    unittest.main()
