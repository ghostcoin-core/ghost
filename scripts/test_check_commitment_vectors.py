"""Tests for check_commitment_vectors.py: it passes on the specification and
fails when a vector, the tag table or the code behind a rule is damaged."""

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = HERE.parent / "docs" / "spec" / "01-commitments-and-keys.md"

_spec = importlib.util.spec_from_file_location("check_commitment_vectors", HERE / "check_commitment_vectors.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


def _flip_hex(value):
    return ("1" if value[0] != "1" else "2") + value[1:]


class CheckerTest(unittest.TestCase):
    def setUp(self):
        self.text = SPEC.read_text(encoding="utf-8")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_on(self, text):
        path = Path(self.tmp.name) / "spec.md"
        path.write_text(text, encoding="utf-8")
        return checker.run(path)[0]

    def replace_field(self, vector, field, new_value):
        """Return the document with one field of one vector replaced."""
        start = self.text.index(f"[{vector}]\n")
        line_start = self.text.index(f"\n{field} = ", start) + 1
        line_end = self.text.index("\n", line_start)
        return self.text[:line_start] + f"{field} = {new_value}" + self.text[line_end:]

    def field(self, vector, name):
        start = self.text.index(f"[{vector}]\n")
        line_start = self.text.index(f"\n{name} = ", start) + 1
        return self.text[line_start : self.text.index("\n", line_start)].split(" = ", 1)[1]

    def test_specification_passes(self):
        errors, count, checked = checker.run(SPEC)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(count, 20)
        self.assertGreaterEqual(checked, 60)
        self.assertEqual(checker.main(["x", str(SPEC)]), 0)

    def test_keccak_matches_known_values(self):
        self.assertEqual(checker.keccak_self_test(), [])
        self.assertNotEqual(checker.keccak256(b"abc"), hashlib.sha3_256(b"abc").digest())

    def test_sha3_padding_in_place_of_keccak_fails(self):
        with mock.patch.object(checker, "keccak256", lambda data: hashlib.sha3_256(data).digest()):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("known value" in e for e in errors))
        self.assertTrue(any("[coin-commit] commitment" in e for e in errors))

    def test_broken_permutation_fails_self_test(self):
        constants = list(checker._ROUND_CONSTANTS)
        constants[5] ^= 1
        with mock.patch.object(checker, "_ROUND_CONSTANTS", constants):
            self.assertNotEqual(checker.keccak_self_test(), [])

    def test_every_changed_value_is_caught(self):
        cases = [
            ("derivation-standard", "key-bytes"),
            ("derivation-standard", "s"),
            ("derivation-standard", "r"),
            ("derivation-standard", "b1"),
            ("derivation-long", "note-key"),
            ("derivation-long", "data-key"),
            ("coin-commit", "fingerprint"),
            ("coin-commit", "commitment"),
            ("coin-remainder", "marker"),
            ("data-commit", "content-fingerprint"),
            ("data-commit", "commitment"),
            ("data-commit", "marker"),
            ("empty-leaf", "leaf"),
            ("coin-tree-node", "node"),
            ("data-tree-node", "node"),
            ("note-coin-remainder", "plaintext"),
            ("note-data-commit", "associated-data"),
            ("keccak-abc", "digest"),
        ]
        for vector, name in cases:
            with self.subTest(vector=vector, field=name):
                text = self.replace_field(vector, name, _flip_hex(self.field(vector, name)))
                errors = self.run_on(text)
                self.assertTrue(any(f"[{vector}] {name}" in e for e in errors), errors)

    def test_changed_amount_changes_commitment(self):
        errors = self.run_on(self.replace_field("coin-commit", "amount", "1000000000000000001"))
        self.assertTrue(any("[coin-commit] commitment" in e for e in errors))
        self.assertFalse(any("[coin-commit] fingerprint" in e for e in errors))

    def test_checksum_errors_are_caught(self):
        # A wrong check group in a key that the document calls valid.
        key = self.field("checksum-standard", "key")
        errors = self.run_on(self.replace_field("checksum-standard", "key", key[:-1] + "8"))
        self.assertTrue(any("[checksum-standard] valid" in e for e in errors))
        # A wrong documented check value.
        errors = self.run_on(self.replace_field("checksum-long", "check", "6390 8043"))
        self.assertTrue(any("[checksum-long] check" in e for e in errors))
        # A key that fails its checksum cannot be used for derivation.
        errors = self.run_on(self.replace_field("derivation-standard", "key", key[:-1] + "8"))
        self.assertTrue(any("[derivation-standard] cannot be checked" in e for e in errors))

    def test_checksum_depends_on_format(self):
        payload = self.field("checksum-long", "key").split()
        fmt, groups, _ = checker.parse_key(" ".join(payload))
        self.assertEqual(fmt, checker.FORMAT_24)
        first = checker.compute_checks(checker.FORMAT_12, groups[:11])
        self.assertNotEqual(first[0], payload[11])

    def test_key_entry_rules(self):
        for bad in ("1111 2222", "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 041a",
                    "١111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417"):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    checker.parse_key(bad)
        spaced = checker.parse_key("1111-2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417")
        self.assertEqual(spaced[0], checker.FORMAT_12)

    def test_same_blinding_every_time_is_caught(self):
        # The old design reused one remainder blinding; that must not pass.
        original = checker.derive_blinding
        with mock.patch.object(checker, "derive_blinding", lambda kb, i: original(kb, 0)):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[derivation-standard] b1" in e for e in errors))
        self.assertTrue(any("[coin-remainder] marker" in e for e in errors))

    def test_blindings_and_secrets_are_distinct(self):
        kb = checker.valid_key_bytes(self.field("derivation-standard", "key"))
        values = [checker.derive_blinding(kb, i) for i in range(50)]
        values += [checker.derive_secret(kb), checker.derive_reveal_secret(kb),
                   checker.derive_note_key(kb), checker.derive_data_key(kb)]
        self.assertEqual(len(set(values)), len(values))

    def test_missing_vector_kind_fails(self):
        # Both note vectors sit in one block; drop the block's contents.
        start = self.text.index("[note-coin-remainder]")
        end = self.text.index("```", start)
        self.assertNotIn("kind = note", self.text[:start] + self.text[end:])
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertIn("no vector of kind note", errors)

    def test_missing_remainder_vector_fails(self):
        start = self.text.index("[coin-remainder]")
        end = self.text.index("[data-commit]", start)
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertTrue(any("index 1" in e for e in errors))

    def test_tag_table_must_list_every_tag(self):
        text = self.text.replace("| `ghost/hold-binding/v1` |", "| hold binding |", 1)
        errors = self.run_on(text)
        self.assertIn("tag ghost/hold-binding/v1 is used but not listed in the tag table", errors)
        text = self.text.replace("`ghost/empty-leaf/v1`", "`ghost/empty-leaf/v2`")
        errors = self.run_on(text)
        self.assertTrue(any("ghost/empty-leaf/v2 is listed" in e for e in errors))

    def test_tags_are_distinct_ascii_with_version(self):
        self.assertEqual(len(checker.ALL_TAGS), 19)
        for tag in checker.ALL_TAGS:
            self.assertRegex(tag, r"^ghost/[a-z0-9-]+/v1$")
        prefixes = {checker._tag_prefix(t) for t in checker.ALL_TAGS}
        self.assertEqual(len(prefixes), len(checker.ALL_TAGS))

    def test_unknown_kind_and_bad_lines_fail(self):
        text = self.text.replace("kind = empty-leaf", "kind = nothing", 1)
        self.assertTrue(any("unknown kind" in e for e in self.run_on(text)))
        text = self.text.replace("kind = empty-leaf", "kind: empty-leaf", 1)
        self.assertEqual(checker.main(["x", str(self._write(text))]), 1)

    def test_missing_file_fails(self):
        self.assertEqual(checker.main(["x", str(Path(self.tmp.name) / "absent.md")]), 1)

    def _write(self, text):
        path = Path(self.tmp.name) / "other.md"
        path.write_text(text, encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
