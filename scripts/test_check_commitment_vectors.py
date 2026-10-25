"""Tests for check_commitment_vectors.py: it passes on the specification and
fails when a vector, the tag table or the code behind a rule is damaged."""

import hashlib
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = HERE.parent / "docs" / "spec" / "01-commitments-and-keys.md"

_spec = importlib.util.spec_from_file_location("check_commitment_vectors", HERE / "check_commitment_vectors.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


WORD_KEY_TESTS = HERE.parent / "client" / "tests" / "word_key.rs"

# The digit view of the words key of spec 01, section 5.
WORDS_EXAMPLE = ("0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 "
                 "7303 1997 5454 7598 3699 7944 0671 6812")


def words_vectors():
    """The WordsVector entries of client/tests/word_key.rs, as dicts."""
    text = WORD_KEY_TESTS.read_text(encoding="utf-8")
    body = text[text.index("const WORDS_VECTORS") :]
    body = body[: body.index("];")]
    vectors = []
    for block in body.split("WordsVector {")[1:]:
        vectors.append(dict(re.findall(r'(\w+): "([^"]*)"', block)))
    return vectors


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
            ("coin-commit-salted", "fingerprint"),
            ("coin-commit-salted-other", "commitment"),
            ("coin-remainder-salted", "marker"),
            ("data-commit-salted", "fingerprint"),
            ("data-commit-salted-other", "marker"),
            ("data-commit", "content-fingerprint"),
            ("data-commit", "commitment"),
            ("data-commit", "marker"),
            ("empty-leaf", "leaf"),
            ("coin-tree-node", "node"),
            ("data-tree-node", "node"),
            ("note-coin-remainder", "plaintext"),
            ("note-data-commit", "associated-data"),
            ("note-coin-remainder-salted", "plaintext"),
            ("note-data-commit-salted", "plaintext"),
            ("note-data-commit-salted", "associated-data"),
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
        # The words code enters the check too: the same 80 digits under another
        # code give another group.
        fmt, groups, checks = checker.parse_key(WORDS_EXAMPLE)
        self.assertEqual(fmt, checker.FORMAT_WORDS)
        for code in (checker.FORMAT_12, checker.FORMAT_24, 0x21):
            self.assertNotEqual(checker._check_group(code, 1, groups), checks[0])

    def test_words_digit_view(self):
        # The digit view of a words key: code 0x20, the 80 secret digits read
        # as one decimal number into 32 bytes, and check group 21. Every words
        # vector of the client is recomputed here from its digits alone.
        vectors = words_vectors()
        self.assertEqual(len(vectors), 5)
        for v in vectors:
            with self.subTest(digits=v["digits"]):
                kb = checker.valid_key_bytes(v["digits"])
                self.assertEqual(kb, b"\x20" + bytes.fromhex(v["bits"]))
                self.assertEqual(checker.derive_secret(kb).hex(), v["s"])
                self.assertEqual(checker.derive_reveal_secret(kb).hex(), v["r"])
                self.assertEqual(checker.derive_blinding(kb, 0).hex(), v["b0"])
                self.assertEqual(checker.derive_note_key(kb).hex(), v["note_key"])
                self.assertEqual(checker.derive_data_key(kb).hex(), v["data_key"])
        self.assertEqual(checker.valid_key_bytes(WORDS_EXAMPLE), b"\x20" + bytes(range(32)))

    def test_words_digit_view_errors(self):
        fmt, payload, checks = checker.parse_key(WORDS_EXAMPLE)
        self.assertEqual(checks, checker.compute_checks(fmt, payload))
        # One digit or two groups changed: the check group no longer matches.
        for bad in (WORDS_EXAMPLE.replace("0722", "0723"),
                    WORDS_EXAMPLE.replace("4496 0722", "0722 4496")):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    checker.valid_key_bytes(bad)
        # 2^256 has a right check group but is no words key.
        too_large = ("0011 5792 0892 3731 6195 4235 7098 5008 6879 0785 3269 9846 6564 "
                     "0564 0394 5758 4007 9131 2963 9936")
        fmt, payload, _ = checker.parse_key(too_large + " 0000")
        self.assertFalse(checker.in_range(fmt, payload))
        full = too_large + " " + checker.compute_checks(fmt, payload)[0]
        with self.assertRaises(ValueError):
            checker.valid_key_bytes(full)
        # Other counts of digits are refused.
        for bad in ("0000 " * 20, "0000 " * 22, WORDS_EXAMPLE + " 0000"):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    checker.parse_key(bad)

    def test_key_entry_rules(self):
        for bad in ("1111 2222", "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 041a",
                    "١111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417",
                    WORDS_EXAMPLE[:-1] + "a"):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    checker.parse_key(bad)
        spaced = checker.parse_key("1111-2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417")
        self.assertEqual(spaced[0], checker.FORMAT_12)
        self.assertEqual(checker.parse_key(WORDS_EXAMPLE.replace(" ", "-", 3)),
                         checker.parse_key(WORDS_EXAMPLE))

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

    def test_salted_note_layout(self):
        # Note version 2 (section 9), field by field: version, scheme, type tag,
        # number (8), amount (12), cf (32), length (8), rule (32), salt (16),
        # then 16 zero bytes, 128 in all.
        vectors = {v["name"]: v for v in
                   checker.parse_vectors(checker.section(self.text, "Test vectors"))}
        for name, tag, amount, cf, length in (
            ("note-coin-remainder-salted", "0201", 700000000000000000, bytes(32), 0),
            ("note-data-commit-salted", "0202", 0,
             bytes.fromhex(vectors["data-commit-salted"]["content-fingerprint"]), 18),
        ):
            with self.subTest(name=name):
                v = vectors[name]
                salt = bytes.fromhex(v["salt"])
                expected = (b"\x02\x01" + bytes.fromhex(tag)
                            + int(v["index"]).to_bytes(8, "big")
                            + amount.to_bytes(12, "big") + cf + length.to_bytes(8, "big")
                            + bytes(32) + salt + bytes(16))
                self.assertEqual(len(expected), 128)
                plaintext = bytes.fromhex(v["plaintext"])
                self.assertEqual(plaintext, expected)
                self.assertEqual(plaintext[96:112], salt)
                self.assertEqual(plaintext[112:], bytes(16))
                self.assertEqual(v["kind"], "salted-note")
                self.assertEqual(v["version"], "2")
        # The leaf of each salted note is the salted commitment it carries the
        # salt of.
        self.assertEqual(vectors["note-coin-remainder-salted"]["leaf"],
                         vectors["coin-remainder-salted"]["commitment"])
        self.assertEqual(vectors["note-coin-remainder-salted"]["salt"],
                         vectors["coin-remainder-salted"]["salt"])
        self.assertEqual(vectors["note-data-commit-salted"]["leaf"],
                         vectors["data-commit-salted"]["commitment"])
        # The largest amount still fits in 12 bytes; a larger one is refused.
        top = checker.note_plaintext("COIN", 0, checker.V_MAX, bytes(32), 0, bytes(32),
                                     SALT_A, checker.NOTE_VERSION_2)
        self.assertEqual(top[12:24], b"\xff" * 12)
        with self.assertRaises(ValueError):
            checker.note_plaintext("COIN", 0, checker.V_MAX + 1, bytes(32), 0, bytes(32),
                                   SALT_A, checker.NOTE_VERSION_2)
        # A salt is required in version 2 and refused in version 1.
        with self.assertRaises(ValueError):
            checker.note_plaintext("COIN", 0, 1, bytes(32), 0, bytes(32), None,
                                   checker.NOTE_VERSION_2)
        with self.assertRaises(ValueError):
            checker.note_plaintext("COIN", 0, 1, bytes(32), 0, bytes(32), SALT_A,
                                   checker.NOTE_VERSION)
        with self.assertRaises(ValueError):
            checker.note_plaintext("COIN", 0, 1, bytes(32), 0, bytes(32), SALT_A, 3)
        # A changed salt byte is caught: the plaintext no longer matches, and
        # the salt is no longer the one of the commitment the note is stored with.
        salt = self.field("note-coin-remainder-salted", "salt")
        changed = salt[:-1] + ("1" if salt[-1] != "1" else "2")
        errors = self.run_on(self.replace_field("note-coin-remainder-salted", "salt", changed))
        self.assertTrue(any("[note-coin-remainder-salted] plaintext" in e for e in errors), errors)
        self.assertTrue(any("[note-coin-remainder-salted] salt is not that of "
                            "[coin-remainder-salted]" in e for e in errors), errors)
        # The salt written into the plaintext elsewhere is caught too.
        plaintext = self.field("note-data-commit-salted", "plaintext")
        moved = plaintext[:2 * 96] + plaintext[2 * 112:] + plaintext[2 * 96:2 * 112]
        errors = self.run_on(self.replace_field("note-data-commit-salted", "plaintext", moved))
        self.assertTrue(any("[note-data-commit-salted] plaintext" in e for e in errors), errors)
        # A salted note needs its salt.
        start = self.text.index("[note-data-commit-salted]\n")
        at = self.text.index("salt = ", start)
        end = self.text.index("\n", at) + 1
        errors = self.run_on(self.text[:at] + self.text[end:])
        self.assertTrue(any("[note-data-commit-salted] cannot be checked" in e for e in errors),
                        errors)
        # And the document must carry a salted-note vector.
        start = self.text.index("### Salted note vectors")
        errors = self.run_on(self.text[:start])
        self.assertIn("no vector of kind salted-note", errors)

    def test_note_version_must_match_type_tag(self):
        # A salted-note vector (note version 2) with a version 1 type tag.
        errors = self.run_on(self.replace_field("note-coin-remainder-salted", "type-tag", "0101"))
        self.assertTrue(any("[note-coin-remainder-salted] cannot be checked: note version 2 "
                            "needs a version 2 type tag, not 0101" in e for e in errors), errors)
        # A note vector (note version 1) with a version 2 type tag.
        errors = self.run_on(self.replace_field("note-data-commit", "type-tag", "0202"))
        self.assertTrue(any("[note-data-commit] cannot be checked: note version 1 needs a "
                            "version 1 type tag, not 0202" in e for e in errors), errors)
        # The kind fixes the note version: neither kind takes the other's.
        errors = self.run_on(self.replace_field("note-coin-remainder", "version", "2"))
        self.assertTrue(any("[note-coin-remainder] cannot be checked: kind note is note "
                            "version 1, not 2" in e for e in errors), errors)
        start = self.text.index("[note-data-commit-salted]\n")
        at = self.text.index("kind = salted-note", start)
        old = "kind = salted-note"
        errors = self.run_on(self.text[:at] + "kind = note" + self.text[at + len(old):])
        self.assertTrue(any("[note-data-commit-salted] cannot be checked: kind note is note "
                            "version 1, not 2" in e for e in errors), errors)
        # An unknown type tag version, or a type tag of another type, is refused.
        for tag in ("0301", "0203"):
            with self.subTest(tag=tag):
                errors = self.run_on(self.replace_field("note-coin-remainder-salted",
                                                        "type-tag", tag))
                self.assertTrue(any("[note-coin-remainder-salted] cannot be checked: unknown "
                                    "type tag" in e for e in errors), errors)
        errors = self.run_on(self.replace_field("note-coin-remainder-salted", "type-tag", "0202"))
        self.assertTrue(any("[note-coin-remainder-salted] cannot be checked: type tag 0202 is "
                            "DATA, not COIN" in e for e in errors), errors)
        # The type tag written into the plaintext follows the note version.
        v1 = checker.note_plaintext("DATA", 0, 0, bytes(32), 0, bytes(32))
        v2 = checker.note_plaintext("DATA", 0, 0, bytes(32), 0, bytes(32), SALT_A,
                                    checker.NOTE_VERSION_2)
        self.assertEqual((v1[:4], v2[:4]), (b"\x01\x01\x01\x02", b"\x02\x01\x02\x02"))

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
        self.assertEqual(len(checker.ALL_TAGS), 23)
        for tag in checker.ALL_TAGS:
            self.assertRegex(tag, r"^ghost/[a-z0-9-]+/v[12]$")
        v2 = sorted(t for t in checker.ALL_TAGS if t.endswith("/v2"))
        self.assertEqual(v2, ["ghost/coin-fingerprint/v2", "ghost/coin-marker/v2",
                              "ghost/data-fingerprint/v2", "ghost/data-marker/v2"])
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


SALT_A = bytes.fromhex("00112233445566778899aabbccddeeff")
SALT_B = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")


class SaltTest(unittest.TestCase):
    """Commitment format version 2: a fresh public 16-byte salt in the
    fingerprint and the marker, so one guess at a key checks one leaf."""

    def setUp(self):
        self.text = SPEC.read_text(encoding="utf-8")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.vectors = {v["name"]: v for v in
                        checker.parse_vectors(checker.section(self.text, "Test vectors"))}
        kb = checker.valid_key_bytes(self.vectors["coin-commit"]["key"])
        self.s = checker.derive_secret(kb)
        self.r = checker.derive_reveal_secret(kb)
        self.b = checker.derive_blinding(kb, 0)
        self.rule = bytes(32)

    def run_on(self, text):
        path = Path(self.tmp.name) / "spec.md"
        path.write_text(text, encoding="utf-8")
        return checker.run(path)[0]

    def coin(self, salt, version=checker.VERSION_2):
        f = checker.coin_fingerprint(self.s, self.r, self.b, self.rule, salt, version)
        c = checker.coin_commitment(f, 10**18, version)
        m = checker.marker("COIN", self.r, self.b, salt, version)
        return f, c, m

    def data(self, salt, version=checker.VERSION_2):
        cf = checker.content_fingerprint(b"Ghost example data")
        f = checker.data_fingerprint(self.s, self.r, self.b, cf, self.rule, salt, version)
        return f, checker.data_commitment(f, version), checker.marker("DATA", self.r, self.b, salt, version)

    def test_two_salts_give_unrelated_values(self):
        for make in (self.coin, self.data):
            with self.subTest(kind=make.__name__):
                a, b = make(SALT_A), make(SALT_B)
                old = make(None, checker.VERSION_1)
                for x, y, z in zip(a, b, old):
                    self.assertGreaterEqual(checker._bits_apart(x, y), checker.MIN_BITS_APART)
                    self.assertGreaterEqual(checker._bits_apart(x, z), checker.MIN_BITS_APART)
                    self.assertGreaterEqual(checker._bits_apart(y, z), checker.MIN_BITS_APART)

    def test_salt_sits_right_after_b(self):
        coin2 = bytes([0x02, 0x01])
        f = checker.keccak_tagged("ghost/coin-fingerprint/v2", self.s, self.r, self.b, SALT_A,
                                  coin2, bytes(32), self.rule)
        c = checker.keccak_tagged("ghost/coin-commitment/v1", coin2, f, (10**18).to_bytes(32, "big"))
        m = checker.keccak_tagged("ghost/coin-marker/v2", self.r, self.b, SALT_A)
        self.assertEqual(self.coin(SALT_A), (f, c, m))
        data2 = bytes([0x02, 0x02])
        cf = checker.content_fingerprint(b"Ghost example data")
        fd = checker.keccak_tagged("ghost/data-fingerprint/v2", self.s, self.r, self.b, SALT_A,
                                   data2, cf, self.rule)
        self.assertEqual(self.data(SALT_A)[0], fd)
        self.assertEqual(self.data(SALT_A)[1],
                         checker.keccak_tagged("ghost/data-commitment/v1", data2, fd))
        self.assertEqual(self.data(SALT_A)[2],
                         checker.keccak_tagged("ghost/data-marker/v2", self.r, self.b, SALT_A))

    def test_version_1_hashes_as_before(self):
        # No salt and the v1 tags: exactly the formula before the salt existed.
        coin1 = bytes([0x01, 0x01])
        f = checker.keccak_tagged("ghost/coin-fingerprint/v1", self.s, self.r, self.b, coin1,
                                  bytes(32), self.rule)
        self.assertEqual(self.coin(None, checker.VERSION_1)[0], f)
        self.assertEqual(self.coin(None, checker.VERSION_1)[2],
                         checker.keccak_tagged("ghost/coin-marker/v1", self.r, self.b))
        v = self.vectors["coin-commit"]
        self.assertEqual(self.coin(None, checker.VERSION_1)[0].hex(), v["fingerprint"])

    def test_document_vectors_match_two_salts(self):
        a, b = self.vectors["coin-commit-salted"], self.vectors["coin-commit-salted-other"]
        self.assertEqual((a["key"], a["index"], a["amount"]), (b["key"], b["index"], b["amount"]))
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertEqual(self.coin(bytes.fromhex(a["salt"]))[0].hex(), a["fingerprint"])
        self.assertEqual(self.coin(bytes.fromhex(b["salt"]))[2].hex(), b["marker"])
        self.assertEqual(checker.check_salt_pairs(list(self.vectors.values())), [])

    def test_ignoring_the_salt_is_caught(self):
        original_fp, original_marker = checker._fingerprint, checker.marker

        def fp_without_salt(type_name, s, r, b, cf, rule, salt, version):
            if version == checker.VERSION_2:
                tag = checker.VERSION_TAGS[version][type_name][0]
                return checker.keccak_tagged(tag, s, r, b, checker.type_tag(type_name, version), cf, rule)
            return original_fp(type_name, s, r, b, cf, rule, salt, version)

        with mock.patch.object(checker, "_fingerprint", fp_without_salt):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[coin-commit-salted] fingerprint" in e for e in errors), errors)
        self.assertTrue(any("[data-commit-salted-other] commitment" in e for e in errors), errors)
        self.assertFalse(any("[coin-commit] " in e for e in errors), errors)

        def marker_without_salt(type_name, r, b, salt=None, version=checker.VERSION_1):
            if version == checker.VERSION_2:
                return checker.keccak_tagged(checker.VERSION_TAGS[version][type_name][1], r, b)
            return original_marker(type_name, r, b, salt, version)

        with mock.patch.object(checker, "marker", marker_without_salt):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[coin-remainder-salted] marker" in e for e in errors), errors)
        self.assertTrue(any("[data-commit-salted] marker" in e for e in errors), errors)

    def test_salt_after_the_type_tag_is_caught(self):
        def fp_salt_moved(type_name, s, r, b, cf, rule, salt, version):
            tag = checker.VERSION_TAGS[version][type_name][0]
            parts = (salt,) if salt is not None else ()
            return checker.keccak_tagged(tag, s, r, b, checker.type_tag(type_name, version), *parts, cf, rule)

        with mock.patch.object(checker, "_fingerprint", fp_salt_moved):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[coin-commit-salted] fingerprint" in e for e in errors), errors)

    def test_v1_tags_with_salt_are_caught(self):
        # A version 2 commitment hashed under the version 1 tags must not pass.
        with mock.patch.dict(checker.VERSION_TAGS, {checker.VERSION_2: checker.VERSION_TAGS[checker.VERSION_1]}):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[coin-commit-salted] fingerprint" in e for e in errors), errors)
        self.assertTrue(any("[coin-commit-salted] marker" in e for e in errors), errors)

    def test_same_salt_twice_fails(self):
        text = self.text.replace("salt = f0e1d2c3b4a5968778695a4b3c2d1e0f",
                                 "salt = 00112233445566778899aabbccddeeff")
        errors = self.run_on(text)
        self.assertTrue(any("the same salt is used twice" in e for e in errors), errors)

    def test_equal_values_under_two_salts_fail(self):
        # A document whose second salt vector repeats the first one's values.
        a = self.vectors["coin-commit-salted"]
        text = self.text
        for field in ("fingerprint", "commitment", "marker"):
            text = text.replace(f"{field} = {self.vectors['coin-commit-salted-other'][field]}",
                                f"{field} = {a[field]}")
        errors = checker.check_salt_pairs(
            checker.parse_vectors(checker.section(text, "Test vectors")))
        for field in ("fingerprint", "commitment", "marker"):
            self.assertTrue(any(f"{field} values are not unrelated" in e for e in errors), errors)

    def test_salt_pairs_are_required(self):
        start = self.text.index("[data-commit-salted-other]")
        end = self.text.index("```", start)
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertIn("no data-commitment vectors of one secret under two salts", errors)
        start = self.text.index("### Salted commitment vectors")
        end = self.text.index("### Tree vectors")
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertTrue(any("version 2 coin commitment vectors must cover" in e for e in errors), errors)
        self.assertIn("no version 2 data commitment vector", errors)

    def test_salt_length_and_presence(self):
        for bad in (bytes(15), bytes(17), None):
            with self.subTest(salt=bad):
                with self.assertRaises(ValueError):
                    self.coin(bad)
        with self.assertRaises(ValueError):
            self.coin(SALT_A, checker.VERSION_1)
        text = self.text.replace("salt = 00112233445566778899aabbccddeeff",
                                 "salt = 00112233445566778899aabbccddee", 1)
        self.assertTrue(any("[coin-commit-salted] cannot be checked" in e
                            for e in self.run_on(text)))

    def test_unknown_version_is_rejected(self):
        for tag in (b"\x03\x01", b"\x00\x01", b"\x02\x03", b"\x02"):
            with self.subTest(tag=tag.hex()):
                with self.assertRaises(ValueError):
                    checker.read_type_tag(tag)
        self.assertEqual(checker.read_type_tag(b"\x02\x01"), (2, "COIN"))
        self.assertEqual(checker.read_type_tag(b"\x01\x02"), (1, "DATA"))
        with self.assertRaises(ValueError):
            self.coin(SALT_A, 3)
        with self.assertRaises(ValueError):
            checker.marker("COIN", self.r, self.b, SALT_A, 3)
        start = self.text.index("[coin-commit-salted]\n")
        at = self.text.index("version = 2", start)
        text = self.text[:at] + "version = 3" + self.text[at + len("version = 2"):]
        self.assertTrue(any("[coin-commit-salted] cannot be checked" in e
                            for e in self.run_on(text)))

    def test_salted_vectors_have_their_own_kind(self):
        # A coin-commitment or data-commitment vector is always version 1, so a
        # reader that knows only version 1 can take all of them.
        vectors = checker.parse_vectors(checker.section(self.text, "Test vectors"))
        for v in vectors:
            if v.get("kind") in ("coin-commitment", "data-commitment"):
                self.assertEqual(v.get("version"), "1", v["name"])
                self.assertNotIn("salt", v, v["name"])
            if v.get("kind", "").startswith("salted-"):
                self.assertEqual(v.get("version"), "2", v["name"])
        for name, kind in (("coin-commit-salted", "coin-commitment"),
                           ("data-commit-salted", "data-commitment")):
            with self.subTest(name=name):
                start = self.text.index(f"[{name}]\n")
                at = self.text.index(f"kind = salted-{kind}", start)
                old = f"kind = salted-{kind}"
                text = self.text[:at] + f"kind = {kind}" + self.text[at + len(old):]
                errors = self.run_on(text)
                self.assertTrue(any(f"[{name}] cannot be checked: kind {kind} is version 1"
                                    in e for e in errors), errors)
        start = self.text.index("[coin-commit]\n")
        at = self.text.index("kind = coin-commitment", start)
        old = "kind = coin-commitment"
        text = self.text[:at] + "kind = salted-coin-commitment" + self.text[at + len(old):]
        self.assertTrue(any("[coin-commit] cannot be checked: kind salted-coin-commitment "
                            "is version 2" in e for e in self.run_on(text)))

    def test_type_tag_is_checked(self):
        start = self.text.index("[coin-commit-salted]\n")
        at = self.text.index("type-tag = 0201", start)
        text = self.text[:at] + "type-tag = 0101" + self.text[at + len("type-tag = 0201"):]
        self.assertTrue(any("[coin-commit-salted] type-tag" in e for e in self.run_on(text)))

    def test_tag_table_sizes(self):
        body = checker.section(self.text, "Tagged hashing")
        rows = {r["Tag"]: r for r in checker._table_rows(body)}
        for tag, size in (("ghost/coin-fingerprint/v2", "204"), ("ghost/data-fingerprint/v2", "204"),
                          ("ghost/coin-marker/v2", "101"), ("ghost/data-marker/v2", "101")):
            self.assertEqual(rows[f"`{tag}`"]["Input bytes"], size)
        self.assertEqual(rows["`ghost/coin-fingerprint/v2`"]["Keccak permutations"], "2")
        self.assertEqual(rows["`ghost/coin-marker/v2`"]["Keccak permutations"], "1")
        text = self.text.replace("`salt`, `COIN`, `cf`, `rule` | 204 | 2 |",
                                 "`salt`, `COIN`, `cf`, `rule` | 188 | 2 |")
        self.assertIn("tag ghost/coin-fingerprint/v2: table says '188' input bytes, recomputed 204",
                      self.run_on(text))
        text = self.text.replace("`r`, `b`, `salt` | 101 | 1 |", "`r`, `b`, `salt` | 101 | 2 |", 1)
        self.assertIn("tag ghost/coin-marker/v2: table says '2' Keccak permutations, recomputed '1'",
                      self.run_on(text))


if __name__ == "__main__":
    unittest.main()
