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


# Vector blocks of the removed unsalted format (commitment format version 1),
# in the shape the specification once carried them; the checker must refuse
# them.
V1_COIN_COMMIT = f"""[coin-commit]
kind = coin-commitment
version = 1
key = {WORDS_EXAMPLE}
index = 0
amount = 1000000000000000000
rule = {"00" * 32}
type-tag = 0101
fingerprint = adb657b17abd3d6a22f29a4d9fded4367c0c27f0b167fc5d9eccf33dfbc2ff6c
commitment = 9cadb00df6812a83ff2525fbaef0b634a020d600dc3bf3315efc3b20bfdb876c
marker = ed3aec8b2a68aa001654023dafa7bf3a187b9f3bb59940fd40389b20beda8a98
"""

V1_DATA_COMMIT = f"""[data-commit]
kind = data-commitment
version = 1
key = 0005 7669 0013 0642 8065 9560 5300 0376 8759 3842 1040 3453 0406 4124 0510 2397 3211 7841 8613 4399 8027
index = 0
content-ascii = Ghost example data
content-length = 18
rule = {"00" * 32}
type-tag = 0102
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
fingerprint = b1e44e364ce85a0f886580a51de4af3c5678d39fa9b975a0827067cca7bc4090
commitment = 5bc2c9ef3f27a49943b7885eb8babf9be3dda232a41894f3ca5a09b0129340c1
marker = f10b00e4d411afc3a56a0c1d72f49f02b8ea370ffe2430fca37596e82ae38d61
"""

V1_NOTE = f"""[note-coin-remainder]
kind = note
version = 1
type = COIN
type-tag = 0101
index = 1
amount = 700000000000000000
content-fingerprint = {"00" * 32}
content-length = 0
rule = {"00" * 32}
chain-id = 1234
leaf = 5530014e689c4a5a4b494f49a4a5be5a08a2c4d78e66128b824e5c1309c00503
plaintext = {"01010101" + "00" * 7 + "01" + "00" * 24 + "09b6e64a8ec60000" + "00" * 84}
associated-data = 00000000000004d25530014e689c4a5a4b494f49a4a5be5a08a2c4d78e66128b824e5c1309c00503
"""


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
        self.assertTrue(any("[coin-commit-salted] commitment" in e for e in errors))

    def test_broken_permutation_fails_self_test(self):
        constants = list(checker._ROUND_CONSTANTS)
        constants[5] ^= 1
        with mock.patch.object(checker, "_ROUND_CONSTANTS", constants):
            self.assertNotEqual(checker.keccak_self_test(), [])

    def test_every_changed_value_is_caught(self):
        cases = [
            ("derivation-words", "key-bytes"),
            ("derivation-words", "s"),
            ("derivation-words", "r"),
            ("derivation-words", "b1"),
            ("derivation-words", "note-key"),
            ("derivation-words", "data-key"),
            ("derivation-words-data", "b2"),
            ("derivation-words-data", "data-key"),
            ("coin-commit-salted", "fingerprint"),
            ("coin-commit-salted", "commitment"),
            ("coin-commit-salted", "marker"),
            ("coin-commit-salted-other", "commitment"),
            ("coin-remainder-salted", "marker"),
            ("coin-remainder-salted-other", "fingerprint"),
            ("data-commit-salted", "fingerprint"),
            ("data-commit-salted", "content-fingerprint"),
            ("data-commit-salted", "commitment"),
            ("data-commit-salted", "marker"),
            ("data-commit-salted-other", "marker"),
            ("empty-leaf", "leaf"),
            ("coin-tree-node", "node"),
            ("data-tree-node", "node"),
            ("note-coin-remainder-salted", "plaintext"),
            ("note-coin-remainder-salted", "associated-data"),
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
        errors = self.run_on(self.replace_field("coin-commit-salted", "amount",
                                                "1000000000000000001"))
        self.assertTrue(any("[coin-commit-salted] commitment" in e for e in errors))
        self.assertFalse(any("[coin-commit-salted] fingerprint" in e for e in errors))

    def test_checksum_errors_are_caught(self):
        # A wrong check group in a key that the document calls valid.
        key = self.field("checksum-words", "key")
        self.assertEqual(key, WORDS_EXAMPLE)
        errors = self.run_on(self.replace_field("checksum-words", "key", key[:-1] + "3"))
        self.assertTrue(any("[checksum-words] valid" in e for e in errors))
        # A wrong documented check value.
        errors = self.run_on(self.replace_field("checksum-words", "check", "6813"))
        self.assertTrue(any("[checksum-words] check" in e for e in errors))
        # A key that fails its checksum cannot be used for derivation.
        errors = self.run_on(self.replace_field("derivation-words", "key", key[:-1] + "3"))
        self.assertTrue(any("[derivation-words] cannot be checked" in e for e in errors))
        # A secret of 2^256 or more is refused even with a right check group.
        errors = self.run_on(self.replace_field("checksum-words-too-large", "valid", "yes"))
        self.assertTrue(any("[checksum-words-too-large] valid" in e for e in errors))

    def test_checksum_depends_on_format(self):
        # The words code enters the check: the same 80 digits under the codes of
        # the retired digit keys, or any other code, give another group, and
        # the checker computes no check for another code at all.
        fmt, groups, checks = checker.parse_key(WORDS_EXAMPLE)
        self.assertEqual(fmt, checker.FORMAT_WORDS)
        digits = "".join(groups).encode("ascii")
        for code in (0x0C, 0x18, 0x21):
            h = checker.sha3_tagged(checker.TAG_KEY_CHECK, bytes([code, 0x01]), digits)
            self.assertNotEqual(f"{int.from_bytes(h, 'big') % 10000:04d}", checks[0])
            with self.assertRaises(ValueError):
                checker.compute_checks(code, groups)
            with self.assertRaises(ValueError):
                checker.key_bytes(code, groups)

    def test_legacy_digit_keys_are_refused(self):
        # The twelve- and twenty-four-group digit keys are no longer read: not
        # in a vector, and not by the key reader.
        for key in ("1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417",
                    "3141 5926 5358 9793 2384 6264 3383 2795 0288 4197 1693 6390 "
                    "9937 5105 8209 7494 4592 3078 1640 6286 2089 9862 8034 8042"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    checker.parse_key(key)
                with self.assertRaises(ValueError):
                    checker.valid_key_bytes(key)
                text = self.replace_field("coin-commit-salted", "key", key)
                errors = self.run_on(text)
                self.assertTrue(any("[coin-commit-salted] cannot be checked" in e
                                    for e in errors), errors)
        # Every key in the document is a words key of 21 groups.
        keys = [v["key"] for v in checker.parse_vectors(checker.section(self.text, "Test vectors"))
                if "key" in v]
        self.assertGreaterEqual(len(keys), 10)
        for key in keys:
            self.assertEqual(len(key.split()), checker.WORDS_GROUPS, key)
        self.assertNotIn("derivation-standard", self.text)
        self.assertNotIn("checksum-long", self.text)

    def test_checksum_coverage(self):
        # Without a valid or an invalid words checksum vector, or without the
        # out-of-range one, the document is incomplete.
        for name, gap in (("checksum-words-too-large",
                           "no checksum vector of an out-of-range secret"),):
            with self.subTest(vector=name):
                text = self.replace_field(name, "kind", "other")
                self.assertTrue(any(gap in e for e in self.run_on(text)))
        text = self.text
        for name in ("checksum-one-digit-wrong", "checksum-groups-swapped",
                     "checksum-words-too-large"):
            start = text.index(f"[{name}]\n")
            line_start = text.index("\nvalid = ", start) + 1
            text = text[:line_start] + "valid = yes" + text[text.index("\n", line_start):]
        self.assertTrue(any("no checksum vector with format 20 and valid = no" in e
                            for e in self.run_on(text)))

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
        for bad in ("1111 2222", "0000 " * 12, "0000 " * 24, "١" + WORDS_EXAMPLE[1:],
                    WORDS_EXAMPLE[:-1] + "a"):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    checker.parse_key(bad)
        self.assertEqual(checker.parse_key(WORDS_EXAMPLE.replace(" ", "-", 3)),
                         checker.parse_key(WORDS_EXAMPLE))

    def test_same_blinding_every_time_is_caught(self):
        # The old design reused one remainder blinding; that must not pass.
        original = checker.derive_blinding
        with mock.patch.object(checker, "derive_blinding", lambda kb, i: original(kb, 0)):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[derivation-words] b1" in e for e in errors))
        self.assertTrue(any("[coin-remainder-salted] marker" in e for e in errors))

    def test_blindings_and_secrets_are_distinct(self):
        kb = checker.valid_key_bytes(self.field("derivation-words", "key"))
        values = [checker.derive_blinding(kb, i) for i in range(50)]
        values += [checker.derive_secret(kb), checker.derive_reveal_secret(kb),
                   checker.derive_note_key(kb), checker.derive_data_key(kb)]
        self.assertEqual(len(set(values)), len(values))

    def test_missing_vector_kind_fails(self):
        # Both tree-node vectors sit after the empty leaf in one block; drop them.
        start = self.text.index("[coin-tree-node]")
        end = self.text.index("```", start)
        self.assertNotIn("kind = tree-node", self.text[:start] + self.text[end:])
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertIn("no vector of kind tree-node", errors)

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
        # A salt is required, and note version 2 is the only one.
        with self.assertRaises(ValueError):
            checker.note_plaintext("COIN", 0, 1, bytes(32), 0, bytes(32), None,
                                   checker.NOTE_VERSION_2)
        for note_version in (1, 3):
            with self.subTest(note_version=note_version):
                with self.assertRaises(ValueError):
                    checker.note_plaintext("COIN", 0, 1, bytes(32), 0, bytes(32), SALT_A,
                                           note_version)
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
        # The kind fixes the note version: a salted-note vector is note version 2.
        errors = self.run_on(self.replace_field("note-coin-remainder-salted", "version", "1"))
        self.assertTrue(any("[note-coin-remainder-salted] cannot be checked: kind salted-note "
                            "is note version 2, not 1" in e for e in errors), errors)
        # An unknown type tag version, or a type tag of another type, is refused.
        for tag in ("0301", "0203", "0101"):
            with self.subTest(tag=tag):
                errors = self.run_on(self.replace_field("note-coin-remainder-salted",
                                                        "type-tag", tag))
                self.assertTrue(any("[note-coin-remainder-salted] cannot be checked: unknown "
                                    "type tag" in e for e in errors), errors)
        errors = self.run_on(self.replace_field("note-coin-remainder-salted", "type-tag", "0202"))
        self.assertTrue(any("[note-coin-remainder-salted] cannot be checked: type tag 0202 is "
                            "DATA, not COIN" in e for e in errors), errors)
        # The note version and the type tag written into the plaintext are
        # those of version 2, also by default.
        v2 = checker.note_plaintext("DATA", 0, 0, bytes(32), 0, bytes(32), SALT_A)
        self.assertEqual(v2[:4], b"\x02\x01\x02\x02")

    def test_missing_remainder_vector_fails(self):
        start = self.text.index("[coin-remainder-salted]\n")
        end = self.text.index("[data-commit-salted]\n", start)
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertTrue(any("index 1" in e for e in errors), errors)

    def test_tag_table_must_list_every_tag(self):
        text = self.text.replace("| `ghost/hold-binding/v1` |", "| hold binding |", 1)
        errors = self.run_on(text)
        self.assertIn("tag ghost/hold-binding/v1 is used but not listed in the tag table", errors)
        text = self.text.replace("`ghost/empty-leaf/v1`", "`ghost/empty-leaf/v2`")
        errors = self.run_on(text)
        self.assertTrue(any("ghost/empty-leaf/v2 is listed" in e for e in errors))

    def test_tags_are_distinct_ascii_with_version(self):
        self.assertEqual(len(checker.ALL_TAGS), 22)
        for tag in checker.ALL_TAGS:
            self.assertRegex(tag, r"^ghost/[a-z0-9-]+/v[12]$")
        v2 = sorted(t for t in checker.ALL_TAGS if t.endswith("/v2"))
        self.assertEqual(v2, ["ghost/coin-fingerprint/v2", "ghost/coin-marker/v2",
                              "ghost/data-fingerprint/v2", "ghost/data-marker/v2"])
        prefixes = {checker._tag_prefix(t) for t in checker.ALL_TAGS}
        self.assertEqual(len(prefixes), len(checker.ALL_TAGS))

    def test_note_tag_is_in_the_tag_list(self):
        tag = "ghost/note-tag/v1"
        self.assertEqual(checker.TAG_NOTE_TAG, tag)
        self.assertIn(tag, checker.ALL_TAGS)
        # A SHA3-256 tag: no Keccak layout or permutation count.
        self.assertNotIn(tag, checker.TAG_LAYOUTS)
        body = checker.section(self.text, "Tagged hashing")
        rows = {r["Tag"]: r for r in checker._table_rows(body)}
        row = rows[f"`{tag}`"]
        self.assertEqual(row["Hash"], "SHA3-256")
        self.assertEqual(row["Inputs after the tag"], "`k_note`, `i` as 8 bytes")
        self.assertEqual(row["Input bytes"], str(len(checker._tag_prefix(tag)) + 32 + 8))
        self.assertEqual(row["Input bytes"], "58")
        # Without its row, the tag table is incomplete.
        text = self.text.replace(f"| `{tag}` |", "| note tag |", 1)
        text = text.replace(f"`{tag}` takes", "The note tag takes", 1)
        self.assertIn(f"tag {tag} is used but not listed in the tag table", self.run_on(text))

    def test_note_tag_vectors_required(self):
        vectors = {v["name"]: v for v in
                   checker.parse_vectors(checker.section(self.text, "Test vectors"))}
        kb = bytes.fromhex(vectors["derivation-words"]["key-bytes"])
        for index in (0, 1):
            v = vectors[f"note-tag-index-{index}"]
            self.assertEqual(v["kind"], "note-tag")
            self.assertEqual(v["key-bytes"], kb.hex())
            # An independent recomputation: k_note, then the tag over it.
            note_key = hashlib.sha3_256(b"\x11ghost/note-key/v1" + kb).digest()
            self.assertEqual(note_key.hex(), vectors["derivation-words"]["note-key"])
            digest = hashlib.sha3_256(b"\x11ghost/note-tag/v1" + note_key
                                      + index.to_bytes(8, "big")).digest()
            self.assertEqual(v["digest"], digest.hex())
            self.assertEqual(v["tag"], digest[:3].hex())
        self.assertEqual([(vectors[f"bucket-rule-{n}"]["notes"], vectors[f"bucket-rule-{n}"]["bits"])
                          for n in range(6)],
                         [("0", "0"), ("8191", "0"), ("8192", "1"), ("1048576", "8"),
                          ("3650000000", "19"), ("1099511627776", "24")])
        # A changed tag, digest, index or rule is caught.
        for vector, name in (("note-tag-index-0", "tag"), ("note-tag-index-1", "tag"),
                             ("note-tag-index-1", "digest")):
            with self.subTest(vector=vector, field=name):
                text = self.replace_field(vector, name, _flip_hex(self.field(vector, name)))
                self.assertTrue(any(f"[{vector}] {name}" in e for e in self.run_on(text)))
        errors = self.run_on(self.replace_field("note-tag-index-1", "index", "2"))
        self.assertTrue(any("[note-tag-index-1] digest" in e for e in errors), errors)
        for vector, bits in (("bucket-rule-2", "0"), ("bucket-rule-4", "20"), ("bucket-rule-5", "28")):
            with self.subTest(vector=vector):
                errors = self.run_on(self.replace_field(vector, "bits", bits))
                self.assertTrue(any(f"[{vector}] bits" in e for e in errors), errors)
        # A tag over the key bytes in place of k_note is caught.
        with mock.patch.object(checker, "derive_note_key", lambda kb: kb):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[note-tag-index-0] digest" in e for e in errors), errors)
        # The rule without its clamp at 24 bits is caught.
        with mock.patch.object(checker, "MAX_BUCKET_BITS", 64):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[bucket-rule-5] bits" in e for e in errors), errors)
        # Without the vectors of a kind, the document is incomplete.
        start = self.text.index("### Note tag and bucket vectors")
        end = self.text.index("### Salted commitment vectors")
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertIn("no vector of kind note-tag", errors)
        self.assertIn("no vector of kind bucket-rule", errors)
        for kind in ("note-tag", "bucket-rule"):
            with self.subTest(kind=kind):
                text = self.text.replace(f"kind = {kind}\n", "kind = other\n")
                self.assertIn(f"no vector of kind {kind}", self.run_on(text))
        # Both numbers and both ends of the rule must be covered.
        start = self.text.index("[note-tag-index-1]")
        end = self.text.index("[bucket-rule-0]")
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertIn("note-tag vectors must cover index 0 and index 1", errors)
        start = self.text.index("[bucket-rule-5]")
        end = self.text.index("```", start)
        errors = self.run_on(self.text[:start] + self.text[end:])
        self.assertIn("bucket-rule vectors must cover 0 bits and the clamp at 24", errors)
        # Key bytes that are not a words key's are refused.
        errors = self.run_on(self.replace_field("note-tag-index-0", "key-bytes", "21" + kb.hex()[2:]))
        self.assertTrue(any("[note-tag-index-0] cannot be checked" in e for e in errors), errors)

    def test_version_1_vectors_are_refused(self):
        # A block of an old unsalted kind is an unknown kind, not a vector the
        # checker still recomputes.
        for name, block, kind in (("coin-commit", V1_COIN_COMMIT, "coin-commitment"),
                                  ("data-commit", V1_DATA_COMMIT, "data-commitment"),
                                  ("note-coin-remainder", V1_NOTE, "note")):
            with self.subTest(kind=kind):
                at = self.text.index("### Tree vectors")
                text = self.text[:at] + "```text\n" + block + "```\n\n" + self.text[at:]
                errors = self.run_on(text)
                self.assertIn(f"[{name}] unknown kind {kind!r}", errors)
        # A version 1 type tag in a salted vector is refused, never read as
        # another version.
        errors = self.run_on(self.replace_field("coin-commit-salted", "type-tag", "0101"))
        self.assertTrue(any("[coin-commit-salted] type-tag: document has '0101'" in e
                            for e in errors), errors)
        errors = self.run_on(self.replace_field("note-data-commit-salted", "type-tag", "0102"))
        self.assertTrue(any("[note-data-commit-salted] cannot be checked: unknown type tag 0102"
                            in e for e in errors), errors)
        for tag in (b"\x01\x01", b"\x01\x02"):
            with self.subTest(tag=tag.hex()):
                with self.assertRaises(ValueError):
                    checker.read_type_tag(tag)
        # Nothing hashes under version 1: no type tag, fingerprint or marker.
        kb = checker.valid_key_bytes(WORDS_EXAMPLE)
        r, b = checker.derive_reveal_secret(kb), checker.derive_blinding(kb, 0)
        for call in (lambda: checker.type_tag("COIN", 1),
                     lambda: checker.marker("COIN", r, b, None, 1),
                     lambda: checker.marker("DATA", r, b, SALT_A, 1),
                     lambda: checker.coin_fingerprint(r, r, b, bytes(32), None, 1)):
            with self.assertRaises(ValueError):
                call()
        self.assertFalse(hasattr(checker, "VERSION_1"))
        # The unsalted tags are not in the table, and listing one is refused.
        for tag in ("ghost/coin-fingerprint/v1", "ghost/data-fingerprint/v1",
                    "ghost/coin-marker/v1", "ghost/data-marker/v1"):
            with self.subTest(tag=tag):
                self.assertNotIn(tag, checker.ALL_TAGS)
                self.assertNotIn(f"`{tag}`", self.text)
                row = "| `ghost/empty-leaf/v1` |"
                text = self.text.replace(row, f"| `{tag}` | Keccak-256 | old | `r`, `b` "
                                              f"| 85 | 1 |\n" + row, 1)
                self.assertIn(f"tag {tag} is listed but not known to this checker",
                              self.run_on(text))

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
        kb = checker.valid_key_bytes(self.vectors["coin-commit-salted"]["key"])
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
                for x, y in zip(a, b):
                    self.assertGreaterEqual(checker._bits_apart(x, y), checker.MIN_BITS_APART)

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
        reserve = (250_000_000_000_000_000).to_bytes(32, "big")
        self.assertEqual(self.data(SALT_A)[1],
                         checker.keccak_tagged("ghost/data-commitment/v1", data2, reserve, fd))
        self.assertEqual(self.data(SALT_A)[2],
                         checker.keccak_tagged("ghost/data-marker/v2", self.r, self.b, SALT_A))

    def test_version_2_is_the_default(self):
        # The functions take version 2 when no version is given.
        f = checker.coin_fingerprint(self.s, self.r, self.b, self.rule, SALT_A)
        self.assertEqual(f, self.coin(SALT_A)[0])
        self.assertEqual(checker.coin_commitment(f, 10**18), self.coin(SALT_A)[1])
        self.assertEqual(checker.marker("COIN", self.r, self.b, SALT_A), self.coin(SALT_A)[2])
        self.assertEqual(f.hex(), self.vectors["coin-commit-salted"]["fingerprint"])
        self.assertEqual(checker.type_tag("DATA", checker.VERSION_2), b"\x02\x02")

    def test_document_vectors_match_two_salts(self):
        a, b = self.vectors["coin-commit-salted"], self.vectors["coin-commit-salted-other"]
        self.assertEqual((a["key"], a["index"], a["amount"]), (b["key"], b["index"], b["amount"]))
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertEqual(self.coin(bytes.fromhex(a["salt"]))[0].hex(), a["fingerprint"])
        self.assertEqual(self.coin(bytes.fromhex(b["salt"]))[2].hex(), b["marker"])
        self.assertEqual(checker.check_salt_pairs(list(self.vectors.values())), [])

    def test_ignoring_the_salt_is_caught(self):
        def fp_without_salt(type_name, s, r, b, cf, rule, salt, version):
            tag = checker.VERSION_TAGS[version][type_name][0]
            return checker.keccak_tagged(tag, s, r, b, checker.type_tag(type_name, version), cf, rule)

        with mock.patch.object(checker, "_fingerprint", fp_without_salt):
            errors = checker.run(SPEC)[0]
        self.assertTrue(any("[coin-commit-salted] fingerprint" in e for e in errors), errors)
        self.assertTrue(any("[data-commit-salted-other] commitment" in e for e in errors), errors)

        def marker_without_salt(type_name, r, b, salt=None, version=checker.VERSION_2):
            return checker.keccak_tagged(checker.VERSION_TAGS[version][type_name][1], r, b)

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
        # A commitment hashed under the removed unsalted tags must not pass.
        old_tags = {"COIN": ("ghost/coin-fingerprint/v1", "ghost/coin-marker/v1"),
                    "DATA": ("ghost/data-fingerprint/v1", "ghost/data-marker/v1")}
        with mock.patch.dict(checker.VERSION_TAGS, {checker.VERSION_2: old_tags}):
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
            self.coin(SALT_A, 1)
        text = self.text.replace("salt = 00112233445566778899aabbccddeeff",
                                 "salt = 00112233445566778899aabbccddee", 1)
        self.assertTrue(any("[coin-commit-salted] cannot be checked" in e
                            for e in self.run_on(text)))

    def test_unknown_version_is_rejected(self):
        for tag in (b"\x03\x01", b"\x00\x01", b"\x02\x03", b"\x02", b"\x01\x01", b"\x01\x02"):
            with self.subTest(tag=tag.hex()):
                with self.assertRaises(ValueError):
                    checker.read_type_tag(tag)
        self.assertEqual(checker.read_type_tag(b"\x02\x01"), (2, "COIN"))
        self.assertEqual(checker.read_type_tag(b"\x02\x02"), (2, "DATA"))
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
        # Every commitment and note vector is of a salted kind, at version 2
        # and with a salt; a salted vector relabelled with an old kind is refused.
        vectors = checker.parse_vectors(checker.section(self.text, "Test vectors"))
        salted = [v for v in vectors if "salt" in v]
        self.assertEqual(len(salted), 8)
        for v in vectors:
            if v.get("kind", "").startswith("salted-") or "salt" in v:
                self.assertTrue(v["kind"].startswith("salted-"), v["name"])
                self.assertEqual(v.get("version"), "2", v["name"])
                self.assertIn("salt", v, v["name"])
        for name, kind in (("coin-commit-salted", "coin-commitment"),
                           ("data-commit-salted", "data-commitment")):
            with self.subTest(name=name):
                start = self.text.index(f"[{name}]\n")
                at = self.text.index(f"kind = salted-{kind}", start)
                old = f"kind = salted-{kind}"
                text = self.text[:at] + f"kind = {kind}" + self.text[at + len(old):]
                self.assertIn(f"[{name}] unknown kind {kind!r}", self.run_on(text))
        start = self.text.index("[coin-commit-salted]\n")
        at = self.text.index("version = 2", start)
        text = self.text[:at] + "version = 1" + self.text[at + len("version = 2"):]
        self.assertTrue(any("[coin-commit-salted] cannot be checked: kind "
                            "salted-coin-commitment is version 2, not 1" in e
                            for e in self.run_on(text)))

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
        # The data commitment counts the reserve word: 91 bytes, not the 59
        # of the outer hash without it.
        self.assertEqual(rows["`ghost/data-commitment/v1`"]["Input bytes"], "91")
        text = self.text.replace("`DATA`, `DATA_RESERVE`, `F_d` | 91 | 1 |", "`DATA`, `F_d` | 59 | 1 |")
        self.assertIn("tag ghost/data-commitment/v1: table says '59' input bytes, recomputed 91",
                      self.run_on(text))

    def test_marker_set_tags_are_listed(self):
        leaf, node = "ghost/data-marker-set-leaf/v1", "ghost/data-marker-set-node/v1"
        self.assertIn(leaf, checker.ALL_TAGS)
        self.assertIn(node, checker.ALL_TAGS)
        self.assertEqual(checker.TAG_LAYOUTS[leaf], (32, 32, 5))
        self.assertEqual(checker.TAG_LAYOUTS[node], (1, 32, 32))
        body = checker.section(self.text, "Tagged hashing")
        rows = {r["Tag"]: r for r in checker._table_rows(body)}
        self.assertEqual((rows[f"`{leaf}`"]["Input bytes"], rows[f"`{leaf}`"]["Keccak permutations"]),
                         ("99", "1"))
        self.assertEqual((rows[f"`{node}`"]["Input bytes"], rows[f"`{node}`"]["Keccak permutations"]),
                         ("95", "1 per level"))
        # A missing row, a wrong size and a wrong permutation count are caught.
        for tag in (leaf, node):
            with self.subTest(tag=tag):
                text = self.text.replace(f"| `{tag}` |", "| marker set |", 1)
                self.assertIn(f"tag {tag} is used but not listed in the tag table", self.run_on(text))
        text = self.text.replace("`nextIndex` as 5 bytes | 99 | 1 |", "`nextIndex` as 8 bytes | 102 | 1 |")
        self.assertIn(f"tag {leaf}: table says '102' input bytes, recomputed 99", self.run_on(text))
        row = f"| `{node}` |"
        start = self.text.index(row)
        end = self.text.index("\n", start)
        text = self.text[:start] + self.text[start:end].replace("| 95 | 1 per level |", "| 95 | 1 |") + \
            self.text[end:]
        self.assertIn(f"tag {node}: table says '1' Keccak permutations, recomputed '1 per level'",
                      self.run_on(text))

    def test_data_commitment_without_the_reserve_is_caught(self):
        # The data vectors are computed with DATA_RESERVE in the outer hash;
        # a checker that leaves it out finds every data commitment wrong.
        self.assertEqual(checker.DATA_RESERVE, 250_000_000_000_000_000)

        def without_reserve(fingerprint, version=checker.VERSION_2):
            return checker.keccak_tagged(checker.TAG_DATA_COMMITMENT, checker.type_tag("DATA", version),
                                         fingerprint)

        def other_reserve(fingerprint, version=checker.VERSION_2):
            return checker.keccak_tagged(checker.TAG_DATA_COMMITMENT, checker.type_tag("DATA", version),
                                         (checker.DATA_RESERVE + 1).to_bytes(32, "big"), fingerprint)

        for wrong in (without_reserve, other_reserve):
            with self.subTest(wrong=wrong.__name__), mock.patch.object(checker, "data_commitment", wrong):
                errors = checker.run(SPEC)[0]
                self.assertTrue(any("[data-commit-salted] commitment" in e for e in errors), errors)
                self.assertTrue(any("[data-commit-salted-other] commitment" in e for e in errors), errors)
        self.assertEqual(checker.run(SPEC)[0], [])


if __name__ == "__main__":
    unittest.main()
