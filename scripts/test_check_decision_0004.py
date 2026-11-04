"""Tests for scripts/check_decision_0004.py, against docs/decisions/0004-lookup-formats.md."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_decision_0004 as cd  # noqa: E402

RECORD = cd.DEFAULT_RECORD.read_text(encoding="utf-8")
SPEC_01 = cd.SPEC_01.read_text(encoding="utf-8")
SPEC_05 = cd.SPEC_05.read_text(encoding="utf-8")
VECTORS = cd.compute(SPEC_01, SPEC_05)


def replaced(old, new, text=RECORD):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def field(name, key):
    return dict(VECTORS[name])[key]


class Committed(unittest.TestCase):
    def test_record_agrees(self):
        self.assertEqual(cd.check_text(RECORD, SPEC_01, SPEC_05), [])

    def test_keccak(self):
        self.assertEqual(cd.self_test(), [])

    def test_same_construction_as_spec_05(self):
        self.assertEqual(cd.check_spec05_construction(SPEC_05), [])

    def test_sizes(self):
        self.assertEqual(cd.LOOKUP_LEAF_BYTES, 47)
        self.assertEqual(cd.COIN_SET_LEAF_BYTES, 74)
        self.assertEqual(cd.LOOKUP_WITNESS_BYTES, 1332)
        self.assertEqual(cd.COIN_SET_WITNESS_BYTES, 1359)

    def test_printed_blocks_are_the_record_blocks(self):
        self.assertEqual(cd.blocks(cd.render(VECTORS).join(["```text\n", "```"])), cd.blocks(RECORD))


class Mismatches(unittest.TestCase):
    def assertFails(self, text, fragment, spec05=SPEC_05):
        failures = cd.check_text(text, SPEC_01, spec05)
        self.assertTrue(failures, "expected a mismatch")
        self.assertTrue(any(fragment in f for f in failures), failures)

    def test_changed_root(self):
        root = field("coin-lookup-two-leaves", "root")
        text = RECORD.replace(f"root = {root}", f"root = {root[:-1]}0")
        self.assertFails(text, "vector coin-lookup-two-leaves")

    def test_changed_tag(self):
        old = "tag = 74c5d993f5f018e3174926b2c8e8fb68\n\n[lookup-tag-index-1]"
        self.assertFails(replaced(old, old.replace("74c5", "74c6")), "vector lookup-tag-index-0")

    def test_changed_witness(self):
        w = field("coin-lookup-absence", "witness")
        bad = w[:100] + ("1" if w[100] != "1" else "2") + w[101:]
        self.assertFails(replaced(f"witness = {w}", f"witness = {bad}"), "vector coin-lookup-absence")

    def test_missing_vector(self):
        self.assertFails(replaced("[coin-lookup-one-leaf]", "[coin-lookup-one]"),
                         "missing vector coin-lookup-one-leaf")

    def test_missing_section(self):
        self.assertFails(replaced("## Block lookup digest\n", "## Digest\n"),
                         "missing section: Block lookup digest")

    def test_section_must_name_the_ties(self):
        text = RECORD.replace("copied tag", "repeated value")
        self.assertFails(text, "does not say 'copied tag'")

    def test_header_field_order(self):
        text = replaced("| 21 | `coinMarkerRoot` |", "| 21 | `lookupDigest` |")
        text = replaced("| 22 | `lookupDigest` |", "| 22 | `coinMarkerRoot` |", text)
        self.assertFails(text, "header fields table")

    def test_header_after_spec_05(self):
        spec05 = SPEC_05.replace("| 18 | `dataMarkerRoot` |", "| 18 | `otherRoot` |")
        self.assertFails(RECORD, "field 18", spec05)

    def test_tag_table_input_bytes(self):
        self.assertFails(replaced("`nextIndex`, `appended` | 104 | 1 |", "`nextIndex`, `appended` | 103 | 1 |"),
                         "ghost/coin-marker-set-leaf/v1 input bytes")

    def test_forbidden_line(self):
        text = RECORD + "\nThe new roots are a spec" + " 08 header" + " field.\n"
        self.assertFails(text, "pairs specification 08")

    def test_spec_05_vectors_change(self):
        root = "f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f"
        spec05 = SPEC_05.replace(f"root = {root}", "root = " + "0" * 64, 1)
        self.assertTrue(cd.check_spec05_construction(spec05))


class Rules(unittest.TestCase):
    def tags(self):
        return [bytes.fromhex(field(f"lookup-tag-index-{i}", "tag")) for i in range(3)]

    def test_tag_is_first_16_bytes(self):
        k_note = bytes.fromhex(field("lookup-tag-index-0", "note-key"))
        digest, tag = cd.lookup_tag(k_note, 0)
        self.assertEqual(tag, digest[:16])
        self.assertNotEqual(cd.lookup_tag(k_note, 1)[1], tag)

    def test_copy_sorts_after_the_original(self):
        t0, t1, _ = self.tags()
        tree = cd.tree_obj_for("coin", [(t0, 0), (t1, 1), (t0, 2)])
        answer = cd.lookup_answer(tree.witness(tree.low_for_query(t0 + bytes(5))), t0, tree.root())
        self.assertEqual(answer, ("first", 0))

    def test_absence_only_for_absent_tags(self):
        t0, t1, t2 = self.tags()
        tree = cd.tree_obj_for("coin", [(t0, 0), (t1, 1)])
        root = tree.root()
        for tag, want in ((t2, ("absent", None)), (t0, ("first", 0)), (t1, ("first", 1))):
            w = tree.witness(tree.low_for_query(tag + bytes(5)))
            self.assertEqual(cd.lookup_answer(w, tag, root), want)
        w2 = tree.witness(tree.low_for_query(t2 + bytes(5)))
        self.assertIsNone(cd.lookup_answer(w2, t1, root))
        self.assertIsNone(cd.lookup_answer(w2, t2, cd.tree_obj_for("coin", [(t0, 0)]).root()))

    def test_coin_and_data_indices_differ(self):
        t0 = self.tags()[0]
        self.assertNotEqual(cd.tree_obj_for("coin", [(t0, 0)]).root(),
                            cd.tree_obj_for("data", [(t0, 0)]).root())

    def test_zero_tag_and_marker_rejected(self):
        with self.assertRaises(ValueError):
            cd.tree_obj_for("coin", [(bytes(16), 0)])
        with self.assertRaises(ValueError):
            cd.coin_set([(bytes(32), 1)])

    def test_spent_marker_leads_to_appended_leaf(self):
        m = bytes.fromhex(field("coin-marker-set-membership", "marker"))
        s = cd.coin_set([(m, 7)])
        self.assertEqual(cd.set_membership(s.witness(1), m, s.root()), 7)
        self.assertFalse(cd.set_absence(s.witness(0), m, s.root()))
        sentinel = cd.coin_set([])
        self.assertTrue(cd.set_absence(sentinel.witness(0), m, sentinel.root()))

    def test_rewritten_low_leaf_keeps_appended(self):
        a = bytes([0x10]) * 32
        b = bytes([0x20]) * 32
        s = cd.coin_set([(a, 3), (b, 4)])
        self.assertEqual(s.leaves[1][3], (3).to_bytes(5, "big"))
        self.assertEqual(s.leaves[0][3], b"\xff" * 5)

    def test_global_positions(self):
        self.assertEqual(cd.global_position(1, 0), 2**32)
        self.assertEqual(cd.global_position(255, 2**32 - 2), 2**40 - 2)
        with self.assertRaises(ValueError):
            cd.global_position(255, 2**32 - 1)
        with self.assertRaises(ValueError):
            cd.global_position(0, 2**32)

    def test_digest_encoding(self):
        body, digest = cd.lookup_digest(0, [], 0, [], [], [])
        self.assertEqual(len(body), 26)
        t = bytes(range(16))
        m = bytes(range(32))
        body, other = cd.lookup_digest(0, [t], 0, [], [m], [])
        self.assertEqual(len(body), 26 + 48)
        self.assertNotEqual(digest, other)
        # A tag moved from the coin list to the data list changes the digest.
        self.assertNotEqual(cd.lookup_digest(0, [t], 0, [], [], [])[1],
                            cd.lookup_digest(0, [], 0, [t], [], [])[1])
        # So does the position of the first leaf.
        self.assertNotEqual(cd.lookup_digest(0, [t], 0, [], [], [])[1],
                            cd.lookup_digest(1, [t], 0, [], [], [])[1])


if __name__ == "__main__":
    unittest.main()
