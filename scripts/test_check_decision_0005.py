"""Tests for scripts/check_decision_0005.py, against docs/decisions/0005-header-mmr.md."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_decision_0005 as cd  # noqa: E402

RECORD = cd.DEFAULT_RECORD.read_text(encoding="utf-8")
SPEC_05 = cd.SPEC_05.read_text(encoding="utf-8")
D0004 = cd.DECISION_0004.read_text(encoding="utf-8")
VECTORS = cd.compute(SPEC_05)


def replaced(old, new, text=RECORD):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def field(name, key):
    return dict(VECTORS[name])[key]


def example_leaves(n):
    return {i: (bytes([i % 251 + 1]) * 32, cd.D_START + 4096 * i) for i in range(n)}


class Committed(unittest.TestCase):
    def test_record_agrees(self):
        self.assertEqual(cd.check_text(RECORD, SPEC_05, D0004), [])

    def test_keccak(self):
        self.assertEqual(cd.d4.self_test(), [])

    def test_rlp_encoder_gives_spec_05(self):
        self.assertEqual(cd.check_rlp_against_spec05(SPEC_05), [])

    def test_printed_blocks_are_the_record_blocks(self):
        self.assertEqual(cd.blocks(cd.render(VECTORS).join(["```text\n", "```"])), cd.blocks(RECORD))

    def test_sizes(self):
        self.assertEqual(cd.ENTRY_BYTES, 48)
        self.assertEqual(cd.WORK_BYTES, 16)
        self.assertEqual(cd.FIVE_YEARS, 5_256_000)
        self.assertEqual({t: len(cd.tagbytes(t)) + n for t, n in cd.TAG_ROWS.items()},
                         {cd.TAG_LEAF: 73, cd.TAG_NODE: 121, cd.TAG_BAG: 120, cd.TAG_ROOT: 81})

    def test_five_year_path_is_in_the_record(self):
        rows = dict(cd.blocks(RECORD)["header-mmr-path-five-years-genesis"])
        self.assertEqual(rows["n"], "5256000")
        self.assertEqual(rows["entries"], "23")
        self.assertEqual(len(bytes.fromhex(rows["path"])), 1104)

    def test_header_sizes(self):
        self.assertEqual(cd.header_sizes(SPEC_05),
                         {"block-one-18": 582, "block-one-19": 615, "block-one-23": 747,
                          "block-one-24": 780, "genesis-23": 776, "genesis-24": 809})
        # 582 bytes, plus dataMarkerRoot, plus five fields of 33 encoded bytes.
        self.assertEqual(582 + 33 + 5 * 33, 780)


class Mismatches(unittest.TestCase):
    def assertFails(self, text, fragment, spec05=SPEC_05, d0004=D0004):
        failures = cd.check_text(text, spec05, d0004)
        self.assertTrue(failures, "expected a mismatch")
        self.assertTrue(any(fragment in f for f in failures), failures)

    def test_changed_root(self):
        root = field("header-mmr-five-years", "root")
        text = RECORD.replace(f"root = {root}", f"root = {root[:-1]}0")
        self.assertFails(text, "vector header-mmr-five-years")

    def test_changed_path(self):
        p = field("header-mmr-path-five-years-genesis", "path")
        bad = p[:500] + ("1" if p[500] != "1" else "2") + p[501:]
        self.assertFails(replaced(f"path = {p}", f"path = {bad}"), "vector header-mmr-path-five-years-genesis")

    def test_changed_work_before(self):
        self.assertFails(replaced("work-before = 70464307200000", "work-before = 70464307200001"),
                         "vector header-mmr-path-five-years-middle")

    def test_missing_five_year_path(self):
        self.assertFails(replaced("[header-mmr-path-five-years-genesis]", "[header-mmr-path-genesis]"),
                         "missing vector header-mmr-path-five-years-genesis")

    def test_missing_section(self):
        self.assertFails(replaced("## Cumulative work\n", "## Work\n"), "missing section: Cumulative work")

    def test_section_must_name_the_overflow_rule(self):
        self.assertFails(RECORD.replace("work-overflow", "too-much-work"), "does not say 'work-overflow'")

    def test_header_field_index(self):
        self.assertFails(replaced("| 23 | `headerMmrRoot` |", "| 24 | `headerMmrRoot` |"), "header field table")

    def test_header_size_table(self):
        self.assertFails(replaced("with `headerMmrRoot` | 780 |", "with `headerMmrRoot` | 779 |"),
                         "header size table: block-one-24")

    def test_tag_table_input_bytes(self):
        self.assertFails(replaced("right hash, right work | 121 |", "right hash, right work | 120 |"),
                         "ghost/header-mmr-node/v1 input bytes")

    def test_forbidden_spec_08_line(self):
        text = RECORD + "\nThe new root is a spec" + " 08 header" + " field.\n"
        self.assertFails(text, "pairs specification 08")

    def test_modeled_header_size_line(self):
        text = RECORD + "\nA header is 7" + "42 bytes.\n"
        self.assertFails(text, "modeled header size")

    def test_spec_05_last_field(self):
        spec05 = SPEC_05.replace("| 22 | `lookupDigest` |", "| 22 | `otherDigest` |")
        self.assertFails(RECORD, "lookupDigest as field 22", spec05)

    def test_spec_05_vectors_change(self):
        h = field("header-mmr-leaf-genesis", "header-hash")
        self.assertTrue(h)
        spec05 = SPEC_05.replace("gasLimit = 30000000", "gasLimit = 30000001", 1)
        self.assertTrue(cd.check_rlp_against_spec05(spec05))
        self.assertFails(RECORD, "RLP encoder", spec05)

    def test_decision_0004_last_field(self):
        d0004 = D0004.replace("| 22 | `lookupDigest` |", "| 22 | `otherDigest` |")
        self.assertFails(RECORD, "decision 0004's last header field", d0004=d0004)


class Rules(unittest.TestCase):
    def test_peaks(self):
        self.assertEqual(cd.peaks(7), [(0, 2), (4, 1), (6, 0)])
        self.assertEqual([h for _s, h in cd.peaks(cd.FIVE_YEARS)], [22, 20, 13, 12, 9, 8, 6])
        self.assertEqual(cd.peaks(0), [])

    def test_every_path_folds_to_the_root(self):
        for n in range(1, 18):
            leaves = example_leaves(n)
            m = cd.Mmr(n, leaves)
            root = m.root()
            for i in range(n):
                path = cd.encode_path(m.path(i))
                got = cd.verify_path(path, n, i, *leaves[i], root)
                want = (sum(leaves[x][1] for x in range(i)), sum(d for _h, d in leaves.values()))
                self.assertEqual(got, want, (n, i))
                if n > 1:
                    other = (i + 1) % n
                    self.assertIsNone(cd.verify_path(path, n, other, *leaves[i], root), (n, i))

    def test_path_length_bound(self):
        for n in list(range(1, 600)) + [cd.ONE_YEAR, cd.FIVE_YEARS, 2**40 - 1]:
            most = max(cd.path_shape(n, s)[3] for s, _h in cd.peaks(n))
            self.assertLessEqual(most, n.bit_length(), n)

    def test_filler_gives_the_same_root(self):
        filler = (bytes([0xEE]) * 32, cd.D_START)
        special = {0: (bytes([1]) * 32, 5), 9: (bytes([2]) * 32, 7)}
        full = {i: special.get(i, filler) for i in range(13)}
        self.assertEqual(cd.Mmr(13, special, filler).root(), cd.Mmr(13, full).root())
        self.assertEqual(cd.Mmr(13, special, filler).path(9), cd.Mmr(13, full).path(9))

    def test_root_binds_the_leaf_count(self):
        bag = (bytes([3]) * 32, 10)
        self.assertNotEqual(cd.root_of(4, bag), cd.root_of(5, bag))

    def test_bag_is_right_to_left(self):
        m = cd.Mmr(7, example_leaves(7))
        p = m.peak_nodes()
        self.assertEqual(m.bagged(), cd.bag(p[0], cd.bag(p[1], p[2])))
        self.assertNotEqual(m.bagged(), cd.bag(cd.bag(p[0], p[1]), p[2]))

    def test_work_is_bound(self):
        leaves = example_leaves(4)
        m = cd.Mmr(4, leaves)
        entries = m.path(1)
        entries[0] = (entries[0][0], entries[0][1] + 1)
        self.assertIsNone(cd.verify_path(cd.encode_path(entries), 4, 1, *leaves[1], m.root()))

    def test_work_overflow(self):
        with self.assertRaises(ValueError):
            cd.leaf(bytes(32), 2**128)
        big = cd.leaf(bytes([1]) * 32, 2**127)
        with self.assertRaises(ValueError):
            cd.node(big, big)
        with self.assertRaises(ValueError):
            cd.bag(big, big)
        leaves = {0: (bytes([1]) * 32, 2**127), 1: (bytes([2]) * 32, 2**127)}
        m = cd.Mmr(1, {0: leaves[0]})
        path = cd.encode_path([(bytes([9]) * 32, 2**127)])
        self.assertIsNone(cd.verify_path(path, 2, 0, *leaves[0], m.root()))

    def test_index_must_be_below_the_count(self):
        m = cd.Mmr(3, example_leaves(3))
        path = cd.encode_path(m.path(2))
        self.assertIsNone(cd.verify_path(path, 3, 3, *example_leaves(3)[2], m.root()))
        self.assertIsNone(cd.verify_path(b"", 0, 0, bytes(32), 1, m.root()))

    def test_header_field_23(self):
        ex = cd.example_headers(SPEC_05)
        g24, _g_rlp, g_hash, _d = ex["genesis"]
        b24 = ex["one"][0]
        self.assertEqual(len(g24), 24)
        self.assertEqual(g24[-1], ("headerMmrRoot", cd.root_of(0, cd.EMPTY_BAG).hex()))
        self.assertEqual(dict(b24)["parentHash"], g_hash.hex())
        self.assertEqual(dict(b24)["headerMmrRoot"], ex["mmr-one"].root().hex())
        self.assertEqual([f for f, _v in g24[:23]], [f for f, _v in cd.header_fields(SPEC_05, "header-genesis-example")])

    def test_five_year_work(self):
        m = cd.five_year_mmr(SPEC_05)
        self.assertEqual(m.bagged()[1], m.work_before(m.n))
        self.assertEqual(m.bagged()[1], (cd.FIVE_YEARS + 4) * cd.D_START)


if __name__ == "__main__":
    unittest.main()
