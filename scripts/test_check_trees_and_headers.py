"""Tests for check_trees_and_headers.py: it passes on the specification and
fails when a section, a parameter, a table, the header layout, the genesis
list, a tree, rollover or header vector, the encoder's output, a requirement,
the recovery test, a conflict or a tag is damaged. It also checks that the
separately written encoder agrees with the checker's own RLP code and stays
separate from it."""

import importlib.util
import random
import re
import shutil
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC_DIR = HERE.parent / "docs" / "spec"
SPEC = SPEC_DIR / "05-trees-and-headers.md"
SPEC01 = SPEC_DIR / "01-commitments-and-keys.md"
SPEC06 = SPEC_DIR / "06-consensus-and-emission.md"
ENCODER = HERE / "header_golden_encoder.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load("check_trees_and_headers", HERE / "check_trees_and_headers.py")
encoder = _load("header_golden_encoder", ENCODER)
ENCODER_VECTORS = checker.load_encoder_vectors()


class CheckerTest(unittest.TestCase):
    def setUp(self):
        self.text = SPEC.read_text(encoding="utf-8")
        self.spec01 = SPEC01.read_text(encoding="utf-8")
        self.spec06 = SPEC06.read_text(encoding="utf-8")

    def errors(self, text, spec01=None, spec06=None, vectors=ENCODER_VECTORS):
        return checker.check_text(text, self.spec01 if spec01 is None else spec01,
                                  self.spec06 if spec06 is None else spec06, vectors)

    def damaged(self, old, new, count=1):
        self.assertIn(old, self.text)
        return self.text.replace(old, new, count)

    def in_block(self, name, old, new):
        """Replace `old` inside the vector block `[name]` only."""
        start = self.text.index(f"[{name}]\n")
        end = min(i for i in (self.text.find("\n\n", start), self.text.find("```", start)) if i > 0)
        at = self.text.index(old, start)
        self.assertLess(at, end, f"'{old}' is not in [{name}]")
        return self.text[:at] + new + self.text[at + len(old):]

    def assert_gap(self, text, fragment, **kw):
        errors = self.errors(text, **kw)
        self.assertTrue(any(fragment in e for e in errors), f"no '{fragment}' in {errors}")

    # -- the whole document ------------------------------------------------

    def test_specification_passes(self):
        self.assertEqual(self.errors(self.text), [])
        self.assertEqual(checker.main(["x", str(SPEC)]), 0)

    def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertNotEqual(checker.main(["x", str(Path(tmp) / "absent.md")]), 0)

    def test_missing_sibling_chapters_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "05.md"
            path.write_text(self.text, encoding="utf-8")
            self.assertNotEqual(checker.main(["x", str(path)]), 0)
            shutil.copy(SPEC01, Path(tmp) / SPEC01.name)
            self.assertNotEqual(checker.main(["x", str(path)]), 0)
            shutil.copy(SPEC06, Path(tmp) / SPEC06.name)
            self.assertEqual(checker.main(["x", str(path)]), 0)

    def test_required_sections(self):
        for word in checker.REQUIRED_SECTIONS:
            with self.subTest(word=word):
                m = re.search(rf"^## (\d+)\. [^\n]*{re.escape(word)}[^\n]*$", self.text, re.M)
                self.assertIsNotNone(m, word)
                text = self.text[:m.start()] + f"## {m.group(1)}. Elsewhere" + self.text[m.end():]
                self.assert_gap(text, f"contains '{word}'")

    def test_section_numbering(self):
        self.assert_gap(self.damaged("## 6. Markers", "## 16. Markers"), "sections are numbered")
        self.assert_gap(self.damaged("## 6. Markers", "## Markers"), "is not numbered")

    def test_section_subjects(self):
        for word, phrases in checker.SECTION_WORDS.items():
            for phrase in phrases:
                with self.subTest(word=word, phrase=phrase):
                    m = re.search(rf"^## \d+\. [^\n]*{re.escape(word)}", self.text, re.M)
                    end = self.text.find("\n## ", m.end())
                    body = self.text[m.end():end]
                    flat = re.sub(re.escape(phrase), "x", body, flags=re.I)
                    # Phrases may wrap; remove every occurrence across line ends too.
                    pattern = r"\s+".join(re.escape(part) for part in phrase.split())
                    flat = re.sub(pattern, "x", flat, flags=re.I)
                    text = self.text[:m.end()] + flat + self.text[end:]
                    self.assert_gap(text, f"section '{word}' does not mention '{phrase}'")

    # -- targets and tables ------------------------------------------------

    def test_depth_target(self):
        self.assert_gap(self.damaged("| `TREE_DEPTH` | 32 |", "| `TREE_DEPTH` | 31 |"),
                        "TREE_DEPTH is 31; the target is 32")
        self.assert_gap(self.damaged("| `LEAVES_PER_TREE` | 4294967296 |",
                                     "| `LEAVES_PER_TREE` | 2147483648 |"),
                        "LEAVES_PER_TREE is 2147483648")

    def test_parameter_missing(self):
        self.assert_gap(self.damaged("| `MARKER_BYTES` | 32 |", "| `OTHER_BYTES` | 32 |"),
                        "parameters missing: ['MARKER_BYTES']")

    def test_note_size_follows_spec_01(self):
        self.assert_gap(self.damaged("| `NOTE_BYTES` | 156 |", "| `NOTE_BYTES` | 128 |"),
                        "NOTE_BYTES is 128, spec 01 says 156")
        self.assert_gap(self.text, "spec 01 states no note length",
                        spec01=self.spec01.replace("**On the chain: 156 bytes, fixed.**", ""))

    def test_page_size(self):
        self.assert_gap(self.damaged("| `PAGE_LEAVES` | 4096 |", "| `PAGE_LEAVES` | 4000 |"),
                        "PAGE_LEAVES 4000 is not a power of two")
        self.assert_gap(self.damaged("| `PAGE_LEAVES` | 4096 |", "| `PAGE_LEAVES` | 2048 |"),
                        "page table has no row for PAGE_LEAVES = 2048")

    def test_page_table(self):
        self.assert_gap(self.damaged("| 4096 | 770048 |", "| 4096 | 770049 |"),
                        "page table row for 4096 leaves")

    def test_storage_table(self):
        self.assert_gap(self.damaged("| Notes | 4294967296 | 156 | 670014898176 |",
                                     "| Notes | 4294967296 | 128 | 549755813888 |"),
                        "storage row 'Notes' says 4294967296 x 128")
        self.assert_gap(self.damaged("| Total | | | 944926359552 |", "| Total | | | 944926359553 |"),
                        "storage table total is 944926359553")
        self.assert_gap(self.damaged("| Page roots | 1048576 | 32 | 33554432 |\n", ""),
                        "storage table has no row 'Page roots'")

    # -- header layout -----------------------------------------------------

    def test_header_field_order(self):
        text = self.damaged("| 16 | `coinTreeRoot` |", "| 16 | `dataTreeRootX` |")
        self.assert_gap(text, "header fields are")
        text = self.damaged("| 8 | `number` | integer below 2^64 | base |\n| 9 | `gasLimit` |",
                            "| 8 | `gasLimit` | integer below 2^64 | base |\n| 9 | `number` |")
        self.assert_gap(text, "header fields are")

    def test_no_third_header_field(self):
        row = "| 17 | `dataTreeRoot` | 32 bytes | Ghost |\n"
        text = self.damaged(row, row + "| 18 | `spentMarkerRoot` | 32 bytes | Ghost |\n")
        self.assert_gap(text, "no spent-marker-set root may be added")
        self.assert_gap(text, "header fields are")

    def test_base_fee_required(self):
        text = self.damaged("| `baseFee` | integer below 2^256 | base, required |",
                            "| `baseFee` | integer below 2^256 | base, optional |")
        self.assert_gap(text, "the base fee is not marked required")
        self.assert_gap(text, "'baseFee' is optional")

    def test_field_encoding(self):
        self.assert_gap(self.damaged("| 14 | `nonce` | 8 bytes |", "| 14 | `nonce` | 16 bytes |"),
                        "header field 'nonce' encoding '16 bytes'")

    def test_forbidden_fields(self):
        self.assert_gap(self.damaged("| `excessBlobGas` | `ExcessBlobGas` |\n", ""),
                        "forbidden field 'excessBlobGas' is not listed")
        text = self.damaged("| 17 | `dataTreeRoot` | 32 bytes | Ghost |\n",
                            "| 17 | `dataTreeRoot` | 32 bytes | Ghost |\n"
                            "| 18 | `withdrawalsRoot` | 32 bytes | base |\n")
        self.assert_gap(text, "forbidden field 'withdrawalsRoot' is in the header")

    # -- genesis -----------------------------------------------------------

    def test_genesis_field_missing(self):
        start = self.text.index("| `gasUsed` | `0` |")
        end = self.text.index("\n", start) + 1
        self.assert_gap(self.text[:start] + self.text[end:], "genesis field 'gasUsed' is listed 0 times")

    def test_genesis_source(self):
        self.assert_gap(self.damaged("| `nonce` | zero | spec 06 |", "| `nonce` | zero | this chapter |"),
                        "genesis field 'nonce' is fixed by 'this chapter'")

    def test_genesis_value_matches_vector(self):
        self.assert_gap(self.damaged("| `gasLimit` | `30000000`", "| `gasLimit` | `30000001`"),
                        "genesis field 'gasLimit' is '30000001'")

    def test_genesis_against_spec_06(self):
        self.assert_gap(self.text, "spec 06 not found", spec06="")
        spec06 = self.spec06.replace("defined in the header specification", "defined elsewhere")
        self.assert_gap(self.text, "does not leave fields to the header specification", spec06=spec06)

    # -- vectors -----------------------------------------------------------

    def test_tree_root_vector(self):
        text = self.damaged("root = caa746ecf6160767cdf1cdffb8c1aa5628cce4e6037cac1b90e5978ae65cc5e8\n",
                            "root = caa746ecf6160767cdf1cdffb8c1aa5628cce4e6037cac1b90e5978ae65cc5e9\n")
        self.assert_gap(text, "vector data-tree-one-leaf: root is")
        text = self.damaged("root = dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a\n",
                            "root = dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237b\n")
        self.assert_gap(text, "vector data-tree-header-example: root is")

    def test_tree_leaves_are_spec_01_commitments(self):
        # The leaves of the two-leaf coin tree are spec 01's salted
        # coin-commit-salted and coin-remainder-salted, made with its words
        # example key.
        old_leaf = "1525d1f6caa2f9314988542a3dcb7ab5a76a9ba5dd3fef97a1ecf72ddeb516bc"
        self.assertNotIn(old_leaf[:-1] + "d", self.spec01)
        spec01 = self.spec01.replace(old_leaf, old_leaf[:-1] + "d")
        self.assert_gap(self.text, "vector coin-tree-two-leaves: leaves are not the commitments",
                        spec01=spec01)
        self.assert_gap(self.text, "vector coin-page-two-leaves: leaves are not the commitments",
                        spec01=spec01)
        data = self.in_block("data-tree-one-leaf",
                             "leaves = 523c415b17bb5c6b2270b71193a2737273d1be5aa519cd253155323aaad97e3f",
                             "leaves = 39c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06")
        self.assert_gap(data, "vector data-tree-one-leaf: leaves are not the commitments")
        self.assert_gap(self.text, "no test vectors found in spec 01", spec01="no vectors")

    def test_spec_01_leaves_need_a_words_key(self):
        # A twelve-group digit key in spec 01 is refused like the client refuses it.
        words = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812"
        head = "[coin-remainder-salted]\nkind = salted-coin-commitment\nversion = 2\n"
        self.assertIn(f"{head}key = {words}\nindex = 1\n", self.spec01)
        spec01 = self.spec01.replace(
            f"{head}key = {words}\nindex = 1\n",
            f"{head}key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417\nindex = 1\n", 1)
        self.assert_gap(self.text, "spec 01 vector coin-remainder-salted is not made with a words key",
                        spec01=spec01)

    def test_empty_tree_vector(self):
        old = "tree = coin\nroot = 8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8"
        self.assert_gap(self.damaged(old, old.replace("tree = coin", "tree = data")),
                        "vector empty-coin-tree: root is")

    def test_tree_vector_required(self):
        self.assert_gap(self.damaged("kind = empty-tree\ntree = data", "kind = other\ntree = data"),
                        "no empty-tree vector for the data tree")

    def test_page_vector(self):
        self.assert_gap(self.damaged("page-root = 8001", "page-root = 9001"),
                        "vector coin-page-two-leaves: page-root")
        self.assert_gap(self.damaged("empty-page-root = b50a", "empty-page-root = c50a"),
                        "vector coin-page-two-leaves: empty-page-root")
        self.assert_gap(self.damaged("kind = page", "kind = other"), "no page vector")

    def test_append_vectors(self):
        text = self.in_block("rollover-in-filling-block", "includable = no", "includable = yes")
        self.assert_gap(text, "vector rollover-in-filling-block: includable is yes, recomputed no")
        text = self.in_block("rollover", "index-after = 1", "index-after = 0")
        self.assert_gap(text, "vector rollover: index-after is 0, recomputed 1")
        text = self.in_block("append-fills-tree", "position = 4294967295", "position = 0")
        self.assert_gap(text, "vector append-fills-tree: position is 0")

    def test_rollover_cases_required(self):
        for name, fragment in (("rollover", "no rollover vector"),
                               ("rollover-in-filling-block", "the block that filled the tree"),
                               ("rollover-index-exhausted", "an exhausted tree index")):
            with self.subTest(name=name):
                text = self.in_block(name, "kind = append", "kind = other")
                self.assert_gap(text, fragment)

    def test_header_vector_rlp(self):
        start = self.text.index("[header-block-one-example]")
        at = self.text.index("rlp = f90243", start)
        text = self.text[:at] + "rlp = f90244" + self.text[at + len("rlp = f90243"):]
        errors = self.errors(text)
        self.assertTrue(any("header-block-one-example: rlp differs" in e for e in errors), errors)
        self.assertTrue(any("differs from the encoder's output" in e for e in errors), errors)

    def test_header_vector_field(self):
        text = self.in_block("header-block-one-example", "gasUsed = 126000", "gasUsed = 126001")
        errors = self.errors(text)
        self.assertTrue(any("header-block-one-example: rlp differs" in e for e in errors), errors)
        self.assertTrue(any("header-block-one-example: hash is" in e for e in errors), errors)

    def test_header_vector_hash(self):
        text = self.damaged("hash = 943182f2", "hash = 043182f2")
        self.assert_gap(text, "vector header-block-one-example: hash is")

    def test_parent_link(self):
        text = self.damaged("parentHash = ffc501cc", "parentHash = efc501cc")
        self.assert_gap(text, "parentHash is not the genesis example's hash")

    def test_header_root_must_be_a_tree_vector(self):
        text = self.in_block("header-block-one-example",
                             "coinTreeRoot = 142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5",
                             "coinTreeRoot = " + "55" * 32)
        self.assert_gap(text, "coinTreeRoot is not the root of any coin tree vector")

    def test_negative_vector_reason(self):
        text = self.in_block("header-non-canonical-integer", "reject = non-canonical-integer",
                             "reject = item-count")
        self.assert_gap(text, "header-non-canonical-integer: rejected as non-canonical-integer")

    def test_negative_vector_bytes(self):
        start = self.text.index("[header-extra-trailing-field]")
        at = self.text.index("3237a80\n", start)
        text = self.text[:at] + "3237a81\n" + self.text[at + len("3237a80\n"):]
        self.assert_gap(text, "header-extra-trailing-field: rlp differs from the re-derived")

    def test_negative_vector_marked_valid(self):
        text = self.in_block("header-forbidden-field", "valid = no", "valid = yes")
        self.assert_gap(text, "header-forbidden-field: a faulty header must have valid = no")

    def test_each_required_fault(self):
        for fault in checker.REQUIRED_FAULTS:
            with self.subTest(fault=fault):
                text = self.damaged(f"fault = {fault}\n", "fault = unknown\n")
                self.assert_gap(text, f"no negative header vector with fault '{fault}'")

    def test_encoder_output_required(self):
        self.assert_gap(self.text, "could not be run", vectors=None)
        altered = [(n, [(k, "00" if k == "hash" else v) for k, v in lines])
                   for n, lines in ENCODER_VECTORS]
        self.assert_gap(self.text, "vector header-genesis-example differs from the encoder's output",
                        vectors=altered)
        self.assert_gap(self.text, "is not produced by the encoder", vectors=ENCODER_VECTORS[:-1])
        extra = ENCODER_VECTORS + [("header-other", [("kind", "header")])]
        self.assert_gap(self.text, "encoder vector header-other is not in the chapter", vectors=extra)

    # -- requirements, recovery test, conflicts, tags ----------------------

    def test_requirement_numbering(self):
        self.assert_gap(self.damaged("- **TH-5. ", "- **TH-50. "), "requirements are numbered")

    def test_requirement_without_expected(self):
        start = self.text.index("- **TH-12.")
        at = self.text.index("Expected:", start)
        text = self.text[:at] + "Result:" + self.text[at + len("Expected:"):]
        self.assert_gap(text, "TH-12 states no expected result")

    def test_undefined_requirement_cited(self):
        self.assert_gap(self.damaged("(TH-1)", "(TH-99)"), "TH-99 is cited but not defined")

    def test_section_without_requirement(self):
        start = self.text.index("- **TH-12.")
        end = self.text.index("## 7.")
        self.assert_gap(self.text[:start] + self.text[end:], "section 'Markers' has no conformance")

    def test_recovery_test(self):
        start = self.text.index("- **RT-7.")
        at = self.text.index("Expected:", start)
        text = self.text[:at] + "Result:" + self.text[at + len("Expected:"):]
        self.assert_gap(text, "RT-7 states no expected result")
        self.assert_gap(self.damaged("- **RT-3. ", "- **RT-30. "), "recovery test steps are numbered")
        start = self.text.index("- **RT-1.")
        end = self.text.index("- **TH-21.")
        body = re.sub("indexer", "service", self.text[start:end])
        self.assert_gap(self.text[:start] + body + self.text[end:],
                        "the recovery test does not cover 'indexer'")
        body = re.sub("rollover", "change", self.text[start:end])
        self.assert_gap(self.text[:start] + body + self.text[end:],
                        "the recovery test does not cover 'rollover'")

    def test_required_conflicts(self):
        self.assert_gap(self.damaged("and question 6 default", "and question 7 default"),
                        "no conflict citing spec 03, question 6")
        self.assert_gap(self.damaged("section 8.3\n   leaves every", "section 8.4\n   leaves every"),
                        "no conflict citing spec 06, 8.3")

    def test_unknown_tag(self):
        text = self.damaged("`ghost/data-marker/v2`, each", "`ghost/spent-set/v1`, each")
        self.assert_gap(text, "tag ghost/spent-set/v1 is not in the tag table")
        self.assert_gap(self.text, "no tag table found in spec 01", spec01="no table")


class TreeAndRlpTest(unittest.TestCase):
    def test_roots_against_spec_01_node_vector(self):
        # Spec 01's coin-tree-node vector is the level-0 node of the two leaves.
        left = bytes.fromhex("9cadb00df6812a83ff2525fbaef0b634a020d600dc3bf3315efc3b20bfdb876c")
        right = bytes.fromhex("5530014e689c4a5a4b494f49a4a5be5a08a2c4d78e66128b824e5c1309c00503")
        node = checker.node(checker.TAG_COIN_NODE, 0, left, right)
        self.assertEqual(node.hex(), "df419dcb5b0e8b93b8bc2dffb17e8257e0b8b7d5d177a69f1b6cd18acffaee6d")
        self.assertIn(f"node = {node.hex()}", SPEC01.read_text(encoding="utf-8"))
        self.assertEqual(checker.empty_leaf().hex(),
                         "e050b25c8ab09717b0a6846b688b5047b93c0d37e18599cc7deec37f914bcca4")

    def test_sparse_root_matches_dense_root(self):
        rng = random.Random(5)
        tag = checker.TAG_DATA_NODE
        leaves = [bytes(rng.randrange(256) for _ in range(32)) for _ in range(5)]
        z = checker.empty_roots(tag)
        layer = leaves + [z[0]] * 3
        for level in range(3):
            layer = [checker.node(tag, level, layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        top = layer[0]
        for level in range(3, checker.DEPTH):
            top = checker.node(tag, level, top, z[level])
        self.assertEqual(checker.tree_root(tag, leaves), top)

    def test_append_rule(self):
        full = checker.LEAVES
        self.assertEqual(checker.append(0, 0, False), (True, 0, 1, 0))
        self.assertEqual(checker.append(3, full, False), (True, 4, 1, 0))
        self.assertEqual(checker.append(3, full, True), (False, 3, full, None))
        self.assertEqual(checker.append(checker.INDEX_MAX, full, False),
                         (False, checker.INDEX_MAX, full, None))

    def test_decoder_rejects_non_canonical_rlp(self):
        genesis = encoder.genesis_example()
        good = checker.encode_header(genesis)
        self.assertEqual(checker.decode_header(good), genesis)
        # A wrapped single byte: the gasUsed field 0 written as 0x81 0x00 is a
        # non-canonical integer; a value below 0x80 written as 0x81 0x05 is
        # non-canonical RLP.
        fields = dict(genesis, gasUsed=5)
        raw = checker.encode_header(fields)
        at = raw.index(bytes([0x05, 0x84]))
        wrapped = raw[:at] + b"\x81" + raw[at:]
        body = wrapped[3:]
        wrapped = bytes([0xF9]) + len(body).to_bytes(2, "big") + body
        with self.assertRaises(checker.DecodeError) as ctx:
            checker.decode_header(wrapped)
        self.assertEqual(ctx.exception.reason, "non-canonical-rlp")
        # The outer list length in long form with a leading zero byte.
        body = good[3:]
        padded = bytes([0xFA, 0x00]) + len(body).to_bytes(2, "big") + body
        with self.assertRaises(checker.DecodeError) as ctx:
            checker.decode_header(padded)
        self.assertEqual(ctx.exception.reason, "non-canonical-rlp")

    def test_decoder_integer_range(self):
        fields = dict(encoder.genesis_example(), number=2**64)
        raw = encoder.rlp_list_of_encoded(
            [encoder.rlp_uint(fields[n]) if k == "int" else encoder.rlp_string(fields[n])
             for n, k, _ in encoder.HEADER_LAYOUT])
        with self.assertRaises(checker.DecodeError) as ctx:
            checker.decode_header(raw)
        self.assertEqual(ctx.exception.reason, "integer-range")


class EncoderTest(unittest.TestCase):
    def test_encoder_is_separate(self):
        source = ENCODER.read_text(encoding="utf-8")
        self.assertNotIn("check_trees_and_headers", source)
        self.assertNotIn("import check_", source)
        self.assertTrue(hasattr(encoder, "rlp_string") and hasattr(encoder, "rlp_uint"))

    def test_same_layout_as_checker(self):
        self.assertEqual(tuple(encoder.HEADER_LAYOUT), checker.HEADER)

    def test_chapter_holds_encoder_output(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertIn(encoder.render(), text)

    def test_two_rlp_codes_agree(self):
        rng = random.Random(7)
        for _ in range(300):
            value = rng.choice((0, 1, 0x7F, 0x80, 0xFF, 2**64 - 1, rng.getrandbits(rng.randrange(1, 257))))
            self.assertEqual(encoder.rlp_uint(value), checker.rlp_encode(checker.int_bytes(value)))
            data = bytes(rng.randrange(256) for _ in range(rng.choice((0, 1, 2, 55, 56, 300))))
            self.assertEqual(encoder.rlp_string(data), checker.rlp_encode(data))

    def test_checker_rejects_every_encoder_negative(self):
        for name, lines in encoder.golden_vectors():
            fields = dict(lines)
            raw = bytes.fromhex(fields["rlp"])
            if fields["valid"] == "yes":
                checker.decode_header(raw)
                continue
            with self.subTest(name=name):
                with self.assertRaises(checker.DecodeError) as ctx:
                    checker.decode_header(raw)
                self.assertEqual(ctx.exception.reason, fields["reject"])

    def test_encoder_refuses_bad_fields(self):
        fields = encoder.genesis_example()
        for key, value in (("coinTreeRoot", bytes(31)), ("number", -1), ("extraData", bytes(33))):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    encoder.encode_header(dict(fields, **{key: value}))


if __name__ == "__main__":
    unittest.main()
