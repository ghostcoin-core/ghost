"""Tests for benchmarks/scale/layer_witness.py: every statement proven with the batch STARK
states its witness on docs/scale/stage2-design.md, and none relies on hiding the LogUp
terminals that the pinned Plonky3 revision publishes unmasked.

The repository itself must pass. The negative cases change one thing in a copy of the
repository's own text, held in memory, and check that the change is caught; nothing on disk
is written.
"""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import labels  # noqa: E402
import layer_witness as lw  # noqa: E402

DOC_TEXT = (REPO / lw.DOC).read_text(encoding="utf-8")
SOURCES = lw.rust_sources(REPO)
MANIFESTS = lw.manifests(REPO)
TESTS = lw.proof_tests(REPO)
KEYS = "proofs/src/layers/keys.rs"
MLDSA = "proofs/src/mldsa/mod.rs"
OTHER_REVISION = "1" * 40


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def with_source(path, text):
    sources = dict(SOURCES)
    sources[path] = text
    return sources


def row_line(name):
    for line in lw.section(DOC_TEXT):
        if line.startswith(f"| {name} |"):
            return line
    raise AssertionError(name)


class Repository(unittest.TestCase):
    def test_the_repository_passes(self):
        self.assertEqual(lw.check(), [])

    def test_command_line(self):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(lw.main([]), 0)
        self.assertIn("statements proven with the batch STARK", out.getvalue())

    def test_every_layer_and_the_chunk_has_a_public_witness(self):
        problems, verdicts = lw.check_doc(DOC_TEXT)
        self.assertEqual(problems, [])
        self.assertEqual(set(verdicts), {"Batch over reveal proofs", "Batch over chunk proofs", "Root", "Shrink",
                                         "ML-DSA-44 chunk"})
        self.assertEqual(set(verdicts.values()), {lw.PUBLIC})

    def test_the_pin_is_the_unmasked_revision_everywhere(self):
        # The verdicts above are what allow it.
        revisions = {rev for text in MANIFESTS.values() for rev in lw.REV.findall(text)}
        self.assertEqual(revisions, {lw.UNMASKED_REVISION})

    def test_the_layers_and_the_chunk_are_the_batch_stark_provers(self):
        found = sorted(p for p, t in SOURCES.items() if lw.PROVE_CALL.search(t))
        self.assertEqual(found, sorted(lw.PROVERS))
        senders = sorted(p for p, t in SOURCES.items() if lw.GLOBAL_SEND.search(t))
        self.assertEqual(senders, sorted(lw.GLOBAL_SENDERS))

    def test_the_reveal_statements_have_no_lookups(self):
        for path in ("proofs/src/stark.rs", "proofs/src/scale.rs", "proofs/src/reveal.rs", "proofs/src/reveal_v2.rs"):
            with self.subTest(path=path):
                text = SOURCES[path]
                self.assertNotIn("p3_lookup", text)
                self.assertIsNone(lw.PROVE_CALL.search(text))

    def test_the_page_is_labelled(self):
        self.assertEqual(labels.check_text(DOC_TEXT), [])

    def test_the_open_item_is_gone(self):
        self.assertNotIn("Open: zero knowledge of the lookup terminals", DOC_TEXT)


class Page(unittest.TestCase):
    def problems(self, text):
        return lw.check_doc(text)[0]

    def test_a_missing_row(self):
        text = replace_once(DOC_TEXT, row_line("Root") + "\n", "")
        self.assertIn("no row for Root", self.problems(text))

    def test_a_row_relying_on_hiding_is_read(self):
        line = row_line("Shrink")
        text = replace_once(DOC_TEXT, line, line.replace(lw.PUBLIC, lw.RELIES))
        problems, verdicts = lw.check_doc(text)
        self.assertEqual(problems, [])
        self.assertEqual(verdicts["Shrink"], lw.RELIES)

    def test_a_verdict_that_is_neither(self):
        line = row_line("Batch over reveal proofs")
        text = replace_once(DOC_TEXT, line, line.replace(lw.PUBLIC, "probably fine"))
        self.assertTrue(any("probably fine" in p for p in self.problems(text)))

    def test_a_marker_does_not_change_the_verdict(self):
        line = row_line("ML-DSA-44 chunk")
        self.assertIn("<!-- no-figure -->", line)
        self.assertEqual(lw.cells(line)[3], lw.PUBLIC)

    def test_a_row_naming_another_prover(self):
        line = row_line("Root")
        text = replace_once(DOC_TEXT, line, line.replace("`prove_layer_of`", "`prove_root`"))
        self.assertTrue(any("does not name `prove_layer_of`" in p for p in self.problems(text)))

    def test_an_empty_witness(self):
        line = row_line("Shrink")
        cells = lw.cells(line)
        text = replace_once(DOC_TEXT, line, f"| {cells[0]} | {cells[1]} |  | {cells[3]} |")
        self.assertIn("Shrink: the witness column is empty", self.problems(text))

    def test_an_unknown_statement(self):
        line = row_line("Shrink")
        text = replace_once(DOC_TEXT, line, line + "\n| Reveal over lookups | `prove_reveal` | the digits | "
                            + lw.PUBLIC + " |")
        self.assertIn("row for a statement this check does not know: Reveal over lookups", self.problems(text))

    def test_the_open_item_back(self):
        line = row_line("Root")
        anchor = "| Statement | Prover | Its witness | Cross-AIR terminals |"
        text = replace_once(DOC_TEXT, anchor, "- **Open: zero knowledge of the lookup terminals.** Unsettled.\n\n"
                            + anchor)
        self.assertIn(line, text)
        self.assertIn("the open item on the lookup terminals is still on the page", self.problems(text))

    def test_no_table(self):
        text = replace_once(DOC_TEXT, lw.TABLE_HEADER, "| Statement | Witness |")
        self.assertTrue(self.problems(text)[0].endswith("has no table headed " + lw.TABLE_HEADER))

    def test_no_section(self):
        text = replace_once(DOC_TEXT, lw.SECTION + "\n", "### Another heading\n")
        self.assertEqual(self.problems(text), [f"missing section {lw.SECTION}"])


class Provers(unittest.TestCase):
    def test_the_real_provers_pass(self):
        self.assertEqual(lw.check_provers(SOURCES), [])

    def test_a_new_input_to_a_layer_prover(self):
        text = replace_once(SOURCES[KEYS], "    children: &[(Vec<u8>, Claim)],\n",
                            "    children: &[(Vec<u8>, Claim)],\n    note_key: &[u8; 32],\n")
        problems = lw.check_provers(with_source(KEYS, text))
        self.assertTrue(any("takes note_key" in p for p in problems))

    def test_a_batch_child_that_is_not_a_proof(self):
        text = replace_once(SOURCES[KEYS], "    children: &[(Vec<u8>, Vec<F>)],\n",
                            "    children: &[(RowMajorMatrix<F>, Vec<F>)],\n")
        problems = lw.check_provers(with_source(KEYS, text))
        self.assertTrue(any("Batch over reveal proofs" in p and "RowMajorMatrix" in p for p in problems))

    def test_a_dropped_input(self):
        # prove_chunk_of is the first function to take it.
        source = SOURCES[MLDSA]
        self.assertLess(source.index("fn prove_chunk_of("), source.index("    txs: &[SignedTx],\n"))
        text = source.replace("    txs: &[SignedTx],\n", "", 1)
        problems = lw.check_provers(with_source(MLDSA, text))
        self.assertIn("ML-DSA-44 chunk: prove_chunk_of no longer takes txs", problems)

    def test_a_renamed_prover(self):
        text = SOURCES[MLDSA].replace("fn prove_chunk_of(", "fn prove_chunk_inner(")
        problems = lw.check_provers(with_source(MLDSA, text))
        self.assertIn(f"ML-DSA-44 chunk: no fn prove_chunk_of in {MLDSA}", problems)

    def test_a_secret_field_in_the_signed_transaction(self):
        text = replace_once(SOURCES[MLDSA], "    pub signature: Vec<u8>,\n",
                            "    pub signature: Vec<u8>,\n    pub signing_seed: [u8; 32],\n")
        problems = lw.check_provers(with_source(MLDSA, text))
        self.assertTrue(any(p.startswith("SignedTx has fields") for p in problems))

    def test_parameters_are_read_with_their_types(self):
        got = lw.params(SOURCES[KEYS], "prove_batch_of")
        self.assertEqual(got["children"], "&[(Vec<u8>, Vec<F>)]")
        self.assertEqual(got["binding_slots"], "&[usize; BINDING_ELEMS]")


class Sources(unittest.TestCase):
    def problems(self, sources=None, manifests=None):
        return lw.check_sources(SOURCES if sources is None else sources,
                                MANIFESTS if manifests is None else manifests)

    def test_the_real_sources_pass(self):
        self.assertEqual(self.problems(), [])

    def test_a_reveal_sending_on_the_wire_bus(self):
        path = "proofs/src/reveal.rs"
        text = SOURCES[path] + "\nfn send<AB: InteractionBuilder>(b: &mut AB) { b.push_interaction(\"wire\", f, c); }\n"
        self.assertIn(f"{path} sends a lookup across AIRs; list the statement and its witness first",
                      self.problems(with_source(path, text)))

    def test_a_statement_proven_with_the_tables(self):
        path = "proofs/src/stark.rs"
        text = SOURCES[path] + "\nfn p() { let _ = crate::layers::tables::prove(&k, &c, &f, &t, s); }\n"
        self.assertIn(f"{path} proves with the batch STARK; list the statement and its witness first",
                      self.problems(with_source(path, text)))

    def test_another_crate_calling_the_library_prover(self):
        path = "client/src/lib.rs"
        text = SOURCES[path] + "\nfn p() { let _ = p3_batch_stark::prove_batch(&c, &i, &d); }\n"
        self.assertIn(f"{path} proves with the batch STARK; list the statement and its witness first",
                      self.problems(with_source(path, text)))

    def test_a_comment_is_not_a_call(self):
        path = "proofs/src/stark.rs"
        text = SOURCES[path] + "\n// Not here: tables::prove(..) and b.push_interaction(..).\n"
        self.assertEqual(self.problems(with_source(path, text)), [])

    def test_the_layer_api_is_not_a_new_prover(self):
        path = "client/src/lib.rs"
        text = SOURCES[path] + "\nfn p() { let _ = ghost_proofs::layers::prove_batch(&k, &a, &b, 0, &s, &c, z); }\n"
        self.assertEqual(self.problems(with_source(path, text)), [])

    def test_the_lookup_check_stays_local(self):
        text = SOURCES[lw.LOOKUP_CHECK].replace("push_local_interaction(", "push_interaction(\"range\", ")
        self.assertIn(f"{lw.LOOKUP_CHECK} must use local lookups only",
                      self.problems(with_source(lw.LOOKUP_CHECK, text)))

    def test_the_lookup_check_stays_test_only(self):
        text = replace_once(SOURCES[lw.LIB], "#[cfg(test)]\nmod lookup_check;", "mod lookup_check;")
        self.assertIn(f"{lw.LOOKUP_CHECK} must stay a test-only module of {lw.LIB}",
                      self.problems(with_source(lw.LIB, text)))

    def test_another_crate_depending_on_the_lookup_crates(self):
        manifests = dict(MANIFESTS)
        manifests["client/Cargo.toml"] += ('\np3-lookup = { git = "https://github.com/Plonky3/Plonky3", rev = "'
                                           + lw.UNMASKED_REVISION + '" }\n')
        self.assertIn("client/Cargo.toml depends on p3-lookup; only proofs/Cargo.toml may",
                      self.problems(manifests=manifests))


class Pin(unittest.TestCase):
    PUBLIC = {s["row"]: lw.PUBLIC for s in lw.STATEMENTS}
    MASK_TEST = {"proofs/tests/terminal_masking.rs": "assert!(masked(proof.lookup_terminals[1]));"}

    def relying(self):
        return dict(self.PUBLIC, Root=lw.RELIES)

    def moved(self):
        return {p: t.replace(lw.UNMASKED_REVISION, OTHER_REVISION) for p, t in MANIFESTS.items()}

    def test_public_witnesses_at_the_unmasked_pin(self):
        self.assertEqual(lw.check_pin(self.PUBLIC, MANIFESTS, TESTS), [])

    def test_relying_on_hiding_at_the_unmasked_pin(self):
        problems = lw.check_pin(self.relying(), MANIFESTS, TESTS)
        self.assertTrue(any(p.startswith("Root relies on hiding the terminals") for p in problems))
        self.assertIn("no test under proofs/tests shows a cross-AIR terminal masked", problems)

    def test_relying_on_hiding_after_the_pin_moves_with_a_test(self):
        tests = dict(TESTS, **self.MASK_TEST)
        self.assertEqual(lw.check_pin(self.relying(), self.moved(), tests), [])

    def test_relying_on_hiding_after_the_pin_moves_without_a_test(self):
        self.assertEqual(lw.check_pin(self.relying(), self.moved(), TESTS),
                         ["no test under proofs/tests shows a cross-AIR terminal masked"])

    def test_one_revision_for_the_whole_repository(self):
        manifests = dict(MANIFESTS)
        manifests["benchmarks/Cargo.toml"] = manifests["benchmarks/Cargo.toml"].replace(
            lw.UNMASKED_REVISION, OTHER_REVISION, 1)
        problems = lw.check_pin(self.PUBLIC, manifests, TESTS)
        self.assertTrue(any(p.startswith("the Plonky3 crates name 2 revisions") for p in problems))

    def test_the_page_drives_the_pin_check(self):
        line = row_line("Root")
        text = replace_once(DOC_TEXT, line, line.replace(lw.PUBLIC, lw.RELIES))
        _, verdicts = lw.check_doc(text)
        self.assertNotEqual(lw.check_pin(verdicts, MANIFESTS, TESTS), [])


if __name__ == "__main__":
    unittest.main()
