"""Tests for benchmarks/scale/labels.py, the figure label checker."""

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scale"))

import labels  # noqa: E402

SCRIPT = HERE.parent / "scale" / "labels.py"


def failing(text):
    return [number for number, _ in labels.check_text(text)]


class Lines(unittest.TestCase):
    def test_labelled_figures_pass(self):
        for line in [
            "A reveal is 1,311,067 bytes (modeled).",
            "Warm median 13.15 s, emulated-measured on the Mac Studio.",
            "Real phone memory: NOT YET ESTABLISHED; run it on a phone.",
            "Real phone memory: not yet\testablished.",
            "Ten **Measured** runs.",
        ]:
            self.assertEqual(failing(line), [], line)

    def test_unlabelled_figures_fail(self):
        for line in [
            "A reveal is 1,311,067 bytes.",
            "The merge takes 0.3 s.",
            "About 3,500 per block, unmeasured.",
            "Remodeled at 40 machines.",
            "A tree holds 2^32 leaves.",
        ]:
            self.assertEqual(failing(line), [1], line)

    def test_lines_without_figures_pass(self):
        self.assertEqual(failing("Nodes keep the sequential marker check."), [])
        self.assertEqual(failing(""), [])

    def test_references_are_not_figures(self):
        for line in [
            "See spec 05, sections 3, 6, 7 and 8.",
            "As spec 09 section 8.4 says.",
            "Section 3 of the spec.",
            "Measured on 2026-10-23.",
            "Read docs/spec/05-trees-and-headers.md and proofs/src/stark.rs.",
            "The files under benchmarks/scale/ and the tag ghost/coin-marker/v1.",
            "Chrome 155.0.8059.85 and rustc 1.99.1, format v2.",
            "Step 1.1 and rules 1 to 6 apply, and rule 2.",
            "1. Nodes keep the marker check.",
            "12) Nodes keep the marker check.",
        ]:
            self.assertEqual(failing(line), [], line)

    def test_a_figure_beside_a_reference_still_fails(self):
        self.assertEqual(failing("Spec 07, section 3 says 347 bytes."), [1])
        self.assertEqual(failing("1. Pay 40 machines."), [1])
        self.assertEqual(failing("Step 1.1 needs 30 s."), [1])


class Structure(unittest.TestCase):
    def test_code_fences_are_skipped(self):
        text = "```sh\npython3 run.py --runs 50\n```\n~~~\n3,500\n~~~\nAfter 7 runs.\n"
        self.assertEqual(failing(text), [7])

    def test_headings_are_skipped(self):
        self.assertEqual(failing("## 10 million a day\n\n### Step 2\n"), [])

    def test_table_rows(self):
        text = "\n".join([
            "| Item | Value | Label |",
            "|---|---|---|",
            "| Envelope | 1,311,067 bytes | modeled |",
            "| Proof field | 1,310,720 bytes | |",
            "| Version | 2 | | <!-- no-figure -->",
        ])
        self.assertEqual(failing(text), [4])

    def test_no_figure_marks_the_whole_bullet(self):
        text = "\n".join([
            "- Rule 3 names Poseidon2 over BabyBear width 24 <!-- no-figure -->",
            "  and t=16 on its second line.",
            "- An unmarked bullet with 24",
            "  and a modeled 16.",
            "",
            "A paragraph with 24.",
            "A paragraph with 16. <!-- no-figure -->",
        ])
        self.assertEqual(failing(text), [3, 6])

    def test_no_figure_does_not_reach_the_next_bullet_or_row(self):
        text = "- First 1 <!-- no-figure -->\n- Second 2\n| a | 3 | <!-- no-figure -->\n| b | 4 |\n"
        self.assertEqual(failing(text), [2, 4])


class Command(unittest.TestCase):
    def run_on(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "doc.md"
            path.write_text(text, encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = labels.main([str(path)])
            return code, out.getvalue()

    def test_passing_file_exits_zero(self):
        code, out = self.run_on("# Title\n\nA modeled 347 bytes.\n")
        self.assertEqual((code, out), (0, ""))

    def test_failing_file_exits_one_and_prints_the_line(self):
        code, out = self.run_on("# Title\n\nFine.\nA bare 347 bytes.\n")
        self.assertEqual(code, 1)
        self.assertIn("doc.md:4:", out)
        self.assertIn("A bare 347 bytes.", out)

    def test_script_runs_as_a_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.md"
            bad = Path(tmp) / "bad.md"
            good.write_text("Modeled: 3,500 per block.\n", encoding="utf-8")
            bad.write_text("3,500 per block.\n", encoding="utf-8")
            ok = subprocess.run([sys.executable, str(SCRIPT), str(good)], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            no = subprocess.run([sys.executable, str(SCRIPT), str(good), str(bad)], capture_output=True, text=True)
            self.assertEqual(no.returncode, 1)
            self.assertIn("bad.md:1:", no.stdout)
            self.assertNotIn("good.md", no.stdout)


PAGE = HERE.parent.parent / "docs" / "scale" / "bundle-security.md"

OBLIGATION_ROWS = [
    "| Recursion with the hash inside the circuit | open | Would close it: a theorem for recursive STARKs. | not yet established |",
    "| Extraction over three layers | open | Would close it: a composable extractor. | not yet established |",
    "| Round-by-round soundness of the Plonky3 IOP | open | Would close it: a proof for the batch STARK. | not yet established |",
    "| Theorem numbers | discharged | Theorem 8.3 of the paper, read in full. | modeled |",
    "| A published analysis of Poseidon2 over BabyBear, width 24 | open | Would close it: a paper on this instance. | not yet established |",
]


def obligations_page(rows=None, header="| Obligation | Status | Theorem and number, or what would close it | Label |"):
    rows = OBLIGATION_ROWS if rows is None else rows
    return "\n".join(["# Page", "", header, "|---|---|---|---|", *rows, ""])


def problems(text):
    return [problem for _, problem in labels.check_obligation_lines(text.splitlines())]


class Obligations(unittest.TestCase):
    def test_five_rows_each_with_one_status_pass(self):
        self.assertEqual(problems(obligations_page()), [])

    def test_emphasis_and_case_of_the_status_are_ignored(self):
        rows = [r.replace("| open |", "| **Open** |") for r in OBLIGATION_ROWS]
        rows = [r.replace("| discharged |", "| `discharged` |") for r in rows]
        self.assertEqual(problems(obligations_page(rows)), [])

    def test_each_missing_obligation_fails(self):
        for i in range(len(OBLIGATION_ROWS)):
            rows = OBLIGATION_ROWS[:i] + OBLIGATION_ROWS[i + 1:]
            found = problems(obligations_page(rows))
            self.assertEqual(len(found), 1, found)
            self.assertIn("missing obligation", found[0])

    def test_a_repeated_obligation_fails(self):
        found = problems(obligations_page(OBLIGATION_ROWS + [OBLIGATION_ROWS[0]]))
        self.assertEqual(len(found), 1, found)
        self.assertIn("more than once", found[0])

    def test_a_row_that_is_no_obligation_fails(self):
        extra = "| Digest length | open | Would close it: nothing. | not yet established |"
        found = problems(obligations_page(OBLIGATION_ROWS + [extra]))
        self.assertEqual(len(found), 1, found)
        self.assertIn("not one of the five", found[0])

    def test_a_status_other_than_one_of_the_two_fails(self):
        for status in ["closed", "open, discharged", "discharged and open", "", "partly open", "not yet established"]:
            rows = [OBLIGATION_ROWS[0].replace("| open |", f"| {status} |")] + OBLIGATION_ROWS[1:]
            found = problems(obligations_page(rows))
            self.assertEqual(len(found), 1, (status, found))
            self.assertIn("exactly one of discharged or open", found[0])

    def test_discharged_needs_a_theorem_and_its_number(self):
        for evidence in ["The theorem of the paper.", "Theorem of BCIKS.", "Would close it: Theorem."]:
            rows = OBLIGATION_ROWS[:3] + [f"| Theorem numbers | discharged | {evidence} | modeled |"] + OBLIGATION_ROWS[4:]
            found = problems(obligations_page(rows))
            self.assertEqual(len(found), 1, (evidence, found))
            self.assertIn("without a theorem", found[0])
        for evidence in ["Lemma 8.2 and Theorem 7.2.", "Corollary 3 of the paper.", "Proposition 4.1.2."]:
            rows = OBLIGATION_ROWS[:3] + [f"| Theorem numbers | discharged | {evidence} | modeled |"] + OBLIGATION_ROWS[4:]
            self.assertEqual(problems(obligations_page(rows)), [], evidence)

    def test_open_needs_what_would_close_it(self):
        for evidence in ["", "Still open.", "A theorem would close it.", "Would close it:"]:
            rows = [f"| Recursion with the hash inside the circuit | open | {evidence} | not yet established |"]
            found = problems(obligations_page(rows + OBLIGATION_ROWS[1:]))
            self.assertEqual(len(found), 1, (evidence, found))
            self.assertIn("what would close it", found[0])

    def test_a_page_without_the_table_fails(self):
        self.assertEqual(len(problems("# Page\n\nNo table.\n")), 1)
        # A table without the status or the closing column is not the table.
        self.assertEqual(len(problems(obligations_page(header="| Obligation | State | Theorem | Label |"))), 1)
        self.assertEqual(len(problems(obligations_page(header="| Obligation | Status | Theorem | Label |"))), 1)

    def test_the_command_takes_the_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.md"
            bad = Path(tmp) / "bad.md"
            good.write_text(obligations_page(), encoding="utf-8")
            bad.write_text(obligations_page(OBLIGATION_ROWS[1:]), encoding="utf-8")
            ok = subprocess.run([sys.executable, str(SCRIPT), "--obligations", str(good)], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            no = subprocess.run([sys.executable, str(SCRIPT), "--obligations", str(good), str(bad)],
                                capture_output=True, text=True)
            self.assertEqual(no.returncode, 1)
            self.assertIn("bad.md", no.stdout)
            self.assertIn("missing obligation: recursion with the hash inside the circuit", no.stdout)
            self.assertNotIn("good.md", no.stdout)
            usage = subprocess.run([sys.executable, str(SCRIPT), "--obligations"], capture_output=True, text=True)
            self.assertEqual(usage.returncode, 2)

    def test_the_write_up_holds_its_obligations_and_labels(self):
        self.assertEqual(labels.check_obligations_file(PAGE), [])
        unlabelled = labels.check_file(PAGE)
        self.assertEqual(unlabelled, [], "\n".join(f"{n}: {t}" for n, t in unlabelled))


if __name__ == "__main__":
    unittest.main()
