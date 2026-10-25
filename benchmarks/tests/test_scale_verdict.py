"""Tests for docs/scale/stage1-verdict.md: one verdict, its headings, labels and reproducible paths.

The negative cases check short pages written in the test; none of them is the verdict.
"""

import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import labels  # noqa: E402

DOC = REPO / "docs" / "scale" / "stage1-verdict.md"

PHRASES = ("Feasible to proceed", "Not feasible as designed", "Not demonstrated")
NEGATIVE = "Not feasible as designed"
HEADINGS = (
    "## Evidence",
    "## Limiting constraint",
    "## Requirements carried into stage 3",
    "## Reproduce",
)
FENCE = re.compile(r"^\s*(```|~~~)")
BULLET = re.compile(r"^\s*[-*+]\s+\S")
BACKTICKED = re.compile(r"`([^`\n]+)`")


def verdict_lines(text):
    return [line for line in text.splitlines() if line.startswith("Verdict: ")]


def phrases_in(text):
    """Every verdict phrase on the text, any case, with its count."""
    lowered = text.lower()
    return {p: lowered.count(p.lower()) for p in PHRASES if p.lower() in lowered}


def section(text, heading):
    """The lines under a level-two heading, up to the next one; None when the heading is missing."""
    lines = text.splitlines()
    if heading not in lines:
        return None
    start = lines.index(heading) + 1
    out = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        out.append(line)
    return out


def outside_fences(lines):
    in_fence = False
    for line in lines:
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield line


def problems(text, root=REPO):
    """Every reason the page is not an acceptable verdict, as text; empty when it is."""
    out = []
    found = verdict_lines(text)
    if len(found) != 1:
        out.append(f"expected exactly one 'Verdict: ' line, found {len(found)}")
    verdict = None
    if found:
        named = [p for p in PHRASES if p in found[0]]
        if len(named) != 1 or found[0] != f"Verdict: {named[0]}":
            out.append(f"the verdict line must name exactly one of {', '.join(PHRASES)}")
        else:
            verdict = named[0]
    counts = phrases_in(text)
    if sum(counts.values()) != 1:
        out.append(f"the verdict phrases must appear once in all, on the verdict line: {counts}")
    for heading in HEADINGS:
        if section(text, heading) is None:
            out.append(f"missing heading {heading}")
    limiting = section(text, "## Limiting constraint")
    if limiting is not None and not any(line.strip() for line in limiting):
        out.append("## Limiting constraint is empty")
    if verdict == NEGATIVE and limiting is not None and not any(line.strip() for line in limiting):
        out.append("a negative verdict must name its limiting constraint")
    carried = section(text, "## Requirements carried into stage 3")
    if carried is not None and not any(BULLET.match(line) for line in carried):
        out.append("## Requirements carried into stage 3 has no bullet")
    reproduce = section(text, "## Reproduce")
    if reproduce is not None:
        paths = [p for line in outside_fences(reproduce) for p in BACKTICKED.findall(line)]
        if not paths:
            out.append("## Reproduce names no path")
        for path in paths:
            if not (root / path).exists():
                out.append(f"missing path {path}")
    for number, line in labels.check_text(text):
        out.append(f"line {number}: figure without a label: {line.strip()}")
    return out


GOOD = """# A verdict

Verdict: Not feasible as designed

## Evidence

A block needs 14,283,500 bytes (modeled).

## Limiting constraint

The message cap.

## Requirements carried into stage 3

- Propagation (not yet established).

## Reproduce

- `benchmarks/scale/budget.py`

```sh
python3 `not/a/path.py`
```
"""


class Page(unittest.TestCase):
    def test_the_verdict_page_passes(self):
        self.assertEqual(problems(DOC.read_text(encoding="utf-8")), [])

    def test_exactly_one_verdict(self):
        text = DOC.read_text(encoding="utf-8")
        lines = verdict_lines(text)
        self.assertEqual(len(lines), 1)
        self.assertEqual([p for p in PHRASES if p in lines[0]], [lines[0][len("Verdict: "):]])
        self.assertEqual(sum(phrases_in(text).values()), 1)

    def test_headings_and_bullets(self):
        text = DOC.read_text(encoding="utf-8")
        for heading in HEADINGS:
            self.assertIsNotNone(section(text, heading), heading)
        self.assertTrue(any(line.strip() for line in section(text, "## Limiting constraint")))
        bullets = [line for line in section(text, "## Requirements carried into stage 3") if BULLET.match(line)]
        for name in ("Propagation", "State execution", "Real capacity", "Reorganisation and marker rules",
                     "Denial-of-service bounds", "Independent operation"):
            with self.subTest(requirement=name):
                self.assertTrue(any(name in line for line in bullets))

    def test_every_reproduce_path_exists(self):
        reproduce = section(DOC.read_text(encoding="utf-8"), "## Reproduce")
        paths = [p for line in outside_fences(reproduce) for p in BACKTICKED.findall(line)]
        self.assertIn("benchmarks/scale/throughput.py", paths)
        self.assertIn("benchmarks/scale/public_encoding.py", paths)
        self.assertIn("docs/scale/recursion-proxy.jsonl", paths)
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue((REPO / path).exists())

    def test_every_figure_is_labelled(self):
        self.assertEqual(labels.check_file(DOC), [])


class Negative(unittest.TestCase):
    def test_a_good_sample_passes(self):
        self.assertEqual(problems(GOOD), [])

    def test_two_verdict_phrases(self):
        text = GOOD.replace("Verdict: Not feasible as designed", "Verdict: Not feasible as designed, Not demonstrated")
        self.assertTrue(any("exactly one of" in p for p in problems(text)))

    def test_a_phrase_elsewhere(self):
        text = GOOD.replace("The message cap.", "The message cap; otherwise feasible to proceed.")
        self.assertTrue(any("once in all" in p for p in problems(text)))

    def test_two_verdict_lines(self):
        text = GOOD.replace("## Evidence", "Verdict: Not demonstrated\n\n## Evidence")
        self.assertTrue(any("exactly one 'Verdict: ' line" in p for p in problems(text)))

    def test_no_verdict_line(self):
        self.assertTrue(problems(GOOD.replace("Verdict: ", "Outcome: ")))

    def test_a_missing_label(self):
        text = GOOD.replace("14,283,500 bytes (modeled)", "14,283,500 bytes")
        self.assertTrue(any("figure without a label" in p for p in problems(text)))

    def test_a_missing_path(self):
        text = GOOD.replace("`benchmarks/scale/budget.py`", "`benchmarks/scale/no_such_script.py`")
        self.assertIn("missing path benchmarks/scale/no_such_script.py", problems(text))

    def test_an_empty_limiting_constraint(self):
        text = GOOD.replace("The message cap.\n", "")
        found = problems(text)
        self.assertIn("a negative verdict must name its limiting constraint", found)

    def test_no_carried_bullet(self):
        text = GOOD.replace("- Propagation (not yet established).", "Propagation (not yet established).")
        self.assertIn("## Requirements carried into stage 3 has no bullet", problems(text))

    def test_a_missing_heading(self):
        self.assertIn("missing heading ## Evidence", problems(GOOD.replace("## Evidence", "## Findings")))


if __name__ == "__main__":
    unittest.main()
