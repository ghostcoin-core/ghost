"""Check that every figure in a markdown file carries a label.

A line outside code fences and headings that carries a figure must also say
"measured", "modeled" or "not yet established" (in any case), or belong to a
table row or bullet marked with the HTML comment ``<!-- no-figure -->``.

A figure is any digit left on the line after removing what is not a quantity:
spec and section references, dates, file names and paths, version strings,
"step" or "rule" followed by a number, and the marker of a numbered list item.

Usage: python3 benchmarks/scale/labels.py FILE...
Exits 1 and prints each offending line when a file fails.
"""

import re
import sys

NO_FIGURE = "<!-- no-figure -->"
LABEL = re.compile(r"\bmeasured\b|\bmodeled\b|\bnot\s+yet\s+established\b", re.IGNORECASE)
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^\s{0,3}#")
ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
NUMBER = re.compile(r"\d")

NUM = r"\d+(?:\.\d+)*"
NUM_LIST = NUM + r"(?:(?:\s*,\s*|\s+and\s+|\s+to\s+|\s*,\s*and\s+)" + NUM + r")*"
EXTENSIONS = "md|py|rs|toml|json|jsonl|yaml|yml|js|mjs|ts|sh|html|wasm|txt|lock"

# Applied in this order; each match is replaced by a space.
NOT_FIGURES = [
    # Dates: 2026-10-23.
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    # File names and paths: docs/spec/05-trees-and-headers.md, benchmarks/scale/.
    re.compile(r"[\w./-]*[A-Za-z][\w./-]*\.(?:" + EXTENSIONS + r")\b"),
    re.compile(r"(?:[\w.-]*[A-Za-z][\w.-]*/)+[\w.-]*"),
    # Version strings: v1, v1.2, 1.99.1, 155.0.8059.85.
    re.compile(r"\bv\d+(?:\.\d+)*\b"),
    re.compile(r"\b\d+\.\d+\.\d+(?:\.\d+)*\b"),
    # Spec and section references: spec 05, section 8.4; sections 3, 6, 7 and 8.
    re.compile(r"\bspecs?\s+" + NUM_LIST + r"(?:\s*,?\s*sections?\s+" + NUM_LIST + r")?", re.IGNORECASE),
    re.compile(r"\bsections?\s+" + NUM_LIST, re.IGNORECASE),
    # Step and rule numbers: step 1.1, rules 1 to 6.
    re.compile(r"\b(?:steps?|rules?)\s+" + NUM_LIST, re.IGNORECASE),
]


def strip_non_figures(line):
    """The line with every non-figure number removed."""
    line = ITEM.sub(" ", line, count=1)
    for pattern in NOT_FIGURES:
        line = pattern.sub(" ", line)
    return line


def has_figure(line):
    return bool(NUMBER.search(strip_non_figures(line)))


def blocks(lines):
    """Group lines outside code fences and headings into checkable blocks.

    Yields lists of (line number, text). A bullet or numbered item and its
    continuation lines form one block, a table row is a block of its own, and
    every other line is a block of its own.
    """
    in_fence = False
    item = None
    for number, text in enumerate(lines, start=1):
        if FENCE.match(text):
            in_fence = not in_fence
            if item:
                yield item
                item = None
            continue
        if in_fence or HEADING.match(text) or not text.strip():
            if item:
                yield item
                item = None
            continue
        if ITEM.match(text):
            if item:
                yield item
            item = [(number, text)]
        elif item and not text.lstrip().startswith("|"):
            item.append((number, text))
        else:
            if item:
                yield item
                item = None
            yield [(number, text)]
    if item:
        yield item


def check_lines(lines):
    """The (line number, text) of every line whose figure carries no label."""
    failures = []
    for block in blocks(lines):
        if any(NO_FIGURE in text for _, text in block):
            continue
        for number, text in block:
            if has_figure(text) and not LABEL.search(text):
                failures.append((number, text))
    return failures


def check_text(text):
    return check_lines(text.splitlines())


def check_file(path):
    with open(path, encoding="utf-8") as f:
        return check_text(f.read())


def main(argv=None):
    paths = sys.argv[1:] if argv is None else argv
    if not paths:
        print("usage: labels.py FILE...", file=sys.stderr)
        return 2
    failed = False
    for path in paths:
        for number, text in check_file(path):
            failed = True
            print(f"{path}:{number}: figure without a label: {text.strip()}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
