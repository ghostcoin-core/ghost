"""Check that every figure in a markdown file carries a label.

A line outside code fences and headings that carries a figure must also say
"measured", "modeled" or "not yet established" (in any case), or belong to a
table row or bullet marked with the HTML comment ``<!-- no-figure -->``.

A figure is any digit left on the line after removing what is not a quantity:
spec and section references, dates, file names and paths, version strings,
"step" or "rule" followed by a number, and the marker of a numbered list item.

Usage: python3 benchmarks/scale/labels.py FILE...
Exits 1 and prints each offending line when a file fails.

With ``--obligations`` it checks instead that a page holds the five proof
obligations of the whole-bundle security bound, in a table whose header names
an "Obligation" column, a "Status" column and a column of what discharges or
would close it (its header says "close"):

1. recursion with the hash inside the circuit;
2. extraction over three layers;
3. round-by-round soundness of the Plonky3 IOP;
4. theorem numbers;
5. a published analysis of Poseidon2 over BabyBear width 24.

Each obligation has exactly one row, every row is one of them, and each row's
status is exactly one word, ``discharged`` or ``open``. A discharged row names
a theorem and its number (Theorem, Lemma, Corollary or Proposition followed by
its number); an open row says what would close it, starting
"Would close it:".

Usage: python3 benchmarks/scale/labels.py --obligations FILE...
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


# --------------------------------------------------------------------------
# Proof obligations.

# Each obligation and the patterns its row's first cell must all match.
OBLIGATIONS = [
    ("recursion with the hash inside the circuit",
     [r"\brecursion\b", r"\bhash\b.*\binside\b.*\bcircuit\b"]),
    ("extraction over three layers", [r"\bextraction\b", r"\bthree\s+layers\b"]),
    ("round-by-round soundness of the Plonky3 IOP",
     [r"\bround-by-round\s+soundness\b", r"\bplonky3\b", r"\biop\b"]),
    ("theorem numbers", [r"\btheorem\s+numbers\b"]),
    ("a published analysis of Poseidon2 over BabyBear width 24",
     [r"\bpublished\s+analysis\b", r"\bposeidon2\b", r"\bbabybear\b", r"\bwidth\s+24\b"]),
]
STATUSES = ("discharged", "open")
THEOREM = re.compile(r"\b(?:theorem|lemma|corollary|proposition)\s+\d+(?:\.\d+)*\b", re.IGNORECASE)
WOULD_CLOSE = re.compile(r"^would close it:\s*\S", re.IGNORECASE)
TABLE_ROW = re.compile(r"^\s*\|")
SEPARATOR = re.compile(r"^\s*\|(?:\s*:?-+:?\s*\|)+\s*$")


def cells(line):
    """The cells of a table row, stripped."""
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    return [c.strip() for c in text.split("|")]


def plain(cell):
    """A cell without emphasis, code marks or the no-figure marker."""
    return re.sub(r"[*`_]", "", cell.replace(NO_FIGURE, "")).strip()


def tables(lines):
    """Every table: a list of (line number, text) of consecutive table rows."""
    found = []
    current = []
    for number, text in enumerate(lines, start=1):
        if TABLE_ROW.match(text):
            current.append((number, text))
        elif current:
            found.append(current)
            current = []
    if current:
        found.append(current)
    return found


def obligations_table(lines):
    """The obligations table and its status and closing columns, or None."""
    for table in tables(lines):
        header = [plain(c).lower() for c in cells(table[0][1])]
        if not header or header[0] != "obligation" or "status" not in header:
            continue
        closing = [i for i, h in enumerate(header) if "close" in h]
        if not closing:
            continue
        return table, header.index("status"), closing[0]
    return None


def check_obligation_lines(lines):
    """The (line number, problem) of every way the page's obligations fail."""
    found = obligations_table(lines)
    if found is None:
        return [(0, "no obligations table (columns Obligation, Status and what would close it)")]
    table, status_col, close_col = found
    failures = []
    seen = {name: [] for name, _ in OBLIGATIONS}
    for number, text in table[1:]:
        if SEPARATOR.match(text):
            continue
        row = cells(text)
        name = plain(row[0]) if row else ""
        matches = [o for o, patterns in OBLIGATIONS
                   if all(re.search(p, name, re.IGNORECASE) for p in patterns)]
        if len(matches) != 1:
            failures.append((number, f"not one of the five obligations: {name}"))
            continue
        seen[matches[0]].append(number)
        status = plain(row[status_col]).lower() if status_col < len(row) else ""
        if status not in STATUSES:
            failures.append((number, f"status must be exactly one of discharged or open, not {status!r}"))
            continue
        closing = plain(row[close_col]) if close_col < len(row) else ""
        if status == "discharged" and not THEOREM.search(closing):
            failures.append((number, "discharged without a theorem and its number"))
        if status == "open" and not WOULD_CLOSE.match(closing):
            failures.append((number, "open without what would close it (\"Would close it: ...\")"))
    for name, rows in seen.items():
        if not rows:
            failures.append((table[0][0], f"missing obligation: {name}"))
        elif len(rows) > 1:
            failures.append((rows[1], f"obligation listed more than once: {name}"))
    return failures


def check_obligations_file(path):
    with open(path, encoding="utf-8") as f:
        return check_obligation_lines(f.read().splitlines())


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    obligations = bool(args) and args[0] == "--obligations"
    paths = args[1:] if obligations else args
    if not paths:
        print("usage: labels.py [--obligations] FILE...", file=sys.stderr)
        return 2
    failed = False
    for path in paths:
        if obligations:
            for number, problem in check_obligations_file(path):
                failed = True
                print(f"{path}:{number}: {problem}")
            continue
        for number, text in check_file(path):
            failed = True
            print(f"{path}:{number}: figure without a label: {text.strip()}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
