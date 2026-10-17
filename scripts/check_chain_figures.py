#!/usr/bin/env python3
"""Recomputes the chain figures in docs/benchmarks/results.md.

Python standard library only. It reads the tables of the sections on native
verification, private transactions per block, chain growth per year and the
cost of identical size and shape, takes the stated proof size and
verification time as given, and recomputes from them:

  1. seconds and blocks per year at 30-second blocks, and the verification
     budget (10 percent of the block interval);
  2. proofs verified within the budget;
  3. bytes per private transaction, private transactions per block and per
     second at each block size limit, and what each usage level needs;
  4. private transactions and bytes per year;
  5. the padding that an identical size costs, per transaction and per year.

Usage:
    python3 scripts/check_chain_figures.py [RESULTS_MD]

Exit status is non-zero on any mismatch, missing table or missing row.
"""

import sys
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path

DEFAULT_RESULTS = Path(__file__).resolve().parent.parent / "docs" / "benchmarks" / "results.md"

BLOCK_INTERVAL_S = 30
SECONDS_PER_YEAR = 365 * 24 * 3600              # 31,536,000
BLOCKS_PER_YEAR = SECONDS_PER_YEAR // BLOCK_INTERVAL_S   # 1,051,200
BUDGET_MS = BLOCK_INTERVAL_S * 1000 * 10 // 100          # 3,000
TB = Decimal(10) ** 12
GB = Decimal(10) ** 9

CANDIDATE = "keccak-256"
BLOWUPS = ("2^2", "2^3")
USAGES = ("0.1", "1", "10")                     # private transactions per second
LIMITS = {"1 MB": 1_000_000, "4 MB": 4_000_000, "16 MB": 16_000_000}

S_NATIVE = "Native verification on the chain"
S_SIZE = "Proof size and proving time"
S_BLOCK = "Private transactions per block"
S_GROWTH = "Chain growth per year"
S_SHAPE = "Cost of identical size and shape"


class Mismatch(Exception):
    pass


def sections(text):
    """Map each '## ' heading to the lines under it, up to the next one."""
    out, name = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            name = line[3:].strip()
            out[name] = []
        elif name is not None:
            out[name].append(line)
    return out


def tables(lines):
    """Every Markdown table in `lines` as (header, rows), rows as dicts."""
    found, block = [], []
    for line in lines + [""]:
        if line.startswith("|"):
            block.append([c.strip() for c in line.strip().strip("|").split("|")])
            continue
        if len(block) >= 2:
            header = block[0]
            rows = [dict(zip(header, cells)) for cells in block[2:]
                    if len(cells) == len(header)]
            if len(rows) != len(block) - 2:
                raise Mismatch(f"a table with columns {header} has a row of the wrong width")
            found.append((header, rows))
        block = []
    return found


def find_table(secs, section, columns):
    if section not in secs:
        raise Mismatch(f"section '## {section}' is missing")
    hits = [rows for header, rows in tables(secs[section]) if set(columns) <= set(header)]
    if len(hits) != 1:
        raise Mismatch(f"expected one table with columns {list(columns)} in '{section}', "
                       f"found {len(hits)}")
    return hits[0]


def keyed(rows, key_columns, expected_keys, what):
    """Index rows by their key columns; every expected key exactly once, no others."""
    out = {}
    for row in rows:
        key = tuple(row[c] for c in key_columns)
        if key in out:
            raise Mismatch(f"{what}: row {key} appears twice")
        out[key] = row
    missing = [k for k in expected_keys if k not in out]
    extra = [k for k in out if k not in expected_keys]
    if missing or extra:
        raise Mismatch(f"{what}: missing rows {missing}, unexpected rows {extra}")
    return out


def num(cell, what):
    try:
        return Decimal(cell.replace(",", "").rstrip("%").strip())
    except InvalidOperation:
        raise Mismatch(f"{what}: '{cell}' is not a number") from None


def floor_div(a, b):
    return int((Decimal(a) / Decimal(b)).to_integral_value(rounding=ROUND_FLOOR))


def rounded(value, places):
    return Decimal(value).quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)


class Checker:
    def __init__(self, text):
        self.secs = sections(text)
        self.failures = []

    def expect(self, row, column, expected, what):
        """Compare a table cell with the recomputed value."""
        cell = row.get(column)
        if cell is None:
            self.failures.append(f"{what}: no column '{column}'")
            return
        if isinstance(expected, str):
            ok = cell == expected
        else:
            try:
                ok = num(cell, what) == Decimal(expected)
            except Mismatch as e:
                self.failures.append(str(e))
                return
        if not ok:
            self.failures.append(f"{what}, '{column}': table says {cell}, recomputed {expected}")

    def run(self):
        try:
            self.check_all()
        except Mismatch as e:
            self.failures.append(str(e))
        return self.failures

    def check_all(self):
        # Constants
        rows = find_table(self.secs, S_BLOCK, ("Quantity", "Value"))
        const = keyed(rows, ("Quantity",), [
            ("Block interval (s)",), ("Seconds per year",), ("Blocks per year",),
            ("Verification budget (ms)",), ("Public inputs (bytes)",)], "constants")
        for name, value in (("Block interval (s)", BLOCK_INTERVAL_S),
                            ("Seconds per year", SECONDS_PER_YEAR),
                            ("Blocks per year", BLOCKS_PER_YEAR),
                            ("Verification budget (ms)", BUDGET_MS)):
            self.expect(const[(name,)], "Value", value, f"constants, {name}")
        public_inputs = int(num(const[("Public inputs (bytes)",)]["Value"], "public inputs"))

        # Stated measurements: the inputs of everything below.
        rows = find_table(self.secs, S_NATIVE, (
            "Candidate", "Blowup", "Verification median (ms)", "Verification largest (ms)",
            "Proof bytes median", "Proof bytes largest"))
        measured = {}
        for b in BLOWUPS:
            match = [r for r in rows if r["Candidate"] == CANDIDATE and r["Blowup"] == b]
            if len(match) != 1:
                raise Mismatch(f"native measurements: expected one {CANDIDATE} {b} row")
            r, what = match[0], f"native measurements {b}"
            measured[b] = dict(
                median_ms=num(r["Verification median (ms)"], what),
                largest_ms=num(r["Verification largest (ms)"], what),
                median_bytes=int(num(r["Proof bytes median"], what)),
                largest_bytes=int(num(r["Proof bytes largest"], what)))

        # Proof sizes repeated in the size section must match the measurements.
        rows = find_table(self.secs, S_SIZE, ("Candidate", "Blowup", "Proof bytes median"))
        for b in BLOWUPS:
            for r in rows:
                if r["Candidate"] == CANDIDATE and r["Blowup"] == b:
                    self.expect(r, "Proof bytes median", measured[b]["median_bytes"],
                                f"proof size table {b}")

        # Verification budget
        rows = find_table(self.secs, S_NATIVE, (
            "Candidate", "Blowup", "Statistic", "Verification time (ms)", "Budget (ms)",
            "Proofs verified in budget"))
        stats = ("median", "largest")
        budget = keyed(rows, ("Candidate", "Blowup", "Statistic"),
                       [(CANDIDATE, b, s) for b in BLOWUPS for s in stats], "verification budget")
        verify_fit = {}
        for b in BLOWUPS:
            for s in stats:
                t = measured[b][f"{s}_ms"]
                r, what = budget[(CANDIDATE, b, s)], f"verification budget {b} {s}"
                self.expect(r, "Verification time (ms)", t, what)
                self.expect(r, "Budget (ms)", BUDGET_MS, what)
                self.expect(r, "Proofs verified in budget", floor_div(BUDGET_MS, t), what)
            verify_fit[b] = floor_div(BUDGET_MS, measured[b]["median_ms"])

        tx_bytes = {b: measured[b]["largest_bytes"] + public_inputs for b in BLOWUPS}

        # Capacity of one block
        rows = find_table(self.secs, S_BLOCK, (
            "Candidate", "Blowup", "Bytes per private transaction", "Block size limit",
            "Limit (bytes)", "Fit by size", "Fit by verification budget",
            "Private transactions per block", "Private transactions per second"))
        cap_rows = keyed(rows, ("Candidate", "Blowup", "Block size limit"),
                         [(CANDIDATE, b, lim) for b in BLOWUPS for lim in LIMITS], "capacity")
        capacity = {}
        for b in BLOWUPS:
            for lim, limit_bytes in LIMITS.items():
                r, what = cap_rows[(CANDIDATE, b, lim)], f"capacity {b} {lim}"
                by_size = limit_bytes // tx_bytes[b]
                per_block = min(by_size, verify_fit[b])
                capacity[(b, lim)] = per_block
                self.expect(r, "Bytes per private transaction", tx_bytes[b], what)
                self.expect(r, "Limit (bytes)", limit_bytes, what)
                self.expect(r, "Fit by size", by_size, what)
                self.expect(r, "Fit by verification budget", verify_fit[b], what)
                self.expect(r, "Private transactions per block", per_block, what)
                self.expect(r, "Private transactions per second",
                            rounded(Decimal(per_block) / BLOCK_INTERVAL_S, 3), what)

        # Usage levels
        usage_col = "Usage (private transactions per second)"
        rows = find_table(self.secs, S_BLOCK, (
            "Candidate", "Blowup", usage_col, "Private transactions per block needed",
            "Bytes per block needed", "Verification time per block (ms)",
            "Within verification budget") + tuple(f"Fits {lim}" for lim in LIMITS))
        use_rows = keyed(rows, ("Candidate", "Blowup", usage_col),
                         [(CANDIDATE, b, u) for b in BLOWUPS for u in USAGES], "usage levels")
        needed = {}
        for u in USAGES:
            n = Decimal(u) * BLOCK_INTERVAL_S
            if n != n.to_integral_value():
                raise Mismatch(f"usage {u} per second is not a whole number per block")
            needed[u] = int(n)
        for b in BLOWUPS:
            for u in USAGES:
                r, what = use_rows[(CANDIDATE, b, u)], f"usage {b} {u}/s"
                block_bytes = needed[u] * tx_bytes[b]
                verify_ms = needed[u] * measured[b]["median_ms"]
                self.expect(r, "Private transactions per block needed", needed[u], what)
                self.expect(r, "Bytes per block needed", block_bytes, what)
                self.expect(r, "Verification time per block (ms)", verify_ms, what)
                for lim, limit_bytes in LIMITS.items():
                    self.expect(r, f"Fits {lim}", "yes" if block_bytes <= limit_bytes else "no",
                                what)
                self.expect(r, "Within verification budget",
                            "yes" if verify_ms <= BUDGET_MS else "no", what)

        # Chain growth per year
        rows = find_table(self.secs, S_GROWTH, (
            "Candidate", "Blowup", usage_col, "Block size limit",
            "Private transactions per block carried", "Private transactions per year",
            "Bytes per year", "TB per year"))
        limits = ("none",) + tuple(LIMITS)
        grow_rows = keyed(rows, ("Candidate", "Blowup", usage_col, "Block size limit"),
                          [(CANDIDATE, b, u, lim) for b in BLOWUPS for u in USAGES
                           for lim in limits], "chain growth")
        for b in BLOWUPS:
            for u in USAGES:
                for lim in limits:
                    r, what = grow_rows[(CANDIDATE, b, u, lim)], f"growth {b} {u}/s {lim}"
                    carried = needed[u] if lim == "none" else min(needed[u], capacity[(b, lim)])
                    per_year = carried * BLOCKS_PER_YEAR
                    year_bytes = per_year * tx_bytes[b]
                    self.expect(r, "Private transactions per block carried", carried, what)
                    self.expect(r, "Private transactions per year", per_year, what)
                    self.expect(r, "Bytes per year", year_bytes, what)
                    self.expect(r, "TB per year", rounded(year_bytes / TB, 2), what)

        # Cost of identical size: padding to the largest proof
        rows = find_table(self.secs, S_SHAPE, (
            "Candidate", "Blowup", "Proof bytes median", "Proof bytes largest",
            "Padding per transaction (bytes)", "Padding share of median"))
        pad_rows = keyed(rows, ("Candidate", "Blowup"),
                         [(CANDIDATE, b) for b in BLOWUPS], "padding")
        padding = {}
        for b in BLOWUPS:
            m = measured[b]
            r, what = pad_rows[(CANDIDATE, b)], f"padding {b}"
            padding[b] = m["largest_bytes"] - m["median_bytes"]
            self.expect(r, "Proof bytes median", m["median_bytes"], what)
            self.expect(r, "Proof bytes largest", m["largest_bytes"], what)
            self.expect(r, "Padding per transaction (bytes)", padding[b], what)
            self.expect(r, "Padding share of median",
                        rounded(Decimal(padding[b]) * 100 / m["median_bytes"], 2), what)

        rows = find_table(self.secs, S_SHAPE, (
            "Candidate", "Blowup", usage_col, "Private transactions per year",
            "Padding bytes per year", "Padding GB per year"))
        pad_year = keyed(rows, ("Candidate", "Blowup", usage_col),
                         [(CANDIDATE, b, u) for b in BLOWUPS for u in USAGES], "padding per year")
        for b in BLOWUPS:
            for u in USAGES:
                r, what = pad_year[(CANDIDATE, b, u)], f"padding per year {b} {u}/s"
                per_year = needed[u] * BLOCKS_PER_YEAR
                pad_bytes = per_year * padding[b]
                self.expect(r, "Private transactions per year", per_year, what)
                self.expect(r, "Padding bytes per year", pad_bytes, what)
                self.expect(r, "Padding GB per year", rounded(pad_bytes / GB, 2), what)


def check_text(text):
    """All mismatches found in the text of results.md (empty when it agrees)."""
    return Checker(text).run()


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_RESULTS
    failures = check_text(path.read_text(encoding="utf-8"))
    for f in failures:
        print("MISMATCH: " + f)
    if failures:
        print(f"{len(failures)} mismatch(es) in {path}")
        return 1
    print(f"Chain figures agree: {BLOCKS_PER_YEAR:,} blocks per year, "
          f"verification budget {BUDGET_MS:,} ms.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
