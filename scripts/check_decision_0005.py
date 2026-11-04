#!/usr/bin/env python3
"""Checks docs/decisions/0005-header-mmr.md.

Python standard library only. Keccak-256 and the vector-block reader are those
of scripts/check_decision_0004.py, whose own self test runs first. Then it
checks that:

  1. the record has one section for each item it must fix, each naming what it
     has to cover;
  2. this script's RLP encoder gives spec 05's header vectors byte for byte, so
     the headers it extends with field 23 are spec 05's;
  3. every vector block of the record (the empty MMR, the header leaf, the
     24-item example headers, a seven-leaf MMR with its paths, and a chain of
     five years of 30-second blocks with paths from genesis, the middle and the
     last block) is exactly what this script computes from the rules the
     record states;
  4. every path of the record is accepted for its header and gives the stated
     work before it and total work, and is rejected for any changed byte, at
     any other length, for another index, another leaf count, another
     difficulty and another root;
  5. the path sizes are those of the rule, at most floor(log2 n) + 1 entries,
     and at one and five years equal the stage 2 design's modeled path;
  6. the tag table rows give the right input bytes and permutation counts;
  7. the header field table places `headerMmrRoot` right after decision 0004's
     last field, and spec 05 and decision 0004 still end where the record says;
  8. the header size table gives the encoded sizes of spec 05's vectors and of
     the 24-item headers;
  9. no line of the record pairs specification 08 with a header field, and none
     states the stage 2 design's modeled header size as a size in bytes.

Usage:
    python3 scripts/check_decision_0005.py [RECORD_MD]
    python3 scripts/check_decision_0005.py --print

With --print it writes the vector blocks the record quotes. Exit status is
non-zero on any mismatch.
"""

import bisect
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import check_decision_0004 as d4  # noqa: E402
from check_decision_0004 import K, blocks, keccak256, permutations, render, sections, table_rows, tagbytes  # noqa: E402

ROOT = HERE.parent
DEFAULT_RECORD = ROOT / "docs" / "decisions" / "0005-header-mmr.md"
SPEC_05 = ROOT / "docs" / "spec" / "05-trees-and-headers.md"
DECISION_0004 = ROOT / "docs" / "decisions" / "0004-lookup-formats.md"

# ------------------------------------------------------- constants and tags

TAG_LEAF = "ghost/header-mmr-leaf/v1"
TAG_NODE = "ghost/header-mmr-node/v1"
TAG_BAG = "ghost/header-mmr-bag/v1"
TAG_ROOT = "ghost/header-mmr-root/v1"

HASH_BYTES = 32
WORK_BYTES = 16
COUNT_BYTES = 8
ENTRY_BYTES = HASH_BYTES + WORK_BYTES  # one path entry: a hash and its work
WORK_LIMIT = 2 ** (8 * WORK_BYTES)  # every work value, and the chain's total difficulty, stays below
COUNT_LIMIT = 2 ** (8 * COUNT_BYTES)

D_START = 2**24  # spec 06, section 4.5
BLOCKS_PER_DAY = 86400 // 30  # 30-second blocks, spec 06
ONE_YEAR = 365 * BLOCKS_PER_DAY
FIVE_YEARS = 5 * ONE_YEAR

# Tag -> (input bytes after the tag, use).
TAG_ROWS = {
    TAG_LEAF: HASH_BYTES + WORK_BYTES,
    TAG_NODE: 2 * ENTRY_BYTES,
    TAG_BAG: 2 * ENTRY_BYTES,
    TAG_ROOT: COUNT_BYTES + ENTRY_BYTES,
}

HEADER_FIELD = ("23", "headerMmrRoot")
LAST_0004_FIELD = ("22", "lookupDigest")
HEADER_ITEMS = 24

INT_FIELDS = {"difficulty", "number", "gasLimit", "gasUsed", "timestamp", "baseFee"}
HEADER_ROWS_SKIPPED = {"kind", "rlp", "hash", "valid"}

REQUIRED_SECTIONS = ("Decision", "Conventions", "Leaf", "Nodes, peaks and root", "Cumulative work",
                     "Path from a header to the tip", "Header field", "Header size",
                     "Reorganisation", "Specification 08 is not touched", "Tag table rows",
                     "Worked examples", "What the build ticket writes into the specifications",
                     "What this record does not settle", "What would reverse this decision",
                     "Reproduce")
# Words each section must use, so that its subject is covered.
SECTION_WORDS = {
    "Leaf": ("ghost/header-mmr-leaf/v1", "keccak256(rlp(header))", "difficulty", "16 bytes",
             "block number"),
    "Nodes, peaks and root": ("ghost/header-mmr-node/v1", "ghost/header-mmr-bag/v1",
                              "ghost/header-mmr-root/v1", "highest first", "right to left",
                              "n as 8 bytes", "empty"),
    "Cumulative work": ("16 bytes", "2^128", "total difficulty", "80 bits", "work before",
                        "work-overflow"),
    "Path from a header to the tip": ("48 bytes", "nearest first", "floor(log2 n) + 1",
                                      "1,104 bytes", "23 entries", "any other length",
                                      "key block", "tip"),
    "Header field": ("headerMmrRoot", "field 23", "24 items", "item-count", "23 items",
                     "decision 0004"),
    "Header size": ("780 bytes", "809 bytes", "582", "615", "747", "33 bytes",
                    "dataMarkerRoot", "38 bytes"),
    "Reorganisation": ("common ancestor", "canonical", "truncat"),
    "Specification 08 is not touched": ("RandomX", "seal hash", "spec 05"),
    "What this record does not settle": ("sampler", "difficulty rule", "not yet established"),
}
FORBIDDEN_LINE = re.compile(r"spec" + r"\s08.*header" + r"\sfield", re.IGNORECASE)
# The stage 2 design's modeled header size must not be restated as a size in bytes.
MODELED_SIZE_LINE = re.compile("74" + "2" + r".byte", re.IGNORECASE)

# ----------------------------------------------------------------- the MMR


def work_bytes(work):
    if not 0 <= work < WORK_LIMIT:
        raise ValueError("work-overflow")
    return work.to_bytes(WORK_BYTES, "big")


def leaf(header_hash, difficulty):
    """(hash, work) of the leaf of one header."""
    if len(header_hash) != HASH_BYTES:
        raise ValueError("header hash is not 32 bytes")
    return K(TAG_LEAF, header_hash, work_bytes(difficulty)), difficulty


def _pair(tag, left, right):
    work = left[1] + right[1]
    work_bytes(work)
    return K(tag, left[0], work_bytes(left[1]), right[0], work_bytes(right[1])), work


def node(left, right):
    return _pair(TAG_NODE, left, right)


def bag(peak, rest):
    return _pair(TAG_BAG, peak, rest)


EMPTY_BAG = (bytes(HASH_BYTES), 0)


def root_of(n, bagged):
    if not 0 <= n < COUNT_LIMIT:
        raise ValueError("leaf count out of range")
    return K(TAG_ROOT, n.to_bytes(COUNT_BYTES, "big"), bagged[0], work_bytes(bagged[1]))


def peaks(n):
    """(start, height) of each peak of an MMR of n leaves, highest first."""
    out, start = [], 0
    for height in range(n.bit_length() - 1, -1, -1):
        if n >> height & 1:
            out.append((start, height))
            start += 1 << height
    return out


def bag_peaks(peak_nodes):
    """Bag the peaks right to left: the last peak alone, then bag(peak, rest)."""
    if not peak_nodes:
        return EMPTY_BAG
    acc = peak_nodes[-1]
    for p in reversed(peak_nodes[:-1]):
        acc = bag(p, acc)
    return acc


def path_shape(n, i):
    """(peak number, peak start, peak height, entries) for leaf i of n, or None."""
    if not (0 < n < COUNT_LIMIT and 0 <= i < n):
        return None
    pk = peaks(n)
    for j, (start, height) in enumerate(pk):
        if start <= i < start + (1 << height):
            right = 1 if j < len(pk) - 1 else 0
            return j, start, height, height + right + j
    return None


class Mmr:
    """An MMR of n header leaves.

    `leaves` maps an index to (header hash, difficulty). Every other index below
    n holds `filler`, one example header repeated, so that a chain of millions
    of blocks is computed with a few hundred hashes: a subtree holding only the
    filler is the same at every start.
    """

    def __init__(self, n, leaves, filler=None):
        self.n = n
        self.leaves = dict(leaves)
        self.special = sorted(self.leaves)
        if filler is None and len(self.special) != n:
            raise ValueError("every leaf needs a header when there is no filler")
        self.filler = filler
        self.memo = {}
        self.filled = [leaf(*filler)] if filler else []

    def _filled(self, height):
        while len(self.filled) <= height:
            self.filled.append(node(self.filled[-1], self.filled[-1]))
        return self.filled[height]

    def subtree(self, start, height):
        key = (start, height)
        if key in self.memo:
            return self.memo[key]
        end = start + (1 << height)
        lo = bisect.bisect_left(self.special, start)
        if lo == len(self.special) or self.special[lo] >= end:
            out = self._filled(height)
        elif height == 0:
            out = leaf(*self.leaves[start])
        else:
            half = 1 << (height - 1)
            out = node(self.subtree(start, height - 1), self.subtree(start + half, height - 1))
        self.memo[key] = out
        return out

    def peak_nodes(self):
        return [self.subtree(s, h) for s, h in peaks(self.n)]

    def bagged(self):
        return bag_peaks(self.peak_nodes())

    def root(self):
        return root_of(self.n, self.bagged())

    def path(self, i):
        """The entries of the path of leaf i: siblings from the bottom, then the
        bag of the peaks to the right, then the peaks to the left, nearest first."""
        j, start, height, _count = path_shape(self.n, i)
        local = i - start
        entries = []
        for level in range(height):
            sibling = start + (((local >> level) ^ 1) << level)
            entries.append(self.subtree(sibling, level))
        nodes = self.peak_nodes()
        if j < len(nodes) - 1:
            entries.append(bag_peaks(nodes[j + 1:]))
        entries.extend(reversed(nodes[:j]))
        return entries

    def work_before(self, i):
        """The summed difficulty of leaves 0 to i - 1, counted leaf by leaf."""
        specials = [x for x in self.special if x < i]
        return sum(self.leaves[x][1] for x in specials) + (i - len(specials)) * (self.filler[1] if self.filler else 0)


def encode_path(entries):
    return b"".join(h + work_bytes(w) for h, w in entries)


def verify_path(path, n, i, header_hash, difficulty, root):
    """Fold a path. (work before the leaf, total work) if it reaches `root`, else None.

    `n` is the number of the header carrying `root` and `i` that of the sampled
    header; the path carries neither.
    """
    shape = path_shape(n, i)
    if shape is None or len(header_hash) != HASH_BYTES or len(root) != HASH_BYTES:
        return None
    j, start, height, count = shape
    if len(path) != ENTRY_BYTES * count:
        return None
    entries = [(path[k:k + HASH_BYTES], int.from_bytes(path[k + HASH_BYTES:k + ENTRY_BYTES], "big"))
               for k in range(0, len(path), ENTRY_BYTES)]
    try:
        cur = leaf(header_hash, difficulty)
        before = 0
        local = i - start
        for level in range(height):
            sibling = entries[level]
            if local >> level & 1:
                cur = node(sibling, cur)
                before += sibling[1]
            else:
                cur = node(cur, sibling)
        k = height
        if j < len(peaks(n)) - 1:
            cur = bag(cur, entries[k])
            k += 1
        for p in entries[k:]:
            cur = bag(p, cur)
            before += p[1]
        if root_of(n, cur) != root:
            return None
    except ValueError:
        return None
    return before, cur[1]

# ------------------------------------------------------------------- RLP


def rlp_string(b):
    if len(b) == 1 and b[0] < 0x80:
        return bytes(b)
    return _rlp_length(len(b), 0x80) + bytes(b)


def rlp_int(v):
    return rlp_string(v.to_bytes((v.bit_length() + 7) // 8, "big") if v else b"")


def rlp_list(items):
    body = b"".join(items)
    return _rlp_length(len(body), 0xC0) + body


def _rlp_length(n, offset):
    if n < 56:
        return bytes([offset + n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(raw)]) + raw


def header_fields(spec05, name, keep_mmr=False):
    """The fields of one of spec 05's header vectors, in order: (name, value).

    Without `keep_mmr`, a `headerMmrRoot` that spec 05 carries once the build
    ticket has written field 23 is left out, so the 23 fields of decision 0004
    are the base either way.
    """
    rows = blocks(spec05).get(name)
    if not rows:
        raise KeyError(f"spec 05 has no vector {name}")
    return [(f, v) for f, v in rows
            if f not in HEADER_ROWS_SKIPPED and (keep_mmr or f != HEADER_FIELD[1])]


def header_rlp(fields):
    return rlp_list([rlp_int(int(v)) if f in INT_FIELDS else rlp_string(bytes.fromhex(v))
                     for f, v in fields])


def with_mmr(fields, mmr_root, parent=None):
    out = [(f, parent.hex() if f == "parentHash" and parent is not None else v) for f, v in fields]
    return out + [(HEADER_FIELD[1], mmr_root.hex())]

# --------------------------------------------------------------- vectors


def entry_line(e):
    return f"{e[0].hex()} {work_bytes(e[1]).hex()}"


def mmr_rows(m, names):
    rows = [("kind", "header-mmr"), ("n", str(m.n))]
    if m.filler:
        rows.append(("filler", f"{m.filler[0].hex()} {work_bytes(m.filler[1]).hex()}"))
    for idx in m.special:
        hh, d = m.leaves[idx]
        label = names.get(idx, "example")
        rows.append((f"leaf-{idx}", f"{label} {hh.hex()} {work_bytes(d).hex()} {leaf(hh, d)[0].hex()}"))
    for (start, height), p in zip(peaks(m.n), m.peak_nodes()):
        rows.append((f"peak-{start}-{height}", entry_line(p)))
    rows.append(("bag", entry_line(m.bagged())))
    rows.append(("root", m.root().hex()))
    rows.append(("total-work", str(m.bagged()[1])))
    return rows


def path_rows(m, mmr_name, i, reject_index):
    entries = m.path(i)
    hh, d = m.leaves[i]
    path = encode_path(entries)
    before, total = verify_path(path, m.n, i, hh, d, m.root())
    return [("kind", "header-mmr-path"), ("mmr", mmr_name), ("n", str(m.n)), ("index", str(i)),
            ("header-hash", hh.hex()), ("difficulty", str(d)), ("root", m.root().hex()),
            ("entries", str(len(entries))), ("bytes", str(len(path))), ("path", path.hex()),
            ("work-before", str(before)), ("total-work", str(total)),
            ("reject-index", str(reject_index))]


def path_size_rows(n, label):
    pk = peaks(n)
    counts = [path_shape(n, s)[3] for s, _h in pk]
    return [("kind", "header-mmr-path-size"), ("chain", label), ("n", str(n)),
            ("peak-heights", " ".join(str(h) for _s, h in pk)),
            ("entries-by-peak", " ".join(str(c) for c in counts)),
            ("most-entries", str(max(counts))), ("most-bytes", str(ENTRY_BYTES * max(counts)))]


def example_headers(spec05):
    """The genesis and block one examples of spec 05 with field 23 added."""
    g23 = header_fields(spec05, "header-genesis-example")
    b23 = header_fields(spec05, "header-block-one-example")
    g_root = root_of(0, EMPTY_BAG)
    g24 = with_mmr(g23, g_root)
    g_rlp = header_rlp(g24)
    g_hash = keccak256(g_rlp)
    g_diff = int(dict(g24)["difficulty"])
    one = Mmr(1, {0: (g_hash, g_diff)})
    b24 = with_mmr(b23, one.root(), parent=g_hash)
    b_rlp = header_rlp(b24)
    b_hash = keccak256(b_rlp)
    b_diff = int(dict(b24)["difficulty"])
    return {"genesis": (g24, g_rlp, g_hash, g_diff), "one": (b24, b_rlp, b_hash, b_diff), "mmr-one": one}


def size_of(spec05, name):
    return len(bytes.fromhex(dict(blocks(spec05)[name])["rlp"]))


def header_sizes(spec05):
    ex = example_headers(spec05)
    return {
        "block-one-18": size_of(spec05, "header-eighteen-items"),
        "block-one-19": size_of(spec05, "header-nineteen-items"),
        "block-one-23": size_of(spec05, "header-block-one-example"),
        "block-one-24": len(ex["one"][1]),
        "genesis-23": size_of(spec05, "header-genesis-example"),
        "genesis-24": len(ex["genesis"][1]),
    }


SEVEN_EXAMPLES = {j: (bytes([0x11 * j]) * HASH_BYTES, D_START + 65536 * j) for j in range(2, 7)}
FIVE_YEAR_FILLER = (bytes([0xEE]) * HASH_BYTES, D_START)
FIVE_YEAR_MIDDLE = 4_200_000
FIVE_YEAR_EXAMPLES = {FIVE_YEAR_MIDDLE: (bytes([0x5A]) * HASH_BYTES, 2**25),
                      FIVE_YEARS - 1: (bytes([0x5B]) * HASH_BYTES, 2**26)}


def seven_leaf_mmr(spec05):
    ex = example_headers(spec05)
    leaves = {0: (ex["genesis"][2], ex["genesis"][3]), 1: (ex["one"][2], ex["one"][3])}
    leaves.update(SEVEN_EXAMPLES)
    return Mmr(7, leaves)


def five_year_mmr(spec05):
    ex = example_headers(spec05)
    leaves = {0: (ex["genesis"][2], ex["genesis"][3]), 1: (ex["one"][2], ex["one"][3])}
    leaves.update(FIVE_YEAR_EXAMPLES)
    return Mmr(FIVE_YEARS, leaves, FIVE_YEAR_FILLER)


NAMES = {0: "header-genesis-with-mmr", 1: "header-block-one-with-mmr"}


def compute(spec05):
    """The record's vector blocks, computed: name -> list of (field, value)."""
    out = {}
    ex = example_headers(spec05)
    out["header-mmr-empty"] = [("kind", "header-mmr"), ("n", "0"), ("bag", entry_line(EMPTY_BAG)),
                               ("root", root_of(0, EMPTY_BAG).hex()), ("total-work", "0")]
    g24, g_rlp, g_hash, g_diff = ex["genesis"]
    out["header-genesis-with-mmr"] = [
        ("kind", "header-with-mmr"), ("base", "header-genesis-example"),
        ("headerMmrRoot", dict(g24)[HEADER_FIELD[1]]), ("items", str(len(g24))),
        ("bytes", str(len(g_rlp))), ("rlp", g_rlp.hex()), ("hash", g_hash.hex())]
    lf = leaf(g_hash, g_diff)
    out["header-mmr-leaf-genesis"] = [
        ("kind", "header-mmr-leaf"), ("header", "header-genesis-with-mmr"),
        ("header-hash", g_hash.hex()), ("difficulty", str(g_diff)), ("work", work_bytes(g_diff).hex()),
        ("input", (tagbytes(TAG_LEAF) + g_hash + work_bytes(g_diff)).hex()), ("leaf", lf[0].hex())]
    out["header-mmr-one-leaf"] = mmr_rows(ex["mmr-one"], NAMES)
    b24, b_rlp, b_hash, _b_diff = ex["one"]
    out["header-block-one-with-mmr"] = [
        ("kind", "header-with-mmr"), ("base", "header-block-one-example"),
        ("parentHash", dict(b24)["parentHash"]), ("headerMmrRoot", dict(b24)[HEADER_FIELD[1]]),
        ("items", str(len(b24))), ("bytes", str(len(b_rlp))), ("rlp", b_rlp.hex()), ("hash", b_hash.hex())]

    seven = seven_leaf_mmr(spec05)
    out["header-mmr-seven-leaves"] = mmr_rows(seven, NAMES)
    for i, other in ((0, 1), (4, 5), (6, 5)):
        out[f"header-mmr-path-seven-{i}"] = path_rows(seven, "header-mmr-seven-leaves", i, other)

    five = five_year_mmr(spec05)
    out["header-mmr-five-years"] = mmr_rows(five, NAMES)
    for label, i, other in (("genesis", 0, 1), ("middle", FIVE_YEAR_MIDDLE, FIVE_YEAR_MIDDLE + 1),
                            ("last", FIVE_YEARS - 1, FIVE_YEARS - 2)):
        out[f"header-mmr-path-five-years-{label}"] = path_rows(five, "header-mmr-five-years", i, other)
    out["header-mmr-path-size-one-year"] = path_size_rows(ONE_YEAR, "one year")
    out["header-mmr-path-size-five-years"] = path_size_rows(FIVE_YEARS, "five years")

    sizes = header_sizes(spec05)
    out["header-sizes"] = [("kind", "header-size")] + [(k, str(v)) for k, v in sizes.items()]
    return out

# ----------------------------------------------------------- the checks


def check_rlp_against_spec05(spec05):
    """The RLP encoder here gives spec 05's two positive header vectors."""
    failures = []
    for name in ("header-genesis-example", "header-block-one-example"):
        rows = dict(blocks(spec05).get(name, []))
        if not rows:
            failures.append(f"spec 05 has no vector {name}")
            continue
        enc = header_rlp(header_fields(spec05, name, keep_mmr=True))
        if enc.hex() != rows["rlp"]:
            failures.append(f"the RLP encoder differs from spec 05 at {name}")
        if keccak256(enc).hex() != rows["hash"]:
            failures.append(f"the header hash differs from spec 05 at {name}")
        if len(header_fields(spec05, name)) != HEADER_ITEMS - 1:
            failures.append(f"spec 05's {name} does not have the {HEADER_ITEMS - 1} fields of decision 0004")
    return failures


def flipped(b):
    positions = sorted({0, 31, 32, 47, len(b) // 2, len(b) - 17, len(b) - 1})
    return [b[:p] + bytes([b[p] ^ 1]) + b[p + 1:] for p in positions if 0 <= p < len(b)]


def check_paths(vectors):
    """Every path is accepted for what it shows and rejected otherwise."""
    failures = []
    for name, rows in vectors.items():
        v = dict(rows)
        if v.get("kind") != "header-mmr-path":
            continue
        path, hh, root = (bytes.fromhex(v[k]) for k in ("path", "header-hash", "root"))
        n, i, d = int(v["n"]), int(v["index"]), int(v["difficulty"])
        want = (int(v["work-before"]), int(v["total-work"]))
        if verify_path(path, n, i, hh, d, root) != want:
            failures.append(f"{name}: not accepted with work before {want[0]} and total {want[1]}")
        for bad in flipped(path) + [path[:-1], path + b"\0", path[:-ENTRY_BYTES], path + path[-ENTRY_BYTES:]]:
            if verify_path(bad, n, i, hh, d, root) is not None:
                failures.append(f"{name}: a changed path is accepted")
                break
        other = int(v["reject-index"])
        if verify_path(path, n, other, hh, d, root) is not None:
            failures.append(f"{name}: accepted at index {other}")
        if verify_path(path, n + 1, i, hh, d, root) is not None or verify_path(path, n - 1, i, hh, d, root) is not None:
            failures.append(f"{name}: accepted for another leaf count")
        if verify_path(path, n, i, hh, d + 1, root) is not None:
            failures.append(f"{name}: accepted for another difficulty")
        if any(verify_path(path, n, i, b, d, root) is not None for b in flipped(hh)):
            failures.append(f"{name}: accepted for another header")
        if verify_path(path, n, i, hh, d, bytes(32)) is not None:
            failures.append(f"{name}: accepted against another root")
        if int(v["entries"]) != path_shape(n, i)[3] or int(v["bytes"]) != len(path):
            failures.append(f"{name}: entries or bytes are not those of the rule")
    return failures


def check_sizes(vectors):
    failures = []
    for name in ("header-mmr-path-size-one-year", "header-mmr-path-size-five-years"):
        v = dict(vectors[name])
        n = int(v["n"])
        most = int(v["most-entries"])
        if most > n.bit_length():  # floor(log2 n) + 1
            failures.append(f"{name}: {most} entries, more than floor(log2 n) + 1")
        # The stage 2 design models a path as ceil(log2 n) nodes of 48 bytes.
        modeled = (n - 1).bit_length() * ENTRY_BYTES
        if int(v["most-bytes"]) != modeled:
            failures.append(f"{name}: {v['most-bytes']} bytes, not the modeled {modeled}")
    v = dict(vectors["header-mmr-path-five-years-genesis"])
    if int(v["entries"]) != int(dict(vectors["header-mmr-path-size-five-years"])["most-entries"]):
        failures.append("the five-year genesis path is not the deepest path of the chain")
    return failures


def check_work_sums(spec05, vectors):
    """Work before and total work, as the paths give them, against a leaf-by-leaf sum."""
    failures = []
    mmrs = {"header-mmr-seven-leaves": seven_leaf_mmr(spec05), "header-mmr-five-years": five_year_mmr(spec05)}
    for name, rows in vectors.items():
        v = dict(rows)
        if v.get("kind") != "header-mmr-path":
            continue
        m = mmrs[v["mmr"]]
        if int(v["work-before"]) != m.work_before(int(v["index"])):
            failures.append(f"{name}: work before is not the sum of the earlier difficulties")
        if int(v["total-work"]) != m.work_before(m.n):
            failures.append(f"{name}: total work is not the sum of every difficulty")
    return failures


def check_header_fields(text, spec05, d0004):
    failures = []
    secs = sections(text)
    hrows = [r for r in table_rows(secs.get("Header field", "")) if r and r[0].isdigit()]
    got = [(r[0], r[1].strip("`")) for r in hrows]
    if got != [HEADER_FIELD]:
        failures.append(f"header field table is {got}, not {[HEADER_FIELD]}")
    for r in hrows:
        if len(r) < 3 or r[2] != "32 bytes":
            failures.append(f"header field {r[1]} is not 32 bytes")
    spec_rows = [(r[0], r[1].strip("`")) for r in table_rows(spec05)
                 if len(r) == 4 and r[0].isdigit() and r[1].startswith("`")]
    if LAST_0004_FIELD not in spec_rows:
        failures.append("spec 05 no longer has lookupDigest as field 22")
    for idx, fname in spec_rows:
        if int(idx) > 22 and (idx, fname) != HEADER_FIELD:
            failures.append(f"spec 05 field {idx} {fname} disagrees with this record")
    d4_secs = sections(d0004)
    d4_rows = [(r[0], r[1].strip("`")) for r in table_rows(d4_secs.get("Header fields", "")) if r and r[0].isdigit()]
    if not d4_rows or d4_rows[-1] != LAST_0004_FIELD:
        failures.append(f"decision 0004's last header field is not {LAST_0004_FIELD}")
    return failures


def check_size_table(text, sizes):
    """The 'Header size' table: each row's bytes are the computed size."""
    failures = []
    body = sections(text).get("Header size", "")
    rows = [r for r in table_rows(body) if len(r) >= 3 and r[0].startswith("`")]
    have = {r[0].strip("`"): r[2] for r in rows}
    for key, size in sizes.items():
        if have.get(key) != f"{size:,}":
            failures.append(f"header size table: {key} is {have.get(key)}, not {size:,}")
    return failures


def check_tag_table(text):
    failures = []
    secs = sections(text)
    rows = {r[0].strip("`"): r for r in table_rows(secs.get("Tag table rows", "")) if r and r[0].startswith("`")}
    for tag, inputs in TAG_ROWS.items():
        row = rows.get(tag)
        if row is None:
            failures.append(f"tag table: no row for {tag}")
            continue
        total = len(tagbytes(tag)) + inputs
        want_perm = str(permutations(total)) + (" per level" if tag == TAG_NODE else "")
        if row[1] != "Keccak-256":
            failures.append(f"tag table: {tag} hash is {row[1]}, not Keccak-256")
        if row[4] != str(total):
            failures.append(f"tag table: {tag} input bytes {row[4]}, not {total}")
        if row[5] != want_perm:
            failures.append(f"tag table: {tag} permutations {row[5]}, not {want_perm}")
    for tag in rows:
        if tag not in TAG_ROWS:
            failures.append(f"tag table: {tag} is not a tag of this record")
    return failures


def check_text(text, spec05=None, d0004=None):
    spec05 = spec05 if spec05 is not None else SPEC_05.read_text(encoding="utf-8")
    d0004 = d0004 if d0004 is not None else DECISION_0004.read_text(encoding="utf-8")
    failures = []
    secs = sections(text)
    for title in REQUIRED_SECTIONS:
        if title not in secs:
            failures.append(f"missing section: {title}")
    for title, words in SECTION_WORDS.items():
        body = secs.get(title, "").lower()
        for word in words:
            if word.lower() not in body:
                failures.append(f"section {title}: does not say {word!r}")

    for n, line in enumerate(text.splitlines(), 1):
        if FORBIDDEN_LINE.search(line):
            failures.append(f"line {n} pairs specification 08 with a header field")
        if MODELED_SIZE_LINE.search(line):
            failures.append(f"line {n} states the stage 2 design's modeled header size in bytes")

    rlp_failures = check_rlp_against_spec05(spec05)
    if rlp_failures:
        return failures + rlp_failures

    vectors = compute(spec05)
    found = blocks(text)
    for name, rows in vectors.items():
        if name not in found:
            failures.append(f"missing vector {name}")
        elif found[name] != rows:
            have = dict(found[name])
            bad = [f for f, v in rows if have.get(f) != v] or ["field order"]
            failures.append(f"vector {name}: {', '.join(bad)} differ")
    for name in found:
        if name not in vectors:
            failures.append(f"vector {name} is not one this script computes")

    failures += check_tag_table(text)
    failures += check_header_fields(text, spec05, d0004)
    failures += check_size_table(text, header_sizes(spec05))
    for size, what in ((ENTRY_BYTES, "path entry"),):
        if f"{size} bytes" not in text:
            failures.append(f"the record does not state the {what} size, {size} bytes")
    failures += check_paths(vectors)
    failures += check_work_sums(spec05, vectors)
    failures += check_sizes(vectors)
    return failures


def main(argv):
    failures = d4.self_test()
    if failures:
        print("\n".join(failures))
        return 1
    spec05 = SPEC_05.read_text(encoding="utf-8")
    if argv[1:2] == ["--print"]:
        sys.stdout.write(render(compute(spec05)))
        return 0
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_RECORD
    failures = check_text(path.read_text(encoding="utf-8"), spec05)
    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"{path.name}: every section, vector, path and table agrees")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
