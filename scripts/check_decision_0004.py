#!/usr/bin/env python3
"""Checks docs/decisions/0004-lookup-formats.md.

Python standard library only. The script has its own Keccak-256 and checks it
against known digests and, with the SHA3 padding, against hashlib.sha3_256.
Then it checks that:

  1. the record has one section for each item it must fix;
  2. its indexed-tree code is the construction of spec 05, section 6: rebuilt
     with the data marker-set tags, it gives spec 05's marker-set roots and
     its absence witness byte for byte;
  3. every vector block of the record (lookup tags, lookup index roots and
     witnesses, coin marker-set roots and witnesses, block lookup digests and
     the genesis values of the new header fields) is exactly what this script
     computes from the rules the record states, with the inputs taken from
     spec 01's vectors;
  4. every witness of the record is accepted for what it shows and rejected
     for the values the record lists, for any changed byte and at any other
     length;
  5. the tag table rows give the right input bytes and permutation counts,
     and the witness sizes the record states are the computed ones;
  6. the header field table places the four new fields right after spec 05's
     current fields, in the stated order;
  7. no line of the record pairs specification 08 with a header field.

Usage:
    python3 scripts/check_decision_0004.py [RECORD_MD]
    python3 scripts/check_decision_0004.py --print

With --print it writes the vector blocks the record quotes. Exit status is
non-zero on any mismatch.
"""

import hashlib
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_RECORD = ROOT / "docs" / "decisions" / "0004-lookup-formats.md"
SPEC_01 = ROOT / "docs" / "spec" / "01-commitments-and-keys.md"
SPEC_05 = ROOT / "docs" / "spec" / "05-trees-and-headers.md"

# ---------------------------------------------------------------- Keccak-256

MASK = (1 << 64) - 1


def _rol(a, n):
    n %= 64
    return ((a << n) | (a >> (64 - n))) & MASK


def _keccak_f(lanes):
    r = 1
    for _ in range(24):
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        lanes = [[lanes[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        x, y = 1, 0
        current = lanes[x][y]
        for t in range(24):
            x, y = y, (2 * x + 3 * y) % 5
            current, lanes[x][y] = lanes[x][y], _rol(current, (t + 1) * (t + 2) // 2)
        for y in range(5):
            row = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                lanes[0][0] ^= 1 << ((1 << j) - 1)
    return lanes


def _sponge(data, delimiter):
    rate = 136
    msg = bytearray(data) + bytes([delimiter])
    msg += bytes((-len(msg)) % rate)
    msg[-1] ^= 0x80
    lanes = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            lanes[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        lanes = _keccak_f(lanes)
    out = b"".join(lanes[i % 5][i // 5].to_bytes(8, "little") for i in range(rate // 8))
    return out[:32]


def keccak256(data):
    return _sponge(data, 0x01)


def tagbytes(tag):
    raw = tag.encode("ascii")
    return bytes([len(raw)]) + raw


def K(tag, *parts):
    return keccak256(tagbytes(tag) + b"".join(parts))


def S(tag, *parts):
    return hashlib.sha3_256(tagbytes(tag) + b"".join(parts)).digest()


def permutations(n_bytes):
    return n_bytes // 136 + 1


def self_test():
    failures = []
    known = {b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
             b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"}
    for msg, digest in known.items():
        if keccak256(msg).hex() != digest:
            failures.append(f"keccak-256 of {msg!r} is wrong")
    for n in (0, 1, 135, 136, 137, 300):
        msg = bytes(i % 256 for i in range(n))
        if _sponge(msg, 0x06) != hashlib.sha3_256(msg).digest():
            failures.append(f"the sponge with SHA3 padding differs from hashlib at {n} bytes")
    return failures

# ------------------------------------------------------- constants and tags

TAG_EMPTY_LEAF = "ghost/empty-leaf/v1"
TAG_NOTE_LOOKUP = "ghost/note-lookup/v1"
TAG_COIN_LOOKUP_LEAF = "ghost/coin-lookup-leaf/v1"
TAG_COIN_LOOKUP_NODE = "ghost/coin-lookup-node/v1"
TAG_DATA_LOOKUP_LEAF = "ghost/data-lookup-leaf/v1"
TAG_DATA_LOOKUP_NODE = "ghost/data-lookup-node/v1"
TAG_COIN_SET_LEAF = "ghost/coin-marker-set-leaf/v1"
TAG_COIN_SET_NODE = "ghost/coin-marker-set-node/v1"
TAG_DATA_SET_LEAF = "ghost/data-marker-set-leaf/v1"
TAG_DATA_SET_NODE = "ghost/data-marker-set-node/v1"
TAG_DIGEST = "ghost/block-lookup-digest/v1"

DEPTH = 40
POS_BYTES = 5
LOOKUP_TAG_BYTES = 16
MARKER_BYTES = 32
COUNT_BYTES = 4
NONE_POSITION = 2**40 - 1  # ff ff ff ff ff: "no appended leaf"
LEAVES_PER_TREE = 2**32
# tag, position, nextTag, nextPosition, nextIndex
LOOKUP_LEAF_BYTES = LOOKUP_TAG_BYTES + POS_BYTES + LOOKUP_TAG_BYTES + POS_BYTES + POS_BYTES
# value, nextValue, nextIndex, appended
COIN_SET_LEAF_BYTES = MARKER_BYTES + MARKER_BYTES + POS_BYTES + POS_BYTES
LOOKUP_WITNESS_BYTES = LOOKUP_LEAF_BYTES + POS_BYTES + 32 * DEPTH
COIN_SET_WITNESS_BYTES = COIN_SET_LEAF_BYTES + POS_BYTES + 32 * DEPTH

# Tag -> (hash, input bytes after the tag, or None when variable).
TAG_ROWS = {
    TAG_NOTE_LOOKUP: ("SHA3-256", 32 + 8),
    TAG_COIN_LOOKUP_LEAF: ("Keccak-256", LOOKUP_LEAF_BYTES),
    TAG_COIN_LOOKUP_NODE: ("Keccak-256", 1 + 32 + 32),
    TAG_DATA_LOOKUP_LEAF: ("Keccak-256", LOOKUP_LEAF_BYTES),
    TAG_DATA_LOOKUP_NODE: ("Keccak-256", 1 + 32 + 32),
    TAG_COIN_SET_LEAF: ("Keccak-256", COIN_SET_LEAF_BYTES),
    TAG_COIN_SET_NODE: ("Keccak-256", 1 + 32 + 32),
    TAG_DIGEST: ("Keccak-256", None),
}

HEADER_FIELDS = (("19", "coinLookupRoot"), ("20", "dataLookupRoot"),
                 ("21", "coinMarkerRoot"), ("22", "lookupDigest"))
SPEC_05_LAST = ("18", "dataMarkerRoot")

REQUIRED_SECTIONS = ("Decision", "Conventions", "Lookup tag", "Lookup index trees",
                     "Coin spent-marker set tree", "Header fields", "Block lookup digest",
                     "Proofs of holding, rollover and reorganisation",
                     "Specification 08 is not touched", "Tag table rows", "Worked examples",
                     "What the build ticket writes into the specifications",
                     "What would reverse this decision", "Reproduce")
# Words each section must use, so that its subject is covered.
SECTION_WORDS = {
    "Lookup tag": ("ghost/note-lookup/v1", "k_note", "8 bytes", "first 16 bytes",
                   "remainder_tag", "claim", "not an input", "16 zero bytes"),
    "Lookup index trees": ("sentinel", "position", "nextIndex", "copied tag",
                           "membership witness", "lookup witness", "absent", "first entry",
                           "1,332 bytes", "spec 05, section 6"),
    "Coin spent-marker set tree": ("appended", "none", "ff ff ff ff ff", "1,359 bytes",
                                   "membership witness", "absence witness"),
    "Header fields": ("coinLookupRoot", "dataLookupRoot", "coinMarkerRoot", "lookupDigest",
                      "2026-10-25", "superseded", "23 items"),
    "Block lookup digest": ("transaction order", "count", "ghost/block-lookup-digest/v1",
                            "lookupDigest"),
    "Proofs of holding, rollover and reorganisation": ("constraint 4", "stay rejected",
                                                       "rollover", "canonical",
                                                       "disconnected block", "absent"),
    "Specification 08 is not touched": ("RandomX", "spec 05"),
}
FORBIDDEN_LINE = re.compile(r"spec" + r"\s08.*header" + r"\sfield", re.IGNORECASE)

# ------------------------------------------------------------ indexed trees

EMPTY_LEAF = K(TAG_EMPTY_LEAF)


def zeros(node_tag):
    z = [EMPTY_LEAF]
    for level in range(DEPTH):
        z.append(K(node_tag, bytes([level]), z[level], z[level]))
    return z


class IndexedTree:
    """An append-only indexed tree of depth 40, as spec 05, section 6 builds it.

    `kind` is "lookup" (leaf: tag, position, nextTag, nextPosition, nextIndex),
    "coin-set" (leaf: value, nextValue, nextIndex, appended) or "data-set"
    (leaf: value, nextValue, nextIndex, spec 05's own).
    """

    def __init__(self, kind, leaf_tag, node_tag):
        self.kind = kind
        self.leaf_tag = leaf_tag
        self.node_tag = node_tag
        self.z = zeros(node_tag)
        if kind == "lookup":
            self.leaves = [(bytes(16), bytes(5), bytes(16), bytes(5), bytes(5))]
        elif kind == "coin-set":
            self.leaves = [(bytes(32), bytes(32), bytes(5), NONE_POSITION.to_bytes(5, "big"))]
        else:
            self.leaves = [(bytes(32), bytes(32), bytes(5))]

    # Ordering keys: a lookup leaf orders by tag then position, a set leaf by value.
    def key(self, leaf):
        return leaf[0] + leaf[1] if self.kind == "lookup" else leaf[0]

    def next_key(self, leaf):
        return leaf[2] + leaf[3] if self.kind == "lookup" else leaf[1]

    def leaf_hash(self, leaf):
        return K(self.leaf_tag, *leaf)

    def node(self, level, left, right):
        return K(self.node_tag, bytes([level]), left, right)

    def low_index(self, q):
        found = [i for i, leaf in enumerate(self.leaves)
                 if self.key(leaf) < q and (q < self.next_key(leaf) or not any(self.next_key(leaf)))]
        assert len(found) == 1, "exactly one low leaf"
        return found[0]

    def low_for_query(self, q):
        """The leaf below `q` whose next key is `q` or above: the low leaf of a lookup."""
        found = [i for i, leaf in enumerate(self.leaves)
                 if self.key(leaf) < q and (q <= self.next_key(leaf) or not any(self.next_key(leaf)))]
        assert len(found) == 1, "exactly one low leaf"
        return found[0]

    def insert(self, q, extra=b""):
        n = len(self.leaves)
        assert n < 2**DEPTH
        if not any(q[:16] if self.kind == "lookup" else q):
            raise ValueError("the zero tag or marker is rejected")
        i = self.low_index(q)
        low = self.leaves[i]
        if self.kind == "lookup":
            tag, pos = q[:16], q[16:]
            self.leaves.append((tag, pos, low[2], low[3], low[4]))
            self.leaves[i] = (low[0], low[1], tag, pos, n.to_bytes(5, "big"))
        else:
            if self.kind == "coin-set":
                self.leaves.append((q, low[1], low[2], extra))
                self.leaves[i] = (low[0], q, n.to_bytes(5, "big"), low[3])
            else:
                self.leaves.append((q, low[1], low[2]))
                self.leaves[i] = (low[0], q, n.to_bytes(5, "big"))
        return n

    def levels(self):
        out = [[self.leaf_hash(leaf) for leaf in self.leaves]]
        for level in range(DEPTH):
            cur = out[-1]
            out.append([self.node(level, cur[j], cur[j + 1] if j + 1 < len(cur) else self.z[level])
                        for j in range(0, len(cur), 2)])
        return out

    def root(self):
        return self.levels()[-1][0]

    def witness(self, position):
        lv = self.levels()
        sibs = []
        for level in range(DEPTH):
            j = (position >> level) ^ 1
            sibs.append(lv[level][j] if j < len(lv[level]) else self.z[level])
        return b"".join(self.leaves[position]) + position.to_bytes(5, "big") + b"".join(sibs)


def fold(leaf_hash, position, siblings, node_tag):
    h = leaf_hash
    for level, sib in enumerate(siblings):
        if (position >> level) & 1:
            h = K(node_tag, bytes([level]), sib, h)
        else:
            h = K(node_tag, bytes([level]), h, sib)
    return h


def split(witness, widths):
    out, off = [], 0
    for w in widths:
        out.append(witness[off:off + w])
        off += w
    return out, witness[off:]


def open_lookup_witness(witness, root, leaf_tag, node_tag):
    """The leaf and its lookup position if `witness` takes a leaf to `root`, else None."""
    if len(witness) != LOOKUP_WITNESS_BYTES:
        return None
    leaf, rest = split(witness, (16, 5, 16, 5, 5, 5))
    leaf, lpos = tuple(leaf[:5]), int.from_bytes(leaf[5], "big")
    sibs = [rest[32 * i:32 * i + 32] for i in range(DEPTH)]
    if fold(K(leaf_tag, *leaf), lpos, sibs, node_tag) != root:
        return None
    return leaf, lpos


def lookup_answer(witness, tag, root, leaf_tag=TAG_COIN_LOOKUP_LEAF, node_tag=TAG_COIN_LOOKUP_NODE):
    """("absent", None), ("first", position) or None for a lookup witness for `tag`."""
    if len(tag) != 16 or not any(tag):
        return None
    opened = open_lookup_witness(witness, root, leaf_tag, node_tag)
    if opened is None:
        return None
    (ltag, _lpos, ntag, npos, _nidx), _ = opened
    if not ltag < tag:
        return None
    if not any(ntag) or ntag > tag:
        return ("absent", None)
    if ntag == tag:
        return ("first", int.from_bytes(npos, "big"))
    return None


def lookup_membership(witness, tag, position, root,
                      leaf_tag=TAG_COIN_LOOKUP_LEAF, node_tag=TAG_COIN_LOOKUP_NODE):
    opened = open_lookup_witness(witness, root, leaf_tag, node_tag)
    if opened is None or not any(tag):
        return False
    (ltag, lpos, _ntag, _npos, _nidx), _ = opened
    return ltag == tag and int.from_bytes(lpos, "big") == position


def open_set_witness(witness, root):
    if len(witness) != COIN_SET_WITNESS_BYTES:
        return None
    leaf, rest = split(witness, (32, 32, 5, 5, 5))
    leaf, lpos = tuple(leaf[:4]), int.from_bytes(leaf[4], "big")
    sibs = [rest[32 * i:32 * i + 32] for i in range(DEPTH)]
    if fold(K(TAG_COIN_SET_LEAF, *leaf), lpos, sibs, TAG_COIN_SET_NODE) != root:
        return None
    return leaf


def set_absence(witness, marker, root):
    leaf = open_set_witness(witness, root)
    if leaf is None or not any(marker):
        return False
    value, nvalue, _nidx, _app = leaf
    return value < marker and (marker < nvalue or not any(nvalue))


def set_membership(witness, marker, root):
    """The recorded appended position (None for "none") if `marker` is spent, else False."""
    leaf = open_set_witness(witness, root)
    if leaf is None or not any(marker) or leaf[0] != marker:
        return False
    app = int.from_bytes(leaf[3], "big")
    return None if app == NONE_POSITION else app


def global_position(tree_index, position):
    g = tree_index * LEAVES_PER_TREE + position
    if not 0 <= position < LEAVES_PER_TREE or g >= NONE_POSITION:
        raise ValueError("no lookup position for this leaf")
    return g


def lookup_digest(coin_start, coin_tags, data_start, data_tags, coin_markers, data_markers):
    """The encoded list of a block and its digest.

    coin_start and data_start are the global positions of the block's first new
    leaf of each type: the number of leaves of that type before the block.
    """
    body = coin_start.to_bytes(POS_BYTES, "big") + len(coin_tags).to_bytes(COUNT_BYTES, "big")
    body += b"".join(coin_tags)
    body += data_start.to_bytes(POS_BYTES, "big") + len(data_tags).to_bytes(COUNT_BYTES, "big")
    body += b"".join(data_tags)
    for items in (coin_markers, data_markers):
        body += len(items).to_bytes(COUNT_BYTES, "big") + b"".join(items)
    return body, K(TAG_DIGEST, body)

# --------------------------------------------------------------- vectors


def blocks(text):
    """Every [name] block inside ```text fences: name -> list of (field, value)."""
    out = {}
    for fence in re.findall(r"```text\n(.*?)```", text, re.S):
        name = None
        for line in fence.splitlines():
            m = re.fullmatch(r"\[([a-z0-9-]+)\]", line.strip())
            if m:
                name = m.group(1)
                out[name] = []
            elif name and " = " in line + " ":
                field, _, value = line.partition(" =")
                out[name].append((field.strip(), value.strip()))
    return out


def spec_value(text, block, field):
    for f, v in blocks(text).get(block, []):
        if f == field:
            return v
    raise KeyError(f"{block}.{field}")


def lookup_tag(k_note, i):
    digest = S(TAG_NOTE_LOOKUP, k_note, i.to_bytes(8, "big"))
    return digest, digest[:16]


def leaf_line(leaf):
    return " ".join(part.hex() for part in leaf)


def tree_block(kind, tree, entries):
    t = tree_obj_for(tree, entries)
    rows = [("kind", kind), ("tree", tree)]
    rows.append(("entries", " ".join(f"{tag.hex()}@{g}" for tag, g in entries)))
    rows.append(("count", str(len(t.leaves))))
    for i, leaf in enumerate(t.leaves):
        rows.append((f"leaf-{i}", leaf_line(leaf)))
    rows.append(("root", t.root().hex()))
    return rows


def lookup_tree(tree):
    if tree == "coin":
        return IndexedTree("lookup", TAG_COIN_LOOKUP_LEAF, TAG_COIN_LOOKUP_NODE)
    return IndexedTree("lookup", TAG_DATA_LOOKUP_LEAF, TAG_DATA_LOOKUP_NODE)


def tree_obj_for(tree, entries):
    t = lookup_tree(tree)
    for tag, g in entries:
        t.insert(tag + g.to_bytes(5, "big"))
    return t


def coin_set(spends):
    t = IndexedTree("coin-set", TAG_COIN_SET_LEAF, TAG_COIN_SET_NODE)
    for marker, app in spends:
        t.insert(marker, (NONE_POSITION if app is None else app).to_bytes(5, "big"))
    return t


def compute(spec01, spec05):
    """The record's vector blocks, computed: name -> list of (field, value)."""
    key_bytes = bytes.fromhex(spec_value(spec01, "derivation-words", "key-bytes"))
    data_key_bytes = bytes.fromhex(spec_value(spec01, "derivation-words-data", "key-bytes"))
    k_note = S("ghost/note-key/v1", key_bytes)
    k_note_data = S("ghost/note-key/v1", data_key_bytes)
    assert k_note.hex() == spec_value(spec01, "derivation-words", "note-key")
    assert k_note_data.hex() == spec_value(spec01, "derivation-words-data", "note-key")
    m_commit = bytes.fromhex(spec_value(spec01, "coin-commit-salted", "marker"))
    m_remainder = bytes.fromhex(spec_value(spec01, "coin-remainder-salted", "marker"))

    out = {}
    tags = {}
    for i in (0, 1, 2):
        digest, tag = lookup_tag(k_note, i)
        tags[i] = tag
        out[f"lookup-tag-index-{i}"] = [
            ("kind", "lookup-tag"), ("key-bytes", key_bytes.hex()), ("note-key", k_note.hex()),
            ("index", str(i)), ("index-bytes", i.to_bytes(8, "big").hex()),
            ("digest", digest.hex()), ("tag", tag.hex())]
    digest, dtag = lookup_tag(k_note_data, 0)
    out["lookup-tag-data-index-0"] = [
        ("kind", "lookup-tag"), ("key-bytes", data_key_bytes.hex()), ("note-key", k_note_data.hex()),
        ("index", "0"), ("index-bytes", bytes(8).hex()), ("digest", digest.hex()), ("tag", dtag.hex())]

    sets = {
        "coin-lookup-empty": ("coin", []),
        "data-lookup-empty": ("data", []),
        "coin-lookup-one-leaf": ("coin", [(tags[0], 0)]),
        "coin-lookup-two-leaves": ("coin", [(tags[0], 0), (tags[1], 1)]),
        "coin-lookup-copied-tag": ("coin", [(tags[0], 0), (tags[1], 1), (tags[0], 2)]),
        "data-lookup-one-leaf": ("data", [(dtag, 0)]),
    }
    for name, (tree, entries) in sets.items():
        out[name] = tree_block("lookup-index", tree, entries)

    # The absence witness: number 2 of the example key against the two-leaf index.
    two = tree_obj_for("coin", sets["coin-lookup-two-leaves"][1])
    q = tags[2] + bytes(5)
    lpos = two.low_for_query(q)
    w = two.witness(lpos)
    low = two.leaves[lpos]
    out["coin-lookup-absence"] = [
        ("kind", "lookup-witness"), ("tree", "coin"), ("set", "coin-lookup-two-leaves"),
        ("root", two.root().hex()), ("tag", tags[2].hex()), ("low-position", str(lpos)),
        ("low-leaf", leaf_line(low)), ("witness", w.hex()), ("outcome", "absent")]
    # The tags for which the same witness gives no answer: the low leaf's own tag
    # (when it is not the sentinel) and one just above its next tag.
    # Below the sentinel there is only the zero tag, which is rejected as such.
    rejects = []
    if any(low[0]):
        rejects.append(("reject-equal", low[0].hex()))
        rejects.append(("reject-below", (int.from_bytes(low[0], "big") - 1).to_bytes(16, "big").hex()))
    else:
        rejects.append(("reject-zero", bytes(16).hex()))
    if any(low[2]):
        above = (int.from_bytes(low[2], "big") + 1).to_bytes(16, "big")
        rejects.append(("reject-next-tag", low[2].hex()))
        rejects.append(("reject-above-next", above.hex()))
    out["coin-lookup-absence"] += rejects

    # The first entry of a copied tag: the original, not the copy.
    cop = tree_obj_for("coin", sets["coin-lookup-copied-tag"][1])
    q = tags[0] + bytes(5)
    lpos = cop.low_for_query(q)
    w = cop.witness(lpos)
    out["coin-lookup-first-entry"] = [
        ("kind", "lookup-witness"), ("tree", "coin"), ("set", "coin-lookup-copied-tag"),
        ("root", cop.root().hex()), ("tag", tags[0].hex()), ("low-position", str(lpos)),
        ("low-leaf", leaf_line(cop.leaves[lpos])), ("witness", w.hex()),
        ("outcome", "first"), ("position", str(int.from_bytes(cop.leaves[lpos][3], "big")))]
    # The membership witness of the copy itself.
    cpos = next(i for i, leaf in enumerate(cop.leaves)
                if leaf[0] == tags[0] and int.from_bytes(leaf[1], "big") == 2)
    out["coin-lookup-membership"] = [
        ("kind", "lookup-membership"), ("tree", "coin"), ("set", "coin-lookup-copied-tag"),
        ("root", cop.root().hex()), ("tag", tags[0].hex()), ("position", "2"),
        ("leaf-position", str(cpos)), ("leaf", leaf_line(cop.leaves[cpos])),
        ("witness", cop.witness(cpos).hex())]

    # The coin marker set: the commit's marker spent by the reveal whose remainder
    # is coin leaf 1, then the remainder's marker spent by one whose remainder is leaf 2.
    spends = {
        "coin-marker-set-empty": [],
        "coin-marker-set-one-marker": [(m_commit, 1)],
        "coin-marker-set-two-markers": [(m_commit, 1), (m_remainder, 2)],
    }
    for name, sp in spends.items():
        t = coin_set(sp)
        rows = [("kind", "coin-marker-set"),
                ("spends", " ".join(f"{m.hex()}@{a}" for m, a in sp))]
        rows.append(("count", str(len(t.leaves))))
        for i, leaf in enumerate(t.leaves):
            rows.append((f"leaf-{i}", leaf_line(leaf)))
        rows.append(("root", t.root().hex()))
        out[name] = rows
    t2 = coin_set(spends["coin-marker-set-two-markers"])
    mpos = 1
    out["coin-marker-set-membership"] = [
        ("kind", "coin-marker-set-membership"), ("set", "coin-marker-set-two-markers"),
        ("root", t2.root().hex()), ("marker", m_commit.hex()), ("leaf-position", str(mpos)),
        ("leaf", leaf_line(t2.leaves[mpos])), ("witness", t2.witness(mpos).hex()),
        ("appended", "1")]
    absent_marker = bytes([0x88]) * 32
    apos = t2.low_index(absent_marker)
    out["coin-marker-set-absence"] = [
        ("kind", "coin-marker-set-absence"), ("set", "coin-marker-set-two-markers"),
        ("root", t2.root().hex()), ("marker", absent_marker.hex()), ("low-position", str(apos)),
        ("low-leaf", leaf_line(t2.leaves[apos])), ("witness", t2.witness(apos).hex()),
        ("valid", "yes"), ("reject-spent", m_commit.hex())]

    # The block lookup digest.
    def digest_rows(coin_start, coin_tags, data_start, data_tags, coin_markers, data_markers):
        body, dig = lookup_digest(coin_start, coin_tags, data_start, data_tags,
                                  coin_markers, data_markers)
        return [("kind", "lookup-digest"),
                ("coin-start", str(coin_start)), ("coin-tags", " ".join(x.hex() for x in coin_tags)),
                ("data-start", str(data_start)), ("data-tags", " ".join(x.hex() for x in data_tags)),
                ("coin-markers", " ".join(x.hex() for x in coin_markers)),
                ("data-markers", " ".join(x.hex() for x in data_markers)),
                ("encoding", body.hex()), ("digest", dig.hex())]

    out["lookup-digest-empty"] = digest_rows(0, [], 0, [], [], [])
    # The block after the commit of number 0 (coin leaf 0): the reveal of number 0,
    # whose remainder is coin leaf 1, and a data commit, data leaf 0.
    out["lookup-digest-example"] = digest_rows(1, [tags[1]], 0, [dtag], [m_commit], [])

    out["header-genesis-new-fields"] = [
        ("kind", "genesis-fields"),
        ("coinLookupRoot", lookup_tree("coin").root().hex()),
        ("dataLookupRoot", lookup_tree("data").root().hex()),
        ("coinMarkerRoot", coin_set([]).root().hex()),
        ("lookupDigest", lookup_digest(0, [], 0, [], [], [])[1].hex())]

    out["global-position-examples"] = [
        ("kind", "global-position"),
        ("tree-0-position-0", f"{global_position(0, 0):010x}"),
        ("tree-0-position-4294967295", f"{global_position(0, 2**32 - 1):010x}"),
        ("tree-1-position-0", f"{global_position(1, 0):010x}"),
        ("tree-255-position-4294967294", f"{global_position(255, 2**32 - 2):010x}"),
        ("tree-255-position-4294967295", "rejected"),
        ("none", f"{NONE_POSITION:010x}")]
    return out


def render(vectors):
    chunks = []
    for name, rows in vectors.items():
        lines = [f"[{name}]"] + [f"{f} = {v}" if v else f"{f} =" for f, v in rows]
        chunks.append("\n".join(lines))
    return "\n\n".join(chunks) + "\n"

# ----------------------------------------------------------- the checks


def check_spec05_construction(spec05):
    """The indexed tree here, with spec 05's data marker-set tags, gives spec 05's vectors."""
    failures = []
    bl = blocks(spec05)
    for name in ("marker-set-empty", "marker-set-one-marker", "marker-set-two-markers"):
        rows = dict(bl.get(name, []))
        if not rows:
            failures.append(f"spec 05 has no vector {name}")
            continue
        t = IndexedTree("data-set", TAG_DATA_SET_LEAF, TAG_DATA_SET_NODE)
        for m in rows["markers"].split():
            t.insert(bytes.fromhex(m))
        if t.root().hex() != rows["root"]:
            failures.append(f"the indexed tree differs from spec 05 at {name}")
    rows = dict(bl.get("marker-set-absence", []))
    t = IndexedTree("data-set", TAG_DATA_SET_LEAF, TAG_DATA_SET_NODE)
    for m in dict(bl["marker-set-two-markers"])["markers"].split():
        t.insert(bytes.fromhex(m))
    if t.witness(int(rows["low-position"])).hex() != rows["absence"]:
        failures.append("the witness layout differs from spec 05's absence witness")
    return failures


def check_witnesses(vectors):
    """Every witness is accepted for what it shows and rejected otherwise."""
    failures = []

    def flipped(w):
        return [w[:i] + bytes([w[i] ^ 1]) + w[i + 1:] for i in (0, 20, 47, 52, len(w) - 1)]

    for name in ("coin-lookup-absence", "coin-lookup-first-entry"):
        v = dict(vectors[name])
        w, tag, root = (bytes.fromhex(v[k]) for k in ("witness", "tag", "root"))
        want = ("absent", None) if v["outcome"] == "absent" else ("first", int(v["position"]))
        if lookup_answer(w, tag, root) != want:
            failures.append(f"{name}: not accepted as {want[0]}")
        for bad in flipped(w) + [w[:-1], w + b"\0"]:
            if lookup_answer(bad, tag, root) is not None:
                failures.append(f"{name}: a changed witness is accepted")
                break
        for f, val in v.items():
            if f.startswith("reject-") and lookup_answer(w, bytes.fromhex(val), root) == want:
                failures.append(f"{name}: {f} gets the same answer")
        if lookup_answer(w, tag, root, TAG_DATA_LOOKUP_LEAF, TAG_DATA_LOOKUP_NODE) is not None:
            failures.append(f"{name}: a coin witness is accepted against the data tags")
    v = dict(vectors["coin-lookup-absence"])
    for f in ("reject-equal", "reject-next-tag", "reject-above-next"):
        if f in v and lookup_answer(bytes.fromhex(v["witness"]), bytes.fromhex(v[f]),
                                    bytes.fromhex(v["root"])) == ("absent", None):
            failures.append(f"coin-lookup-absence: {f} reads as absent")
    v = dict(vectors["coin-lookup-membership"])
    w, tag, root = (bytes.fromhex(v[k]) for k in ("witness", "tag", "root"))
    if not lookup_membership(w, tag, int(v["position"]), root):
        failures.append("coin-lookup-membership: not accepted")
    if lookup_membership(w, tag, int(v["position"]) - 1, root):
        failures.append("coin-lookup-membership: accepted for another position")
    if any(lookup_membership(b, tag, int(v["position"]), root) for b in flipped(w)):
        failures.append("coin-lookup-membership: a changed witness is accepted")

    v = dict(vectors["coin-marker-set-membership"])
    w, m, root = (bytes.fromhex(v[k]) for k in ("witness", "marker", "root"))
    if set_membership(w, m, root) != int(v["appended"]):
        failures.append("coin-marker-set-membership: wrong appended position")
    if any(set_membership(b, m, root) is not False for b in flipped(w)):
        failures.append("coin-marker-set-membership: a changed witness is accepted")
    v = dict(vectors["coin-marker-set-absence"])
    w, m, root = (bytes.fromhex(v[k]) for k in ("witness", "marker", "root"))
    if not set_absence(w, m, root):
        failures.append("coin-marker-set-absence: not accepted")
    if set_absence(w, bytes.fromhex(v["reject-spent"]), root):
        failures.append("coin-marker-set-absence: accepted for a spent marker")
    if any(set_absence(b, m, root) for b in flipped(w) + [w[:-1]]):
        failures.append("coin-marker-set-absence: a changed witness is accepted")
    return failures


def check_invariants(vectors):
    """The entry of the leaf at global position g sits at index position g + 1."""
    failures = []
    for name, rows in vectors.items():
        if dict(rows).get("kind") != "lookup-index":
            continue
        for field, value in rows:
            if not field.startswith("leaf-"):
                continue
            _tag, pos, ntag, npos, nidx = (bytes.fromhex(x) for x in value.split())
            index = int(field[5:])
            if index and int.from_bytes(pos, "big") + 1 != index:
                failures.append(f"{name}: {field} is not at its position plus one")
            if any(ntag) and int.from_bytes(nidx, "big") != int.from_bytes(npos, "big") + 1:
                failures.append(f"{name}: {field} has nextIndex other than nextPosition + 1")
    return failures


def sections(text):
    """'## Title' -> body up to the next '## '."""
    out = {}
    parts = re.split(r"^## (.+)$", text, flags=re.M)
    for title, body in zip(parts[1::2], parts[2::2]):
        out[title.strip()] = body
    return out


def table_rows(body):
    return [[c.strip() for c in line.strip().strip("|").split("|")]
            for line in body.splitlines()
            if line.strip().startswith("|") and not re.match(r"^\|[-| ]+\|$", line.strip())]


def check_text(text, spec01=None, spec05=None):
    spec01 = spec01 if spec01 is not None else SPEC_01.read_text(encoding="utf-8")
    spec05 = spec05 if spec05 is not None else SPEC_05.read_text(encoding="utf-8")
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

    vectors = compute(spec01, spec05)
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

    # Tag table: hash, input bytes with the tag, permutations.
    rows = {r[0].strip("`"): r for r in table_rows(secs.get("Tag table rows", "")) if r and r[0].startswith("`")}
    for tag, (hname, inputs) in TAG_ROWS.items():
        row = rows.get(tag)
        if row is None:
            failures.append(f"tag table: no row for {tag}")
            continue
        if row[1] != hname:
            failures.append(f"tag table: {tag} hash is {row[1]}, not {hname}")
        if inputs is None:
            fixed = len(tagbytes(tag)) + 2 * POS_BYTES + 4 * COUNT_BYTES
            want_bytes = f"{fixed} + 16 a tag + 32 a marker"
            want_perm = "not in a proof"
        else:
            total = len(tagbytes(tag)) + inputs
            want_bytes = str(total)
            want_perm = "not in a proof" if hname == "SHA3-256" else str(permutations(total))
            if tag.endswith("-node/v1"):
                want_perm += " per level"
        if row[4] != want_bytes:
            failures.append(f"tag table: {tag} input bytes {row[4]}, not {want_bytes}")
        if row[5] != want_perm:
            failures.append(f"tag table: {tag} permutations {row[5]}, not {want_perm}")
    for tag in rows:
        if tag not in TAG_ROWS:
            failures.append(f"tag table: {tag} is not a tag of this record")

    # Header fields: after spec 05's last field, in order.
    hrows = [r for r in table_rows(secs.get("Header fields", "")) if r and r[0].isdigit()]
    got = [(r[0], r[1].strip("`")) for r in hrows]
    if got != list(HEADER_FIELDS):
        failures.append(f"header fields table is {got}, not {list(HEADER_FIELDS)}")
    for r in hrows:
        if r[2] != "32 bytes":
            failures.append(f"header field {r[1]} is not 32 bytes")
    spec_rows = [(r[0], r[1].strip("`")) for r in table_rows(spec05)
                 if len(r) == 4 and r[0].isdigit() and r[1].startswith("`")]
    if SPEC_05_LAST not in spec_rows:
        failures.append("spec 05 no longer has dataMarkerRoot as field 18")
    for idx, fname in spec_rows:
        if int(idx) > 18 and (idx, fname) not in HEADER_FIELDS:
            failures.append(f"spec 05 field {idx} {fname} disagrees with this record")

    # Stated sizes.
    for size, what in ((LOOKUP_WITNESS_BYTES, "lookup witness"), (COIN_SET_WITNESS_BYTES, "coin marker-set witness"),
                       (LOOKUP_LEAF_BYTES, "lookup leaf"), (COIN_SET_LEAF_BYTES, "coin marker-set leaf")):
        if f"{size:,} bytes" not in text and f"{size} bytes" not in text:
            failures.append(f"the record does not state the {what} size, {size} bytes")
    for name in ("coin-lookup-absence", "coin-lookup-first-entry", "coin-lookup-membership"):
        if name in found and len(bytes.fromhex(dict(found[name]).get("witness", ""))) != LOOKUP_WITNESS_BYTES:
            failures.append(f"vector {name}: witness is not {LOOKUP_WITNESS_BYTES} bytes")

    failures += check_spec05_construction(spec05)
    failures += check_witnesses(vectors)
    failures += check_invariants(vectors)
    return failures


def main(argv):
    failures = self_test()
    if failures:
        print("\n".join(failures))
        return 1
    spec01 = SPEC_01.read_text(encoding="utf-8")
    spec05 = SPEC_05.read_text(encoding="utf-8")
    if argv[1:2] == ["--print"]:
        sys.stdout.write(render(compute(spec01, spec05)))
        return 0
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_RECORD
    failures = check_text(path.read_text(encoding="utf-8"), spec01, spec05)
    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"{path.name}: every section, vector, witness and table agrees")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
