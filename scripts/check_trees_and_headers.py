#!/usr/bin/env python3
"""Checks docs/spec/05-trees-and-headers.md.

Python standard library only, plus the Keccak-256 function of
check_commitment_vectors.py. It checks that:

  1. the required sections are present and numbered 1 upwards;
  2. the parameters keep the stated targets: depth 32, 2^32 leaves per tree,
     and the note size of spec 01;
  3. the page-size and storage tables are right;
  4. the header field table is the pinned base header in order with the base
     fee required, then the two tree roots and the data marker-set root as
     field 18, exactly 19 fields; that no forbidden field and no other
     marker-set root is in it; and that every genesis field is listed once with
     its source and agrees with the genesis vector;
  5. every tree, page and rollover vector is right, and the tree vectors over
     spec 01's commitments hold exactly those of its words-key vectors; every
     marker-set vector is recomputed with this script's own indexed tree
     (insertions, leaves, root, the absence witness and its rejected markers),
     and each header's dataMarkerRoot is the root of a marker-set vector;
     every witness-extension vector is recomputed with this script's own tree
     code (the page-root tail must hash to the header root, the witness after
     must be the one recomputed and hash to it), and every marker-query vector
     is served only with exactly 64 distinct markers, each "spent" answer
     carried by a receipt; section 8 states the tail read, the status query
     and their cost, and its "Forbidden." paragraph and TH-19 name the reads;
  6. every header vector re-encodes byte for byte with this script's own RLP
     code, every negative vector is re-derived and rejected for the stated
     reason, and the header vectors equal the output of the separately written
     header_golden_encoder.py;
  7. the conformance requirements (TH-n) and the recovery test (RT-n) are
     numbered without gaps and each states its expected result;
  8. the conflicts the ticket of this chapter names are listed;
  9. every hash tag named is in the tag table of spec 01.

Usage:
    python3 scripts/check_trees_and_headers.py [SPEC_MD]

Exit status is non-zero on any gap.
"""

import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_SPEC = HERE.parent / "docs" / "spec" / "05-trees-and-headers.md"
SPEC_01 = "01-commitments-and-keys.md"
SPEC_06 = "06-consensus-and-emission.md"
ENCODER = HERE / "header_golden_encoder.py"

_spec = importlib.util.spec_from_file_location("_check_commitment_vectors",
                                               HERE / "check_commitment_vectors.py")
_ccv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ccv)
keccak256 = _ccv.keccak256

# Tree vectors whose leaves are the commitments of spec 01's salted (format
# version 2) vectors, in order. Those vectors use the words key, the only
# Phantom Key format, shown as its 21 digit groups.
SPEC_01_LEAVES = {
    "coin-tree-two-leaves": ("coin-commit-salted", "coin-remainder-salted"),
    "coin-page-two-leaves": ("coin-commit-salted", "coin-remainder-salted"),
    "data-tree-one-leaf": ("data-commit-salted",),
}
WORDS_KEY_GROUPS = 21

REQUIRED_SECTIONS = ("Trees and rollover", "Historical roots", "Markers", "Reorganisation",
                     "Wallet tree data", "History availability", "Header encoding",
                     "Golden vectors", "Conflicts with other chapters")
# Sections that must hold at least one conformance requirement.
TH_SECTIONS = ("Trees and rollover", "Historical roots", "Markers", "Reorganisation",
               "Wallet tree data", "History availability", "Header encoding")
# Words each section must use, so that its subject is covered.
SECTION_WORDS = {
    "Historical roots": ("canonical", "discarded branch", "age limit", "before its including block"),
    "Markers": ("ghost/coin-marker/v2", "ghost/data-marker/v2","state root", "pool admission"),
    "Reorganisation": ("frontier", "tree index", "marker", "pool", "no longer canonical",
                       "depth limit"),
    "Wallet tree data": ("whole", "page-root list", "witness"),
    "History availability": ("full node", "snap-synced", "header-only", "indexer"),
}

DEPTH = 32
LEAVES = 2**DEPTH
PAGE_DEPTH_MAX = 16
INDEX_MAX = 2**64 - 1
TAG_COIN_NODE = "ghost/coin-tree-node/v1"
TAG_DATA_NODE = "ghost/data-tree-node/v1"
TAG_EMPTY_LEAF = "ghost/empty-leaf/v1"
NODE_TAGS = {"coin": TAG_COIN_NODE, "data": TAG_DATA_NODE}

# The data marker-set tree of section 6: an append-only indexed tree.
TAG_MARKER_SET_LEAF = "ghost/data-marker-set-leaf/v1"
TAG_MARKER_SET_NODE = "ghost/data-marker-set-node/v1"
MARKER_SET_DEPTH = 40
MARKER_SET_POSITIONS = 2**MARKER_SET_DEPTH
INDEX_BYTES = 5
ABSENCE_BYTES = 32 + 32 + INDEX_BYTES + INDEX_BYTES + 32 * MARKER_SET_DEPTH
# Marker-set vectors the chapter must hold, and the spec 01 vectors whose data
# markers they insert, in order.
MARKER_SET_VECTORS = ("marker-set-empty", "marker-set-one-marker", "marker-set-two-markers",
                      "marker-set-absence")
SPEC_01_MARKERS = {
    "marker-set-empty": (),
    "marker-set-one-marker": ("data-commit-salted",),
    "marker-set-two-markers": ("data-commit-salted", "data-commit-salted-other"),
}
# The rejected markers of an absence vector, with the relation each must have
# to the low leaf.
ABSENCE_REJECTS = ("reject-equal", "reject-below", "reject-above-next")

# Witness extension and the marker status query of section 8. A page-root
# tail starts at a multiple of TAIL_PAGES pages, a page read whole is read with
# decoys PAGE_READ pages a request, and a status query holds exactly
# MARKER_QUERY_SIZE markers.
WITNESS_EXTENSION_VECTORS = ("witness-extension-same-page", "witness-extension-new-pages")
MARKER_QUERY_VECTORS = ("marker-query-one-real", "marker-query-rejects-wrong-count")
TAIL_PAGES = 65536
PAGE_READ = 8
MARKER_QUERY_SIZE = 64
# Section 8's subsections on restore at scale, with the words each must use.
RESTORE_SUBSECTIONS = {
    "Reading the tail of the page roots": (
        "65,536 pages", "about a month", "2 MiB", "header root", "Z_12", "8 pages",
        "7 decoy pages", "reused on retry", "no new witness endpoint"),
    "Marker status query": (
        "exactly 64 markers", "one real", "63 decoys", "uniformly random 32-byte value",
        "reused on every retry", "spent needs a receipt", "7 decoy blocks",
        "not spent cannot be authenticated", "unchecked, not reported spent",
        "refused by every node", "never make a real unspent coin look spent",
        "no absence-witness read"),
    "Cost against the restore ceilings": (
        "modeled", "restore_sim.py", "stage1-verdict.md", "611.8 MB", "298 days", "500 MB",
        "50 MB a month", "10 minutes", "not feasible as designed", "header-chain proof"),
}
# The reads the "Forbidden." paragraph and TH-19 must allow, the bucket read
# among them.
ALLOWED_READS = ("bucket read", "page-root tail", "8-page read", "64-marker status query",
                 "block-range receipts request")
UNCHECKED_STATUS = "unchecked, not reported spent"

PARAMETERS = ("TREE_DEPTH", "LEAVES_PER_TREE", "PAGE_LEAVES", "LEAF_BYTES", "NOTE_BYTES",
              "MARKER_BYTES", "TREE_INDEX_MAX")

# The Ghost header: the base header of the pinned Core-Geth commit (Go Ethereum
# 1.13.15) in its order, the base fee required, then the two tree roots and the
# data marker-set root.
# (name, kind, size): "fixed" is exactly size bytes, "bytes" at most size bytes,
# "int" a canonical integer below 2^size.
HEADER = (
    ("parentHash", "fixed", 32),
    ("uncleHash", "fixed", 32),
    ("coinbase", "fixed", 20),
    ("stateRoot", "fixed", 32),
    ("transactionsRoot", "fixed", 32),
    ("receiptsRoot", "fixed", 32),
    ("logsBloom", "fixed", 256),
    ("difficulty", "int", 256),
    ("number", "int", 64),
    ("gasLimit", "int", 64),
    ("gasUsed", "int", 64),
    ("timestamp", "int", 64),
    ("extraData", "bytes", 32),
    ("mixDigest", "fixed", 32),
    ("nonce", "fixed", 8),
    ("baseFee", "int", 256),
    ("coinTreeRoot", "fixed", 32),
    ("dataTreeRoot", "fixed", 32),
    ("dataMarkerRoot", "fixed", 32),
)
HEADER_NAMES = tuple(name for name, _, _ in HEADER)
GHOST_FIELDS = ("coinTreeRoot", "dataTreeRoot", "dataMarkerRoot")
# The one marker-set root in the header, and its index.
MARKER_FIELD = "dataMarkerRoot"
MARKER_FIELD_INDEX = 18
FORBIDDEN_FIELDS = ("withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconRoot")
# Genesis fields that spec 06, section 8.3 fixes, with the word it uses.
SPEC06_GENESIS = {"parentHash": "parentHash", "uncleHash": "uncle hash", "coinbase": "coinbase",
                  "difficulty": "difficulty", "number": "number", "timestamp": "timestamp",
                  "extraData": "extraData", "mixDigest": "mixDigest", "nonce": "nonce"}
D_START = 2**24

REQUIRED_FAULTS = ("forbidden-field", "extra-trailing-field", "missing-required-field",
                   "non-canonical-integer", "eighteen-items")
# Conflicts this chapter must list: (chapter, place) both in one item.
REQUIRED_CONFLICTS = (("spec 03", "question 6"), ("spec 04", "question 2"),
                      ("spec 02", "section 8"), ("spec 06", "8.3"))

HEADING_RE = re.compile(r"^## (\d+)\. (.+)$")
TAG_RE = re.compile(r"ghost/[a-z0-9-]+/v\d+")
TH_RE = re.compile(r"^- \*\*TH-(\d+)\. (.+?)\*\*")
RT_RE = re.compile(r"^- \*\*RT-(\d+)\. (.+?)\*\*")
TH_REF_RE = re.compile(r"\bTH-(\d+)\b")
CONFLICT_RE = re.compile(r"^(\d+)\. \*\*(.+?)\*\*")
NOTE_LENGTH_RE = re.compile(r"\*\*On the chain: (\d+) bytes, fixed\.\*\*")
HEX_RE = re.compile(r"^[0-9a-f]*$")


# ---------------------------------------------------------------------------
# Reading the document
# ---------------------------------------------------------------------------

def sections(text):
    """Map each '## ' heading (without '## ') to its lines."""
    out, name = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            name = line[3:].strip()
            out[name] = []
        elif name is not None:
            out[name].append(line)
    return out


def find_section(secs, word):
    word = word.lower()
    return [name for name in secs if word in name.lower()]


def tables(lines):
    """Every Markdown table in lines, as (header, rows of dicts)."""
    found, block = [], []
    for line in lines + [""]:
        if line.startswith("|"):
            block.append([c.strip() for c in line.strip().strip("|").split("|")])
            continue
        if len(block) >= 3:
            header = block[0]
            found.append((header, [dict(zip(header, cells)) for cells in block[2:]]))
        block = []
    return found


def table_with(lines, columns):
    for header, rows in tables(lines):
        if header == list(columns):
            return rows
    return None


def entries(lines, item_re):
    """List items matching item_re, each with its full text (to the next item)."""
    found, current = [], None
    for line in lines:
        m = item_re.match(line)
        if m:
            current = [int(m.group(1)), m.group(2), [line]]
            found.append(current)
        elif line.startswith("- ") or line.startswith("#") or re.match(r"^\d+\. ", line):
            current = None
        elif current is not None:
            current[2].append(line)
    return [(n, title, " ".join(" ".join(text).split())) for n, title, text in found]


def vector_blocks(lines):
    """Every `[name]` block inside fenced code blocks, as name -> list of
    (key, value) in order."""
    blocks, fenced, current = {}, False, None
    for line in lines:
        if line.startswith("```"):
            fenced, current = not fenced, None
            continue
        if not fenced:
            continue
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = []
            blocks[line[1:-1]] = current
        elif current is not None and " = " in line:
            key, value = line.split(" = ", 1)
            current.append((key.strip(), value.strip()))
        elif current is not None and line.endswith(" ="):
            current.append((line[:-2].strip(), ""))
    return blocks


def subsection(lines, title):
    """The lines under the '### title' heading, to the next '### ', or None."""
    out, inside = None, False
    for line in lines:
        if line.startswith("### "):
            inside = line[4:].strip() == title
            if inside:
                out = []
        elif inside:
            out.append(line)
    return out


def paragraph(lines, start):
    """The paragraph whose first line starts with `start`, on one line."""
    for i, line in enumerate(lines):
        if line.startswith(start):
            end = next((j for j in range(i, len(lines)) if not lines[j].strip()), len(lines))
            return " ".join(" ".join(lines[i:end]).split())
    return None


def number(cell):
    try:
        return int(cell.replace(",", "").strip().strip("`"))
    except (AttributeError, ValueError):
        return None


def first_code(cell):
    m = re.search(r"`([^`]*)`", cell)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Trees
# ---------------------------------------------------------------------------

def tagged(tag, *parts):
    raw = tag.encode("ascii")
    return keccak256(bytes([len(raw)]) + raw + b"".join(parts))


def empty_leaf():
    return tagged(TAG_EMPTY_LEAF)


def node(tag, level, left, right):
    return tagged(tag, bytes([level]), left, right)


def empty_roots(tag):
    """Z_0 to Z_32 of the tree with this node tag."""
    z = [empty_leaf()]
    for level in range(DEPTH):
        z.append(node(tag, level, z[level], z[level]))
    return z


def sparse_root(tag, nodes, start_level, top_level=DEPTH):
    """The node at top_level over `nodes` (position -> value at start_level);
    every missing position is empty."""
    z = empty_roots(tag)
    layer = dict(nodes)
    for level in range(start_level, top_level):
        parents = {}
        for pos in sorted({p // 2 for p in layer}):
            left = layer.get(2 * pos, z[level])
            right = layer.get(2 * pos + 1, z[level])
            parents[pos] = node(tag, level, left, right)
        layer = parents
    return layer.get(0, z[top_level]) if layer else z[top_level]


def tree_root(tag, leaves, offset=0):
    return sparse_root(tag, {offset + i: leaf for i, leaf in enumerate(leaves)}, 0)


def page_root(tag, leaves, page_depth):
    return sparse_root(tag, dict(enumerate(leaves)), 0, page_depth)


def path_siblings(tag, nodes, start_level, at, top_level=DEPTH):
    """The siblings, from start_level up to top_level, of the node at index
    `at` of start_level, over `nodes` (index -> value at start_level)."""
    z = empty_roots(tag)
    layer, out = dict(nodes), []
    for level in range(start_level, top_level):
        out.append(layer.get(at ^ 1, z[level]))
        layer = {pos: node(tag, level, layer.get(2 * pos, z[level]), layer.get(2 * pos + 1, z[level]))
                 for pos in sorted({p // 2 for p in layer})}
        at //= 2
    return out


def fold(tag, value, at, siblings, start_level=0):
    """The node reached from `value` at index `at` of start_level, hashed up
    with `siblings` one level each."""
    for i, sibling in enumerate(siblings):
        level = start_level + i
        if (at >> i) & 1:
            value = node(tag, level, sibling, value)
        else:
            value = node(tag, level, value, sibling)
    return value


def witness(tag, page_leaves, page_roots, position, page_depth):
    """The 32 siblings of the leaf at `position`: page_depth from the leaves of
    its page (a list from the page's first position), the rest from the
    page-root list."""
    in_page = path_siblings(tag, dict(enumerate(page_leaves)), 0,
                            position % (1 << page_depth), page_depth)
    return in_page + path_siblings(tag, dict(enumerate(page_roots)), page_depth,
                                   position >> page_depth)


def query_reject(markers):
    """None when a marker status query (hex strings) may be served, else the
    reason a node refuses it."""
    if len(markers) != MARKER_QUERY_SIZE:
        return "marker-count"
    if any(not HEX_RE.match(m) or len(m) != 64 for m in markers):
        return "marker-size"
    if len(set(markers)) != len(markers):
        return "duplicate-marker"
    return None


def append(index, count, filled_this_block):
    """One append under the rules of section 3: (includable, index, count,
    position)."""
    if count < LEAVES:
        return True, index, count + 1, count
    if filled_this_block or index >= INDEX_MAX:
        return False, index, count, None
    return True, index + 1, 1, 0


# ---------------------------------------------------------------------------
# The data marker-set tree, this script's own
# ---------------------------------------------------------------------------

class MarkerRejected(Exception):
    pass


def marker_leaf_hash(leaf):
    value, next_value, next_index = leaf
    return tagged(TAG_MARKER_SET_LEAF, value, next_value, next_index.to_bytes(INDEX_BYTES, "big"))


def marker_empty_roots():
    """Z_0 to Z_40 of the marker-set tree."""
    z = [empty_leaf()]
    for level in range(MARKER_SET_DEPTH):
        z.append(node(TAG_MARKER_SET_NODE, level, z[level], z[level]))
    return z


def marker_set_genesis():
    """The used leaves of the genesis set: the sentinel (0, 0, 0) at position 0."""
    return [(bytes(32), bytes(32), 0)]


def marker_low(leaves, marker):
    """Position of the one used leaf with value < marker and (marker <
    nextValue or nextValue = 0)."""
    found = [p for p, (value, next_value, _) in enumerate(leaves)
             if value < marker and (marker < next_value or next_value == bytes(32))]
    if len(found) != 1:
        raise MarkerRejected(f"{len(found)} low leaves for {marker.hex()}")
    return found[0]


def marker_insert(leaves, marker):
    """Insert one marker into the set under the rules of section 6."""
    if len(marker) != 32 or marker == bytes(32):
        raise MarkerRejected("the marker 0 is never valid")
    if any(value == marker for value, _, _ in leaves):
        raise MarkerRejected("the marker is already in the set")
    n = len(leaves)
    if n >= MARKER_SET_POSITIONS:
        raise MarkerRejected("the set is full")
    low = marker_low(leaves, marker)
    value, next_value, next_index = leaves[low]
    leaves.append((marker, next_value, next_index))
    leaves[low] = (value, marker, n)


def marker_set(markers):
    leaves = marker_set_genesis()
    for m in markers:
        marker_insert(leaves, m)
    return leaves


def marker_layers(leaves):
    """Every level of the tree as position -> node, level 0 the leaf hashes,
    level 40 the root."""
    z = marker_empty_roots()
    layers = [{p: marker_leaf_hash(leaf) for p, leaf in enumerate(leaves)}]
    for level in range(MARKER_SET_DEPTH):
        below, parents = layers[-1], {}
        for pos in sorted({p // 2 for p in below}):
            parents[pos] = node(TAG_MARKER_SET_NODE, level, below.get(2 * pos, z[level]),
                                below.get(2 * pos + 1, z[level]))
        layers.append(parents)
    return layers


def marker_set_root(leaves):
    return marker_layers(leaves)[MARKER_SET_DEPTH][0]


def absence_witness(leaves, marker):
    """The non-membership witness for marker: the low leaf, its position and
    its 40 siblings."""
    position = marker_low(leaves, marker)
    value, next_value, next_index = leaves[position]
    z = marker_empty_roots()
    layers = marker_layers(leaves)
    siblings = [layers[level].get((position >> level) ^ 1, z[level])
                for level in range(MARKER_SET_DEPTH)]
    return (value + next_value + next_index.to_bytes(INDEX_BYTES, "big")
            + position.to_bytes(INDEX_BYTES, "big") + b"".join(siblings))


def check_absence(root, marker, witness):
    """None when witness shows marker is not in the set under root, else the
    reason it fails."""
    if len(witness) != ABSENCE_BYTES:
        return "witness-size"
    if len(marker) != 32 or marker == bytes(32):
        return "zero-marker"
    value, next_value = witness[0:32], witness[32:64]
    next_index = int.from_bytes(witness[64:69], "big")
    position = int.from_bytes(witness[69:74], "big")
    at = marker_leaf_hash((value, next_value, next_index))
    for level in range(MARKER_SET_DEPTH):
        sibling = witness[74 + 32 * level:106 + 32 * level]
        if (position >> level) & 1:
            at = node(TAG_MARKER_SET_NODE, level, sibling, at)
        else:
            at = node(TAG_MARKER_SET_NODE, level, at, sibling)
    if at != root:
        return "root"
    if not value < marker:
        return "not-above-low"
    if not (marker < next_value or next_value == bytes(32)):
        return "not-below-next"
    return None


# ---------------------------------------------------------------------------
# RLP, this script's own
# ---------------------------------------------------------------------------

class DecodeError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def rlp_encode(item):
    """item is bytes (a string) or a list of items."""
    if isinstance(item, list):
        body = b"".join(rlp_encode(x) for x in item)
        return _prefix(0xC0, len(body)) + body
    if len(item) == 1 and item[0] <= 0x7F:
        return bytes(item)
    return _prefix(0x80, len(item)) + bytes(item)


def _prefix(base, length):
    if length <= 55:
        return bytes([base + length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(raw)]) + raw


def int_bytes(value):
    return value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""


def _read(data, at):
    """One item at `at`: (is_list, payload start, payload end)."""
    if at >= len(data):
        raise DecodeError("non-canonical-rlp")
    b = data[at]
    if b <= 0x7F:
        return False, at, at + 1
    is_list = b >= 0xC0
    short = b - (0xC0 if is_list else 0x80)
    if short <= 55:
        start, length = at + 1, short
        if not is_list and length == 1 and start < len(data) and data[start] <= 0x7F:
            raise DecodeError("non-canonical-rlp")
    else:
        size = short - 55
        raw = data[at + 1:at + 1 + size]
        if len(raw) != size or raw[0] == 0:
            raise DecodeError("non-canonical-rlp")
        length = int.from_bytes(raw, "big")
        if length <= 55:
            raise DecodeError("non-canonical-rlp")
        start = at + 1 + size
    end = start + length
    if end > len(data):
        raise DecodeError("non-canonical-rlp")
    return is_list, start, end


def decode_header(data):
    """The header fields of `data`, or DecodeError with the reason of
    section 10."""
    is_list, start, end = _read(data, 0)
    if not is_list:
        raise DecodeError("non-canonical-rlp")
    if end != len(data):
        raise DecodeError("trailing-bytes")
    items, at = [], start
    while at < end:
        sub_list, s, e = _read(data, at)
        if e > end:
            raise DecodeError("non-canonical-rlp")
        items.append((sub_list, data[s:e]))
        at = e
    if len(items) != len(HEADER) or any(sub for sub, _ in items):
        raise DecodeError("item-count")
    fields = {}
    for (name, kind, size), (_, value) in zip(HEADER, items):
        if kind == "fixed" and len(value) != size:
            raise DecodeError("field-size")
        if kind == "bytes" and len(value) > size:
            raise DecodeError("field-size")
        if kind == "int":
            if value[:1] == b"\x00":
                raise DecodeError("non-canonical-integer")
            if len(value) * 8 > size:
                raise DecodeError("integer-range")
            fields[name] = int.from_bytes(value, "big")
        else:
            fields[name] = bytes(value)
    return fields


def header_list(fields):
    return [int_bytes(fields[n]) if k == "int" else fields[n] for n, k, _ in HEADER]


def encode_header(fields):
    return rlp_encode(header_list(fields))


def with_fault(fields, fault):
    """The bytes of a header with one fault, as section 11 describes."""
    items = [rlp_encode(x) for x in header_list(fields)]
    at = HEADER_NAMES.index
    if fault == "forbidden-field":
        items.insert(at("baseFee") + 1, rlp_encode(keccak256(b"\x80")))
    elif fault == "extra-trailing-field":
        items.append(rlp_encode(b""))
    elif fault == "missing-required-field":
        items.pop(at("baseFee"))
    elif fault == "non-canonical-integer":
        body = b"\x00" + (int_bytes(fields["number"]) or b"\x00")
        items[at("number")] = _prefix(0x80, len(body)) + body
    elif fault == "short-tree-root":
        items[at("coinTreeRoot")] = rlp_encode(fields["coinTreeRoot"][:31])
    elif fault == "eighteen-items":
        items.pop(at(MARKER_FIELD))
    elif fault == "trailing-bytes":
        body = b"".join(items)
        return _prefix(0xC0, len(body)) + body + b"\x00"
    else:
        return None
    body = b"".join(items)
    return _prefix(0xC0, len(body)) + body


# ---------------------------------------------------------------------------
# The checker
# ---------------------------------------------------------------------------

class Checker:
    def __init__(self, text, spec01_text, spec06_text, encoder_vectors):
        self.text = text
        self.secs = sections(text)
        self.spec01 = spec01_text
        self.spec06 = spec06_text
        self.encoder_vectors = encoder_vectors
        self.errors = []
        self.params = {}
        self.roots = {"coin": set(), "data": set()}
        self.marker_roots = set()
        self.marker_sets = {}
        self.headers = {}

    def fail(self, message):
        self.errors.append(message)

    def section(self, word):
        names = find_section(self.secs, word)
        return self.secs[names[0]] if names else None

    def run(self):
        self.check_sections()
        self.check_parameters()
        self.check_page_table()
        self.check_storage_table()
        self.check_header_table()
        self.check_genesis_table_shape()
        self.check_tree_vectors()
        self.check_spec01_leaves()
        self.check_append_vectors()
        self.check_marker_set_vectors()
        self.check_witness_extension_vectors()
        self.check_marker_query_vectors()
        self.check_restore_reads()
        self.check_header_vectors()
        self.check_encoder()
        self.check_genesis_values()
        self.check_requirements()
        self.check_recovery_test()
        self.check_conflicts()
        self.check_tags()
        return self.errors

    # -- structure ---------------------------------------------------------

    def check_sections(self):
        numbers = []
        for line in self.text.splitlines():
            if line.startswith("## "):
                m = HEADING_RE.match(line)
                if not m:
                    self.fail(f"heading '{line}' is not numbered as '## N. Title'")
                    continue
                numbers.append(int(m.group(1)))
        if numbers != list(range(1, len(numbers) + 1)):
            self.fail(f"sections are numbered {numbers}, expected 1 upwards without gaps")
        for word in REQUIRED_SECTIONS:
            if not find_section(self.secs, word):
                self.fail(f"no '## N.' section whose title contains '{word}'")
        for word, needed in SECTION_WORDS.items():
            lines = self.section(word)
            if lines is None:
                continue
            body = " ".join(" ".join(lines).split()).lower()
            for phrase in needed:
                if phrase.lower() not in body:
                    self.fail(f"section '{word}' does not mention '{phrase}'")

    def check_parameters(self):
        lines = self.section("Trees and rollover")
        if lines is None:
            return
        rows = table_with(lines, ("Name", "Value", "Meaning"))
        if rows is None:
            self.fail("no parameters table (Name, Value, Meaning) in 'Trees and rollover'")
            return
        for row in rows:
            name = row["Name"].strip("`")
            value = number(row["Value"])
            if value is None:
                self.fail(f"parameter {name}: value '{row['Value']}' is not an integer")
                continue
            self.params[name] = value
        missing = [p for p in PARAMETERS if p not in self.params]
        if missing:
            self.fail(f"parameters missing: {missing}")
            return
        p = self.params
        if p["TREE_DEPTH"] != DEPTH:
            self.fail(f"TREE_DEPTH is {p['TREE_DEPTH']}; the target is {DEPTH}")
        if p["LEAVES_PER_TREE"] != LEAVES:
            self.fail(f"LEAVES_PER_TREE is {p['LEAVES_PER_TREE']}; the target is 2^32 = {LEAVES}")
        page = p["PAGE_LEAVES"]
        if page <= 1 or page & (page - 1) or page > 2**PAGE_DEPTH_MAX:
            self.fail(f"PAGE_LEAVES {page} is not a power of two from 2 to 2^{PAGE_DEPTH_MAX}")
        if p["LEAF_BYTES"] != 32 or p["MARKER_BYTES"] != 32:
            self.fail("LEAF_BYTES and MARKER_BYTES must be 32")
        if p["TREE_INDEX_MAX"] != INDEX_MAX:
            self.fail(f"TREE_INDEX_MAX is {p['TREE_INDEX_MAX']}, expected 2^64 - 1")
        m = NOTE_LENGTH_RE.search(self.spec01)
        if not m:
            self.fail("spec 01 states no note length ('**On the chain: N bytes, fixed.**')")
        elif int(m.group(1)) != p["NOTE_BYTES"]:
            self.fail(f"NOTE_BYTES is {p['NOTE_BYTES']}, spec 01 says {m.group(1)}")

    def _have_params(self):
        return all(name in self.params for name in PARAMETERS)

    def check_page_table(self):
        lines = self.section("Wallet tree data")
        if lines is None or not self._have_params():
            return
        rows = table_with(lines, ("Leaves per page", "Page bytes", "Pages per full tree",
                                  "Page-root list bytes"))
        if rows is None:
            self.fail("no page-size table in 'Wallet tree data'")
            return
        per_leaf = self.params["LEAF_BYTES"] + self.params["NOTE_BYTES"]
        sizes = []
        for row in rows:
            values = [number(row[c]) for c in ("Leaves per page", "Page bytes",
                                               "Pages per full tree", "Page-root list bytes")]
            if None in values or values[0] <= 0:
                self.fail(f"page table row {row} is not numeric")
                continue
            leaves, page_bytes, pages, list_bytes = values
            sizes.append(leaves)
            expect = (leaves * per_leaf, LEAVES // leaves, (LEAVES // leaves) * 32)
            if (page_bytes, pages, list_bytes) != expect:
                self.fail(f"page table row for {leaves} leaves says {(page_bytes, pages, list_bytes)}, "
                          f"recomputed {expect}")
        if self.params["PAGE_LEAVES"] not in sizes:
            self.fail(f"page table has no row for PAGE_LEAVES = {self.params['PAGE_LEAVES']}")

    def check_storage_table(self):
        lines = self.section("History availability")
        if lines is None or not self._have_params():
            return
        rows = table_with(lines, ("Item", "Count", "Bytes each", "Total bytes"))
        if rows is None:
            self.fail("no storage table (Item, Count, Bytes each, Total bytes) in 'History availability'")
            return
        p = self.params
        expected = {"Commitments": (LEAVES, p["LEAF_BYTES"]),
                    "Notes": (LEAVES, p["NOTE_BYTES"]),
                    "Page roots": (LEAVES // p["PAGE_LEAVES"], 32),
                    "Spent markers, at most": (LEAVES, p["MARKER_BYTES"])}
        seen, total, stated_total = set(), 0, None
        for row in rows:
            item = row["Item"]
            if item == "Total":
                stated_total = number(row["Total bytes"])
                continue
            count, each, total_bytes = (number(row[c]) for c in ("Count", "Bytes each", "Total bytes"))
            if item not in expected:
                self.fail(f"storage table has an unknown row '{item}'")
                continue
            seen.add(item)
            if (count, each) != expected[item]:
                self.fail(f"storage row '{item}' says {count} x {each}, expected "
                          f"{expected[item][0]} x {expected[item][1]}")
            if count is None or each is None or total_bytes != count * each:
                self.fail(f"storage row '{item}' total is {total_bytes}, recomputed "
                          f"{None if count is None or each is None else count * each}")
            else:
                total += total_bytes
        for item in expected:
            if item not in seen:
                self.fail(f"storage table has no row '{item}'")
        if stated_total != total:
            self.fail(f"storage table total is {stated_total}, recomputed {total}")

    # -- header ------------------------------------------------------------

    def check_header_table(self):
        lines = self.section("Header encoding")
        if lines is None:
            return
        rows = table_with(lines, ("Index", "Field", "Encoding", "Source"))
        if rows is None:
            self.fail("no header field table (Index, Field, Encoding, Source)")
            return
        names = [row["Field"].strip("`") for row in rows]
        markers = [(i, name) for i, name in enumerate(names) if "marker" in name.lower()]
        if markers != [(MARKER_FIELD_INDEX, MARKER_FIELD)]:
            self.fail(f"header marker fields are {markers}: the one marker-set root must be "
                      f"'{MARKER_FIELD}', field {MARKER_FIELD_INDEX}, and no coin marker-set "
                      "root may be added")
        if len(names) != len(HEADER):
            self.fail(f"the header table lists {len(names)} fields, expected exactly {len(HEADER)}")
        if names != list(HEADER_NAMES):
            self.fail(f"header fields are {names}, expected {list(HEADER_NAMES)}")
        for i, row in enumerate(rows):
            name = row["Field"].strip("`")
            if number(row["Index"]) != i:
                self.fail(f"header field '{name}' has index {row['Index']}, expected {i}")
            spec = dict((n, (k, s)) for n, k, s in HEADER).get(name)
            if spec is None:
                continue
            kind, size = spec
            encoding = {"fixed": f"{size} bytes", "bytes": f"at most {size} bytes",
                        "int": f"integer below 2^{size}"}[kind]
            if row["Encoding"] != encoding:
                self.fail(f"header field '{name}' encoding '{row['Encoding']}', expected '{encoding}'")
            source = row["Source"].lower()
            if name in GHOST_FIELDS and source != "ghost":
                self.fail(f"header field '{name}' must have source Ghost")
            if name not in GHOST_FIELDS and not source.startswith("base"):
                self.fail(f"header field '{name}' must have source base")
            if name == "baseFee" and "required" not in source:
                self.fail("the base fee is not marked required")
            if "optional" in source:
                self.fail(f"header field '{name}' is optional; no field may be")
        body = " ".join(" ".join(lines).split())
        if f"exactly {len(HEADER)} items" not in body:
            self.fail(f"the decoding rules do not say the list holds exactly {len(HEADER)} items")
        forbidden = table_with(lines, ("Field", "Base client name"))
        if forbidden is None:
            self.fail("no forbidden-field table (Field, Base client name)")
            return
        listed = {row["Field"].strip("`") for row in forbidden}
        for name in FORBIDDEN_FIELDS:
            if name not in listed:
                self.fail(f"forbidden field '{name}' is not listed")
        for name in listed & set(names):
            self.fail(f"forbidden field '{name}' is in the header")

    def genesis_rows(self):
        lines = self.section("Header encoding")
        if lines is None:
            return None
        return table_with(lines, ("Field", "Genesis value", "Fixed by"))

    def check_genesis_table_shape(self):
        rows = self.genesis_rows()
        if rows is None:
            self.fail("no genesis field table (Field, Genesis value, Fixed by)")
            return
        names = [row["Field"].strip("`") for row in rows]
        for name in HEADER_NAMES:
            if names.count(name) != 1:
                self.fail(f"genesis field '{name}' is listed {names.count(name)} times")
        for name in set(names) - set(HEADER_NAMES):
            self.fail(f"genesis table lists '{name}', which is not a header field")
        for row in rows:
            name, source = row["Field"].strip("`"), row["Fixed by"]
            want = "spec 06" if name in SPEC06_GENESIS else "this chapter"
            if source != want:
                self.fail(f"genesis field '{name}' is fixed by '{source}', expected '{want}'")
        if not self.spec06:
            self.fail("spec 06 not found; cannot check which genesis fields it fixes")
            return
        start = self.spec06.find("### 8.3")
        end = self.spec06.find("### 8.4")
        rule = " ".join(self.spec06[start:end].split()) if start >= 0 and end > start else ""
        if "defined in the header specification" not in rule:
            self.fail("spec 06, section 8.3 does not leave fields to the header specification")
        for name, word in SPEC06_GENESIS.items():
            if word not in rule:
                self.fail(f"spec 06, section 8.3 does not fix '{name}' ('{word}')")

    def check_genesis_values(self):
        rows = self.genesis_rows()
        genesis = self.headers.get("header-genesis-example")
        if rows is None or genesis is None:
            if genesis is None:
                self.fail("no vector header-genesis-example")
            return
        sizes = {n: (k, s) for n, k, s in HEADER}
        for row in rows:
            name = row["Field"].strip("`")
            if name not in sizes or row["Fixed by"] != "this chapter":
                continue
            kind, size = sizes[name]
            code = first_code(row["Genesis value"])
            if code is None:
                self.fail(f"genesis field '{name}' gives no value in backticks")
                continue
            if kind == "int":
                value = number(code)
            elif code == "zero":
                value = bytes(size)
            elif HEX_RE.match(code) and len(code) == 2 * size:
                value = bytes.fromhex(code)
            else:
                value = None
            if value is None or genesis.get(name) != value:
                self.fail(f"genesis field '{name}' is '{code}' in the table but differs in "
                          "header-genesis-example")
        fixed = {"parentHash": bytes(32), "uncleHash": keccak256(rlp_encode([])),
                 "coinbase": bytes(20), "difficulty": D_START, "number": 0,
                 "mixDigest": bytes(32), "nonce": bytes(8),
                 "stateRoot": keccak256(rlp_encode(b"")),
                 "transactionsRoot": keccak256(rlp_encode(b"")),
                 "receiptsRoot": keccak256(rlp_encode(b"")),
                 "coinTreeRoot": empty_roots(TAG_COIN_NODE)[DEPTH],
                 "dataTreeRoot": empty_roots(TAG_DATA_NODE)[DEPTH],
                 MARKER_FIELD: marker_set_root(marker_set_genesis())}
        for name, value in fixed.items():
            if genesis.get(name) != value:
                self.fail(f"header-genesis-example: '{name}' is not the genesis value")

    # -- vectors -----------------------------------------------------------

    def blocks(self):
        lines = self.section("Golden vectors")
        return vector_blocks(lines) if lines is not None else {}

    def check_tree_vectors(self):
        blocks = self.blocks()
        if not blocks:
            self.fail("no vectors in 'Golden vectors'")
            return
        zeros = {t: empty_roots(tag) for t, tag in NODE_TAGS.items()}
        kinds = {}
        for name, lines in blocks.items():
            v = dict(lines)
            kind = v.get("kind")
            if kind not in ("empty-tree", "tree-root", "page"):
                continue
            tree = v.get("tree")
            if tree not in NODE_TAGS:
                self.fail(f"vector {name}: tree '{tree}' is not coin or data")
                continue
            kinds.setdefault((kind, tree), []).append(name)
            tag = NODE_TAGS[tree]
            try:
                leaves = [bytes.fromhex(x) for x in v.get("leaves", "").split()]
                root = bytes.fromhex(v.get("root", ""))
            except ValueError:
                self.fail(f"vector {name}: leaves or root are not hex")
                continue
            if any(len(x) != 32 for x in leaves):
                self.fail(f"vector {name}: a leaf is not 32 bytes")
                continue
            if kind == "empty-tree":
                expect = zeros[tree][DEPTH]
            elif kind == "tree-root":
                expect = tree_root(tag, leaves)
            else:
                expect = self.check_page(name, v, tag, leaves, zeros[tree])
                if expect is None:
                    continue
            if root != expect:
                self.fail(f"vector {name}: root is {root.hex()}, recomputed {expect.hex()}")
            self.roots[tree].add(root)
        for kind in ("empty-tree", "tree-root"):
            for tree in NODE_TAGS:
                if not kinds.get((kind, tree)):
                    self.fail(f"no {kind} vector for the {tree} tree")
        if not any(k == "page" for k, _ in kinds):
            self.fail("no page vector")

    def check_spec01_leaves(self):
        """The tree vectors over spec 01's commitments hold exactly those
        commitments, in order, and spec 01 makes them with words keys."""
        try:
            spec01 = {v["name"]: v for v in
                      _ccv.parse_vectors(_ccv.section(self.spec01, "Test vectors"))}
        except ValueError:
            self.fail("no test vectors found in spec 01")
            return
        blocks = self.blocks()
        for name, sources in SPEC_01_LEAVES.items():
            if name not in blocks:
                self.fail(f"no vector {name}")
                continue
            leaves = dict(blocks[name]).get("leaves", "").split()
            if leaves != [spec01.get(s, {}).get("commitment") for s in sources]:
                self.fail(f"vector {name}: leaves are not the commitments of spec 01's "
                          f"{', '.join(sources)}")
        for source in sorted({s for sources in SPEC_01_LEAVES.values() for s in sources}):
            digits = re.sub(r"[ -]", "", spec01.get(source, {}).get("key", ""))
            if len(digits) != 4 * WORDS_KEY_GROUPS:
                self.fail(f"spec 01 vector {source} is not made with a words key")

    def check_page(self, name, v, tag, leaves, z):
        page_leaves = self.params.get("PAGE_LEAVES", 0)
        if page_leaves <= 1 or page_leaves & (page_leaves - 1):
            return None
        depth = page_leaves.bit_length() - 1
        page = number(v.get("page", ""))
        if page is None or not 0 <= page < LEAVES // page_leaves or len(leaves) > page_leaves:
            self.fail(f"vector {name}: page number or leaf count out of range")
            return None
        stated = v.get("page-root", "")
        computed = page_root(tag, leaves, depth)
        if stated != computed.hex():
            self.fail(f"vector {name}: page-root is {stated}, recomputed {computed.hex()}")
        if v.get("empty-page-root") != z[depth].hex():
            self.fail(f"vector {name}: empty-page-root is {v.get('empty-page-root')}, "
                      f"recomputed {z[depth].hex()}")
        from_pages = sparse_root(tag, {page: computed}, depth)
        direct = tree_root(tag, leaves, page * page_leaves)
        if from_pages != direct:
            self.fail(f"vector {name}: the root from page roots differs from the tree root")
        return from_pages

    def check_append_vectors(self):
        found = {}
        for name, lines in self.blocks().items():
            v = dict(lines)
            if v.get("kind") != "append":
                continue
            ints = {k: number(v.get(k, "")) for k in ("index-before", "count-before")}
            flag = v.get("filled-this-block")
            if None in ints.values() or flag not in ("yes", "no"):
                self.fail(f"vector {name}: malformed append vector")
                continue
            if not 0 <= ints["count-before"] <= LEAVES or not 0 <= ints["index-before"] <= INDEX_MAX:
                self.fail(f"vector {name}: state out of range")
                continue
            ok, index, count, position = append(ints["index-before"], ints["count-before"], flag == "yes")
            want = {"includable": "yes" if ok else "no", "index-after": str(index),
                    "count-after": str(count),
                    "position": "none" if position is None else str(position)}
            for key, value in want.items():
                if v.get(key) != value:
                    self.fail(f"vector {name}: {key} is {v.get(key)}, recomputed {value}")
            found[name] = (ints["count-before"] == LEAVES, flag == "yes", ok, index)
        cases = found.values()
        if not any(full and not filled and ok for full, filled, ok, _ in cases):
            self.fail("no rollover vector (a full tree, the next append goes to the next index)")
        if not any(full and filled and not ok for full, filled, ok, _ in cases):
            self.fail("no vector for an append in the block that filled the tree")
        if not any(full and not ok and index == INDEX_MAX for full, _, ok, index in cases):
            self.fail("no vector for an exhausted tree index")

    def _hex32(self, name, key, raw):
        if raw is None or not HEX_RE.match(raw) or len(raw) != 64:
            self.fail(f"vector {name}: '{key}' is not 32 bytes of hex")
            return None
        return bytes.fromhex(raw)

    def _leaf_text(self, leaf):
        value, next_value, next_index = leaf
        return f"{value.hex()} {next_value.hex()} {next_index.to_bytes(INDEX_BYTES, 'big').hex()}"

    def check_marker_set_vectors(self):
        blocks = self.blocks()
        try:
            spec01 = {v["name"]: v for v in
                      _ccv.parse_vectors(_ccv.section(self.spec01, "Test vectors"))}
        except ValueError:
            spec01 = {}
        absences = []
        for name, lines in blocks.items():
            v = dict(lines)
            if v.get("kind") == "marker-set-absence":
                absences.append((name, v))
                continue
            if v.get("kind") != "marker-set":
                continue
            markers = [self._hex32(name, "markers", x) for x in v.get("markers", "").split()]
            if None in markers:
                continue
            try:
                leaves = marker_set(markers)
            except MarkerRejected as e:
                self.fail(f"vector {name}: a marker cannot be inserted ({e})")
                continue
            self.marker_sets[name] = leaves
            if v.get("count") != str(len(leaves)):
                self.fail(f"vector {name}: count is {v.get('count')}, recomputed {len(leaves)}")
            stated = [(k, x) for k, x in lines if k.startswith("leaf-")]
            want = [(f"leaf-{p}", self._leaf_text(leaf)) for p, leaf in enumerate(leaves)]
            if stated != want:
                self.fail(f"vector {name}: the leaves differ from the insertions, recomputed "
                          f"{want}")
            root = marker_set_root(leaves)
            if v.get("root") != root.hex():
                self.fail(f"vector {name}: root is {v.get('root')}, recomputed {root.hex()}")
            self.marker_roots.add(root)
            sources = SPEC_01_MARKERS.get(name)
            if sources is not None and spec01 and \
                    [m.hex() for m in markers] != [spec01.get(s, {}).get("marker") for s in sources]:
                self.fail(f"vector {name}: markers are not the data markers of spec 01's "
                          f"{', '.join(sources) or 'no vector'}")
        for name, v in absences:
            self.check_absence_vector(name, v)
        for name in MARKER_SET_VECTORS:
            if name not in blocks:
                self.fail(f"no vector {name}")
        empty = self.marker_sets.get("marker-set-empty")
        if empty is not None and empty != marker_set_genesis():
            self.fail("vector marker-set-empty: the set holds more than the sentinel")

    def check_absence_vector(self, name, v):
        leaves = self.marker_sets.get(v.get("set"))
        if leaves is None:
            self.fail(f"vector {name}: set '{v.get('set')}' is not a marker-set vector")
            return
        root = marker_set_root(leaves)
        if v.get("root") != root.hex():
            self.fail(f"vector {name}: root is {v.get('root')}, the root of {v.get('set')} is "
                      f"{root.hex()}")
        marker = self._hex32(name, "marker", v.get("marker"))
        raw = v.get("absence", "")
        if marker is None or not HEX_RE.match(raw) or len(raw) % 2:
            self.fail(f"vector {name}: marker or absence is not hex")
            return
        witness = bytes.fromhex(raw)
        if len(witness) != ABSENCE_BYTES:
            self.fail(f"vector {name}: absence is {len(witness)} bytes, expected {ABSENCE_BYTES}")
            return
        try:
            expect = absence_witness(leaves, marker)
        except MarkerRejected as e:
            self.fail(f"vector {name}: no absence witness for the marker ({e})")
            return
        if witness != expect:
            self.fail(f"vector {name}: absence differs from the witness recomputed from the set")
        position = int.from_bytes(witness[69:74], "big")
        low = (witness[0:32], witness[32:64], int.from_bytes(witness[64:69], "big"))
        if v.get("low-position") != str(position):
            self.fail(f"vector {name}: low-position is {v.get('low-position')}, the witness says "
                      f"{position}")
        if v.get("low-leaf") != self._leaf_text(low):
            self.fail(f"vector {name}: low-leaf differs from the witness")
        reason = check_absence(root, marker, witness)
        if (reason is None) != (v.get("valid") == "yes"):
            self.fail(f"vector {name}: valid is {v.get('valid')}, the witness check gives "
                      f"{'yes' if reason is None else reason}")
        value, next_value, _ = low
        relations = {"reject-equal": lambda m: m == value,
                     "reject-below": lambda m: m < value,
                     "reject-above-next": lambda m: next_value != bytes(32) and m > next_value}
        for key in ABSENCE_REJECTS:
            m = self._hex32(name, key, v.get(key))
            if m is None:
                continue
            if not relations[key](m):
                self.fail(f"vector {name}: {key} does not have its relation to the low leaf")
            if check_absence(root, m, witness) is None:
                self.fail(f"vector {name}: the witness is accepted for {key}")

    def _hex_list(self, name, key, v, count=None):
        values = [self._hex32(name, key, x) for x in v.get(key, "").split()]
        if None in values:
            return None
        if count is not None and len(values) != count:
            self.fail(f"vector {name}: '{key}' holds {len(values)} values, expected {count}")
            return None
        return values

    def check_witness_extension_vectors(self):
        blocks = self.blocks()
        page_leaves = self.params.get("PAGE_LEAVES", 0)
        if page_leaves > 1 and not page_leaves & (page_leaves - 1):
            for name, lines in blocks.items():
                v = dict(lines)
                if v.get("kind") == "witness-extension":
                    self.check_witness_extension(name, v, page_leaves)
        for name in WITNESS_EXTENSION_VECTORS:
            if name not in blocks:
                self.fail(f"no vector {name}")

    def check_witness_extension(self, name, v, page_leaves):
        """A stored witness extended from count-before to count-after: the
        page-root list (the stored roots below the tail, then the tail) must
        hash to the header root, and the witness after must be the one
        recomputed from it and hash to that root."""
        depth = page_leaves.bit_length() - 1
        tag = NODE_TAGS.get(v.get("tree"))
        ints = {k: number(v.get(k, "")) for k in ("position", "count-before", "count-after",
                                                   "scan-start", "tail-start")}
        if tag is None or None in ints.values():
            self.fail(f"vector {name}: malformed witness-extension vector")
            return
        position, before, after = ints["position"], ints["count-before"], ints["count-after"]
        if not 0 <= position < before <= after <= LEAVES:
            self.fail(f"vector {name}: position and counts out of range")
            return
        start, scan = ints["tail-start"], ints["scan-start"]
        if start != scan // TAIL_PAGES * TAIL_PAGES:
            self.fail(f"vector {name}: tail-start is {start}, expected the scan start {scan} "
                      f"rounded down to a multiple of {TAIL_PAGES} pages")
        stored = self._hex_list(name, "stored-page-roots", v)
        tail = self._hex_list(name, "page-roots", v)
        before_w = self._hex_list(name, "witness-before", v, DEPTH)
        after_w = self._hex_list(name, "witness-after", v, DEPTH)
        root_before = self._hex32(name, "header-root-before", v.get("header-root-before"))
        root = self._hex32(name, "header-root", v.get("header-root"))
        if None in (stored, tail, before_w, after_w, root_before, root):
            return
        if len(stored) != start:
            self.fail(f"vector {name}: stored-page-roots holds {len(stored)} roots, expected the "
                      f"{start} below the tail")
            return
        roots, page = stored + tail, position // page_leaves
        if len(roots) != (after - 1) // page_leaves + 1:
            self.fail(f"vector {name}: the page-root list holds {len(roots)} pages, the tree at "
                      f"count-after {after} has {(after - 1) // page_leaves + 1}")
            return
        list_root = sparse_root(tag, dict(enumerate(roots)), depth)
        if list_root != root:
            self.fail(f"vector {name}: the page-root tail does not hash to the header root; the "
                      f"list and Z_{depth} give {list_root.hex()}")
        first = page * page_leaves
        if "leaves-after" in v:
            # The leaf's page is not full: it is read whole, with decoy pages.
            leaves_before = self._hex_list(name, "leaves-before", v)
            leaves_after = self._hex_list(name, "leaves-after", v)
            if leaves_before is None or leaves_after is None:
                return
            if (len(leaves_before) != before - first or len(leaves_after) != min(after - first, page_leaves)
                    or leaves_after[:len(leaves_before)] != leaves_before):
                self.fail(f"vector {name}: leaves-before and leaves-after are not page {page} at "
                          "count-before and count-after")
                return
            if len(leaves_after) == page_leaves:
                self.fail(f"vector {name}: page {page} is full; give its in-page siblings instead")
                return
            self.check_page_read(name, v, page, after, page_leaves)
            leaf = leaves_after[position - first]
            own = page_root(tag, leaves_after, depth)
            if roots[page] != own:
                self.fail(f"vector {name}: page-roots: the root of page {page} is not the root of "
                          f"the page read whole, {own.hex()}")
            expect = witness(tag, leaves_before, roots[:page] + [page_root(tag, leaves_before, depth)],
                             position, depth)
            if before_w != expect:
                self.fail(f"vector {name}: witness-before differs from the witness at count-before, "
                          f"recomputed {' '.join(x.hex() for x in expect)}")
            expect = witness(tag, leaves_after, roots, position, depth)
        else:
            # The leaf's page is full: its in-page siblings are final.
            leaf = self._hex32(name, "leaf", v.get("leaf"))
            in_page = self._hex_list(name, "in-page-siblings", v, depth)
            if leaf is None or in_page is None:
                return
            if before < first + page_leaves:
                self.fail(f"vector {name}: page {page} is not full at count-before; it is read whole")
                return
            if before_w[:depth] != in_page:
                self.fail(f"vector {name}: witness-before does not start with the in-page siblings")
            climbed = fold(tag, leaf, position % page_leaves, in_page)
            if roots[page] != climbed:
                self.fail(f"vector {name}: page-roots: the root of page {page} is not the root "
                          f"climbed from the leaf, {climbed.hex()}")
            expect = in_page + path_siblings(tag, dict(enumerate(roots)), depth, page)
        at = fold(tag, leaf, position, before_w)
        if at != root_before:
            self.fail(f"vector {name}: witness-before does not hash to header-root-before; it "
                      f"gives {at.hex()}")
        if after_w != expect:
            self.fail(f"vector {name}: witness-after differs from the witness recomputed from the "
                      f"page roots, {' '.join(x.hex() for x in expect)}")
        if fold(tag, leaf, position, after_w) != root:
            self.fail(f"vector {name}: witness-after does not hash to the header root at "
                      "count-after")

    def check_page_read(self, name, v, page, count, page_leaves):
        """The 8-page read: the leaf's page and decoy full pages, distinct, in
        page order; every page when the tree has fewer than 8."""
        pages = [number(x) for x in v.get("pages-read", "").split()]
        want = min(PAGE_READ, (count - 1) // page_leaves + 1)
        full = count // page_leaves
        if (None in pages or len(set(pages)) != want or pages != sorted(set(pages))
                or page not in pages or any(p != page and not 0 <= p < full for p in pages)):
            self.fail(f"vector {name}: pages-read is not {want} distinct pages in page order, page "
                      f"{page} and {want - 1} full decoy pages")

    def check_marker_query_vectors(self):
        blocks = self.blocks()
        spent = {value.hex() for leaves in self.marker_sets.values() for value, _, _ in leaves[1:]}
        for name, lines in blocks.items():
            v = dict(lines)
            if v.get("kind") == "marker-query":
                self.check_marker_query(name, v, spent)
        for name in MARKER_QUERY_VECTORS:
            if name not in blocks:
                self.fail(f"no vector {name}")

    def check_marker_query(self, name, v, spent):
        """A status query is served only with exactly 64 distinct markers; a
        "spent" answer needs a reveal receipt of its block, and "not spent"
        leaves the real marker unchecked."""
        if v.get("type") not in NODE_TAGS:
            self.fail(f"vector {name}: type '{v.get('type')}' is not coin or data")
        markers = v.get("markers", "").split()
        reason = query_reject(markers)
        if (reason is None) != (v.get("valid") == "yes"):
            self.fail(f"vector {name}: valid is {v.get('valid')}, a query of {len(markers)} "
                      f"markers gives {'yes' if reason is None else reason}")
            return
        if reason is not None:
            if v.get("reject") != reason:
                self.fail(f"vector {name}: rejected as {reason}, the vector says {v.get('reject')}")
            return
        real = v.get("real")
        if markers.count(real) != 1:
            self.fail(f"vector {name}: real is not one of the markers")
            return
        for m in markers:
            if m != real and m in spent:
                self.fail(f"vector {name}: decoy {m} is a spent marker of a marker-set vector")
        answers = v.get("answers", "").split()
        if len(answers) != len(markers):
            self.fail(f"vector {name}: {len(answers)} answers for {len(markers)} markers")
            return
        checked = {}
        for m, answer in zip(markers, answers):
            if answer == "not-spent":
                continue
            block = number(answer[len("spent-"):]) if answer.startswith("spent-") else None
            if block is None:
                self.fail(f"vector {name}: answer '{answer}' is not spent-N or not-spent")
                continue
            checked[m] = m in v.get(f"receipt-markers-{block}", "").split()
            if not checked[m]:
                self.fail(f"vector {name}: the answer spent-{block} for {m} has no receipt: no "
                          f"reveal receipt of block {block} carries it")
        if real not in checked:
            status = "unchecked-not-reported-spent"
        else:
            status = "spent" if checked[real] else "rejected"
        if v.get("status") != status:
            self.fail(f"vector {name}: status is {v.get('status')}, the answer for the real marker "
                      f"gives {status}")

    def check_restore_reads(self):
        """Section 8 states the tail read, the status query and their cost, and
        its "Forbidden." paragraph, TH-19, the "Marker status." Rule and
        section 12, item 4 follow them."""
        lines = self.section("Wallet tree data")
        if lines is None:
            return
        for title, words in RESTORE_SUBSECTIONS.items():
            body = subsection(lines, title)
            if body is None:
                self.fail(f"section 'Wallet tree data' has no subsection '{title}'")
                continue
            text = " ".join(" ".join(body).split()).lower()
            for word in words:
                if word.lower() not in text:
                    self.fail(f"subsection '{title}' does not mention '{word}'")
        forbidden = paragraph(lines, "**Forbidden.**")
        th19 = next((body for n, _, body in entries(lines, TH_RE) if n == 19), None)
        for label, text in (("the 'Forbidden.' paragraph", forbidden), ("TH-19", th19)):
            if text is None:
                self.fail(f"section 'Wallet tree data' has no {label}")
                continue
            for read in ALLOWED_READS:
                if read not in text.lower():
                    self.fail(f"{label} does not name the {read}")
            if "exactly 64 distinct" not in text.lower():
                self.fail(f"{label} does not refuse a status query that is not exactly 64 "
                          "distinct markers")
        status = paragraph(lines, "**Marker status.**")
        settled = self.section("Not settled")
        item4 = next((body for n, _, body in entries(settled or [], CONFLICT_RE) if n == 4), None)
        for label, text in (("the 'Marker status.' Rule", status), ("section 12, item 4", item4)):
            text = (text or "").lower()
            if UNCHECKED_STATUS not in text or "marker pages" not in text:
                self.fail(f"{label} does not keep 'unknown' for marker pages and give "
                          f"'{UNCHECKED_STATUS}' for a 64-marker query")

    def parse_header_fields(self, name, v):
        fields = {}
        for field, kind, size in HEADER:
            raw = v.get(field)
            if raw is None:
                self.fail(f"vector {name}: field '{field}' missing")
                return None
            if kind == "int":
                value = number(raw)
                if value is None or not 0 <= value < 2**size:
                    self.fail(f"vector {name}: '{field}' is not an integer in range")
                    return None
            else:
                if not HEX_RE.match(raw) or len(raw) % 2:
                    self.fail(f"vector {name}: '{field}' is not hex")
                    return None
                value = bytes.fromhex(raw)
                if (kind == "fixed" and len(value) != size) or len(value) > size:
                    self.fail(f"vector {name}: '{field}' has the wrong size")
                    return None
            fields[field] = value
        return fields

    def check_header_vectors(self):
        blocks = self.blocks()
        negatives = []
        for name, lines in blocks.items():
            v = dict(lines)
            if v.get("kind") == "header-negative":
                negatives.append((name, v))
                continue
            if v.get("kind") != "header":
                continue
            fields = self.parse_header_fields(name, v)
            if fields is None:
                continue
            self.headers[name] = fields
            encoded = encode_header(fields)
            if v.get("rlp") != encoded.hex():
                self.fail(f"vector {name}: rlp differs from the re-encoding")
            if v.get("hash") != keccak256(encoded).hex():
                self.fail(f"vector {name}: hash is {v.get('hash')}, recomputed {keccak256(encoded).hex()}")
            if v.get("valid") != "yes":
                self.fail(f"vector {name}: a well-formed header must have valid = yes")
            try:
                if decode_header(bytes.fromhex(v.get("rlp", ""))) != fields:
                    self.fail(f"vector {name}: rlp decodes to other fields")
            except (DecodeError, ValueError) as e:
                self.fail(f"vector {name}: rlp does not decode ({e})")
            for tree, field in (("coin", "coinTreeRoot"), ("data", "dataTreeRoot")):
                if fields[field] not in self.roots[tree]:
                    self.fail(f"vector {name}: {field} is not the root of any {tree} tree vector")
            if fields[MARKER_FIELD] not in self.marker_roots:
                self.fail(f"vector {name}: {MARKER_FIELD} is not the root of any marker-set vector")
        genesis = self.headers.get("header-genesis-example")
        one = self.headers.get("header-block-one-example")
        if genesis is None or one is None:
            self.fail("header vectors header-genesis-example and header-block-one-example are required")
        else:
            if one["parentHash"] != keccak256(encode_header(genesis)):
                self.fail("header-block-one-example: parentHash is not the genesis example's hash")
            for header, fields, vector in (("header-genesis-example", genesis, "marker-set-empty"),
                                           ("header-block-one-example", one, "marker-set-two-markers")):
                want = self.marker_sets.get(vector)
                if want is not None and fields[MARKER_FIELD] != marker_set_root(want):
                    self.fail(f"{header}: {MARKER_FIELD} is not the root of {vector}")
        faults = set()
        for name, v in negatives:
            base = self.headers.get(v.get("base"))
            if base is None:
                self.fail(f"vector {name}: base vector '{v.get('base')}' not found")
                continue
            fault = v.get("fault")
            derived = with_fault(base, fault)
            if derived is None:
                self.fail(f"vector {name}: unknown fault '{fault}'")
                continue
            faults.add(fault)
            if v.get("rlp") != derived.hex():
                self.fail(f"vector {name}: rlp differs from the re-derived faulty header")
            if v.get("valid") != "no":
                self.fail(f"vector {name}: a faulty header must have valid = no")
            try:
                decode_header(bytes.fromhex(v.get("rlp", "")))
                self.fail(f"vector {name}: the decoder accepts it")
            except DecodeError as e:
                if e.reason != v.get("reject"):
                    self.fail(f"vector {name}: rejected as {e.reason}, the vector says {v.get('reject')}")
            except ValueError:
                self.fail(f"vector {name}: rlp is not hex")
        for fault in REQUIRED_FAULTS:
            if fault not in faults:
                self.fail(f"no negative header vector with fault '{fault}'")

    def check_encoder(self):
        if self.encoder_vectors is None:
            self.fail(f"the separately written encoder {ENCODER.name} could not be run")
            return
        blocks = {n: lines for n, lines in self.blocks().items()
                  if dict(lines).get("kind") in ("header", "header-negative")}
        produced = dict(self.encoder_vectors)
        for name, lines in produced.items():
            if name not in blocks:
                self.fail(f"encoder vector {name} is not in the chapter")
            elif blocks[name] != list(lines):
                self.fail(f"vector {name} differs from the encoder's output")
        for name in blocks:
            if name not in produced:
                self.fail(f"header vector {name} is not produced by the encoder")

    # -- requirements, recovery test, conflicts, tags ----------------------

    def check_requirements(self):
        lines = self.text.splitlines()
        items = entries(lines, TH_RE)
        numbers = [n for n, _, _ in items]
        if not items:
            self.fail("no conformance requirements (- **TH-n. ...**)")
        if numbers != list(range(1, len(numbers) + 1)):
            self.fail(f"requirements are numbered {numbers}, expected TH-1 upwards without gaps")
        for n, _, body in items:
            if "Expected:" not in body:
                self.fail(f"TH-{n} states no expected result ('Expected:')")
        defined = set(numbers)
        for ref in sorted({int(x) for x in TH_REF_RE.findall(self.text)}):
            if ref not in defined:
                self.fail(f"TH-{ref} is cited but not defined")
        for word in TH_SECTIONS:
            body = self.section(word)
            if body is not None and not entries(body, TH_RE):
                self.fail(f"section '{word}' has no conformance requirement")

    def check_recovery_test(self):
        lines = self.section("History availability")
        if lines is None:
            return
        items = entries(lines, RT_RE)
        numbers = [n for n, _, _ in items]
        if not items:
            self.fail("no recovery test (- **RT-n. ...**) in 'History availability'")
            return
        if numbers != list(range(1, len(numbers) + 1)):
            self.fail(f"recovery test steps are numbered {numbers}, expected RT-1 upwards")
        for n, _, body in items:
            if "Expected:" not in body:
                self.fail(f"RT-{n} states no expected result ('Expected:')")
        text = " ".join(body for _, _, body in items).lower()
        for word in ("indexer", "rollover", "clean device", "digits"):
            if word not in text:
                self.fail(f"the recovery test does not cover '{word}'")

    def check_conflicts(self):
        lines = self.section("Conflicts with other chapters")
        if lines is None:
            return
        items = [body.lower() for _, _, body in entries(lines, CONFLICT_RE)]
        if not items:
            self.fail("no numbered conflicts")
        for chapter, place in REQUIRED_CONFLICTS:
            if not any(chapter in body and place in body for body in items):
                self.fail(f"no conflict citing {chapter}, {place}")

    def check_tags(self):
        known = set()
        for line in self.spec01.splitlines():
            if line.startswith("| `ghost/"):
                known.add(line.strip("|").split("|")[0].strip().strip("`"))
        if not known:
            self.fail("no tag table found in spec 01")
            return
        for tag in (TAG_COIN_NODE, TAG_DATA_NODE, TAG_EMPTY_LEAF, TAG_MARKER_SET_LEAF,
                    TAG_MARKER_SET_NODE):
            if tag not in known:
                self.fail(f"tree tag {tag} is not in the tag table of spec 01")
        for tag in sorted(set(TAG_RE.findall(self.text))):
            if tag not in known:
                self.fail(f"tag {tag} is not in the tag table of spec 01")


def load_encoder_vectors(path=ENCODER):
    """The encoder's vectors as (name, [(key, value), ...]), or None if it
    cannot be loaded or imports the checker."""
    try:
        source = Path(path).read_text(encoding="utf-8")
        if "check_trees_and_headers" in source:
            return None
        spec = importlib.util.spec_from_file_location("_header_golden_encoder", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return [(name, list(lines)) for name, lines in module.golden_vectors()]
    except Exception:  # any failure to run the encoder is a gap, never a pass
        return None


def check_text(text, spec01_text, spec06_text, encoder_vectors):
    """All gaps found in the text of the specification (empty when complete)."""
    return Checker(text, spec01_text, spec06_text, encoder_vectors).run()


def run(path):
    path = Path(path)
    texts = []
    for name in (SPEC_01, SPEC_06):
        sibling = path.parent / name
        texts.append(sibling.read_text(encoding="utf-8") if sibling.exists() else "")
    return check_text(path.read_text(encoding="utf-8"), texts[0], texts[1], load_encoder_vectors())


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_SPEC
    if not path.exists():
        print(f"MISSING: {path}")
        return 1
    errors = run(path)
    for e in errors:
        print("GAP: " + e)
    if errors:
        print(f"{len(errors)} gap(s) in {path}")
        return 1
    print(f"Trees and headers complete: {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
