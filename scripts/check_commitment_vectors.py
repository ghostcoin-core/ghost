#!/usr/bin/env python3
"""Recompute the test vectors of the commitments and keys specification.

Reads every vector block in the "Test vectors" section of
docs/spec/01-commitments-and-keys.md, recomputes the Phantom Key checksum and
every derivation from the rules in that document, and exits nonzero on any
mismatch. Every key is a words key, read from its digit view: code 0x20, the 80
secret digits and their check group 21; any other number of digits, the
retired twelve- and twenty-four-group digit keys among them, is refused. It
also checks that the tag table lists exactly the tags used here,
with the right input sizes, that the same secret under two salts gives
unrelated fingerprints, commitments and markers, and that every note vector
has a version 2 type tag and is the note of a commitment vector. It recomputes
the note lookup tag of the note nonce and the bucket rule. Commitment
format version 2, the salted format, is the only one: a vector of another
kind or a type tag of another version is refused.

Only the standard library is used. Keccak-256 (original padding) is written
out below, because hashlib.sha3_256 applies the FIPS 202 padding and gives
different digests. The Keccak code is checked against known Keccak-256 values
and, with the FIPS 202 padding byte, against hashlib.sha3_256.

Usage: python3 scripts/check_commitment_vectors.py [path-to-spec]
"""

import hashlib
import re
import sys
from pathlib import Path

DEFAULT_SPEC = (
    Path(__file__).resolve().parent.parent / "docs" / "spec" / "01-commitments-and-keys.md"
)

# ---------------------------------------------------------------------------
# Keccak-256
# ---------------------------------------------------------------------------

_MASK = (1 << 64) - 1


def _rc_bit(t):
    """FIPS 202, algorithm 5: one bit of the round-constant LFSR."""
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


_ROUND_CONSTANTS = []
for _round in range(24):
    _c = 0
    for _j in range(7):
        if _rc_bit(_j + 7 * _round):
            _c |= 1 << ((1 << _j) - 1)
    _ROUND_CONSTANTS.append(_c)

_ROTATIONS = [[0] * 5 for _ in range(5)]
_x, _y = 1, 0
for _t in range(24):
    _ROTATIONS[_x][_y] = ((_t + 1) * (_t + 2) // 2) % 64
    _x, _y = _y, (2 * _x + 3 * _y) % 5


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _MASK


def _keccak_f(a):
    """Keccak-f[1600] on 25 lanes indexed x + 5 * y."""
    for rc in _ROUND_CONSTANTS:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROTATIONS[x][y])
        a = [
            b[i] ^ (~b[(i + 1) % 5 + 5 * (i // 5)] & b[(i + 2) % 5 + 5 * (i // 5)])
            for i in range(25)
        ]
        a[0] ^= rc
    return a


def _sponge256(data, pad):
    """256-bit output, rate 136 bytes, with the given first padding byte."""
    rate = 136
    msg = bytearray(data)
    msg.append(pad)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(msg[off + 8 * i : off + 8 * i + 8], "little")
        state = _keccak_f(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


def keccak256(data):
    return _sponge256(data, 0x01)


KNOWN_KECCAK = {
    b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
}


def keccak_self_test():
    """Return a list of failures of the Keccak code against known values."""
    failures = []
    for message, digest in KNOWN_KECCAK.items():
        if keccak256(message).hex() != digest:
            failures.append(f"Keccak-256({message!r}) does not match the known value")
    # Same permutation and absorption, FIPS 202 padding: must equal hashlib,
    # across the block boundaries.
    for length in (0, 1, 55, 135, 136, 137, 271, 272, 273, 500):
        message = bytes((7 * i + 3) % 256 for i in range(length))
        if _sponge256(message, 0x06) != hashlib.sha3_256(message).digest():
            failures.append(f"Keccak permutation differs from hashlib at length {length}")
    return failures


# ---------------------------------------------------------------------------
# The rules of the specification
# ---------------------------------------------------------------------------

TAG_KEY_CHECK = "ghost/key-check/v1"
TAG_SECRET = "ghost/secret/v1"
TAG_REVEAL_SECRET = "ghost/reveal-secret/v1"
TAG_BLINDING = "ghost/blinding/v1"
TAG_NOTE_KEY = "ghost/note-key/v1"
TAG_DATA_KEY = "ghost/data-key/v1"
TAG_NOTE_TAG = "ghost/note-tag/v1"
TAG_COIN_FINGERPRINT_V2 = "ghost/coin-fingerprint/v2"
TAG_COIN_COMMITMENT = "ghost/coin-commitment/v1"
TAG_DATA_FINGERPRINT_V2 = "ghost/data-fingerprint/v2"
TAG_DATA_COMMITMENT = "ghost/data-commitment/v1"
TAG_CONTENT_FINGERPRINT = "ghost/content-fingerprint/v1"
TAG_COIN_MARKER_V2 = "ghost/coin-marker/v2"
TAG_DATA_MARKER_V2 = "ghost/data-marker/v2"
TAG_COIN_TREE_NODE = "ghost/coin-tree-node/v1"
TAG_DATA_TREE_NODE = "ghost/data-tree-node/v1"
TAG_EMPTY_LEAF = "ghost/empty-leaf/v1"
TAG_DATA_MARKER_SET_LEAF = "ghost/data-marker-set-leaf/v1"
TAG_DATA_MARKER_SET_NODE = "ghost/data-marker-set-node/v1"
TAG_COIN_REVEAL_BINDING = "ghost/coin-reveal-binding/v1"
TAG_DATA_REVEAL_BINDING = "ghost/data-reveal-binding/v1"
TAG_HOLD_BINDING = "ghost/hold-binding/v1"

ALL_TAGS = {
    TAG_KEY_CHECK,
    TAG_SECRET,
    TAG_REVEAL_SECRET,
    TAG_BLINDING,
    TAG_NOTE_KEY,
    TAG_DATA_KEY,
    TAG_NOTE_TAG,
    TAG_COIN_FINGERPRINT_V2,
    TAG_COIN_COMMITMENT,
    TAG_DATA_FINGERPRINT_V2,
    TAG_DATA_COMMITMENT,
    TAG_CONTENT_FINGERPRINT,
    TAG_COIN_MARKER_V2,
    TAG_DATA_MARKER_V2,
    TAG_COIN_TREE_NODE,
    TAG_DATA_TREE_NODE,
    TAG_EMPTY_LEAF,
    TAG_DATA_MARKER_SET_LEAF,
    TAG_DATA_MARKER_SET_NODE,
    TAG_COIN_REVEAL_BINDING,
    TAG_DATA_REVEAL_BINDING,
    TAG_HOLD_BINDING,
}

# The one key format (section 5): a words key, read here from its digit view of
# 21 groups, the 80 secret digits and the check group 21.
FORMAT_WORDS = 0x20
WORDS_GROUPS = 21
WORDS_SECRET_GROUPS = 20
SECRET_LIMIT = 1 << 256

# Commitment format version (section 10): version 2, the salted format, is the
# only one. Any other version byte is rejected, never guessed.
VERSION_2 = 0x02
TYPE_CODES = {"COIN": 0x01, "DATA": 0x02}
SALT_LENGTH = 16

# Per version: (fingerprint tag, marker tag) of each type. The commitment tags
# keep their v1 suffix, because their input layout did not change.
VERSION_TAGS = {
    VERSION_2: {
        "COIN": (TAG_COIN_FINGERPRINT_V2, TAG_COIN_MARKER_V2),
        "DATA": (TAG_DATA_FINGERPRINT_V2, TAG_DATA_MARKER_V2),
    },
}
COMMITMENT_TAGS = {"COIN": TAG_COIN_COMMITMENT, "DATA": TAG_DATA_COMMITMENT}

# Inputs after the tag of each fixed-layout Keccak-256 tag, in bytes, for the
# input-size columns of the tag table.
TAG_LAYOUTS = {
    TAG_COIN_FINGERPRINT_V2: (32, 32, 32, SALT_LENGTH, 2, 32, 32),
    TAG_COIN_COMMITMENT: (2, 32, 32),
    TAG_DATA_FINGERPRINT_V2: (32, 32, 32, SALT_LENGTH, 2, 32, 32),
    TAG_DATA_COMMITMENT: (2, 32, 32),
    TAG_COIN_MARKER_V2: (32, 32, SALT_LENGTH),
    TAG_DATA_MARKER_V2: (32, 32, SALT_LENGTH),
    TAG_COIN_TREE_NODE: (1, 32, 32),
    TAG_DATA_TREE_NODE: (1, 32, 32),
    TAG_EMPTY_LEAF: (),
    # The data marker-set tree of spec 05, section 6: a leaf (value,
    # nextValue, nextIndex as 5 bytes) and a node (level, left, right).
    TAG_DATA_MARKER_SET_LEAF: (32, 32, 5),
    TAG_DATA_MARKER_SET_NODE: (1, 32, 32),
}
KECCAK_RATE = 136

NOTE_VERSION_2 = 0x02
SCHEME_ID = 0x01
NOTE_PLAINTEXT_LENGTH = 128
V_MAX = (1 << 96) - 1
ZERO32 = bytes(32)
# The fee reserve of a data commitment in wei (spec 04, section 3, "The fee
# reserve"): 2.5 x 10^17 wei, 0.25 GHOST, in the outer hash of every data leaf.
DATA_RESERVE = 250_000_000_000_000_000


def _tag_prefix(tag):
    raw = tag.encode("ascii")
    if not 1 <= len(raw) <= 255:
        raise ValueError(f"tag length out of range: {tag}")
    return bytes([len(raw)]) + raw


def keccak_tagged(tag, *parts):
    return keccak256(_tag_prefix(tag) + b"".join(parts))


def sha3_tagged(tag, *parts):
    return hashlib.sha3_256(_tag_prefix(tag) + b"".join(parts)).digest()


def parse_key(text):
    """Split typed digits into (format code, payload groups, check groups)."""
    digits = re.sub(r"[ -]", "", text)
    if not (digits.isascii() and digits.isdigit()):
        raise ValueError(f"key has characters other than digits: {text!r}")
    groups = [digits[i : i + 4] for i in range(0, len(digits), 4)]
    if len(digits) != 4 * WORDS_GROUPS:
        raise ValueError(f"key must have {WORDS_GROUPS} groups of four digits, "
                         f"not {len(digits)} digits: {text!r}")
    return FORMAT_WORDS, groups[:WORDS_SECRET_GROUPS], groups[WORDS_SECRET_GROUPS:]


def compute_checks(fmt, payload):
    """The check group 21 over the 80 secret digits (section 6)."""
    if fmt != FORMAT_WORDS:
        raise ValueError(f"unknown key format code {fmt:02x}")
    if len(payload) != WORDS_SECRET_GROUPS:
        raise ValueError(f"a key has {WORDS_SECRET_GROUPS} secret groups, not {len(payload)}")
    h = sha3_tagged(TAG_KEY_CHECK, bytes([fmt, 0x01]), "".join(payload).encode("ascii"))
    return [f"{int.from_bytes(h, 'big') % 10000:04d}"]


def in_range(fmt, payload):
    """The 80 secret digits, read in decimal, are below 2^256."""
    return int("".join(payload)) < SECRET_LIMIT


def key_bytes(fmt, payload):
    """`0x20 || the 32 secret bytes`."""
    if fmt != FORMAT_WORDS:
        raise ValueError(f"unknown key format code {fmt:02x}")
    if not in_range(fmt, payload):
        raise ValueError("the 80 secret digits are 2^256 or more")
    return bytes([fmt]) + int("".join(payload)).to_bytes(32, "big")


def valid_key_bytes(text):
    fmt, payload, checks = parse_key(text)
    if checks != compute_checks(fmt, payload):
        raise ValueError(f"key fails its checksum: {text!r}")
    return key_bytes(fmt, payload)


def derive_secret(kb):
    return sha3_tagged(TAG_SECRET, kb)


def derive_reveal_secret(kb):
    return sha3_tagged(TAG_REVEAL_SECRET, kb)


def derive_blinding(kb, index):
    return sha3_tagged(TAG_BLINDING, kb, index.to_bytes(8, "big"))


def derive_note_key(kb):
    return sha3_tagged(TAG_NOTE_KEY, kb)


def derive_data_key(kb):
    return sha3_tagged(TAG_DATA_KEY, kb)


# The note lookup tag (sections 8 and 9): the first LOOKUP_TAG_BYTES bytes of
# S("ghost/note-tag/v1", k_note, i as 8 bytes), the start of the note's nonce.
LOOKUP_TAG_BYTES = 3
# The bucket rule (spec 05, section 8): m = clamp(floor(log2(n / 4096)), 0, 24).
MIN_BUCKET_NOTES = 4096
MAX_BUCKET_BITS = 8 * LOOKUP_TAG_BYTES


def note_tag_digest(note_key, index):
    return sha3_tagged(TAG_NOTE_TAG, note_key, index.to_bytes(8, "big"))


def bucket_bits(notes):
    """The prefix bits of a bucket of a tree of `notes` leaves."""
    if notes < 0:
        raise ValueError("a leaf count is not negative")
    quotient = notes // MIN_BUCKET_NOTES
    return min(quotient.bit_length() - 1, MAX_BUCKET_BITS) if quotient else 0


def content_fingerprint(content):
    return keccak_tagged(TAG_CONTENT_FINGERPRINT, len(content).to_bytes(8, "big"), content)


def type_tag(type_name, version):
    """The two-byte type tag: format version, then type."""
    if version not in VERSION_TAGS:
        raise ValueError(f"unknown commitment format version {version}")
    return bytes([version, TYPE_CODES[type_name]])


def read_type_tag(tag):
    """(version, type name) of a type tag; an unknown byte is rejected, never guessed."""
    if len(tag) != 2 or tag[0] not in VERSION_TAGS:
        raise ValueError(f"unknown type tag {tag.hex()}")
    for name, code in TYPE_CODES.items():
        if tag[1] == code:
            return tag[0], name
    raise ValueError(f"unknown type tag {tag.hex()}")


def _salt(version, salt):
    """The 16-byte salt of a version 2 commitment; any other version is rejected."""
    if version != VERSION_2:
        raise ValueError(f"unknown commitment format version {version}")
    if salt is None or len(salt) != SALT_LENGTH:
        raise ValueError(f"a version 2 commitment needs a {SALT_LENGTH}-byte salt")
    return salt


def _fingerprint(type_name, s, r, b, cf, rule, salt, version):
    tag = VERSION_TAGS.get(version, {}).get(type_name, (None,))[0]
    salt = _salt(version, salt)
    return keccak_tagged(tag, s, r, b, salt, type_tag(type_name, version), cf, rule)


def coin_fingerprint(s, r, b, rule, salt=None, version=VERSION_2):
    return _fingerprint("COIN", s, r, b, ZERO32, rule, salt, version)


def coin_commitment(fingerprint, amount, version=VERSION_2):
    if not 0 <= amount <= V_MAX:
        raise ValueError("amount out of range")
    return keccak_tagged(TAG_COIN_COMMITMENT, type_tag("COIN", version), fingerprint,
                         amount.to_bytes(32, "big"))


def data_fingerprint(s, r, b, cf, rule, salt=None, version=VERSION_2):
    return _fingerprint("DATA", s, r, b, cf, rule, salt, version)


def data_commitment(fingerprint, version=VERSION_2):
    """`K(data-commitment, DATA, DATA_RESERVE, F_d)`: the node binds the fee
    reserve into the outer hash, as a 32-byte big-endian amount word."""
    return keccak_tagged(TAG_DATA_COMMITMENT, type_tag("DATA", version),
                         DATA_RESERVE.to_bytes(32, "big"), fingerprint)


def marker(type_name, r, b, salt=None, version=VERSION_2):
    salt = _salt(version, salt)
    return keccak_tagged(VERSION_TAGS[version][type_name][1], r, b, salt)


def tree_node(tag, level, left, right):
    return keccak_tagged(tag, bytes([level]), left, right)


# Per note version (section 9): the commitment format version its type tag must
# have and the width of its amount. Version 2 carries the 16-byte salt after the
# rule. Any other note version is rejected.
NOTE_LAYOUTS = {
    NOTE_VERSION_2: {"tag_version": VERSION_2, "amount_bytes": 12},
}


def note_plaintext(type_name, index, amount, cf, length, rule, salt=None,
                   note_version=NOTE_VERSION_2):
    """The 128-byte plaintext of note version 2, with the salt."""
    layout = NOTE_LAYOUTS.get(note_version)
    if layout is None:
        raise ValueError(f"unknown note version {note_version}")
    if not 0 <= amount <= V_MAX:
        raise ValueError("amount out of range")
    out = (
        bytes([note_version, SCHEME_ID])
        + type_tag(type_name, layout["tag_version"])
        + index.to_bytes(8, "big")
        + amount.to_bytes(layout["amount_bytes"], "big")
        + cf
        + length.to_bytes(8, "big")
        + rule
        + _salt(layout["tag_version"], salt)
    )
    return out + bytes(NOTE_PLAINTEXT_LENGTH - len(out))


def note_associated_data(chain_id, leaf):
    return chain_id.to_bytes(8, "big") + leaf


# ---------------------------------------------------------------------------
# Reading the document
# ---------------------------------------------------------------------------


def section(text, heading_pattern):
    """Return the body of the first level-2 section whose heading matches."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if start is None:
            if re.match(r"^## .*" + heading_pattern, line):
                start = i + 1
        elif line.startswith("## "):
            return "\n".join(lines[start:i])
    if start is None:
        raise ValueError(f"no section matching {heading_pattern!r}")
    return "\n".join(lines[start:])


def parse_vectors(body):
    """Parse the [name] blocks inside the section's fenced text blocks."""
    vectors = []
    current = None
    fence = None
    for line in body.splitlines():
        if line.startswith("```"):
            fence = line[3:].strip() if fence is None else None
            current = None
            continue
        if fence != "text" or not line.strip():
            continue
        head = re.fullmatch(r"\[([a-z0-9-]+)\]", line.strip())
        if head:
            current = {"name": head.group(1)}
            vectors.append(current)
            continue
        field = re.fullmatch(r"([a-z0-9-]+) =(?: (.*))?", line.strip())
        if field is None or current is None:
            raise ValueError(f"cannot read vector line: {line!r}")
        if field.group(1) in current:
            raise ValueError(f"field {field.group(1)} repeated in [{current['name']}]")
        current[field.group(1)] = (field.group(2) or "").strip()
    return vectors


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------


class Checker:
    def __init__(self):
        self.errors = []
        self.checked = 0

    def expect(self, vector, field, computed):
        self.checked += 1
        given = vector.get(field)
        if given is None:
            self.errors.append(f"[{vector['name']}] missing field {field} (computed {computed})")
        elif given.lower() != computed.lower():
            self.errors.append(
                f"[{vector['name']}] {field}: document has {given!r}, computed {computed!r}"
            )


def _hex_field(vector, field):
    value = vector[field]
    return bytes.fromhex(value) if value else b""


def _rule(vector):
    rule = _hex_field(vector, "rule")
    if len(rule) != 32:
        raise ValueError("rule must be 32 bytes")
    return rule


def check_keccak(ch, v):
    if "message-ascii" in v:
        message = v["message-ascii"].encode("ascii")
    else:
        message = _hex_field(v, "message-hex")
    ch.expect(v, "digest", keccak256(message).hex())


def check_checksum(ch, v):
    fmt, payload, checks = parse_key(v["key"])
    computed = compute_checks(fmt, payload)
    ch.expect(v, "format", f"{fmt:02x}")
    ch.expect(v, "check", " ".join(computed))
    ok = checks == computed and in_range(fmt, payload)
    ch.expect(v, "valid", "yes" if ok else "no")


def check_derivation(ch, v):
    kb = valid_key_bytes(v["key"])
    ch.expect(v, "key-bytes", kb.hex())
    ch.expect(v, "s", derive_secret(kb).hex())
    ch.expect(v, "r", derive_reveal_secret(kb).hex())
    for i in range(3):
        ch.expect(v, f"b{i}", derive_blinding(kb, i).hex())
    ch.expect(v, "note-key", derive_note_key(kb).hex())
    ch.expect(v, "data-key", derive_data_key(kb).hex())


# Each commitment vector kind is one type at format version 2. The unsalted
# kinds coin-commitment and data-commitment are gone and refused as unknown.
COMMITMENT_KINDS = {
    "salted-coin-commitment": ("coin-commitment", "2"),
    "salted-data-commitment": ("data-commitment", "2"),
}


def _version_and_salt(v):
    """The vector's commitment format version and salt (None when absent)."""
    _, expected = COMMITMENT_KINDS[v["kind"]]
    if v["version"] != expected:
        raise ValueError(f"kind {v['kind']} is version {expected}, not {v['version']}")
    version = int(v["version"])
    salt = _salt(version, _hex_field(v, "salt") if "salt" in v else None)
    return version, salt


def check_coin_commitment(ch, v):
    kb = valid_key_bytes(v["key"])
    index = int(v["index"])
    amount = int(v["amount"])
    version, salt = _version_and_salt(v)
    s, r, b = derive_secret(kb), derive_reveal_secret(kb), derive_blinding(kb, index)
    f = coin_fingerprint(s, r, b, _rule(v), salt, version)
    c = coin_commitment(f, amount, version)
    ch.expect(v, "type-tag", type_tag("COIN", version).hex())
    ch.expect(v, "fingerprint", f.hex())
    ch.expect(v, "commitment", c.hex())
    ch.expect(v, "marker", marker("COIN", r, b, salt, version).hex())


def check_data_commitment(ch, v):
    kb = valid_key_bytes(v["key"])
    index = int(v["index"])
    content = v["content-ascii"].encode("ascii")
    version, salt = _version_and_salt(v)
    s, r, b = derive_secret(kb), derive_reveal_secret(kb), derive_blinding(kb, index)
    cf = content_fingerprint(content)
    f = data_fingerprint(s, r, b, cf, _rule(v), salt, version)
    ch.expect(v, "type-tag", type_tag("DATA", version).hex())
    ch.expect(v, "content-length", str(len(content)))
    ch.expect(v, "content-fingerprint", cf.hex())
    ch.expect(v, "fingerprint", f.hex())
    ch.expect(v, "commitment", data_commitment(f, version).hex())
    ch.expect(v, "marker", marker("DATA", r, b, salt, version).hex())


def check_empty_leaf(ch, v):
    ch.expect(v, "leaf", keccak_tagged(TAG_EMPTY_LEAF).hex())


def check_tree_node(ch, v):
    tags = {"coin": TAG_COIN_TREE_NODE, "data": TAG_DATA_TREE_NODE}
    level = int(v["level"])
    if not 0 <= level <= 31:
        raise ValueError("level out of range")
    node = tree_node(tags[v["tree"]], level, _hex_field(v, "left"), _hex_field(v, "right"))
    ch.expect(v, "node", node.hex())


# Each note vector kind is one note version: a salted-note vector is note
# version 2 with a version 2 type tag. The unsalted kind note is refused.
NOTE_KINDS = {"salted-note": NOTE_VERSION_2}


def _note_version_and_type(v):
    """The vector's note version and type, refusing a note version and type tag
    that disagree; never guessing a layout."""
    note_version = NOTE_KINDS[v["kind"]]
    if int(v["version"]) != note_version:
        raise ValueError(f"kind {v['kind']} is note version {note_version}, not {v['version']}")
    tag_version, type_name = read_type_tag(_hex_field(v, "type-tag"))
    expected = NOTE_LAYOUTS[note_version]["tag_version"]
    if tag_version != expected:
        raise ValueError(f"note version {note_version} needs a version {expected} type tag, "
                         f"not {v['type-tag']}")
    if type_name != v["type"]:
        raise ValueError(f"type tag {v['type-tag']} is {type_name}, not {v['type']}")
    return note_version, type_name


def check_note(ch, v):
    note_version, type_name = _note_version_and_type(v)
    salt = _hex_field(v, "salt") if "salt" in v else None
    plaintext = note_plaintext(
        type_name,
        int(v["index"]),
        int(v["amount"]),
        _hex_field(v, "content-fingerprint"),
        int(v["content-length"]),
        _rule(v),
        salt,
        note_version,
    )
    if len(plaintext) != NOTE_PLAINTEXT_LENGTH:
        raise ValueError("note plaintext has the wrong length")
    ch.expect(v, "plaintext", plaintext.hex())
    ad = note_associated_data(int(v["chain-id"]), _hex_field(v, "leaf"))
    ch.expect(v, "associated-data", ad.hex())


def check_note_tag(ch, v):
    kb = _hex_field(v, "key-bytes")
    if len(kb) != 33 or kb[0] != FORMAT_WORDS:
        raise ValueError("key-bytes must be the format code 20 and 32 secret bytes")
    index = int(v["index"])
    if not 0 <= index < 1 << 64:
        raise ValueError("index out of range")
    digest = note_tag_digest(derive_note_key(kb), index)
    ch.expect(v, "digest", digest.hex())
    ch.expect(v, "tag", digest[:LOOKUP_TAG_BYTES].hex())


def check_bucket_rule(ch, v):
    ch.expect(v, "bits", str(bucket_bits(int(v["notes"]))))


CHECKS = {
    "keccak256": check_keccak,
    "checksum": check_checksum,
    "derivation": check_derivation,
    "note-tag": check_note_tag,
    "bucket-rule": check_bucket_rule,
    "salted-coin-commitment": check_coin_commitment,
    "salted-data-commitment": check_data_commitment,
    "empty-leaf": check_empty_leaf,
    "tree-node": check_tree_node,
    "salted-note": check_note,
}


def check_coverage(vectors):
    """The document must carry every kind of vector, not only some."""
    errors = []
    kinds = [v.get("kind") for v in vectors]
    for kind in CHECKS:
        if kind not in kinds:
            errors.append(f"no vector of kind {kind}")
    checksum = [v for v in vectors if v.get("kind") == "checksum"]
    for valid in ("yes", "no"):
        if not any(v.get("format") == f"{FORMAT_WORDS:02x}" and v.get("valid") == valid
                   for v in checksum):
            errors.append(f"no checksum vector with format {FORMAT_WORDS:02x} and valid = {valid}")
    def written_check(v):
        groups = v.get("key", "").split()
        return groups[-1] if groups else None

    if not any(v.get("valid") == "no" and v.get("check") == written_check(v) for v in checksum):
        errors.append("no checksum vector of an out-of-range secret with a right check group")
    def of(family, version):
        return [v for v in vectors
                if COMMITMENT_KINDS.get(v.get("kind")) == (family, version)
                and v.get("version") == version]

    coin_indexes = {v.get("index") for v in of("coin-commitment", "2")}
    if not {"0", "1"} <= coin_indexes:
        errors.append("version 2 coin commitment vectors must cover index 0 "
                      "and a remainder at index 1")
    if not of("data-commitment", "2"):
        errors.append("no version 2 data commitment vector")
    tag_indexes = {v.get("index") for v in vectors if v.get("kind") == "note-tag"}
    if not {"0", "1"} <= tag_indexes:
        errors.append("note-tag vectors must cover index 0 and index 1")
    rule_bits = {v.get("bits") for v in vectors if v.get("kind") == "bucket-rule"}
    if not {"0", str(MAX_BUCKET_BITS)} <= rule_bits:
        errors.append(f"bucket-rule vectors must cover 0 bits and the clamp at {MAX_BUCKET_BITS}")
    names = [v["name"] for v in vectors]
    for name in sorted({n for n in names if names.count(n) > 1}):
        errors.append(f"vector name [{name}] used more than once")
    return errors


def check_note_leaves(vectors):
    """Every note vector is the note of a commitment vector of the document: its
    leaf is that vector's commitment, and its type tag, number, amount, content
    fingerprint and salt are that commitment's."""
    errors = []
    leaves = {v.get("commitment"): v for v in vectors if v.get("kind") in COMMITMENT_KINDS}
    for note in vectors:
        if note.get("kind") not in NOTE_KINDS:
            continue
        leaf = leaves.get(note.get("leaf"))
        if leaf is None:
            errors.append(f"[{note['name']}] leaf is not the commitment of any commitment vector")
            continue
        coin = COMMITMENT_KINDS[leaf["kind"]][0] == "coin-commitment"
        expected = {
            "type-tag": leaf.get("type-tag"),
            "index": leaf.get("index"),
            "salt": leaf.get("salt"),
            "amount": leaf.get("amount") if coin else "0",
            "content-fingerprint": ZERO32.hex() if coin else leaf.get("content-fingerprint"),
            "content-length": "0" if coin else leaf.get("content-length"),
        }
        for field, want in expected.items():
            if note.get(field) != want:
                errors.append(f"[{note['name']}] {field} is not that of "
                              f"[{leaf['name']}], the commitment it is stored with")
    return errors


def _bits_apart(x, y):
    return bin(int.from_bytes(x, "big") ^ int.from_bytes(y, "big")).count("1")


# Two unrelated 256-bit values differ in about 128 bits; fewer than this many
# would mean the salt barely entered the hash.
MIN_BITS_APART = 64


def check_salt_pairs(vectors):
    """The same secret under two salts must give unrelated values.

    Groups the commitment vectors by everything except the salt (type, key,
    index, amount or content, rule). Each kind must have a group with at least
    two salts, and within a group every salt, fingerprint, commitment and
    marker must differ from every other by at least MIN_BITS_APART bits."""
    errors = []
    groups = {}
    for v in vectors:
        if v.get("kind") not in COMMITMENT_KINDS:
            continue
        family, _ = COMMITMENT_KINDS[v["kind"]]
        key = (family, " ".join(v.get("key", "").split()), v.get("index"),
               v.get("amount"), v.get("content-ascii"), v.get("rule"))
        groups.setdefault(key, []).append(v)
    paired = set()
    for (kind, *_), members in groups.items():
        salted = [v for v in members if v.get("version") == "2"]
        if len(salted) < 2:
            continue
        paired.add(kind)
        salts = [v.get("salt") for v in salted]
        if len(set(salts)) != len(salts):
            names = ", ".join(f"[{v['name']}]" for v in salted)
            errors.append(f"{names}: the same salt is used twice; a wallet draws a fresh one")
            continue
        for field in ("fingerprint", "commitment", "marker"):
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    try:
                        x, y = bytes.fromhex(a[field]), bytes.fromhex(b[field])
                    except (KeyError, ValueError):
                        errors.append(f"[{a['name']}] and [{b['name']}]: {field} is "
                                      f"missing or not hex")
                        continue
                    if _bits_apart(x, y) < MIN_BITS_APART:
                        errors.append(f"[{a['name']}] and [{b['name']}]: {field} values are "
                                      f"not unrelated under different salts")
    for kind in ("coin-commitment", "data-commitment"):
        if kind not in paired:
            errors.append(f"no {kind} vectors of one secret under two salts")
    return errors


def _table_rows(body):
    """The tag table rows as dictionaries keyed by its header."""
    rows = [[c.strip() for c in line.strip().strip("|").split("|")]
            for line in body.splitlines() if line.startswith("|")]
    if len(rows) < 3:
        return []
    return [dict(zip(rows[0], cells)) for cells in rows[2:]]


def check_tag_table(text):
    """The tagged hashing section must list exactly the tags in use, and its
    size columns must match the fixed input layouts."""
    body = section(text, "Tagged hashing")
    listed = set(re.findall(r"`(ghost/[a-z0-9-]+/v[0-9]+)`", body))
    errors = []
    for tag in sorted(ALL_TAGS - listed):
        errors.append(f"tag {tag} is used but not listed in the tag table")
    for tag in sorted(listed - ALL_TAGS):
        errors.append(f"tag {tag} is listed but not known to this checker")
    rows = {}
    for row in _table_rows(body):
        found = re.fullmatch(r"`(ghost/[a-z0-9-]+/v[0-9]+)`", row.get("Tag", ""))
        if found:
            rows[found.group(1)] = row
    for tag, widths in sorted(TAG_LAYOUTS.items()):
        row = rows.get(tag)
        if row is None:
            continue
        total = len(_tag_prefix(tag)) + sum(widths)
        if row.get("Input bytes") != str(total):
            errors.append(f"tag {tag}: table says {row.get('Input bytes')!r} input bytes, "
                          f"recomputed {total}")
        perms = row.get("Keccak permutations", "")
        expect = total // KECCAK_RATE + 1
        if tag in (TAG_COIN_TREE_NODE, TAG_DATA_TREE_NODE, TAG_DATA_MARKER_SET_NODE):
            expect_text = f"{expect} per level"
        elif tag == TAG_EMPTY_LEAF:
            expect_text = "a constant"
        else:
            expect_text = str(expect)
        if perms != expect_text:
            errors.append(f"tag {tag}: table says {perms!r} Keccak permutations, "
                          f"recomputed {expect_text!r}")
    return errors


def run(path):
    errors = keccak_self_test()
    text = Path(path).read_text(encoding="utf-8")
    errors += check_tag_table(text)
    vectors = parse_vectors(section(text, "Test vectors"))
    errors += check_coverage(vectors)
    errors += check_salt_pairs(vectors)
    errors += check_note_leaves(vectors)
    ch = Checker()
    for v in vectors:
        kind = v.get("kind")
        if kind not in CHECKS:
            errors.append(f"[{v['name']}] unknown kind {kind!r}")
            continue
        try:
            CHECKS[kind](ch, v)
        except (KeyError, ValueError) as exc:
            errors.append(f"[{v['name']}] cannot be checked: {exc}")
    errors += ch.errors
    return errors, len(vectors), ch.checked


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_SPEC
    try:
        errors, count, checked = run(path)
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    if errors:
        print(f"{len(errors)} failure(s) in {path}", file=sys.stderr)
        return 1
    print(f"ok: {count} vectors, {checked} values recomputed, Keccak-256 self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
