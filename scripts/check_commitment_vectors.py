#!/usr/bin/env python3
"""Recompute the test vectors of the commitments and keys specification.

Reads every vector block in the "Test vectors" section of
docs/spec/01-commitments-and-keys.md, recomputes the Phantom Key checksum and
every derivation from the rules in that document, and exits nonzero on any
mismatch. It also checks that the tag table lists exactly the tags used here.

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
TAG_COIN_FINGERPRINT = "ghost/coin-fingerprint/v1"
TAG_COIN_COMMITMENT = "ghost/coin-commitment/v1"
TAG_DATA_FINGERPRINT = "ghost/data-fingerprint/v1"
TAG_DATA_COMMITMENT = "ghost/data-commitment/v1"
TAG_CONTENT_FINGERPRINT = "ghost/content-fingerprint/v1"
TAG_COIN_MARKER = "ghost/coin-marker/v1"
TAG_DATA_MARKER = "ghost/data-marker/v1"
TAG_COIN_TREE_NODE = "ghost/coin-tree-node/v1"
TAG_DATA_TREE_NODE = "ghost/data-tree-node/v1"
TAG_EMPTY_LEAF = "ghost/empty-leaf/v1"
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
    TAG_COIN_FINGERPRINT,
    TAG_COIN_COMMITMENT,
    TAG_DATA_FINGERPRINT,
    TAG_DATA_COMMITMENT,
    TAG_CONTENT_FINGERPRINT,
    TAG_COIN_MARKER,
    TAG_DATA_MARKER,
    TAG_COIN_TREE_NODE,
    TAG_DATA_TREE_NODE,
    TAG_EMPTY_LEAF,
    TAG_COIN_REVEAL_BINDING,
    TAG_DATA_REVEAL_BINDING,
    TAG_HOLD_BINDING,
}

FORMAT_12 = 0x0C
FORMAT_24 = 0x18

TYPE_TAGS = {"COIN": bytes([0x01, 0x01]), "DATA": bytes([0x01, 0x02])}
NOTE_VERSION = 0x01
SCHEME_ID = 0x01
NOTE_PLAINTEXT_LENGTH = 128
V_MAX = (1 << 96) - 1
ZERO32 = bytes(32)


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
    if len(digits) == 48:
        return FORMAT_12, groups[:11], [groups[11]]
    if len(digits) == 96:
        return FORMAT_24, groups[:11] + groups[12:23], [groups[11], groups[23]]
    raise ValueError(f"key must have 12 or 24 groups of four digits: {text!r}")


def _check_group(fmt, part, payload_groups):
    h = sha3_tagged(TAG_KEY_CHECK, bytes([fmt, part]), "".join(payload_groups).encode("ascii"))
    return f"{int.from_bytes(h, 'big') % 10000:04d}"


def compute_checks(fmt, payload):
    if fmt == FORMAT_12:
        return [_check_group(fmt, 1, payload[:11])]
    return [_check_group(fmt, 1, payload[:11]), _check_group(fmt, 2, payload)]


def key_bytes(fmt, payload):
    return bytes([fmt]) + "".join(payload).encode("ascii")


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


def content_fingerprint(content):
    return keccak_tagged(TAG_CONTENT_FINGERPRINT, len(content).to_bytes(8, "big"), content)


def coin_fingerprint(s, r, b, rule):
    return keccak_tagged(TAG_COIN_FINGERPRINT, s, r, b, TYPE_TAGS["COIN"], ZERO32, rule)


def coin_commitment(fingerprint, amount):
    if not 0 <= amount <= V_MAX:
        raise ValueError("amount out of range")
    return keccak_tagged(TAG_COIN_COMMITMENT, TYPE_TAGS["COIN"], fingerprint, amount.to_bytes(32, "big"))


def data_fingerprint(s, r, b, cf, rule):
    return keccak_tagged(TAG_DATA_FINGERPRINT, s, r, b, TYPE_TAGS["DATA"], cf, rule)


def data_commitment(fingerprint):
    return keccak_tagged(TAG_DATA_COMMITMENT, TYPE_TAGS["DATA"], fingerprint)


def marker(tag, r, b):
    return keccak_tagged(tag, r, b)


def tree_node(tag, level, left, right):
    return keccak_tagged(tag, bytes([level]), left, right)


def note_plaintext(type_name, index, amount, cf, length, rule):
    out = (
        bytes([NOTE_VERSION, SCHEME_ID])
        + TYPE_TAGS[type_name]
        + index.to_bytes(8, "big")
        + amount.to_bytes(32, "big")
        + cf
        + length.to_bytes(8, "big")
        + rule
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
    ch.expect(v, "valid", "yes" if checks == computed else "no")


def check_derivation(ch, v):
    kb = valid_key_bytes(v["key"])
    ch.expect(v, "key-bytes", kb.hex())
    ch.expect(v, "s", derive_secret(kb).hex())
    ch.expect(v, "r", derive_reveal_secret(kb).hex())
    for i in range(3):
        ch.expect(v, f"b{i}", derive_blinding(kb, i).hex())
    ch.expect(v, "note-key", derive_note_key(kb).hex())
    ch.expect(v, "data-key", derive_data_key(kb).hex())


def check_coin_commitment(ch, v):
    kb = valid_key_bytes(v["key"])
    index = int(v["index"])
    amount = int(v["amount"])
    s, r, b = derive_secret(kb), derive_reveal_secret(kb), derive_blinding(kb, index)
    f = coin_fingerprint(s, r, b, _rule(v))
    c = coin_commitment(f, amount)
    ch.expect(v, "fingerprint", f.hex())
    ch.expect(v, "commitment", c.hex())
    ch.expect(v, "marker", marker(TAG_COIN_MARKER, r, b).hex())


def check_data_commitment(ch, v):
    kb = valid_key_bytes(v["key"])
    index = int(v["index"])
    content = v["content-ascii"].encode("ascii")
    s, r, b = derive_secret(kb), derive_reveal_secret(kb), derive_blinding(kb, index)
    cf = content_fingerprint(content)
    f = data_fingerprint(s, r, b, cf, _rule(v))
    ch.expect(v, "content-length", str(len(content)))
    ch.expect(v, "content-fingerprint", cf.hex())
    ch.expect(v, "fingerprint", f.hex())
    ch.expect(v, "commitment", data_commitment(f).hex())
    ch.expect(v, "marker", marker(TAG_DATA_MARKER, r, b).hex())


def check_empty_leaf(ch, v):
    ch.expect(v, "leaf", keccak_tagged(TAG_EMPTY_LEAF).hex())


def check_tree_node(ch, v):
    tags = {"coin": TAG_COIN_TREE_NODE, "data": TAG_DATA_TREE_NODE}
    level = int(v["level"])
    if not 0 <= level <= 31:
        raise ValueError("level out of range")
    node = tree_node(tags[v["tree"]], level, _hex_field(v, "left"), _hex_field(v, "right"))
    ch.expect(v, "node", node.hex())


def check_note(ch, v):
    plaintext = note_plaintext(
        v["type"],
        int(v["index"]),
        int(v["amount"]),
        _hex_field(v, "content-fingerprint"),
        int(v["content-length"]),
        _rule(v),
    )
    if len(plaintext) != NOTE_PLAINTEXT_LENGTH:
        raise ValueError("note plaintext has the wrong length")
    ch.expect(v, "plaintext", plaintext.hex())
    ad = note_associated_data(int(v["chain-id"]), _hex_field(v, "leaf"))
    ch.expect(v, "associated-data", ad.hex())


CHECKS = {
    "keccak256": check_keccak,
    "checksum": check_checksum,
    "derivation": check_derivation,
    "coin-commitment": check_coin_commitment,
    "data-commitment": check_data_commitment,
    "empty-leaf": check_empty_leaf,
    "tree-node": check_tree_node,
    "note": check_note,
}


def check_coverage(vectors):
    """The document must carry every kind of vector, not only some."""
    errors = []
    kinds = [v.get("kind") for v in vectors]
    for kind in CHECKS:
        if kind not in kinds:
            errors.append(f"no vector of kind {kind}")
    checksum = [v for v in vectors if v.get("kind") == "checksum"]
    for fmt, valid in (("0c", "yes"), ("18", "yes"), ("0c", "no"), ("18", "no")):
        if not any(v.get("format") == fmt and v.get("valid") == valid for v in checksum):
            errors.append(f"no checksum vector with format {fmt} and valid = {valid}")
    derivations = [v for v in vectors if v.get("kind") == "derivation"]
    for groups in (12, 24):
        if not any(len(re.sub(r"[ -]", "", v.get("key", ""))) == 4 * groups for v in derivations):
            errors.append(f"no derivation vector for a {groups}-group key")
    coin_indexes = {v.get("index") for v in vectors if v.get("kind") == "coin-commitment"}
    if not {"0", "1"} <= coin_indexes:
        errors.append("coin commitment vectors must cover index 0 and a remainder at index 1")
    names = [v["name"] for v in vectors]
    for name in sorted({n for n in names if names.count(n) > 1}):
        errors.append(f"vector name [{name}] used more than once")
    return errors


def check_tag_table(text):
    """The tagged hashing section must list exactly the tags in use."""
    body = section(text, "Tagged hashing")
    listed = set(re.findall(r"`(ghost/[a-z0-9-]+/v[0-9]+)`", body))
    errors = []
    for tag in sorted(ALL_TAGS - listed):
        errors.append(f"tag {tag} is used but not listed in the tag table")
    for tag in sorted(listed - ALL_TAGS):
        errors.append(f"tag {tag} is listed but not known to this checker")
    return errors


def run(path):
    errors = keccak_self_test()
    text = Path(path).read_text(encoding="utf-8")
    errors += check_tag_table(text)
    vectors = parse_vectors(section(text, "Test vectors"))
    errors += check_coverage(vectors)
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
