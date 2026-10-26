#!/usr/bin/env python3
"""Separately written encoder for the golden header vectors of
docs/spec/05-trees-and-headers.md, section 11.

Python standard library only, plus the Keccak-256 function of
check_commitment_vectors.py. It has its own RLP code and imports nothing from
the chapter's checker, so that the chapter's vectors come from a second
implementation and not from the code that reads them.

Usage:
    python3 scripts/header_golden_encoder.py

prints every golden header vector as the `[name]` blocks of the chapter.
"""

import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("_keccak_source", _HERE / "check_commitment_vectors.py")
_keccak_source = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_keccak_source)
keccak256 = _keccak_source.keccak256

# The Ghost header, in RLP order: the pinned base header's fields with the base
# fee required, then the two tree roots and the data marker-set root, 19 fields
# in all. Each entry is (name, kind, size): a
# "fixed" field is exactly `size` bytes, a "bytes" field at most `size` bytes,
# an "int" field a canonical integer below 2^size.
HEADER_LAYOUT = (
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


# ---------------------------------------------------------------------------
# RLP, written for this encoder
# ---------------------------------------------------------------------------

def _length_prefix(length, short_base):
    """The RLP prefix for a payload of `length` bytes; short_base is 0x80 for
    a string and 0xc0 for a list."""
    if length < 56:
        return bytes([short_base + length])
    size = (length.bit_length() + 7) // 8
    return bytes([short_base + 55 + size]) + length.to_bytes(size, "big")


def rlp_string(data):
    data = bytes(data)
    if len(data) == 1 and data[0] < 0x80:
        return data
    return _length_prefix(len(data), 0x80) + data


def rlp_uint(value):
    if value < 0:
        raise ValueError("RLP integers are unsigned")
    if value == 0:
        return rlp_string(b"")
    return rlp_string(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def rlp_list_of_encoded(items):
    """A list whose items are already RLP-encoded byte strings."""
    payload = b"".join(items)
    return _length_prefix(len(payload), 0xC0) + payload


def encode_field(kind, value):
    if kind == "int":
        return rlp_uint(value)
    return rlp_string(value)


def header_items(fields):
    """The encoded items of a header, in layout order."""
    items = []
    for name, kind, size in HEADER_LAYOUT:
        value = fields[name]
        if kind == "fixed" and len(value) != size:
            raise ValueError(f"{name} must be {size} bytes")
        if kind == "bytes" and len(value) > size:
            raise ValueError(f"{name} must be at most {size} bytes")
        if kind == "int" and not 0 <= value < 2**size:
            raise ValueError(f"{name} out of range")
        items.append(encode_field(kind, value))
    return items


def encode_header(fields):
    return rlp_list_of_encoded(header_items(fields))


def header_hash(encoded):
    return keccak256(encoded)


# ---------------------------------------------------------------------------
# The examples
# ---------------------------------------------------------------------------

EMPTY_TRIE_ROOT = keccak256(rlp_string(b""))
EMPTY_LIST_HASH = keccak256(rlp_list_of_encoded([]))

# Root of an empty coin tree and of an empty data tree, and the roots after the
# leaves of spec 01's commitment vectors (section 3 of the chapter; the checker
# recomputes them from the tree rules, this encoder takes them as given).
EMPTY_COIN_TREE_ROOT = bytes.fromhex("8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8")
EMPTY_DATA_TREE_ROOT = bytes.fromhex("3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03")
COIN_ROOT_TWO_LEAVES = bytes.fromhex("142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5")
DATA_ROOT_ONE_LEAF = bytes.fromhex("dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a")
# Root of the data marker-set tree at genesis (vector marker-set-empty) and after
# spec 01's two data markers (vector marker-set-two-markers), taken as given.
EMPTY_MARKER_SET_ROOT = bytes.fromhex("0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3")
MARKER_SET_ROOT_TWO_MARKERS = bytes.fromhex("f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f")

# Stand-in for Bitcoin block B: the hash of Bitcoin's own first block, as
# Bitcoin Core prints it. An example only, never Ghost's anchor.
EXAMPLE_ANCHOR_HASH = bytes.fromhex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
EXAMPLE_MTP = 1798761600
GENESIS_OFFSET = 6000
D_START = 2**24
GENESIS_GAS_LIMIT = 30_000_000
GENESIS_BASE_FEE = 1_000_000_000


def genesis_example():
    return {
        "parentHash": bytes(32),
        "uncleHash": EMPTY_LIST_HASH,
        "coinbase": bytes(20),
        "stateRoot": EMPTY_TRIE_ROOT,
        "transactionsRoot": EMPTY_TRIE_ROOT,
        "receiptsRoot": EMPTY_TRIE_ROOT,
        "logsBloom": bytes(256),
        "difficulty": D_START,
        "number": 0,
        "gasLimit": GENESIS_GAS_LIMIT,
        "gasUsed": 0,
        "timestamp": EXAMPLE_MTP + GENESIS_OFFSET,
        "extraData": EXAMPLE_ANCHOR_HASH,
        "mixDigest": bytes(32),
        "nonce": bytes(8),
        "baseFee": GENESIS_BASE_FEE,
        "coinTreeRoot": EMPTY_COIN_TREE_ROOT,
        "dataTreeRoot": EMPTY_DATA_TREE_ROOT,
        "dataMarkerRoot": EMPTY_MARKER_SET_ROOT,
    }


def block_one_example(parent_hash):
    return {
        "parentHash": parent_hash,
        "uncleHash": EMPTY_LIST_HASH,
        "coinbase": bytes.fromhex("00000000000000000000000000000000000004d2"),
        "stateRoot": bytes([0x11]) * 32,
        "transactionsRoot": bytes([0x22]) * 32,
        "receiptsRoot": bytes([0x33]) * 32,
        "logsBloom": bytes(256),
        "difficulty": D_START,
        "number": 1,
        "gasLimit": GENESIS_GAS_LIMIT,
        "gasUsed": 126_000,
        "timestamp": EXAMPLE_MTP + GENESIS_OFFSET + 30,
        "extraData": b"",
        "mixDigest": bytes([0x44]) * 32,
        "nonce": bytes.fromhex("0102030405060708"),
        "baseFee": 875_000_000,
        "coinTreeRoot": COIN_ROOT_TWO_LEAVES,
        "dataTreeRoot": DATA_ROOT_ONE_LEAF,
        "dataMarkerRoot": MARKER_SET_ROOT_TWO_MARKERS,
    }


# Each negative vector: name, fault, the reason a decoder must give.
NEGATIVE_VECTORS = (
    ("header-forbidden-field", "forbidden-field", "item-count"),
    ("header-extra-trailing-field", "extra-trailing-field", "item-count"),
    ("header-missing-required-field", "missing-required-field", "item-count"),
    ("header-non-canonical-integer", "non-canonical-integer", "non-canonical-integer"),
    ("header-short-tree-root", "short-tree-root", "field-size"),
    ("header-trailing-bytes", "trailing-bytes", "trailing-bytes"),
    ("header-eighteen-items", "eighteen-items", "item-count"),
)


def damaged(fields, fault):
    """The bytes of `fields` with one fault, built item by item."""
    items = header_items(fields)
    index = {name: i for i, (name, _, _) in enumerate(HEADER_LAYOUT)}
    if fault == "forbidden-field":
        # The withdrawals root where the base client would put it, after the
        # base fee and before the tree roots.
        items.insert(index["baseFee"] + 1, rlp_string(EMPTY_TRIE_ROOT))
    elif fault == "extra-trailing-field":
        items.append(rlp_string(b""))
    elif fault == "missing-required-field":
        del items[index["baseFee"]]
    elif fault == "non-canonical-integer":
        # The block number with a leading zero byte.
        value = fields["number"]
        body = b"\x00" + value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        items[index["number"]] = bytes([0x80 + len(body)]) + body
    elif fault == "short-tree-root":
        items[index["coinTreeRoot"]] = rlp_string(fields["coinTreeRoot"][:31])
    elif fault == "trailing-bytes":
        return rlp_list_of_encoded(items) + b"\x00"
    elif fault == "eighteen-items":
        # The 18-field header from before the data marker-set root.
        del items[index["dataMarkerRoot"]]
    else:
        raise ValueError(f"unknown fault {fault}")
    return rlp_list_of_encoded(items)


def _format_value(kind, value):
    return str(value) if kind == "int" else bytes(value).hex()


def golden_vectors():
    """Every golden header vector, in the order of the chapter, as
    (name, ordered list of (key, value) strings)."""
    out = []
    genesis = genesis_example()
    genesis_rlp = encode_header(genesis)
    genesis_hash = header_hash(genesis_rlp)
    one = block_one_example(genesis_hash)
    one_rlp = encode_header(one)
    for name, fields, encoded in (("header-genesis-example", genesis, genesis_rlp),
                                  ("header-block-one-example", one, one_rlp)):
        lines = [("kind", "header")]
        lines += [(n, _format_value(k, fields[n])) for n, k, _ in HEADER_LAYOUT]
        lines += [("rlp", encoded.hex()), ("hash", header_hash(encoded).hex()), ("valid", "yes")]
        out.append((name, lines))
    for name, fault, reason in NEGATIVE_VECTORS:
        lines = [("kind", "header-negative"), ("base", "header-block-one-example"),
                 ("fault", fault), ("reject", reason),
                 ("rlp", damaged(one, fault).hex()), ("valid", "no")]
        out.append((name, lines))
    return out


def render():
    blocks = []
    for name, lines in golden_vectors():
        blocks.append("\n".join([f"[{name}]"] + [f"{k} = {v}" if v != "" else f"{k} ="
                                                 for k, v in lines]))
    return "\n\n".join(blocks) + "\n"


def main():
    sys.stdout.write(render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
