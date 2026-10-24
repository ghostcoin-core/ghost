#!/usr/bin/env python3
"""Derives Ghost's genesis block from Bitcoin headers, as spec 06 section 8 says.

A second, independent implementation of the genesis rule, written from the text
of docs/spec/06-consensus-and-emission.md (section 8, with the starting
difficulty of section 4.5) and docs/spec/05-trees-and-headers.md (section 10,
"Genesis fields" and the header encoding). It shares no code with the node, so
an operator who runs both and gets the same bytes has two derivations that
agree (section 8.6).

    python3 scripts/derive_genesis.py -tl <T_L unix seconds> -headers <file>

The file is the raw concatenation of 80-byte Bitcoin headers in order, possibly
with competing branches. Every header but the first must link to an earlier
header in the file. On success it prints five lines on stdout; on any refusal
it prints the reason on stderr, nothing on stdout, and exits with code 1.

Standard library only. Keccak-256 is implemented here because hashlib's
sha3_256 is the NIST variant, whose padding differs.
"""

import argparse
import hashlib
import sys

# Spec 06, section 8.2.
CONFIRMATIONS = 6
GENESIS_OFFSET = 6000
# Spec 06, section 4.5: the starting difficulty, 2^24.
START_DIFFICULTY = 16_777_216
# Median time past spans a block and its 10 predecessors (section 8.3).
MTP_SPAN = 11
# Bitcoin mainnet's proof-of-work limit, as compact bits.
DEFAULT_POWLIMIT_BITS = 0x1D00FFFF

HEADER_SIZE = 80

# Spec 05, section 10, "Genesis fields": constants of the frozen configuration.
EMPTY_TRIE_ROOT = bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
EMPTY_COIN_TREE_ROOT = bytes.fromhex("8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8")
EMPTY_DATA_TREE_ROOT = bytes.fromhex("3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03")
GENESIS_GAS_LIMIT = 30_000_000
GENESIS_BASE_FEE = 1_000_000_000


class Refusal(Exception):
    """A reason not to print a genesis."""


# --- Keccak-256 (the original Keccak padding, as Ethereum uses it) ----------

_MASK64 = (1 << 64) - 1


def _round_constants():
    def rc_bit(t):
        if t % 255 == 0:
            return 1
        r = [1, 0, 0, 0, 0, 0, 0, 0]
        for _ in range(t % 255):
            r = [0] + r
            r[0] ^= r[8]
            r[4] ^= r[8]
            r[5] ^= r[8]
            r[6] ^= r[8]
            r = r[:8]
        return r[0]

    constants = []
    for ir in range(24):
        value = 0
        for j in range(7):
            if rc_bit(j + 7 * ir):
                value |= 1 << ((1 << j) - 1)
        constants.append(value)
    return constants


def _rotation_offsets():
    offsets = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        offsets[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


_RC = _round_constants()
_ROT = _rotation_offsets()


def _rotl(value, shift):
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(lanes):
    for rc in _RC:
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(lanes[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                lanes[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y] & _MASK64)
        lanes[0][0] ^= rc


def keccak256(data):
    """Keccak-256 of data: rate 1088 bits, padding 0x01 ... 0x80."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    lanes = [[0] * 5 for _ in range(5)]
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            lanes[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(lanes)
    out = b"".join(lanes[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


# --- RLP ---------------------------------------------------------------------

def _rlp_length(length, offset):
    if length < 56:
        return bytes([offset + length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(encoded)]) + encoded


def rlp_bytes(value):
    if len(value) == 1 and value[0] < 0x80:
        return bytes(value)
    return _rlp_length(len(value), 0x80) + bytes(value)


def rlp_int(value):
    if value < 0:
        raise ValueError("RLP integers are non-negative")
    return rlp_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def rlp_list(encoded_items):
    payload = b"".join(encoded_items)
    return _rlp_length(len(payload), 0xC0) + payload


# --- Bitcoin headers ---------------------------------------------------------

def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def bits_to_target(bits):
    """The target a compact `bits` value encodes, refusing the encodings
    Bitcoin Core treats as invalid (negative, overflowing or zero)."""
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000 and mantissa:
        raise Refusal("bits %08x encode a negative target" % bits)
    if mantissa and (exponent > 34 or (mantissa > 0xFF and exponent > 33)
                     or (mantissa > 0xFFFF and exponent > 32)):
        raise Refusal("bits %08x encode a target that overflows 256 bits" % bits)
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if target == 0:
        raise Refusal("bits %08x encode a zero target" % bits)
    return target


class Header:
    def __init__(self, raw):
        self.raw = raw
        self.prev = raw[4:36]
        self.time = int.from_bytes(raw[68:72], "little")
        self.bits = int.from_bytes(raw[72:76], "little")
        self.digest = sha256d(raw)
        # Bitcoin Core prints the digest byte-reversed.
        self.hash_hex = self.digest[::-1].hex()


def parse_headers(data):
    if not data:
        raise Refusal("header file is empty")
    if len(data) % HEADER_SIZE:
        raise Refusal("header file length %d is not a multiple of %d" % (len(data), HEADER_SIZE))
    return [Header(data[i:i + HEADER_SIZE]) for i in range(0, len(data), HEADER_SIZE)]


def link_headers(headers):
    """Index of each header's parent, None for the first header."""
    index_of = {}
    parents = []
    for i, header in enumerate(headers):
        if header.digest in index_of:
            raise Refusal("header %d (%s) appears twice" % (i, header.hash_hex))
        if i == 0:
            parents.append(None)
        else:
            parent = index_of.get(header.prev)
            if parent is None:
                raise Refusal("header %d (%s) does not link to an earlier header in the file"
                              % (i, header.hash_hex))
            parents.append(parent)
        index_of[header.digest] = i
    return parents


def check_work(headers, powlimit):
    """Proof of work of each header against its own bits, and the bits against
    the limit. Returns each header's work."""
    works = []
    for i, header in enumerate(headers):
        target = bits_to_target(header.bits)
        if target > powlimit:
            raise Refusal("header %d (%s) has bits %08x, easier than the proof-of-work limit"
                          % (i, header.hash_hex, header.bits))
        if int.from_bytes(header.digest, "little") > target:
            raise Refusal("header %d (%s) does not meet the target of its bits %08x"
                          % (i, header.hash_hex, header.bits))
        works.append(2 ** 256 // (target + 1))
    return works


def best_chain(headers, parents, works):
    """Indices from the first header to the tip with the most accumulated
    work. A tie for the most work is refused."""
    total = []
    has_child = [False] * len(headers)
    for i, parent in enumerate(parents):
        total.append(works[i] + (total[parent] if parent is not None else 0))
        if parent is not None:
            has_child[parent] = True
    tips = [i for i in range(len(headers)) if not has_child[i]]
    most = max(total[i] for i in tips)
    best = [i for i in tips if total[i] == most]
    if len(best) > 1:
        raise Refusal("branches tie for the most work: tips %s"
                      % ", ".join(headers[i].hash_hex for i in best))
    chain = []
    i = best[0]
    while i is not None:
        chain.append(i)
        i = parents[i]
    chain.reverse()
    return chain


def median_time_past(times):
    ordered = sorted(times)
    return ordered[len(ordered) // 2]


def select(headers, chain, t_l):
    """Position in the chain of B, the lowest block with MTP(B) >= T_L, and its MTP."""
    times = [headers[i].time for i in chain]
    for pos in range(MTP_SPAN - 1, len(chain)):
        mtp = median_time_past(times[pos - MTP_SPAN + 1:pos + 1])
        if mtp >= t_l:
            if pos < MTP_SPAN:
                raise Refusal("block %s is the first with median time past >= %d, but the "
                              "file has %d headers before it, want at least %d to show no "
                              "lower block qualifies"
                              % (headers[chain[pos]].hash_hex, t_l, pos, MTP_SPAN))
            return pos, mtp
    raise Refusal("no block on the best chain has median time past >= %d" % t_l)


# --- Genesis -----------------------------------------------------------------

def genesis_header(mtp, bitcoin_hash_hex):
    """The 18 header fields of spec 05 section 10, in order, RLP-encoded."""
    fields = [
        rlp_bytes(bytes(32)),                           # parentHash
        rlp_bytes(keccak256(rlp_list([]))),             # uncleHash
        rlp_bytes(bytes(20)),                           # coinbase
        rlp_bytes(EMPTY_TRIE_ROOT),                     # stateRoot
        rlp_bytes(EMPTY_TRIE_ROOT),                     # transactionsRoot
        rlp_bytes(EMPTY_TRIE_ROOT),                     # receiptsRoot
        rlp_bytes(bytes(256)),                          # logsBloom
        rlp_int(START_DIFFICULTY),                      # difficulty
        rlp_int(0),                                     # number
        rlp_int(GENESIS_GAS_LIMIT),                     # gasLimit
        rlp_int(0),                                     # gasUsed
        rlp_int(mtp + GENESIS_OFFSET),                  # timestamp
        rlp_bytes(bytes.fromhex(bitcoin_hash_hex)),     # extraData
        rlp_bytes(bytes(32)),                           # mixDigest
        rlp_bytes(bytes(8)),                            # nonce
        rlp_int(GENESIS_BASE_FEE),                      # baseFee
        rlp_bytes(EMPTY_COIN_TREE_ROOT),                # coinTreeRoot
        rlp_bytes(EMPTY_DATA_TREE_ROOT),                # dataTreeRoot
    ]
    return rlp_list(fields)


def derive(data, t_l, powlimit_bits=DEFAULT_POWLIMIT_BITS):
    """The five output lines for a raw header file, or a Refusal."""
    powlimit = bits_to_target(powlimit_bits)
    headers = parse_headers(data)
    parents = link_headers(headers)
    works = check_work(headers, powlimit)
    chain = best_chain(headers, parents, works)
    pos, mtp = select(headers, chain, t_l)
    selected = headers[chain[pos]]
    confirmations = len(chain) - pos
    if confirmations < CONFIRMATIONS:
        raise Refusal("selected block has too few confirmations: block %s has %d, want %d"
                      % (selected.hash_hex, confirmations, CONFIRMATIONS))
    header = genesis_header(mtp, selected.hash_hex)
    block = rlp_list([header, rlp_list([]), rlp_list([])])
    return [
        "bitcoin-block %s" % selected.hash_hex,
        "confirmations %d" % confirmations,
        "median-time-past %d" % mtp,
        "genesis-hash %s" % keccak256(header).hex(),
        "genesis-block %s" % block.hex(),
    ]


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print("derive_genesis: %s" % message, file=sys.stderr)
        sys.exit(1)


def main(argv=None):
    parser = _Parser(description="Derive Ghost's genesis block from raw Bitcoin headers.")
    parser.add_argument("-tl", required=True, type=int, help="T_L, the launch time in Unix seconds")
    parser.add_argument("-headers", required=True, help="file of raw 80-byte Bitcoin headers")
    parser.add_argument("-powlimit-bits", default="%08x" % DEFAULT_POWLIMIT_BITS,
                        help="proof-of-work limit as compact bits in hex (default %(default)s)")
    args = parser.parse_args(argv)
    try:
        powlimit_bits = int(args.powlimit_bits, 16)
    except ValueError:
        parser.error("-powlimit-bits %r is not hexadecimal" % args.powlimit_bits)
    if not 0 <= powlimit_bits <= 0xFFFFFFFF:
        parser.error("-powlimit-bits must fit in 32 bits")
    try:
        with open(args.headers, "rb") as handle:
            data = handle.read()
    except OSError as err:
        print("derive_genesis: cannot read %s: %s" % (args.headers, err), file=sys.stderr)
        return 1
    try:
        lines = derive(data, args.tl, powlimit_bits)
    except Refusal as err:
        print("derive_genesis: %s" % err, file=sys.stderr)
        return 1
    sys.stdout.write("".join(line + "\n" for line in lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
