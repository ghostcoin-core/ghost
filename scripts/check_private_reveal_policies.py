#!/usr/bin/env python3
"""Checks the figures of docs/spec/10-private-reveal-policies.md.

Python standard library only. It recomputes, from the field lists, tags and
pinned inputs below, and compares with what the document states:

  1. the section structure: sections numbered 1 to 19 without gaps, each
     required section and subsection present;
  2. the note: the capsule layout (224 bytes), the plaintext (352) and
     `NOTE_BYTES` (380), in section 1, section 3.2 and section 19;
  3. the rule hash input (section 3.1): its tag, its six fields, its length
     and its Keccak blocks;
  4. every payload: the ordinary formula of section 4.1, the policy table of
     section 5.1 and the action table of section 8.1, field by field in
     order, contiguous, at their widths, and the payload and envelope sizes;
  5. every binding: the tables of sections 4.2, 5.1 and 8.2 and the field
     list of section 9.2, their tags, lengths with and without the tag,
     Keccak permutations and public-value lengths, and the statement codes
     against the table of section 9;
  6. every trace: the permutation table of section 4.4 and the hash lists of
     sections 5.4, 8.2 and 9.2, the rows, the carried columns and the widths,
     and `MAX_TRACE_WIDTH`;
  7. the proof-length bounds of section 4.4 with `proof_length_bound` of
     `proofs/src/stark.rs`, ported here, and `ACTION_PROOF_BYTES`;
  8. the verification charge of section 10.2: the recorded slowest
     verification, its scaling to the ordinary width, the gas it gives, the
     rounding up to `VERIFY_GAS`, the 11.0 ms threshold, and that the slowest
     verification of every statement is at most its constant divided by
     `GAS_PER_MS`;
  9. the gas constants of section 10.3 (`G_PRIV`, `G_POLICY`, `G_ACTION`, and
     `G_DATA` of section 10.5), the formulas beside them, the other
     parameters, and the figures that repeat them (sections 1, 7.1, 7.2, 8.4,
     9.3, 10.4, 11, 12, 15 and 17);
 10. the two window fee examples of section 10.3 and the comparisons after
     them;
 11. the properties RP-1 to RP-30, and every RP-n cited;
 12. every formula of section 19.

When the repository's benchmark record (`docs/benchmarks/reveal-parameters.md`)
and `proofs/src/stark.rs` sit next to the document, it also checks that the
recorded slowest verification is the record's, and that the proof parameters
the bound is ported with are the prover's.

Usage:
    python3 scripts/check_private_reveal_policies.py [SPEC_MD]
    python3 scripts/check_private_reveal_policies.py --constants [SPEC_MD]

With `--constants` it prints the recomputed constants as JSON (the RP-24 gas
constants among them) after a clean check, for a node test to compare with.

Exit status is non-zero on any gap.
"""

import ast
import json
import math
import re
import sys
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SPEC = ROOT / "docs" / "spec" / "10-private-reveal-policies.md"
# Relative to the specification's directory.
BENCHMARK_RECORD = Path("..") / "benchmarks" / "reveal-parameters.md"
STARK_SOURCE = Path("..") / ".." / "proofs" / "src" / "stark.rs"

SECTION_COUNT = 19
REQUIRED_SECTIONS = ("Decisions at a glance", "What this document corrects",
                     "The rule, the capsule and the note", "The ordinary class",
                     "The policy class", "Frozen policies", "Escrow slots", "Policy actions",
                     "Native statements", "Gas constants and fees", "Pool admission",
                     "Ghost Guard", "Privacy and quantum claims", "Properties", "Not settled",
                     "What this supersedes", "Questions for the founder", "Build tickets",
                     "Checking this document")
REQUIRED_SUBSECTIONS = ("3.1", "3.2", "4.1", "4.2", "4.3", "4.4", "5.1", "5.4", "6.1", "7.1",
                        "7.2", "8.1", "8.2", "8.4", "9.2", "9.3", "10.1", "10.2", "10.3", "10.4",
                        "10.5")

# Inputs fixed elsewhere: spec 07 (proof field, gas prices, fee window), spec
# 01 (the 128-byte note version 2 plaintext, nonce and tag) and the proofs
# crate (the trace columns of version 1).
PROOF_FIELD_BYTES = 1_310_720
BYTE_GAS = 16
BASE_TX_GAS = 21_000
GAS_PER_MS = 10_000
BLOCK_GAS_LIMIT = 30_000_000
BLOCK_MS = 3_000
V1_VERIFY_GAS = 92_300
FEE_WINDOW, FEE_STEPS, TIP_DIVISOR = 4, 1, 10
NOTE_NONCE, NOTE_TAG, NOTE_V2_PLAINTEXT = 12, 16, 128
V1_NOTE_BYTES = 156
KECCAK_COLUMNS, BIT_COLUMNS, DIRECTION_COLUMNS = 2_633, 1_088, 1
BASE_WIDTH = KECCAK_COLUMNS + BIT_COLUMNS + DIRECTION_COLUMNS
V1_CARRIED = 102
V1_WIDTH = BASE_WIDTH + V1_CARRIED
V1_PERMUTATIONS = 43
ROWS_PER_PERMUTATION = 24
KECCAK_RATE = 136
TREE_DEPTH = 32
NEW_STORAGE_WORD_GAS = 20_000
STORAGE_UPDATE_GAS = 5_000
BLOCK_SECONDS = 30
HOLD_HOURS = 72
WEI_PER_GHOST = 10**18
GENESIS_BASE_FEE = 10**9
# The recorded slowest native verification at the shipped configuration, in
# milliseconds (docs/benchmarks/reveal-parameters.md, "Verifying times").
RECORDED_SLOWEST_MS = Fraction(1061, 100)
# VERIFY_GAS is the scaled charge rounded up to a multiple of this.
VERIFY_ROUNDING = 10_000
VERIFY_GAS = 110_000
# The slowest of at least 1,000 valid and 1,000 invalid verifications of each
# statement in the node's own verifier, in milliseconds (section 10.2). Each
# statement's charge is its slowest rounded up to VERIFY_ROUNDING; the
# preimage statement, which has the action's trace dimensions and is not yet
# linked into the node, takes the action's charge.
MEASURED_RUNS = 1_000
MEASURED_SLOWEST_MS = {"ordinary": Fraction(3692, 100), "policy": Fraction(4399, 100),
                       "action": Fraction(3889, 100)}
MEASURED_ROWS = {"ordinary": "`S1` version 2", "policy": "`S4`", "action": "`KNOW_ACTION_v1`"}
VERIFY = {k: max(VERIFY_GAS, -(-ms * GAS_PER_MS // VERIFY_ROUNDING) * VERIFY_ROUNDING)
          for k, ms in MEASURED_SLOWEST_MS.items()}
VERIFY["preimage"] = VERIFY["action"]

# The proof parameters of proofs/src/stark.rs that the bound depends on.
STARK = {"EXTENSION_DEGREE": 5, "LOG_BLOWUP": 3, "NUM_QUERIES": 43, "MAX_TRACE_HEIGHT": 2048}

# Tags (spec 01, section 2: one length byte, then the ASCII bytes).
RULE_TAG = "ghost/reveal-policy/v2"
OVERRIDE_TAG = "ghost/policy-override/v1"
ACTION_TAG_TAG = "ghost/policy-action/v1"
PREIMAGE_Y_TAG = "ghost/policy-preimage/v1"
V1_BINDING_TAG = "ghost/coin-reveal-binding/v1"
BINDING_TAGS = {"ordinary": "ghost/coin-reveal-binding/v2",
                "policy": "ghost/policy-reveal-binding/v1",
                "action": "ghost/action-binding/v1",
                "preimage": "ghost/preimage-binding/v1"}
RULE_FIELDS = 6

# The capsule of section 3.2.
CAPSULE = (("version", 1), ("policy_address", 20), ("policy_codehash", 32), ("override_hash", 32),
           ("action_tag", 32), ("action_salt", 32), ("params_len", 1), ("params", 64),
           ("zero pad", 10))
CAPSULE_BYTES = sum(w for _, w in CAPSULE)
NOTE_PLAINTEXT = NOTE_V2_PLAINTEXT + CAPSULE_BYTES
NOTE_BYTES = NOTE_NONCE + NOTE_PLAINTEXT + NOTE_TAG
MAX_PARAMS_BYTES = dict(CAPSULE)["params"]

# Payload fields, in order. "proof" and "note" take the proof field and the
# note widths; "calldata" takes ACTION_CALLDATA_MAX.
ACTION_CALLDATA_MAX = 1_024
ORD_PAYLOAD = (("version", 2), ("chain_id", 8), ("marker", 32), ("root", 32), ("remainder", 32),
               ("recipient", 20), ("out", 32), ("fee", 32), ("proof", None), ("note", None))
POLICY_PAYLOAD = (("version", 2), ("chain_id", 8), ("marker", 32), ("root", 32),
                  ("remainder", 32), ("out", 32), ("fee", 32), ("policy_address", 20),
                  ("policy_codehash", 32), ("params_hash", 32), ("action_tag", 32),
                  ("action_salt", 32), ("instr", 32), ("proof", None), ("note", None))
ACTION_PAYLOAD = (("version", 2), ("chain_id", 8), ("marker", 32), ("action_nonce", 8),
                  ("expected_remaining", 32), ("debit", 32), ("expiry", 8),
                  ("calldata_len", 2), ("calldata", ACTION_CALLDATA_MAX), ("proof", None))
DATA_PAYLOAD_NOTE = V1_NOTE_BYTES

# Binding fields, in order, with widths; "remainder_note" is NOTE_BYTES.
HEADER = (("chain_id", 8), ("version", 2), ("domain", 32), ("statement", 1),
          ("statement_version", 1))
ORD_BINDING = HEADER + (("type", 2), ("purpose", 1), ("root", 32), ("marker", 32),
                        ("remainder", 32), ("recipient", 20), ("out", 32), ("fee", 32),
                        ("remainder_note", NOTE_BYTES))
POLICY_BINDING = HEADER + (("type", 2), ("purpose", 1), ("root", 32), ("marker", 32),
                           ("remainder", 32), ("out", 32), ("fee", 32), ("policy_address", 20),
                           ("policy_codehash", 32), ("params_hash", 32), ("action_tag", 32),
                           ("action_salt", 32), ("instr", 32), ("remainder_note", NOTE_BYTES))
ACTION_BINDING = HEADER + (("purpose", 1), ("policy_address", 20), ("marker", 32),
                           ("action_nonce", 8), ("action_tag", 32), ("action_salt", 32),
                           ("expected_remaining", 32), ("debit", 32), ("expiry", 8),
                           ("calldata_hash", 32))
PREIMAGE_BINDING = HEADER + (("purpose", 1), ("policy_address", 20), ("y", 32), ("context", 64))
BINDINGS = {"ordinary": ORD_BINDING, "policy": POLICY_BINDING, "action": ACTION_BINDING,
            "preimage": PREIMAGE_BINDING}
# The coin reveal binding of version 1: the version 2 fields with the 32-byte
# rule and the 156-byte note.
V1_BINDING_BYTES = sum(w for _, w in ORD_BINDING) - NOTE_BYTES + V1_NOTE_BYTES + 32

# Statement codes (statement, version, purpose) of section 9.
STATEMENTS = {"ordinary": (0x01, 0x02, 0x01), "policy": (0x04, 0x01, 0x05),
              "action": (0x05, 0x01, 0x06), "preimage": (0x06, 0x01, 0x07)}
STATEMENT_ROWS = {"ordinary": "`S1` version 2", "policy": "`S4`",
                  "action": "`KNOW_ACTION_v1`", "preimage": "`KNOW_PREIMAGE_v1`"}

# Carried columns.
ORD_NEW_CARRIED = (("use_override", 1), ("RIN", 32), ("override hash", 32), ("Sinv", 1))
ORD_CARRIED = V1_CARRIED + sum(w for _, w in ORD_NEW_CARRIED)
POLICY_CARRIED = (("r", 32), ("b", 32), ("salt", 16), ("v", 6), ("v'", 6), ("carry bits", 10),
                  ("RIN", 32))

# Ethereum's own transaction types, the deposit type of the OP Stack and the
# data reveal of spec 04.
TAKEN_TYPES = set(range(0x00, 0x05)) | {0x7E, 0x51}

NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
                "eight": 8, "nine": 9, "ten": 10}

# The constants tables of section 10.3: every name with an integer value.
CONSTANTS = ("NOTE_BYTES", "ORD_ENVELOPE_BYTES", "POLICY_ENVELOPE_BYTES",
             "ACTION_ENVELOPE_BYTES", "VERIFY_GAS_ORD", "VERIFY_GAS_POLICY",
             "VERIFY_GAS_ACTION", "SLOT_OPEN_GAS", "ACTION_STATE_GAS", "ACTION_CALL_GAS",
             "G_PRIV", "G_POLICY", "G_ACTION", "FEE_WINDOW", "FEE_STEPS", "TIP_DIVISOR",
             "ORD_TX_TYPE", "ORD_TX_VERSION", "POLICY_TX_TYPE", "POLICY_VERSION",
             "ACTION_TX_TYPE", "ACTION_VERSION", "ACTION_CALLDATA_MAX", "ACTION_PROOF_BYTES",
             "MAX_TRACE_WIDTH", "MAX_PARAMS_BYTES", "HOLD_BLOCKS", "HOLD_SECONDS",
             "REGISTRY_GAS", "ESCROW_NATIVES", "STATEMENT_CHECKER", "POLICY_FACTORY",
             "PEER_FAIL_LIMIT")
NON_NUMERIC = ("ESCROW_ACCOUNT", "POLICY_REGISTRY", "ACTION_CALLER")
# The constants of RP-24: each type's gas from the block gas pool.
RP24 = ("G_PRIV", "G_POLICY", "G_ACTION", "G_DATA")

# The formulas section 19 must state.
FORMULAS = ("NOTE_BYTES", "ORD_PAYLOAD", "POLICY_PAYLOAD", "ACTION_PAYLOAD", "ordinary binding",
            "policy binding", "action binding", "permutations", "trace width", "capsule",
            "G_PRIV", "G_POLICY", "G_ACTION", "G_DATA")

PROPERTY_COUNT = 30
HEADING_RE = re.compile(r"^## (\d+)\. (.+)$")
SUBHEADING_RE = re.compile(r"^### (\d+\.\d+) (.+)$")
PROPERTY_RE = re.compile(r"^- \*\*RP-(\d+)\. (.+?)\*\*")
RP_REF_RE = re.compile(r"\bRP-(\d+)\b")
N = r"(\d[\d,]*)"  # an integer with optional thousands commas
MS = r"(\d+(?:\.\d+)?)"  # a decimal number of milliseconds


# Arithmetic


def tag_bytes(tag):
    return 1 + len(tag.encode("ascii"))


def permutations(length):
    """Keccak-f[1600] calls to absorb `length` bytes at rate 136 with Keccak
    padding (at least one padding byte)."""
    return length // KECCAK_RATE + 1


def ceil_div(a, b):
    return -(-a // b)


def next_pow2(n):
    return 1 << (n - 1).bit_length()


def trace_rows(perms):
    return next_pow2(perms * ROWS_PER_PERMUTATION)


def _seq(length, item):
    return 10 + length * item


def _multiproof_digests(depth, queries):
    return sum(min(queries, 1 << level) for level in range(depth))


def proof_length_bound(trace_height, trace_width, stark=None):
    """`proof_length_bound` of proofs/src/stark.rs, term for term."""
    s = dict(STARK, **(stark or {}))
    ext, log_blowup, queries = s["EXTENSION_DEGREE"], s["LOG_BLOWUP"], s["NUM_QUERIES"]
    field, varint, option = 4, 10, 1
    challenge = ext * field
    digest = 4 * varint
    cap = varint + digest
    chunks = 2 * (1 << log_blowup)
    flattened = ext
    random_codewords = ext
    salt_elems = 5
    opening_points = 2
    zk_min = 2 * (queries + ext * opening_points)
    h = next_pow2(max(trace_height, zk_min))
    log_codeword = (2 * h).bit_length() - 1 + log_blowup
    fri_rounds = log_codeword - log_blowup

    def challenges(n):
        return _seq(n, challenge)

    def row(n):
        return _seq(n, field)

    commitments = 3 * cap + option
    opened = (challenges(trace_width) + option + challenges(trace_width) + 2 * option
              + _seq(chunks, challenges(flattened)) + option + challenges(flattened))
    hidden = challenges(random_codewords)
    hidden_openings = (varint + _seq(1, _seq(1, hidden)) + _seq(1, _seq(opening_points, hidden))
                       + _seq(chunks, _seq(1, hidden)))

    def batch(matrices, width):
        return (_seq(queries, _seq(matrices, row(width)))
                + _seq(queries, _seq(matrices, row(salt_elems)))
                + _seq(_multiproof_digests(log_codeword, queries), digest))

    input_openings = (varint + batch(1, random_codewords + flattened)
                      + batch(1, trace_width + random_codewords)
                      + batch(chunks, flattened + random_codewords))
    layers = sum(_seq(queries, challenges(1)) + _seq(queries, _seq(1, row(salt_elems)))
                 + _seq(_multiproof_digests(log_codeword - 1 - i, queries), digest)
                 for i in range(fri_rounds))
    fri = (field + _seq(fri_rounds, cap) + _seq(fri_rounds, field) + input_openings + varint
           + layers + challenges(1) + field)
    return commitments + opened + hidden_openings + fri + varint + field


def growth_bound(b_ref, steps):
    """The most the base fee can be `steps` blocks after b_ref (spec 07)."""
    u = b_ref
    for _ in range(steps):
        u = u + u // 8 + u // 20000 + 1
    return u


def window_fee(price, gas, tip_divisor=TIP_DIVISOR):
    """(base_part, tip, fee) of a class with this gas (spec 07, section 4)."""
    base = gas * price
    tip = ceil_div(base, tip_divisor)
    return base, tip, base + tip


def gas_of(envelope, verify, extra=0):
    return BYTE_GAS * envelope + BASE_TX_GAS + verify + extra


def verification_within_charge(slowest_ms, verify_gas, gas_per_ms=GAS_PER_MS):
    """True when a slowest verification of `slowest_ms` milliseconds is at most
    the constant divided by GAS_PER_MS (section 10.2)."""
    return Fraction(slowest_ms) * gas_per_ms <= verify_gas


def round_up(value, step):
    return ceil_div(value, step) * step


def to_int(text):
    """An integer written in decimal with optional commas, or in hex as 0x..."""
    text = text.strip().strip("*").strip("`").strip()
    text = text.split()[0] if text else ""
    text = text.strip("`").replace(",", "")
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def num(text):
    return int(text.replace(",", ""))


def word_number(text):
    return NUMBER_WORDS.get(text.lower())


def millis(text):
    return Fraction(text)


def evaluate(expr):
    """An integer expression of +, -, *, /, parentheses and ceil(), exactly;
    None when it is not one."""
    expr = re.sub(r"(?<=\d),(?=\d{3}\b)", "", expr.strip())
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return Fraction(node.value)
        if isinstance(node, ast.BinOp):
            a, b = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Add):
                return a + b
            if isinstance(node.op, ast.Sub):
                return a - b
            if isinstance(node.op, ast.Mult):
                return a * b
            if isinstance(node.op, ast.Div):
                return a / b
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ("ceil", "floor") and len(node.args) == 1
                and not node.keywords):
            rounding = math.ceil if node.func.id == "ceil" else math.floor
            return Fraction(rounding(ev(node.args[0])))
        raise ValueError(ast.dump(node))

    try:
        value = ev(tree)
    except (ValueError, ZeroDivisionError):
        return None
    return int(value) if value.denominator == 1 else None


# Text


def flat(lines):
    return " ".join(" ".join(lines).split())


def name_of(cell):
    """The first backticked name in a cell, or the cell itself."""
    m = re.search(r"`([^`]+)`", cell)
    return m.group(1) if m else cell.strip()


def tables_in(lines):
    """Every Markdown table in the lines, as (header, rows of dicts)."""
    tables, block = [], []
    for line in lines + [""]:
        if line.startswith("|"):
            block.append([c.strip() for c in line.strip().strip("|").split("|")])
            continue
        if len(block) >= 2:
            header = block[0]
            tables.append((header, [dict(zip(header, cells)) for cells in block[2:]]))
        block = []
    return tables


def fenced(lines):
    """The lines inside fenced code blocks."""
    out, inside = [], False
    for line in lines:
        if line.startswith("```"):
            inside = not inside
            continue
        if inside:
            out.append(line)
    return out


def vector_blocks(lines):
    """Every `[name]` block inside fenced code blocks, as name -> fields."""
    blocks, current = {}, None
    for line in fenced(lines):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = {}
            blocks[line[1:-1]] = current
        elif current is not None and " = " in line:
            key, value = line.split(" = ", 1)
            current[key.strip()] = value.strip()
    return blocks


def stark_constants(source):
    found = {}
    for name in list(STARK) + ["MAX_TRACE_WIDTH"]:
        m = re.search(rf"^pub const {name}: usize = (\d+);", source, re.M)
        if m:
            found[name] = int(m.group(1))
    return found


def recorded_slowest(record):
    """The slowest verification of the shipped configuration in the
    benchmark record: the largest time of the 'After' row of its table of
    verifying times."""
    for header, rows in tables_in(record.splitlines()):
        if header[1:] != ["Verifying times (ms)"]:
            continue
        for row in rows:
            if row.get(header[0]) == "After":
                try:
                    return max(Fraction(x.strip()) for x in row[header[1]].split(";"))
                except (ValueError, ZeroDivisionError):
                    return None
    return None


# The recomputed values


def expected():
    """Every figure of the document, recomputed from the inputs above."""
    small = BASE_WIDTH
    ord_width = BASE_WIDTH + ORD_CARRIED
    policy_width = BASE_WIDTH + sum(w for _, w in POLICY_CARRIED)
    binding = {k: sum(w for _, w in v) for k, v in BINDINGS.items()}
    with_tag = {k: binding[k] + tag_bytes(BINDING_TAGS[k]) for k in BINDINGS}
    perms_b = {k: permutations(v) for k, v in with_tag.items()}
    rule_input = tag_bytes(RULE_TAG) + RULE_FIELDS * 32
    rin = permutations(rule_input)
    ov_input = tag_bytes(OVERRIDE_TAG) + 32
    a1_input = tag_bytes(ACTION_TAG_TAG) + 64
    y_input = tag_bytes(PREIMAGE_Y_TAG) + 32
    coin_hashes = {"F": 2, "C": 1, "N0": TREE_DEPTH, "M": 1, "F'": 2, "C'": 1}
    ord_hashes = dict({"RIN": rin, "OV": permutations(ov_input)}, **coin_hashes,
                      B=perms_b["ordinary"])
    policy_hashes = dict({"RIN": rin}, **coin_hashes, B=perms_b["policy"])
    action_perms = permutations(a1_input) + perms_b["action"]
    preimage_perms = permutations(y_input) + perms_b["preimage"]
    ord_perms, policy_perms = sum(ord_hashes.values()), sum(policy_hashes.values())
    dims = {"v1": (trace_rows(V1_PERMUTATIONS), V1_WIDTH),
            "ordinary": (trace_rows(ord_perms), ord_width),
            "policy": (trace_rows(policy_perms), policy_width),
            "action": (trace_rows(action_perms), small),
            "preimage": (trace_rows(preimage_perms), small)}
    bounds = {k: proof_length_bound(*v) for k, v in dims.items()}
    small_bound = max(bounds["action"], bounds["preimage"])
    action_proof = round_up(small_bound, 1024)

    def payload(fields, proof):
        widths = {"proof": proof, "note": NOTE_BYTES}
        return sum(widths[n] if w is None else w for n, w in fields)

    ord_payload = payload(ORD_PAYLOAD, PROOF_FIELD_BYTES)
    policy_payload = payload(POLICY_PAYLOAD, PROOF_FIELD_BYTES)
    action_payload = payload(ACTION_PAYLOAD, action_proof)
    data_payload = payload(ORD_PAYLOAD[:-1], PROOF_FIELD_BYTES) + DATA_PAYLOAD_NOTE
    slot_words = 8
    e = {
        "CAPSULE_BYTES": CAPSULE_BYTES, "NOTE_PLAINTEXT": NOTE_PLAINTEXT,
        "NOTE_BYTES": NOTE_BYTES, "MAX_PARAMS_BYTES": MAX_PARAMS_BYTES,
        "RULE_TAG_BYTES": tag_bytes(RULE_TAG), "RULE_INPUT": rule_input, "RIN_PERMS": rin,
        "OV_INPUT": ov_input, "A1_INPUT": a1_input, "Y_INPUT": y_input,
        "ORD_PAYLOAD": ord_payload, "ORD_ENVELOPE_BYTES": ord_payload + 1,
        "POLICY_PAYLOAD": policy_payload, "POLICY_ENVELOPE_BYTES": policy_payload + 1,
        "ACTION_PAYLOAD": action_payload, "ACTION_ENVELOPE_BYTES": action_payload + 1,
        "DATA_PAYLOAD": data_payload, "DATA_ENVELOPE_BYTES": data_payload + 1,
        "binding": binding, "binding_with_tag": with_tag, "binding_perms": perms_b,
        "V1_BINDING_PERMS": permutations(V1_BINDING_BYTES + tag_bytes(V1_BINDING_TAG)),
        "ord_hashes": ord_hashes, "policy_hashes": policy_hashes,
        "ORD_PERMS": ord_perms, "POLICY_PERMS": policy_perms,
        "ACTION_PERMS": action_perms, "PREIMAGE_PERMS": preimage_perms,
        "ORD_CARRIED": ORD_CARRIED, "POLICY_CARRIED": policy_width - BASE_WIDTH,
        "dims": dims, "bounds": bounds, "ACTION_PROOF_BYTES": action_proof,
        "MAX_TRACE_WIDTH": max(w for _, w in dims.values()),
        "ACTION_CALLDATA_MAX": ACTION_CALLDATA_MAX,
        "VERIFY_GAS": VERIFY_GAS, "VERIFY_GAS_DATA": V1_VERIFY_GAS,
        "VERIFY_GAS_ORD": VERIFY["ordinary"], "VERIFY_GAS_POLICY": VERIFY["policy"],
        "VERIFY_GAS_ACTION": VERIFY["action"], "PREIMAGE_VERIFY_GAS": VERIFY["preimage"],
        "SLOT_WORDS": slot_words, "SLOT_OPEN_GAS": slot_words * NEW_STORAGE_WORD_GAS,
        "ACTION_STATE_GAS": 3 * STORAGE_UPDATE_GAS, "REGISTRY_GAS": 2 * NEW_STORAGE_WORD_GAS,
        "ACTION_CALL_GAS": 250_000,
        "HOLD_SECONDS": HOLD_HOURS * 3600, "HOLD_BLOCKS": HOLD_HOURS * 3600 // BLOCK_SECONDS,
        "OVERRIDE_SUM_MAX": 32 * 255,
        "RECOMMIT_BYTE_GAS": BYTE_GAS * (32 + 16 + NOTE_BYTES),
    }
    e["G_PRIV"] = gas_of(e["ORD_ENVELOPE_BYTES"], VERIFY["ordinary"])
    e["G_POLICY"] = gas_of(e["POLICY_ENVELOPE_BYTES"], VERIFY["policy"], e["SLOT_OPEN_GAS"])
    e["G_ACTION"] = gas_of(e["ACTION_ENVELOPE_BYTES"], VERIFY["action"],
                           e["ACTION_STATE_GAS"] + e["ACTION_CALL_GAS"])
    e["G_DATA"] = gas_of(e["DATA_ENVELOPE_BYTES"], V1_VERIFY_GAS)
    e["V1_G_PRIV"] = e["G_DATA"]
    return e


def constants():
    """The recomputed constants a node pins, RP-24's gas among them."""
    e = expected()
    names = ("NOTE_BYTES", "ORD_ENVELOPE_BYTES", "POLICY_ENVELOPE_BYTES", "ACTION_ENVELOPE_BYTES",
             "ACTION_PROOF_BYTES", "MAX_TRACE_WIDTH", "SLOT_OPEN_GAS", "ACTION_STATE_GAS",
             "ACTION_CALL_GAS", "REGISTRY_GAS") + RP24
    out = {name: e[name] for name in names}
    out.update(VERIFY_GAS_ORD=VERIFY["ordinary"], VERIFY_GAS_POLICY=VERIFY["policy"],
               VERIFY_GAS_ACTION=VERIFY["action"], PREIMAGE_VERIFY_GAS=VERIFY["preimage"],
               VERIFY_GAS_DATA=V1_VERIFY_GAS, GAS_PER_MS=GAS_PER_MS)
    return out


class Checker:
    def __init__(self, text, record=None, stark_source=None):
        self.text = text
        self.record = record
        self.stark_source = stark_source
        self.lines = text.splitlines()
        self.errors = []
        self.e = expected()
        self.params = {}
        self.secs = {}
        self.subs = {}
        name = sub = None
        for line in self.lines:
            if line.startswith("## "):
                m = HEADING_RE.match(line)
                name = int(m.group(1)) if m else line
                sub = None
                self.secs[name] = []
                continue
            if line.startswith("### "):
                m = SUBHEADING_RE.match(line)
                sub = m.group(1) if m else None
                if sub is not None:
                    self.subs[sub] = []
                if name is not None:
                    self.secs[name].append(line)
                continue
            if name is not None:
                self.secs[name].append(line)
            if sub is not None:
                self.subs[sub].append(line)

    def fail(self, message):
        self.errors.append(message)

    def run(self):
        for check in (self.check_sections, self.check_note, self.check_rule,
                      self.check_ordinary, self.check_policy, self.check_action,
                      self.check_preimage, self.check_statements, self.check_trace,
                      self.check_bounds, self.check_constants, self.check_verification,
                      self.check_gas_mentions, self.check_fees, self.check_block_space,
                      self.check_data, self.check_pool, self.check_slots, self.check_guard,
                      self.check_properties, self.check_formulas, self.check_sources):
            check()
        return self.errors

    # Helpers

    def section(self, number):
        return self.secs.get(number, [])

    def sub(self, number):
        return self.subs.get(number, [])

    def find(self, pattern, lines, what):
        """The match of `pattern` in the flattened lines; a gap when absent."""
        m = re.search(pattern, flat(lines))
        if m is None:
            self.fail(f"{what}: not stated as expected")
        return m

    def same(self, what, got, want):
        if got != want:
            self.fail(f"{what} is {got}, recomputed {want}")

    def same_word(self, what, word, want):
        got = word_number(word)
        if got != want:
            self.fail(f"{what} is '{word}', recomputed {want}")

    # 1. Structure

    def check_sections(self):
        numbers = []
        for line in self.lines:
            if line.startswith("## "):
                m = HEADING_RE.match(line)
                if not m:
                    self.fail(f"heading '{line}' is not numbered as '## N. ...'")
                    continue
                numbers.append(int(m.group(1)))
        if numbers != list(range(1, SECTION_COUNT + 1)):
            self.fail(f"sections are numbered {numbers}, expected 1 to {SECTION_COUNT}")
        titles = [line for line in self.lines if line.startswith("## ")]
        for word in REQUIRED_SECTIONS:
            if not any(word.lower() in t.lower() for t in titles):
                self.fail(f"no '## N.' section whose title contains '{word}'")
        for number in REQUIRED_SUBSECTIONS:
            if number not in self.subs:
                self.fail(f"no subsection '### {number} ...'")
            elif not self.secs.get(int(number.split(".")[0])) or not any(
                    line.startswith(f"### {number} ")
                    for line in self.secs[int(number.split(".")[0])]):
                self.fail(f"subsection {number} is outside section {number.split('.')[0]}")

    # 2. Note and capsule

    def check_note(self):
        e = self.e
        lines = self.sub("3.2")
        code = fenced(lines)
        capsule = " ".join(line.strip() for line in code
                           if not line.startswith("plaintext")).split("capsule =", 1)
        if len(capsule) != 2:
            self.fail("section 3.2: no 'capsule = ...' layout")
        else:
            fields = [(n.strip(), int(w)) for n, w in
                      re.findall(r"([a-z_ ]+?) \((\d+)\)", capsule[1])]
            if fields != list(CAPSULE):
                self.fail(f"section 3.2: capsule fields are {fields}, expected {list(CAPSULE)}")
        m = self.find(r"plaintext \((\d+)\) = note version 2 fields \((\d+), with version byte "
                      r"0x03\) \|\| capsule \((\d+)\)", code, "section 3.2 plaintext layout")
        if m:
            self.same("section 3.2: plaintext", int(m.group(1)), e["NOTE_PLAINTEXT"])
            self.same("section 3.2: note version 2 fields", int(m.group(2)), NOTE_V2_PLAINTEXT)
            self.same("section 3.2: capsule", int(m.group(3)), e["CAPSULE_BYTES"])
        m = self.find(r"grows from (\d+) to " + N + r" bytes\. The plaintext grows from (\d+) to "
                      + N + r" bytes: the note version 2 plaintext of spec 01, section 9, then a "
                      + r"(\d+)-byte capsule", lines, "section 3.2 note growth")
        if m:
            self.same("section 3.2: old note", int(m.group(1)), V1_NOTE_BYTES)
            self.same("section 3.2: note", num(m.group(2)), e["NOTE_BYTES"])
            self.same("section 3.2: old plaintext", int(m.group(3)), NOTE_V2_PLAINTEXT)
            self.same("section 3.2: plaintext", num(m.group(4)), e["NOTE_PLAINTEXT"])
            self.same("section 3.2: capsule", int(m.group(5)), e["CAPSULE_BYTES"])
        m = self.find(r"`NOTE_BYTES = (\d+) \+ (\d+) \+ (\d+) = (\d+)`", lines,
                      "section 3.2 NOTE_BYTES")
        if m:
            parts = [int(x) for x in m.groups()]
            self.same("section 3.2: NOTE_BYTES terms", parts[:3],
                      [NOTE_NONCE, e["NOTE_PLAINTEXT"], NOTE_TAG])
            self.same("section 3.2: NOTE_BYTES", parts[3], e["NOTE_BYTES"])
        m = self.find(r"`params_len` is at most (\d+)", lines, "section 3.2 params_len")
        if m:
            self.same("section 3.2: params_len bound", int(m.group(1)), MAX_PARAMS_BYTES)
        m = self.find(r"own note slot of (\d+) bytes", lines, "section 3.2 data note slot")
        if m:
            self.same("section 3.2: data reveal note slot", int(m.group(1)), DATA_PAYLOAD_NOTE)
        m = self.find(r"\| Notes \| " + N + r" bytes for every commitment: today's (\d+)-byte "
                      r"plaintext plus a (\d+)-byte capsule", self.section(1), "section 1 notes")
        if m:
            self.same("section 1: note", num(m.group(1)), e["NOTE_BYTES"])
            self.same("section 1: plaintext", int(m.group(2)), NOTE_V2_PLAINTEXT)
            self.same("section 1: capsule", int(m.group(3)), e["CAPSULE_BYTES"])

    # 3. The rule

    def check_rule(self):
        e = self.e
        lines = self.sub("3.1")
        m = self.find(r'rule = K\("([^"]+)",', lines, "section 3.1 rule tag")
        if m and m.group(1) != RULE_TAG:
            self.fail(f"section 3.1: rule tag is '{m.group(1)}', expected '{RULE_TAG}'")
        m = self.find(r"The rule hash input is (\d+) bytes of tag, then (\w+) 32-byte fields: "
                      + N + r" bytes, (\w+) Keccak blocks", lines, "section 3.1 rule hash input")
        if m:
            self.same("section 3.1: rule tag bytes", int(m.group(1)), e["RULE_TAG_BYTES"])
            self.same_word("section 3.1: rule fields", m.group(2), RULE_FIELDS)
            self.same("section 3.1: rule hash input", num(m.group(3)), e["RULE_INPUT"])
            self.same_word("section 3.1: rule Keccak blocks", m.group(4), e["RIN_PERMS"])

    # 4. Payloads and bindings

    def payload_table(self, what, table, fields, proof):
        """Check an Offset/Width/Field table against `fields`; its total."""
        widths = {"proof": proof, "note": self.e["NOTE_BYTES"]}
        offset, order = 0, []
        for row in table[1]:
            field = name_of(row.get("Field", ""))
            at, width = to_int(row.get("Offset", "")), to_int(row.get("Width", ""))
            if at is None or width is None:
                self.fail(f"{what}: field '{field}' has a non-numeric offset or width")
                continue
            if at != offset:
                self.fail(f"{what}: field '{field}' at offset {at}, expected {offset}")
            order.append((field, width))
            offset = at + width
        want = [(n, widths[n] if w is None else w) for n, w in fields]
        if [f for f, _ in order] != [f for f, _ in want]:
            self.fail(f"{what}: fields are {[f for f, _ in order]}, expected "
                      f"{[f for f, _ in want]}")
        else:
            for (field, width), (_, need) in zip(order, want):
                if width != need:
                    self.fail(f"{what}: field '{field}' is {width} bytes, expected {need}")
        return offset

    def binding_table(self, kind, what, table):
        """Check a binding table; return (bytes, statement codes)."""
        offset, order, codes = 0, [], {}
        for row in table[1]:
            cell = row.get("Field", "")
            field = name_of(cell)
            at, width = to_int(row.get("Offset", "")), to_int(row.get("Width", ""))
            if at is None or width is None:
                self.fail(f"{what}: field '{field}' has a non-numeric offset or width")
                continue
            if at != offset:
                self.fail(f"{what}: field '{field}' at offset {at}, expected {offset}")
            order.append((field, width))
            offset = at + width
            value = row.get("Value")
            if value is None:
                ticks = re.findall(r"`([^`]+)`", cell)
                value = ticks[1] if len(ticks) > 1 else ""
            codes[field] = to_int(value) if value.strip() else None
        want = list(BINDINGS[kind])
        if [f for f, _ in order] != [f for f, _ in want]:
            self.fail(f"{what}: fields are {[f for f, _ in order]}, expected "
                      f"{[f for f, _ in want]}")
        else:
            for (field, width), (_, need) in zip(order, want):
                if width != need:
                    self.fail(f"{what}: field '{field}' is {width} bytes, expected {need}")
        self.check_codes(kind, what, codes)
        return offset

    def check_codes(self, kind, what, codes):
        for field, want in zip(("statement", "statement_version", "purpose"), STATEMENTS[kind]):
            if field in codes and codes[field] is not None and codes[field] != want:
                self.fail(f"{what}: {field} is {codes[field]:#04x}, expected {want:#04x}")

    def check_binding_total(self, kind, what, lines, public=None):
        e = self.e
        m = self.find(r'binding = K\("([^"]+)", fields\)', lines, f"{what} tag")
        if m and m.group(1) != BINDING_TAGS[kind]:
            self.fail(f"{what}: tag is '{m.group(1)}', expected '{BINDING_TAGS[kind]}'")
        m = self.find(r"Total: " + N + r" bytes after the tag, " + N + r" with the (\d+)-byte "
                      r"tag, (\w+) (?:Keccak )?permutations", lines, f"{what} total")
        if m:
            self.same(f"{what}: bytes after the tag", num(m.group(1)), e["binding"][kind])
            self.same(f"{what}: bytes with the tag", num(m.group(2)), e["binding_with_tag"][kind])
            self.same(f"{what}: tag bytes", int(m.group(3)), tag_bytes(BINDING_TAGS[kind]))
            self.same_word(f"{what}: permutations", m.group(4), e["binding_perms"][kind])
        if public:
            m = self.find(public, lines, f"{what} public values")
            if m:
                self.same(f"{what}: public binding bytes", num(m.group(1)), e["binding"][kind])
                self.same(f"{what}: public values", num(m.group(2)), e["binding"][kind] + 32)

    def check_ordinary(self):
        e = self.e
        lines = self.sub("4.1")
        m = self.find(r"The payload is " + N + r" bytes and the envelope " + N + r" bytes",
                      lines, "section 4.1 payload")
        if m:
            self.same("section 4.1: payload", num(m.group(1)), e["ORD_PAYLOAD"])
            self.same("section 4.1: envelope", num(m.group(2)), e["ORD_ENVELOPE_BYTES"])
        m = self.find(r"PAYLOAD_BYTES = ([\d+, ]+?) = " + N + r" ENVELOPE_BYTES = " + N,
                      fenced(lines), "section 4.1 payload formula")
        if m:
            terms = [num(t) for t in m.group(1).split("+")]
            want = [PROOF_FIELD_BYTES if n == "proof" else e["NOTE_BYTES"] if n == "note" else w
                    for n, w in ORD_PAYLOAD]
            self.same("section 4.1: payload terms", terms, want)
            self.same("section 4.1: PAYLOAD_BYTES", num(m.group(2)), e["ORD_PAYLOAD"])
            self.same("section 4.1: ENVELOPE_BYTES", num(m.group(3)), e["ORD_ENVELOPE_BYTES"])
        m = self.find(r"`note` is `NOTE_BYTES = (\d+)`", lines, "section 4.1 note")
        if m:
            self.same("section 4.1: note", int(m.group(1)), e["NOTE_BYTES"])
        lines = self.sub("4.2")
        tables = tables_in(lines)
        if not tables:
            self.fail("section 4.2: no binding table")
        else:
            got = self.binding_table("ordinary", "section 4.2 binding", tables[0])
            self.same("section 4.2: binding table bytes", got, e["binding"]["ordinary"])
        self.check_binding_total("ordinary", "section 4.2 binding", lines,
                                 r"The public values of the proof are these " + N
                                 + r" bytes and the 32-byte digest: " + N + r" bytes")
        m = self.find(r"permutations \((\w+) today\)", lines, "section 4.2 version 1 binding")
        if m:
            self.same_word("section 4.2: version 1 binding permutations", m.group(1),
                           e["V1_BINDING_PERMS"])
        m = self.find(r"`S` is at most " + N, self.sub("4.3"), "section 4.3 O5")
        if m:
            self.same("section 4.3: largest byte sum S", num(m.group(1)), e["OVERRIDE_SUM_MAX"])

    def check_policy(self):
        e = self.e
        lines = self.sub("5.1")
        tables = tables_in(lines)
        if len(tables) < 2:
            self.fail("section 5.1: needs the payload table and the binding table")
            return
        got = self.payload_table("section 5.1 payload", tables[0], POLICY_PAYLOAD,
                                 PROOF_FIELD_BYTES)
        self.same("section 5.1: payload table bytes", got, e["POLICY_PAYLOAD"])
        m = self.find(r"Payload " + N + r" bytes, envelope " + N + r" bytes", lines,
                      "section 5.1 payload")
        if m:
            self.same("section 5.1: payload", num(m.group(1)), e["POLICY_PAYLOAD"])
            self.same("section 5.1: envelope", num(m.group(2)), e["POLICY_ENVELOPE_BYTES"])
        got = self.binding_table("policy", "section 5.1 binding", tables[1])
        self.same("section 5.1: binding table bytes", got, e["binding"]["policy"])
        self.check_binding_total("policy", "section 5.1 binding", lines,
                                 r"Public values: " + N + r" plus the 32-byte digest, " + N
                                 + r" bytes")

    def check_action(self):
        e = self.e
        lines = self.sub("8.1")
        tables = tables_in(lines)
        if not tables:
            self.fail("section 8.1: no payload table")
        else:
            got = self.payload_table("section 8.1 payload", tables[0], ACTION_PAYLOAD,
                                     e["ACTION_PROOF_BYTES"])
            self.same("section 8.1: payload table bytes", got, e["ACTION_PAYLOAD"])
        m = self.find(r"Payload " + N + r" bytes, envelope " + N + r" bytes", lines,
                      "section 8.1 payload")
        if m:
            self.same("section 8.1: payload", num(m.group(1)), e["ACTION_PAYLOAD"])
            self.same("section 8.1: envelope", num(m.group(2)), e["ACTION_ENVELOPE_BYTES"])
        m = self.find(r"`ACTION_PROOF_BYTES` is the bound of section 4\.4 for the small "
                      r"statements, " + N + r", rounded up to a multiple of " + N, lines,
                      "section 8.1 ACTION_PROOF_BYTES")
        if m:
            self.same("section 8.1: small statement bound", num(m.group(1)),
                      max(e["bounds"]["action"], e["bounds"]["preimage"]))
            self.same("section 8.1: rounding", num(m.group(2)), 1024)
        m = self.find(r"`calldata_len` \| At most `ACTION_CALLDATA_MAX = " + N + "`", lines,
                      "section 8.1 calldata_len")
        if m:
            self.same("section 8.1: ACTION_CALLDATA_MAX", num(m.group(1)), ACTION_CALLDATA_MAX)
        lines = self.sub("8.2")
        tables = tables_in(lines)
        if not tables:
            self.fail("section 8.2: no binding table")
        else:
            got = self.binding_table("action", "section 8.2 binding", tables[0])
            self.same("section 8.2: binding table bytes", got, e["binding"]["action"])
        self.check_binding_total("action", "section 8.2 binding", lines)
        m = self.find(r"`action_root` free and private \((\w+) permutation, (\d+) bytes of "
                      r"input\)", lines, "section 8.2 A1")
        if m:
            self.same_word("section 8.2: A1 permutations", m.group(1),
                           permutations(e["A1_INPUT"]))
            self.same("section 8.2: A1 input", int(m.group(2)), e["A1_INPUT"])
        m = self.find(r"\*\*A3\.\*\* The binding \((\w+) permutations\)", lines, "section 8.2 A3")
        if m:
            self.same_word("section 8.2: A3 permutations", m.group(1),
                           e["binding_perms"]["action"])
        m = self.find(r"(\w+) permutations, (\d+) rows, padded to (\d+)\. No carried columns: "
                      r"width " + N, lines, "section 8.2 trace")
        if m:
            self.same_word("section 8.2: permutations", m.group(1), e["ACTION_PERMS"])
            self.same("section 8.2: rows", int(m.group(2)),
                      e["ACTION_PERMS"] * ROWS_PER_PERMUTATION)
            self.same("section 8.2: padded rows", int(m.group(3)), e["dims"]["action"][0])
            self.same("section 8.2: width", num(m.group(4)), e["dims"]["action"][1])
        m = self.find(r"\*\*A4\.\*\* `statement = (0x[0-9a-f]+)`, `statement_version = "
                      r"(0x[0-9a-f]+)`, `purpose = (0x[0-9a-f]+)`", lines, "section 8.2 A4")
        if m:
            self.same("section 8.2: A4 codes", tuple(int(x, 16) for x in m.groups()),
                      STATEMENTS["action"])
        m = self.find(r"Statement code `(0x[0-9a-f]+)`, version `(0x[0-9a-f]+)`, purpose "
                      r"`(0x[0-9a-f]+)`", lines, "section 8.2 codes")
        if m:
            self.same("section 8.2: statement codes", tuple(int(x, 16) for x in m.groups()),
                      STATEMENTS["action"])

    def check_preimage(self):
        e = self.e
        lines = self.sub("9.2")
        self.check_binding_tag_only("preimage", "section 9.2 binding", lines)
        m = self.find(r"fields\)` over: (.*?); (\d+) bytes, (\d+) with the tag, (\w+) "
                      r"permutations\. One more permutation computes `y`\. (\w+) permutations, "
                      r"(\d+) rows, padded to (\d+); width " + N, lines, "section 9.2 binding")
        if not m:
            return
        fields = [(f, int(w)) for f, w in re.findall(r"`(\w+) \((\d+)\)`", m.group(1))]
        if fields != list(PREIMAGE_BINDING):
            self.fail(f"section 9.2 binding: fields are {fields}, expected "
                      f"{list(PREIMAGE_BINDING)}")
        self.same("section 9.2: binding bytes", int(m.group(2)), e["binding"]["preimage"])
        self.same("section 9.2: binding with the tag", int(m.group(3)),
                  e["binding_with_tag"]["preimage"])
        self.same_word("section 9.2: binding permutations", m.group(4),
                       e["binding_perms"]["preimage"])
        self.same_word("section 9.2: permutations", m.group(5), e["PREIMAGE_PERMS"])
        self.same("section 9.2: rows", int(m.group(6)), e["PREIMAGE_PERMS"] * ROWS_PER_PERMUTATION)
        self.same("section 9.2: padded rows", int(m.group(7)), e["dims"]["preimage"][0])
        self.same("section 9.2: width", num(m.group(8)), e["dims"]["preimage"][1])
        m = self.find(r'`y = K\("([^"]+)", x\)`', lines, "section 9.2 y")
        if m and m.group(1) != PREIMAGE_Y_TAG:
            self.fail(f"section 9.2: y tag is '{m.group(1)}', expected '{PREIMAGE_Y_TAG}'")

    def check_binding_tag_only(self, kind, what, lines):
        m = self.find(r'binding = K\("([^"]+)", fields\)', lines, f"{what} tag")
        if m and m.group(1) != BINDING_TAGS[kind]:
            self.fail(f"{what}: tag is '{m.group(1)}', expected '{BINDING_TAGS[kind]}'")

    def check_statements(self):
        tables = tables_in(self.section(9))
        rows = tables[0][1] if tables and "Code" in tables[0][0] else None
        if rows is None:
            self.fail("section 9: no statement table with a Code column")
            return
        seen = set()
        for kind, label in STATEMENT_ROWS.items():
            row = next((r for r in rows if r.get("Statement", "").startswith(label)), None)
            if row is None:
                self.fail(f"section 9: no row for {label}")
                continue
            got = tuple(to_int(row.get(c, "")) for c in ("Code", "Version", "Purpose"))
            self.same(f"section 9: codes of {label}", got, STATEMENTS[kind])
            if got[0] in seen:
                self.fail(f"section 9: statement code {got[0]} is used twice")
            seen.add(got[0])
        purposes = [to_int(r.get("Purpose", "")) for r in rows]
        if len(set(purposes)) != len(purposes):
            self.fail(f"section 9: purpose codes {purposes} are not distinct")

    # 5. Traces and bounds

    def check_trace(self):
        e = self.e
        lines = self.sub("4.4")
        tables = tables_in(lines)
        table = next((t for t in tables if "Permutations" in t[0]), None)
        if table is None:
            self.fail("section 4.4: no Hash/Permutations table")
        else:
            got, total = {}, None
            for row in table[1]:
                name, count = name_of(row.get("Hash", "")), to_int(row.get("Permutations", ""))
                if name == "Total":
                    total = count
                else:
                    got[name] = count
            self.same("section 4.4: permutations per hash", got, e["ord_hashes"])
            self.same("section 4.4: total permutations", total, e["ORD_PERMS"])
            if total is not None and sum(v or 0 for v in got.values()) != total:
                self.fail(f"section 4.4: the hashes add up to {sum(v or 0 for v in got.values())}"
                          f", the total says {total}")
            m = re.search(r"(\w+) more than the (\d+) of version 1",
                          flat([r.get("Note", "") for r in table[1]]))
            if m is None:
                self.fail("section 4.4: the total does not compare with version 1")
            else:
                self.same_word("section 4.4: permutations added", m.group(1),
                               e["ORD_PERMS"] - V1_PERMUTATIONS)
                self.same("section 4.4: version 1 permutations", int(m.group(2)),
                          V1_PERMUTATIONS)
            for row in table[1]:
                note = row.get("Note", "")
                m = re.search(r"(\d+) bytes of input", note)
                name = name_of(row.get("Hash", ""))
                if m and name in ("RIN", "OV"):
                    want = e["RULE_INPUT"] if name == "RIN" else e["OV_INPUT"]
                    self.same(f"section 4.4: input of {name}", int(m.group(1)), want)
        m = self.find(r"New carried columns: (.*?)\. The carried columns go from (\d+) to (\d+)\.",
                      lines, "section 4.4 carried columns")
        if m:
            items = [int(x) for x in re.findall(r"\((\d+)\)", m.group(1))]
            self.same("section 4.4: new carried columns", items,
                      [w for _, w in ORD_NEW_CARRIED])
            self.same("section 4.4: version 1 carried columns", int(m.group(2)), V1_CARRIED)
            self.same("section 4.4: carried columns", int(m.group(3)), e["ORD_CARRIED"])
        m = self.find(r"The trace is (\d+) \* (\d+) = " + N + r" rows, padded to " + N, lines,
                      "section 4.4 rows")
        if m:
            perms, per, rows, padded = (num(x) for x in m.groups())
            self.same("section 4.4: trace permutations", perms, e["ORD_PERMS"])
            self.same("section 4.4: rows per permutation", per, ROWS_PER_PERMUTATION)
            self.same("section 4.4: rows", rows, e["ORD_PERMS"] * ROWS_PER_PERMUTATION)
            self.same("section 4.4: padded rows", padded, e["dims"]["ordinary"][0])
        m = self.find(r"the Keccak circuit \(" + N + r"\), the bit columns \(" + N + r"\) and the "
                      r"direction column \((\d+)\), " + N + r" in all, plus (\d+): \*\*" + N
                      + r" columns\*\*", lines, "section 4.4 width")
        if m:
            keccak, bits, direction, base, carried, width = (num(x) for x in m.groups())
            self.same("section 4.4: column groups", (keccak, bits, direction),
                      (KECCAK_COLUMNS, BIT_COLUMNS, DIRECTION_COLUMNS))
            self.same("section 4.4: base width", base, BASE_WIDTH)
            self.same("section 4.4: carried columns in the width", carried, e["ORD_CARRIED"])
            self.same("section 4.4: width", width, e["dims"]["ordinary"][1])
        m = self.find(r"`MAX_TRACE_WIDTH` goes from " + N + r" to " + N + r"\. `MAX_TRACE_HEIGHT` "
                      r"stays " + N, lines, "section 4.4 budget")
        if m:
            self.same("section 4.4: old MAX_TRACE_WIDTH", num(m.group(1)), V1_WIDTH)
            self.same("section 4.4: MAX_TRACE_WIDTH", num(m.group(2)), e["MAX_TRACE_WIDTH"])
            self.same("section 4.4: MAX_TRACE_HEIGHT", num(m.group(3)), STARK["MAX_TRACE_HEIGHT"])
        m = self.find(r"Both large bounds are below the " + N + r"-byte proof field", lines,
                      "section 4.4 proof field")
        if m:
            self.same("section 4.4: proof field", num(m.group(1)), PROOF_FIELD_BYTES)
        m = self.find(N + r" over " + N + r" moves it by about ([\d.]+) bit", lines,
                      "section 4.4 estimator shift")
        if m:
            self.same("section 4.4: estimator widths", (num(m.group(1)), num(m.group(2))),
                      (e["dims"]["ordinary"][1], V1_WIDTH))
            shift = math.log2(e["dims"]["ordinary"][1] / V1_WIDTH)
            self.same("section 4.4: estimator shift", m.group(3), f"{shift:.3f}")
        # Section 5.4: the policy statement.
        lines = self.sub("5.4")
        m = self.find(r"Hashes: (.*?); (\d+) permutations\. Carried columns: (.*?), (\d+) in all\. "
                      r"Width " + N + r" \+ (\d+) = \*\*" + N + r"\*\*, " + N + r" rows", lines,
                      "section 5.4 trace")
        if m:
            hashes = {k: int(v) for k, v in re.findall(r"`([^`]+)` (\d+)", m.group(1))}
            hashes = {("N0" if k.startswith("N0") else k): v for k, v in hashes.items()}
            self.same("section 5.4: permutations per hash", hashes, e["policy_hashes"])
            self.same("section 5.4: permutations", int(m.group(2)), e["POLICY_PERMS"])
            items = [int(x) for x in re.findall(r"\((\d+)\)", m.group(3))]
            self.same("section 5.4: carried columns", items, [w for _, w in POLICY_CARRIED])
            self.same("section 5.4: carried column total", int(m.group(4)), e["POLICY_CARRIED"])
            self.same("section 5.4: base width", num(m.group(5)), BASE_WIDTH)
            self.same("section 5.4: carried columns in the width", int(m.group(6)),
                      e["POLICY_CARRIED"])
            self.same("section 5.4: width", num(m.group(7)), e["dims"]["policy"][1])
            self.same("section 5.4: rows", num(m.group(8)), e["dims"]["policy"][0])

    def check_bounds(self):
        e = self.e
        table = next((t for t in tables_in(self.sub("4.4")) if "Columns" in t[0]), None)
        if table is None:
            self.fail("section 4.4: no Statement/Rows/Columns bound table")
            return
        labels = (("S1 version 1", "v1"), ("S1 version 2", "ordinary"),
                  ("Policy class", "policy"), ("Small statements", "action"))
        bound_col = next((c for c in table[0] if "proof_length_bound" in c), None)
        for label, kind in labels:
            row = next((r for r in table[1] if r.get("Statement", "").startswith(label)), None)
            if row is None or bound_col is None:
                self.fail(f"section 4.4: no bound row for '{label}'")
                continue
            rows, cols = to_int(row.get("Rows", "")), to_int(row.get("Columns", ""))
            self.same(f"section 4.4: {label} rows and columns", (rows, cols), e["dims"][kind])
            self.same(f"section 4.4: {label} proof_length_bound", to_int(row[bound_col]),
                      e["bounds"][kind])
        if e["dims"]["preimage"] != e["dims"]["action"]:
            self.fail("the two small statements no longer share one trace size")
        for kind in ("ordinary", "policy"):
            if e["bounds"][kind] > PROOF_FIELD_BYTES:
                self.fail(f"the {kind} bound is above the proof field")

    # 6. Constants

    def check_constants(self):
        e = self.e
        lines = self.sub("10.3")
        tables = [t for t in tables_in(lines) if {"Name", "Value"} <= set(t[0])]
        if len(tables) < 2:
            self.fail("section 10.3: needs the constants table and the other parameters table")
            return
        formulas = {}
        for _, rows in tables:
            for row in rows:
                names = re.findall(r"`([^`]+)`", row.get("Name", ""))
                if names and names[0].startswith("_"):
                    continue
                full, base = [], None
                for name in names:
                    if name.startswith("_") and base:
                        full.append(base + name)
                    else:
                        full.append(name)
                        base = name.rsplit("_", 1)[0]
                value_text = row.get("Value", "")
                if value_text.strip().endswith(" each"):
                    values = [value_text.strip()[:-5]] * len(full)
                else:
                    values = [v for v in re.split(r",\s+", value_text)]
                if len(values) != len(full):
                    self.fail(f"section 10.3: {full} have values '{value_text}'")
                    continue
                for name, value in zip(full, values):
                    if name in NON_NUMERIC:
                        continue
                    number = to_int(value)
                    if number is None:
                        self.fail(f"section 10.3: {name} is '{value}', not an integer")
                        continue
                    if name in self.params:
                        self.fail(f"section 10.3: {name} appears twice")
                    self.params[name] = number
                    m = re.fullmatch(r"`([^`]+)`", row.get("Meaning", "").strip())
                    if m and len(full) == 1:
                        formulas[name] = m.group(1)
        missing = [c for c in CONSTANTS if c not in self.params]
        if missing:
            self.fail(f"section 10.3: the tables lack {missing}")
        p = self.params
        want = {
            "NOTE_BYTES": e["NOTE_BYTES"], "ORD_ENVELOPE_BYTES": e["ORD_ENVELOPE_BYTES"],
            "POLICY_ENVELOPE_BYTES": e["POLICY_ENVELOPE_BYTES"],
            "ACTION_ENVELOPE_BYTES": e["ACTION_ENVELOPE_BYTES"],
            "VERIFY_GAS_ORD": VERIFY["ordinary"], "VERIFY_GAS_POLICY": VERIFY["policy"],
            "VERIFY_GAS_ACTION": VERIFY["action"], "SLOT_OPEN_GAS": e["SLOT_OPEN_GAS"],
            "ACTION_STATE_GAS": e["ACTION_STATE_GAS"], "ACTION_CALL_GAS": e["ACTION_CALL_GAS"],
            "G_PRIV": e["G_PRIV"], "G_POLICY": e["G_POLICY"], "G_ACTION": e["G_ACTION"],
            "FEE_WINDOW": FEE_WINDOW, "FEE_STEPS": FEE_STEPS, "TIP_DIVISOR": TIP_DIVISOR,
            "ORD_TX_VERSION": 2, "POLICY_VERSION": 1, "ACTION_VERSION": 1,
            "ACTION_CALLDATA_MAX": ACTION_CALLDATA_MAX,
            "ACTION_PROOF_BYTES": e["ACTION_PROOF_BYTES"],
            "MAX_TRACE_WIDTH": e["MAX_TRACE_WIDTH"], "MAX_PARAMS_BYTES": MAX_PARAMS_BYTES,
            "HOLD_BLOCKS": e["HOLD_BLOCKS"], "HOLD_SECONDS": e["HOLD_SECONDS"],
            "REGISTRY_GAS": e["REGISTRY_GAS"],
        }
        for name, value in want.items():
            if name in p and p[name] != value:
                self.fail(f"constant {name} is {p[name]}, recomputed {value}")
        # The gas of each class from the table's own entries, so that a
        # changed input moves the derived figure.
        if all(n in p for n in CONSTANTS):
            own = {
                "G_PRIV": gas_of(p["ORD_ENVELOPE_BYTES"], p["VERIFY_GAS_ORD"]),
                "G_POLICY": gas_of(p["POLICY_ENVELOPE_BYTES"], p["VERIFY_GAS_POLICY"],
                                   p["SLOT_OPEN_GAS"]),
                "G_ACTION": gas_of(p["ACTION_ENVELOPE_BYTES"], p["VERIFY_GAS_ACTION"],
                                   p["ACTION_STATE_GAS"] + p["ACTION_CALL_GAS"]),
            }
            for name, value in own.items():
                if p[name] != value:
                    self.fail(f"constant {name} is {p[name]}, the table's own entries give "
                              f"{value}")
        for name, formula in formulas.items():
            value = evaluate(formula)
            if value is None:
                self.fail(f"section 10.3: the formula of {name}, '{formula}', is not arithmetic")
            elif value != p[name]:
                self.fail(f"section 10.3: the formula of {name} gives {value}, the table says "
                          f"{p[name]}")
        for name in ("G_PRIV", "G_POLICY", "G_ACTION", "ACTION_PROOF_BYTES"):
            if name in p and name not in formulas:
                self.fail(f"section 10.3: {name} has no formula in its Meaning column")
        types = [p.get(n) for n in ("ORD_TX_TYPE", "POLICY_TX_TYPE", "ACTION_TX_TYPE")]
        self.same("section 10.3: transaction types", types, [0x50, 0x53, 0x54])
        for t in types:
            if t is not None and t != 0x50 and (t in TAKEN_TYPES or not 0 < t < 0x7F):
                self.fail(f"section 10.3: type {t:#04x} is taken or outside EIP-2718's range")
        if len(set(types)) != len(types):
            self.fail(f"section 10.3: transaction types {types} are not distinct")
        addresses = {"ESCROW_NATIVES": (0x60, "7.2"), "STATEMENT_CHECKER": (0x61, "9.3"),
                     "POLICY_FACTORY": (0x62, "6.1")}
        for name, (value, where) in addresses.items():
            self.same(f"section 10.3: {name}", p.get(name), value)
            m = self.find(rf"`{name} = (0x[0-9a-f]{{40}})`", self.sub(where),
                          f"section {where} {name}")
            if m:
                self.same(f"section {where}: {name}", int(m.group(1), 16), p.get(name))

    def check_verification(self):
        e = self.e
        lines = self.sub("10.1")
        m = self.find(r"`BYTE_GAS = (\d+)` and `BASE_TX_GAS = " + N + "`", lines,
                      "section 10.1 gas prices")
        if m:
            self.same("section 10.1: BYTE_GAS", int(m.group(1)), BYTE_GAS)
            self.same("section 10.1: BASE_TX_GAS", num(m.group(2)), BASE_TX_GAS)
        m = self.find(r"`GAS_PER_MS = " + N + r"` \(" + N + r" gas over " + N + r" ms\)", lines,
                      "section 10.1 GAS_PER_MS")
        if m:
            per, gas, ms = (num(x) for x in m.groups())
            self.same("section 10.1: GAS_PER_MS", per, GAS_PER_MS)
            self.same("section 10.1: block gas and time", (gas, ms), (BLOCK_GAS_LIMIT, BLOCK_MS))
            if ms and gas != per * ms:
                self.fail(f"section 10.1: {gas} gas over {ms} ms is not {per} gas per ms")
        lines = self.sub("10.2")
        m = self.find(r"The recorded slowest verification of the budget trace is \*\*" + MS
                      + r" ms\*\*", lines, "section 10.2 recorded slowest")
        recorded = millis(m.group(1)) if m else None
        if recorded is not None:
            self.same("section 10.2: recorded slowest ms", recorded, RECORDED_SLOWEST_MS)
        code = fenced(lines)
        m = self.find(MS + r" ms \* \(" + N + r" / " + N + r"\) = " + MS + r" ms -> " + N
                      + r" gas", code, "section 10.2 scaling")
        exact = RECORDED_SLOWEST_MS * e["dims"]["ordinary"][1] / V1_WIDTH
        stated = Fraction(round(exact * 100), 100)
        if m:
            self.same("section 10.2: scaled ms", millis(m.group(1)), RECORDED_SLOWEST_MS)
            self.same("section 10.2: width ratio", (num(m.group(2)), num(m.group(3))),
                      (e["dims"]["ordinary"][1], V1_WIDTH))
            self.same("section 10.2: scaled slowest", millis(m.group(4)), stated)
            self.same("section 10.2: scaled gas", num(m.group(5)), int(stated * GAS_PER_MS))
        m = self.find(r"estimate = " + N + r" \(rounded up\)", code, "section 10.2 estimate")
        if m:
            self.same("section 10.2: estimate", num(m.group(1)), VERIFY_GAS)
        # The measurement: one row per statement, its runs, its slowest and
        # the charge that slowest rounds up to.
        rows = {}
        for line in lines:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) == 5 and cells[0] in MEASURED_ROWS.values():
                rows[cells[0]] = cells[1:]
        names = {"ordinary": "VERIFY_GAS_ORD", "policy": "VERIFY_GAS_POLICY",
                 "action": "VERIFY_GAS_ACTION"}
        for kind, row_name in MEASURED_ROWS.items():
            row = rows.get(row_name)
            if row is None:
                self.fail(f"section 10.2: the measurement has no row for {row_name}")
                continue
            valid, invalid, ms, gas = row
            for label, n in (("valid", valid), ("invalid", invalid)):
                if to_int(n) is None or to_int(n) < 1000:
                    self.fail(f"section 10.2: {row_name} has {n} {label} runs, fewer than 1,000")
            self.same(f"section 10.2: {row_name} runs", (to_int(valid), to_int(invalid)),
                      (MEASURED_RUNS, MEASURED_RUNS))
            self.same(f"section 10.2: {row_name} slowest ms", millis(ms),
                      MEASURED_SLOWEST_MS[kind])
            self.same(f"section 10.2: {row_name} charge", to_int(gas.strip("`")), VERIFY[kind])
            if VERIFY[kind] != max(VERIFY_GAS, round_up(math.ceil(MEASURED_SLOWEST_MS[kind]
                                                                 * GAS_PER_MS), VERIFY_ROUNDING)):
                self.fail(f"{names[kind]} {VERIFY[kind]} is not the measured slowest rounded up")
            if not verification_within_charge(MEASURED_SLOWEST_MS[kind], VERIFY[kind]):
                self.fail(f"the measured slowest {kind} verification is above its charge")
        want = round_up(math.ceil(exact * GAS_PER_MS), VERIFY_ROUNDING)
        if VERIFY_GAS != want:
            self.fail(f"VERIFY_GAS {VERIFY_GAS} is not the scaled charge rounded up, {want}")
        m = self.find(r"If the slowest exceeds " + MS + r" ms \(" + N + r" gas\) the constant is "
                      r"\*\*raised\*\*", lines, "section 10.2 threshold")
        if m:
            self.same("section 10.2: threshold ms", millis(m.group(1)),
                      Fraction(VERIFY_GAS, GAS_PER_MS))
            self.same("section 10.2: threshold gas", num(m.group(2)), VERIFY_GAS)
        m = self.find(r"The small statements \(" + N + r" rows, " + N + r" columns\)", lines,
                      "section 10.2 small statements")
        if m:
            self.same("section 10.2: small statements", (num(m.group(1)), num(m.group(2))),
                      e["dims"]["action"])
        m = self.find(r"`VERIFY_GAS_DATA = " + N + "`", lines, "section 10.2 VERIFY_GAS_DATA")
        if m:
            self.same("section 10.2: VERIFY_GAS_DATA", num(m.group(1)), V1_VERIFY_GAS)
        m = self.find(r"at least " + N + r" verifications of each statement", lines,
                      "section 10.2 measurement")
        if m and num(m.group(1)) < 1000:
            self.fail(f"section 10.2: the build ticket measures {num(m.group(1))} verifications, "
                      f"fewer than 1,000")
        # The slowest verification of each statement, scaled from the record
        # by width (every statement has at most the budget trace's rows), is at
        # most its constant divided by GAS_PER_MS.
        verify = {"ordinary": "VERIFY_GAS_ORD", "policy": "VERIFY_GAS_POLICY",
                  "action": "VERIFY_GAS_ACTION", "preimage": "VERIFY_GAS_ACTION"}
        for kind, name in verify.items():
            rows, width = e["dims"][kind]
            slowest = RECORDED_SLOWEST_MS * Fraction(max(width, V1_WIDTH), V1_WIDTH)
            gas = self.params.get(name, VERIFY[kind])
            if rows > STARK["MAX_TRACE_HEIGHT"] or not verification_within_charge(slowest, gas):
                self.fail(f"the slowest {kind} verification, {float(slowest):.2f} ms, is above "
                          f"{name} / GAS_PER_MS = {Fraction(gas, GAS_PER_MS)} ms")
        m = self.find(r"measured a slowest native verification of " + MS + r" ms in (\w+) runs",
                      self.section(2), "section 2 recorded slowest")
        if m:
            self.same("section 2: recorded slowest ms", millis(m.group(1)), RECORDED_SLOWEST_MS)
            self.same_word("section 2: runs", m.group(2), 9)
        m = self.find(r"were set from the recorded " + MS + r" ms", self.section(15),
                      "section 15 item 1")
        if m:
            self.same("section 15: recorded slowest ms", millis(m.group(1)), RECORDED_SLOWEST_MS)
        m = self.find(r"\*\*Verification charge\.\*\* " + N + r" gas for each new statement, above "
                      r"the recorded " + MS + r" ms", self.section(17), "section 17 question 2")
        if m:
            self.same("section 17: verification charge", num(m.group(1)), VERIFY_GAS)
            self.same("section 17: recorded slowest ms", millis(m.group(2)), RECORDED_SLOWEST_MS)
        m = self.find(r"charges are raised to (\d{1,3}(?:,\d{3})*), (\d{1,3}(?:,\d{3})*) and "
                      r"(\d{1,3}(?:,\d{3})*) gas", self.section(17), "section 17 measured charges")
        if m:
            self.same("section 17: measured charges", tuple(num(x) for x in m.groups()),
                      (VERIFY["ordinary"], VERIFY["policy"], VERIFY["action"]))
        m = self.find(r"`PREIMAGE_VERIFY_GAS = " + N + "`", self.sub("9.3"),
                      "section 9.3 PREIMAGE_VERIFY_GAS")
        if m:
            self.same("section 9.3: PREIMAGE_VERIFY_GAS", num(m.group(1)), VERIFY["preimage"])

    def check_gas_mentions(self):
        e = self.e
        m = self.find(r"`G_PRIV` " + N + r"; `G_POLICY` " + N + r"; `G_ACTION` " + N
                      + r"; the data reveal keeps " + N, self.section(1), "section 1 gas")
        if m:
            got = tuple(num(x) for x in m.groups())
            self.same("section 1: gas", got, (e["G_PRIV"], e["G_POLICY"], e["G_ACTION"],
                                              e["G_DATA"]))
        m = self.find(r"Spec 07 sets ([\d,]+) from the ([\d.]+) ms", self.section(2),
                      "section 2 spec 07 charge")
        if m:
            self.same("section 2: spec 07 VERIFY_GAS", num(m.group(1)), V1_VERIFY_GAS)
            self.same("section 2: spec 07 slowest ms", millis(m.group(2)),
                      Fraction(V1_VERIFY_GAS, GAS_PER_MS))
        m = self.find(r"the proof bytes alone cost over " + N + r" million gas", self.section(2),
                      "section 2 action proof gas")
        if m and BYTE_GAS * e["ACTION_PROOF_BYTES"] <= num(m.group(1)) * 10**6:
            self.fail(f"section 2: the action proof bytes cost "
                      f"{BYTE_GAS * e['ACTION_PROOF_BYTES']} gas, not over {m.group(1)} million")

    def check_fees(self):
        e = self.e
        lines = self.sub("10.3")
        m = self.find(r"\(`b_ref = " + N + r"`, `price = " + N + r"`\)", lines,
                      "section 10.3 genesis price")
        if not m:
            return
        b_ref, price = num(m.group(1)), num(m.group(2))
        self.same("section 10.3: b_ref", b_ref, GENESIS_BASE_FEE)
        steps = self.params.get("FEE_STEPS", FEE_STEPS)
        want_price = growth_bound(b_ref, steps)
        self.same("section 10.3: price", price, want_price)
        blocks = vector_blocks(lines)
        divisor = self.params.get("TIP_DIVISOR", TIP_DIVISOR)
        fees = {}
        for name, gas_name in (("window-genesis-ordinary", "G_PRIV"),
                               ("window-genesis-policy", "G_POLICY")):
            fields = blocks.get(name)
            if fields is None:
                self.fail(f"section 10.3: no worked example [{name}]")
                continue
            values = {k: to_int(fields.get(k, "")) for k in ("g", "base_part", "tip", "fee",
                                                             "cover_limit")}
            for k, v in values.items():
                if v is None:
                    self.fail(f"example {name}: '{k}' is missing or not an integer")
            if None in values.values():
                continue
            self.same(f"example {name}: g", values["g"], e[gas_name])
            base, tip, fee = window_fee(want_price, e[gas_name], divisor)
            for k, want in (("base_part", base), ("tip", tip), ("fee", fee),
                            ("cover_limit", fee // e[gas_name])):
                self.same(f"example {name}: {k}", values[k], want)
            fees[gas_name] = fee
        old = window_fee(want_price, e["V1_G_PRIV"], divisor)[2]
        m = self.find(r"The ordinary fee rises by " + N + r" wei over version 1's " + N
                      + r" \(about ([\d.]+) percent\)", lines, "section 10.3 fee comparison")
        if m and "G_PRIV" in fees:
            rise = fees["G_PRIV"] - old
            self.same("section 10.3: version 1 fee", num(m.group(2)), old)
            self.same("section 10.3: fee rise", num(m.group(1)), rise)
            self.same("section 10.3: fee rise percent", m.group(3), f"{100 * rise / old:.1f}")
        m = self.find(r"`G_ACTION \* " + N + r" = " + N + r"` wei, about ([\d.]+) GHOST", lines,
                      "section 10.3 lowest debit")
        if m:
            self.same("section 10.3: lowest debit base fee", num(m.group(1)), b_ref)
            debit = e["G_ACTION"] * b_ref
            self.same("section 10.3: lowest debit", num(m.group(2)), debit)
            self.same("section 10.3: lowest debit in GHOST", m.group(3),
                      f"{debit / WEI_PER_GHOST:.4f}")

    def check_block_space(self):
        e = self.e
        lines = self.sub("10.4")
        m = self.find(r"The default gas limit is " + N, lines, "section 10.4 gas limit")
        limit = num(m.group(1)) if m else BLOCK_GAS_LIMIT
        self.same("section 10.4: gas limit", limit, BLOCK_GAS_LIMIT)
        m = self.find(r"`G_ACTION` is ([\d.]+) million; it plus `G_PRIV` is ([\d.]+) million and "
                      r"two actions are ([\d.]+) million", lines, "section 10.4 figures")
        if m:
            for what, got, value in (("G_ACTION", m.group(1), e["G_ACTION"]),
                                     ("G_ACTION + G_PRIV", m.group(2),
                                      e["G_ACTION"] + e["G_PRIV"]),
                                     ("two actions", m.group(3), 2 * e["G_ACTION"])):
                self.same(f"section 10.4: {what} in millions", got, f"{value / 10**6:.1f}")
        for name in ("G_PRIV", "G_POLICY", "G_ACTION"):
            if 2 * e[name] <= limit:
                self.fail(f"section 10.4: {name} is not over half the gas limit, so a block "
                          f"can hold two private transactions")

    def check_data(self):
        e = self.e
        lines = self.sub("10.5")
        m = self.find(r"`G_DATA = (\d+) \* " + N + r" \+ " + N + r" \+ " + N + r" = " + N,
                      lines, "section 10.5 G_DATA")
        if m:
            byte_gas, env, base, verify, gas = (num(x) for x in m.groups())
            self.same("section 10.5: G_DATA terms", (byte_gas, env, base, verify),
                      (BYTE_GAS, e["DATA_ENVELOPE_BYTES"], BASE_TX_GAS, V1_VERIFY_GAS))
            self.same("section 10.5: G_DATA", gas, e["G_DATA"])
        m = self.find(r"payload stays " + N + r" bytes with a (\d+)-byte note slot", lines,
                      "section 10.5 data payload")
        if m:
            self.same("section 10.5: data payload", num(m.group(1)), e["DATA_PAYLOAD"])
            self.same("section 10.5: data note slot", int(m.group(2)), DATA_PAYLOAD_NOTE)
        m = self.find(r"`DATA_NOTE_SLOT = (\d+)`\)\. The slot carries `cf` in its first (\d+) "
                      r"bytes and (\d+) zero bytes", lines, "section 10.5 note slot")
        if m:
            slot, cf, zeros = (int(x) for x in m.groups())
            self.same("section 10.5: DATA_NOTE_SLOT", slot, DATA_PAYLOAD_NOTE)
            self.same("section 10.5: cf and zero bytes", cf + zeros, slot)

    def check_pool(self):
        e = self.e
        lines = self.section(11)
        m = self.find(r"`MaxReveals = (\d+)` and `MaxBytes = (\d+) \* " + N + r" = " + N + "`",
                      lines, "section 11 reveal caps")
        if m:
            count, factor, env, total = (num(x) for x in m.groups())
            self.same("section 11: MaxBytes count", factor, count)
            self.same("section 11: MaxBytes envelope", env,
                      max(e["ORD_ENVELOPE_BYTES"], e["POLICY_ENVELOPE_BYTES"]))
            self.same("section 11: MaxBytes", total, count * env)
        m = self.find(r"`MaxActions = (\d+)` and `MaxActionBytes = (\d+) \* " + N + r" = " + N
                      + "`", lines, "section 11 action caps")
        if m:
            count, factor, env, total = (num(x) for x in m.groups())
            self.same("section 11: MaxActionBytes count", factor, count)
            self.same("section 11: MaxActionBytes envelope", env, e["ACTION_ENVELOPE_BYTES"])
            self.same("section 11: MaxActionBytes", total, count * env)
        m = self.find(r"`PEER_FAIL_LIMIT = (\d+)`", lines, "section 11 PEER_FAIL_LIMIT")
        if m and "PEER_FAIL_LIMIT" in self.params:
            self.same("section 11: PEER_FAIL_LIMIT", int(m.group(1)),
                      self.params["PEER_FAIL_LIMIT"])

    def check_slots(self):
        e = self.e
        lines = self.sub("7.1")
        table = next((t for t in tables_in(lines) if "Word" in t[0]), None)
        if table is None:
            self.fail("section 7.1: no Word/Content/Width table")
        else:
            words = [to_int(r.get("Word", "")) for r in table[1]]
            self.same("section 7.1: slot words", words, list(range(e["SLOT_WORDS"])))
            for row in table[1]:
                parts = [int(x) for x in re.findall(r"\((\d+)\)", row.get("Content", ""))]
                width = to_int(row.get("Width", ""))
                if not parts:
                    parts = [32]
                if width != sum(parts) or width > 32:
                    self.fail(f"section 7.1: word {row.get('Word')} holds {sum(parts)} bytes, "
                              f"its width says {width}")
        m = self.find(r"`SLOT_OPEN_GAS = (\d+) \* " + N + r" = " + N + "`", lines,
                      "section 7.1 SLOT_OPEN_GAS")
        if m:
            words, price, gas = (num(x) for x in m.groups())
            self.same("section 7.1: SLOT_OPEN_GAS words", words, e["SLOT_WORDS"])
            self.same("section 7.1: new storage word price", price, NEW_STORAGE_WORD_GAS)
            self.same("section 7.1: SLOT_OPEN_GAS", gas, e["SLOT_OPEN_GAS"])
        m = self.find(r"plus the bytes of a recommit at (\d+) gas each \(" + N + r"\)",
                      self.sub("7.2"), "section 7.2 recommit bytes")
        if m:
            self.same("section 7.2: recommit byte gas", num(m.group(2)), e["RECOMMIT_BYTE_GAS"])
        m = self.find(r"`note \((\d+)\)`", self.sub("7.2"), "section 7.2 recommit note")
        if m:
            self.same("section 7.2: recommit note", int(m.group(1)), e["NOTE_BYTES"])
        m = self.find(r"gas `ACTION_CALL_GAS = " + N + "`", self.sub("8.4"),
                      "section 8.4 ACTION_CALL_GAS")
        if m:
            self.same("section 8.4: ACTION_CALL_GAS", num(m.group(1)), e["ACTION_CALL_GAS"])
        m = self.find(r"`REGISTRY_GAS = " + N + r"` for the two registry words", self.sub("6.1"),
                      "section 6.1 REGISTRY_GAS")
        if m:
            self.same("section 6.1: REGISTRY_GAS", num(m.group(1)), e["REGISTRY_GAS"])

    def check_guard(self):
        e = self.e
        m = self.find(r"`HOLD_BLOCKS = " + N + r"` and `HOLD_SECONDS = " + N + r"` \((\d+) hours "
                      r"at (\d+) seconds a block\)", self.section(12), "section 12 hold")
        if m:
            blocks, seconds, hours, per = (num(x) for x in m.groups())
            self.same("section 12: hold hours and block time", (hours, per),
                      (HOLD_HOURS, BLOCK_SECONDS))
            self.same("section 12: HOLD_SECONDS", seconds, e["HOLD_SECONDS"])
            self.same("section 12: HOLD_BLOCKS", blocks, e["HOLD_BLOCKS"])
        m = self.find(r"(\d+) hour and " + N + r" block hold", self.section(1), "section 1 hold")
        if m:
            self.same("section 1: hold", (int(m.group(1)), num(m.group(2))),
                      (HOLD_HOURS, e["HOLD_BLOCKS"]))

    # 7. Properties and formulas

    def check_properties(self):
        lines = self.section(14)
        numbers = [int(m.group(1)) for m in map(PROPERTY_RE.match, lines) if m]
        if numbers != list(range(1, PROPERTY_COUNT + 1)):
            self.fail(f"properties are numbered {numbers}, expected RP-1 to RP-{PROPERTY_COUNT}")
        defined = set(numbers)
        for ref in sorted({int(x) for x in RP_REF_RE.findall(self.text)}):
            if ref not in defined:
                self.fail(f"RP-{ref} is cited but not defined")
        body = flat(lines)
        m = re.search(r"\*\*RP-24\. Gas is fixed\.\*\* (.*?) - \*\*RP-25", body)
        if m is None or "`G_DATA`" not in m.group(1):
            self.fail("RP-24 does not fix each type's gas and the data reveal's `G_DATA`")

    def check_formulas(self):
        e = self.e
        lines = fenced(self.section(19))
        want = {
            "NOTE_BYTES": [e["NOTE_BYTES"]], "ORD_PAYLOAD": [e["ORD_PAYLOAD"]],
            "POLICY_PAYLOAD": [e["POLICY_PAYLOAD"]], "ACTION_PAYLOAD": [e["ACTION_PAYLOAD"]],
            "ordinary binding": [e["binding"]["ordinary"]],
            "policy binding": [e["binding"]["policy"]],
            "action binding": [e["binding"]["action"]],
            "permutations": [e["binding_perms"][k] for k in ("ordinary", "policy", "action")],
            "trace width": [BASE_WIDTH], "capsule": [e["CAPSULE_BYTES"]],
            "G_PRIV": [e["G_PRIV"]], "G_POLICY": [e["G_POLICY"]],
            "G_ACTION": [e["G_ACTION"]], "G_DATA": [e["G_DATA"]],
        }
        tagged = {"permutations": [e["binding_with_tag"][k]
                                   for k in ("ordinary", "policy", "action")]}
        seen = set()
        for line in lines:
            if " = " not in line:
                continue
            name, rest = (x.strip() for x in line.split("=", 1))
            if name not in want:
                self.fail(f"section 19: unknown formula '{name}'")
                continue
            seen.add(name)
            pieces = [p.strip() for p in rest.split(";")]
            if len(pieces) != len(want[name]):
                self.fail(f"section 19: {name} states {len(pieces)} values, expected "
                          f"{len(want[name])}")
                continue
            for i, (piece, value) in enumerate(zip(pieces, want[name])):
                parts = [p.strip() for p in piece.split("=")]
                if name == "trace width":
                    parts = [parts[0].replace("+ carried columns", "").strip()]
                for part in parts:
                    got = evaluate(part)
                    if got is None:
                        self.fail(f"section 19: {name}: '{part}' is not arithmetic")
                    elif got != value:
                        self.fail(f"section 19: {name}: '{part}' is {got}, recomputed {value}")
                if name in tagged:
                    m = re.fullmatch(r"floor\(\((.+)\)/(\d+)\)\+1", parts[0].replace(" ", ""))
                    inner = evaluate(m.group(1)) if m else None
                    if m is None or inner != tagged[name][i] or int(m.group(2)) != KECCAK_RATE:
                        self.fail(f"section 19: permutations: '{parts[0]}' is not "
                                  f"floor(binding with its tag / {KECCAK_RATE}) + 1")
        missing = [f for f in FORMULAS if f not in seen]
        if missing:
            self.fail(f"section 19 lacks the formulas {missing}")
        body = flat(self.section(19))
        if "`proof_length_bound(rows, columns)`" not in body:
            self.fail("section 19 does not name `proof_length_bound(rows, columns)`")
        if f"takes `floor(n / {KECCAK_RATE}) + 1` permutations" not in body:
            self.fail(f"section 19 does not state that n bytes take floor(n / {KECCAK_RATE}) + 1 "
                      f"permutations")

    def check_sources(self):
        if self.record is not None:
            slowest = recorded_slowest(self.record)
            if slowest != RECORDED_SLOWEST_MS:
                self.fail(f"the benchmark record's slowest verification is {slowest} ms, "
                          f"recorded here {RECORDED_SLOWEST_MS}")
        if self.stark_source is not None:
            found = stark_constants(self.stark_source)
            want = dict(STARK, MAX_TRACE_WIDTH=self.e["MAX_TRACE_WIDTH"])
            for name, value in want.items():
                if found.get(name) != value:
                    self.fail(f"proofs/src/stark.rs sets {name} to {found.get(name)}, the bound "
                              f"here uses {value}")


def check_text(text, record=None, stark_source=None):
    """All gaps found in the text of the specification (empty when complete)."""
    return Checker(text, record, stark_source).run()


def read_beside(path, relative):
    other = (path.parent / relative).resolve()
    return other.read_text(encoding="utf-8") if other.exists() else None


def main(argv):
    args = argv[1:]
    print_constants = "--constants" in args
    args = [a for a in args if a != "--constants"]
    path = Path(args[0]) if args else DEFAULT_SPEC
    if not path.exists():
        print(f"MISSING: {path}")
        return 1
    errors = check_text(path.read_text(encoding="utf-8"), read_beside(path, BENCHMARK_RECORD),
                        read_beside(path, STARK_SOURCE))
    for e in errors:
        print("GAP: " + e)
    if errors:
        print(f"{len(errors)} gap(s) in {path}")
        return 1
    if print_constants:
        print(json.dumps(constants(), indent=2, sort_keys=True))
    else:
        print(f"Private reveal policies complete: {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
