"""Byte, gas, storage, restore and merge budgets at the scale target.

A pure model: every figure it returns is arithmetic on INPUTS, which quote the
repository's own numbers (the specs named beside each one). Pass a changed copy
of INPUTS to any function to see the effect of a different input.

Usage: python3 benchmarks/scale/budget.py
"""

import math
from fractions import Fraction

INPUTS = {
    # The target: 10 million private reveals and 10 million public
    # transactions a day, about 3,500 of each per 30 s block.
    "private_per_day": 10_000_000,
    "public_per_day": 10_000_000,
    "private_per_block": 3_500,
    "public_per_block": 3_500,
    "block_seconds": 30,
    "seconds_per_day": 86_400,
    "days_per_year": 365,
    # Private reveal today (spec 07, section 2 and 3).
    "private_envelope_bytes": 1_311_067,
    "private_proof_field_bytes": 1_310_720,
    "private_gas": 21_090_372,
    "block_gas_limit": 30_000_000,
    # Public transaction: ML-DSA-44 scheme, key and signature (spec 09, section 8).
    "public_auth_bytes": 3_734,
    # The base client's cap on one eth protocol message (spec 09, section 8.4).
    "message_cap_bytes": 10 * 1024 * 1024,
    # Wallet restore: a 32-byte leaf and its 156-byte note (spec 05, section 8).
    "leaf_and_note_bytes": 188,
    "new_leaves_per_day": 10_000_000,
    # One spent marker (spec 05, "Who keeps what").
    "marker_bytes": 32,
    "tree_leaves": 2 ** 32,
    # Recursive merging of one block's private proofs.
    "merge_seconds": "0.3",
    "machines": 40,
}


def _get(inputs, key):
    return (INPUTS if inputs is None else inputs)[key]


def _exact(value):
    """A number as an exact fraction; decimal strings and floats keep their written value."""
    return Fraction(str(value))


def _number(value):
    """An exact fraction as an int when whole, else as a float."""
    return int(value) if value.denominator == 1 else float(value)


def blocks_per_day(inputs=None):
    return _get(inputs, "seconds_per_day") // _get(inputs, "block_seconds")


# Private reveals.

def private_non_proof_bytes(inputs=None):
    """Bytes of one reveal outside its proof field: 347 today."""
    return _get(inputs, "private_envelope_bytes") - _get(inputs, "private_proof_field_bytes")


def private_proof_bytes_per_block(inputs=None):
    return _get(inputs, "private_per_block") * _get(inputs, "private_proof_field_bytes")


def private_proof_bytes_per_day(inputs=None):
    return _get(inputs, "private_per_day") * _get(inputs, "private_proof_field_bytes")


def private_non_proof_bytes_per_block(inputs=None):
    return _get(inputs, "private_per_block") * private_non_proof_bytes(inputs)


def private_envelope_bytes_per_day(inputs=None):
    return _get(inputs, "private_per_day") * _get(inputs, "private_envelope_bytes")


def gas_per_block_today(inputs=None):
    """Gas of a block of private reveals under today's rule, one full charge each."""
    return _get(inputs, "private_per_block") * _get(inputs, "private_gas")


def gas_limit_multiple(inputs=None):
    """How many block gas limits that is."""
    return _number(Fraction(gas_per_block_today(inputs), _get(inputs, "block_gas_limit")))


def private_per_block_today(inputs=None):
    """Private reveals that fit under the block gas limit today."""
    return _get(inputs, "block_gas_limit") // _get(inputs, "private_gas")


# Public transactions.

def public_signature_bytes_per_block(inputs=None):
    return _get(inputs, "public_per_block") * _get(inputs, "public_auth_bytes")


def public_and_private_non_proof_bytes_per_block(inputs=None):
    return public_signature_bytes_per_block(inputs) + private_non_proof_bytes_per_block(inputs)


def bytes_over_message_cap(inputs=None):
    """Bytes above the message cap (negative when under it)."""
    return public_and_private_non_proof_bytes_per_block(inputs) - _get(inputs, "message_cap_bytes")


def fits_message_cap(inputs=None):
    return bytes_over_message_cap(inputs) <= 0


# Wallet restore and state.

def restore_bytes_per_day(inputs=None):
    return _get(inputs, "new_leaves_per_day") * _get(inputs, "leaf_and_note_bytes")


def restore_bytes_per_year(inputs=None):
    return restore_bytes_per_day(inputs) * _get(inputs, "days_per_year")


def marker_bytes_per_year(inputs=None):
    return _get(inputs, "private_per_day") * _get(inputs, "marker_bytes") * _get(inputs, "days_per_year")


def days_to_fill_tree(inputs=None):
    return _number(Fraction(_get(inputs, "tree_leaves"), _get(inputs, "new_leaves_per_day")))


# Recursive merging.

def merges_per_block(inputs=None):
    """Two-to-one merges that fold one block's private proofs into one: n - 1."""
    return max(_get(inputs, "private_per_block") - 1, 0)


def machine_seconds(merges, merge_seconds):
    """Total machine time of a batch of merges."""
    return _number(merges * _exact(merge_seconds))


def min_wall_seconds(merges, merge_seconds, machines):
    """The work bound: no schedule on that many machines finishes sooner."""
    return _number(merges * _exact(merge_seconds) / machines)


def merge_tree_levels(proofs):
    """Levels of a balanced two-to-one merge tree over that many proofs."""
    return math.ceil(math.log2(proofs)) if proofs > 1 else 0


def level_schedule_wall_seconds(proofs, merge_seconds, machines):
    """Wall time when each level of the tree is merged in rounds of `machines`.

    Every proof arrives at once and a level starts when the one below ends.
    """
    rounds = 0
    while proofs > 1:
        merges = proofs // 2
        rounds += -(-merges // machines)
        proofs -= merges
    return _number(rounds * _exact(merge_seconds))


def block_merge_budget(inputs=None):
    merges = merges_per_block(inputs)
    seconds = _get(inputs, "merge_seconds")
    machines = _get(inputs, "machines")
    proofs = _get(inputs, "private_per_block")
    return {
        "merges": merges,
        "machine_seconds": machine_seconds(merges, seconds),
        "min_wall_seconds": min_wall_seconds(merges, seconds, machines),
        "tree_levels": merge_tree_levels(proofs),
        "critical_path_seconds": _number(merge_tree_levels(proofs) * _exact(seconds)),
        "level_schedule_wall_seconds": level_schedule_wall_seconds(proofs, seconds, machines),
    }


def report(inputs=None):
    rows = [
        ("Blocks a day", blocks_per_day(inputs)),
        ("Private non-proof bytes per reveal", private_non_proof_bytes(inputs)),
        ("Private proof bytes per block", private_proof_bytes_per_block(inputs)),
        ("Private proof bytes per day", private_proof_bytes_per_day(inputs)),
        ("Private non-proof bytes per block", private_non_proof_bytes_per_block(inputs)),
        ("Private envelope bytes per day", private_envelope_bytes_per_day(inputs)),
        ("Gas per block under today's rule", gas_per_block_today(inputs)),
        ("Multiple of the block gas limit", gas_limit_multiple(inputs)),
        ("Private reveals per block under the gas limit today", private_per_block_today(inputs)),
        ("Public signature bytes per block", public_signature_bytes_per_block(inputs)),
        ("Public plus private non-proof bytes per block", public_and_private_non_proof_bytes_per_block(inputs)),
        ("Message cap bytes", _get(inputs, "message_cap_bytes")),
        ("Bytes over the message cap", bytes_over_message_cap(inputs)),
        ("Restore bytes per day", restore_bytes_per_day(inputs)),
        ("Restore bytes per year", restore_bytes_per_year(inputs)),
        ("Marker bytes per year", marker_bytes_per_year(inputs)),
        ("Days to fill one tree", days_to_fill_tree(inputs)),
    ]
    rows += [(f"Merge {key.replace('_', ' ')}", value) for key, value in block_merge_budget(inputs).items()]
    width = max(len(name) for name, _ in rows)
    return "\n".join(f"{name.ljust(width)}  {value:,}" for name, value in rows)


if __name__ == "__main__":
    print("Modeled from the inputs at the top of benchmarks/scale/budget.py")
    print(report())
