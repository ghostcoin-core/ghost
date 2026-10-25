"""Block bytes of 3,500 public transactions against the 10 MiB message cap.

Two encodings of the signing part of a public transaction, beside one block's private
non-proof parts and the private aggregate proofs:

- raw: every transaction carries its ML-DSA-44 scheme ID, public key and signature,
  2 + 1,312 + 2,420 = 3,734 bytes (spec 09, section 8);
- proof: the signatures leave the chain and an aggregate verification proof stands in
  for them. Each transaction keeps only the bytes that bind it to the proof: the account,
  the identity of its signing key and the transaction hash. The proof binds each account,
  signing key and transaction (designs.md, public transactions, requirement 2).

A pure model: every figure is arithmetic on INPUTS. Bodies (the transfer, commit or call
itself), headers and RLP framing are not counted; the result reports the bytes left for
them. The size of an aggregate verification proof and the seconds to prove one are not in
the repository: the proof size below is an input (the proof field of spec 07), and the
proving time is not yet established.

Usage: python3 benchmarks/scale/public_encoding.py
"""

import math
import sys
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import budget  # noqa: E402

INPUTS = {
    # The target, about 3,500 of each per block (workload.md).
    "public_per_block": budget.INPUTS["public_per_block"],
    "private_per_block": budget.INPUTS["private_per_block"],
    # ML-DSA-44 scheme ID, public key and signature (spec 09, section 8).
    "public_auth_bytes": budget.INPUTS["public_auth_bytes"],
    # A reveal outside its proof field (spec 07, section 3).
    "private_non_proof_bytes": budget.private_non_proof_bytes(),
    # The base client's eth protocol message cap (spec 09, section 8.4).
    "message_cap_bytes": budget.INPUTS["message_cap_bytes"],
    # What each transaction keeps when its signature leaves the chain: a 20-byte address
    # (spec 09, section 4.3), a 32-byte digest of its signing key and a 32-byte
    # transaction hash.
    "account_bytes": 20,
    "key_identity_bytes": 32,
    "transaction_hash_bytes": 32,
    # One aggregate verification proof: no such proof exists; the input is the proof field
    # of a reveal (spec 07, section 2), a stated input and not a measured size.
    "verification_proof_bytes": budget.INPUTS["private_proof_field_bytes"],
    "verifications_per_proof": 3_500,
    # Private bundles in a block, one root proof each, at the same stated size: one per
    # aggregator of the throughput model's three.
    "private_bundles_per_block": 3,
    "private_bundle_proof_bytes": budget.INPUTS["private_proof_field_bytes"],
    # Seconds to prove one block's verification proof: not in the repository.
    "verification_proof_seconds": None,
}


def _get(inputs, key):
    return (INPUTS if inputs is None else inputs)[key]


def private_non_proof_bytes(inputs=None):
    return _get(inputs, "private_per_block") * _get(inputs, "private_non_proof_bytes")


def private_aggregate_bytes(inputs=None):
    return _get(inputs, "private_bundles_per_block") * _get(inputs, "private_bundle_proof_bytes")


def binding_bytes(inputs=None):
    """Bytes one transaction keeps on chain when its signature is replaced by the proof."""
    return _get(inputs, "account_bytes") + _get(inputs, "key_identity_bytes") + _get(inputs, "transaction_hash_bytes")


def verifications_per_block(inputs=None):
    """ML-DSA verifications the proofs of one block must prove: one per public transaction."""
    return _get(inputs, "public_per_block")


def proofs_per_block(inputs=None):
    return math.ceil(verifications_per_block(inputs) / _get(inputs, "verifications_per_proof"))


def raw_public_bytes(inputs=None):
    return _get(inputs, "public_per_block") * _get(inputs, "public_auth_bytes")


def proof_public_bytes(inputs=None):
    """Binding bytes of every transaction plus the verification proofs."""
    return (_get(inputs, "public_per_block") * binding_bytes(inputs)
            + proofs_per_block(inputs) * _get(inputs, "verification_proof_bytes"))


def variant(name, public_bytes, inputs=None):
    cap = _get(inputs, "message_cap_bytes")
    with_private = public_bytes + private_non_proof_bytes(inputs)
    total = with_private + private_aggregate_bytes(inputs)
    headroom = cap - total
    per_tx = _get(inputs, "public_per_block")
    return {
        "variant": name,
        "public_bytes": public_bytes,
        "with_private_non_proof": with_private,
        "with_aggregate_proofs": total,
        "message_cap_bytes": cap,
        "fits": headroom >= 0,
        "headroom_bytes": headroom,
        # What every public transaction may still spend on its body, headers and framing
        # included, for the block to stay under the cap.
        "body_bytes_per_transaction": float(Fraction(headroom, per_tx)) if headroom > 0 else 0.0,
    }


def raw(inputs=None):
    return variant("raw ML-DSA-44", raw_public_bytes(inputs), inputs)


def proof(inputs=None):
    out = variant("signature replaced by a proof", proof_public_bytes(inputs), inputs)
    out["binding_bytes"] = binding_bytes(inputs)
    out["proofs_per_block"] = proofs_per_block(inputs)
    out["verifications_per_block"] = verifications_per_block(inputs)
    out["proving_seconds"] = _get(inputs, "verification_proof_seconds")
    return out


def public_capacity(name="raw", inputs=None):
    """Public transactions a block can carry under the cap, before bodies, beside the private
    non-proof parts and the aggregate proofs."""
    room = _get(inputs, "message_cap_bytes") - private_non_proof_bytes(inputs) - private_aggregate_bytes(inputs)
    if name == "raw":
        return max(room // _get(inputs, "public_auth_bytes"), 0)
    # Each verification proof covers verifications_per_proof transactions.
    per = _get(inputs, "verifications_per_proof")
    group = per * binding_bytes(inputs) + _get(inputs, "verification_proof_bytes")
    groups, rest = divmod(max(room, 0), group)
    extra = max(rest - _get(inputs, "verification_proof_bytes"), 0) // binding_bytes(inputs)
    return groups * per + min(extra, per)


def report(inputs=None):
    lines = [
        "| Variant | Public bytes | With the private non-proof parts | With the aggregate proofs too | Fits under the cap | Headroom | Body bytes a transaction may add |",
        "|---|---|---|---|---|---|---|",
    ]
    for v in (raw(inputs), proof(inputs)):
        lines.append(
            f"| {v['variant']} | {v['public_bytes']:,} (modeled) | {v['with_private_non_proof']:,} (modeled) "
            f"| {v['with_aggregate_proofs']:,} (modeled) | {'yes' if v['fits'] else 'no'} (modeled) "
            f"| {v['headroom_bytes']:,} (modeled) | {v['body_bytes_per_transaction']:,.2f} (modeled) |"
        )
    p = proof(inputs)
    lines += [
        "",
        f"Binding bytes a transaction: {p['binding_bytes']:,} (modeled)",
        f"Verification proofs a block: {p['proofs_per_block']:,} (modeled)",
        f"ML-DSA-44 verifications to prove a block: {p['verifications_per_block']:,} (modeled)",
        f"Public transactions a block fits, raw: {public_capacity('raw', inputs):,} (modeled)",
        f"Public transactions a block fits, proof: {public_capacity('proof', inputs):,} (modeled)",
        "Seconds to prove a block's verification proof: "
        + ("not yet established" if p["proving_seconds"] is None else f"{p['proving_seconds']:,} (input)"),
    ]
    return "\n".join(lines)


def main(argv=None):
    print("Modeled from the inputs at the top of benchmarks/scale/public_encoding.py")
    print(report())
    return 0


if __name__ == "__main__":
    sys.exit(main())
