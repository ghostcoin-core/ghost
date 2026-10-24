"""Error-exponent arithmetic for the security argument of the recursive bundle.

A pure model, used by docs/scale/security.md. A term is given in bits, the
negative base-2 logarithm of an error probability. Terms of one proof, and the
proofs of one bundle, are added as probabilities (a union bound), so the bound
of several terms is -log2 of the sum of 2^-bits. Every figure this module
returns is modeled: it is arithmetic on its inputs, never a run of the pinned
library's estimator.

Usage: python3 benchmarks/scale/security_budget.py
"""

import math

# The requirement: at least 128 bits proven classically and NIST Category 1
# proven against a quantum attacker (spec 09, section 3: Grover's search over
# 2^128 keys, about 2^64 iterations), grinding counted at half, over the whole
# bundled proof.
TARGET_CLASSICAL_BITS = 128
TARGET_QUANTUM_BITS = 64

# Decision 0003 at the configuration that ships: the pinned estimator's
# output, quoted here, not recomputed.
SHIPPED_CONFIGURATION = "keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk"
SHIPPED = {
    "log_blowup": 3,
    "queries": 43,
    "query_grinding_bits": 16,
    "batch_grinding_bits": 16,
    "extension_degree": 5,
    "challenge_field_bits": 154,
    "digest_bits": 256,
}
DECISION_0003 = {
    "queries_alone_conjectured_bits": 129,
    "conjectured_classical_bits": 128,
    "conjectured_quantum_bits": 64,
    "proven_classical_bits": 80,
    "proven_quantum_bits": 40,
    # The earlier configuration, blowup 2^2 with 57 queries.
    "earlier_proven_classical_bits": 72,
}

# Reveals folded into one bundle at the scale target (workload.md).
BUNDLE_LEAVES = 3_500


def combine(bits):
    """One bound from several error terms: -log2(sum of 2^-b) over the terms.

    An infinite term (no error) adds nothing; no terms at all give infinity.
    The sum is taken relative to the smallest term so that large exponents
    do not underflow.
    """
    finite = [b for b in bits if b != math.inf]
    if not finite:
        return math.inf
    least = min(finite)
    return least - math.log2(math.fsum(2.0 ** (least - b) for b in finite))


def grinding_at_half(grinding_bits):
    """The bits a grinding site is counted at: half its proof-of-work bits.

    Grover's search finds a g-bit grinding nonce in about 2^(g/2)
    evaluations, so g bits of proof of work are worth g/2 against a quantum
    attacker; the requirement counts them at that half in both figures.
    """
    return grinding_bits / 2


def classical_bits(base_bits, grinding_bits=0):
    """A classical term: its bits without grinding plus its grinding at half."""
    return base_bits + grinding_at_half(grinding_bits)


def quantum_bits(base_bits, grinding_bits=0):
    """The classical-to-quantum conversion the document uses.

    Chiesa, Manohar and Spooner, "Succinct Arguments in the Quantum Random
    Oracle Model" (ePrint 2019/834, TCC 2019): the BCS transformation of an
    IOP whose round-by-round soundness error is e is sound against an
    attacker making t quantum queries with error about t^2 * e + t^3 / 2^L,
    L the hash output in bits (spec 09, section 4.1). The t^2 * e part halves
    the round-by-round bits: base_bits becomes base_bits / 2. Grinding is
    counted at half, as in grinding_at_half.

    When a figure's split into base and grinding bits is not known, pass the
    whole figure as base_bits: that halves the grinding too, which can only
    understate the quantum figure.
    """
    return base_bits / 2 + grinding_at_half(grinding_bits)


def collision_bits(digest_bits):
    """Classical collision resistance of a digest: half its bits (birthday)."""
    return digest_bits / 2


def quantum_hash_bits(digest_bits):
    """The quantum hash term of ePrint 2019/834, t^3 / 2^L: a third of L."""
    return digest_bits / 3


def conjectured_query_bits(log_blowup, queries):
    """FRI queries under the conjectured estimate: log2(1/rate) per query."""
    return queries * log_blowup


def johnson_query_bits(log_blowup, queries):
    """FRI queries in the proven (Johnson bound) regime: half that per query.

    About -log2(sqrt(rate)) per query, with the Johnson slack taken to zero,
    so it can only overstate the proven query term.
    """
    return queries * log_blowup / 2


def whole_bundle_bits(per_layer_terms, layers, once_terms=()):
    """The whole-bundle bound from one layer's terms and a layer count.

    Every layer contributes the same per_layer_terms; once_terms (the hash
    collision terms, one event for the whole bundle) are counted once.
    """
    return combine(list(per_layer_terms) * layers + list(once_terms))


def tree_layers(leaves):
    """Proofs made at each merge layer of a two-to-one tree over the leaves.

    A layer merges proofs in pairs; an odd proof is carried up unmerged, as
    benchmarks/scale/budget.py schedules them.
    """
    layers = []
    while leaves > 1:
        merges = leaves // 2
        layers.append(merges)
        leaves -= merges
    return layers


def total_proofs(leaves):
    """Leaf proofs plus every merge proof: 2n - 1 for n leaves."""
    return leaves + sum(tree_layers(leaves))


def tree_bundle_bits(leaf_bits, layer_bits, leaves, once_terms=()):
    """The whole-bundle bound of a tree: every proof's term, added up.

    leaf_bits is one leaf proof's term; layer_bits is one merge proof's term,
    a single figure or a list with one entry per layer (the first entry is
    the conversion layer when leaves and layers use different hashes).
    """
    sizes = tree_layers(leaves)
    if not isinstance(layer_bits, (list, tuple)):
        layer_bits = [layer_bits] * len(sizes)
    if len(layer_bits) != len(sizes):
        raise ValueError(f"{len(sizes)} layers, {len(layer_bits)} layer terms")
    terms = [leaf_bits - math.log2(leaves)] if leaves else []
    terms += [bits - math.log2(count) for bits, count in zip(layer_bits, sizes)]
    return combine(terms + list(once_terms))


def per_proof_bits_needed(target_bits, proofs):
    """The bits each of that many equal proofs needs for the sum to reach the target."""
    return target_bits + math.log2(proofs)


def johnson_queries_needed(log_blowup, proofs, grinding_bits):
    """Fewest queries whose proven query term, in every one of that many
    proofs, reaches the classical and the quantum target over the sum."""
    queries = 1
    while True:
        base = johnson_query_bits(log_blowup, queries)
        if (
            classical_bits(base, grinding_bits) >= per_proof_bits_needed(TARGET_CLASSICAL_BITS, proofs)
            and quantum_bits(base, grinding_bits) >= per_proof_bits_needed(TARGET_QUANTUM_BITS, proofs)
        ):
            return queries
        queries += 1


def shortfall(classical, quantum):
    """How far a bound is from 128 classical and Category 1 quantum."""
    short_classical = max(0.0, TARGET_CLASSICAL_BITS - classical)
    short_quantum = max(0.0, TARGET_QUANTUM_BITS - quantum)
    return {
        "classical": short_classical,
        "quantum": short_quantum,
        "meets": short_classical == 0 and short_quantum == 0,
    }


# The three architectures of docs/scale/security.md, section "Parameters".
# Leaf and layer parameters are the same except for the hash; the digest of
# each hash enters once. Poseidon2 digests are 9 BabyBear elements (279 bits),
# as in the benchmark harness (benchmarks/prover/src/zk.rs).
CANDIDATE_LAYER = {"log_blowup": 3, "queries": 92, "grinding_bits": 16, "extension_degree": 5}
ARCHITECTURES = {
    "keccak-keccak": {"leaf_hash": "keccak", "layer_hash": "keccak", "digests": [256]},
    "keccak-poseidon2": {"leaf_hash": "keccak", "layer_hash": "poseidon2", "digests": [256, 279]},
    "poseidon2-poseidon2": {"leaf_hash": "poseidon2", "layer_hash": "poseidon2", "digests": [279]},
}


def query_phase_bits(params):
    """One proof's proven query-phase term, classical and quantum."""
    base = johnson_query_bits(params["log_blowup"], params["queries"])
    return classical_bits(base, params["grinding_bits"]), quantum_bits(base, params["grinding_bits"])


def architecture_bounds(name, leaves=BUNDLE_LEAVES, leaf=None, layer=None):
    """Whole-bundle query-phase and hash bound of one architecture.

    Only the query phase and the hash terms are modeled; the extension-field
    terms of the proven estimate are not, so this is an upper bound on what
    the proven estimate could give.
    """
    arch = ARCHITECTURES[name]
    leaf = CANDIDATE_LAYER if leaf is None else leaf
    layer = CANDIDATE_LAYER if layer is None else layer
    leaf_c, leaf_q = query_phase_bits(leaf)
    layer_c, layer_q = query_phase_bits(layer)
    classical = tree_bundle_bits(leaf_c, layer_c, leaves, [collision_bits(d) for d in arch["digests"]])
    quantum = tree_bundle_bits(leaf_q, layer_q, leaves, [quantum_hash_bits(d) for d in arch["digests"]])
    return {"classical": classical, "quantum": quantum, "shortfall": shortfall(classical, quantum)}


def report():
    rows = [
        ("Proofs in a bundle of 3,500 leaves", total_proofs(BUNDLE_LEAVES)),
        ("Merge layers", len(tree_layers(BUNDLE_LEAVES))),
        ("Bits each proof needs, classical", per_proof_bits_needed(TARGET_CLASSICAL_BITS, total_proofs(BUNDLE_LEAVES))),
        ("Bits each proof needs, quantum", per_proof_bits_needed(TARGET_QUANTUM_BITS, total_proofs(BUNDLE_LEAVES))),
        ("Queries needed at blowup 2^3, 16 grinding bits", johnson_queries_needed(3, total_proofs(BUNDLE_LEAVES), 16)),
        ("Shipped proven query term, classical, grinding at half", classical_bits(johnson_query_bits(3, 43), 16)),
        ("Shipped proven query term, quantum", quantum_bits(johnson_query_bits(3, 43), 16)),
    ]
    for name in ARCHITECTURES:
        bounds = architecture_bounds(name)
        rows.append((f"{name}: whole bundle, classical", bounds["classical"]))
        rows.append((f"{name}: whole bundle, quantum", bounds["quantum"]))
        rows.append((f"{name}: shortfall, classical", bounds["shortfall"]["classical"]))
        rows.append((f"{name}: shortfall, quantum", bounds["shortfall"]["quantum"]))
    width = max(len(name) for name, _ in rows)
    return "\n".join(f"{name.ljust(width)}  {value:,.4f}" for name, value in rows)


if __name__ == "__main__":
    print("Modeled from benchmarks/scale/security_budget.py (query phase and hash terms only)")
    print(report())
