"""Fleet cost of the recursion proxy records, judged against the aggregator ceilings.

Reads docs/scale/recursion-proxy.jsonl, the records benchmarks/reveal/tests/recursion_proxy.rs
writes, checks every record's fields and label, and computes for each of the three
architectures the modeled machine-seconds of one block's conversions and merges, the least
wall time on the aggregator machines, the memory of the largest trace, and a verdict against
the ceilings of docs/scale/workload.md: met, missed or not yet established. It never changes
a record.

A proxy record is a lower bound on a real recursive layer: it proves only the Keccak-f[1600]
permutations a verifier performs. So a proxy can show a ceiling missed, never met; only a
record labelled "measured" (a real recursive verifier, which no piece has run yet) can show
it met. Seconds from a prover of fewer threads than the machine has cores are divided by the
cores as if the work spread perfectly, which only lowers them.

Usage: python3 benchmarks/scale/recursion_costs.py [RECORDS.jsonl]
"""

import json
import math
import sys
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import budget  # noqa: E402

RECORDS = HERE.parent.parent / "docs" / "scale" / "recursion-proxy.jsonl"

INPUTS = {
    # The target and the aggregator ceilings of workload.md.
    "reveals_per_block": budget.INPUTS["private_per_block"],
    "merge_seconds_ceiling": budget.INPUTS["merge_seconds"],
    "machines": budget.INPUTS["machines"],
    "cores_per_machine": 32,
    "memory_per_machine_gib": 128,
    "block_seconds": budget.INPUTS["block_seconds"],
    # The shipped leaf parameters the proxy runs at (proofs/src/stark.rs).
    "log_blowup": 3,
    "random_codewords": 5,
    "field_bytes": 4,
    # Rows of p3-keccak-air a permutation.
    "keccak_air_rows": 24,
}

ARCHITECTURES = {
    "keccak-leaves-keccak-aggregation": "(a) Keccak leaves, Keccak aggregation",
    "keccak-leaves-poseidon2-aggregation": "(b) Keccak leaves, Poseidon2 aggregation",
    "poseidon2-leaves-poseidon2-aggregation": "(c) Poseidon2 leaves, Poseidon2 aggregation",
}
# The hash construction each architecture's records must name (designs.md, rule 3).
HASHES = {
    "keccak-leaves-keccak-aggregation": ("keccak-256",),
    "keccak-leaves-poseidon2-aggregation": ("keccak-256", "poseidon2-babybear-w24"),
    "poseidon2-leaves-poseidon2-aggregation": ("poseidon2-babybear-w24",),
}
# Primitives whose records do not apply to Ghost's: NIST SHA3-256, and Poseidon1 over KoalaBear.
OTHER_PRIMITIVES = ("sha3", "koalabear", "poseidon1")
LAYERS = ("conversion", "merge")
MEASURED_LABELS = ("measured", "measured (proxy)")
LABELS = MEASURED_LABELS + ("modeled",)
MIN_REPEATS = 3

REQUIRED = (
    "architecture", "layer", "permutation_count", "trace_rows", "trace_width", "proof_bytes",
    "median_seconds", "slowest_seconds", "repeats", "cpu_model", "threads", "prover_threads",
    "parameters", "label", "quick",
)

MET, MISSED, NOT_ESTABLISHED = "met", "missed", "not yet established"


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _seconds(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def problems(record, inputs=None):
    """Every reason the record is not acceptable, as text; empty when it is."""
    inputs = INPUTS if inputs is None else inputs
    if not isinstance(record, dict):
        return ["a record must be a JSON object"]
    out = [f"missing field {name}" for name in REQUIRED if name not in record]
    if out:
        return out
    arch = record["architecture"]
    if arch not in ARCHITECTURES:
        out.append(f"unknown architecture {arch!r}")
    if record["layer"] not in LAYERS:
        out.append(f"layer must be one of {', '.join(LAYERS)}")
    label = record["label"]
    if label not in LABELS:
        out.append(f"label must be one of {', '.join(LABELS)}")
    for name in ("permutation_count", "trace_rows", "trace_width", "threads", "prover_threads"):
        if not _int(record[name]) or record[name] <= 0:
            out.append(f"{name} must be a positive integer")
    if _int(record["trace_rows"]) and record["trace_rows"] > 0 and record["trace_rows"] & (record["trace_rows"] - 1):
        out.append("trace_rows must be a power of two")
    if not isinstance(record["quick"], bool):
        out.append("quick must be true or false")
    for name in ("median_seconds", "slowest_seconds"):
        if not _seconds(record[name]):
            out.append(f"{name} must be a positive number of seconds")
    if _seconds(record["median_seconds"]) and _seconds(record["slowest_seconds"]):
        if record["median_seconds"] > record["slowest_seconds"]:
            out.append("median_seconds is above slowest_seconds")
    if not _int(record["repeats"]) or record["repeats"] < 0:
        out.append("repeats must be a whole number")
    parameters = record["parameters"]
    if not isinstance(parameters, str) or not parameters.strip():
        out.append("parameters must name the configuration")
    else:
        lowered = parameters.lower()
        for name in HASHES.get(arch, ()):
            if name not in lowered:
                out.append(f"parameters must name the hash {name}")
        for name in OTHER_PRIMITIVES:
            if name in lowered:
                out.append(f"parameters name {name}, a primitive Ghost does not use")
        rows, count = record["trace_rows"], record["permutation_count"]
        if "p3-keccak-air" in lowered and _int(rows) and _int(count) and count > 0:
            want = 1 << (count * inputs["keccak_air_rows"] - 1).bit_length()
            if rows != want:
                out.append(f"trace_rows must be {want} for {count} permutations of p3-keccak-air")
    cpu = record["cpu_model"]
    if label in MEASURED_LABELS:
        if not isinstance(cpu, str) or not cpu.strip():
            out.append("a measured record must name the CPU model")
        if _int(record["repeats"]) and record["repeats"] < MIN_REPEATS:
            out.append(f"a measured record needs at least {MIN_REPEATS} repeats")
        if not _int(record["proof_bytes"]) or record["proof_bytes"] <= 0:
            out.append("a measured record must give its proof bytes")
    if label == "modeled":
        if record["repeats"] != 0:
            out.append("a modeled record ran nothing: repeats must be 0")
        if record["proof_bytes"] is not None and (not _int(record["proof_bytes"]) or record["proof_bytes"] <= 0):
            out.append("proof_bytes must be null or a positive integer")
        if not isinstance(record.get("model"), str) or not record["model"].strip():
            out.append("a modeled record must state its model")
    return out


def load(path=RECORDS):
    """The records of a JSON-lines file; ValueError naming every bad line."""
    records, bad = [], []
    with open(path, encoding="utf-8") as f:
        for number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                bad.append(f"line {number}: not JSON ({e})")
                continue
            for problem in problems(record):
                bad.append(f"line {number}: {problem}")
            records.append(record)
    if bad:
        raise ValueError("; ".join(bad))
    return records


def _exact(value):
    return Fraction(str(value))


def _number(value):
    return int(value) if value.denominator == 1 else float(value)


def per_machine_seconds(record, inputs=None):
    """Seconds of one proof on one aggregator machine, its cores used perfectly: a lower bound."""
    inputs = INPUTS if inputs is None else inputs
    threads = min(record["prover_threads"], inputs["cores_per_machine"])
    return _number(_exact(record["median_seconds"]) * threads / inputs["cores_per_machine"])


def lde_bytes(rows, width, inputs=None):
    """Bytes of the trace's low-degree extension alone: zero-knowledge doubles the rows, the
    blowup multiplies them, and hiding adds the random codewords."""
    inputs = INPUTS if inputs is None else inputs
    return 2 * rows * 2 ** inputs["log_blowup"] * (width + inputs["random_codewords"]) * inputs["field_bytes"]


def gib(nbytes):
    return _number(Fraction(nbytes, 2 ** 30))


def choose(records, architecture, layer):
    """The record that stands for a layer at its counted size: a real measurement first, then a
    full-size proxy, then a model. Quick-path proxies are the model's anchors, not the layer."""
    rank = {"measured": 0, "measured (proxy)": 1, "modeled": 2}
    candidates = [
        r for r in records
        if r["architecture"] == architecture and r["layer"] == layer and not r["quick"]
    ]
    return min(candidates, key=lambda r: rank[r["label"]], default=None)


def layer_figures(record, proofs, inputs=None):
    """Machine-seconds and the least wall time for `proofs` proofs of the record's layer."""
    inputs = INPUTS if inputs is None else inputs
    seconds = per_machine_seconds(record, inputs)
    nbytes = lde_bytes(record["trace_rows"], record["trace_width"], inputs)
    return {
        "label": record["label"],
        "permutations": record["permutation_count"],
        "trace_rows": record["trace_rows"],
        "proofs": proofs,
        "single_proof_seconds": seconds,
        "machine_seconds": budget.machine_seconds(proofs, seconds),
        "min_wall_seconds": budget.min_wall_seconds(proofs, seconds, inputs["machines"]),
        "trace_lde_bytes": nbytes,
        "trace_lde_gib": gib(nbytes),
    }


def verdict(merge, conversion, inputs=None):
    """Met, missed or not yet established, from the merge and conversion figures."""
    inputs = INPUTS if inputs is None else inputs
    if merge is None:
        return NOT_ESTABLISHED
    ceiling = _exact(inputs["merge_seconds_ceiling"])
    memory = inputs["memory_per_machine_gib"] * 2 ** 30
    layers = [f for f in (merge, conversion) if f is not None]
    over = (
        _exact(merge["single_proof_seconds"]) > ceiling
        or any(f["trace_lde_bytes"] > memory for f in layers)
        or any(_exact(f["min_wall_seconds"]) > inputs["block_seconds"] for f in layers)
    )
    if over:
        return MISSED
    if merge["label"] == "measured" and (conversion is None or conversion["label"] == "measured"):
        return MET
    # A proxy under every ceiling is a lower bound under it, which shows nothing.
    return NOT_ESTABLISHED


def fleet(records, inputs=None):
    """For every architecture: its conversion and merge figures and the verdict."""
    inputs = INPUTS if inputs is None else inputs
    merges = budget.merges_per_block({"private_per_block": inputs["reveals_per_block"]})
    out = {}
    for arch in ARCHITECTURES:
        conversion_record = choose(records, arch, "conversion")
        merge_record = choose(records, arch, "merge")
        conversion = None if conversion_record is None else layer_figures(conversion_record, inputs["reveals_per_block"], inputs)
        merge = None if merge_record is None else layer_figures(merge_record, merges, inputs)
        out[arch] = {"conversion": conversion, "merge": merge, "verdict": verdict(merge, conversion, inputs)}
    return out


def render(result):
    lines = [
        "| Architecture | Layer | Record | Permutations | Trace rows | Seconds a proof, one machine | Machine-seconds a block | Least wall time on the machines | Trace LDE |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for arch, figures in result.items():
        for layer in LAYERS:
            f = figures[layer]
            if f is None:
                lines.append(f"| {ARCHITECTURES[arch]} | {layer} | none: not yet established | | | | | | |")
                continue
            lines.append(
                f"| {ARCHITECTURES[arch]} | {layer} | {f['label']} | {f['permutations']:,} | {f['trace_rows']:,} "
                f"| {f['single_proof_seconds']:,.2f} s (modeled) | {f['machine_seconds']:,.2f} for {f['proofs']:,} (modeled) "
                f"| {f['min_wall_seconds']:,.2f} s (modeled) | {f['trace_lde_gib']:,.3f} GiB (modeled) |"
            )
    lines.append("")
    for arch, figures in result.items():
        lines.append(f"{ARCHITECTURES[arch]}: {figures['verdict']}")
    return "\n".join(lines)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else RECORDS
    try:
        records = load(path)
    except (OSError, ValueError) as e:
        print(f"{path}: {e}", file=sys.stderr)
        return 1
    print(f"Modeled from {path} and the inputs at the top of benchmarks/scale/recursion_costs.py")
    print(render(fleet(records)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
