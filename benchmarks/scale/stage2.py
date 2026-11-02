"""The modeled figures of docs/scale/stage2-design.md.

The second stage of the scale work picks one design for each limit the first
stage's verdict (docs/scale/stage1-verdict.md) named: wallet restore volume, the
aggregation cost, the whole-bundle proven security bound and the size of public
signatures in a block. This module computes every figure that page quotes, from
the inputs below, against the ceilings of docs/scale/workload.md, which do not
change here.

A pure model, like budget.py: every figure it returns is arithmetic on INPUTS
and on the measured (proxy) records of docs/scale/recursion-proxy.jsonl. Nothing
here is a run of a prover, a PIR server or a phone. Each input says where it
comes from and how it is labelled on the page: a quoted measurement, a figure
modeled elsewhere in the repository, or an assumption that is not yet
established. Pass a changed copy of INPUTS to any function to see the effect of
a different input; the page's break-even figures do exactly that.

Usage: python3 benchmarks/scale/stage2.py
"""

import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import budget  # noqa: E402
import security_budget  # noqa: E402

RECORDS = HERE.parent.parent / "docs" / "scale" / "recursion-proxy.jsonl"

MB = 10 ** 6
GB = 10 ** 9
GIB = 2 ** 30
BABYBEAR = 15 * 2 ** 27 + 1

INPUTS = {
    # The target (workload.md), unchanged.
    "leaves_per_day": budget.INPUTS["new_leaves_per_day"],
    "spends_per_day": budget.INPUTS["private_per_day"],
    "blocks_per_day": budget.blocks_per_day(),
    "days_per_year": budget.INPUTS["days_per_year"],
    "days_per_month": 30,
    "private_per_block": budget.INPUTS["private_per_block"],
    "public_per_block": budget.INPUTS["public_per_block"],
    "block_seconds": budget.INPUTS["block_seconds"],
    "message_cap_bytes": budget.INPUTS["message_cap_bytes"],
    "private_non_proof_bytes": budget.private_non_proof_bytes(),
    "proof_field_bytes": budget.INPUTS["private_proof_field_bytes"],

    # The ceilings of workload.md, proposals the founder may change.
    "restore_download_ceiling": 500 * MB,
    "keep_up_ceiling_per_month": 50 * MB,
    "restore_time_ceiling_seconds": 10 * 60,
    "phone_memory_ceiling": GIB,
    "phone_storage_ceiling": 200 * MB,
    "node_storage_ceiling_per_year": 2 * 10 ** 12,
    "aggregator_machines": budget.INPUTS["machines"],
    "aggregator_cores": 32,
    "aggregator_memory_bytes": 128 * GIB,
    "merge_machine_seconds_per_reveal": 0.29991,  # 1,049.7 / 3,500, workload.md
    "cost_ceiling_cents": 0.1,
    "price_per_machine_hour": 2.0,  # illustrative, as throughput.md
    "delay_ceiling_seconds": 300,
    "aggregator_bandwidth_bytes_per_second": 10 ** 9 // 8,
    "burst_spare": 0.5,

    # Wallet restore: the phone (the inputs of phone-results.md and recovery-cost.md).
    "phone_link_bytes_per_second": 5_000_000,
    # 32 ms a RandomX hash on the build machine over 8 threads, 0.52 s a cache
    # build (recovery-cost.md, section 3.3), each times the assumed phone slowdown of 4.
    "seal_seconds_eight_threads": 0.032 * 4,
    "cache_build_seconds": 0.52 * 4,
    "randomx_cache_bytes": 256 * 2 ** 20,
    "randomx_epoch_blocks": 8192,  # spec 08
    # A header of spec 05 (582 bytes) with five more 32-byte fields: the header
    # chain's MMR root, the coin spent-marker set root, the coin and data lookup
    # index roots and the block's lookup digest.
    "header_bytes": 582 + 5 * 32,
    "mmr_node_bytes": 48,  # a 32-byte hash and 16 bytes of cumulative work
    "tail_headers": 64,
    "sampling_bits": 64,
    "attacker_work_ratio": 0.5,  # an attacker's valid work against the honest chain's

    # Wallet restore: the lookup data.
    "leaf_bytes": 32,
    "note_bytes": 156,
    "lookup_tag_bytes": 16,
    "marker_bytes": 32,
    "position_bytes": 5,
    "node_bytes": 32,
    # A coin marker-set leaf: value, next value, next index, and the position of
    # the leaf the same reveal appended (its remainder), or none.
    "set_leaf_bytes": 32 + 32 + 5 + 5,
    "lookup_leaf_bytes": 21 + 21 + 5,  # tag and position, the next ones, next index
    "hint_entry_bytes": 8 + 5,  # an 8-byte prefix of the value and a 5-byte position
    "hint_bucket_average": 4,
    "hint_bucket_slots": 16,
    # Entries past a bucket's slots, by chance or by an attacker's copied tags:
    # its size is set by what an attacker spends, an assumption.
    "overflow_db_bytes": GB,
    "minipage_leaves": 64,
    "page_leaves": 4096,
    "bulk_level": 20,
    "snapshot_blocks": 20,
    "hops_per_year": 52,
    "max_padded_hops": 1023,
    "checks_per_month": 2,

    # PIR: the YPIR figures recovery-cost.md quotes for a 32 GB database, not
    # established for these records; communication taken to grow with the
    # square root of the database above that size, and never to fall below it.
    "pir_reference_db_bytes": 32 * GB,
    "pir_reference_query_bytes": 2_500_000,
    "pir_server_bytes_per_core_second": 12.1e9,
    "restore_server_cores": 32,

    # Aggregation: the Poseidon2 architecture (c) with wide layers.
    "keccak_permutation_seconds": 131e-9,  # measured, reveal-parameters.md
    "keccak_rate_bytes": 136,
    "poseidon2_permutation_seconds": 400e-9,  # an assumption, not yet established
    "poseidon2_rate": 15,
    "poseidon2_air_columns": 451,
    "poseidon2_digest_bytes": 36,
    "field_bytes": 4,
    "extension_degree": 8,
    "log_blowup": 3,
    "queries": 96,
    "shrink_log_blowup": 5,
    "shrink_queries": 56,
    "johnson_m": 16,
    "grinding_bits": 16,
    "batch_grinding_bits": 16,
    "poseidon2_digest_bits": 279,
    "leaf_trace_log": 11,
    "leaf_width": 3808,
    "leaf_ood_values": 7701,
    "leaf_functions": 7716,
    "zk_extra_columns": 10,
    "quotient_chunks": 8,
    "final_log": 3,
    "deep_cells_per_term": 17,
    "fold_cells_per_round": 200,
    "ood_cells_leaf": 3_000_000,
    "ood_cells_layer": 1_000_000,
    "layer_width": 600,
    "batch_arity": 32,
    "aggregator_shares": (0.4, 0.35, 0.25),

    # Public signatures: ML-DSA-44 verification proofs (spec 09, section 8).
    "binding_bytes": 20 + 32 + 32,  # account, key identity, transaction hash
    "mldsa_keccak_permutations": 101,
    "keccak_air_rows": 24,
    "keccak_air_columns": 2633,
    "mldsa_arith_cells": 750_000,
    "chunk_verifications": 32,
    "chunk_width": 2700,
    "raw_signature_bytes": budget.INPUTS["public_auth_bytes"],
}


def _get(inputs, key):
    return (INPUTS if inputs is None else inputs)[key]


def _with(inputs, **changes):
    out = dict(INPUTS if inputs is None else inputs)
    out.update(changes)
    return out


def log2_ceil(value):
    return max(0, math.ceil(math.log2(value))) if value > 1 else 0


def pow2_at_least(value):
    return 1 << log2_ceil(value)


# --------------------------------------------------------------------------
# Wallet restore.


def chain(days, inputs=None):
    """Leaves, spent markers and blocks after that many days at the target."""
    return {
        "leaves": _get(inputs, "leaves_per_day") * days,
        "markers": _get(inputs, "spends_per_day") * days,
        "blocks": _get(inputs, "blocks_per_day") * days,
    }


def sample_bits(blocks, inputs=None):
    """Bits of assurance one sampled header gives, at the attacker ratio.

    Headers are sampled by cumulative work with density 1 / ((1 - x) ln(1/delta))
    over x in [0, 1 - delta], delta the share of the last tail_headers. Against an
    attacker whose valid work after its fork is at most c of the honest work,
    any fork point leaves an invalid stretch the sample hits with probability at
    least ln(1/c) / ln(1/delta) (the FlyClient argument).
    """
    tail = _get(inputs, "tail_headers")
    c = _get(inputs, "attacker_work_ratio")
    p = math.log(1 / c) / math.log(blocks / tail)
    return -math.log2(1 - p), p


def samples_needed(blocks, inputs=None):
    bits, _ = sample_bits(blocks, inputs)
    return math.ceil(_get(inputs, "sampling_bits") / bits)


def expected_epochs(blocks, samples, inputs=None):
    """Expected distinct RandomX keys the samples and the tail need."""
    tail = _get(inputs, "tail_headers")
    epoch = _get(inputs, "randomx_epoch_blocks")
    delta = tail / blocks
    top = 1 - delta
    denominator = math.log(1 / delta)
    total = 0.0
    for start in range(0, blocks, epoch):
        end = min(start + epoch, blocks)
        if end > blocks - tail:
            total += 1.0  # the tail is checked header by header
            continue
        a, b = start / blocks, min(end / blocks, top)
        p = math.log((1 - a) / (1 - b)) / denominator
        total += 1 - (1 - p) ** samples
    return total


def header_proof(blocks, chain_blocks=None, inputs=None):
    """The work-sampled header proof over a span of blocks.

    chain_blocks sets the MMR depth (the whole chain); the sampled span is
    `blocks` (from genesis on a restore, from the last checked header on a
    keep-up).
    """
    chain_blocks = blocks if chain_blocks is None else chain_blocks
    header = _get(inputs, "header_bytes")
    path = log2_ceil(chain_blocks) * _get(inputs, "mmr_node_bytes")
    tail = _get(inputs, "tail_headers")
    samples = samples_needed(blocks, inputs)
    epochs = expected_epochs(blocks, samples, inputs)
    key_blocks = math.ceil(epochs)
    nbytes = tail * header + (samples + key_blocks) * (header + path) + path
    seals = tail + samples
    seconds = key_blocks * _get(inputs, "cache_build_seconds") + seals * _get(inputs, "seal_seconds_eight_threads")
    return {
        "samples": samples,
        "seals": seals,
        "epochs": key_blocks,
        "bytes": nbytes,
        "seconds": seconds,
        "bits_per_sample": sample_bits(blocks, inputs)[0],
    }


def pir_query_bytes(db_bytes, inputs=None):
    ref = _get(inputs, "pir_reference_db_bytes")
    return _get(inputs, "pir_reference_query_bytes") * max(1.0, math.sqrt(db_bytes / ref))


def pir_core_seconds(db_bytes, inputs=None):
    return db_bytes / _get(inputs, "pir_server_bytes_per_core_second")


def hint_db_bytes(entries, inputs=None):
    """A bucketed hint table: one bucket for every `average` entries, each of fixed
    slots plus the entry just before the bucket (for an absence)."""
    buckets = math.ceil(entries / _get(inputs, "hint_bucket_average"))
    record = (_get(inputs, "hint_bucket_slots") + 1) * _get(inputs, "hint_entry_bytes")
    return buckets * record


def positional_dbs(entries, leaf_record_bytes, inputs=None):
    """The two PIR databases of a positional tree's witness, and its bulk top.

    Records: 64 leaves (levels 0 to 6); a page's 64 mini-page roots with the 256
    page roots under its level-20 node (levels 6 to 20); the level-20 nodes are
    downloaded in bulk.
    """
    node = _get(inputs, "node_bytes")
    mini = _get(inputs, "minipage_leaves")
    page = _get(inputs, "page_leaves")
    level = 2 ** _get(inputs, "bulk_level")
    bulk = math.ceil(entries / level) * node
    page_record = (page // mini + level // page) * node
    return [entries * leaf_record_bytes, math.ceil(entries / page) * page_record], bulk


def probes(inputs=None):
    """Lookup probes of a restore, padded: probe 0, the doubling probes, the halving ones."""
    bits = log2_ceil(_get(inputs, "max_padded_hops") + 1)
    return 1 + (bits + 1) + bits


def gap_bytes(inputs=None, tags=True):
    """The blocks after a PIR snapshot, read in bulk: their spent markers, and their
    new lookup tags on a restore."""
    item = _get(inputs, "marker_bytes") + (_get(inputs, "lookup_tag_bytes") if tags else 0)
    return _get(inputs, "snapshot_blocks") * _get(inputs, "private_per_block") * item


def restore_queries(days, inputs=None):
    """Every PIR query of one restore, as (name, database bytes, count)."""
    c = chain(days, inputs)
    coin, coin_bulk = positional_dbs(c["leaves"], _get(inputs, "leaf_bytes"), inputs)
    marks, mark_bulk = positional_dbs(c["markers"], _get(inputs, "set_leaf_bytes"), inputs)
    look, look_bulk = positional_dbs(c["leaves"], _get(inputs, "lookup_leaf_bytes"), inputs)
    # Every restore asks every database once after its probes, found or not: the
    # lookup index's witness proves "no first commitment" when nothing is found
    # and is fetched as padding otherwise, so the two cases look the same.
    queries = [
        ("lookup hints", hint_db_bytes(c["leaves"], inputs), probes(inputs)),
        ("lookup hint overflow, for the bucket of the first tag", _get(inputs, "overflow_db_bytes"), 1),
        ("note", c["leaves"] * _get(inputs, "note_bytes"), 1),
        ("coin leaves", coin[0], 1),
        ("coin page witness", coin[1], 1),
        ("marker hint", hint_db_bytes(c["markers"], inputs), 1),
        ("marker-set leaves", marks[0], 1),
        ("marker-set page witness", marks[1], 1),
        ("lookup-index leaves", look[0], 1),
        ("lookup-index page witness", look[1], 1),
    ]
    return queries, coin_bulk + mark_bulk + look_bulk


def restore(days, inputs=None):
    """A full restore from the digits alone after that many days of chain."""
    c = chain(days, inputs)
    queries, bulk = restore_queries(days, inputs)
    head = header_proof(c["blocks"], inputs=inputs)
    pir = sum(n * pir_query_bytes(db, inputs) for _, db, n in queries)
    core_seconds = sum(n * pir_core_seconds(db, inputs) for _, db, n in queries)
    gap = gap_bytes(inputs)
    total = head["bytes"] + pir + bulk + gap
    download_seconds = total / _get(inputs, "phone_link_bytes_per_second")
    server_seconds = core_seconds / _get(inputs, "restore_server_cores")
    # The header check needs nothing from the lookups and runs beside them; the
    # lookups' witnesses are checked against the snapshot header once both are done.
    seconds = max(head["seconds"], download_seconds + server_seconds)
    memory = _get(inputs, "randomx_cache_bytes") + bulk + 2 * MB
    storage = bulk + 2 * MB
    return {
        "days": days,
        "header": head,
        "pir_bytes": pir,
        "bulk_bytes": bulk,
        "gap_bytes": gap,
        "total_bytes": total,
        "queries": sum(n for _, _, n in queries),
        "server_core_seconds": core_seconds,
        "server_seconds": server_seconds,
        "download_seconds": download_seconds,
        "seconds": seconds,
        "memory_bytes": memory,
        "storage_bytes": storage,
        "meets_download": total <= _get(inputs, "restore_download_ceiling"),
        "meets_time": seconds <= _get(inputs, "restore_time_ceiling_seconds"),
        "meets_memory": memory <= _get(inputs, "phone_memory_ceiling"),
        "meets_storage": storage <= _get(inputs, "phone_storage_ceiling"),
    }


def status_check(days, span_blocks, inputs=None):
    """One authenticated spent-status check of the wallet's coin, with the header refresh."""
    c = chain(days, inputs)
    marks, mark_bulk = positional_dbs(c["markers"], _get(inputs, "set_leaf_bytes"), inputs)
    dbs = [hint_db_bytes(c["markers"], inputs)] + marks
    head = header_proof(span_blocks, chain_blocks=c["blocks"], inputs=inputs)
    nbytes = head["bytes"] + sum(pir_query_bytes(db, inputs) for db in dbs) + mark_bulk + gap_bytes(inputs, tags=False)
    return {"bytes": nbytes, "header": head, "core_seconds": sum(pir_core_seconds(db, inputs) for db in dbs)}


def keep_up(days, checks=None, inputs=None):
    """Bytes a month for a wallet that checks its coin `checks` times a month."""
    checks = _get(inputs, "checks_per_month") if checks is None else checks
    span = _get(inputs, "blocks_per_day") * _get(inputs, "days_per_month") // checks
    one = status_check(days, span, inputs)
    total = checks * one["bytes"]
    return {"checks": checks, "per_check": one["bytes"], "bytes": total,
            "meets": total <= _get(inputs, "keep_up_ceiling_per_month")}


def most_checks(days, inputs=None):
    """The most status checks a month that stay within the keep-up ceiling."""
    best = 0
    for checks in range(1, 31):
        if keep_up(days, checks, inputs)["meets"]:
            best = checks
    return best


def node_storage_per_year(inputs=None):
    """Growth of an ordinary full node a year: today's leaves, notes and markers,
    plus the lookup tags, the lookup index, the coin marker-set tree and the header MMR."""
    year = _get(inputs, "days_per_year")
    c = chain(year, inputs)
    inner = 2 * _get(inputs, "node_bytes")
    today = c["leaves"] * (_get(inputs, "leaf_bytes") + _get(inputs, "note_bytes")) + c["markers"] * _get(inputs, "marker_bytes")
    tags = c["leaves"] * _get(inputs, "lookup_tag_bytes")
    lookup = c["leaves"] * (_get(inputs, "lookup_leaf_bytes") - _get(inputs, "lookup_tag_bytes") + inner)
    markers = c["markers"] * (_get(inputs, "set_leaf_bytes") - _get(inputs, "marker_bytes") + inner)
    mmr = c["blocks"] * 2 * _get(inputs, "mmr_node_bytes")
    total = today + tags + lookup + markers + mmr
    return {"today": today, "tags": tags, "lookup_index": lookup, "marker_set": markers, "mmr": mmr,
            "total": total, "meets": total <= _get(inputs, "node_storage_ceiling_per_year")}


def restore_server_extra(days, inputs=None):
    """What a restore server keeps beyond a full node: the two hint tables."""
    c = chain(days, inputs)
    return hint_db_bytes(c["leaves"], inputs) + hint_db_bytes(c["markers"], inputs)


# --------------------------------------------------------------------------
# Aggregation: architecture (c), Poseidon2 leaves and Poseidon2 layers.


def load_records(path=RECORDS):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def proxy_cell_seconds(records=None):
    """Single-thread seconds a trace cell of the Keccak proxy, past the smaller proof.

    The difference of the measured (proxy) medians at 4,096 and 2,048 rows over
    the difference of the cells, which removes what both pay whatever their size.
    """
    records = load_records() if records is None else records
    quick = {r["layer"]: r for r in records if r.get("quick") and r["label"] == "measured (proxy)"}
    small, large = quick["conversion"], quick["merge"]
    cells = (large["trace_rows"] - small["trace_rows"]) * large["trace_width"]
    return (large["median_seconds"] - small["median_seconds"]) / cells


def lde_elements_per_cell(log_blowup=None, inputs=None):
    log_blowup = _get(inputs, "log_blowup") if log_blowup is None else log_blowup
    return 2 * 2 ** log_blowup  # rows doubled for zero knowledge, times the blowup


def cell_seconds(inputs=None, log_blowup=None, records=None):
    """Single-thread seconds a trace cell when commitments hash with Poseidon2.

    The proxy's measured cost a cell, less its Keccak-f[1600] leaf hashing of the
    low-degree extension at 131 ns a permutation, plus the same extension hashed
    with Poseidon2 at the stated cost a permutation. A larger blowup scales the
    whole cell cost with the extension.
    """
    base = lde_elements_per_cell(inputs=inputs)
    keccak = base * _get(inputs, "field_bytes") / _get(inputs, "keccak_rate_bytes") * _get(inputs, "keccak_permutation_seconds")
    poseidon2 = base / _get(inputs, "poseidon2_rate") * _get(inputs, "poseidon2_permutation_seconds")
    seconds = proxy_cell_seconds(records) - keccak + poseidon2
    if log_blowup is not None:
        seconds *= lde_elements_per_cell(log_blowup, inputs) / base
    return seconds


def child_cost(trace_log, width, queries=None, log_blowup=None, ood_values=None, functions=None,
               ood_cells=None, inputs=None):
    """Trace cells a Poseidon2 verifier circuit spends on one child proof.

    Hashing: every compression and leaf hash of a fixed-shape verifier (three
    input trees and the folding trees, every query's leaves), and the duplex
    transcript of the out-of-domain values, one row of the Poseidon2 AIR a
    permutation. Arithmetic: the DEEP combination of every opened function at
    every query, the folding of every round and the child's constraints at the
    out-of-domain point, at the stated cells a step.
    """
    queries = _get(inputs, "queries") if queries is None else queries
    log_blowup = _get(inputs, "log_blowup") if log_blowup is None else log_blowup
    ext = _get(inputs, "extension_degree")
    rate = _get(inputs, "poseidon2_rate")
    opened = width + _get(inputs, "zk_extra_columns")
    chunks = _get(inputs, "quotient_chunks")
    ood_values = 2 * opened + chunks if ood_values is None else ood_values
    functions = ood_values if functions is None else functions
    ood_cells = _get(inputs, "ood_cells_layer") if ood_cells is None else ood_cells
    lde_log = trace_log + 1 + log_blowup
    final = _get(inputs, "final_log")
    rounds = lde_log - final
    compressions = 3 * lde_log + sum(range(final, lde_log))
    leaf_hashes = (math.ceil(34 / rate) + math.ceil(opened / rate) + math.ceil(chunks * ext / rate)
                   + rounds * math.ceil(2 * ext / rate))
    transcript = math.ceil(ood_values * ext / rate) + 2 * rounds + 16
    permutations = queries * (compressions + leaf_hashes) + transcript
    hashing = permutations * _get(inputs, "poseidon2_air_columns")
    deep = queries * functions * _get(inputs, "deep_cells_per_term")
    fold = queries * rounds * _get(inputs, "fold_cells_per_round")
    total = hashing + deep + fold + ood_cells
    return {"permutations": permutations, "hashing": hashing, "deep": deep, "fold": fold,
            "ood": ood_cells, "cells": total}


def leaf_child(inputs=None):
    return child_cost(_get(inputs, "leaf_trace_log"), _get(inputs, "leaf_width"),
                      ood_values=_get(inputs, "leaf_ood_values"), functions=_get(inputs, "leaf_functions"),
                      ood_cells=_get(inputs, "ood_cells_leaf"), inputs=inputs)


def layer(children_cells, inputs=None, width=None):
    """A layer proof verifying children of the given cells: its padded trace."""
    width = _get(inputs, "layer_width") if width is None else width
    rows = pow2_at_least(math.ceil(children_cells / width))
    return {"rows": rows, "trace_log": log2_ceil(rows), "width": width, "cells": rows * width}


def lde_bytes(rows, width, log_blowup, inputs=None):
    return rows * 2 * 2 ** log_blowup * width * _get(inputs, "field_bytes")


def bundle(reveals, inputs=None, records=None):
    """Machine-seconds, memory and walls of one bundle of reveals: batches, root, shrink."""
    cores = _get(inputs, "aggregator_cores")
    arity = _get(inputs, "batch_arity")
    s_cell = cell_seconds(inputs, records=records)
    s_shrink = cell_seconds(inputs, log_blowup=_get(inputs, "shrink_log_blowup"), records=records)
    leaf = leaf_child(inputs)
    batches = math.ceil(reveals / arity)
    full = layer(arity * leaf["cells"], inputs)
    last_count = reveals - (batches - 1) * arity
    last = layer(last_count * leaf["cells"], inputs)
    batch_child = child_cost(full["trace_log"], full["width"], inputs=inputs)
    root = layer(batches * batch_child["cells"], inputs)
    root_child = child_cost(root["trace_log"], root["width"], inputs=inputs)
    shrink = layer(root_child["cells"], inputs)
    batch_seconds = ((batches - 1) * full["cells"] + last["cells"]) * s_cell
    root_seconds = root["cells"] * s_cell
    shrink_seconds = shrink["cells"] * s_shrink
    total = batch_seconds + root_seconds + shrink_seconds
    return {
        "reveals": reveals,
        "batches": batches,
        "leaf_child_cells": leaf["cells"],
        "batch": full,
        "root": root,
        "shrink": shrink,
        "batch_child_cells": batch_child["cells"],
        "root_child_cells": root_child["cells"],
        "machine_seconds": total / cores,
        "batch_wall": full["cells"] * s_cell / cores,
        "root_wall": root_seconds / cores,
        "shrink_wall": shrink_seconds / cores,
        "batch_lde": lde_bytes(full["rows"], full["width"], _get(inputs, "log_blowup"), inputs),
        "root_lde": lde_bytes(root["rows"], root["width"], _get(inputs, "log_blowup"), inputs),
        "shrink_lde": lde_bytes(shrink["rows"], shrink["width"], _get(inputs, "shrink_log_blowup"), inputs),
    }


def shares(total, inputs=None):
    """Reveals a block of each aggregator, by share; the largest takes the remainder."""
    parts = [math.floor(total * s) for s in _get(inputs, "aggregator_shares")]
    parts[0] += total - sum(parts)
    return parts


def gamma2_p99(mean):
    """The 99th percentile of the sum of two exponential waits of that mean."""
    lo, hi = 0.0, 50.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if math.exp(-mid) * (1 + mid) > 0.01:
            lo = mid
        else:
            hi = mid
    return hi * mean


def private_aggregation(inputs=None, records=None):
    per_block = _get(inputs, "private_per_block")
    bundles = [bundle(n, inputs, records) for n in shares(per_block, inputs)]
    machine_seconds = sum(b["machine_seconds"] for b in bundles)
    largest = bundles[0]
    fill = _get(inputs, "batch_arity") / (largest["reveals"] / _get(inputs, "block_seconds"))
    fixed = fill + largest["batch_wall"] + largest["root_wall"] + largest["shrink_wall"]
    p99 = fixed + gamma2_p99(_get(inputs, "block_seconds"))
    return {"bundles": bundles, "machine_seconds": machine_seconds,
            "per_reveal": machine_seconds / per_block, "fixed_delay": fixed, "p99_delay": p99,
            "largest_memory": max(max(b["batch_lde"], b["root_lde"], b["shrink_lde"]) for b in bundles)}


def public_aggregation(inputs=None, records=None):
    """ML-DSA-44 verification chunks, then the same batch, root and shrink layers."""
    cores = _get(inputs, "aggregator_cores")
    s_cell = cell_seconds(inputs, records=records)
    per = (_get(inputs, "mldsa_keccak_permutations") * _get(inputs, "keccak_air_rows")
           * _get(inputs, "keccak_air_columns") + _get(inputs, "mldsa_arith_cells"))
    n = _get(inputs, "public_per_block")
    size = _get(inputs, "chunk_verifications")
    chunks = math.ceil(n / size)
    chunk = layer(size * per, inputs, width=_get(inputs, "chunk_width"))
    chunk_child = child_cost(chunk["trace_log"], chunk["width"], inputs=inputs)
    arity = _get(inputs, "batch_arity")
    batches = math.ceil(chunks / arity)
    batch = layer(arity * chunk_child["cells"], inputs)
    batch_child = child_cost(batch["trace_log"], batch["width"], inputs=inputs)
    root = layer(batches * batch_child["cells"], inputs)
    root_child = child_cost(root["trace_log"], root["width"], inputs=inputs)
    shrink = layer(root_child["cells"], inputs)
    s_shrink = cell_seconds(inputs, log_blowup=_get(inputs, "shrink_log_blowup"), records=records)
    core_seconds = (chunks * chunk["cells"] + batches * batch["cells"] + root["cells"]) * s_cell + shrink["cells"] * s_shrink
    return {"cells_per_verification": per, "chunks": chunks, "chunk": chunk, "batches": batches,
            "root": root, "shrink": shrink, "machine_seconds": core_seconds / cores,
            "per_transaction": core_seconds / cores / n,
            "chunk_lde": lde_bytes(chunk["rows"], chunk["width"], _get(inputs, "log_blowup"), inputs)}


def fleet(inputs=None, records=None):
    """Machines a block's private and public proving needs, against the 40 of workload.md."""
    private = private_aggregation(inputs, records)
    public = public_aggregation(inputs, records)
    seconds = private["machine_seconds"] + public["machine_seconds"]
    block = _get(inputs, "block_seconds")
    machines = math.ceil(seconds / block)
    spare = math.ceil(seconds * (1 + _get(inputs, "burst_spare")) / block)
    budget_seconds = _get(inputs, "aggregator_machines") * block
    price = _get(inputs, "price_per_machine_hour")
    cents = private["per_reveal"] * price / 3600 * 100
    return {"private": private, "public": public, "machine_seconds": seconds, "machines": machines,
            "machines_with_spare": spare, "meets_machines": seconds <= budget_seconds,
            "meets_merge_budget": private["per_reveal"] <= _get(inputs, "merge_machine_seconds_per_reveal"),
            "cents_per_reveal": cents, "meets_cost": cents <= _get(inputs, "cost_ceiling_cents"),
            "meets_delay": private["p99_delay"] <= _get(inputs, "delay_ceiling_seconds"),
            "meets_memory": private["largest_memory"] <= _get(inputs, "aggregator_memory_bytes")
            and public["chunk_lde"] <= _get(inputs, "aggregator_memory_bytes")}


def break_even_poseidon2(test, inputs=None, records=None):
    """The highest Poseidon2 permutation cost, in nanoseconds, at which test(fleet) holds."""
    lo, hi = 0.0, 100_000.0
    if not test(fleet(_with(inputs, poseidon2_permutation_seconds=lo * 1e-9), records)):
        return None
    for _ in range(60):
        mid = (lo + hi) / 2
        if test(fleet(_with(inputs, poseidon2_permutation_seconds=mid * 1e-9), records)):
            lo = mid
        else:
            hi = mid
    return lo


# --------------------------------------------------------------------------
# Proof sizes and block bytes.


def proof_bytes(trace_log, width, queries=None, log_blowup=None, inputs=None):
    """Bytes of one Poseidon2 proof: every query's openings and paths, the
    out-of-domain values and the commitments."""
    queries = _get(inputs, "queries") if queries is None else queries
    log_blowup = _get(inputs, "log_blowup") if log_blowup is None else log_blowup
    ext = _get(inputs, "extension_degree")
    fb = _get(inputs, "field_bytes")
    digest = _get(inputs, "poseidon2_digest_bytes")
    opened = width + _get(inputs, "zk_extra_columns")
    chunks = _get(inputs, "quotient_chunks")
    lde_log = trace_log + 1 + log_blowup
    final = _get(inputs, "final_log")
    rounds = lde_log - final
    per_query = (opened * fb + chunks * ext * fb + 34 * fb + 3 * lde_log * digest
                 + sum(range(final, lde_log)) * digest + rounds * 2 * ext * fb)
    ood = (2 * opened + chunks) * ext * fb
    commitments = (3 + rounds) * digest + 2 ** final * ext * fb
    return queries * per_query + ood + commitments


def leaf_proof_bytes(inputs=None):
    return proof_bytes(_get(inputs, "leaf_trace_log"), _get(inputs, "leaf_width"), inputs=inputs)


def shrink_proof_bytes(inputs=None):
    largest = bundle(shares(_get(inputs, "private_per_block"), inputs)[0], inputs)
    s = largest["shrink"]
    return proof_bytes(s["trace_log"], s["width"], _get(inputs, "shrink_queries"), _get(inputs, "shrink_log_blowup"), inputs)


def ingress_bits(inputs=None):
    """Bits a second of reveal proofs arriving at the largest aggregator."""
    largest = shares(_get(inputs, "private_per_block"), inputs)[0]
    return 8 * largest * leaf_proof_bytes(inputs) / _get(inputs, "block_seconds")


def block_bytes(inputs=None):
    """A block's bytes with signatures replaced by the public proof."""
    root = shrink_proof_bytes(inputs)
    private = _get(inputs, "private_per_block") * (_get(inputs, "private_non_proof_bytes") + _get(inputs, "lookup_tag_bytes"))
    roots = len(_get(inputs, "aggregator_shares")) * root
    public = _get(inputs, "public_per_block") * _get(inputs, "binding_bytes") + root
    total = private + roots + public
    cap = _get(inputs, "message_cap_bytes")
    headroom = cap - total
    return {"private_non_proof": private, "private_roots": roots, "public": public, "total": total,
            "headroom": headroom, "per_transaction": headroom / _get(inputs, "public_per_block"),
            "fits": headroom >= 0, "root_bytes": root}


def raw_fallback_capacity(inputs=None):
    """Public transactions with raw signatures a block still carries beside everything else."""
    b = block_bytes(inputs)
    room = _get(inputs, "message_cap_bytes") - b["private_non_proof"] - b["private_roots"]
    return room // _get(inputs, "raw_signature_bytes")


# --------------------------------------------------------------------------
# Proven security of one bundle.


def field_bits(inputs=None):
    return _get(inputs, "extension_degree") * math.log2(BABYBEAR)


def query_bits(log_blowup, m):
    """Proven bits a FRI query, Johnson regime with parameter m: -log2(sqrt(rho)(1 + 1/(2m)))."""
    return log_blowup / 2 - math.log2(1 + 1 / (2 * m))


def proximity_bits(lde_log, functions, log_blowup, inputs=None):
    """The commit-phase and batching term of the Johnson-regime FRI bound.

    ((m + 1/2)^7 / (3 rho^(3/2))) n^2 (M - 1) / |F| for M functions batched with
    the powers of one challenge, plus (2m + 1)(n + 1) R / (sqrt(rho) |F|) for R
    folding rounds; n the codeword length, |F| the challenge field.
    """
    m = _get(inputs, "johnson_m")
    rho = 2.0 ** -log_blowup
    n = 2.0 ** lde_log
    rounds = lde_log - _get(inputs, "final_log")
    first = (m + 0.5) ** 7 / (3 * rho ** 1.5) * n * n * max(functions - 1, 1)
    second = (2 * m + 1) * (n + 1) * rounds / math.sqrt(rho)
    return field_bits(inputs) - math.log2(first + second)


def proof_terms(lde_log, functions, queries, log_blowup, inputs=None):
    """Classical and quantum bits of one proof: query phase and proximity, grinding at half."""
    m = _get(inputs, "johnson_m")
    q = queries * query_bits(log_blowup, m)
    prox = proximity_bits(lde_log, functions, log_blowup, inputs)
    g, b = _get(inputs, "grinding_bits"), _get(inputs, "batch_grinding_bits")
    classical = security_budget.combine([security_budget.classical_bits(q, g), security_budget.classical_bits(prox, b)])
    quantum = security_budget.combine([security_budget.quantum_bits(q, g), security_budget.quantum_bits(prox, b)])
    return classical, quantum


def bundle_security(reveals=None, inputs=None):
    """The modeled whole-bundle bound: every proof's terms added, the digest once."""
    reveals = _get(inputs, "private_per_block") if reveals is None else reveals
    b = bundle(reveals, inputs)
    lb = _get(inputs, "log_blowup")
    leaf_lde = _get(inputs, "leaf_trace_log") + 1 + lb
    kinds = [
        ("leaf", leaf_lde, _get(inputs, "leaf_functions"), _get(inputs, "queries"), lb, reveals),
        ("batch", b["batch"]["trace_log"] + 1 + lb, 2 * (b["batch"]["width"] + 10) + 8, _get(inputs, "queries"), lb, b["batches"]),
        ("root", b["root"]["trace_log"] + 1 + lb, 2 * (b["root"]["width"] + 10) + 8, _get(inputs, "queries"), lb, 1),
        ("shrink", b["shrink"]["trace_log"] + 1 + _get(inputs, "shrink_log_blowup"),
         2 * (b["shrink"]["width"] + 10) + 8, _get(inputs, "shrink_queries"), _get(inputs, "shrink_log_blowup"), 1),
    ]
    classical_terms, quantum_terms, rows = [], [], []
    for name, lde_log, functions, queries, blowup, count in kinds:
        c, q = proof_terms(lde_log, functions, queries, blowup, inputs)
        rows.append((name, count, c, q))
        classical_terms.append(c - math.log2(count))
        quantum_terms.append(q - math.log2(count))
    digest = _get(inputs, "poseidon2_digest_bits")
    classical = security_budget.combine(classical_terms + [security_budget.collision_bits(digest)])
    quantum = security_budget.combine(quantum_terms + [security_budget.quantum_hash_bits(digest)])
    proofs = sum(count for _, _, _, _, _, count in kinds)
    return {"rows": rows, "proofs": proofs, "classical": classical, "quantum": quantum,
            "meets": classical >= security_budget.TARGET_CLASSICAL_BITS and quantum >= security_budget.TARGET_QUANTUM_BITS}


# --------------------------------------------------------------------------
# The page's tables.


def _mb(nbytes):
    return f"{nbytes / MB:,.1f} MB"


def _gb(nbytes):
    return f"{nbytes / GB:,.1f} GB"


def _yes(flag):
    return "met" if flag else "missed"


def restore_table(inputs=None):
    lines = [
        "| Figure (all modeled) | One year of chain | Five years of chain | Ceiling (workload.md) |",
        "|---|---|---|---|",
    ]
    one, five = restore(365, inputs), restore(5 * 365, inputs)

    def row(name, f, ceiling):
        lines.append(f"| {name} (modeled) | {f(one)} | {f(five)} | {ceiling} |")

    row("Header proof: sampled headers, tail headers, RandomX keys",
        lambda r: f"{r['header']['samples']:,}, {_get(inputs, 'tail_headers'):,}, {r['header']['epochs']:,}", "none")
    row("Header proof bytes", lambda r: _mb(r["header"]["bytes"]), "none")
    row("PIR queries and their bytes", lambda r: f"{r['queries']:,} queries, {_mb(r['pir_bytes'])}", "none")
    row("Bulk tree tops and the blocks after the snapshot", lambda r: _mb(r["bulk_bytes"] + r["gap_bytes"]), "none")
    row("Full-restore download", lambda r: f"{_mb(r['total_bytes'])}, {_yes(r['meets_download'])}",
        "proposed 500 MB (not yet established)")
    row("Restore time: the header check beside the download and the server's work",
        lambda r: f"{r['seconds']:,.0f} s (header {r['header']['seconds']:,.0f} s; download {r['download_seconds']:,.0f} s and server {r['server_seconds']:,.0f} s), {_yes(r['meets_time'])}",
        "proposed 10 minutes (not yet established)")
    row("Server work a restore", lambda r: f"{r['server_core_seconds']:,.0f} core-seconds", "none")
    row("Phone memory at its peak", lambda r: f"{r['memory_bytes'] / 2 ** 20:,.1f} MiB, {_yes(r['meets_memory'])}",
        "proposed 1 GiB (not yet established)")
    row("Phone storage", lambda r: f"{_mb(r['storage_bytes'])}, {_yes(r['meets_storage'])}",
        "proposed 200 MB (not yet established)")
    ku1, ku5 = keep_up(365, inputs=inputs), keep_up(5 * 365, inputs=inputs)
    lines.append(f"| Keeping up, {ku1['checks']} status checks a month (modeled) | {_mb(ku1['bytes'])} ({_mb(ku1['per_check'])} a check), {_yes(ku1['meets'])} "
                 f"| {_mb(ku5['bytes'])} ({_mb(ku5['per_check'])} a check), {_yes(ku5['meets'])} | proposed 50 MB a month (not yet established) |")
    lines.append(f"| Most status checks a month within 50 MB (modeled) | {most_checks(365, inputs)} | {most_checks(5 * 365, inputs)} | none |")
    return lines


def storage_table(inputs=None):
    s = node_storage_per_year(inputs)
    return [
        "| Full-node growth a year (all modeled) | Bytes |",
        "|---|---|",
        f"| Leaves, notes and spent markers, as the first stage counted (modeled) | {_gb(s['today'])} |",
        f"| Lookup tags (modeled) | {_gb(s['tags'])} |",
        f"| Lookup index tree (modeled) | {_gb(s['lookup_index'])} |",
        f"| Coin spent-marker set tree (modeled) | {_gb(s['marker_set'])} |",
        f"| Header MMR (modeled) | {_gb(s['mmr'])} |",
        f"| Total, against the proposed 2 TB a year (modeled) | {_gb(s['total'])}, {_yes(s['meets'])} |",
        f"| A restore server's hint tables at one year of chain, beyond a full node (modeled) | {_gb(restore_server_extra(365, inputs))} |",
    ]


def aggregation_table(inputs=None):
    f = fleet(inputs)
    p, q = f["private"], f["public"]
    big = p["bundles"][0]
    machines = _get(inputs, "aggregator_machines")
    t40 = break_even_poseidon2(lambda r: r["meets_machines"], inputs)
    t40s = break_even_poseidon2(lambda r: r["machine_seconds"] * (1 + _get(inputs, "burst_spare"))
                                <= machines * _get(inputs, "block_seconds"), inputs)
    tmerge = break_even_poseidon2(lambda r: r["meets_merge_budget"], inputs)
    tcost = break_even_poseidon2(lambda r: r["meets_cost"], inputs)
    tdelay = break_even_poseidon2(lambda r: r["meets_delay"], inputs)
    return [
        "| Figure (all modeled) | Value | Ceiling (workload.md) |",
        "|---|---|---|",
        f"| Cells to verify one reveal proof inside a layer (modeled) | {big['leaf_child_cells']:,} | none |",
        f"| Single-thread seconds a cell, Poseidon2 commitments (modeled) | {cell_seconds(inputs) * 1e9:,.1f} ns | none |",
        f"| Batch proof of {_get(inputs, 'batch_arity')} reveals on one machine (modeled) | {big['batch_wall']:,.1f} s, extension {big['batch_lde'] / GIB:,.1f} GiB | 128 GiB a machine (not yet established) |",
        f"| Root over the largest aggregator's {big['batches']} batches, then the shrink (modeled) | {big['root_wall']:,.1f} s and {big['shrink_wall']:,.1f} s, extensions {big['root_lde'] / GIB:,.1f} and {big['shrink_lde'] / GIB:,.1f} GiB | 128 GiB a machine (not yet established) |",
        f"| Machine-seconds a private reveal (modeled) | {p['per_reveal']:,.4f}, {_yes(f['meets_merge_budget'])} | 0.29991, the 0.3 s merge budget (not yet established) |",
        f"| Machine-seconds a block, private (modeled) | {p['machine_seconds']:,.1f} | none |",
        f"| Machine-seconds a block, public signature proofs (modeled) | {q['machine_seconds']:,.1f} | none |",
        f"| Machines a block needs, and with 50 percent spare (modeled) | {f['machines']:,} and {f['machines_with_spare']:,}, {_yes(f['meets_machines'])} | 40 machines (not yet established) |",
        f"| Cost a private reveal at 2 US dollars a machine-hour (modeled) | {f['cents_per_reveal']:,.4f} US cents, {_yes(f['meets_cost'])} | 0.1 US cents (not yet established) |",
        f"| p99 transaction-to-inclusion delay, largest aggregator (modeled) | {p['p99_delay']:,.1f} s ({p['fixed_delay']:,.1f} s proving and filling, the rest two block waits), {_yes(f['meets_delay'])} | 5 minutes (not yet established) |",
        f"| Reveal proofs into the largest aggregator (modeled) | {ingress_bits(inputs) / 1e9:,.2f} Gbit/s, {_yes(ingress_bits(inputs) <= 8 * _get(inputs, 'aggregator_bandwidth_bytes_per_second'))} | 1 Gbit/s sustained (not yet established) |",
        f"| Highest Poseidon2 permutation cost that meets each ceiling (modeled) | 40 machines: {t40:,.0f} ns; with 50 percent spare: {t40s:,.0f} ns; merge budget: {tmerge:,.0f} ns; cost: {tcost:,.0f} ns; delay: {tdelay:,.0f} ns | the input is 400 ns (not yet established) |",
    ]


def public_table(inputs=None):
    b = block_bytes(inputs)
    q = public_aggregation(inputs)
    return [
        "| Figure (all modeled) | Value |",
        "|---|---|",
        f"| Cells to prove one ML-DSA-44 verification (modeled) | {q['cells_per_verification']:,} |",
        f"| Chunk proofs a block, {_get(inputs, 'chunk_verifications')} verifications each, extension of one (modeled) | {q['chunks']:,}, {q['chunk_lde'] / GIB:,.1f} GiB |",
        f"| Machine-seconds a block, and a public transaction (modeled) | {q['machine_seconds']:,.1f} and {q['per_transaction']:,.4f} |",
        f"| Root proof after the shrink, every bundle (modeled) | {b['root_bytes']:,} bytes |",
        f"| Private non-proof parts with lookup tags (modeled) | {b['private_non_proof']:,} bytes |",
        f"| Three private roots (modeled) | {b['private_roots']:,} bytes |",
        f"| Public binding bytes and the public root (modeled) | {b['public']:,} bytes |",
        f"| Block before bodies, headers and framing (modeled) | {b['total']:,} bytes, under the 10,485,760-byte cap: {'yes' if b['fits'] else 'no'} |",
        f"| Headroom, and a public transaction's share of it (modeled) | {b['headroom']:,} bytes, {b['per_transaction']:,.1f} bytes |",
        f"| Raw-signature transactions a block carries when no public proof is built (modeled) | {raw_fallback_capacity(inputs):,} |",
        f"| A reveal proof at {_get(inputs, 'queries')} queries, sent to an aggregator (modeled) | {leaf_proof_bytes(inputs):,} bytes |",
    ]


def security_table(inputs=None):
    s = bundle_security(inputs=inputs)
    lines = [
        "| Proof (all modeled) | Proofs in a bundle of 3,500 | Classical bits each | Quantum bits each |",
        "|---|---|---|---|",
    ]
    for name, count, c, q in s["rows"]:
        lines.append(f"| {name} (modeled) | {count:,} | {c:,.2f} | {q:,.2f} |")
    digest = _get(inputs, "poseidon2_digest_bits")
    lines.append(f"| Poseidon2 digest of {digest} bits, counted once (modeled) | 1 | {security_budget.collision_bits(digest):,.2f} | {security_budget.quantum_hash_bits(digest):,.2f} |")
    lines.append(f"| Whole bundle, {s['proofs']:,} proofs (modeled) | | {s['classical']:,.2f} | {s['quantum']:,.2f} |")
    five = bundle_security(inputs=_with(inputs, extension_degree=5))
    lines.append(f"| The same with the degree-5 extension of today (modeled) | | {five['classical']:,.2f} | {five['quantum']:,.2f} |")
    return lines


def header_table(inputs=None):
    lines = [
        "| Attacker's valid work against the honest chain's (all modeled) | Bits a sample, one year | Assurance of the restore's samples, one year |",
        "|---|---|---|",
    ]
    blocks = chain(365, inputs)["blocks"]
    samples = samples_needed(blocks, inputs)
    for ratio in (0.25, 0.5, 0.75, 0.9):
        bits, _ = sample_bits(blocks, _with(inputs, attacker_work_ratio=ratio))
        lines.append(f"| {ratio:.2f} (modeled) | {bits:,.4f} | {samples * bits:,.1f} bits |")
    return lines


def report(inputs=None):
    return "\n".join(
        restore_table(inputs) + [""] + header_table(inputs) + [""] + storage_table(inputs) + [""]
        + aggregation_table(inputs) + [""] + security_table(inputs) + [""] + public_table(inputs)
    )


def main(argv=None):
    print("Modeled from the inputs at the top of benchmarks/scale/stage2.py")
    print(report())
    return 0


if __name__ == "__main__":
    sys.exit(main())
