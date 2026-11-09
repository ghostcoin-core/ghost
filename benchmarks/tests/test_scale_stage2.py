"""Tests for docs/scale/stage2-design.md and the model behind it, benchmarks/scale/stage2.py.

The page must carry the four limits of the first stage's verdict, one chosen design
for each, every figure labelled, and every table row exactly as the model prints it,
so a change of an input that is not carried to the page fails here. The model tests
check that each ceiling comparison turns when its input crosses the ceiling. The
negative cases check short pages written in the test; none of them is the design.
"""

import math
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import labels  # noqa: E402
import recursion_costs  # noqa: E402
import stage2  # noqa: E402

DOC = REPO / "docs" / "scale" / "stage2-design.md"

LIMITS = (
    "## Wallet restore volume",
    "## Aggregation cost",
    "## Whole-bundle proven security bound",
    "## Public signature size",
)
HEADINGS = LIMITS + ("## Decisions for the founder", "## Build tickets", "## Reproduce")
CHOSEN = re.compile(r"^\*\*Chosen:\*\* \S")
FENCE = re.compile(r"^\s*(```|~~~)")
BACKTICKED = re.compile(r"`([^`\n]+)`")
TICKET = re.compile(r"^\s*\d+\.\s+\*\*\S")


def section(text, heading):
    lines = text.splitlines()
    if heading not in lines:
        return None
    out = []
    for line in lines[lines.index(heading) + 1:]:
        if line.startswith("## "):
            break
        out.append(line)
    return out


def model_rows():
    return [line for line in stage2.report().splitlines() if line.startswith("| ") and not line.startswith("|---")]


def problems(text, rows=None, root=REPO):
    """Every reason the page is not an acceptable stage two design, as text."""
    out = []
    lines = text.splitlines()
    for heading in HEADINGS:
        if heading not in lines:
            out.append(f"missing heading {heading}")
    for heading in LIMITS:
        body = section(text, heading)
        if body is None:
            continue
        chosen = [line for line in body if CHOSEN.match(line)]
        if len(chosen) != 1:
            out.append(f"{heading} must state exactly one chosen design, found {len(chosen)}")
        if not any(re.search(r"\b(measured|modeled)\b", line, re.IGNORECASE) for line in body):
            out.append(f"{heading} carries no measured or modeled figure")
    tickets = section(text, "## Build tickets")
    if tickets is not None and not any(TICKET.match(line) for line in tickets):
        out.append("## Build tickets lists no ticket")
    reproduce = section(text, "## Reproduce")
    if reproduce is not None:
        in_fence = False
        paths = []
        for line in reproduce:
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if not in_fence:
                paths += BACKTICKED.findall(line)
        if not paths:
            out.append("## Reproduce names no path")
        for path in paths:
            if not (root / path).exists():
                out.append(f"missing path {path}")
    for row in (model_rows() if rows is None else rows):
        if row not in lines:
            out.append(f"row not on the page as the model prints it: {row}")
    for number, line in labels.check_text(text):
        out.append(f"line {number}: figure without a label: {line.strip()}")
    return out


class Page(unittest.TestCase):
    def test_the_design_page_passes(self):
        self.assertEqual(problems(DOC.read_text(encoding="utf-8")), [])

    def test_every_figure_is_labelled(self):
        self.assertEqual(labels.check_file(DOC), [])

    def test_reproduce_names_the_model_and_this_test(self):
        reproduce = "\n".join(section(DOC.read_text(encoding="utf-8"), "## Reproduce"))
        self.assertIn("`benchmarks/scale/stage2.py`", reproduce)
        self.assertIn("`benchmarks/tests/test_scale_stage2.py`", reproduce)

    def test_the_verdict_points_here(self):
        verdict = (REPO / "docs" / "scale" / "stage1-verdict.md").read_text(encoding="utf-8")
        self.assertIn("stage2-design.md", verdict)


SAMPLE_ROWS = ["| Full-restore download (modeled) | 1.0 MB, met | 2.0 MB, met | proposed 500 MB (not yet established) |"]

GOOD = """# A design

## Wallet restore volume

**Chosen:** lookups by PIR.

| Full-restore download (modeled) | 1.0 MB, met | 2.0 MB, met | proposed 500 MB (not yet established) |

## Aggregation cost

**Chosen:** wide layers. One reveal costs 0.2 machine-seconds (modeled).

## Whole-bundle proven security bound

**Chosen:** a larger field. The bundle reaches 135 bits (modeled).

## Public signature size

**Chosen:** a proof. The block takes 5 MB (modeled).

## Decisions for the founder

- Move the proof hash (no figure). <!-- no-figure -->

## Build tickets

1. **Prover.** Build it (not yet established).

## Reproduce

- `benchmarks/scale/stage2.py`
"""


class Negative(unittest.TestCase):
    def test_a_good_sample_passes(self):
        self.assertEqual(problems(GOOD, SAMPLE_ROWS), [])

    def test_a_missing_limit(self):
        text = GOOD.replace("## Public signature size", "## Signatures")
        self.assertIn("missing heading ## Public signature size", problems(text, SAMPLE_ROWS))

    def test_two_chosen_designs(self):
        text = GOOD.replace("**Chosen:** a proof.", "**Chosen:** a proof.\n\n**Chosen:** raw signatures.")
        self.assertIn("## Public signature size must state exactly one chosen design, found 2", problems(text, SAMPLE_ROWS))

    def test_no_chosen_design(self):
        text = GOOD.replace("**Chosen:** wide layers.", "Wide layers.")
        self.assertIn("## Aggregation cost must state exactly one chosen design, found 0", problems(text, SAMPLE_ROWS))

    def test_a_limit_without_a_figure(self):
        text = GOOD.replace("The bundle reaches 135 bits (modeled).", "The bundle is strong.")
        self.assertIn("## Whole-bundle proven security bound carries no measured or modeled figure",
                      problems(text, SAMPLE_ROWS))

    def test_a_missing_label(self):
        text = GOOD.replace("The block takes 5 MB (modeled).", "The block takes 5 MB.")
        self.assertTrue(any("figure without a label" in p for p in problems(text, SAMPLE_ROWS)))

    def test_a_stale_row(self):
        text = GOOD.replace("1.0 MB, met", "0.9 MB, met")
        self.assertTrue(any(p.startswith("row not on the page") for p in problems(text, SAMPLE_ROWS)))

    def test_no_ticket(self):
        text = GOOD.replace("1. **Prover.** Build it (not yet established).", "Nothing yet.")
        self.assertIn("## Build tickets lists no ticket", problems(text, SAMPLE_ROWS))

    def test_a_missing_path(self):
        text = GOOD.replace("`benchmarks/scale/stage2.py`", "`benchmarks/scale/no_such_model.py`")
        self.assertIn("missing path benchmarks/scale/no_such_model.py", problems(text, SAMPLE_ROWS))


class Restore(unittest.TestCase):
    def test_one_year_meets_every_phone_ceiling(self):
        r = stage2.restore(365)
        self.assertTrue(r["meets_download"] and r["meets_time"] and r["meets_memory"] and r["meets_storage"])

    def test_the_download_ceiling_turns_with_the_pir_cost(self):
        r = stage2.restore(365)
        factor = 1.01 * stage2.INPUTS["restore_download_ceiling"] / r["pir_bytes"]
        dear = stage2._with(None, pir_reference_query_bytes=stage2.INPUTS["pir_reference_query_bytes"] * factor)
        self.assertFalse(stage2.restore(365, dear)["meets_download"])

    def test_the_time_ceiling_turns_with_the_seal_cost(self):
        slow = stage2._with(None, cache_build_seconds=stage2.INPUTS["restore_time_ceiling_seconds"] / 10)
        self.assertFalse(stage2.restore(365, slow)["meets_time"])

    def test_the_parts_add_up(self):
        r = stage2.restore(365)
        self.assertAlmostEqual(r["total_bytes"], r["header"]["bytes"] + r["pir_bytes"] + r["bulk_bytes"] + r["gap_bytes"])
        self.assertAlmostEqual(r["seconds"], max(r["header"]["seconds"], r["download_seconds"] + r["server_seconds"]))

    def test_requests_do_not_depend_on_the_coins(self):
        # Every restore makes the same queries to the same databases: the probes are
        # padded to the most hops, whatever the key's own count.
        few = stage2.restore_queries(365, stage2._with(None, hops_per_year=1))
        many = stage2.restore_queries(365, stage2._with(None, hops_per_year=500))
        self.assertEqual(few, many)
        self.assertEqual(stage2.probes(), 22)

    def test_more_assurance_needs_more_samples(self):
        blocks = stage2.chain(365)["blocks"]
        low = stage2.samples_needed(blocks, stage2._with(None, sampling_bits=32))
        high = stage2.samples_needed(blocks, stage2._with(None, sampling_bits=64))
        self.assertLess(low, high)
        bits = stage2.header_proof(blocks)["bits_per_sample"]
        self.assertGreaterEqual(high * bits, 64)
        self.assertLess((high - 1) * bits, 64)

    def test_a_stronger_attacker_gives_less_a_sample(self):
        blocks = stage2.chain(365)["blocks"]
        weak = stage2.sample_bits(blocks, stage2._with(None, attacker_work_ratio=0.25))[0]
        strong = stage2.sample_bits(blocks, stage2._with(None, attacker_work_ratio=0.9))[0]
        self.assertGreater(weak, strong)
        self.assertAlmostEqual(stage2.sample_bits(blocks, stage2._with(None, attacker_work_ratio=1.0))[0], 0.0)

    def test_epochs_lie_between_the_tail_and_the_chain(self):
        blocks = stage2.chain(365)["blocks"]
        head = stage2.header_proof(blocks)
        self.assertGreaterEqual(head["epochs"], 1)
        self.assertLessEqual(head["epochs"], math.ceil(blocks / stage2.INPUTS["randomx_epoch_blocks"]))
        self.assertLessEqual(head["epochs"], head["samples"] + 2)

    def test_pir_communication_never_falls_below_the_reference(self):
        ref = stage2.INPUTS["pir_reference_query_bytes"]
        self.assertEqual(stage2.pir_query_bytes(10 ** 6), ref)
        self.assertAlmostEqual(stage2.pir_query_bytes(4 * stage2.INPUTS["pir_reference_db_bytes"]), 2 * ref)

    def test_keep_up_grows_with_checks(self):
        self.assertLess(stage2.keep_up(365, 1)["bytes"], stage2.keep_up(365, 8)["bytes"])
        most = stage2.most_checks(365)
        self.assertTrue(stage2.keep_up(365, most)["meets"])
        self.assertFalse(stage2.keep_up(365, most + 1)["meets"])

    def test_node_storage_turns_with_the_ceiling(self):
        s = stage2.node_storage_per_year()
        self.assertTrue(s["meets"])
        roomy = stage2._with(None, node_storage_ceiling_per_year=s["total"])
        self.assertTrue(stage2.node_storage_per_year(roomy)["meets"])
        tight = stage2._with(None, node_storage_ceiling_per_year=s["total"] - 1)
        self.assertFalse(stage2.node_storage_per_year(tight)["meets"])

    def test_the_380_byte_note_in_node_storage(self):
        # The 380-byte note of spec 10, section 3.2 adds 224 bytes a leaf over the
        # 156-byte one; at 1 million leaves a day the year's growth meets 2 TB with either.
        self.assertEqual(stage2.INPUTS["note_bytes"], 380)
        s = stage2.node_storage_per_year()
        self.assertEqual(s["today"], 365_000_000 * (32 + 380) + 365_000_000 * 32)
        self.assertEqual(s["total"], 241_365_915_200)
        old = stage2.node_storage_per_year(stage2._with(None, note_bytes=156))
        self.assertTrue(old["meets"])
        self.assertEqual(s["total"] - old["total"], 365_000_000 * 224)

    def test_the_note_database_follows_the_note_length(self):
        queries, _ = stage2.restore_queries(365)
        note = next(db for name, db, _ in queries if name == "note")
        self.assertEqual(note, 365_000_000 * 380)
        shorter = stage2.restore(365, stage2._with(None, note_bytes=156))
        self.assertLess(shorter["total_bytes"], stage2.restore(365)["total_bytes"])


class Aggregation(unittest.TestCase):
    def test_the_first_stage_architectures_miss_the_fleet_budget(self):
        # Architectures (a) and (b) are ruled out by the first stage's own lower bounds:
        # (b)'s conversion layer alone, and (a)'s conversion and merge, cost more
        # machine-seconds a reveal than 40 machines have in a 30 s block.
        budget = stage2.INPUTS["aggregator_machines"] * stage2.INPUTS["block_seconds"] / stage2.INPUTS["private_per_block"]
        records = [r for r in stage2.load_records() if not r["quick"]]
        conversion = next(r for r in records if r["layer"] == "conversion")
        merge = next(r for r in records if r["layer"] == "merge")
        self.assertGreater(recursion_costs.per_machine_seconds(conversion), budget)
        self.assertGreater(recursion_costs.per_machine_seconds(conversion) + recursion_costs.per_machine_seconds(merge), budget)

    def test_the_proxy_cell_cost_comes_from_the_records(self):
        self.assertAlmostEqual(stage2.proxy_cell_seconds() * 2048 * 2633, 0.000440636 * 2048, places=6)

    def test_a_dearer_poseidon2_raises_every_cost(self):
        cheap = stage2.fleet(stage2._with(None, poseidon2_permutation_seconds=100e-9))
        dear = stage2.fleet(stage2._with(None, poseidon2_permutation_seconds=1000e-9))
        self.assertLess(cheap["machine_seconds"], dear["machine_seconds"])
        self.assertLess(cheap["private"]["p99_delay"], dear["private"]["p99_delay"])

    def test_the_break_even_is_where_the_ceiling_turns(self):
        test = lambda r: r["meets_machines"]  # noqa: E731
        ns = stage2.break_even_poseidon2(test)
        self.assertTrue(test(stage2.fleet(stage2._with(None, poseidon2_permutation_seconds=ns * 0.999e-9))))
        self.assertFalse(test(stage2.fleet(stage2._with(None, poseidon2_permutation_seconds=ns * 1.01e-9))))

    def test_layers_fit_an_aggregator_machine(self):
        f = stage2.fleet()
        self.assertTrue(f["meets_memory"])
        wide = stage2._with(None, batch_arity=512)
        self.assertFalse(stage2.fleet(wide)["meets_memory"])

    def test_bundles_cover_every_reveal(self):
        self.assertEqual(sum(stage2.shares(350)), 350)
        b = stage2.bundle(1400)
        self.assertEqual(b["batches"], math.ceil(1400 / stage2.INPUTS["batch_arity"]))

    def test_two_block_waits(self):
        self.assertAlmostEqual(stage2.gamma2_p99(30), 199.15, places=1)


class Security(unittest.TestCase):
    def test_the_bundle_meets_the_requirement_in_the_model(self):
        s = stage2.bundle_security()
        self.assertTrue(s["meets"])
        self.assertGreaterEqual(s["classical"], 128)
        self.assertGreaterEqual(s["quantum"], 64)

    def test_todays_extension_does_not(self):
        self.assertFalse(stage2.bundle_security(inputs=stage2._with(None, extension_degree=5))["meets"])

    def test_todays_queries_do_not(self):
        self.assertFalse(stage2.bundle_security(inputs=stage2._with(None, queries=43))["meets"])

    def test_a_short_digest_caps_the_bundle(self):
        short = stage2.bundle_security(inputs=stage2._with(None, poseidon2_digest_bits=248))
        self.assertLess(short["classical"], 128)

    def test_more_functions_lower_the_proximity_term(self):
        self.assertGreater(stage2.proximity_bits(15, 100, 3), stage2.proximity_bits(15, 10_000, 3))

    def test_query_bits_approach_half_the_blowup(self):
        self.assertLess(stage2.query_bits(3, 16), 1.5)
        self.assertAlmostEqual(stage2.query_bits(3, 10 ** 9), 1.5, places=6)


class PublicSignatures(unittest.TestCase):
    def test_the_proof_encoding_fits_and_at_the_target_raw_signatures_do_too(self):
        self.assertTrue(stage2.block_bytes()["fits"])
        self.assertGreaterEqual(stage2.raw_fallback_capacity(), stage2.INPUTS["public_per_block"])
        ten_times = stage2._with(None, public_per_block=10 * stage2.INPUTS["public_per_block"])
        self.assertLess(stage2.raw_fallback_capacity(ten_times), ten_times["public_per_block"])

    def test_the_cap_turns_with_the_root_size(self):
        b = stage2.block_bytes()
        per = stage2.INPUTS["public_per_block"]
        many = stage2._with(None, binding_bytes=stage2.INPUTS["binding_bytes"] + b["headroom"] // per + 1)
        self.assertFalse(stage2.block_bytes(many)["fits"])

    def test_the_root_fits_the_proof_field_and_a_reveal_proof_does_not(self):
        self.assertLessEqual(stage2.shrink_proof_bytes(), stage2.INPUTS["proof_field_bytes"])
        self.assertGreater(stage2.leaf_proof_bytes(), stage2.INPUTS["proof_field_bytes"])


def table_rows(lines):
    return [line for line in lines if line.startswith("| ") and not line.startswith("|---")]


class StageTwoVolumes(unittest.TestCase):
    """The aggregation shape at 1 million a day, and the same figures at 10,000 and 100,000."""

    def test_the_target_is_one_million_a_day(self):
        self.assertEqual(stage2.INPUTS["leaves_per_day"], 1_000_000)
        self.assertEqual(stage2.INPUTS["spends_per_day"], 1_000_000)
        self.assertEqual(stage2.INPUTS["private_per_block"], 350)
        self.assertEqual(stage2.VOLUMES, (10_000, 100_000, 1_000_000))

    def test_the_volumes_scale_the_blocks(self):
        per_block = {v: stage2.at_volume(v)["private_per_block"] for v in stage2.VOLUMES}
        self.assertEqual(per_block, {10_000: 4, 100_000: 35, 1_000_000: 350})
        low = stage2.at_volume(10_000)
        self.assertEqual(low["leaves_per_day"], 10_000)
        self.assertEqual(low["public_per_block"], 4)
        self.assertEqual(low["aggregator_memory_bytes"], stage2.INPUTS["aggregator_memory_bytes"])

    def test_the_poseidon2_cost_is_the_measured_one(self):
        self.assertAlmostEqual(stage2.INPUTS["poseidon2_permutation_seconds"], 897.1e-9, places=15)
        cheap = stage2.cell_seconds(stage2._with(None, poseidon2_permutation_seconds=100e-9))
        self.assertGreater(stage2.cell_seconds(), cheap)

    def test_the_shape_is_the_one_the_model_chooses(self):
        self.assertEqual(stage2.choose_shape(), (stage2.INPUTS["batch_arity"], stage2.INPUTS["root_capacity"]))
        self.assertEqual((stage2.INPUTS["batch_arity"], stage2.INPUTS["root_capacity"]), (8, 29))

    def test_the_choice_turns_with_its_ceilings(self):
        # Without 8 a batch the next cheapest admissible arity is taken, its root
        # just large enough for the burst or as large at the same cost.
        arity, capacity = stage2.choose_shape(arities=(16, 32))
        self.assertEqual(arity, 16)
        self.assertGreaterEqual(arity * capacity, stage2.burst_reveals())
        # Under 40 GiB a machine no shape holds the burst in one root.
        self.assertIsNone(stage2.choose_shape(stage2._with(None, aggregator_memory_bytes=40 * stage2.GIB)))
        # A dearer permutation that breaks the delay rules every shape out.
        self.assertIsNone(stage2.choose_shape(stage2._with(None, poseidon2_permutation_seconds=10e-6)))

    def test_every_layer_fits_an_aggregator_machine(self):
        peaks = stage2.prover_peaks()
        self.assertEqual(set(peaks), {"batch", "root", "shrink"})
        for name, peak in peaks.items():
            self.assertLessEqual(peak, stage2.INPUTS["aggregator_memory_bytes"], name)
        self.assertTrue(stage2.fleet()["meets_memory"])
        self.assertFalse(stage2.shape_fits(stage2._with(None, batch_arity=64, root_capacity=4)))

    def test_the_peaks_are_the_plan_at_the_planned_shape(self):
        planned = stage2._with(None, batch_arity=32, root_capacity=44)
        peaks = stage2.prover_peaks(planned)
        self.assertAlmostEqual(peaks["batch"], 93.3 * stage2.GIB)
        self.assertAlmostEqual(peaks["root"], 116.3 * stage2.GIB)
        self.assertAlmostEqual(peaks["shrink"], 8.0 * stage2.GIB)
        self.assertLess(stage2.prover_peaks()["root"], peaks["root"])

    def test_the_root_holds_the_largest_aggregator_at_the_burst(self):
        burst = stage2.burst_reveals()
        self.assertEqual(burst, 211)
        self.assertLessEqual(burst, stage2.INPUTS["batch_arity"] * stage2.INPUTS["root_capacity"])
        short = stage2._with(None, root_capacity=math.ceil(burst / stage2.INPUTS["batch_arity"]) - 1)
        self.assertFalse(stage2.shape_fits(short))
        self.assertEqual(stage2.bundle(burst)["roots"], 1)
        self.assertEqual(stage2.bundle(burst, short)["roots"], 2)

    def test_a_fixed_shape_pays_for_its_padding(self):
        arity = stage2.INPUTS["batch_arity"]
        one, full = stage2.bundle(1), stage2.bundle(arity)
        self.assertAlmostEqual(one["machine_seconds"], full["machine_seconds"])
        self.assertGreater(stage2.bundle(arity + 1)["machine_seconds"], full["machine_seconds"])

    def test_the_network_machines_are_whole_machines_of_each_aggregator(self):
        f = stage2.fleet()
        block = stage2.INPUTS["block_seconds"]
        own = [b["machine_seconds"] for b in f["private"]["bundles"]] + [f["public"]["machine_seconds"]]
        self.assertEqual(f["network_machines"], sum(math.ceil(s / block) for s in own))
        self.assertGreaterEqual(f["network_machines"], f["machines"])
        self.assertEqual((f["network_machines"], f["network_machines_with_spare"]), (26, 37))
        self.assertLessEqual(f["network_machines_with_spare"], stage2.INPUTS["aggregator_machines"])

    def test_the_cost_a_reveal_falls_with_volume(self):
        cents = [stage2.volume(v)["fleet"]["cents_per_reveal"] for v in stage2.VOLUMES]
        self.assertGreater(cents[0], cents[1])
        self.assertGreater(cents[1], cents[2])
        self.assertFalse(stage2.volume(10_000)["fleet"]["meets_cost"])
        self.assertFalse(stage2.volume(100_000)["fleet"]["meets_cost"])
        self.assertTrue(stage2.volume(1_000_000)["fleet"]["meets_cost"])
        for v in stage2.VOLUMES:
            self.assertTrue(stage2.volume(v)["fleet"]["meets_delay"], v)

    def test_a_quiet_batch_closes_after_a_block(self):
        low = stage2.volume(10_000)["fleet"]["private"]
        self.assertEqual(low["fill"], stage2.INPUTS["batch_close_seconds"])
        late = stage2.at_volume(10_000, stage2._with(None, batch_close_seconds=600))
        self.assertFalse(stage2.fleet(late)["meets_delay"])

    def test_quiet_blocks(self):
        q = stage2.quiet_block(1)
        self.assertGreater(q["fixed"]["machine_seconds"], q["quiet"]["machine_seconds"])
        self.assertFalse(q["fixed"]["cents_per_reveal"] <= stage2.INPUTS["cost_ceiling_cents"])
        self.assertEqual(q["direct"]["machine_seconds"], 0.0)
        self.assertEqual(q["direct_per_block_gas"], 1)
        self.assertEqual(q["direct_per_block"], 4)
        four = stage2.quiet_block(4)
        self.assertAlmostEqual(four["fixed"]["machine_seconds"], q["fixed"]["machine_seconds"])
        self.assertGreater(four["quiet"]["cents_per_reveal"], stage2.INPUTS["cost_ceiling_cents"])

    def test_the_shape_and_volume_rows_are_on_the_page(self):
        lines = DOC.read_text(encoding="utf-8").splitlines()
        rows = table_rows(stage2.aggregation_table() + stage2.shape_table() + stage2.choice_table()
                          + stage2.volume_table() + stage2.quiet_table() + stage2.security_table())
        self.assertGreater(len(rows), 40)
        for row in rows:
            self.assertIn(row, lines)
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("the input is 897.1 ns (measured)", text)
        self.assertNotIn("the input is 400 ns", text)


if __name__ == "__main__":
    unittest.main()
