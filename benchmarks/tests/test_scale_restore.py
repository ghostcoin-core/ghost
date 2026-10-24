"""Tests for benchmarks/scale/restore_sim.py: wallet restore against a simulated mature chain."""

import contextlib
import io
import re
import sys
import unittest
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import restore_sim as rs  # noqa: E402

SIM_CHECKPOINT = replace(rs.CHECKPOINT, epoch_leaves=rs.TEST_EPOCH_LEAVES)
SIM_DESIGNS = (rs.BASELINE, rs.BUCKETS, SIM_CHECKPOINT)
# A buckets design small enough to save bytes on the simulated chain.
SMALL_BUCKETS = replace(rs.BUCKETS, decoys_per_hit=1, min_pages=4)

CHAIN = rs.generate_chain()


def run(design, key=rs.TEST_KEY, spent_check="canonical", chain=CHAIN):
    return rs.restore(chain, key, design, key_birth=rs.TEST_KEY_BIRTH, spent_check=spent_check)


class Inputs(unittest.TestCase):
    """The ceilings and target are the values workload.md states."""

    def setUp(self):
        self.text = (REPO / "docs" / "scale" / "workload.md").read_text(encoding="utf-8")

    def row(self, name):
        for line in self.text.splitlines():
            if line.startswith(f"| {name} |"):
                return line
        self.fail(f"workload.md has no row {name!r}")

    def test_phone_ceilings_match_workload(self):
        self.assertIn("proposed 1 GiB for the whole tab", self.row("Memory ceiling"))
        self.assertEqual(rs.PHONE_MEMORY_CEILING_BYTES, 1024 ** 3)
        download = self.row("Restore download ceiling")
        full, month = re.search(r"proposed (\d+) MB for a full restore, (\d+) MB a month", download).groups()
        self.assertEqual(rs.PHONE_RESTORE_DOWNLOAD_CEILING_BYTES, int(full) * 10 ** 6)
        self.assertEqual(rs.PHONE_CATCH_UP_CEILING_BYTES_PER_MONTH, int(month) * 10 ** 6)
        minutes = re.search(r"proposed (\d+) minutes", self.row("Restore time ceiling")).group(1)
        self.assertEqual(rs.PHONE_RESTORE_TIME_CEILING_SECONDS, int(minutes) * 60)
        storage = re.search(r"proposed (\d+) MB for wallet data", self.row("Phone storage ceiling")).group(1)
        self.assertEqual(rs.PHONE_STORAGE_CEILING_BYTES, int(storage) * 10 ** 6)

    def test_target_and_encoding_match_workload(self):
        self.assertIn("| 188 bytes |", self.row("Leaf and note a wallet downloads"))
        self.assertEqual(rs.LEAF_AND_NOTE_BYTES, 188)
        self.assertEqual(rs.NEW_LEAVES_PER_DAY, 10_000_000)
        self.assertEqual(rs.SPENDS_PER_DAY, 10_000_000)
        self.assertEqual(rs.BLOCKS_PER_DAY, 2_880)
        self.assertIn("| 2,880 |", self.row("Blocks a day"))

    def test_phone_cost_inputs(self):
        self.assertEqual(rs.TRIAL_DECRYPT_NS_PHONE, 1_148)
        self.assertEqual(rs.LEAF_HASH_NS_PHONE, 680)
        self.assertEqual(rs.PHONE_LINK_BYTES_PER_SECOND, 5_000_000)


class Chain(unittest.TestCase):
    def test_deterministic(self):
        again = rs.generate_chain()
        self.assertEqual(again.leaves, CHAIN.leaves)
        self.assertEqual(again.notes, CHAIN.notes)
        self.assertEqual(again.markers, CHAIN.markers)
        self.assertNotEqual(rs.generate_chain(seed=rs.SEED + 1).leaves, CHAIN.leaves)

    def test_sizes(self):
        self.assertEqual(CHAIN.count, 100_000)
        self.assertEqual(len(CHAIN.leaves), 100_000 * 32)
        self.assertEqual(len(CHAIN.notes), 100_000 * 156)
        self.assertEqual(CHAIN.pages, 25)
        self.assertEqual(sorted(CHAIN.owned), list(rs.TEST_OWNED))

    def test_any_size(self):
        small = rs.generate_chain(5_000, owned=[10, 4_200], spent=[10], spent_disconnected=[])
        self.assertEqual(small.count, 5_000)
        self.assertEqual(set(run(rs.BASELINE, chain=small).coins), {10, 4_200})

    def test_rejects_impossible_coins(self):
        with self.assertRaises(ValueError):
            rs.generate_chain(1_000, owned=[1_000])
        with self.assertRaises(ValueError):
            rs.generate_chain(1_000, owned=[5], spent=[6], spent_disconnected=[])
        with self.assertRaises(ValueError):
            rs.generate_chain(1_000, owned=[5], spent=[5], spent_disconnected=[5])


class Recovery(unittest.TestCase):
    def test_every_design_recovers_every_note(self):
        for design in SIM_DESIGNS + (SMALL_BUCKETS,):
            with self.subTest(design=design.key):
                r = run(design)
                self.assertEqual(r.coins, CHAIN.owned)

    def test_wrong_key_recovers_nothing(self):
        for design in SIM_DESIGNS + (SMALL_BUCKETS,):
            with self.subTest(design=design.key):
                r = run(design, key=rs.OTHER_KEY)
                self.assertEqual(r.coins, {})
                self.assertEqual(r.status, {})

    def test_trial_decryption_needs_the_matching_leaf(self):
        p = rs.TEST_OWNED[0]
        self.assertIsNotNone(rs.trial_decrypt(rs.TEST_KEY, CHAIN.leaf(p), CHAIN.note(p)))
        self.assertIsNone(rs.trial_decrypt(rs.TEST_KEY, CHAIN.leaf(p + 1), CHAIN.note(p)))
        self.assertIsNone(rs.trial_decrypt(rs.OTHER_KEY, CHAIN.leaf(p), CHAIN.note(p)))
        altered = bytearray(CHAIN.note(p))
        altered[-1] ^= 1
        self.assertIsNone(rs.trial_decrypt(rs.TEST_KEY, CHAIN.leaf(p), bytes(altered)))

    def test_checkpoint_after_a_coin_misses_it(self):
        # The epoch must not start after the key's first coin; a later start
        # hides coins, which is why the design scans from the epoch's start.
        late = rs.restore(CHAIN, rs.TEST_KEY, SIM_CHECKPOINT, key_birth=70_000)
        self.assertEqual(late.counts.scan_start, 65_536)
        self.assertNotIn(rs.TEST_OWNED[0], late.coins)
        self.assertIn(70_000, late.coins)


class Bytes(unittest.TestCase):
    def test_baseline_bytes_are_leaves_times_188(self):
        c = run(rs.BASELINE).costs
        self.assertEqual(c["leaf_and_note_bytes"], CHAIN.count * 188)
        self.assertEqual(c["leaf_and_note_bytes"], 18_800_000)
        self.assertEqual(c["trial_decryptions"], CHAIN.count)
        self.assertEqual(c["page_root_bytes"], 25 * 32)
        self.assertEqual(c["marker_bytes"], CHAIN.count * 32)
        self.assertEqual(c["download_bytes"], 22_000_800)
        self.assertEqual(c["label"], "modeled")

    def test_alternatives_never_download_more_than_the_baseline(self):
        base = run(rs.BASELINE).costs
        for design in (rs.BUCKETS, SIM_CHECKPOINT, SMALL_BUCKETS):
            with self.subTest(design=design.key):
                c = run(design).costs
                self.assertLessEqual(c["leaf_and_note_bytes"], base["leaf_and_note_bytes"])
                self.assertLessEqual(c["download_bytes"], base["download_bytes"])
                self.assertLessEqual(c["trial_decryptions"], base["trial_decryptions"])
        for days in (1, 30, 365, 5 * 365):
            leaves = rs.leaves_after(days)
            base = rs.analytic(rs.BASELINE, leaves, 52)
            for design in rs.DESIGNS:
                with self.subTest(design=design.key, days=days):
                    c = rs.analytic(design, leaves, 52, key_birth=leaves // 2)
                    self.assertLessEqual(c["download_bytes"], base["download_bytes"])

    def test_alternatives_save_where_they_can(self):
        base = run(rs.BASELINE).costs
        small = run(SMALL_BUCKETS).costs
        self.assertLess(small["download_bytes"], base["download_bytes"])
        self.assertEqual(small["trial_decryptions"], len(rs.TEST_OWNED))
        checkpoint = run(SIM_CHECKPOINT).costs
        self.assertEqual(checkpoint["scan_start"], 49_152)
        self.assertEqual(checkpoint["leaf_and_note_bytes"], 50_848 * 188)
        self.assertEqual(checkpoint["download_bytes"], 11_187_360)
        # At the default decoys the request covers all 25 pages: no saving.
        self.assertEqual(run(rs.BUCKETS).costs["leaf_and_note_bytes"], base["leaf_and_note_bytes"])

    def test_simulation_matches_the_analytic_mode(self):
        for design in (rs.BASELINE, SIM_CHECKPOINT):
            with self.subTest(design=design.key):
                sim = run(design).costs
                model = rs.analytic(design, rs.TEST_LEAVES, len(rs.TEST_OWNED), rs.TEST_KEY_BIRTH)
                self.assertEqual(sim, model)
        for design in (rs.BUCKETS, SMALL_BUCKETS):
            with self.subTest(design=design.key):
                sim = run(design).costs
                model = rs.analytic(design, rs.TEST_LEAVES, len(rs.TEST_OWNED), rs.TEST_KEY_BIRTH)
                self.assertLessEqual(sim["download_bytes"], model["download_bytes"])
                self.assertLessEqual(sim["trial_decryptions"], model["trial_decryptions"])


class Privacy(unittest.TestCase):
    def test_baseline_privacy_is_the_whole_chain(self):
        c = run(rs.BASELINE).costs
        self.assertEqual(c["anonymity_set"], CHAIN.count)
        self.assertEqual(c["excluded_fraction"], 0)
        self.assertEqual(rs.analytic(rs.BASELINE, 3_650_000_000, 52)["anonymity_set"], 3_650_000_000)

    def test_baseline_requests_do_not_depend_on_the_key(self):
        self.assertEqual(run(rs.BASELINE).requests, run(rs.BASELINE, key=rs.OTHER_KEY).requests)
        self.assertEqual(run(SIM_CHECKPOINT).requests, run(SIM_CHECKPOINT, key=rs.OTHER_KEY).requests)

    def test_bucket_requests_name_only_whole_pages(self):
        r = run(SMALL_BUCKETS)
        pages = [p for kind, *rest in r.requests if kind == "note-rest" for p in rest]
        self.assertEqual(pages, sorted(pages))
        own = {p // rs.PAGE_LEAVES for p in rs.TEST_OWNED}
        self.assertTrue(own <= set(pages))
        self.assertGreater(len(pages), len(own))
        self.assertEqual(r.costs["anonymity_set"], sum(rs._filled(p, CHAIN.count) for p in pages))

    def test_bucket_request_size_hides_a_few_hits(self):
        two = rs.generate_chain(owned=[10, 60_000], spent=[], spent_disconnected=[])
        one = rs.generate_chain(owned=[30_000], spent=[], spent_disconnected=[])
        design = replace(rs.BUCKETS, decoys_per_hit=1, min_pages=8)
        a = rs.restore(two, rs.TEST_KEY, design)
        b = rs.restore(one, rs.OTHER_KEY, design)
        self.assertEqual(len(a.requests), len(b.requests))

    def test_decoys_are_fixed(self):
        self.assertEqual(rs._decoy_pages(rs.TEST_KEY, 3, 15, 1_000), rs._decoy_pages(rs.TEST_KEY, 3, 15, 1_000))
        self.assertNotIn(3, rs._decoy_pages(rs.TEST_KEY, 3, 15, 1_000))
        self.assertEqual(len(set(rs._decoy_pages(rs.TEST_KEY, 3, 15, 1_000))), 15)

    def test_checkpoint_privacy_is_the_span_from_the_epoch(self):
        c = run(SIM_CHECKPOINT).costs
        self.assertEqual(c["anonymity_set"], 50_848)
        self.assertAlmostEqual(c["excluded_fraction"], 0.49152)


class SpentStatus(unittest.TestCase):
    def test_status_follows_the_canonical_chain(self):
        for design in SIM_DESIGNS:
            with self.subTest(design=design.key):
                r = run(design)
                self.assertEqual(rs.audit(r), [])
                for p in rs.TEST_OWNED:
                    self.assertEqual(r.status[p], "spent" if p in rs.TEST_SPENT else "unspent")
                # Spent only on a disconnected block: spendable again.
                self.assertEqual(r.status[rs.TEST_SPENT_DISCONNECTED[0]], "unspent")
                self.assertIn(("markers-from", r.counts.scan_start), r.requests)

    def test_skipping_the_spent_check_is_flagged(self):
        for design in SIM_DESIGNS:
            with self.subTest(design=design.key):
                r = run(design, spent_check="skip")
                problems = rs.audit(r)
                self.assertIn("spent status not checked against the canonical chain (skip)", problems)
                self.assertIn("a found coin has an unknown spent status", problems)
                self.assertEqual(set(r.status.values()), {"unknown"})
                self.assertEqual(r.costs["marker_bytes"], 0)

    def test_unchecked_marker_hints_are_flagged(self):
        for design in SIM_DESIGNS:
            with self.subTest(design=design.key):
                r = run(design, spent_check="hints")
                self.assertEqual(r.status[rs.TEST_SPENT_DISCONNECTED[0]], "spent")
                self.assertIn("spent status not checked against the canonical chain (hints)", rs.audit(r))

    def test_unknown_check_is_refused(self):
        with self.assertRaises(ValueError):
            run(rs.BASELINE, spent_check="age")


class Analytic(unittest.TestCase):
    """The modeled figures of docs/scale/phone-results.md."""

    def test_ten_million_leaves_a_day(self):
        day = rs.analytic(rs.BASELINE, rs.leaves_after(1), 1)
        year = rs.analytic(rs.BASELINE, rs.leaves_after(365), 52)
        self.assertEqual(day["label"], "modeled")
        self.assertEqual(year["label"], "modeled")
        self.assertEqual(day["leaf_and_note_bytes"], 1_880_000_000)
        self.assertEqual(year["leaf_and_note_bytes"], 686_200_000_000)
        self.assertEqual(round(year["leaf_and_note_bytes"] / 1e9, 1), 686.2)

    def test_one_year(self):
        leaves = 3_650_000_000
        base = rs.analytic(rs.BASELINE, leaves, 52)
        self.assertEqual(base["page_root_bytes"], 891_114 * 32)
        self.assertEqual(base["marker_bytes"], 116_800_000_000)
        self.assertEqual(base["download_bytes"], 803_028_515_648)
        self.assertAlmostEqual(base["elapsed_seconds"], 167_277.9031296, places=3)
        self.assertEqual(base["peak_memory_bytes"], 36_232_512)
        self.assertEqual(base["storage_bytes"], 35_331_392)
        buckets = rs.analytic(rs.BUCKETS, leaves, 52)
        self.assertEqual(buckets["leaf_and_note_bytes"], 131_927_958_016)
        self.assertEqual(buckets["download_bytes"], 248_756_473_664)
        self.assertEqual(buckets["trial_decryptions"], 53)
        self.assertEqual(buckets["anonymity_set"], 3_473_408)
        self.assertAlmostEqual(buckets["elapsed_seconds"], 54_715.29479, places=3)
        checkpoint = rs.analytic(rs.CHECKPOINT, leaves, 52, key_birth=0)
        self.assertEqual(checkpoint["download_bytes"], base["download_bytes"])

    def test_five_years(self):
        leaves = 18_250_000_000
        base = rs.analytic(rs.BASELINE, leaves, 52)
        self.assertEqual(base["page_root_bytes"], 142_578_144)
        self.assertEqual(base["download_bytes"], 4_015_142_578_144)
        self.assertAlmostEqual(base["elapsed_seconds"], 836_389.5156, places=3)
        self.assertEqual(base["peak_memory_bytes"], 150_295_008)
        self.assertEqual(base["storage_bytes"], 149_393_888)
        buckets = rs.analytic(rs.BUCKETS, leaves, 52)
        self.assertEqual(buckets["download_bytes"], 1_241_710_382_048)
        self.assertEqual(buckets["anonymity_set"], 3_735_552)
        self.assertAlmostEqual(buckets["elapsed_seconds"], 273_162.0765, places=3)
        checkpoint = rs.analytic(rs.CHECKPOINT, leaves, 52, key_birth=14_600_000_000)
        self.assertEqual(checkpoint["scan_start"], 14_400_000_000)
        self.assertEqual(checkpoint["download_bytes"], 847_142_578_144)
        self.assertEqual(checkpoint["anonymity_set"], 3_850_000_000)
        self.assertAlmostEqual(checkpoint["elapsed_seconds"], 176_466.3156, places=3)

    def test_simulated_size(self):
        self.assertAlmostEqual(rs.analytic(rs.BASELINE, 100_000, 8)["elapsed_seconds"], 4.58296)
        self.assertAlmostEqual(rs.analytic(SIM_CHECKPOINT, 100_000, 8, 50_000)["elapsed_seconds"], 2.330422144)

    def test_ceilings(self):
        year = rs.analytic(rs.BASELINE, rs.leaves_after(365), 52)
        self.assertEqual(rs.ceilings(year), {"restore download": False, "restore time": False, "memory": True, "storage": True})
        tiny = rs.analytic(rs.BASELINE, 1_000, 1)
        self.assertTrue(all(rs.ceilings(tiny).values()))

    def test_catch_up_and_headers(self):
        month = rs.catch_up_bytes(rs.BASELINE, 30, 5)
        self.assertEqual(month["leaf_and_note_bytes"], 56_400_000_000)
        self.assertEqual(month["marker_bytes"], 9_600_000_000)
        self.assertEqual(rs.catch_up_bytes(rs.BUCKETS, 30, 5)["leaf_and_note_bytes"], 10_849_807_360)
        self.assertEqual(rs.header_bytes(365), 611_798_400)
        self.assertEqual(rs.header_bytes(5 * 365), 3_058_992_000)

    def test_report_runs(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rs.main(["--leaves", "20000"])
        text = out.getvalue()
        self.assertIn("Modeled", text)
        self.assertIn("803,028,515,648", text)


if __name__ == "__main__":
    unittest.main()
