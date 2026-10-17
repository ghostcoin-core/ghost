"""Tests for benchmarks/summarize.py, against the fixture in fixtures/."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import summarize  # noqa: E402

FIXTURE = HERE / "fixtures" / "records.jsonl"
# The fixture is small: two cold and four warm runs per device.
SMALL = {"min_cold": 2, "min_warm": 4}
A = "poseidon2-babybear-w24"
B = "keccak-256"


def fixture():
    return summarize.load_records([str(FIXTURE)])


def only(records, candidate):
    return [r for r in records if r["hash_candidate"] == candidate]


def verdict_line(report):
    lines = [line for line in report.splitlines() if line.startswith("Verdict: ")]
    assert len(lines) == 1, report
    return lines[0]


class Statistics(unittest.TestCase):
    def test_nearest_rank_percentile(self):
        self.assertEqual(summarize.percentile(list(range(1, 11)), 90), 9)
        self.assertEqual(summarize.percentile(list(range(1, 51)), 90), 45)
        self.assertEqual(summarize.percentile([7.5], 90), 7.5)
        self.assertIsNone(summarize.percentile([], 90))

    def test_device_statistics(self):
        groups, _ = summarize.group(fixture())
        phone = groups[(A, 1, "wasm-threads")][summarize.PHONE].stats()
        self.assertEqual((phone["cold_runs"], phone["warm_runs"]), (2, 4))
        self.assertEqual(phone["cold_median"], 10750)
        self.assertEqual(phone["cold_slowest"], 12500)
        self.assertEqual(phone["warm_median"], 8300)
        self.assertEqual(phone["warm_p90"], 8600)
        self.assertEqual(phone["warm_slowest"], 8600)
        self.assertEqual(phone["verify_largest"], 95)
        self.assertEqual(phone["proof_largest"], 150100)
        self.assertEqual(phone["failures"], 0)


class Verdicts(unittest.TestCase):
    def test_slow_cold_run_on_the_phone_means_mac_studio_only(self):
        groups, _ = summarize.group(fixture())
        self.assertEqual(
            summarize.config_verdict(groups[(A, 1, "wasm-threads")], **SMALL),
            summarize.VERDICT_MAC_ONLY,
        )
        self.assertEqual(
            summarize.config_verdict(groups[(B, 2, "wasm-threads")], **SMALL),
            summarize.VERDICT_MET,
        )

    def test_overall_verdict_is_met_when_one_configuration_meets_on_both(self):
        report, verdict = summarize.render(fixture(), **SMALL)
        self.assertEqual(verdict, summarize.VERDICT_MET)
        self.assertEqual(verdict_line(report), f"Verdict: met ({B} blowup 2^2)")

    def test_mac_studio_alone_is_not_a_pass(self):
        report, verdict = summarize.render(only(fixture(), A), **SMALL)
        self.assertEqual(verdict, summarize.VERDICT_MAC_ONLY)
        self.assertTrue(verdict_line(report).startswith("Verdict: met on the Mac Studio only"))

    def test_slow_warm_median_is_not_met(self):
        records = copy.deepcopy(only(fixture(), B))
        for r in records:
            if r["device_class"] == summarize.MAC and r["run_kind"] == "warm":
                r["proving_ms"] += 6500
        _, verdict = summarize.render(records, **SMALL)
        self.assertEqual(verdict, summarize.VERDICT_NOT_MET)

    def test_a_failed_run_fails_the_device(self):
        records = copy.deepcopy(only(fixture(), B))
        phone_warm = [r for r in records if r["device_class"] == summarize.PHONE and r["run_kind"] == "warm"]
        phone_warm[0]["outcome"] = "out_of_memory"
        report, verdict = summarize.render(records, **SMALL)
        self.assertEqual(verdict, summarize.VERDICT_MAC_ONLY)
        self.assertIn("| 1 | no |", report)

    def test_missing_runs_are_not_met(self):
        _, verdict = summarize.render(only(fixture(), B), min_cold=5, min_warm=50)
        self.assertEqual(verdict, summarize.VERDICT_NOT_MET)

    def test_native_and_non_zero_knowledge_records_never_count(self):
        records = [r for r in fixture() if r["build"] == "native" or not r["zero_knowledge"]]
        self.assertEqual(len(records), 2)
        report, verdict = summarize.render(records, min_cold=0, min_warm=1)
        self.assertEqual(verdict, summarize.VERDICT_NOT_MET)
        self.assertIn("1 native reference record(s)", report)
        self.assertIn("1 record(s) without zero-knowledge mode", report)

    def test_the_verdict_uses_the_chosen_build(self):
        records = copy.deepcopy(fixture())
        for r in records:
            if r["build"] == "wasm-threads":
                r["build"] = "wasm-single"
        _, verdict = summarize.render(records, **SMALL)
        self.assertEqual(verdict, summarize.VERDICT_NOT_MET)
        _, verdict = summarize.render(records, build="wasm-single", **SMALL)
        self.assertEqual(verdict, summarize.VERDICT_MET)


class Table(unittest.TestCase):
    def test_table_rows_carry_the_statistics(self):
        report, _ = summarize.render(fixture(), **SMALL)
        row = next(
            line for line in report.splitlines()
            if line.startswith(f"| {A} | 2^1 | wasm-threads | emulated mid-range phone, not a real device |")
        )
        self.assertIn("| 2/4 |", row)
        self.assertIn("10.75 s / 12.50 s", row)
        self.assertIn("8.30 s / 8.60 s / 8.60 s", row)
        self.assertIn("146.5 KiB / 146.6 KiB", row)
        self.assertTrue(row.endswith("| 0 | no |"))
        self.assertIn("| Mac Studio |", report)


class Loading(unittest.TestCase):
    def test_directories_json_lists_and_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            records = fixture()
            (tmp / "one.json").write_text(json.dumps(records[:12]), encoding="utf-8")
            nested = tmp / "more"
            nested.mkdir()
            (nested / "rest.jsonl").write_text(
                "\n".join(json.dumps(r) for r in records[12:]) + "\n", encoding="utf-8"
            )
            self.assertEqual(len(summarize.load_records([str(tmp)])), len(records))
            out = tmp / "summary.md"
            code = summarize.main([str(tmp), "--min-cold", "2", "--min-warm", "4", "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertIn("Verdict: met", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
