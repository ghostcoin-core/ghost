"""Tests for benchmarks/scale/phone_records.py: the phone reveal record format.

Every record here is a synthetic sample written in the test; none is a
measurement, and no result file is read or written.
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "scale"))

import phone_records as pr  # noqa: E402

CONFIG = "keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk"
P2_CONFIG = "poseidon2-babybear-w24/hiding-fri/blowup-2^3/queries-38/grinding-q16-b0-o0/ext-5/zk"


def sample(**changes):
    record = {
        "device_model": "Sample Phone 7 (synthetic test record)",
        "os": "Android 16",
        "browser": "Chrome 155.0.8059.85",
        "device_kind": "physical",
        "threads_available": True,
        "thread_count": 8,
        "run_kind": "warm",
        "proof_seconds": 6.5,
        "peak_browser_memory_mib": 900.0,
        "proof_bytes": 958_275,
        "parameters": CONFIG,
        "hash_candidate": "keccak-256",
        "hash_construction": pr.KECCAK_SPONGE,
        "statement": "coin-reveal",
        "date": "2026-10-24",
        "memory_tool": "adb shell dumpsys meminfo",
    }
    record.update(changes)
    return record


def emulated(**changes):
    base = dict(
        device_model="emulated mid-range phone, not a real device",
        device_kind="emulated",
        os="macOS 27.0.1",
        proof_seconds=13.15,
        peak_browser_memory_mib=935.0,
        threads_available=True,
        thread_count=1,
    )
    base.update(changes)
    record = sample(**base)
    record.pop("memory_tool")
    return record


def session(make=sample, cold=5, warm=50, **changes):
    return [make(run_kind="cold", **changes) for _ in range(cold)] + [make(run_kind="warm", **changes) for _ in range(warm)]


class Validate(unittest.TestCase):
    def test_sample_is_valid(self):
        self.assertEqual(pr.problems(sample()), [])
        self.assertEqual(pr.problems(emulated()), [])

    def test_every_required_field(self):
        for name in pr.REQUIRED:
            with self.subTest(field=name):
                record = sample()
                del record[name]
                self.assertIn(f"missing field {name}", pr.problems(record))

    def test_physical_without_a_device_model(self):
        self.assertIn("missing field device_model", pr.problems({k: v for k, v in sample().items() if k != "device_model"}))
        self.assertTrue(pr.problems(sample(device_model="")))
        self.assertTrue(pr.problems(sample(device_model="   ")))
        self.assertIn("a physical record must name the phone, not an emulation",
                      pr.problems(sample(device_model="emulated mid-range phone, not a real device")))

    def test_physical_names_its_memory_tool(self):
        record = sample()
        del record["memory_tool"]
        self.assertTrue(any("memory_tool" in p for p in pr.problems(record)))

    def test_non_numeric_time(self):
        for bad in ("6.5", "6.5 s", None, True, float("nan"), float("inf"), -1, 0, [6.5]):
            with self.subTest(value=bad):
                self.assertTrue(any("proof_seconds" in p for p in pr.problems(sample(proof_seconds=bad))))
        self.assertTrue(pr.problems(sample(peak_browser_memory_mib="900 MiB")))
        self.assertTrue(pr.problems(sample(proof_bytes=958_275.5)))

    def test_failed_run_has_no_time(self):
        self.assertEqual(pr.problems(sample(outcome="out_of_memory", proof_seconds=None, proof_bytes=None)), [])
        self.assertTrue(pr.problems(sample(outcome="out_of_memory", proof_seconds=4.0)))
        self.assertTrue(pr.problems(sample(outcome="crashed")))

    def test_kind_must_be_stated(self):
        self.assertTrue(pr.problems(sample(device_kind="real")))
        self.assertIn("an emulated record's device_model must say it is emulated",
                      pr.problems(emulated(device_model="Sample Phone 7")))

    def test_construction_matches_the_statement(self):
        self.assertTrue(pr.problems(sample(hash_construction=pr.KECCAK_PADDED)))
        self.assertTrue(pr.problems(sample(hash_construction="sha3-256")))
        self.assertTrue(pr.problems(sample(hash_candidate="sha3-256", parameters=CONFIG.replace("keccak-256", "sha3-256"))))
        # No Poseidon2 prover of the real reveal exists.
        self.assertTrue(pr.problems(sample(hash_candidate="poseidon2-babybear-w24", parameters=P2_CONFIG, hash_construction=pr.POSEIDON2)))
        p2 = sample(statement=pr.BENCHMARK_STATEMENT, hash_candidate="poseidon2-babybear-w24", parameters=P2_CONFIG,
                    hash_construction=pr.POSEIDON2, thread_count=1, proof_bytes=251_672)
        self.assertEqual(pr.problems(p2), [])
        padded = sample(statement=pr.BENCHMARK_STATEMENT, hash_construction=pr.KECCAK_PADDED)
        self.assertEqual(pr.problems(padded), [])
        self.assertTrue(pr.problems(sample(statement=pr.BENCHMARK_STATEMENT)))

    def test_other_fields(self):
        self.assertTrue(pr.problems(sample(run_kind="hot")))
        self.assertTrue(pr.problems(sample(date="24/10/2026")))
        self.assertTrue(pr.problems(sample(date="2026-02-30")))
        self.assertTrue(pr.problems(sample(parameters="blowup 2^3, 43 queries")))
        self.assertTrue(pr.problems(sample(parameters=P2_CONFIG)))
        self.assertTrue(pr.problems(sample(threads_available="yes")))
        self.assertTrue(pr.problems(sample(threads_available=False, thread_count=8)))
        self.assertEqual(pr.problems(sample(threads_available=False, thread_count=1)), [])
        self.assertTrue(pr.problems("not an object"))


class Summary(unittest.TestCase):
    def test_emulated_and_physical_are_never_mixed(self):
        rows = pr.summarize(session() + session(emulated))
        self.assertEqual(len(rows), 2)
        by_kind = {r["device_kind"]: r for r in rows}
        self.assertEqual(by_kind["physical"]["warm_median"], 6.5)
        self.assertEqual(by_kind["emulated"]["warm_median"], 13.15)
        self.assertEqual(by_kind["emulated"]["label"], "emulated, not a real device")
        self.assertIsNone(by_kind["emulated"]["meets_ceilings"])
        self.assertTrue(by_kind["physical"]["meets_ceilings"])
        self.assertEqual(by_kind["physical"]["label"], "measured on Sample Phone 7 (synthetic test record)")

    def test_an_emulation_claiming_to_be_physical_is_refused(self):
        bad = emulated(device_kind="physical", memory_tool="macOS footprint")
        with self.assertRaises(ValueError):
            pr.summarize(session() + [bad])

    def test_rows_split_by_thread_mode_and_candidate(self):
        single = session(threads_available=False, thread_count=1, proof_seconds=12.0)
        p2 = session(statement=pr.BENCHMARK_STATEMENT, hash_candidate="poseidon2-babybear-w24", parameters=P2_CONFIG,
                     hash_construction=pr.POSEIDON2, thread_count=1, proof_seconds=1.9, peak_browser_memory_mib=80.0)
        rows = pr.summarize(session() + single + p2)
        self.assertEqual(sorted(r["thread_mode"] for r in rows), ["8 threads", "one thread, threads available", "threads unavailable"])
        unavailable = next(r for r in rows if r["thread_mode"] == "threads unavailable")
        self.assertFalse(unavailable["meets_ceilings"])

    def test_ceilings(self):
        self.assertFalse(pr.summarize(session(peak_browser_memory_mib=1_100.0))[0]["meets_ceilings"])
        slow_cold = session(cold=0) + [sample(run_kind="cold", proof_seconds=10.5)] + [sample(run_kind="cold")] * 4
        self.assertFalse(pr.summarize(slow_cold)[0]["meets_ceilings"])
        self.assertFalse(pr.summarize(session(warm=49))[0]["meets_ceilings"])
        failed = session() + [sample(outcome="killed", proof_seconds=None)]
        row = pr.summarize(failed)[0]
        self.assertEqual(row["failed_runs"], 1)
        self.assertFalse(row["meets_ceilings"])

    def test_ceilings_match_workload(self):
        text = (REPO / "docs" / "scale" / "workload.md").read_text(encoding="utf-8")
        self.assertIn("| Proving time ceiling | 10 s for one reveal, cold or warm |", text)
        self.assertIn("| Memory ceiling | proposed 1 GiB for the whole tab |", text)
        self.assertEqual(pr.PROOF_SECONDS_CEILING, 10.0)
        self.assertEqual(pr.BROWSER_MEMORY_CEILING_MIB, 1024.0)

    def test_render(self):
        text = pr.render(pr.summarize(session() + session(emulated)))
        self.assertIn("not judged: emulated", text)
        self.assertIn("| yes |", text)
        self.assertEqual(len(text.strip().splitlines()), 4)


class Convert(unittest.TestCase):
    HARNESS = {
        "device_class": "mac-studio",
        "device": "Mac Studio (Apple M5 Max, 64 GB)",
        "threads_available": True,
        "hash_candidate": "keccak-256",
        "configuration": CONFIG,
        "statement": "coin-reveal",
        "build": "wasm-threads",
        "threads_used": True,
        "thread_count": 8,
        "run_kind": "cold",
        "start_time_unix_ms": 1_792_800_000_000,
        "proving_ms": 7_250.0,
        "peak_wasm_memory_bytes": 660_733_952,
        "total_bytes": 1_311_067,
        "outcome": "completed",
    }

    def test_harness_device_label_is_replaced(self):
        r = pr.from_harness(self.HARNESS, "physical", "Sample Phone 7 (synthetic test record)", "Android 16",
                            "Chrome 155.0.8059.85", 1_010.5, "adb shell dumpsys meminfo")
        self.assertEqual(pr.problems(r), [])
        self.assertEqual(r["proof_seconds"], 7.25)
        self.assertEqual(r["hash_construction"], pr.KECCAK_SPONGE)
        self.assertEqual(r["date"], "2026-10-24")
        self.assertEqual(r["wasm_memory_mib"], 630.125)
        self.assertNotIn("Mac Studio", json.dumps(r))

    def test_single_thread_and_benchmark_pages(self):
        single = dict(self.HARNESS, build="wasm-single", threads_used=False, threads_available=False)
        del single["thread_count"]
        r = pr.from_harness(single, "physical", "Sample Phone 7", "Android 16", "Chrome 155", 700.0, "dumpsys")
        self.assertEqual(r["thread_count"], 1)
        self.assertEqual(pr.problems(r), [])
        bench = {k: v for k, v in self.HARNESS.items() if k not in ("statement", "thread_count")}
        bench.update(hash_candidate="poseidon2-babybear-w24", configuration=P2_CONFIG, proof_bytes=251_672, threads_used=False)
        r = pr.from_harness(bench, "physical", "Sample Phone 7", "Android 16", "Chrome 155", 80.0, "dumpsys")
        self.assertEqual(r["statement"], pr.BENCHMARK_STATEMENT)
        self.assertEqual(r["hash_construction"], pr.POSEIDON2)
        self.assertEqual(pr.problems(r), [])

    def test_command_line(self):
        with tempfile.TemporaryDirectory() as d:
            harness = Path(d) / "harness.jsonl"
            harness.write_text(json.dumps(self.HARNESS) + "\n", encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = pr.main(["convert", "--kind", "physical", "--device-model", "Sample Phone 7", "--os", "Android 16",
                                "--browser", "Chrome 155", "--memory-mib", "990", "--memory-tool", "dumpsys", str(harness)])
            self.assertEqual(code, 0)
            converted = Path(d) / "phone.jsonl"
            converted.write_text(out.getvalue(), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pr.main(["validate", str(converted)]), 0)
            with contextlib.redirect_stderr(io.StringIO()):
                code = pr.main(["convert", "--kind", "physical", "--device-model", "", "--os", "Android 16",
                                "--browser", "Chrome 155", "--memory-mib", "990", "--memory-tool", "dumpsys", str(harness)])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
