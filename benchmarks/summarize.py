#!/usr/bin/env python3
"""Turn raw benchmark records into the results table and the verdict.

Reads JSON records (one object per line in ``.jsonl`` files, or a list or a
single object in ``.json`` files; directories are searched recursively) and
prints a Markdown table per configuration and device, followed by one plain
verdict line: ``met``, ``met on the Mac Studio only`` or ``not met``.

The rules are the plan's ("Reading the result"):

* Cold proving time: median and slowest of the cold runs (one per session).
* Warm proving time: median, 90th percentile (nearest rank) and slowest.
* Peak memory, proof size and verification time: median and largest.
* Whether any run failed.
* A configuration meets the 10-second target on a device when the median
  warm time and the slowest cold time are both 10 seconds or less, no run
  failed, and the full set of runs is present (five cold, fifty warm).
* The target is met only when both the Mac Studio and the emulated phone
  meet it. A pass on the Mac Studio alone is reported as "met on the Mac
  Studio only". Configurations without zero-knowledge mode, and native
  reference runs, never count.

Python 3 standard library only.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

TARGET_MS = 10_000.0
MAC = "mac-studio"
PHONE = "emulated-phone"
DEVICE_LABELS = {
    MAC: "Mac Studio",
    PHONE: "emulated mid-range phone, not a real device",
}
FAILED_OUTCOMES = {"failed", "killed", "out_of_memory"}
PRIMARY_BUILD = "wasm-threads"
VERDICT_MET = "met"
VERDICT_MAC_ONLY = "met on the Mac Studio only"
VERDICT_NOT_MET = "not met"


def load_records(paths: list[str]) -> list[dict]:
    """Read every record under the given files and directories."""
    records: list[dict] = []
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(p.rglob("*.jsonl")) + sorted(p.rglob("*.json")))
        else:
            files.append(p)
    for f in files:
        text = f.read_text(encoding="utf-8")
        if f.suffix == ".jsonl":
            for n, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        raise SystemExit(f"{f}:{n}: {e}") from e
        else:
            data = json.loads(text)
            records.extend(data if isinstance(data, list) else [data])
    return records


def median(xs: list[float]) -> float | None:
    return statistics.median(xs) if xs else None


def percentile(xs: list[float], p: float) -> float | None:
    """Nearest-rank percentile: the smallest value with at least p% at or below it."""
    if not xs:
        return None
    s = sorted(xs)
    rank = max(1, math.ceil(p / 100.0 * len(s)))
    return s[rank - 1]


def largest(xs: list[float]) -> float | None:
    return max(xs) if xs else None


def numbers(records: list[dict], key: str) -> list[float]:
    return [float(r[key]) for r in records if isinstance(r.get(key), (int, float)) and not isinstance(r.get(key), bool)]


@dataclass
class DeviceResult:
    device: str
    records: list[dict] = field(default_factory=list)

    @property
    def cold(self) -> list[dict]:
        return [r for r in self.records if r.get("run_kind") == "cold"]

    @property
    def warm(self) -> list[dict]:
        return [r for r in self.records if r.get("run_kind") == "warm"]

    @property
    def failures(self) -> int:
        return sum(1 for r in self.records if r.get("outcome") in FAILED_OUTCOMES)

    @property
    def refused(self) -> bool:
        return any(r.get("outcome") == "refused" for r in self.records)

    def stats(self) -> dict:
        done = [r for r in self.records if r.get("outcome") == "completed"]
        cold = numbers([r for r in self.cold if r.get("outcome") == "completed"], "proving_ms")
        warm = numbers([r for r in self.warm if r.get("outcome") == "completed"], "proving_ms")
        return {
            "cold_runs": len(self.cold),
            "warm_runs": len(self.warm),
            "cold_median": median(cold),
            "cold_slowest": largest(cold),
            "warm_median": median(warm),
            "warm_p90": percentile(warm, 90),
            "warm_slowest": largest(warm),
            "wasm_memory_median": median(numbers(done, "peak_wasm_memory_bytes")),
            "wasm_memory_largest": largest(numbers(done, "peak_wasm_memory_bytes")),
            "process_memory_median": median(numbers(done, "process_peak_memory_bytes")),
            "process_memory_largest": largest(numbers(done, "process_peak_memory_bytes")),
            "proof_median": median(numbers(done, "proof_bytes")),
            "proof_largest": largest(numbers(done, "proof_bytes")),
            "verify_median": median(numbers(done, "verification_ms")),
            "verify_largest": largest(numbers(done, "verification_ms")),
            "failures": self.failures,
        }

    def meets(self, min_cold: int, min_warm: int) -> bool:
        s = self.stats()
        return (
            not self.refused
            and s["failures"] == 0
            and s["cold_runs"] >= min_cold
            and s["warm_runs"] >= min_warm
            and s["cold_slowest"] is not None
            and s["warm_median"] is not None
            and s["cold_slowest"] <= TARGET_MS
            and s["warm_median"] <= TARGET_MS
        )


def counts_toward_target(r: dict) -> bool:
    return (
        r.get("build") != "native"
        and r.get("zero_knowledge") is True
        and r.get("counts_toward_target", True) is not False
        and not r.get("diagnostic", False)
        and r.get("device_class") in (MAC, PHONE)
    )


Key = tuple[str, int, str]


def group(records: list[dict]) -> tuple[dict[Key, dict[str, DeviceResult]], list[dict]]:
    """Group counted records by (candidate, log blowup, build) and device."""
    groups: dict[Key, dict[str, DeviceResult]] = {}
    excluded: list[dict] = []
    for r in records:
        if not counts_toward_target(r):
            excluded.append(r)
            continue
        key = (str(r.get("hash_candidate")), int(r.get("log_blowup", 0)), str(r.get("build")))
        devices = groups.setdefault(key, {})
        devices.setdefault(r["device_class"], DeviceResult(r["device_class"])).records.append(r)
    return groups, excluded


def config_verdict(devices: dict[str, DeviceResult], min_cold: int, min_warm: int) -> str:
    mac = devices.get(MAC)
    phone = devices.get(PHONE)
    mac_ok = mac is not None and mac.meets(min_cold, min_warm)
    phone_ok = phone is not None and phone.meets(min_cold, min_warm)
    if mac_ok and phone_ok:
        return VERDICT_MET
    if mac_ok:
        return VERDICT_MAC_ONLY
    return VERDICT_NOT_MET


def fmt_ms(x: float | None) -> str:
    return "-" if x is None else f"{x / 1000:.2f} s"


def fmt_bytes(x: float | None) -> str:
    if x is None:
        return "-"
    if x >= 1 << 20:
        return f"{x / (1 << 20):.1f} MiB"
    if x >= 1 << 10:
        return f"{x / (1 << 10):.1f} KiB"
    return f"{x:.0f} B"


def pair(a: str, b: str) -> str:
    return f"{a} / {b}"


def render(records: list[dict], build: str = PRIMARY_BUILD, min_cold: int = 5, min_warm: int = 50) -> tuple[str, str]:
    """Return (report text, verdict phrase)."""
    groups, excluded = group(records)
    lines = [
        "| Candidate | Blowup | Build | Device | Runs (cold/warm) | Cold median / slowest | "
        "Warm median / p90 / slowest | WASM memory median / largest | Process memory median / largest | "
        "Proof size median / largest | Verify median / largest | Failed runs | Meets target |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    verdicts: dict[Key, str] = {}
    for key in sorted(groups):
        candidate, log_blowup, b = key
        devices = groups[key]
        verdicts[key] = config_verdict(devices, min_cold, min_warm)
        for device in (MAC, PHONE):
            d = devices.get(device)
            if d is None:
                continue
            s = d.stats()
            meets = "refused" if d.refused else ("yes" if d.meets(min_cold, min_warm) else "no")
            lines.append(
                f"| {candidate} | 2^{log_blowup} | {b} | {DEVICE_LABELS[device]} | "
                f"{s['cold_runs']}/{s['warm_runs']} | "
                f"{pair(fmt_ms(s['cold_median']), fmt_ms(s['cold_slowest']))} | "
                f"{fmt_ms(s['warm_median'])} / {fmt_ms(s['warm_p90'])} / {fmt_ms(s['warm_slowest'])} | "
                f"{pair(fmt_bytes(s['wasm_memory_median']), fmt_bytes(s['wasm_memory_largest']))} | "
                f"{pair(fmt_bytes(s['process_memory_median']), fmt_bytes(s['process_memory_largest']))} | "
                f"{pair(fmt_bytes(s['proof_median']), fmt_bytes(s['proof_largest']))} | "
                f"{pair(fmt_ms(s['verify_median']), fmt_ms(s['verify_largest']))} | "
                f"{s['failures']} | {meets} |"
            )

    out = ["## Results", "", *lines, ""]
    out.append("Per configuration (both devices must meet the target):")
    out.append("")
    for key in sorted(verdicts):
        candidate, log_blowup, b = key
        out.append(f"- {candidate}, blowup 2^{log_blowup}, {b}: {verdicts[key]}")
    if not verdicts:
        out.append("- no browser measurements")
    out.append("")
    native = [r for r in excluded if r.get("build") == "native"]
    if native:
        out.append(f"{len(native)} native reference record(s) were read and are not counted toward the target.")
    other = len(excluded) - len(native)
    if other:
        out.append(f"{other} record(s) without zero-knowledge mode or outside the reference devices were not counted.")
    if native or other:
        out.append("")

    primary = {k: v for k, v in verdicts.items() if k[2] == build}
    if any(v == VERDICT_MET for v in primary.values()):
        verdict = VERDICT_MET
    elif any(v == VERDICT_MAC_ONLY for v in primary.values()):
        verdict = VERDICT_MAC_ONLY
    else:
        verdict = VERDICT_NOT_MET
    meeting = [f"{k[0]} blowup 2^{k[1]}" for k, v in sorted(primary.items()) if v == verdict and verdict != VERDICT_NOT_MET]
    detail = f" ({', '.join(meeting)})" if meeting else ("" if primary else f" (no {build} measurements)")
    out.append(f"Verdict: {verdict}{detail}")
    out.append("")
    out.append(
        "Security figures are conjectured estimates; the target is 128 conjectured bits, "
        "with the best proven figure recorded in each record beside it."
    )
    return "\n".join(out) + "\n", verdict


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", help="record files or directories")
    ap.add_argument("--build", default=PRIMARY_BUILD, help="build the verdict is judged on")
    ap.add_argument("--min-cold", type=int, default=5, help="cold runs required per device")
    ap.add_argument("--min-warm", type=int, default=50, help="warm runs required per device")
    ap.add_argument("--out", help="write the report here instead of standard output")
    args = ap.parse_args(argv)
    report, _ = render(load_records(args.paths), args.build, args.min_cold, args.min_warm)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
