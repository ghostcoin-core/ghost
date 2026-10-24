"""Validate and summarize phone reveal records: one JSON object per line, one line per proof.

A record names the device and whether it is a physical phone or an emulation,
the browser, the thread mode, the run kind, the proof time, the peak memory
of the whole browser read from the platform's tool, the proof size, the proof
parameters, the hash candidate and the exact hash construction behind it, and
the date. Emulated and physical records are never summarized together: every
summary row is one device of one kind, and only physical rows are judged
against the reference phone ceilings of docs/scale/workload.md.

Usage:
  python3 benchmarks/scale/phone_records.py validate FILE...
  python3 benchmarks/scale/phone_records.py summarize FILE...
  python3 benchmarks/scale/phone_records.py convert --kind physical \\
      --device-model "MODEL" --os "OS VERSION" --browser "BROWSER VERSION" \\
      --memory-mib PEAK --memory-tool "TOOL" HARNESS.jsonl

`convert` turns the records the browser harness writes (benchmarks/web/,
through drive-reveal.mjs or a page's Download records button) into phone
records on standard output. Python 3 standard library only.
"""

import argparse
import datetime
import json
import math
import re
import statistics
import sys

PHYSICAL = "physical"
EMULATED = "emulated"
KINDS = (PHYSICAL, EMULATED)
RUN_KINDS = ("cold", "warm")
COMPLETED = "completed"
OUTCOMES = (COMPLETED, "failed", "killed", "out_of_memory", "refused")

# The exact constructions behind each hash candidate (designs.md, rule 3).
# Neither Keccak construction is NIST SHA3-256.
KECCAK_SPONGE = "keccak-f1600-padding-free-sponge"
KECCAK_PADDED = "keccak-256-padded"
POSEIDON2 = "poseidon2-babybear-width-24"
CONSTRUCTIONS = {
    KECCAK_SPONGE: "Keccak-f[1600] in the padding-free sponge of proofs/src/stark.rs (the real reveal prover)",
    KECCAK_PADDED: "padded Keccak-256 of benchmarks/prover/src/keccak.rs (the benchmark statement)",
    POSEIDON2: "Poseidon2 over BabyBear, width 24, of benchmarks/prover (the benchmark statement)",
}
# Statement, hash candidate -> the only construction that statement uses.
REAL_STATEMENTS = ("coin-reveal", "salted-coin-reveal")
BENCHMARK_STATEMENT = "benchmark-statement"
EXPECTED_CONSTRUCTION = {
    ("coin-reveal", "keccak-256"): KECCAK_SPONGE,
    ("salted-coin-reveal", "keccak-256"): KECCAK_SPONGE,
    (BENCHMARK_STATEMENT, "keccak-256"): KECCAK_PADDED,
    (BENCHMARK_STATEMENT, "poseidon2-babybear-w24"): POSEIDON2,
}

REQUIRED = {
    "device_model": str,
    "os": str,
    "browser": str,
    "device_kind": str,
    "threads_available": bool,
    "run_kind": str,
    "proof_seconds": float,
    "peak_browser_memory_mib": float,
    "proof_bytes": int,
    "parameters": str,
    "hash_candidate": str,
    "hash_construction": str,
    "statement": str,
    "date": str,
}
PARAMETERS = re.compile(r"^[a-z0-9-]+/hiding-fri/blowup-2\^\d+/queries-\d+/grinding-q\d+-b\d+-o\d+/ext-\d+/zk$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Reference phone ceilings (docs/scale/workload.md, Reference phone).
PROOF_SECONDS_CEILING = 10.0
BROWSER_MEMORY_CEILING_MIB = 1024.0
# The protocol's runs per device and mode: five sessions of one cold and ten warm proofs.
MIN_COLD = 5
MIN_WARM = 50


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def problems(record):
    """Everything wrong with one record; empty when it is valid."""
    if not isinstance(record, dict):
        return ["a record must be a JSON object"]
    out = []
    outcome = record.get("outcome", COMPLETED)
    if outcome not in OUTCOMES:
        out.append(f"outcome must be one of {', '.join(OUTCOMES)}")
    for name, kind in REQUIRED.items():
        if name not in record:
            out.append(f"missing field {name}")
            continue
        value = record[name]
        if name == "proof_seconds" and outcome != COMPLETED:
            if value is not None:
                out.append("proof_seconds must be null for a run that did not complete")
            continue
        if name == "proof_bytes" and outcome != COMPLETED and value is None:
            continue
        if kind is float:
            if not _is_number(value) or value <= 0:
                out.append(f"{name} must be a positive number, got {value!r}")
        elif kind is int:
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                out.append(f"{name} must be a positive whole number, got {value!r}")
        elif kind is bool:
            if not isinstance(value, bool):
                out.append(f"{name} must be true or false, got {value!r}")
        elif not isinstance(value, str) or not value.strip():
            out.append(f"{name} must be a non-empty string, got {value!r}")
    if out:
        return out

    kind = record["device_kind"]
    model = record["device_model"]
    if kind not in KINDS:
        out.append(f"device_kind must be physical or emulated, got {kind!r}")
    elif kind == PHYSICAL:
        if "emulated" in model.lower() or "not a real device" in model.lower():
            out.append("a physical record must name the phone, not an emulation")
        if not str(record.get("memory_tool", "")).strip():
            out.append("a physical record must name the platform tool that read the browser's memory (memory_tool)")
    elif "emulated" not in model.lower():
        out.append("an emulated record's device_model must say it is emulated")
    if record["run_kind"] not in RUN_KINDS:
        out.append(f"run_kind must be cold or warm, got {record['run_kind']!r}")
    if not PARAMETERS.match(record["parameters"]):
        out.append(f"parameters is not a configuration string: {record['parameters']!r}")
    elif not record["parameters"].startswith(record["hash_candidate"] + "/"):
        out.append("parameters must start with the hash candidate")
    if "sha3" in record["hash_candidate"].lower() or "sha3" in record["hash_construction"].lower():
        out.append("no statement here uses NIST SHA3-256")
    expected = EXPECTED_CONSTRUCTION.get((record["statement"], record["hash_candidate"]))
    if expected is None:
        out.append(f"no {record['hash_candidate']} prover exists for statement {record['statement']!r}")
    elif record["hash_construction"] != expected:
        out.append(f"{record['statement']} with {record['hash_candidate']} uses {expected}, not {record['hash_construction']!r}")
    if not DATE.match(record["date"]):
        out.append(f"date must be YYYY-MM-DD, got {record['date']!r}")
    else:
        try:
            datetime.date.fromisoformat(record["date"])
        except ValueError:
            out.append(f"date is not a calendar date: {record['date']!r}")
    threads = record.get("thread_count", 1)
    if not isinstance(threads, int) or isinstance(threads, bool) or threads < 1:
        out.append(f"thread_count must be a whole number of at least 1, got {threads!r}")
    elif not record["threads_available"] and threads != 1:
        out.append("a run with threads unavailable proves on one thread")
    return out


def validate(records):
    """(index, problem) for every problem of every record."""
    return [(i, p) for i, r in enumerate(records) for p in problems(r)]


def load(paths):
    records = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        raise SystemExit(f"{path}:{n}: {e}") from e
    return records


def thread_mode(record):
    if not record["threads_available"]:
        return "threads unavailable"
    n = record.get("thread_count", 1)
    return f"{n} threads" if n > 1 else "one thread, threads available"


def summarize(records):
    """One row per device, kind, statement, candidate, parameters and thread mode.

    Raises ValueError on an invalid record, so an unlabelled emulation can
    never be read as a phone. A physical row is judged against the ceilings;
    an emulated row never is.
    """
    bad = validate(records)
    if bad:
        raise ValueError("; ".join(f"record {i}: {p}" for i, p in bad))
    groups = {}
    for r in records:
        key = (r["device_kind"], r["device_model"], r["os"], r["browser"], r["statement"],
               r["hash_candidate"], r["hash_construction"], r["parameters"], thread_mode(r))
        groups.setdefault(key, []).append(r)
    rows = []
    for key in sorted(groups):
        kind, model, os_name, browser, statement, candidate, construction, parameters, mode = key
        rs = groups[key]
        done = [r for r in rs if r.get("outcome", COMPLETED) == COMPLETED]
        cold = [r["proof_seconds"] for r in done if r["run_kind"] == "cold"]
        warm = [r["proof_seconds"] for r in done if r["run_kind"] == "warm"]
        memory = [r["peak_browser_memory_mib"] for r in rs]
        row = {
            "device_kind": kind,
            "label": f"measured on {model}" if kind == PHYSICAL else "emulated, not a real device",
            "device_model": model,
            "os": os_name,
            "browser": browser,
            "statement": statement,
            "hash_candidate": candidate,
            "hash_construction": construction,
            "parameters": parameters,
            "thread_mode": mode,
            "cold_runs": sum(1 for r in rs if r["run_kind"] == "cold"),
            "warm_runs": sum(1 for r in rs if r["run_kind"] == "warm"),
            "failed_runs": len(rs) - len(done),
            "cold_median": statistics.median(cold) if cold else None,
            "cold_slowest": max(cold) if cold else None,
            "warm_median": statistics.median(warm) if warm else None,
            "warm_slowest": max(warm) if warm else None,
            "peak_memory_mib": max(memory),
            "dates": sorted({r["date"] for r in rs}),
        }
        row["meets_ceilings"] = judge(row) if kind == PHYSICAL else None
        rows.append(row)
    return rows


def judge(row):
    """Pass or fail of a physical row against the reference phone ceilings."""
    return (
        row["failed_runs"] == 0
        and row["cold_runs"] >= MIN_COLD
        and row["warm_runs"] >= MIN_WARM
        and row["cold_slowest"] is not None
        and row["warm_median"] is not None
        and row["cold_slowest"] <= PROOF_SECONDS_CEILING
        and row["warm_median"] <= PROOF_SECONDS_CEILING
        and row["peak_memory_mib"] <= BROWSER_MEMORY_CEILING_MIB
    )


def _s(x):
    return "-" if x is None else f"{x:.2f} s"


def render(rows):
    lines = [
        "| Label | Device | OS | Browser | Statement | Hash construction | Parameters | Thread mode | "
        "Runs (cold/warm) | Cold median / slowest | Warm median / slowest | Peak browser memory | Failed | Meets the ceilings |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        verdict = {True: "yes", False: "no", None: "not judged: emulated"}[r["meets_ceilings"]]
        lines.append(
            f"| {r['label']} | {r['device_model']} | {r['os']} | {r['browser']} | {r['statement']} | "
            f"{r['hash_construction']} | `{r['parameters']}` | {r['thread_mode']} | "
            f"{r['cold_runs']}/{r['warm_runs']} | {_s(r['cold_median'])} / {_s(r['cold_slowest'])} | "
            f"{_s(r['warm_median'])} / {_s(r['warm_slowest'])} | {r['peak_memory_mib']:.1f} MiB | "
            f"{r['failed_runs']} | {verdict} |"
        )
    return "\n".join(lines) + "\n"


def from_harness(record, kind, device_model, os_name, browser, memory_mib, memory_tool=None, date=None):
    """A phone record from one record of the browser harness (benchmarks/web/).

    The harness labels its device as the Mac Studio or the emulated phone; that
    label is replaced by the device given here. Its WebAssembly memory is not
    the whole browser's and is kept apart, as wasm_memory_mib.
    """
    statement = record.get("statement") or BENCHMARK_STATEMENT
    candidate = record.get("hash_candidate")
    if date is None and record.get("start_time_unix_ms") is not None:
        date = datetime.datetime.fromtimestamp(record["start_time_unix_ms"] / 1000, datetime.timezone.utc).date().isoformat()
    outcome = record.get("outcome", COMPLETED)
    proving = record.get("proving_ms")
    out = {
        "device_model": device_model,
        "os": os_name,
        "browser": browser,
        "device_kind": kind,
        "threads_available": bool(record.get("threads_available")),
        "thread_count": record.get("thread_count") or (1 if not record.get("threads_used") else None),
        "run_kind": record.get("run_kind"),
        "outcome": outcome,
        "proof_seconds": proving / 1000 if outcome == COMPLETED and _is_number(proving) else None,
        "peak_browser_memory_mib": memory_mib,
        "proof_bytes": record.get("proof_bytes") or record.get("total_bytes"),
        "parameters": record.get("configuration"),
        "hash_candidate": candidate,
        "hash_construction": EXPECTED_CONSTRUCTION.get((statement, candidate)),
        "statement": statement,
        "date": date,
        "build": record.get("build"),
        "harness_user_agent": record.get("user_agent"),
        "repository_commit": record.get("repository_commit"),
    }
    if not record.get("threads_available") and out["thread_count"] is None:
        out["thread_count"] = 1
    if "proof_bytes" not in record and "total_bytes" in record:
        out["proof_bytes_source"] = "total_bytes: the padded envelope the module returns"
    if _is_number(record.get("peak_wasm_memory_bytes")):
        out["wasm_memory_mib"] = record["peak_wasm_memory_bytes"] / (1 << 20)
    if memory_tool:
        out["memory_tool"] = memory_tool
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="check every record")
    v.add_argument("paths", nargs="+")
    s = sub.add_parser("summarize", help="print the summary table")
    s.add_argument("paths", nargs="+")
    c = sub.add_parser("convert", help="turn harness records into phone records on standard output")
    c.add_argument("paths", nargs="+")
    c.add_argument("--kind", choices=KINDS, required=True)
    c.add_argument("--device-model", required=True)
    c.add_argument("--os", required=True)
    c.add_argument("--browser", required=True)
    c.add_argument("--memory-mib", type=float, required=True, help="peak memory of the whole browser in the session")
    c.add_argument("--memory-tool", help="the platform tool that read it")
    c.add_argument("--date", help="YYYY-MM-DD; default: from each record's start time")
    args = ap.parse_args(argv)
    records = load(args.paths)
    if args.command == "convert":
        records = [from_harness(r, args.kind, args.device_model, args.os, args.browser,
                                args.memory_mib, args.memory_tool, args.date) for r in records]
    bad = validate(records)
    for i, p in bad:
        print(f"record {i}: {p}", file=sys.stderr)
    if bad:
        return 1
    if args.command == "convert":
        for r in records:
            print(json.dumps(r))
    elif args.command == "summarize":
        sys.stdout.write(render(summarize(records)))
    else:
        print(f"{len(records)} record(s) valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
