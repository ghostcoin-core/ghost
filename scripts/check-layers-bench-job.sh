#!/usr/bin/env bash
# Checks that .github/workflows/ci.yml runs the layers benchmark's tests
# (proofs/tests/layers_bench.rs) in a job of their own,
# rust-proofs-layers-bench, and not in rust-proofs-layers-rest: its small
# benchmark proves a small batch, root and shrink, and with it
# rust-proofs-layers-rest ran past its 10-minute limit.
#
# rust-proofs-layers-bench must:
#   - run on the GitHub-hosted ubuntu-24.04 image with timeout-minutes: 10;
#   - use the toolchain (RUST_TOOLCHAIN), RUSTFLAGS and cache key of
#     rust-proofs-layers-rest;
#   - run exactly `cargo test --release --locked --manifest-path
#     proofs/Cargo.toml --test layers_bench`: no features, as the other
#     layers jobs, and no --ignored, so the real-shape benchmark stays
#     ignored.
# No other job may run --test layers_bench.
#
# It then checks itself: copies of the workflow broken in each of those ways
# must fail the same check.
#
# Usage: scripts/check-layers-bench-job.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
workflow="$root/.github/workflows/ci.yml"

bench_job=rust-proofs-layers-bench
rest_job=rust-proofs-layers-rest
bench_run='cargo test --release --locked --manifest-path proofs/Cargo.toml --test layers_bench'

# job_ids WORKFLOW: the ids of WORKFLOW's jobs, one a line.
job_ids() {
  awk '
    /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
    in_jobs && /^[^[:space:]#]/ { in_jobs = 0 }
    in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
      id = $1
      sub(/:$/, "", id)
      print id
    }
  ' "$1"
}

# job_block WORKFLOW ID: the lines of job ID, its header and comment lines
# excluded.
job_block() {
  awk -v id="$2" '
    /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
    in_jobs && /^[^[:space:]#]/ { in_jobs = 0; inside = 0 }
    in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
      header = $1
      sub(/:$/, "", header)
      inside = (header == id)
      next
    }
    /^[[:space:]]*#/ { next }
    inside { print }
  ' "$1"
}

# value BLOCK PATTERN: the text after PATTERN on BLOCK's lines that match it.
value() {
  sed -n -E "s/^$2(.*[^[:space:]])[[:space:]]*\$/\\1/p" <<<"$1"
}

# runs_bench BLOCK: BLOCK's lines that run the layers_bench test file.
runs_bench() {
  grep -E -- '--test[[:space:]]+layers_bench([[:space:]]|$)' <<<"$1" || true
}

# check_workflow WORKFLOW: prints every problem and returns 1 if there is
# one.
check_workflow() {
  local wf="$1"
  local failed=0
  local ids id block rest bench runs field

  ids="$(job_ids "$wf")"
  if ! grep -qxF "$rest_job" <<<"$ids"; then
    echo "check-layers-bench-job: $wf has no job $rest_job" >&2
    return 1
  fi
  if ! grep -qxF "$bench_job" <<<"$ids"; then
    echo "check-layers-bench-job: $wf has no job $bench_job" >&2
    return 1
  fi
  rest="$(job_block "$wf" "$rest_job")"
  bench="$(job_block "$wf" "$bench_job")"

  # layers_bench runs in no job but its own, rust-proofs-layers-rest above all.
  while IFS= read -r id; do
    [ -n "$id" ] && [ "$id" != "$bench_job" ] || continue
    block="$(job_block "$wf" "$id")"
    if [ -n "$(runs_bench "$block")" ]; then
      echo "check-layers-bench-job: job $id runs --test layers_bench; it runs only in $bench_job" >&2
      failed=1
    fi
  done <<<"$ids"

  if ! grep -Eq '^    runs-on: ubuntu-24\.04[[:space:]]*$' <<<"$bench"; then
    echo "check-layers-bench-job: job $bench_job does not run on ubuntu-24.04" >&2
    failed=1
  fi
  if [ "$(value "$bench" '    timeout-minutes: ')" != 10 ]; then
    echo "check-layers-bench-job: job $bench_job does not have timeout-minutes: 10" >&2
    failed=1
  fi
  for field in '      RUST_TOOLCHAIN: ' '      RUSTFLAGS: ' '          key: '; do
    if [ "$(value "$bench" "$field")" != "$(value "$rest" "$field")" ]; then
      echo "check-layers-bench-job: job $bench_job does not have the ${field//[: ]/} of $rest_job" >&2
      failed=1
    fi
  done
  if [ -z "$(value "$rest" '      RUST_TOOLCHAIN: ')" ]; then
    echo "check-layers-bench-job: job $rest_job sets no RUST_TOOLCHAIN to compare with" >&2
    failed=1
  fi
  if ! grep -Eq '^          RUSTUP_TOOLCHAIN: \$\{\{ env\.RUST_TOOLCHAIN \}\}[[:space:]]*$' <<<"$bench"; then
    echo "check-layers-bench-job: job $bench_job does not test with RUSTUP_TOOLCHAIN: \${{ env.RUST_TOOLCHAIN }}" >&2
    failed=1
  fi

  runs="$(runs_bench "$bench")"
  if [ -z "$runs" ]; then
    echo "check-layers-bench-job: job $bench_job does not run --test layers_bench" >&2
    failed=1
  elif [ "$(grep -c . <<<"$runs")" -ne 1 ]; then
    echo "check-layers-bench-job: job $bench_job runs layers_bench more than once" >&2
    failed=1
  elif [ "$(value "$runs" '[[:space:]]*-?[[:space:]]*run: ')" != "$bench_run" ]; then
    echo "check-layers-bench-job: job $bench_job does not run exactly: $bench_run" >&2
    failed=1
  fi

  return "$failed"
}

if ! check_workflow "$workflow"; then
  echo "check-layers-bench-job: FAILED" >&2
  exit 1
fi

# Self-check: each broken copy of the workflow must fail the check above.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# must_refuse WHAT SED_SCRIPT: a copy of the workflow edited by SED_SCRIPT
# must differ from it and fail the check.
must_refuse() {
  local what="$1" script="$2"
  sed -E "$script" "$workflow" >"$tmp/ci.yml"
  if cmp -s "$workflow" "$tmp/ci.yml"; then
    echo "check-layers-bench-job: self-check could not make a workflow that $what" >&2
    exit 1
  fi
  if check_workflow "$tmp/ci.yml" 2>/dev/null; then
    echo "check-layers-bench-job: a workflow that $what passed the check" >&2
    exit 1
  fi
}

in_bench="/^  $bench_job:/,/^  [A-Za-z]/"
in_rest="/^  $rest_job:/,/^  [A-Za-z]/"

must_refuse "runs layers_bench in $rest_job" "${in_rest}s/--test layers_results/--test layers_results --test layers_bench/"
must_refuse "runs layers_bench in $rest_job and drops $bench_job" "${in_rest}s/--test layers_results/--test layers_results --test layers_bench/; ${in_bench}{/--test layers_bench/d}"
must_refuse "has no job $bench_job" "s/^  $bench_job:/  $bench_job-old:/"
must_refuse "runs no layers_bench test in $bench_job" "${in_bench}s/--test layers_bench/--test layers_benches/"
must_refuse "runs the ignored benchmark in $bench_job" "${in_bench}s/--test layers_bench\$/--test layers_bench -- --ignored --nocapture/"
must_refuse "runs $bench_job with the parallel feature" "${in_bench}s/--locked --manifest-path/--locked --features parallel --manifest-path/"
must_refuse "runs $bench_job on another image" "${in_bench}s/^(    runs-on: )ubuntu-24\\.04/\\1ubuntu-22.04/"
must_refuse "gives $bench_job a longer limit" "${in_bench}s/^(    timeout-minutes: )10/\\120/"
must_refuse "gives $bench_job no limit" "${in_bench}{/^    timeout-minutes:/d}"
must_refuse "builds $bench_job with another toolchain" "${in_bench}s/^(      RUST_TOOLCHAIN: ).*/\\11.98.0/"
must_refuse "builds $bench_job with other RUSTFLAGS" "${in_bench}s/^(      RUST_TOOLCHAIN: .*)/\\1\\n      RUSTFLAGS: -C target-feature=+avx2/"
must_refuse "gives $bench_job another cache key" "${in_bench}s/^(          key: .*)-proofs-layers-/\\1-proofs-bench-/"

echo "check-layers-bench-job: layers_bench runs in $bench_job alone, not in $rest_job"
