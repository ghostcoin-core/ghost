#!/usr/bin/env bash
# Checks that .github/workflows/ci.yml derives the production root keys after
# every merge: one or more jobs run the ignored tests of
# proofs/tests/production_root_keys.rs with `-- --ignored --nocapture`, so a
# change that alters a key without re-pinning it turns main red.
#
# Every job that runs that test file must:
#   - run only on a push (to main, the workflow's only push branch), never on
#     a pull request: `if: github.event_name == 'push'`;
#   - run on the GitHub-hosted ubuntu-24.04 image with timeout-minutes: 30
#     (a release build and one derivation do not fit 10 minutes on a hosted
#     4-core runner; the 10-minute target is for pull request checks, and
#     these jobs run only after merge);
#   - build with AVX2 (RUSTFLAGS: -C target-feature=+avx2): built scalar, the
#     build and a derivation together run far longer;
#   - run `cargo test --release --locked --manifest-path proofs/Cargo.toml
#     --test production_root_keys -- --ignored --nocapture --exact` followed
#     only by test names and `--skip NAME`;
#   - select at least one ignored test.
# Every ignored test of the file must be selected by one of those jobs, both
# key derivations among them, and no one job derives both keys (each takes
# minutes, and together they would not fit one job's limit).
#
# It then checks itself: copies of the workflow with the job broken in each
# of those ways must fail the same check.
#
# Usage: scripts/check-production-root-keys-job.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
workflow="$root/.github/workflows/ci.yml"
test_file="$root/proofs/tests/production_root_keys.rs"

# The two derivation tests, one a key.
derivations=(derive_production_bundle_root_key derive_production_public_root_key)

# ignored_tests FILE: the names of FILE's #[ignore]d test functions, one a
# line. An attribute (#[test], #[ignore ...]) may come in either order before
# the function.
ignored_tests() {
  awk '
    /^[[:space:]]*#\[ignore/ { pending = 1; next }
    /^[[:space:]]*#\[/ { next }
    pending && /^[[:space:]]*(pub[[:space:]]+)?fn[[:space:]]/ {
      name = $0
      sub(/^[[:space:]]*(pub[[:space:]]+)?fn[[:space:]]+/, "", name)
      sub(/[^A-Za-z0-9_].*$/, "", name)
      print name
    }
    { pending = 0 }
  ' "$1"
}

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

# job_block WORKFLOW ID: the lines of job ID, its header excluded.
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
    inside { print }
  ' "$1"
}

# in_list WORD LIST...: whether WORD is one of LIST.
in_list() {
  local word="$1" item
  shift
  for item in "$@"; do
    if [ "$item" = "$word" ]; then
      return 0
    fi
  done
  return 1
}

# check_workflow WORKFLOW TEST_FILE: prints every problem and returns 1 if
# there is one.
check_workflow() {
  local wf="$1" tests_rs="$2"
  local failed=0
  local ignored=() jobs=() covered=()
  local name id block runs line harness word timeout i
  local filters skips words selected derived

  while IFS= read -r name; do
    [ -n "$name" ] && ignored+=("$name")
  done < <(ignored_tests "$tests_rs")
  for name in "${derivations[@]}"; do
    if ! in_list "$name" "${ignored[@]}"; then
      echo "check-production-root-keys-job: $tests_rs has no ignored test $name" >&2
      failed=1
    fi
  done

  # The workflow runs on a push to main.
  if ! grep -A1 -E '^  push:[[:space:]]*$' "$wf" | grep -Eq '^    branches: \[main\][[:space:]]*$'; then
    echo "check-production-root-keys-job: $wf does not run on a push to main" >&2
    failed=1
  fi

  while IFS= read -r id; do
    [ -n "$id" ] || continue
    block="$(job_block "$wf" "$id")"
    runs="$(grep -E -- '--test production_root_keys([[:space:]]|$)' <<<"$block" || true)"
    [ -n "$runs" ] || continue
    jobs+=("$id")

    if [ "$(grep -c . <<<"$runs")" -ne 1 ]; then
      echo "check-production-root-keys-job: job $id runs production_root_keys more than once" >&2
      failed=1
      continue
    fi
    line="$runs"

    if ! grep -Eq "^    if: github\\.event_name == 'push'[[:space:]]*$" <<<"$block"; then
      echo "check-production-root-keys-job: job $id does not run only after merge (if: github.event_name == 'push')" >&2
      failed=1
    fi
    if ! grep -Eq '^    runs-on: ubuntu-24\.04[[:space:]]*$' <<<"$block"; then
      echo "check-production-root-keys-job: job $id does not run on ubuntu-24.04" >&2
      failed=1
    fi
    timeout="$(sed -n -E 's/^    timeout-minutes: ([0-9]+)[[:space:]]*$/\1/p' <<<"$block")"
    if [ "$timeout" != 30 ]; then
      echo "check-production-root-keys-job: job $id does not have timeout-minutes: 30" >&2
      failed=1
    fi
    if ! grep -Eq '^      RUSTFLAGS: -C target-feature=\+avx2[[:space:]]*$' <<<"$block"; then
      echo "check-production-root-keys-job: job $id does not build with AVX2 (RUSTFLAGS: -C target-feature=+avx2); without it the derivation runs past its limit" >&2
      failed=1
    fi
    if ! grep -Eq '^[[:space:]]*(- )?run: cargo test --release --locked( --features [a-z,-]+)? --manifest-path proofs/Cargo\.toml --test production_root_keys -- --ignored --nocapture --exact( |$)' <<<"$line"; then
      echo "check-production-root-keys-job: job $id does not run: cargo test --release --locked --manifest-path proofs/Cargo.toml --test production_root_keys -- --ignored --nocapture --exact" >&2
      failed=1
      continue
    fi

    # The harness arguments after --exact: test names and --skip NAME.
    harness="${line#*-- --ignored --nocapture --exact}"
    filters=()
    skips=()
    read -r -a words <<<"$harness"
    i=0
    while [ "$i" -lt "${#words[@]}" ]; do
      word="${words[$i]}"
      case "$word" in
        --skip)
          i=$((i + 1))
          if [ "$i" -ge "${#words[@]}" ]; then
            echo "check-production-root-keys-job: job $id has --skip without a name" >&2
            failed=1
          else
            skips+=("${words[$i]}")
          fi
          ;;
        -*)
          echo "check-production-root-keys-job: job $id passes $word to the tests; only names and --skip NAME may follow --exact" >&2
          failed=1
          ;;
        *) filters+=("$word") ;;
      esac
      i=$((i + 1))
    done

    # The ignored tests this job runs, as the test harness selects them with
    # --exact: a name equal to a filter (or every name when there is none),
    # and not equal to a skip.
    selected=0
    derived=0
    for name in "${ignored[@]}"; do
      if [ "${#filters[@]}" -gt 0 ] && ! in_list "$name" "${filters[@]}"; then
        continue
      fi
      if [ "${#skips[@]}" -gt 0 ] && in_list "$name" "${skips[@]}"; then
        continue
      fi
      selected=$((selected + 1))
      covered+=("$name")
      if in_list "$name" "${derivations[@]}"; then
        derived=$((derived + 1))
      fi
    done
    if [ "$selected" -eq 0 ]; then
      echo "check-production-root-keys-job: job $id runs none of the ignored tests" >&2
      failed=1
    fi
    if [ "$derived" -gt 1 ]; then
      echo "check-production-root-keys-job: job $id derives both keys; give each key its own job" >&2
      failed=1
    fi
  done < <(job_ids "$wf")

  if [ "${#jobs[@]}" -eq 0 ]; then
    echo "check-production-root-keys-job: no job in $wf runs --test production_root_keys" >&2
    return 1
  fi
  for name in "${ignored[@]}"; do
    if [ "${#covered[@]}" -eq 0 ] || ! in_list "$name" "${covered[@]}"; then
      echo "check-production-root-keys-job: no job runs the ignored test $name" >&2
      failed=1
    fi
  done

  return "$failed"
}

if ! check_workflow "$workflow" "$test_file"; then
  echo "check-production-root-keys-job: FAILED" >&2
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
    echo "check-production-root-keys-job: self-check could not make a workflow that $what" >&2
    exit 1
  fi
  if check_workflow "$tmp/ci.yml" "$test_file" 2>/dev/null; then
    echo "check-production-root-keys-job: a workflow that $what passed the check" >&2
    exit 1
  fi
}

must_refuse "runs the tests without --ignored" 's/-- --ignored --nocapture/-- --nocapture/'
must_refuse "runs the root key jobs on pull requests" "/^    if: github\\.event_name == 'push'/d"
must_refuse "runs the public root key job on pull requests" "/^  rust-proofs-root-key-public:/,/^  [A-Za-z]/s/^(    if: github\\.event_name == )'push'/\\1'pull_request'/"
must_refuse "runs the bundle root key job on pull requests" "/^  rust-proofs-root-key-bundle:/,/^  [A-Za-z]/{/^    if: github\\.event_name == 'push'/d}"
must_refuse "runs the root key jobs on another image" 's/^(    runs-on: )ubuntu-24\.04/\1ubuntu-22.04/'
must_refuse "gives the root key jobs 10 minutes" 's/^(    timeout-minutes: )30/\110/'
must_refuse "gives the public root key job 10 minutes" '/^  rust-proofs-root-key-public:/,/^  [A-Za-z]/s/^(    timeout-minutes: )30/\110/'
must_refuse "gives the bundle root key job 60 minutes" '/^  rust-proofs-root-key-bundle:/,/^  [A-Za-z]/s/^(    timeout-minutes: )30/\160/'
must_refuse "gives the bundle root key job no timeout" '/^  rust-proofs-root-key-bundle:/,/^  [A-Za-z]/{/^    timeout-minutes:/d}'
must_refuse "builds the root key jobs without AVX2" '/^      RUSTFLAGS: -C target-feature=\+avx2/d'
must_refuse "never derives the public root key" '/--exact derive_production_public_root_key/d'
must_refuse "skips the bundle root key" 's/--exact --skip derive_production_public_root_key/--exact --skip derive_production_public_root_key --skip derive_production_bundle_root_key/'
must_refuse "derives both keys in one job" 's/ --skip derive_production_public_root_key//'
must_refuse "runs no production root key test" 's/--test production_root_keys/--test production_root_key/'

echo "check-production-root-keys-job: the post-merge jobs run every ignored test of proofs/tests/production_root_keys.rs"
