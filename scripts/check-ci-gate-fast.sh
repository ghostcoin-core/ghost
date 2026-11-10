#!/usr/bin/env bash
# Checks that the merge gate (scripts/ci-gate.sh) runs only the proofs
# crate's fast tests. The heavy proving tests (the recursion layers,
# proofs/tests/layers.rs and layers_*.rs, and the ML-DSA chunk proofs,
# proofs/tests/mldsa_chunk.rs) take minutes each and run after merge in CI;
# this check fails if one of them is added back to the gate's list, if a fast
# test file is left out of it, or if the rust-proofs step runs the whole
# crate again.
#
# It then checks itself: a copy of the gate with the layers files let back in
# must fail the same check.
#
# Usage: scripts/check-ci-gate-fast.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

# The heavy test files, named here apart from the gate's own list so that a
# change to that list is caught.
is_heavy() {
  case "$1" in
    layers | layers_* | mldsa_chunk) return 0 ;;
    *) return 1 ;;
  esac
}

# check_gate GATE_ROOT: checks GATE_ROOT/scripts/ci-gate.sh against the test
# files in GATE_ROOT/proofs/tests. Prints every problem and returns 1 if there
# is one.
check_gate() {
  local gate_root="$1"
  local gate="$gate_root/scripts/ci-gate.sh"
  local failed=0
  local listed f name

  if ! listed="$(bash "$gate" list-proofs-tests)"; then
    echo "check-ci-gate-fast: $gate list-proofs-tests failed" >&2
    return 1
  fi
  if [ -z "$listed" ]; then
    echo "check-ci-gate-fast: the gate lists no proofs integration tests" >&2
    failed=1
  fi

  # No heavy test in the gate's list.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if is_heavy "$name"; then
      echo "check-ci-gate-fast: heavy test file proofs/tests/$name.rs is in the gate's list" >&2
      failed=1
    fi
  done <<<"$listed"

  # Every fast test file in it, and every heavy one present on disk out of it.
  local heavy_seen=0
  for f in "$gate_root"/proofs/tests/*.rs; do
    name="$(basename "$f" .rs)"
    if is_heavy "$name"; then
      heavy_seen=1
    elif ! grep -qxF "$name" <<<"$listed"; then
      echo "check-ci-gate-fast: fast test file proofs/tests/$name.rs is not in the gate's list" >&2
      failed=1
    fi
  done
  if [ "$heavy_seen" -ne 1 ]; then
    echo "check-ci-gate-fast: no heavy test file found in $gate_root/proofs/tests" >&2
    failed=1
  fi

  # The rust-proofs step must not run the whole crate through rust_crate,
  # which tests every file in proofs/tests/.
  if grep -Eq '^[[:space:]]*rust-proofs\)[[:space:]]*rust_crate\b' "$gate"; then
    echo "check-ci-gate-fast: the rust-proofs step runs the whole proofs crate" >&2
    failed=1
  fi
  if ! grep -Eq '^[[:space:]]*rust-proofs\)[[:space:]]*rust_proofs_fast\b' "$gate"; then
    echo "check-ci-gate-fast: the rust-proofs step does not run rust_proofs_fast" >&2
    failed=1
  fi

  return "$failed"
}

if ! check_gate "$root"; then
  echo "check-ci-gate-fast: FAILED" >&2
  exit 1
fi

# Self-check: let the layers files back into a copy of the gate, and the
# check above must refuse it.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/scripts"
ln -s "$root/proofs" "$tmp/proofs"
sed 's/layers | layers_\* | mldsa_chunk) return 0/mldsa_chunk) return 0/' \
  "$root/scripts/ci-gate.sh" >"$tmp/scripts/ci-gate.sh"
if cmp -s "$root/scripts/ci-gate.sh" "$tmp/scripts/ci-gate.sh"; then
  echo "check-ci-gate-fast: self-check could not let the layers files back into a copy of the gate" >&2
  exit 1
fi
if check_gate "$tmp" 2>/dev/null; then
  echo "check-ci-gate-fast: a gate that runs the layers tests passed the check" >&2
  exit 1
fi

# Self-check: a gate whose rust-proofs step runs the whole crate again.
sed 's/rust-proofs) rust_proofs_fast ;;/rust-proofs) rust_crate proofs ;;/' \
  "$root/scripts/ci-gate.sh" >"$tmp/scripts/ci-gate.sh"
if cmp -s "$root/scripts/ci-gate.sh" "$tmp/scripts/ci-gate.sh"; then
  echo "check-ci-gate-fast: self-check could not point a copy of the gate's rust-proofs step at the whole crate" >&2
  exit 1
fi
if check_gate "$tmp" 2>/dev/null; then
  echo "check-ci-gate-fast: a gate that runs the whole proofs crate passed the check" >&2
  exit 1
fi

echo "check-ci-gate-fast: the gate runs only the proofs crate's fast tests"
