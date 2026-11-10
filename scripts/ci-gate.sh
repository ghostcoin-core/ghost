#!/usr/bin/env bash
# Runs the same checks as CI, one step or all of them. CI calls this script
# for each job, so a local run and CI share one list of commands.
#
# Usage: scripts/ci-gate.sh [step]
#   step: required-files, markdown-lint, shell-lint, rust-proofs, rust-client
#         or all. With no step, every step runs. rust-proofs runs the proofs
#         crate's fast tests only; its heavy proving tests run after merge
#         in CI. list-proofs-tests prints the integration tests rust-proofs
#         runs.
#
# The commit-messages check is not here: it runs in CI from the base branch
# and needs the pull request's commit range.
set -euo pipefail

cd "$(dirname "$0")/.."

# The Rust toolchain CI pins. A machine-wide rustup home is used when the
# caller has not chosen one.
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.99.1}"
if [ -z "${RUSTUP_HOME:-}" ] && [ -d /usr/local/rustup ]; then
  export RUSTUP_HOME=/usr/local/rustup
fi

need_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ci-gate: $1 is not installed; the $2 step needs it" >&2
    exit 1
  fi
}

step_required_files() {
  scripts/check-required-files.sh
}

step_markdown_lint() {
  need_tool npx markdown-lint
  npx --yes markdownlint-cli2@0.14.0 "**/*.md" "#benchmarks/target" "#proofs/target" "#client/target"
}

step_shell_lint() {
  need_tool shellcheck shell-lint
  shellcheck scripts/*.sh .githooks/commit-msg
}

rust_crate() {
  local crate="$1"
  need_tool cargo "rust-$crate"
  cargo test --release --locked --manifest-path "$crate/Cargo.toml"
  cargo check --locked --manifest-path "$crate/Cargo.toml" --lib --target wasm32-unknown-unknown
}

# The proofs crate's heavy test files: the recursion layers (layers.rs and
# every layers_*.rs) and the ML-DSA chunk proofs (mldsa_chunk.rs). Their real
# proofs take minutes each, so they stay out of this gate and run after merge
# in the rust-proofs-layers-* and rust-proofs-mldsa-* jobs of
# .github/workflows/ci.yml. scripts/check-ci-gate-fast.sh fails if one of
# them comes back into the gate's list.
proofs_heavy_test() {
  case "$1" in
    layers | layers_* | mldsa_chunk) return 0 ;;
    *) return 1 ;;
  esac
}

# The proofs crate's fast integration tests, one name per line: every file in
# proofs/tests/ except the heavy ones, so a new test file runs in the gate
# without editing a list. The same set as the rust-proofs job of CI.
proofs_fast_tests() {
  local f name
  for f in proofs/tests/*.rs; do
    name="$(basename "$f" .rs)"
    if ! proofs_heavy_test "$name"; then
      echo "$name"
    fi
  done
}

# The proofs crate's fast tests only: the library, doc and fast integration
# tests, then the wasm32 check, as the rust-proofs job of CI runs them. They
# build with the parallel feature, as that job does: proving is
# single-threaded without it.
rust_proofs_fast() {
  need_tool cargo rust-proofs
  local name
  local tests=()
  while IFS= read -r name; do
    tests+=(--test "$name")
  done < <(proofs_fast_tests)
  echo "integration tests: ${tests[*]}"
  cargo test --release --locked --features parallel --manifest-path proofs/Cargo.toml --lib "${tests[@]}"
  cargo test --release --locked --features parallel --manifest-path proofs/Cargo.toml --doc
  cargo check --locked --manifest-path proofs/Cargo.toml --lib --target wasm32-unknown-unknown
}

run_step() {
  echo "== ci-gate: $1"
  case "$1" in
    required-files) step_required_files ;;
    markdown-lint) step_markdown_lint ;;
    shell-lint) step_shell_lint ;;
    rust-proofs) rust_proofs_fast ;;
    rust-client) rust_crate client ;;
    # Prints the integration tests the rust-proofs step runs, for
    # scripts/check-ci-gate-fast.sh. Not part of "all".
    list-proofs-tests) proofs_fast_tests ;;
    *)
      echo "ci-gate: unknown step: $1" >&2
      echo "steps: required-files markdown-lint shell-lint rust-proofs rust-client all" >&2
      exit 2
      ;;
  esac
}

if [ "$#" -gt 1 ]; then
  echo "usage: scripts/ci-gate.sh [step]" >&2
  exit 2
fi

step="${1:-all}"
if [ "$step" = "all" ]; then
  for s in required-files markdown-lint shell-lint rust-proofs rust-client; do
    run_step "$s"
  done
  echo "ci-gate: all steps passed"
else
  run_step "$step"
fi
