#!/usr/bin/env bash
# Runs the same checks as CI, one step or all of them. CI calls this script
# for each job, so a local run and CI share one list of commands.
#
# Usage: scripts/ci-gate.sh [step]
#   step: required-files, markdown-lint, shell-lint, rust-proofs, rust-client
#         or all. With no step, every step runs.
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

run_step() {
  echo "== ci-gate: $1"
  case "$1" in
    required-files) step_required_files ;;
    markdown-lint) step_markdown_lint ;;
    shell-lint) step_shell_lint ;;
    rust-proofs) rust_crate proofs ;;
    rust-client) rust_crate client ;;
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
