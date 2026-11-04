#!/bin/sh
# Rerun the pinned library's security estimator at the real shapes of a
# reveal and of the batch, root and shrink layers, and the stage 2 design's
# whole-bundle formulas at those shapes. Every table of
# docs/scale/bundle-security.md is printed, and the test fails when a row of
# the page differs from the run, or when the whole-bundle sum is below 128
# classical or 64 quantum bits.
#
# Usage: scripts/bundle-security.sh [extra test arguments]
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec cargo test --release --locked --manifest-path "$root/proofs/Cargo.toml" \
    --test bundle_security -- --nocapture --test-threads 1 "$@"
