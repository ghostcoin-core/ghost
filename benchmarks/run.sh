#!/usr/bin/env bash
# One command for the browser proof benchmark harness:
#
#   1. build the native prover and the WebAssembly module (SIMD on);
#   2. run the correctness checks (a good proof verifies, changed public
#      inputs, broken conservation and a wrong Merkle path are rejected,
#      fresh randomness gives different proofs, the trace is tall enough for
#      zero-knowledge mode);
#   3. run a short native reference (context only, never counted);
#   4. print the summary of every record found.
#
# Usage: benchmarks/run.sh [--web] [--reveal] [--native-warm N] [--no-native] [RECORDS...]
#
#   --web            also produce the browser bundle in web/pkg with a pinned
#                    wasm-bindgen, installed into benchmarks/.tools on first use
#   --reveal         also build the real coin reveal prover (benchmarks/reveal)
#                    into web/reveal-pkg for reveal.html, and run its tests;
#                    no bindings generator is needed
#   --native-warm N  warm runs per configuration in the native reference (2)
#   --no-native      skip the native reference
#   RECORDS          record files or directories to summarize
#                    (default: docs/benchmarks/results if present)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
manifest="$here/Cargo.toml"
out_dir="$here/out"
# Must match the wasm-bindgen version locked in Cargo.lock.
bindgen_version="0.2.105"

web=0
reveal=0
native=1
native_warm=2
records=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --web) web=1 ;;
    --no-native) native=0 ;;
    --native-warm) shift; native_warm="$1" ;;
    --reveal) reveal=1 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) records+=("$1") ;;
  esac
  shift
done
if [ "${#records[@]}" -eq 0 ] && [ -d "$repo/docs/benchmarks/results" ]; then
  records=("$repo/docs/benchmarks/results")
fi

step() { printf '\n== %s\n' "$*"; }

step "build: native prover and runner"
cargo build --release --manifest-path "$manifest" -p ghost-bench --features parallel --bin ghost-bench-native

step "build: WebAssembly module (wasm32-unknown-unknown, SIMD)"
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-C target-feature=+simd128" \
  cargo build --release --target wasm32-unknown-unknown --manifest-path "$manifest" -p ghost-bench-wasm
wasm="$here/target/wasm32-unknown-unknown/release/ghost_bench_wasm.wasm"

if [ "$web" -eq 1 ]; then
  step "build: browser bundle (wasm-bindgen $bindgen_version)"
  if ! grep -q "version = \"$bindgen_version\"" "$here/Cargo.lock"; then
    echo "Cargo.lock does not lock wasm-bindgen $bindgen_version; update bindgen_version in run.sh" >&2
    exit 1
  fi
  bindgen="$here/.tools/bin/wasm-bindgen"
  if [ ! -x "$bindgen" ] || ! "$bindgen" --version | grep -q "$bindgen_version"; then
    cargo install --root "$here/.tools" wasm-bindgen-cli --version "$bindgen_version" --locked
  fi
  "$bindgen" --target web --out-dir "$here/web/pkg" "$wasm"
  echo "serve with: python3 $here/web/serve.py"
fi

if [ "$reveal" -eq 1 ]; then
  reveal_manifest="$here/reveal/Cargo.toml"
  step "build: real coin reveal prover (wasm32-unknown-unknown, SIMD)"
  CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-C target-feature=+simd128" \
    cargo build --release --locked --target wasm32-unknown-unknown --manifest-path "$reveal_manifest" --lib
  mkdir -p "$here/web/reveal-pkg"
  cp "$here/reveal/target/wasm32-unknown-unknown/release/ghost_reveal_bench.wasm" "$here/web/reveal-pkg/"
  step "build and test: native verifier of the browser proofs"
  cargo test --release --locked --manifest-path "$reveal_manifest"
  cargo build --release --locked --manifest-path "$reveal_manifest" --bin ghost-reveal-verify
  echo "serve with: python3 $here/web/serve.py, then open http://localhost:8000/reveal.html"
fi

step "correctness checks"
cargo test --release --manifest-path "$manifest"

mkdir -p "$out_dir"
if [ "$native" -eq 1 ]; then
  step "native reference (context only, never counted toward the target)"
  commit="$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)"
  "$here/target/release/ghost-bench-native" \
    --sessions 1 --warm "$native_warm" --repo-commit "$commit" \
    --out "$out_dir/native.jsonl"
  records+=("$out_dir/native.jsonl")
fi

step "summary"
if [ "${#records[@]}" -eq 0 ]; then
  echo "no records to summarize"
  exit 0
fi
python3 "$here/summarize.py" "${records[@]}"
