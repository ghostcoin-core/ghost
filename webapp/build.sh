#!/usr/bin/env bash
# Verifiable build of the Ghost web app into webapp/dist.
#
#   1. checks that the pinned toolchain (the one CI uses) is installed, and
#      installs the pinned nightly toolchain of the threaded module if it is
#      missing;
#   2. fetches the crates Cargo.lock pins and those the nightly standard
#      library's own lock file pins, and nothing else;
#   3. builds the two WebAssembly modules offline, with --locked, with every
#      local path remapped so neither depends on where it was built:
#      - the single-thread module, with SIMD (+simd128), on the pinned
#        toolchain;
#      - the threaded module (feature `threads`: the proofs crate's
#        `parallel` feature over a pool of Web Workers), with SIMD, threads
#        and atomics (+atomics,+bulk-memory,+mutable-globals) on a shared,
#        imported memory, on the pinned nightly toolchain with the standard
#        library rebuilt for atomics (-Z build-std); the page loads it when
#        it is cross-origin isolated and falls back to the single-thread
#        module otherwise;
#   4. copies the page, its modules and both WebAssembly modules into dist
#      and writes dist/SHA256SUMS.
#
# Anyone can run it on the same commit and compare SHA256SUMS with a
# published one; webapp/README.md explains how.
#
# Usage: webapp/build.sh
set -euo pipefail

toolchain="1.99.1"
# A 1.99 nightly (1.99.0-nightly, 2026-08-12), the compiler line of the
# pinned stable toolchain: the 1.101 nightlies panic while type-checking
# p3-monty-31 (into_parallel_byte_streams), which 1.99 compiles.
threads_toolchain="nightly-2026-08-13"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
manifest="$here/wasm/Cargo.toml"
module="$here/wasm/target/wasm32-unknown-unknown/release/ghost_webapp_wasm.wasm"
# The threaded module builds into a target directory of its own.
threads_target="$here/wasm/target/threads"
threads_module="$threads_target/wasm32-unknown-unknown/release/ghost_webapp_wasm.wasm"
dist="$here/dist"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
# The threaded module's shared memory: 64 MiB to start, 4 GiB at most. The
# page creates it with exactly these limits (src/threads.mjs).
threads_initial_memory=67108864
threads_max_memory=4294967296
# The page's own files, in the order they are copied.
files=(index.html style.css favicon.svg)
modules=(app bytes chain flow header local-node popup-wallet prover rpc thread threads wallet-connect wasm worker worker-core)

if ! rustup run "$toolchain" rustc --version >/dev/null 2>&1; then
  echo "Rust $toolchain is not installed. Install it with:" >&2
  echo "  rustup toolchain install $toolchain --profile minimal --target wasm32-unknown-unknown" >&2
  exit 1
fi
rustup run "$toolchain" rustc --version
if ! rustup run "$threads_toolchain" rustc --version >/dev/null 2>&1 \
  || ! rustup component list --installed --toolchain "$threads_toolchain" | grep '^rust-src' >/dev/null; then
  echo "installing $threads_toolchain for the threaded module" >&2
  rustup toolchain install "$threads_toolchain" --profile minimal --component rust-src --target wasm32-unknown-unknown
fi
rustup run "$threads_toolchain" rustc --version

# The only network access: the crates and the Plonky3 revision Cargo.lock pins.
cargo "+$toolchain" fetch --locked --manifest-path "$manifest"
# And the crates the nightly standard library depends on, which the offline
# -Z build-std build below needs in the cache: rust-src brings their sources'
# lock file, not the crates.
cargo "+$threads_toolchain" fetch --locked -Z build-std=std,panic_abort --target wasm32-unknown-unknown \
  --manifest-path "$manifest"

remap="--remap-path-prefix=$repo=/ghost --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup"

CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="$remap -C target-feature=+simd128" \
  cargo "+$toolchain" build --release --locked --offline --target wasm32-unknown-unknown --manifest-path "$manifest"

# Threads and atomics: a shared memory imported from the page, and the
# exports each prover thread's worker needs to give its instance its own
# stack and thread-local storage (src/thread.mjs).
threads_flags=(
  "-C target-feature=+simd128,+atomics,+bulk-memory,+mutable-globals"
  "-C link-arg=--shared-memory"
  "-C link-arg=--import-memory"
  "-C link-arg=--initial-memory=$threads_initial_memory"
  "-C link-arg=--max-memory=$threads_max_memory"
  "-C link-arg=--export=__stack_pointer"
  "-C link-arg=--export=__wasm_init_tls"
  "-C link-arg=--export=__tls_size"
  "-C link-arg=--export=__tls_align"
)
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="$remap ${threads_flags[*]}" \
  cargo "+$threads_toolchain" build --release --locked --offline --target wasm32-unknown-unknown \
  -Z build-std=std,panic_abort --features threads --target-dir "$threads_target" --manifest-path "$manifest"

rm -rf "$dist"
mkdir -p "$dist/src"
for f in "${files[@]}"; do
  cp "$here/$f" "$dist/$f"
done
for m in "${modules[@]}"; do
  cp "$here/src/$m.mjs" "$dist/src/$m.mjs"
done
cp "$module" "$dist/ghost_webapp_wasm.wasm"
cp "$threads_module" "$dist/ghost_webapp_wasm_threads.wasm"
# The self-hosted Instrument Sans and IBM Plex Mono fonts and their licence.
cp -R "$here/fonts" "$dist/fonts"

(
  cd "$dist"
  find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do
    sha256sum "$f"
  done > SHA256SUMS
)
echo
echo "built $dist"
cat "$dist/SHA256SUMS"
