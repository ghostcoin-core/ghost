#!/usr/bin/env bash
# Verifiable build of the Ghost web app into webapp/dist.
#
#   1. checks that the pinned toolchain (the one CI uses) is installed;
#   2. fetches the crates Cargo.lock pins, and nothing else;
#   3. builds the WebAssembly module offline, with --locked, with every
#      local path remapped so the module does not depend on where it was
#      built;
#   4. copies the page, its modules and the WebAssembly module into dist
#      and writes dist/SHA256SUMS.
#
# Anyone can run it on the same commit and compare SHA256SUMS with a
# published one; webapp/README.md explains how.
#
# Usage: webapp/build.sh
set -euo pipefail

toolchain="1.99.1"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
manifest="$here/wasm/Cargo.toml"
module="$here/wasm/target/wasm32-unknown-unknown/release/ghost_webapp_wasm.wasm"
dist="$here/dist"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
# The page's own files, in the order they are copied.
files=(index.html style.css)
modules=(app bytes chain flow header keyimage prover rpc wasm worker worker-core)

if ! rustup run "$toolchain" rustc --version >/dev/null 2>&1; then
  echo "Rust $toolchain is not installed. Install it with:" >&2
  echo "  rustup toolchain install $toolchain --profile minimal --target wasm32-unknown-unknown" >&2
  exit 1
fi
rustup run "$toolchain" rustc --version

# The only network access: the crates and the Plonky3 revision Cargo.lock pins.
cargo "+$toolchain" fetch --locked --manifest-path "$manifest"

export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--remap-path-prefix=$repo=/ghost --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup -C target-feature=+simd128"
cargo "+$toolchain" build --release --locked --offline --target wasm32-unknown-unknown --manifest-path "$manifest"

rm -rf "$dist"
mkdir -p "$dist/src"
for f in "${files[@]}"; do
  cp "$here/$f" "$dist/$f"
done
for m in "${modules[@]}"; do
  cp "$here/src/$m.mjs" "$dist/src/$m.mjs"
done
cp "$module" "$dist/ghost_webapp_wasm.wasm"
# The self-hosted Inter font and its licence.
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
