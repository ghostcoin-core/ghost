#!/usr/bin/env bash
# Builds the release geth of ghost-node that the web app's real-node test
# (webapp/test/e2e/real-node.test.mjs) runs against.
#
#   1. clones ghostcoin-core/ghost-node at the commit in
#      webapp/test/e2e/NODE_COMMIT, and checks that it got that commit;
#   2. builds it with `go run build/ci.go install ./cmd/geth`, the Linux
#      release build with the pinned ghost-proofs verifier;
#   3. prints the path to build/bin/geth, and nothing else, on stdout.
#
# GHOST_NODE_REPO selects another clone URL; GHOST_NODE_DIR the checkout
# directory (default: a directory named after the commit under TMPDIR). Use
# the printed path as GHOST_NODE_GETH:
#
#   GHOST_NODE_GETH="$(webapp/scripts/build-node.sh)" \
#     node --test --test-timeout=3600000 webapp/test/e2e/real-node.test.mjs
#
# Usage: webapp/scripts/build-node.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pin="$here/../test/e2e/NODE_COMMIT"
repo="${GHOST_NODE_REPO:-https://github.com/ghostcoin-core/ghost-node.git}"

die() {
  echo "build-node: $*" >&2
  exit 1
}

[ -s "$pin" ] || die "$pin is missing"
commit="$(tr -d '[:space:]' <"$pin")"
case "$commit" in
  *[!0-9a-f]* | '') die "$pin does not hold a commit hash" ;;
esac
[ "${#commit}" -eq 40 ] || die "$pin does not hold a full 40-character commit hash"
command -v git >/dev/null || die "git is not installed"
command -v go >/dev/null || die "go is not installed"

dir="${GHOST_NODE_DIR:-${TMPDIR:-/tmp}/ghost-node-$commit}"

# Progress goes to stderr, so stdout holds only the path.
{
  if [ ! -d "$dir/.git" ]; then
    git init --quiet "$dir"
    git -C "$dir" remote add origin "$repo"
  fi
  git -C "$dir" fetch --quiet --depth 1 origin "$commit"
  git -C "$dir" checkout --quiet --force --detach FETCH_HEAD
  got="$(git -C "$dir" rev-parse HEAD)"
  [ "$got" = "$commit" ] || die "fetched $got, not $commit"
  echo "build-node: building ghost-node $commit in $dir"
  (cd "$dir" && go run build/ci.go install ./cmd/geth)
} >&2

geth="$dir/build/bin/geth"
[ -x "$geth" ] || die "the build made no $geth"
echo "$geth"
