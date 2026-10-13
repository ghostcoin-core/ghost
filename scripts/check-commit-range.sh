#!/usr/bin/env bash
# Checks the message of every commit in a range.
# Usage: check-commit-range.sh <git revision range or single commit>
set -u

here="$(cd "$(dirname "$0")" && pwd)"
range="$1"
status=0
count=0

case "$range" in
  *..*) commits="$(git rev-list "$range")" || exit 2 ;;
  *) commits="$(git rev-parse --verify "$range^{commit}")" || exit 2 ;;
esac

for commit in $commits; do
  count=$((count + 1))
  if git log -1 --format=%B "$commit" \
    | "$here/check-commit-message.sh" "commit $commit"; then
    echo "ok: $commit"
  else
    status=1
  fi
done

echo "checked $count commit(s)"
exit "$status"
