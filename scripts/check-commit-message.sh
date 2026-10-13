#!/usr/bin/env bash
# Checks one commit message, read from standard input.
# Exits 0 if the message is acceptable and 1 if it is not.
#
# A message is rejected if it:
#   - names one of the listed tools or vendors (whole word, any case);
#   - carries a co-author trailer;
#   - carries a "Generated with" line.
#
# Usage: check-commit-message.sh [label] < message
set -u

label="${1:-commit message}"
message="$(cat)"
status=0

fail() {
  echo "REJECTED ($label): $1" >&2
  status=1
}

names='claude|anthropic|codex|openai|cursor|kipp'

hit="$(printf '%s\n' "$message" | grep -inwE -- "$names" || true)"
if [ -n "$hit" ]; then
  fail "names a tool or vendor that must not appear in commit messages"
  printf '%s\n' "$hit" | sed 's/^/    line /' >&2
fi

hit="$(printf '%s\n' "$message" | grep -inE -- '^[[:space:]]*co-authored-by[[:space:]]*:' || true)"
if [ -n "$hit" ]; then
  fail "carries a co-author trailer"
  printf '%s\n' "$hit" | sed 's/^/    line /' >&2
fi

hit="$(printf '%s\n' "$message" | grep -inE -- 'generated[[:space:]]+with' || true)"
if [ -n "$hit" ]; then
  fail "carries a \"Generated with\" line"
  printf '%s\n' "$hit" | sed 's/^/    line /' >&2
fi

exit "$status"
