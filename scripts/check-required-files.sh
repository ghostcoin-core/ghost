#!/usr/bin/env bash
# Checks that the files every revision must carry are present and intact.
set -u

status=0

need() {
  if [ ! -s "$1" ]; then
    echo "MISSING: $1" >&2
    status=1
  fi
}

need_text() {
  if ! grep -qF -- "$2" "$1" 2>/dev/null; then
    echo "MISSING TEXT in $1: $2" >&2
    status=1
  fi
}

need LICENSE-MIT
need LICENSE-APACHE
need README.md
need docs/ghost-outline.md
need .githooks/commit-msg
need scripts/check-commit-message.sh

need_text LICENSE-MIT "Permission is hereby granted, free of charge"
need_text LICENSE-APACHE "Apache License"
need_text LICENSE-APACHE "Version 2.0, January 2004"
need_text README.md "experimental"

for f in .githooks/commit-msg scripts/*.sh; do
  if [ ! -x "$f" ]; then
    echo "NOT EXECUTABLE: $f" >&2
    status=1
  fi
done

[ "$status" -eq 0 ] && echo "all required files present"
exit "$status"
