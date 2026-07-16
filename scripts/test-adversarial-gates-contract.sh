#!/bin/sh
set -eu

script="$(dirname "$0")/run-adversarial-gates.sh"
sh -n "$script"
grep -Fq -- "-fuzztime=100000x" "$script"
if grep -Eq -- "-fuzztime=[0-9]+(ms|s|m|h)" "$script"; then
  echo "adversarial fuzz gate must use a deterministic execution budget" >&2
  exit 1
fi
