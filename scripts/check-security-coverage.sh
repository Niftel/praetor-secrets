#!/bin/sh
set -eu

cache="${GOCACHE:-/tmp/praetor-secrets-security-coverage-cache}"
check() {
  package="$1"
  minimum="$2"
  output=$(GOWORK=off GOCACHE="$cache" go test -cover "$package")
  coverage=$(printf '%s\n' "$output" | sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p' | tail -1)
  test -n "$coverage"
  awk -v package="$package" -v coverage="$coverage" -v minimum="$minimum" 'BEGIN {
    if (coverage + 0 < minimum + 0) {
      printf "%s security coverage %.1f%% is below %.1f%%\n", package, coverage, minimum
      exit 1
    }
    printf "PASS: %s security coverage %.1f%% >= %.1f%%\n", package, coverage, minimum
  }'
}

check ./envelope 84
check ./masterkey 86
check ./transport 82
check ./credential 78
