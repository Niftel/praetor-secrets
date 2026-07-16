#!/bin/sh
set -eu

GOWORK=off go test ./securitygate
scripts/check-security-coverage.sh
GOWORK=off go run ./scripts/mutationcheck
