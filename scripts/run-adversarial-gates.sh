#!/bin/sh
set -eu

: "${PRAETOR_SECRETS_TEST_DATABASE_URL:?set PRAETOR_SECRETS_TEST_DATABASE_URL}"
cache="${GOCACHE:-/tmp/praetor-secrets-adversarial-cache}"

GOCACHE="$cache" go test -race ./...
# Use a fixed execution budget rather than a wall-clock deadline. Go's fuzz
# worker shutdown can cross a duration deadline on a loaded CI runner and report
# "context deadline exceeded" even though every fuzz case passed.
GOCACHE="$cache" go test ./envelope -run '^$' -fuzz '^FuzzEnvelopeRejectsMutatedRecords$' -fuzztime=100000x
GOCACHE="$cache" go test ./transport -run 'TestEveryWorkloadRole|TestExecutorCannotSelectCredential|TestSecretSentinel'
GOCACHE="$cache" go test ./credential -run 'TestPostgresMasterKeyRotation|TestPostgresRecoveryValidation|TestPostgresRunScopedResolution|TestPostgresMutation'
GOCACHE="$cache" go test ./audit ./auditsink -run 'Tamper|Ordering|Replay|Immutability|RetriesInOrder'
scripts/test-integrated-acceptance-contract.sh
scripts/test-adversarial-gates-contract.sh
