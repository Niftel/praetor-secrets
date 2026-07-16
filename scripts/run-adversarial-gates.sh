#!/bin/sh
set -eu

: "${PRAETOR_SECRETS_TEST_DATABASE_URL:?set PRAETOR_SECRETS_TEST_DATABASE_URL}"
cache="${GOCACHE:-/tmp/praetor-secrets-adversarial-cache}"

GOCACHE="$cache" go test -race ./...
GOCACHE="$cache" go test ./envelope -run '^$' -fuzz '^FuzzEnvelopeRejectsMutatedRecords$' -fuzztime=10s
GOCACHE="$cache" go test ./transport -run 'TestEveryWorkloadRole|TestExecutorCannotSelectCredential|TestSecretSentinel'
GOCACHE="$cache" go test ./credential -run 'TestPostgresMasterKeyRotation|TestPostgresRecoveryValidation|TestPostgresRunScopedResolution|TestPostgresMutation'
GOCACHE="$cache" go test ./audit ./auditsink -run 'Tamper|Ordering|Replay|Immutability|RetriesInOrder'
scripts/test-integrated-acceptance-contract.sh
