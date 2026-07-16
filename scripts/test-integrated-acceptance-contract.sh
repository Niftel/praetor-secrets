#!/bin/sh
set -eu

script="$(dirname "$0")/run-integrated-acceptance.sh"
bash -n "$script"
for required in \
  "test-secrets-execution-e2e.sh" \
  "deployed Secrets Service has no NetworkPolicy" \
  "credential plaintext found in Praetor database dump" \
  "credential plaintext found in Secrets database dump" \
  "terminal run credential was resolvable" \
  "unknown run did not fail closed" \
  "API workload identity reached executor resolution" \
  "executor-controlled credential selector was accepted" \
  "remote audit sink has no evidence" \
  "TestOperationsSurviveRestartAndValidateIsolatedRestore"; do
  grep -Fq "$required" "$script" || {
    echo "acceptance harness lost required check: $required" >&2
    exit 1
  }
done
grep -Fq "credential replacement" "$(dirname "$0")/../app/operations_e2e_test.go"
grep -Fq "wrong-key recovery response leaked plaintext" "$(dirname "$0")/../app/operations_e2e_test.go"
