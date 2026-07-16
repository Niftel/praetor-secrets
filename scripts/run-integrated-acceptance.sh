#!/usr/bin/env bash
set -euo pipefail

# Board-derived acceptance gate for an already deployed Praetor + Secrets stack.
# This composes Praetor's real execution proof with deployed security-boundary,
# leakage, denial, replay, and remote-audit checks.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRAETOR_ROOT="${PRAETOR_ROOT:-$(cd "$ROOT/.." 2>/dev/null && pwd)/praetor}"
NAMESPACE="${PRAETOR_NAMESPACE:-praetor-secrets}"
SECRETS_SERVICE="${PRAETOR_SECRETS_SERVICE:-praetor-secrets}"
SECRETS_PORT="${PRAETOR_SECRETS_ACCEPTANCE_PORT:-18443}"
EXECUTOR_IDENTITY_SECRET="${PRAETOR_EXECUTOR_IDENTITY_SECRET:-praetor-executor-identity}"
API_IDENTITY_SECRET="${PRAETOR_API_IDENTITY_SECRET:-praetor-api-identity}"
SCHEDULER_IDENTITY_SECRET="${PRAETOR_SCHEDULER_IDENTITY_SECRET:-praetor-scheduler-identity}"
TIMEOUT_SECONDS="${PRAETOR_ACCEPTANCE_TIMEOUT_SECONDS:-180}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: required command '$1' is not installed" >&2; exit 1; }; }
for command in base64 curl go jq kubectl nc openssl uuidgen; do need "$command"; done
[[ -x "$PRAETOR_ROOT/scripts/test-secrets-execution-e2e.sh" ]] || {
  echo "error: set PRAETOR_ROOT to the integrated Praetor checkout" >&2
  exit 1
}

TMP="$(mktemp -d "${TMPDIR:-/tmp}/praetor-secrets-acceptance.XXXXXX")"
trap 'kill "${PORT_FORWARD_PID:-}" "${DB_FORWARD_PID:-}" 2>/dev/null || true; rm -rf "$TMP"' EXIT
SENTINEL="acceptance-$(openssl rand -hex 24)"
EVIDENCE="$TMP/execution.json"

echo "==> Proving the real credential-backed execution path"
PRAETOR_E2E_SENTINEL="$SENTINEL" PRAETOR_E2E_EVIDENCE_FILE="$EVIDENCE" \
  "$PRAETOR_ROOT/scripts/test-secrets-execution-e2e.sh"
RUN_ID="$(jq -er .run_id "$EVIDENCE")"
CREDENTIAL_ID="$(jq -er .credential_id "$EVIDENCE")"

echo "==> Verifying deployed Kubernetes isolation"
DEPLOYMENT="$(kubectl get deployment -n "$NAMESPACE" -l app.kubernetes.io/name=praetor-secrets -o json)"
jq -e '
  .items | length == 1 and
  .[0].spec.template.spec.serviceAccountName != "default" and
  .[0].spec.template.spec.automountServiceAccountToken == false and
  .[0].spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem == true and
  .[0].spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation == false and
  .[0].spec.template.spec.containers[0].readinessProbe.httpGet.path == "/readyz" and
  .[0].spec.template.spec.containers[0].livenessProbe.httpGet.path == "/livez" and
  .[0].spec.template.spec.containers[0].resources.requests.cpu != null and
  .[0].spec.template.spec.containers[0].resources.requests.memory != null and
  .[0].spec.template.spec.containers[0].resources.limits.cpu != null and
  .[0].spec.template.spec.containers[0].resources.limits.memory != null and
  any(.[0].spec.template.spec.containers[0].volumeMounts[]; .mountPath == "/restricted" and .readOnly == true)
' <<<"$DEPLOYMENT" >/dev/null || { echo "error: deployed Secrets Service hardening is incomplete" >&2; exit 1; }
kubectl get networkpolicy -n "$NAMESPACE" -o json |
  jq -e 'any(.items[]; .metadata.name | contains("praetor-secrets"))' >/dev/null ||
  { echo "error: deployed Secrets Service has no NetworkPolicy" >&2; exit 1; }

RUNTIME_SECRET="$(jq -r '.items[0].spec.template.spec.volumes[] | select(.name=="runtime-source").secret.secretName' <<<"$DEPLOYMENT")"
for component in api scheduler executor ingestion consumer reconciler ui; do
  kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/component=$component" -o json |
    jq -e --arg secret "$RUNTIME_SECRET" '
      all(.items[];
        all(.spec.volumes[]?; (.secret.secretName // "") != $secret) and
        ([.spec.containers[].env[]?.value // ""] | all(contains("master-key") | not))
      )' >/dev/null ||
    { echo "error: Secrets Service runtime key material is mounted by $component" >&2; exit 1; }
done

echo "==> Proving plaintext absence across deployed persistence and logs"
PRAETOR_DB_POD="$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=postgresql,app.kubernetes.io/instance=praetor -o jsonpath='{.items[0].metadata.name}')"
SECRETS_DB_POD="$(kubectl get pods -n "$NAMESPACE" -l app=praetor-secrets-postgres -o jsonpath='{.items[0].metadata.name}')"
AUDIT_DB_POD="$(kubectl get pods -n "$NAMESPACE" -l app=praetor-audit-postgres -o jsonpath='{.items[0].metadata.name}')"
for pod in "$PRAETOR_DB_POD" "$SECRETS_DB_POD" "$AUDIT_DB_POD"; do
  [[ -n "$pod" ]] || { echo "error: required database pod missing" >&2; exit 1; }
done
if kubectl exec -n "$NAMESPACE" "$PRAETOR_DB_POD" -- pg_dump -U postgres praetor |
  grep -Fq "$SENTINEL"; then
  echo "error: credential plaintext found in Praetor database dump" >&2
  exit 1
fi
if kubectl exec -n "$NAMESPACE" "$SECRETS_DB_POD" -- sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' |
  grep -Fq "$SENTINEL"; then
  echo "error: credential plaintext found in Secrets database dump" >&2
  exit 1
fi
if kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/name=praetor-secrets --all-containers --since=30m |
  grep -Fq "$SENTINEL"; then
  echo "error: credential plaintext found in Secrets Service logs" >&2
  exit 1
fi

extract_secret_file() {
  local secret="$1" key="$2" output="$3"
  kubectl get secret -n "$NAMESPACE" "$secret" -o json |
    jq -er --arg key "$key" '.data[$key]' | base64 -d >"$output"
  chmod 0600 "$output"
}
extract_secret_file "$EXECUTOR_IDENTITY_SECRET" tls.crt "$TMP/executor.crt"
extract_secret_file "$EXECUTOR_IDENTITY_SECRET" tls.key "$TMP/executor.key"
extract_secret_file "$EXECUTOR_IDENTITY_SECRET" secrets-ca.crt "$TMP/ca.crt"
extract_secret_file "$API_IDENTITY_SECRET" tls.crt "$TMP/api.crt"
extract_secret_file "$API_IDENTITY_SECRET" tls.key "$TMP/api.key"
extract_secret_file "$SCHEDULER_IDENTITY_SECRET" tls.crt "$TMP/scheduler.crt"
extract_secret_file "$SCHEDULER_IDENTITY_SECRET" tls.key "$TMP/scheduler.key"

kubectl port-forward -n "$NAMESPACE" "svc/$SECRETS_SERVICE" "$SECRETS_PORT:8443" >"$TMP/port-forward.log" 2>&1 &
PORT_FORWARD_PID=$!
SECRETS_HOST="${SECRETS_SERVICE}.${NAMESPACE}.svc"
BASE="https://${SECRETS_HOST}:$SECRETS_PORT"
for _ in $(seq 1 30); do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --resolve "$SECRETS_HOST:$SECRETS_PORT:127.0.0.1" \
    --cacert "$TMP/ca.crt" --cert "$TMP/executor.crt" --key "$TMP/executor.key" \
    "$BASE/internal/v1/security-status" || true)"
  [[ "$status" != "000" ]] && break
  sleep 1
done

mtls_status() {
  local cert="$1" key="$2" method="$3" path="$4" body="${5:-}"
  local args=(--silent --show-error --output "$TMP/response.json" --write-out '%{http_code}'
    --resolve "$SECRETS_HOST:$SECRETS_PORT:127.0.0.1"
    --cacert "$TMP/ca.crt" --cert "$cert" --key "$key" -X "$method"
    -H 'Content-Type: application/json')
  [[ -n "$body" ]] && args+=(--data "$body")
  curl "${args[@]}" "$BASE$path"
}

echo "==> Proving terminal, unknown-run, identity, and selector denials"
ATTEMPT_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
BODY="$(jq -nc --arg attempt_id "$ATTEMPT_ID" --arg requested_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{attempt_id:$attempt_id,requested_at:$requested_at}')"
[[ "$(mtls_status "$TMP/executor.crt" "$TMP/executor.key" POST "/internal/v1/runs/$RUN_ID/credential:resolve" "$BODY")" == 403 ]] ||
  { echo "error: terminal run credential was resolvable" >&2; exit 1; }
UNKNOWN_RUN="$(uuidgen | tr '[:upper:]' '[:lower:]')"
[[ "$(mtls_status "$TMP/executor.crt" "$TMP/executor.key" POST "/internal/v1/runs/$UNKNOWN_RUN/credential:resolve" "$BODY")" == 403 ]] ||
  { echo "error: unknown run did not fail closed" >&2; exit 1; }
[[ "$(mtls_status "$TMP/api.crt" "$TMP/api.key" POST "/internal/v1/runs/$RUN_ID/credential:resolve" "$BODY")" == 403 ]] ||
  { echo "error: API workload identity reached executor resolution" >&2; exit 1; }
SELECTOR_BODY="$(jq -nc --arg attempt_id "$ATTEMPT_ID" --arg requested_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg credential_id "$CREDENTIAL_ID" '{attempt_id:$attempt_id,requested_at:$requested_at,credential_id:$credential_id}')"
[[ "$(mtls_status "$TMP/executor.crt" "$TMP/executor.key" POST "/internal/v1/runs/$RUN_ID/credential:resolve" "$SELECTOR_BODY")" == 400 ]] ||
  { echo "error: executor-controlled credential selector was accepted" >&2; exit 1; }
if grep -Fq "$SENTINEL" "$TMP/response.json"; then
  echo "error: denial response leaked credential plaintext" >&2
  exit 1
fi

echo "==> Verifying remote audit delivery for the acceptance run"
DEADLINE=$((SECONDS + TIMEOUT_SECONDS))
AUDIT_COUNT=0
while (( SECONDS < DEADLINE )); do
  AUDIT_COUNT="$(kubectl exec -n "$NAMESPACE" "$AUDIT_DB_POD" -- sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc \
     "select count(*) from remote_audit_records where event::text like '\''%$1%'\''"' sh "$RUN_ID")"
  (( AUDIT_COUNT > 0 )) && break
  sleep 1
done
(( AUDIT_COUNT > 0 )) || { echo "error: remote audit sink has no evidence for run $RUN_ID" >&2; exit 1; }
if kubectl exec -n "$NAMESPACE" "$AUDIT_DB_POD" -- sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' |
  grep -Fq "$SENTINEL"; then
  echo "error: remote audit sink contains credential plaintext" >&2
  exit 1
fi

echo "==> Proving lifecycle snapshots, restart-safe rotation, and isolated recovery"
DB_TEST_PORT="${PRAETOR_SECRETS_DATABASE_TEST_PORT:-25433}"
DB_USER="$(kubectl exec -n "$NAMESPACE" "$SECRETS_DB_POD" -- sh -c 'printf %s "$POSTGRES_USER"')"
DB_PASSWORD="$(kubectl exec -n "$NAMESPACE" "$SECRETS_DB_POD" -- sh -c 'printf %s "$POSTGRES_PASSWORD"')"
DB_NAME="$(kubectl exec -n "$NAMESPACE" "$SECRETS_DB_POD" -- sh -c 'printf %s "$POSTGRES_DB"')"
kubectl port-forward -n "$NAMESPACE" "$SECRETS_DB_POD" "$DB_TEST_PORT:5432" >"$TMP/database-port-forward.log" 2>&1 &
DB_FORWARD_PID=$!
for _ in $(seq 1 30); do
  nc -z 127.0.0.1 "$DB_TEST_PORT" >/dev/null 2>&1 && break
  kill -0 "$DB_FORWARD_PID" 2>/dev/null || {
    echo "error: database port-forward stopped unexpectedly" >&2
    exit 1
  }
  sleep 1
done
PRAETOR_SECRETS_TEST_DATABASE_URL="postgres://$DB_USER:$DB_PASSWORD@127.0.0.1:$DB_TEST_PORT/$DB_NAME?sslmode=disable" \
  GOWORK=off GOCACHE="${GOCACHE:-/tmp/praetor-secrets-acceptance-go-cache}" \
  go test "$ROOT/app" -run '^TestOperationsSurviveRestartAndValidateIsolatedRestore$' -count=1

jq -n --arg run_id "$RUN_ID" --arg credential_id "$CREDENTIAL_ID" \
  --argjson audit_records "$AUDIT_COUNT" \
  '{status:"passed",run_id:$run_id,credential_id:$credential_id,audit_records:$audit_records}' \
  >"${PRAETOR_ACCEPTANCE_EVIDENCE_FILE:-$ROOT/integrated-acceptance-evidence.json}"
echo "PASS: integrated Secrets Service acceptance checks completed for run $RUN_ID"
