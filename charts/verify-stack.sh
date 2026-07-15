#!/bin/sh
set -eu

output="$(mktemp)"
trap 'rm -f "$output"' EXIT

helm dependency build charts/praetor-secrets-stack >/dev/null
helm template integration charts/praetor-secrets-stack \
  --namespace security \
  --set praetor-secrets.trustDomain=praetor.internal \
  --set praetor-secrets.secrets.runtimeSecret=secrets-runtime \
  --set praetor-secrets.secrets.serverTLSSecret=secrets-server \
  --set praetor-secrets.secrets.auditSinkTLSSecret=audit-client \
  --set praetor-audit-sink.trustDomain=praetor.internal \
  --set praetor-audit-sink.secrets.runtimeSecret=audit-runtime \
  --set praetor-audit-sink.secrets.serverTLSSecret=audit-server >"$output"

grep -q 'value: "https://praetor-audit-sink.security.svc:8444/internal/v1/audit/events"' "$output"
grep -q 'name: praetor-audit-sink-ingress' "$output"
grep -q 'app.kubernetes.io/name: praetor-secrets' "$output"
grep -q 'app.kubernetes.io/instance: integration' "$output"
grep -q 'command: \["/usr/local/bin/praetor-audit-sink"\]' "$output"

if helm template integration charts/praetor-secrets-stack \
  --set praetor-secrets.trustDomain=one.internal \
  --set praetor-audit-sink.trustDomain=two.internal \
  --set praetor-secrets.secrets.runtimeSecret=runtime \
  --set praetor-secrets.secrets.serverTLSSecret=server \
  --set praetor-secrets.secrets.auditSinkTLSSecret=audit \
  --set praetor-audit-sink.secrets.runtimeSecret=runtime \
  --set praetor-audit-sink.secrets.serverTLSSecret=server >/dev/null 2>&1; then
  echo "mismatched trust domains were accepted" >&2
  exit 1
fi

if helm template integration charts/praetor-secrets-stack \
  --set praetor-secrets.trustDomain=praetor.internal \
  --set praetor-audit-sink.trustDomain=praetor.internal \
  --set praetor-secrets.auditSink.servicePort=9444 \
  --set praetor-secrets.secrets.runtimeSecret=runtime \
  --set praetor-secrets.secrets.serverTLSSecret=server \
  --set praetor-secrets.secrets.auditSinkTLSSecret=audit \
  --set praetor-audit-sink.secrets.runtimeSecret=runtime \
  --set praetor-audit-sink.secrets.serverTLSSecret=server >/dev/null 2>&1; then
  echo "mismatched audit sink ports were accepted" >&2
  exit 1
fi
