# Praetor Secrets stack chart

This umbrella chart deploys the Secrets Service and its independent immutable
audit sink in one namespace. It fixes both Service names and configures the
Secrets Service to deliver to the sink's canonical internal endpoint:

`https://praetor-audit-sink.<namespace>.svc:8444/internal/v1/audit/events`

The two workloads still use separate PostgreSQL URLs and TLS Secrets. Create the
five pre-existing Secrets described by the child chart READMEs, then install:

```sh
helm dependency build charts/praetor-secrets-stack
helm upgrade --install praetor-secrets-stack charts/praetor-secrets-stack \
  --namespace praetor-secrets --create-namespace \
  --set praetor-secrets.trustDomain=praetor.internal \
  --set praetor-secrets.secrets.runtimeSecret=praetor-secrets-runtime \
  --set praetor-secrets.secrets.serverTLSSecret=praetor-secrets-server \
  --set praetor-secrets.secrets.auditSinkTLSSecret=praetor-secrets-audit-client \
  --set praetor-audit-sink.trustDomain=praetor.internal \
  --set praetor-audit-sink.secrets.runtimeSecret=praetor-audit-runtime \
  --set praetor-audit-sink.secrets.serverTLSSecret=praetor-audit-server
```

The sink's NetworkPolicy admits its mTLS port only from Secrets Service pods in
the same namespace. Certificate verification remains the authoritative identity
control; the network policy is an additional boundary.
