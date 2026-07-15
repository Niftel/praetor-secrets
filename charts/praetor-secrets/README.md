# Praetor Secrets Service chart

This chart deploys the standalone mTLS service. PostgreSQL, the audit sink,
master keys, and workload PKI remain external trust domains by design.

Create three pre-existing Secrets; do not place these values in Helm arguments:

```sh
kubectl -n praetor-secrets create secret generic praetor-secrets-runtime \
  --from-file=database-url=database-url \
  --from-file=master-key=master-key \
  --from-file=audit-key=audit-key

kubectl -n praetor-secrets create secret generic praetor-secrets-server \
  --from-file=tls.crt=server.crt \
  --from-file=tls.key=server.key \
  --from-file=ca.crt=workload-client-ca.crt

kubectl -n praetor-secrets create secret generic praetor-secrets-audit-client \
  --from-file=tls.crt=audit-client.crt \
  --from-file=tls.key=audit-client.key \
  --from-file=ca.crt=audit-sink-ca.crt
```

The server certificate must cover the Service DNS name. Client certificates
chain to `serverTLSSecret`'s `ca.crt` and carry one of the URI SANs documented in
the repository README. The audit client certificate and `ca.crt` authenticate
the external HTTPS audit sink in both directions.

Install:

```sh
helm upgrade --install praetor-secrets charts/praetor-secrets \
  --namespace praetor-secrets --create-namespace \
  --set trustDomain=praetor.internal \
  --set secrets.runtimeSecret=praetor-secrets-runtime \
  --set secrets.serverTLSSecret=praetor-secrets-server \
  --set secrets.auditSinkTLSSecret=praetor-secrets-audit-client \
  --set auditSink.url=https://audit.example.internal/events
```

The root-only init container stages projected values into an in-memory volume,
changes ownership to service uid `10001`, and sets every file to `0400`. The
service container then runs non-root with a read-only root filesystem, no Linux
capabilities, and no Kubernetes API token.

For controlled master-key rotation, add `previous-key` to the runtime Secret and
set `secrets.previousKeyEnabled=true`. Restart the Deployment after any existing
Secret changes; Helm cannot checksum content it does not own.
