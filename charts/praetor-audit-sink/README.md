# Praetor audit sink chart

This chart deploys the independent, append-only PostgreSQL audit sink. Only the
Praetor Secrets workload certificate is authorized to ingest records.

Create the required Secrets without placing their contents in Helm values:

```sh
kubectl -n praetor-audit create secret generic praetor-audit-runtime \
  --from-file=database-url=database-url

kubectl -n praetor-audit create secret generic praetor-audit-server \
  --from-file=tls.crt=server.crt \
  --from-file=tls.key=server.key \
  --from-file=ca.crt=praetor-secrets-client-ca.crt
```

The server certificate must cover the Service DNS name. The client CA must only
issue the exact URI SAN `spiffe://<trust-domain>/workload/praetor-secrets` to the
Praetor Secrets workload.

```sh
helm upgrade --install praetor-audit charts/praetor-audit-sink \
  --namespace praetor-audit --create-namespace \
  --set trustDomain=praetor.internal \
  --set secrets.runtimeSecret=praetor-audit-runtime \
  --set secrets.serverTLSSecret=praetor-audit-server
```

The root-only init container copies projected files into memory and restricts
them to service uid `10001`. The runtime is non-root, has a read-only root
filesystem, no capabilities, and no Kubernetes API token.
