# Praetor Secrets Service

Provider-independent, run-scoped credential storage and resolution for Praetor.

This repository owns the Secrets Service security boundary, API, storage format,
deployment, recovery tooling, and security tests. The main Praetor repository
integrates with the service as a client and does not receive its master key.

Development is tracked in the private
[Praetor Secrets Service project](https://github.com/orgs/Niftel/projects/1).

## Current phase

Core service implementation is underway. The envelope format, strict
file-backed master-key loader, redacted credential lifecycle, and transactional
PostgreSQL persistence are implemented. The run-binding and executor-resolution
domain, authenticated internal transport, executable service assembly, and the
authenticated durable audit spool, remote delivery, and independent immutable
audit sink are implemented; Praetor integration follows.

- [Threat model](docs/threat-model.md)
- [Service API and trust-boundary specification](docs/service-api.md)
- [Envelope record format](docs/envelope-format.md)
- [Remote audit sink contract](docs/audit-sink-contract.md)

## Master-key files

The service reads an exact 32-byte binary key from a read-only file. The file
must not grant permissions to group or other users (use mode `0400` or `0600`).
Do not add a newline or store hex/base64 text in the file.

During a bounded rotation window, a separate previous-key file may be mounted.
Only the current key is used for new encryption; the previous key is accepted
for decryption until all records have been rewrapped and verified. The previous
file must then be removed.

## Credential lifecycle

Administrative credential operations return a metadata type that structurally
cannot contain plaintext or ciphertext. Creates and replacements encrypt a
complete schema-validated input payload as a new credential version. Metadata
updates also create a new independently encrypted version so a future run
binding can snapshot one coherent version. Organization ownership and credential
type are immutable, and stale concurrent writes fail without partial changes.

### PostgreSQL persistence

Credential metadata, versioned envelope records, and idempotency responses are
stored transactionally. The schema contains no plaintext input column, enforces
immutable credential ownership and type with a database trigger, and revokes
table access from `PUBLIC`. Conditional version updates provide cross-process
optimistic concurrency; transaction-scoped advisory locks serialize reuse of an
organization's idempotency key.

`ApplyPostgresMigrations` must complete before the service accepts traffic. The
application database role should own only this service's database objects and
must not be shared with Praetor API, scheduler, or executor workloads.

## Run-scoped resolution

The scheduler registers an immutable run binding that snapshots one credential
version and exact executor workload identity. Executors resolve by run ID and
attempt ID only; they cannot submit a credential, organization, version, field,
injector, or output path. PostgreSQL atomically enforces time windows,
cancellation, executor matching, attempt replay, and resolution limits.

Credential inputs pass through a versioned injector registry. The result is
restricted to validated environment names and logical files with mode `0600`.
Failed decryption, authentication, or injector validation rolls back the attempt
and does not consume a resolution. Production transport must construct workload
identities exclusively from verified mTLS certificates, never request headers.

### Workload mTLS

The internal server requires TLS 1.3 and a client certificate chaining to the
configured workload CA. It accepts exactly one SPIFFE URI SAN in the configured
trust domain:

- `spiffe://<trust-domain>/workload/praetor-scheduler`
- `spiffe://<trust-domain>/workload/praetor-executor/<instance>`
- `spiffe://<trust-domain>/workload/praetor-api`
- `spiffe://<trust-domain>/workload/praetor-secrets-operator`
- `spiffe://<trust-domain>/workload/praetor-secrets-auditor`

Certificate subjects, DNS SANs, source addresses, proxy headers, and identity
headers are ignored. Scheduler routes cannot be called by executor identities,
and executor resolution cannot be called by the scheduler. Secret-bearing
responses disable caching and compression, close the connection after the
bounded response, and use stable value-free errors.

## Running the service

Build the executable with `go build ./cmd/praetor-secrets`. It applies database
migrations before becoming ready and shuts down gracefully on `SIGTERM`.
Secret values are accepted through restricted files, not environment variables
or command-line arguments.

Required environment variables:

| Variable | Purpose |
| --- | --- |
| `PRAETOR_SECRETS_LISTEN_ADDRESS` | mTLS API listener, for example `0.0.0.0:8443` |
| `PRAETOR_SECRETS_HEALTH_LISTEN_ADDRESS` | non-secret health listener, for example `0.0.0.0:8081` |
| `PRAETOR_SECRETS_TRUST_DOMAIN` | SPIFFE trust domain |
| `PRAETOR_SECRETS_DATABASE_URL_FILE` | restricted file containing the PostgreSQL URL |
| `PRAETOR_SECRETS_MASTER_KEY_FILE` | restricted current 32-byte master-key file |
| `PRAETOR_SECRETS_AUDIT_KEY_FILE` | restricted 32-byte audit-chain authentication key |
| `PRAETOR_SECRETS_TLS_CERTIFICATE_FILE` | server certificate chain |
| `PRAETOR_SECRETS_TLS_PRIVATE_KEY_FILE` | restricted server private-key file |
| `PRAETOR_SECRETS_CLIENT_CA_FILE` | CA used to authenticate workload clients |
| `PRAETOR_SECRETS_AUDIT_SINK_URL` | HTTPS endpoint accepting ordered audit records |
| `PRAETOR_SECRETS_AUDIT_SINK_CA_FILE` | CA authenticating the remote audit sink |
| `PRAETOR_SECRETS_AUDIT_SINK_CERTIFICATE_FILE` | outbound audit-delivery client certificate |
| `PRAETOR_SECRETS_AUDIT_SINK_PRIVATE_KEY_FILE` | restricted outbound client private key |

`PRAETOR_SECRETS_PREVIOUS_KEY_FILE` is optional during controlled rotation.
Optional bounded resource settings are `PRAETOR_SECRETS_SHUTDOWN_TIMEOUT`
(default `20s`), `PRAETOR_SECRETS_MAX_DATABASE_CONNECTIONS` (default `10`),
and `PRAETOR_SECRETS_MAX_NETWORK_CONNECTIONS` (default `100`).
`PRAETOR_SECRETS_MAX_PENDING_AUDIT_EVENTS` bounds the durable undelivered
audit queue (default `100000`); once full, sensitive mutations fail closed.
Delivery defaults to batches of `100`, a `1s` poll interval, and a `5s`
per-record timeout. The corresponding bounded overrides are
`PRAETOR_SECRETS_AUDIT_DELIVERY_BATCH_SIZE`,
`PRAETOR_SECRETS_AUDIT_DELIVERY_POLL_INTERVAL`, and
`PRAETOR_SECRETS_AUDIT_DELIVERY_REQUEST_TIMEOUT`.

The health listener exposes `GET /livez` and `GET /readyz`. It carries no
credential routes and should remain restricted to the cluster health-check
network. Readiness is reported only while the API listener is running and the
database responds.

### Kubernetes deployment

The repository includes a standalone Helm chart at
[`charts/praetor-secrets`](charts/praetor-secrets/README.md). It requires
pre-existing Kubernetes Secrets for the database URL, encryption/audit keys,
server identity, workload CA, and audit-sink identity. The chart never accepts
their contents as values and stages them as non-root-owned `0400` files in an
in-memory volume before starting the service.

The independent audit receiver is built with `go build ./cmd/praetor-audit-sink`
and deployed with [`charts/praetor-audit-sink`](charts/praetor-audit-sink/README.md).
It uses a separate PostgreSQL ownership boundary and accepts ingestion only from
the exact `spiffe://<trust-domain>/workload/praetor-secrets` client identity.
Its database URL and private key are likewise supplied only through restricted
files; see the chart README for the deployment variables and Secret keys.

For an isolated local cluster, `go run ./cmd/praetor-dev-bootstrap` generates
short-lived development CAs, exact workload identities, random master/audit
keys, and a `kubectl-secrets.sh` helper. Database URLs are read only from
restricted files, generated material is written under a new mode-`0700`
directory, and every output directory contains a deny-all `.gitignore`.
The generator refuses to overwrite an existing directory. These development
CAs must never be used outside a disposable local environment.
The generated `clients` directory contains API, scheduler, executor, operator,
and auditor certificates for local mTLS integration tests. It also includes the
scheduler claim-listener certificate, the executor client CA, and the executor's
separate Secrets server CA key expected by the Praetor chart. The `clients`
directory is not applied as a Kubernetes Secret by the helper.

## Audit spool

Every PostgreSQL security-state mutation requires an audit spool append in the
same transaction. If the spool is unavailable, invalid, or at its configured
pending-event bound, the state change rolls back. Events use a fixed,
value-free schema and form an HMAC-SHA-256 chain authenticated by the separate
audit key. Startup migrations make event content and chain fields immutable;
only an exact-MAC delivery acknowledgement may set `delivered_at`.

The spool verifies the complete chain and durable head before delivery. Sink
downtime does not block mutations until the bounded local spool is exhausted.
Records are sent in sequence order over HTTPS with a stable MAC-derived
idempotency key. A record is acknowledged locally only after a 2xx response;
failures retry without skipping later records.

Every protected request receives a generated request ID and emits a value-free
completion event containing the verified workload identity, stable operation,
result, reason code, and latency class. Successful security mutations persist
their completion and state-transition events in the same transaction. The
operator and auditor identities may read `/internal/v1/security-status`, which
reports only audit integrity, delivery degradation, pending queue pressure, and
the last successful delivery time. Scheduler and executor identities cannot
read this endpoint.

## Core invariants

- Only this service receives the master key.
- PostgreSQL stores authenticated ciphertext and wrapped data keys, never
  credential plaintext.
- Executors resolve only the credential assigned to an authenticated run.
- Browsers and normal API clients cannot retrieve stored secret values.
- Secret material is structurally excluded from logs, events, traces, and
  persisted execution messages.
- Key backup, rotation, and disaster recovery are part of the product boundary.
