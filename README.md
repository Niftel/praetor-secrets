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
domain and authenticated internal transport are implemented; service assembly,
audit delivery, and Praetor integration follow.

- [Threat model](docs/threat-model.md)
- [Service API and trust-boundary specification](docs/service-api.md)
- [Envelope record format](docs/envelope-format.md)

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

Certificate subjects, DNS SANs, source addresses, proxy headers, and identity
headers are ignored. Scheduler routes cannot be called by executor identities,
and executor resolution cannot be called by the scheduler. Secret-bearing
responses disable caching and compression, close the connection after the
bounded response, and use stable value-free errors.

## Core invariants

- Only this service receives the master key.
- PostgreSQL stores authenticated ciphertext and wrapped data keys, never
  credential plaintext.
- Executors resolve only the credential assigned to an authenticated run.
- Browsers and normal API clients cannot retrieve stored secret values.
- Secret material is structurally excluded from logs, events, traces, and
  persisted execution messages.
- Key backup, rotation, and disaster recovery are part of the product boundary.
