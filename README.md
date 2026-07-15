# Praetor Secrets Service

Provider-independent, run-scoped credential storage and resolution for Praetor.

This repository owns the Secrets Service security boundary, API, storage format,
deployment, recovery tooling, and security tests. The main Praetor repository
integrates with the service as a client and does not receive its master key.

Development is tracked in the private
[Praetor Secrets Service project](https://github.com/orgs/Niftel/projects/1).

## Current phase

Core service implementation is underway. The envelope format, strict
file-backed master-key loader, and redacted credential lifecycle domain are
implemented; durable storage, transport, and run-scoped resolution follow.

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

## Core invariants

- Only this service receives the master key.
- PostgreSQL stores authenticated ciphertext and wrapped data keys, never
  credential plaintext.
- Executors resolve only the credential assigned to an authenticated run.
- Browsers and normal API clients cannot retrieve stored secret values.
- Secret material is structurally excluded from logs, events, traces, and
  persisted execution messages.
- Key backup, rotation, and disaster recovery are part of the product boundary.
