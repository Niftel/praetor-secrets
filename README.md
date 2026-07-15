# Praetor Secrets Service

Provider-independent, run-scoped credential storage and resolution for Praetor.

This repository owns the Secrets Service security boundary, API, storage format,
deployment, recovery tooling, and security tests. The main Praetor repository
integrates with the service as a client and does not receive its master key.

Development is tracked in the private
[Praetor Secrets Service project](https://github.com/orgs/Niftel/projects/1).

## Current phase

The project is in security design. Implementation begins only after the threat
model and service API specification have been reviewed.

- [Threat model](docs/threat-model.md)

## Core invariants

- Only this service receives the master key.
- PostgreSQL stores authenticated ciphertext and wrapped data keys, never
  credential plaintext.
- Executors resolve only the credential assigned to an authenticated run.
- Browsers and normal API clients cannot retrieve stored secret values.
- Secret material is structurally excluded from logs, events, traces, and
  persisted execution messages.
- Key backup, rotation, and disaster recovery are part of the product boundary.
