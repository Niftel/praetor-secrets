# Praetor Secrets Service threat model

Status: Accepted baseline  
Project: [Niftel — Praetor Secrets Service](https://github.com/orgs/Niftel/projects/1)

## 1. Purpose

The Praetor Secrets Service stores and releases automation credentials without
allowing the Praetor API, scheduler, message bus, user interface, or a database
backup to recover those credentials independently.

This document defines the security boundary before the service API or storage
format is implemented. A change that violates an invariant in this document must
be treated as a security-design change, not a routine implementation detail.

## 2. Scope

The first release protects credentials used by Praetor automation, including:

- SSH private keys, passwords, and key passphrases;
- privilege-escalation passwords;
- source-control credentials;
- cloud and dynamic-inventory credentials; and
- tokens represented by Praetor credential types.

It covers creating, updating, encrypting, resolving, rotating, auditing, backing
up, and restoring those credentials. It also covers the service identity and
execution-run checks required before plaintext is released.

### Non-goals for the first release

- A general-purpose secret manager for arbitrary applications.
- User-facing retrieval or display of stored plaintext.
- Dynamic database users, certificate-authority functions, PKI, or SSH signing.
- Custom cryptographic algorithms or primitives.
- Protecting plaintext after a legitimately authorized executor is fully
  compromised during the lifetime of a run.
- Protecting against a cluster administrator who can simultaneously read the
  master key, modify the Secrets Service workload, and read its memory.
- Replacing external KMS or Vault products. Provider adapters may be added later
  without changing the run-scoped release contract.

## 3. Assets

| Asset | Security requirement |
|---|---|
| Credential plaintext | Confidentiality and integrity at rest and in transit |
| Master key | Confidentiality, integrity, availability, and independent backup |
| Per-credential data-encryption keys | Confidentiality and integrity |
| Ciphertext and wrapped keys | Integrity, authenticity, durability, and versioning |
| Credential metadata | Organization isolation, integrity, and controlled visibility |
| Run-to-credential binding | Integrity and non-bypassability |
| Service identities | Unforgeability and rotation |
| Audit records | Integrity, useful attribution, and secret-free contents |
| Backup material | Confidentiality, integrity, completeness, and recoverability |

Credential names and ownership are sensitive metadata but are not treated as
credential plaintext. API responses must still be restricted by Praetor RBAC.

## 4. Actors

- **Credential administrator:** creates or changes credential records and grants
  access. May submit plaintext but may not retrieve stored plaintext later.
- **Automation operator:** launches an authorized template. Does not receive the
  credential used by the run.
- **Praetor API:** authenticates users, enforces user-facing RBAC, and sends
  credential write requests. It does not hold the master key.
- **Scheduler:** selects work and snapshots the permitted credential ID onto an
  execution run. It does not receive plaintext.
- **Executor:** resolves the one credential assigned to its authenticated run and
  uses the resulting material for that run.
- **Secrets Service:** owns encryption, decryption, release policy, key versions,
  and secret-safe audit events.
- **Database and backup operators:** maintain storage but are not trusted with
  plaintext or the master key.
- **Cluster administrator:** operates the deployment and trust root. This is a
  privileged role that must be separated operationally where possible.
- **External provider:** optional future Vault or KMS integration. It must not be
  required for a standalone installation.

## 5. Trust boundaries and data flow

```text
Browser
   |
   | user-authenticated TLS; plaintext only on create/update
   v
Praetor API -----------------------> Secrets Service
   |                                  |       |
   | metadata and secret references   |       | read-only master-key file
   v                                  |       v
PostgreSQL <--------------------------+   /etc/praetor-secrets/MASTER_KEY
   ^             ciphertext only
   |
Scheduler -- credential ID --> execution run
                                      |
Executor -- service identity + run ID-+
                                      |
                                      v
                           run-scoped plaintext response
```

The following are distinct trust zones even when deployed in one Kubernetes
cluster:

1. User/browser and public ingress.
2. Praetor API.
3. Scheduler, message bus, and persisted execution manifests.
4. Executor and managed automation host.
5. Secrets Service.
6. PostgreSQL and database backups.
7. Kubernetes control plane and master-key storage.

Network location alone is not authentication. Every cross-service request must
carry a verifiable service identity and must be authorized for the operation.

## 6. Security invariants

### Storage and cryptography

1. The implementation uses standard, reviewed authenticated-encryption
   primitives. Praetor does not design a cipher, mode, padding scheme, nonce
   construction, or random-number generator.
2. Each credential version has an independently generated data-encryption key.
3. Credential plaintext is encrypted with authenticated encryption. Associated
   data binds the ciphertext to immutable identifiers including the credential,
   organization, field, record format, and key version.
4. The master key wraps data-encryption keys; it does not directly encrypt every
   credential value.
5. PostgreSQL stores ciphertext, non-secret metadata, key versions, and wrapped
   data-encryption keys only.
6. The master key is not stored in PostgreSQL, a container image, Helm values in
   source control, logs, events, or execution messages.
7. Ciphertext formats are explicitly versioned. Unknown versions fail closed.
8. Nonces and data-encryption keys come from the operating system's
   cryptographically secure random source and are never reused where the chosen
   primitive forbids reuse.
9. Authentication failures, modified ciphertext, wrong associated data, and
   unknown keys return indistinguishable non-secret errors and never partial
   plaintext.

### Authorization and release

10. Browsers and normal API clients cannot retrieve stored plaintext after a
    write. Secret fields are represented by a stable redaction marker.
11. A credential administrator can replace a secret but cannot reveal its prior
    value.
12. An executor cannot request an arbitrary credential ID. Resolution accepts an
    execution-run identity and derives the permitted credential from the
    server-side run snapshot.
13. The run must be in an eligible non-terminal state and assigned to the
    requesting executor or execution identity.
14. A run with no credential resolves to no credential. Client input cannot add
    or replace a run's credential during resolution.
15. Organization and object RBAC checks are performed when credentials are
    created, attached, launched, and administered. Runtime resolution does not
    replace those checks; it enforces the already-authorized snapshot.
16. Resolution credentials are short-lived and scoped. Replay outside the
    permitted run and time window fails.
17. Internal transport is authenticated and encrypted. Possession of cluster
    network access is insufficient.

### Plaintext handling

18. Plaintext is never persisted in PostgreSQL, an outbox, NATS, execution
    manifests, job events, traces, metrics, panic output, or audit records.
19. Plaintext exists only in bounded process memory and, where an automation tool
    requires a file, a run-specific file with mode `0600` in a private temporary
    directory.
20. Temporary credential files are removed on success, failure, cancellation,
    timeout, and process recovery. The design does not claim secure deletion from
    copy-on-write or journaled storage.
21. Request and response bodies containing secrets are excluded from generic
    logging, tracing, diagnostics, and error middleware by construction.
22. Crash reports and support bundles must redact secrets and encrypted values.

### Operations, rotation, and recovery

23. Production startup fails if the master-key file is absent, empty, malformed,
    too permissive under the documented deployment model, or an unsupported
    version.
24. The master key is stable across upgrades and restarts. Deployments must not
    silently generate a replacement key when encrypted records already exist.
25. Rotation is versioned, resumable, observable, and safe to retry. Mixed key
    versions remain readable during an explicitly bounded migration period.
26. Removing an old key is a deliberate operation gated on proof that no active
    record or supported backup requires it.
27. Database backups and master-key backups are stored and access-controlled
    separately. A recovery procedure requires both.
28. Restore validation proves that representative records can be authenticated
    and decrypted without exposing their values to logs or operators.
29. Key loss is unrecoverable by design. Documentation must state this plainly.
30. Only the Secrets Service workload receives the master-key mount. The API,
    scheduler, UI, message bus, and ordinary migration jobs do not receive it.

## 7. Threat scenarios and required controls

### 7.1 Database or backup theft

**Attacker capability:** Read all tables, indexes, transaction logs, and database
backups; modify database rows in the active system.

**Required outcome:** The attacker cannot recover plaintext without the master
key. Row substitution, rollback, ciphertext modification, or cross-organization
copying is detected through authenticated encryption and associated data.

**Controls:** Envelope encryption, independently stored master key, associated
data, versioned records, database least privilege, and restore integrity checks.

### 7.2 Praetor API compromise

**Attacker capability:** Execute code in the API pod, call internal services using
the API identity, and observe new secret values submitted while compromised.

**Required outcome:** The attacker cannot decrypt historical credentials or
resolve arbitrary run credentials. Secrets submitted during the active compromise
cannot be protected from the compromised receiving process; this residual risk
must be explicit.

**Controls:** No master-key mount in API, distinct service identities, write-only
secret interface, no arbitrary resolution API, network policy, and alerting on
unusual credential writes.

### 7.3 Executor compromise or impersonation

**Attacker capability:** Control one executor or steal its service credential.

**Required outcome:** The attacker cannot resolve another executor's run, another
credential by ID, a terminal run, or an unassigned credential. A legitimately
compromised executor can access plaintext for its currently authorized run; that
is residual risk.

**Controls:** Per-workload identity, run assignment verification, bounded tokens,
eligible-state checks, rate limits, network policy, and resolution audit events.

### 7.4 Replay and confused-deputy attacks

**Attacker capability:** Capture or repeat a valid internal request, substitute a
run identifier, or induce a privileged service to request on its behalf.

**Required outcome:** Replays outside the run's valid window fail, identifiers are
bound to the authenticated caller and request, and the Secrets Service derives the
credential from authoritative run state.

**Controls:** Short-lived audience-bound authentication, request freshness or
one-time grants where practical, server-side run lookup, strict method and content
type validation, and idempotency only where explicitly designed.

### 7.5 Supply-chain compromise

**Attacker capability:** Publish a malicious dependency or image used by one
Praetor component.

**Required outcome:** Compromise of a component without the master key does not
automatically expose stored plaintext. Compromise of the running Secrets Service
can expose credentials it can legitimately decrypt and is a critical residual
risk.

**Controls:** Minimal dependency set, pinned and verified builds, SBOM and
provenance, isolated service account, read-only filesystem, restricted egress,
non-root execution, narrow API, reproducible security tests, and independent
review. Isolation reduces blast radius; it does not make a compromised Secrets
Service safe.

### 7.6 Logging and observability leakage

**Attacker capability:** Read application logs, traces, metrics, events, panic
reports, or support bundles.

**Required outcome:** No plaintext or reusable resolution token appears in those
systems.

**Controls:** Typed secret values that do not implement useful string formatting,
body logging disabled on secret routes, allowlisted audit fields, structured error
codes, and automated canary-secret leakage tests across observability outputs.

### 7.7 Key loss, wrong key, or interrupted rotation

**Attacker or failure capability:** Delete or replace the master key, restore a
database with a mismatched key, or interrupt rewrapping midway.

**Required outcome:** Services fail closed without destroying ciphertext. Rotation
is safely resumable. Operators receive diagnostics identifying key versions and
record counts without receiving plaintext.

**Controls:** Stable key identifiers, previous-key support during migration,
transactional record updates, retry-safe rotation jobs, separate backups, restore
drills, and an explicit finalization gate before old-key destruction.

### 7.8 Malicious credential-type injector

**Attacker capability:** Define or alter an injector to place a secret into an
unsafe environment variable, command argument, path, event, or template.

**Required outcome:** Injectors cannot execute templates or select arbitrary sinks.
Only an allowlisted schema maps secret fields to supported environment variables
or files.

**Controls:** Declarative validated injectors, restricted variable names and file
destinations, no shell interpolation, no path traversal, immutable managed types,
and security review for custom types.

## 8. Availability and denial of service

Secrets resolution is on the execution critical path. The service must fail
closed when unavailable: a run remains pending or fails with a non-secret error;
it never falls back to plaintext stored elsewhere.

Availability controls include bounded request sizes, timeouts, rate limits,
connection limits, readiness checks that do not decrypt customer secrets, safe
retry semantics, and disruption-aware replication. Availability does not justify
replicating the master key to unrelated services.

## 9. Audit requirements

Audit events record:

- credential creation, metadata change, secret replacement, and deletion;
- RBAC grant and revoke events;
- successful and denied resolution attempts;
- caller identity, run ID, credential ID, organization ID, outcome, and reason
  code;
- key rotation start, progress, completion, cancellation, and finalization; and
- backup and restore validation events.

Audit events never contain plaintext, ciphertext, wrapped keys, authentication
tokens, request bodies, injected environment values, or credential files.

## 10. Required security tests

Before production readiness, automated tests must demonstrate:

1. A database dump cannot be decrypted without the master key.
2. Modified, truncated, swapped, or replayed ciphertext fails authentication.
3. Cross-credential, cross-field, and cross-organization ciphertext substitution
   fails because associated data differs.
4. The API identity cannot call resolution or obtain historical plaintext.
5. An executor cannot resolve another run, an unassigned credential, or a
   terminal run.
6. A captured request cannot be reused outside its permitted scope and lifetime.
7. Canary secret values do not appear in logs, traces, metrics, events, errors,
   outbox rows, NATS messages, or persisted manifests.
8. Interrupted rotation resumes without data loss and old keys cannot be removed
   while referenced.
9. Restore with a wrong or missing key fails closed without modifying data.
10. Malicious injector names, paths, templates, and shell syntax are rejected.

An independent review of the design and security-sensitive implementation is a
release gate, not an optional follow-up.

## 11. Open design decisions

The service API specification must resolve these questions without weakening the
invariants above:

- workload identity mechanism for the standalone and Kubernetes deployments;
- authenticated-encryption and key-wrapping primitive provided by the selected
  standard library;
- whether secret fields are encrypted independently or as one credential payload;
- replay-control mechanism for executor resolution;
- memory and temporary-file handling supported consistently across executors;
- audit sink and tamper-resistance boundary; and
- ownership of schema migrations once the master key is removed from the current
  API and ingestion services.

## 12. Acceptance criteria

This threat-model task is complete when:

- owners of the API, scheduler, executor, ingestion, and deployment paths review
  the trust boundaries;
- every security invariant is either accepted or changed through an explicit
  design decision;
- database theft, API compromise, executor impersonation, replay, logging
  leakage, supply-chain compromise, malicious injectors, interrupted rotation,
  and key loss have agreed controls and residual risks;
- the service API specification references these invariants; and
- unresolved decisions are tracked as project items rather than silently assumed.
