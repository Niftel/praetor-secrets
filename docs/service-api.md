# Praetor Secrets Service API and trust-boundary specification

Status: Draft for review  
Threat model: [threat-model.md](threat-model.md)  
Project: [Niftel — Praetor Secrets Service](https://github.com/orgs/Niftel/projects/1)

## 1. Purpose

This specification defines the first internal API for the Praetor Secrets
Service. It translates the accepted threat-model invariants into explicit
service identities, endpoint permissions, request contracts, state transitions,
and data-flow restrictions.

The API is intentionally not a general secret-retrieval API. Credential
plaintext enters through create or replace operations and leaves only through an
authenticated, run-scoped resolution operation.

## 2. Deployment boundary

The Secrets Service is a separately deployable service and repository. It owns:

- encryption and decryption;
- credential ciphertext and wrapped data-key records;
- credential versioning and replacement;
- execution-run credential bindings;
- resolution authorization and replay controls;
- key-version metadata and rotation operations; and
- secret-safe audit events.

It does not own:

- human authentication;
- organizations, teams, or Praetor RBAC policy;
- job templates, workflows, inventories, or execution scheduling;
- executor placement;
- job logs or events; or
- the user interface.

Praetor services use the Secrets Service as clients. They do not share its
master key or decrypt its database records.

## 3. Service identities

Every protected request is authenticated as exactly one workload identity.
Network location, source IP, namespace membership, and possession of a generic
cluster token are not identities.

| Identity | Permitted operations |
|---|---|
| `praetor-api` | Create credential; replace secret fields; update metadata; read redacted metadata; retire credential |
| `praetor-scheduler` | Register, inspect, and cancel run bindings |
| `praetor-executor:<instance>` | Resolve bindings assigned to that exact executor identity |
| `praetor-secrets-operator` | Inspect key status; start/resume/finalize rotation; run recovery validation |
| `praetor-secrets-auditor` | Read secret-free service audit events and security status |

No identity receives an implicit union of permissions. A workload requiring two
roles must use two separately configured clients or an explicitly reviewed
combined identity.

### 3.1 Production authentication

Production uses mutually authenticated TLS with short-lived workload
certificates. The authenticated certificate identity maps to one service role and,
for executors, one immutable executor instance identity.

Requirements:

- certificates have an explicit Secrets Service audience or trust domain;
- certificate lifetimes are bounded and automatically rotated;
- client and server certificate revocation or emergency replacement is
  documented and tested;
- application authorization uses the verified certificate identity, never a
  caller-supplied identity header; and
- TLS terminates at the Secrets Service process or at a sidecar whose verified
  identity is cryptographically forwarded to the process. An ordinary ingress
  header is insufficient.

Kubernetes service-account tokens may be exchanged for workload certificates,
but raw long-lived service-account tokens are not the steady-state application
protocol.

### 3.2 Standalone development authentication

Standalone development may use a local test CA and per-service client
certificates. It must not introduce a shared bearer token fallback into the
production server configuration.

An explicitly compiled or configured insecure mode may exist only for isolated
tests. The service must identify that mode in health output and refuse it when
the production profile is enabled.

### 3.3 Human actor context

Credential writes originate from a human action but arrive through
`praetor-api`. The API includes non-authoritative audit context:

- `actor_user_id`;
- `actor_username` where available;
- `request_id`; and
- the Praetor authorization decision identifier where available.

This context is used for attribution, not service authentication. The Secrets
Service records both the authenticated workload identity and the asserted human
actor. It never accepts actor context from executor or scheduler identities.

## 4. Transport and protocol requirements

- Internal API base path: `/internal/v1`.
- HTTPS with TLS 1.3 is required outside isolated unit tests.
- Requests and responses use `application/json` unless an endpoint explicitly
  states otherwise.
- Unknown JSON fields are rejected.
- Request bodies are size-limited before decoding.
- Duplicate JSON keys are rejected.
- IDs are UUIDs encoded in lowercase canonical text.
- Timestamps are UTC RFC 3339 with fractional seconds allowed.
- Clients send `X-Request-ID`; the service generates one if absent. Request IDs
  are identifiers, never authentication or replay tokens.
- Error responses use `application/problem+json` and stable machine-readable
  error codes.
- Secret-bearing request and response bodies are excluded from generic HTTP
  logging and tracing before middleware is installed.
- Compression is disabled on secret-bearing responses to reduce accidental
  cross-context exposure and simplify bounded-memory handling.

## 5. Resource model

### 5.1 Credential

A credential is a service-owned record with immutable identity and ownership.

```json
{
  "id": "98d977e4-3f0a-44cd-81cb-8965d5522996",
  "organization_id": "5",
  "name": "production-machine",
  "credential_type": "machine",
  "version": 3,
  "state": "active",
  "secret_fields": ["password", "ssh_private_key"],
  "created_at": "2026-07-15T12:00:00Z",
  "updated_at": "2026-07-15T12:10:00Z"
}
```

Rules:

- `organization_id` is an opaque Praetor identifier and is immutable.
- `credential_type` is immutable after creation.
- `version` increases on every metadata or secret replacement that changes the
  record.
- secret values are never present in a credential response.
- `secret_fields` reveals field names that are populated, not their values.
- states are `active` or `retired` in v1.
- retirement prevents new run bindings but does not destroy versions required by
  an already valid run or supported recovery window.

### 5.2 Credential secret payload

Writes contain a map of credential fields. The selected credential-type schema
defines which fields are secret and which non-secret values may be returned.

```json
{
  "username": "automation",
  "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "become_method": "sudo",
  "become_password": "example"
}
```

The service validates the payload against an immutable, versioned credential-type
schema. It does not execute user-supplied templates. Injector rendering is a
separate allowlisted operation performed only during run resolution.

### 5.3 Run binding

A run binding is the server-side authorization that associates one execution run
with one credential version and one executor identity.

```json
{
  "run_id": "32b9fc25-fd71-47e6-b0e8-45db87df9f65",
  "organization_id": "5",
  "credential_id": "98d977e4-3f0a-44cd-81cb-8965d5522996",
  "credential_version": 3,
  "executor_identity": "praetor-executor:worker-7",
  "state": "active",
  "not_before": "2026-07-15T12:30:00Z",
  "expires_at": "2026-07-15T12:45:00Z",
  "max_resolutions": 2,
  "resolution_count": 0
}
```

Rules:

- the scheduler registers the binding after launch authorization and executor
  assignment;
- the Secrets Service snapshots the current credential version at registration;
- an executor supplies only `run_id`, never `credential_id`;
- the service derives the credential and version from the binding;
- the authenticated executor must exactly match `executor_identity`;
- a binding is `pending`, `active`, `canceled`, `expired`, or `exhausted`;
- expiration and resolution limits are enforced atomically; and
- a canceled, expired, or exhausted binding cannot return plaintext.

## 6. Credential-management API

All endpoints in this section require the `praetor-api` identity.

### 6.1 Create credential

`POST /internal/v1/credentials`

Request:

```json
{
  "organization_id": "5",
  "name": "production-machine",
  "credential_type": "machine",
  "schema_version": 1,
  "inputs": {
    "username": "automation",
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
  },
  "actor": {
    "user_id": "104",
    "username": "demo-operator",
    "authorization_decision_id": "01J2EXAMPLE"
  }
}
```

Response: `201 Created` with redacted credential metadata and a `Location`
header. The response never echoes `inputs`.

The route requires `Idempotency-Key`. Repeating the same key and identical
authenticated request returns the original result. Reusing the key with different
content returns `409 idempotency_conflict`.

### 6.2 Read credential metadata

`GET /internal/v1/credentials/{credential_id}`

Response: `200 OK` with redacted metadata. This endpoint has no query parameter,
header, role, or debug mode that reveals secret values or ciphertext.

### 6.3 Replace credential fields

`PUT /internal/v1/credentials/{credential_id}/inputs`

Request:

```json
{
  "expected_version": 3,
  "inputs": {
    "username": "automation",
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
  },
  "actor": {
    "user_id": "104",
    "authorization_decision_id": "01J2EXAMPLE"
  }
}
```

This is replacement, not a secret-aware merge. A client preserves an existing
secret by omitting the entire update operation, not by receiving and resubmitting
an encryption marker. Partial field replacement may be added later only with an
explicit keep/replace/delete operation model.

Response: `200 OK` with redacted metadata. A version mismatch returns
`409 version_conflict` without changing data.

### 6.4 Update non-secret metadata

`PATCH /internal/v1/credentials/{credential_id}`

Only allowlisted metadata fields such as `name` are accepted. Organization,
credential type, key versions, state, and ownership cannot be patched.

Request includes `expected_version`. Response is redacted metadata.

### 6.5 Retire credential

`POST /internal/v1/credentials/{credential_id}/retire`

Retirement is idempotent and prevents new run bindings. It does not immediately
destroy cryptographic material that an active run or retention policy requires.

Hard deletion is not part of the v1 online API. A separately reviewed retention
worker may cryptographically erase eligible retired versions by deleting wrapped
data keys after all retention and recovery constraints are satisfied.

## 7. Scheduler run-binding API

All endpoints in this section require the `praetor-scheduler` identity.

### 7.1 Register run binding

`POST /internal/v1/run-bindings`

Request:

```json
{
  "run_id": "32b9fc25-fd71-47e6-b0e8-45db87df9f65",
  "organization_id": "5",
  "credential_id": "98d977e4-3f0a-44cd-81cb-8965d5522996",
  "executor_identity": "praetor-executor:worker-7",
  "not_before": "2026-07-15T12:30:00Z",
  "expires_at": "2026-07-15T12:45:00Z",
  "max_resolutions": 2,
  "dispatch_id": "ae8d16d8-e58d-4ec3-953a-4ddd10c65962"
}
```

Response: `201 Created` with binding metadata and no secret value.

Validation:

- `run_id` and `dispatch_id` are unique;
- credential exists, is active, and belongs to the organization asserted in the
  scheduler's authenticated dispatch context;
- executor identity is syntactically valid and authorized for executor use;
- `not_before` and `expires_at` fall within configured bounds;
- `max_resolutions` is within the service policy; and
- the binding snapshots the credential version atomically.

The scheduler must not register a binding until Praetor has completed template,
inventory, host-limit, credential-use, and execution authorization. The Secrets
Service does not infer human RBAC from this request.

`Idempotency-Key` is required. A conflicting second binding for the same run
returns `409 run_binding_conflict` and never changes the original credential or
executor assignment.

### 7.2 Inspect binding

`GET /internal/v1/run-bindings/{run_id}`

Returns non-secret binding metadata for scheduler reconciliation. It does not
include ciphertext, wrapped keys, injector output, or resolution credentials.

### 7.3 Cancel binding

`POST /internal/v1/run-bindings/{run_id}/cancel`

Request includes a stable reason code and dispatch ID. Cancellation is monotonic
and idempotent. It cannot reactivate or replace a binding.

The scheduler calls cancellation when a run is canceled, reaches a terminal state,
is reassigned before activation, or fails dispatch. Expiration remains a
server-side backstop and does not depend on scheduler cleanup.

## 8. Executor resolution API

### 8.1 Resolve run credential

`POST /internal/v1/runs/{run_id}/credential:resolve`

This endpoint requires an authenticated `praetor-executor:<instance>` identity.

Request:

```json
{
  "attempt_id": "31024db7-0db8-446a-b049-dd9d172cde94",
  "requested_at": "2026-07-15T12:31:02.123Z"
}
```

The request contains no credential ID, credential version, organization ID,
injector, field list, or output destination.

Before decryption, the service atomically verifies:

1. the binding exists and is active;
2. current time is within its validity window;
3. authenticated executor identity exactly matches the binding;
4. `attempt_id` is either new or an idempotent retry by the same identity;
5. resolution count remains below the binding maximum;
6. the snapshotted credential version still exists and authenticates; and
7. no administrative security lock prevents resolution.

Response: `200 OK`

```json
{
  "run_id": "32b9fc25-fd71-47e6-b0e8-45db87df9f65",
  "attempt_id": "31024db7-0db8-446a-b049-dd9d172cde94",
  "expires_at": "2026-07-15T12:35:00Z",
  "environment": {
    "ANSIBLE_REMOTE_USER": "automation"
  },
  "files": [
    {
      "name": "ANSIBLE_PRIVATE_KEY_FILE",
      "mode": "0600",
      "content": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
    }
  ]
}
```

The response schema is an allowlisted injector result. File `name` values are
logical names, not caller-controlled paths. The executor creates private files in
its run directory and maps logical names to those paths. The service never returns
shell fragments, command-line arguments, arbitrary paths, templates, or logging
directives.

Resolution response requirements:

- `Cache-Control: no-store` and `Pragma: no-cache`;
- no compression;
- no body logging, tracing, or sampling;
- strict response-size bound;
- short deadline and immediate connection close after bounded response where the
  transport implementation makes that safer; and
- zero secret values in error responses.

The response is plaintext over authenticated TLS. Application-level response
encryption may be added only if it is bound to the executor workload identity and
does not create long-lived bearer decryption keys.

### 8.2 Retry semantics

An identical `attempt_id` from the same executor may receive the same logical
credential result while the binding and attempt response window remain valid. It
does not consume another resolution count.

A new `attempt_id` consumes one resolution. An attempt ID used by another
identity, another run, or with conflicting request content returns
`409 attempt_conflict`.

The service stores only the attempt metadata required for replay control. It does
not persist the plaintext response for retries; it deterministically resolves the
same snapshotted credential version again.

## 9. Operations API

Operations endpoints use `/internal/v1/operations` and require the dedicated
`praetor-secrets-operator` identity. They are unavailable to API, scheduler, and
executor identities.

Initial operations:

- `GET /internal/v1/operations/key-status` — key IDs, versions, and record counts;
- `POST /internal/v1/operations/rotations` — start a resumable rewrap operation;
- `GET /internal/v1/operations/rotations/{rotation_id}` — non-secret progress;
- `POST /internal/v1/operations/rotations/{rotation_id}/resume`;
- `POST /internal/v1/operations/rotations/{rotation_id}/finalize`; and
- `POST /internal/v1/operations/recovery-validations` — authenticate and decrypt
  representative records while returning counts and hashes of metadata, never
  plaintext.

Rotation and recovery request schemas require a separate design review before
implementation. No generic debug, SQL, export, decrypt, or reveal endpoint is
permitted.

## 10. Health and security status

- `GET /livez` reports process liveness only.
- `GET /readyz` reports database connectivity, schema compatibility, and usable
  configured primary-key version without decrypting customer credential values.
- `GET /internal/v1/security-status` requires operator or auditor identity and
  returns active key IDs, insecure-mode state, certificate expiry, pending
  rotations, and policy versions without secret material.

Public health responses do not include database addresses, key IDs, certificate
subjects, dependency versions, record counts, or error details useful for
reconnaissance.

## 11. Error model

Errors use a stable code and a request identifier:

```json
{
  "type": "https://docs.praetor.dev/problems/run-binding-not-active",
  "title": "Credential is unavailable for this run",
  "status": 403,
  "code": "run_binding_not_active",
  "request_id": "01J2EXAMPLE"
}
```

Rules:

- errors never include plaintext, ciphertext, wrapped keys, submitted secret
  fields, tokens, certificate contents, SQL, stack traces, or injector output;
- public messages intentionally collapse missing, unauthorized, expired, and
  cryptographically invalid secret states where distinction would aid probing;
- detailed reason codes are restricted to secret-free audit events;
- cryptographic authentication failure returns a generic service error and raises
  a security event; and
- retryability is expressed with stable codes and bounded `Retry-After`, not raw
  internal errors.

Core codes include:

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `invalid_request` | Schema, size, or validation failure |
| 401 | `workload_authentication_failed` | No valid workload identity |
| 403 | `operation_not_permitted` | Identity cannot call this operation |
| 403 | `run_binding_not_active` | Resolution is not authorized now |
| 404 | `resource_not_found` | Non-secret resource unavailable |
| 409 | `version_conflict` | Optimistic credential version mismatch |
| 409 | `run_binding_conflict` | Run already has a different binding |
| 409 | `attempt_conflict` | Attempt identifier replayed inconsistently |
| 413 | `request_too_large` | Body exceeds the endpoint limit |
| 429 | `rate_limited` | Identity or operation limit exceeded |
| 500 | `secure_operation_failed` | Fail-closed cryptographic or storage error |
| 503 | `service_unavailable` | Dependency or security lock prevents service |

## 12. Audit contract

Each protected request emits one completion audit event and, where applicable,
one state-transition event. Required fields:

- event type and schema version;
- timestamp and request ID;
- authenticated workload identity;
- asserted human actor only for API writes;
- organization, credential, run, executor, and rotation identifiers where
  applicable;
- operation, result, stable reason code, and latency class; and
- policy, schema, credential, and key version numbers where non-secret.

Forbidden fields:

- request or response bodies;
- plaintext or encrypted credential values;
- wrapped data keys;
- bearer tokens, certificates, or private keys;
- environment values or file contents;
- SQL and stack traces; and
- hashes of low-entropy secret values.

Audit delivery failure follows an explicit policy: security-sensitive state
changes fail closed when the durable local audit spool cannot accept an event.
Read-only metadata operations may continue with a degraded security-status alert.
Remote audit-sink availability is decoupled through the bounded durable spool.
The local spool authenticates an append-only sequence with a dedicated
file-backed HMAC key. The chain head, sequence, previous MAC, canonical event,
and current MAC are verified before delivery. Delivery acknowledgements may set
only `delivered_at` and must match the record MAC; event content remains
immutable. Exhausting the configured pending-event bound rejects the enclosing
state-change transaction.

## 13. Rate and resource limits

Limits are configured per identity and operation. Conservative defaults include:

- credential input payload: 1 MiB maximum before encoding overhead;
- maximum fields and field-name length defined by credential schema;
- run-binding lifetime: 30 minutes maximum unless a reviewed workflow class
  requires longer;
- resolution response: 1 MiB maximum;
- resolution count: default 2, hard maximum 5;
- request deadline: 10 seconds for writes, 5 seconds for resolution; and
- concurrent resolution limit per executor identity.

Limit failures occur before decryption wherever possible. Rate-limit keys use the
authenticated workload identity, not a caller-controlled address or header.

## 14. Prohibited interfaces and shortcuts

The following are forbidden in v1:

- `GET /secrets/{id}` or any equivalent arbitrary plaintext retrieval;
- a query option, admin role, debug flag, or support mode that reveals secrets;
- accepting `credential_id` from an executor resolution request;
- sending plaintext through NATS, an outbox, job manifest, event, log, trace, or
  metric;
- mounting the master key into API, scheduler, executor, UI, or ordinary migration
  workloads;
- shared cluster-wide bearer authentication;
- caller-defined injector templates, shell snippets, command arguments, or paths;
- returning raw storage or cryptographic errors; and
- silently falling back to the current in-process decryption path when the
  Secrets Service is unavailable.

## 15. Integration sequence

1. Implement storage and credential-management endpoints behind workload mTLS.
2. Teach Praetor API to dual-write only in an isolated migration environment;
   production migration requires a separately reviewed cutover plan.
3. Implement scheduler run-binding registration and cancellation.
4. Implement executor resolution using run ID and executor identity.
5. Verify plaintext is absent from scheduler memory, outbox, NATS, persisted
   manifests, events, logs, and traces.
6. Remove master-key access and legacy decryption code from Praetor API,
   scheduler, ingestion, and other non-Secrets-Service workloads.
7. Disable legacy resolution permanently; no runtime fallback remains.
8. Complete rotation, backup, restore, and adversarial tests before production
   readiness.

## 16. Required contract tests

The implementation must provide automated tests proving:

1. every identity is denied every endpoint not listed for it;
2. executor requests containing a credential ID or unknown field are rejected;
3. executor identity mismatch, expiry, cancellation, exhaustion, and terminal
   binding state fail before plaintext is produced;
4. run registration is idempotent and conflicting reassignment cannot mutate the
   original binding;
5. attempt retry and replay rules are atomic under concurrency;
6. secret-bearing bodies never reach generic logs, traces, metrics, or errors;
7. metadata responses contain only redacted field presence;
8. version conflicts do not partially update a credential;
9. cryptographic or audit-spool failure prevents sensitive state changes;
10. request and response size limits are enforced before unbounded allocation;
11. malicious injector fields, environment names, and paths are rejected; and
12. no compatibility or debug configuration enables arbitrary reveal behavior.

## 17. Open decisions

These decisions remain explicit blockers for implementation items that depend on
them:

- workload certificate issuer and rotation mechanism;
- how the scheduler proves the organization associated with a run binding without
  giving the Secrets Service general access to Praetor's database;
- authoritative executor assignment and reassignment protocol;
- exact credential-type schema ownership and signing/versioning;
- authenticated-encryption and key-wrapping primitives selected from maintained
  libraries;
- durable audit spool implementation and tamper-resistance boundary;
- whether one credential payload or individual fields form encryption records;
- retention period for retired versions and attempt metadata; and
- migration protocol for existing encrypted credentials.

## 18. Acceptance criteria

This specification is accepted when reviewers confirm that:

- each endpoint has exactly one clear workload identity and permission model;
- no executor-controlled value can select a credential;
- resolution derives authorization from a server-side, versioned run binding;
- replay, retry, reassignment, expiration, and cancellation behavior are
  unambiguous;
- no ordinary response or diagnostic path reveals stored plaintext;
- the master-key boundary matches the accepted threat model;
- required integration and contract tests are actionable; and
- every unresolved implementation choice is recorded in Section 17 rather than
  hidden in an assumption.
