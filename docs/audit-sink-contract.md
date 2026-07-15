# Remote audit sink contract

## Purpose

The remote audit sink is a separate trust and failure domain from the Praetor
Secrets Service. It receives the service's durable audit stream over TLS 1.3
mutual authentication and retains an immutable, gap-free copy for operators and
external archival systems.

The sink is not a second secrets database. It never receives credential values,
master keys, the audit HMAC key, or arbitrary request bodies.

## Trust boundary

The HTTPS listener accepts exactly one client workload identity:

`spiffe://<trust-domain>/workload/praetor-secrets`

Identity comes only from a verified client-certificate URI SAN. Certificate
subjects, DNS SANs, source addresses, proxy headers, bearer tokens, and
application identity headers are ignored. The sink certificate must be issued
for its Service DNS name. Both directions require TLS 1.3.

The health listener is separate, contains no ingestion route, and is never
exposed through the audit Service.

## Delivery request

The existing sender issues:

`POST /internal/v1/audit/events`

Headers:

- `Content-Type: application/json`
- `Cache-Control: no-store`
- `Idempotency-Key: audit-<lowercase hex record MAC>`

Body:

```json
{
  "sequence": 42,
  "event": {
    "schema_version": 1,
    "timestamp": "2026-07-15T18:00:00Z",
    "event_type": "state_transition",
    "operation": "run_binding_canceled",
    "result": "success",
    "reason_code": "run_successful"
  },
  "mac": "base64-encoded 32-byte HMAC-SHA-256"
}
```

Requests larger than 64 KiB, unknown JSON fields, trailing JSON, invalid event
fields, non-32-byte MACs, or malformed idempotency keys are rejected before a
database transaction begins. Responses contain no submitted event data.

## Durable append rules

The sink stores records in a dedicated PostgreSQL database, separate from the
Secrets Service operational database.

Within one serializable transaction it locks a singleton stream head and then:

1. accepts `sequence = last_sequence + 1`;
2. inserts the canonical event JSON, MAC, idempotency key, receipt time, and the
   verified certificate identity;
3. advances the durable stream head; and
4. commits before returning `201 Created`.

Redelivery of the same sequence is successful only when the canonical event,
MAC, idempotency key, and workload identity exactly match the stored record; it
returns `200 OK`. Any mismatch is a `409 Conflict`. A future sequence with a gap
is also a conflict and never advances the head.

Database roles used by the process receive only `SELECT` and `INSERT` plus the
narrow stream-head update. Database triggers reject record `UPDATE`, `DELETE`,
and `TRUNCATE`. Retention/export is performed by a distinct operator role and is
outside the ingestion API.

## Integrity claims

The Secrets Service verifies its complete HMAC chain before delivery and sends
the stored record MAC. The current wire record does **not** include
`previous_mac`, and the sink deliberately does not possess the audit HMAC key.
Consequently:

- the sink can enforce exact idempotency, sequence continuity, immutability, and
  authenticated origin;
- the sink can prove that a retained MAC is the one delivered by the authenticated
  Secrets Service;
- the sink cannot independently recompute or cryptographically verify the source
  HMAC chain.

Independent verification is a future wire-contract version requiring either
`previous_mac` plus a verification mechanism, or signed audit checkpoints. It
must not be implied by the version 1 implementation.

## Availability and backpressure

Only a committed `2xx` acknowledges delivery. Timeouts, TLS errors, `409`, or
`5xx` leave the source spool record pending. The source sends records in order
and stops a batch at the first failure, so the sink never needs to buffer gaps.

Sink downtime does not immediately stop credential operations. The bounded
source spool absorbs the outage; when its configured maximum is reached,
sensitive mutations fail closed rather than dropping audit records.

## Operational requirements

- Database URL and TLS private key are file-only restricted inputs.
- The process runs non-root with no Kubernetes API token, no writable root
  filesystem, no privilege escalation, and no Linux capabilities.
- Readiness requires the append database and mTLS listener to be available.
- Metrics expose accepted records, exact replays, conflicts, failures, current
  sequence, and append latency without event labels or actor identifiers.
- Logs contain request IDs, sequence numbers, stable result codes, and latency;
  they never contain event JSON, MAC bytes, human actors, resource IDs, or key
  material.

## Implementation sequence

1. Immutable PostgreSQL append store and migration.
2. TLS 1.3 mTLS HTTP boundary with certificate-derived identity.
3. Non-root container and standalone Helm deployment.
4. End-to-end delivery test covering outage, replay, conflict, and recovery.
5. Optional signed-checkpoint protocol for independent downstream verification.
