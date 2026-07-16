# Independent security review packet

Status: ready for external review; independent review not yet completed.

## Review objective

Determine whether the Praetor Secrets Service preserves the invariants in
[`threat-model.md`](threat-model.md) under database theft, API compromise,
executor impersonation, replay, observability leakage, malicious input,
interrupted rotation, restore failure, and key loss.

## Security boundary

Reviewers should treat PostgreSQL, Praetor API, scheduler, executors, the
network, backup operators, and ordinary cluster administrators as potentially
compromised. Only the Secrets Service process receives the current/previous
master-key files. Plaintext release is limited to an authenticated, run-scoped
executor resolution.

Primary implementation surfaces:

- `envelope/`: AEAD envelope, rewrap, and DEK rotation.
- `masterkey/`: restricted file loading and two-key rotation window.
- `credential/`: lifecycle, PostgreSQL storage, bindings, replay control,
  rotation, backup evidence, and recovery validation.
- `transport/`: TLS 1.3 workload identity and endpoint authorization.
- `audit/` and `auditsink/`: fail-closed authenticated audit chain.
- `app/`, `charts/`, and `scripts/`: assembly, deployment, backup, and drills.

## Adversarial evidence matrix

| Threat-model requirement | Automated evidence |
|---|---|
| Database dump cannot decrypt without key | `TestRecoveryWrongKeyFailsWithoutData`, encrypted-only PostgreSQL lifecycle assertions |
| Modified/truncated/swapped ciphertext fails | `TestTamperingFailsClosed`, `TestMalformedAndUnsupportedRecordsFail`, envelope fuzz gate |
| Cross-context substitution fails | `TestContextSubstitutionFails` |
| API cannot resolve or retrieve historical plaintext | `TestEveryWorkloadRoleIsDeniedRepresentativeUnauthorizedRoute`, administration redaction tests |
| Executor cannot resolve another/invalid run | resolution executor mismatch, cancellation, expiry, exhaustion, and missing-binding tests |
| Captured requests cannot escape scope/lifetime | attempt replay/conflict and binding lifetime tests, PostgreSQL concurrency tests |
| Canary values absent from outputs | sentinel HTTP/audit/log/client tests and stored-record redaction tests |
| Interrupted rotation resumes safely | PostgreSQL manager-restart rotation test and batch rollback test |
| Wrong-key restore fails without mutation | recovery wrong-key test and transactional PostgreSQL validation |
| Malicious injector output is rejected | injector environment/path/size validation tests |

The required runner is `scripts/run-adversarial-gates.sh`; CI executes it in
`.github/workflows/adversarial.yml`.

## Review questions

1. Is AES-256-GCM used with unique random nonces, correct key separation, and
   complete associated-data binding?
2. Can any workload select a credential outside a server-side run binding?
3. Can replay, concurrency, cancellation, expiry, or retry behavior release
   plaintext outside the intended executor and time window?
4. Can a failed audit append, rotation batch, or recovery validation partially
   commit security state?
5. Can errors, logs, metrics, audit events, manifests, or scripts disclose
   plaintext, key bytes, ciphertext, private paths, or low-entropy hashes?
6. Can an old key be removed while live records or retained backups reference it?
7. Do Helm and runtime assembly mount master keys anywhere outside the Secrets
   Service workload?
8. Are backup and key custody sufficiently separated operationally?

## Known residual risks and explicit non-claims

- The service does not protect plaintext after a correctly authorized executor
  receives it; executor hardening remains required.
- Go cannot guarantee immediate physical memory erasure or secure deletion on
  copy-on-write and journaled filesystems.
- A fully compromised Secrets Service process can access configured keys and
  authorized plaintext during operation.
- Availability depends on PostgreSQL, key-file availability, workload PKI, and
  bounded audit capacity.
- The repository prepares evidence but does not constitute an independent
  assessment. Production readiness remains blocked until an external reviewer
  records findings and owners resolve or formally accept them.

## Reviewer deliverables

- findings with severity, exploit preconditions, affected invariants, and
  reproducible evidence;
- confirmation or rejection of each review question;
- review of all cryptographic and authorization changes since the reviewed
  commit;
- disposition for every finding: fixed, accepted with owner/expiry, or release
  blocking; and
- reviewed commit SHA and reviewer identity.
