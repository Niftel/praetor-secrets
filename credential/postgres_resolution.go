package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const bindingColumns = `run_id, dispatch_id, organization_id, credential_id, credential_version,
    executor_identity, state, not_before, expires_at, max_resolutions, resolution_count,
    created_at, updated_at, COALESCE(cancel_reason, '')`

type rowScanner interface {
	Scan(...any) error
}

func scanBinding(row rowScanner, extra ...any) (Binding, error) {
	var binding Binding
	destinations := []any{
		&binding.RunID, &binding.DispatchID, &binding.OrganizationID, &binding.CredentialID,
		&binding.CredentialVersion, &binding.ExecutorIdentity, &binding.State,
		&binding.NotBefore, &binding.ExpiresAt, &binding.MaxResolutions, &binding.ResolutionCount,
		&binding.CreatedAt, &binding.UpdatedAt, &binding.CancelReason,
	}
	destinations = append(destinations, extra...)
	err := row.Scan(destinations...)
	return binding, err
}

func (b *postgresBackend) RegisterBinding(ctx context.Context, registration bindingRegistration) (Binding, error) {
	request := registration.request
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Binding{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 2) # hashtextextended($2, 3))", request.OrganizationID, request.IdempotencyKey); err != nil {
		return Binding{}, ErrStorage
	}
	var existingDigest []byte
	existing, err := scanBinding(tx.QueryRow(ctx, `SELECT `+bindingColumns+`, request_digest
        FROM run_bindings WHERE organization_id = $1 AND idempotency_key = $2`, request.OrganizationID, request.IdempotencyKey), &existingDigest)
	if err == nil {
		if !bytes.Equal(existingDigest, registration.digest[:]) {
			return Binding{}, ErrBindingConflict
		}
		if err := b.appendCompletion(ctx, tx, bindingAudit("run_binding_registered", existing, "praetor-scheduler", "completed", registration.now)); err != nil {
			return Binding{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Binding{}, ErrStorage
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrStorage
	}

	var credentialVersion uint64
	err = tx.QueryRow(ctx, `
        SELECT c.version
        FROM credentials c
        JOIN credential_versions v ON v.credential_id = c.id AND v.version = c.version
        WHERE c.id = $1 AND c.organization_id = $2 AND c.state = 'active'
        FOR SHARE OF c`, request.CredentialID, request.OrganizationID).Scan(&credentialVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrNotFound
	}
	if err != nil {
		return Binding{}, ErrStorage
	}
	state := BindingPending
	if !registration.now.Before(request.NotBefore) {
		state = BindingActive
	}
	binding := Binding{
		RunID: request.RunID, DispatchID: request.DispatchID, OrganizationID: request.OrganizationID,
		CredentialID: request.CredentialID, CredentialVersion: credentialVersion,
		ExecutorIdentity: request.ExecutorIdentity, State: state, NotBefore: request.NotBefore,
		ExpiresAt: request.ExpiresAt, MaxResolutions: request.MaxResolutions,
		CreatedAt: registration.now, UpdatedAt: registration.now,
	}
	_, err = tx.Exec(ctx, `INSERT INTO run_bindings
        (run_id, dispatch_id, organization_id, credential_id, credential_version,
         executor_identity, state, not_before, expires_at, max_resolutions,
         resolution_count, idempotency_key, request_digest, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,$12,$13,$13)`,
		binding.RunID, binding.DispatchID, binding.OrganizationID, binding.CredentialID,
		binding.CredentialVersion, binding.ExecutorIdentity, binding.State, binding.NotBefore,
		binding.ExpiresAt, binding.MaxResolutions, request.IdempotencyKey, registration.digest[:], registration.now)
	if isUniqueViolation(err) {
		return Binding{}, ErrBindingConflict
	}
	if err != nil {
		return Binding{}, ErrStorage
	}
	if err := b.appendSuccessfulTransition(ctx, tx, bindingAudit("run_binding_registered", binding, "praetor-scheduler", "completed", registration.now)); err != nil {
		return Binding{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Binding{}, ErrStorage
	}
	return binding, nil
}

func (b *postgresBackend) GetBinding(ctx context.Context, runID string) (Binding, error) {
	binding, err := scanBinding(b.pool.QueryRow(ctx, `SELECT `+bindingColumns+` FROM run_bindings WHERE run_id = $1`, runID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrBindingNotFound
	}
	if err != nil {
		return Binding{}, ErrStorage
	}
	return binding, nil
}

func (b *postgresBackend) CancelBinding(ctx context.Context, runID, dispatchID, reason string, now time.Time) (Binding, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Binding{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	binding, err := scanBinding(tx.QueryRow(ctx, `SELECT `+bindingColumns+` FROM run_bindings WHERE run_id = $1 FOR UPDATE`, runID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrBindingNotFound
	}
	if err != nil {
		return Binding{}, ErrStorage
	}
	if binding.DispatchID != dispatchID {
		return Binding{}, ErrBindingConflict
	}
	if binding.State != BindingCanceled && binding.State != BindingExpired && binding.State != BindingExhausted {
		binding.State = BindingCanceled
		binding.CancelReason = reason
		binding.UpdatedAt = now
		if _, err := tx.Exec(ctx, "UPDATE run_bindings SET state = $1, cancel_reason = $2, updated_at = $3 WHERE run_id = $4", binding.State, reason, now, runID); err != nil {
			return Binding{}, ErrStorage
		}
		if err := b.appendSuccessfulTransition(ctx, tx, bindingAudit("run_binding_canceled", binding, "praetor-scheduler", reason, now)); err != nil {
			return Binding{}, err
		}
	} else if err := b.appendCompletion(ctx, tx, bindingAudit("run_binding_canceled", binding, "praetor-scheduler", "completed", now)); err != nil {
		return Binding{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Binding{}, ErrStorage
	}
	return binding, nil
}

func (b *postgresBackend) ClaimResolution(ctx context.Context, claim resolutionClaim, validate func(Binding, boundRecord) error) (Binding, time.Time, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Binding{}, time.Time{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	binding, err := scanBinding(tx.QueryRow(ctx, `SELECT `+bindingColumns+` FROM run_bindings WHERE run_id = $1 FOR UPDATE`, claim.runID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, time.Time{}, ErrBindingNotFound
	}
	if err != nil {
		return Binding{}, time.Time{}, ErrStorage
	}
	if binding.ExecutorIdentity != claim.executorIdentity {
		return Binding{}, time.Time{}, ErrUnauthorized
	}
	if binding.State == BindingCanceled {
		return Binding{}, time.Time{}, ErrBindingNotActive
	}
	if binding.State == BindingExpired {
		return Binding{}, time.Time{}, ErrBindingExpired
	}
	if !claim.now.Before(binding.ExpiresAt) {
		if binding.State != BindingExpired && binding.State != BindingExhausted {
			if _, err := tx.Exec(ctx, "UPDATE run_bindings SET state = 'expired', updated_at = $1 WHERE run_id = $2", claim.now, claim.runID); err != nil {
				return Binding{}, time.Time{}, ErrStorage
			}
			binding.State = BindingExpired
			if err := b.appendAudit(ctx, tx, bindingAudit("run_binding_expired", binding, claim.executorIdentity, "binding_expired", claim.now)); err != nil {
				return Binding{}, time.Time{}, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return Binding{}, time.Time{}, ErrStorage
		}
		return Binding{}, time.Time{}, ErrBindingExpired
	}
	if claim.now.Before(binding.NotBefore) {
		return Binding{}, time.Time{}, ErrBindingNotActive
	}

	version, err := postgresBoundVersion(ctx, tx, binding)
	if err != nil {
		return Binding{}, time.Time{}, err
	}
	if err := validate(binding, version); err != nil {
		return Binding{}, time.Time{}, err
	}

	var attemptRunID, attemptExecutor string
	var attemptDigest []byte
	var attemptExpiry time.Time
	err = tx.QueryRow(ctx, `SELECT run_id, executor_identity, request_digest, expires_at
        FROM resolution_attempts WHERE attempt_id = $1`, claim.attemptID).Scan(
		&attemptRunID, &attemptExecutor, &attemptDigest, &attemptExpiry)
	if err == nil {
		if attemptRunID != claim.runID || attemptExecutor != claim.executorIdentity ||
			!bytes.Equal(attemptDigest, claim.digest[:]) || !claim.now.Before(attemptExpiry) {
			return Binding{}, time.Time{}, ErrAttemptConflict
		}
		if err := b.appendCompletion(ctx, tx, bindingAudit("credential_resolved", binding, claim.executorIdentity, "completed", claim.now)); err != nil {
			return Binding{}, time.Time{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Binding{}, time.Time{}, ErrStorage
		}
		return binding, attemptExpiry, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, time.Time{}, ErrStorage
	}
	if binding.ResolutionCount >= binding.MaxResolutions || binding.State == BindingExhausted {
		if binding.State != BindingExhausted {
			if _, err := tx.Exec(ctx, "UPDATE run_bindings SET state = 'exhausted', updated_at = $1 WHERE run_id = $2", claim.now, claim.runID); err != nil {
				return Binding{}, time.Time{}, ErrStorage
			}
			binding.State = BindingExhausted
			if err := b.appendAudit(ctx, tx, bindingAudit("run_binding_exhausted", binding, claim.executorIdentity, "resolution_limit", claim.now)); err != nil {
				return Binding{}, time.Time{}, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return Binding{}, time.Time{}, ErrStorage
		}
		return Binding{}, time.Time{}, ErrBindingExhausted
	}

	attemptExpiry = claim.now.Add(claim.retryWindow)
	if attemptExpiry.After(binding.ExpiresAt) {
		attemptExpiry = binding.ExpiresAt
	}
	if _, err := tx.Exec(ctx, `INSERT INTO resolution_attempts
        (attempt_id, run_id, executor_identity, request_digest, created_at, expires_at)
        VALUES ($1,$2,$3,$4,$5,$6)`, claim.attemptID, claim.runID, claim.executorIdentity,
		claim.digest[:], claim.now, attemptExpiry); err != nil {
		if isUniqueViolation(err) {
			return Binding{}, time.Time{}, ErrAttemptConflict
		}
		return Binding{}, time.Time{}, ErrStorage
	}
	binding.ResolutionCount++
	binding.State = BindingActive
	if binding.ResolutionCount == binding.MaxResolutions {
		binding.State = BindingExhausted
	}
	binding.UpdatedAt = claim.now
	if _, err := tx.Exec(ctx, `UPDATE run_bindings
        SET resolution_count = $1, state = $2, updated_at = $3 WHERE run_id = $4`,
		binding.ResolutionCount, binding.State, binding.UpdatedAt, binding.RunID); err != nil {
		return Binding{}, time.Time{}, ErrStorage
	}
	if err := b.appendSuccessfulTransition(ctx, tx, bindingAudit("credential_resolved", binding, claim.executorIdentity, "completed", claim.now)); err != nil {
		return Binding{}, time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Binding{}, time.Time{}, ErrStorage
	}
	return binding, attemptExpiry, nil
}

func bindingAudit(operation string, binding Binding, workload, reason string, timestamp time.Time) audit.Event {
	return audit.Event{SchemaVersion: audit.SchemaVersion, Timestamp: timestamp.UTC(), EventType: "state_transition", Operation: operation, Result: "success", ReasonCode: reason, WorkloadIdentity: workload, OrganizationID: binding.OrganizationID, CredentialID: binding.CredentialID, RunID: binding.RunID, ExecutorIdentity: binding.ExecutorIdentity, CredentialVersion: binding.CredentialVersion}
}

func postgresBoundVersion(ctx context.Context, tx pgx.Tx, binding Binding) (boundRecord, error) {
	var recordJSON []byte
	var result boundRecord
	err := tx.QueryRow(ctx, `SELECT v.envelope, c.credential_type, c.schema_version
        FROM credential_versions v
        JOIN credentials c ON c.id = v.credential_id
        WHERE v.credential_id = $1 AND v.version = $2 AND c.organization_id = $3`,
		binding.CredentialID, binding.CredentialVersion, binding.OrganizationID).Scan(
		&recordJSON, &result.credentialType, &result.schemaVersion)
	if err != nil {
		return boundRecord{}, ErrResolution
	}
	if err := json.Unmarshal(recordJSON, &result.record); err != nil {
		return boundRecord{}, ErrResolution
	}
	return result, nil
}

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}
