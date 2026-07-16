package credential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/Niftel/praetor-secrets/envelope"
	"github.com/jackc/pgx/v5"
)

func (b *postgresBackend) ValidateRecovery(ctx context.Context, limit int, validate func(rotationRecord) error) (RecoveryValidation, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		return RecoveryValidation{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	started := audit.Event{SchemaVersion: audit.SchemaVersion, Timestamp: now, EventType: audit.EventTypeStateTransition, Operation: audit.OperationRecoveryValidationStarted, Result: audit.ResultSuccess, ReasonCode: audit.ReasonCompleted}
	if err := b.appendSuccessfulTransition(ctx, tx, started); err != nil {
		return RecoveryValidation{}, err
	}
	result := RecoveryValidation{KeyCounts: map[string]int64{}, CompletedAt: now}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM credential_versions`).Scan(&result.TotalRecords); err != nil {
		return RecoveryValidation{}, ErrStorage
	}
	rows, err := tx.Query(ctx, `SELECT master_key_id, count(*) FROM credential_versions GROUP BY master_key_id`)
	if err != nil {
		return RecoveryValidation{}, ErrStorage
	}
	for rows.Next() {
		var id string
		var count int64
		if err := rows.Scan(&id, &count); err != nil {
			rows.Close()
			return RecoveryValidation{}, ErrStorage
		}
		result.KeyCounts[id] = count
	}
	rows.Close()
	rows, err = tx.Query(ctx, `
        SELECT v.credential_id, v.version, v.envelope, c.organization_id,
               c.name, c.credential_type, c.schema_version, c.version, c.state,
               c.secret_fields, c.created_at, c.updated_at
        FROM credential_versions v JOIN credentials c ON c.id=v.credential_id
        ORDER BY v.credential_id, v.version LIMIT $1`, limit)
	if err != nil {
		return RecoveryValidation{}, ErrStorage
	}
	hash := sha256.New()
	for rows.Next() {
		var item rotationRecord
		var encoded []byte
		if err := rows.Scan(&item.metadata.ID, &item.version, &encoded, &item.metadata.OrganizationID,
			&item.metadata.Name, &item.metadata.CredentialType, &item.metadata.SchemaVersion,
			&item.metadata.Version, &item.metadata.State, &item.metadata.SecretFields,
			&item.metadata.CreatedAt, &item.metadata.UpdatedAt); err != nil || json.Unmarshal(encoded, &item.record) != nil {
			rows.Close()
			return RecoveryValidation{}, ErrStorage
		}
		if err := validate(item); err != nil {
			rows.Close()
			return RecoveryValidation{}, err
		}
		fmt.Fprintf(hash, "%s\x00%s\x00%d\x00%d\n", item.metadata.OrganizationID, item.metadata.ID, item.version, item.metadata.SchemaVersion)
		result.ValidatedRecords++
	}
	if rows.Err() != nil {
		rows.Close()
		return RecoveryValidation{}, ErrStorage
	}
	rows.Close()
	result.MetadataSHA256 = hex.EncodeToString(hash.Sum(nil))
	finished := audit.Event{SchemaVersion: audit.SchemaVersion, Timestamp: now, EventType: audit.EventTypeStateTransition, Operation: audit.OperationRecoveryValidationFinished, Result: audit.ResultSuccess, ReasonCode: audit.ReasonCompleted}
	if err := b.appendSuccessfulTransition(ctx, tx, finished); err != nil {
		return RecoveryValidation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RecoveryValidation{}, ErrStorage
	}
	return result, nil
}

func (b *postgresBackend) RegisterBackup(ctx context.Context, backup BackupSet, now time.Time) (BackupSet, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return BackupSet{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	var existing BackupSet
	var expired *time.Time
	err = tx.QueryRow(ctx, `SELECT id,artifact_sha256,key_ids,created_at,retain_until,expired_at FROM backup_sets WHERE id=$1`, backup.ID).
		Scan(&existing.ID, &existing.ArtifactSHA256, &existing.KeyIDs, &existing.CreatedAt, &existing.RetainUntil, &expired)
	if err == nil {
		if existing.ArtifactSHA256 != backup.ArtifactSHA256 {
			return BackupSet{}, ErrBackupConflict
		}
		if expired != nil {
			existing.ExpiredAt = *expired
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return BackupSet{}, ErrStorage
	}
	if _, err := tx.Exec(ctx, `INSERT INTO backup_sets(id,artifact_sha256,key_ids,created_at,retain_until) VALUES($1,$2,$3,$4,$5)`, backup.ID, backup.ArtifactSHA256, backup.KeyIDs, backup.CreatedAt, backup.RetainUntil); err != nil {
		return BackupSet{}, ErrStorage
	}
	event := audit.Event{SchemaVersion: audit.SchemaVersion, Timestamp: now, EventType: audit.EventTypeStateTransition, Operation: audit.OperationBackupRegistered, Result: audit.ResultSuccess, ReasonCode: audit.ReasonCompleted, KeyVersion: backup.KeyIDs[0]}
	if err := b.appendSuccessfulTransition(ctx, tx, event); err != nil {
		return BackupSet{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return BackupSet{}, ErrStorage
	}
	return backup, nil
}

func (b *postgresBackend) ExpireBackup(ctx context.Context, id string, now time.Time) (BackupSet, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return BackupSet{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	var backup BackupSet
	var expired *time.Time
	err = tx.QueryRow(ctx, `UPDATE backup_sets SET expired_at=COALESCE(expired_at,$2) WHERE id=$1 RETURNING id,artifact_sha256,key_ids,created_at,retain_until,expired_at`, id, now).
		Scan(&backup.ID, &backup.ArtifactSHA256, &backup.KeyIDs, &backup.CreatedAt, &backup.RetainUntil, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupSet{}, ErrNotFound
	}
	if err != nil {
		return BackupSet{}, ErrStorage
	}
	if expired != nil {
		backup.ExpiredAt = *expired
	}
	event := audit.Event{SchemaVersion: audit.SchemaVersion, Timestamp: now, EventType: audit.EventTypeStateTransition, Operation: audit.OperationBackupExpired, Result: audit.ResultSuccess, ReasonCode: audit.ReasonCompleted}
	if err := b.appendSuccessfulTransition(ctx, tx, event); err != nil {
		return BackupSet{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return BackupSet{}, ErrStorage
	}
	return backup, nil
}

var _ = envelope.Record{}
