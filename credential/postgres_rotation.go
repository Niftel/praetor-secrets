package credential

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/Niftel/praetor-secrets/envelope"
	"github.com/jackc/pgx/v5"
)

const rotationColumns = `id, source_key_id, target_key_id, state, total_records,
    processed_records, created_at, updated_at, finalized_at`

func scanRotation(row rowScanner) (Rotation, error) {
	var rotation Rotation
	var finalizedAt *time.Time
	err := row.Scan(
		&rotation.ID, &rotation.SourceKeyID, &rotation.TargetKeyID, &rotation.State,
		&rotation.TotalRecords, &rotation.ProcessedRecords, &rotation.CreatedAt,
		&rotation.UpdatedAt, &finalizedAt,
	)
	if finalizedAt != nil {
		rotation.FinalizedAt = *finalizedAt
	}
	return rotation, err
}

func (b *postgresBackend) StartRotation(ctx context.Context, rotation Rotation) (Rotation, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Rotation{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM credential_versions WHERE master_key_id = $1`, rotation.SourceKeyID).Scan(&rotation.TotalRecords); err != nil {
		return Rotation{}, ErrStorage
	}
	if rotation.TotalRecords == 0 {
		rotation.State = RotationReady
	}
	_, err = tx.Exec(ctx, `INSERT INTO master_key_rotations
        (id, source_key_id, target_key_id, state, total_records, processed_records, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,0,$6,$6)`,
		rotation.ID, rotation.SourceKeyID, rotation.TargetKeyID, rotation.State,
		rotation.TotalRecords, rotation.CreatedAt)
	if isUniqueViolation(err) {
		return Rotation{}, ErrRotationConflict
	}
	if err != nil {
		return Rotation{}, ErrStorage
	}
	event := rotationAudit(audit.OperationMasterKeyRotationStarted, rotation, rotation.CreatedAt)
	if err := b.appendSuccessfulTransition(ctx, tx, event); err != nil {
		return Rotation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Rotation{}, ErrStorage
	}
	return rotation, nil
}

func (b *postgresBackend) GetRotation(ctx context.Context, id string) (Rotation, error) {
	rotation, err := scanRotation(b.pool.QueryRow(ctx, `SELECT `+rotationColumns+` FROM master_key_rotations WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rotation{}, ErrNotFound
	}
	if err != nil {
		return Rotation{}, ErrStorage
	}
	return rotation, nil
}

func (b *postgresBackend) KeyStatus(ctx context.Context, current, previous string) (KeyStatus, error) {
	status := KeyStatus{CurrentKeyID: current, PreviousKeyID: previous, RecordCounts: map[string]int64{}}
	rows, err := b.pool.Query(ctx, `SELECT master_key_id, count(*) FROM credential_versions GROUP BY master_key_id`)
	if err != nil {
		return KeyStatus{}, ErrStorage
	}
	for rows.Next() {
		var keyID string
		var count int64
		if err := rows.Scan(&keyID, &count); err != nil {
			rows.Close()
			return KeyStatus{}, ErrStorage
		}
		status.RecordCounts[keyID] = count
	}
	if rows.Err() != nil {
		rows.Close()
		return KeyStatus{}, ErrStorage
	}
	rows.Close()
	rotation, err := scanRotation(b.pool.QueryRow(ctx, `SELECT `+rotationColumns+`
        FROM master_key_rotations WHERE state <> 'finalized' ORDER BY created_at LIMIT 1`))
	if err == nil {
		status.ActiveRotation = &rotation
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return KeyStatus{}, ErrStorage
	}
	status.DatabaseReferencesCleared = previous != "" && status.RecordCounts[previous] == 0 && status.ActiveRotation == nil
	return status, nil
}

func (b *postgresBackend) RotateBatch(ctx context.Context, id string, limit int, transform func(rotationRecord) (envelope.Record, error)) (Rotation, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Rotation{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	rotation, err := scanRotation(tx.QueryRow(ctx, `SELECT `+rotationColumns+` FROM master_key_rotations WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rotation{}, ErrNotFound
	}
	if err != nil {
		return Rotation{}, ErrStorage
	}
	if rotation.State == RotationFinalized {
		return rotation, nil
	}
	rows, err := tx.Query(ctx, `
        SELECT v.credential_id, v.version, v.envelope,
               c.organization_id, c.name, c.credential_type, c.schema_version,
               c.version, c.state, c.secret_fields, c.created_at, c.updated_at
        FROM credential_versions v
        JOIN credentials c ON c.id = v.credential_id
        WHERE v.master_key_id = $1
        ORDER BY v.credential_id, v.version
        FOR UPDATE OF v SKIP LOCKED
        LIMIT $2`, rotation.SourceKeyID, limit)
	if err != nil {
		return Rotation{}, ErrStorage
	}
	type selected struct {
		item rotationRecord
	}
	var records []selected
	for rows.Next() {
		var item rotationRecord
		var encoded []byte
		if err := rows.Scan(
			&item.metadata.ID, &item.version, &encoded,
			&item.metadata.OrganizationID, &item.metadata.Name, &item.metadata.CredentialType,
			&item.metadata.SchemaVersion, &item.metadata.Version, &item.metadata.State,
			&item.metadata.SecretFields, &item.metadata.CreatedAt, &item.metadata.UpdatedAt,
		); err != nil || json.Unmarshal(encoded, &item.record) != nil {
			rows.Close()
			return Rotation{}, ErrStorage
		}
		records = append(records, selected{item: item})
	}
	if rows.Err() != nil {
		rows.Close()
		return Rotation{}, ErrStorage
	}
	rows.Close()
	now := time.Now().UTC()
	for _, selected := range records {
		rotated, err := transform(selected.item)
		if err != nil {
			return Rotation{}, err
		}
		encoded, err := json.Marshal(rotated)
		if err != nil {
			return Rotation{}, ErrStorage
		}
		result, err := tx.Exec(ctx, `UPDATE credential_versions
            SET envelope=$1, master_key_id=$2
            WHERE credential_id=$3 AND version=$4 AND master_key_id=$5`,
			encoded, rotated.MasterKeyID, selected.item.metadata.ID, selected.item.version, rotation.SourceKeyID)
		if err != nil || result.RowsAffected() != 1 {
			return Rotation{}, ErrStorage
		}
		event := audit.Event{
			SchemaVersion: audit.SchemaVersion, Timestamp: now,
			EventType: audit.EventTypeStateTransition, Operation: audit.OperationCredentialKeyRotated,
			Result: audit.ResultSuccess, ReasonCode: audit.ReasonCompleted,
			OrganizationID: selected.item.metadata.OrganizationID, CredentialID: selected.item.metadata.ID,
			CredentialVersion: selected.item.version, CredentialSchema: selected.item.metadata.SchemaVersion,
			KeyVersion: rotation.TargetKeyID, RotationID: rotation.ID,
		}
		if request, ok := audit.RequestFromContext(ctx); ok {
			event.RequestID, event.WorkloadIdentity, event.HumanActor = request.ID, request.WorkloadIdentity, request.HumanActor
		}
		if err := b.appendAudit(ctx, tx, event); err != nil {
			return Rotation{}, err
		}
	}
	rotation.ProcessedRecords += int64(len(records))
	rotation.State = RotationRunning
	var remaining int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM credential_versions WHERE master_key_id=$1`, rotation.SourceKeyID).Scan(&remaining); err != nil {
		return Rotation{}, ErrStorage
	}
	if remaining == 0 {
		rotation.State = RotationReady
		rotation.ProcessedRecords = rotation.TotalRecords
	}
	rotation.UpdatedAt = now
	if _, err := tx.Exec(ctx, `UPDATE master_key_rotations
        SET state=$1, processed_records=$2, updated_at=$3 WHERE id=$4`,
		rotation.State, rotation.ProcessedRecords, rotation.UpdatedAt, rotation.ID); err != nil {
		return Rotation{}, ErrStorage
	}
	if err := b.appendSuccessfulTransition(ctx, tx, rotationAudit(audit.OperationMasterKeyRotationResumed, rotation, now)); err != nil {
		return Rotation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Rotation{}, ErrStorage
	}
	return rotation, nil
}

func (b *postgresBackend) FinalizeRotation(ctx context.Context, id string, now time.Time) (Rotation, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Rotation{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	rotation, err := scanRotation(tx.QueryRow(ctx, `SELECT `+rotationColumns+` FROM master_key_rotations WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rotation{}, ErrNotFound
	}
	if err != nil {
		return Rotation{}, ErrStorage
	}
	if rotation.State == RotationFinalized {
		return rotation, nil
	}
	var remaining int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM credential_versions WHERE master_key_id=$1`, rotation.SourceKeyID).Scan(&remaining); err != nil {
		return Rotation{}, ErrStorage
	}
	if remaining != 0 || rotation.State != RotationReady {
		return Rotation{}, ErrRotationNotReady
	}
	rotation.State, rotation.FinalizedAt, rotation.UpdatedAt = RotationFinalized, now, now
	if _, err := tx.Exec(ctx, `UPDATE master_key_rotations
        SET state=$1, updated_at=$2, finalized_at=$2 WHERE id=$3`, rotation.State, now, id); err != nil {
		return Rotation{}, ErrStorage
	}
	if err := b.appendSuccessfulTransition(ctx, tx, rotationAudit(audit.OperationMasterKeyRotationFinalized, rotation, now)); err != nil {
		return Rotation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Rotation{}, ErrStorage
	}
	return rotation, nil
}

func (b *postgresBackend) RotateCredential(ctx context.Context, request CredentialRotationRequest, transform func(rotationRecord) (envelope.Record, error), now time.Time) error {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrStorage
	}
	defer tx.Rollback(ctx)
	var item rotationRecord
	var encoded []byte
	err = tx.QueryRow(ctx, `
        SELECT v.envelope, c.id, c.organization_id, c.name, c.credential_type,
               c.schema_version, c.version, c.state, c.secret_fields, c.created_at, c.updated_at
        FROM credential_versions v
        JOIN credentials c ON c.id=v.credential_id
        WHERE v.credential_id=$1 AND v.version=$2 AND c.organization_id=$3
        FOR UPDATE OF v`,
		request.CredentialID, request.Version, request.OrganizationID).Scan(
		&encoded, &item.metadata.ID, &item.metadata.OrganizationID, &item.metadata.Name,
		&item.metadata.CredentialType, &item.metadata.SchemaVersion, &item.metadata.Version,
		&item.metadata.State, &item.metadata.SecretFields, &item.metadata.CreatedAt, &item.metadata.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil || json.Unmarshal(encoded, &item.record) != nil {
		return ErrStorage
	}
	item.version = request.Version
	rotated, err := transform(item)
	if err != nil {
		return err
	}
	encoded, err = json.Marshal(rotated)
	if err != nil {
		return ErrStorage
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_versions SET envelope=$1, master_key_id=$2
        WHERE credential_id=$3 AND version=$4`, encoded, rotated.MasterKeyID, request.CredentialID, request.Version); err != nil {
		return ErrStorage
	}
	event := audit.Event{
		SchemaVersion: audit.SchemaVersion, Timestamp: now,
		EventType: audit.EventTypeStateTransition, Operation: audit.OperationCredentialKeyRotated,
		Result: audit.ResultSuccess, ReasonCode: audit.ReasonCompleted,
		OrganizationID: request.OrganizationID, CredentialID: request.CredentialID,
		CredentialVersion: request.Version, CredentialSchema: item.metadata.SchemaVersion,
		KeyVersion: rotated.MasterKeyID,
	}
	if err := b.appendSuccessfulTransition(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrStorage
	}
	return nil
}

func rotationAudit(operation string, rotation Rotation, timestamp time.Time) audit.Event {
	return audit.Event{
		SchemaVersion: audit.SchemaVersion, Timestamp: timestamp.UTC(),
		EventType: audit.EventTypeStateTransition, Operation: operation,
		Result: audit.ResultSuccess, ReasonCode: audit.ReasonCompleted,
		KeyVersion: rotation.TargetKeyID, RotationID: rotation.ID,
	}
}
