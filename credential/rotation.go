package credential

import (
	"context"
	"errors"
	"time"

	"github.com/Niftel/praetor-secrets/envelope"
)

var (
	ErrRotationUnavailable = errors.New("key rotation unavailable")
	ErrRotationConflict    = errors.New("key rotation conflict")
	ErrRotationNotReady    = errors.New("key rotation not ready")
)

type RotationState string

const (
	RotationPending   RotationState = "pending"
	RotationRunning   RotationState = "running"
	RotationReady     RotationState = "ready"
	RotationFinalized RotationState = "finalized"
)

type Rotation struct {
	ID               string        `json:"id"`
	SourceKeyID      string        `json:"source_key_id"`
	TargetKeyID      string        `json:"target_key_id"`
	State            RotationState `json:"state"`
	TotalRecords     int64         `json:"total_records"`
	ProcessedRecords int64         `json:"processed_records"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
	FinalizedAt      time.Time     `json:"finalized_at,omitempty"`
}

type CredentialRotationRequest struct {
	OrganizationID string
	CredentialID   string
	Version        uint64
}

type KeyStatus struct {
	CurrentKeyID              string           `json:"current_key_id"`
	PreviousKeyID             string           `json:"previous_key_id,omitempty"`
	RecordCounts              map[string]int64 `json:"record_counts"`
	ActiveRotation            *Rotation        `json:"active_rotation,omitempty"`
	DatabaseReferencesCleared bool             `json:"database_references_cleared"`
	RetainedBackupReferences  map[string]int64 `json:"retained_backup_references"`
	BackupReferencesCleared   bool             `json:"backup_references_cleared"`
}

type rotationRecord struct {
	metadata Metadata
	version  uint64
	record   envelope.Record
}

func (m *Manager) StartMasterKeyRotation(ctx context.Context) (Rotation, error) {
	if m.keys.Previous == nil || m.keys.Previous.ID() == "" || m.keys.Current.ID() == "" {
		return Rotation{}, ErrRotationUnavailable
	}
	id, err := m.newID()
	if err != nil {
		return Rotation{}, ErrRotationUnavailable
	}
	now := m.now()
	return m.backend.StartRotation(ctx, Rotation{
		ID: id, SourceKeyID: m.keys.Previous.ID(), TargetKeyID: m.keys.Current.ID(),
		State: RotationPending, CreatedAt: now, UpdatedAt: now,
	})
}

func (m *Manager) KeyStatus(ctx context.Context) (KeyStatus, error) {
	previous := ""
	if m.keys.Previous != nil {
		previous = m.keys.Previous.ID()
	}
	return m.backend.KeyStatus(ctx, m.keys.Current.ID(), previous)
}

func (m *Manager) GetMasterKeyRotation(ctx context.Context, rotationID string) (Rotation, error) {
	if rotationID == "" {
		return Rotation{}, ErrInvalidInput
	}
	return m.backend.GetRotation(ctx, rotationID)
}

func (m *Manager) ResumeMasterKeyRotation(ctx context.Context, rotationID string, batchSize int) (Rotation, error) {
	if rotationID == "" || batchSize < 1 || batchSize > 1000 || m.keys.Previous == nil {
		return Rotation{}, ErrInvalidInput
	}
	return m.backend.RotateBatch(ctx, rotationID, batchSize, func(item rotationRecord) (envelope.Record, error) {
		expected := envelope.Context{
			CredentialID: item.metadata.ID, OrganizationID: item.metadata.OrganizationID,
			SchemaVersion: item.metadata.SchemaVersion, CredentialVersion: item.version,
		}
		record, err := envelope.Rewrap(item.record, expected, m.keys.Keyring(), m.keys.Current, nil)
		if err != nil {
			return envelope.Record{}, ErrEncryption
		}
		return record, nil
	})
}

func (m *Manager) FinalizeMasterKeyRotation(ctx context.Context, rotationID string) (Rotation, error) {
	if rotationID == "" {
		return Rotation{}, ErrInvalidInput
	}
	return m.backend.FinalizeRotation(ctx, rotationID, m.now())
}

func (m *Manager) RotateCredentialKey(ctx context.Context, request CredentialRotationRequest) error {
	if request.OrganizationID == "" || request.CredentialID == "" || request.Version == 0 {
		return ErrInvalidInput
	}
	return m.backend.RotateCredential(ctx, request, func(item rotationRecord) (envelope.Record, error) {
		expected := envelope.Context{
			CredentialID: item.metadata.ID, OrganizationID: item.metadata.OrganizationID,
			SchemaVersion: item.metadata.SchemaVersion, CredentialVersion: item.version,
		}
		record, err := envelope.RotateDataKey(item.record, expected, m.keys.Keyring(), m.keys.Current, nil)
		if err != nil {
			return envelope.Record{}, ErrEncryption
		}
		return record, nil
	}, m.now())
}
