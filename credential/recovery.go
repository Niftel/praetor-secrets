package credential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Niftel/praetor-secrets/envelope"
)

var (
	ErrRecoveryValidation = errors.New("recovery validation failed")
	ErrBackupConflict     = errors.New("backup metadata conflict")
)

type RecoveryValidation struct {
	ValidatedRecords int64            `json:"validated_records"`
	TotalRecords     int64            `json:"total_records"`
	KeyCounts        map[string]int64 `json:"key_counts"`
	MetadataSHA256   string           `json:"metadata_sha256"`
	CompletedAt      time.Time        `json:"completed_at"`
}

type BackupSet struct {
	ID             string    `json:"id"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	KeyIDs         []string  `json:"key_ids"`
	CreatedAt      time.Time `json:"created_at"`
	RetainUntil    time.Time `json:"retain_until"`
	ExpiredAt      time.Time `json:"expired_at,omitempty"`
}

func (m *Manager) ValidateRecovery(ctx context.Context, sampleSize int) (RecoveryValidation, error) {
	if sampleSize < 1 || sampleSize > 1000 {
		return RecoveryValidation{}, ErrInvalidInput
	}
	return m.backend.ValidateRecovery(ctx, sampleSize, func(item rotationRecord) error {
		expected := envelope.Context{CredentialID: item.metadata.ID, OrganizationID: item.metadata.OrganizationID, SchemaVersion: item.metadata.SchemaVersion, CredentialVersion: item.version}
		plaintext, err := envelope.Decrypt(item.record, expected, m.keys.Keyring())
		wipe(plaintext)
		if err != nil {
			return ErrRecoveryValidation
		}
		return nil
	})
}

func (m *Manager) RegisterBackup(ctx context.Context, backup BackupSet) (BackupSet, error) {
	if !validBackup(backup) {
		return BackupSet{}, ErrInvalidInput
	}
	sort.Strings(backup.KeyIDs)
	return m.backend.RegisterBackup(ctx, backup, m.now())
}

func (m *Manager) ExpireBackup(ctx context.Context, id string) (BackupSet, error) {
	if id == "" {
		return BackupSet{}, ErrInvalidInput
	}
	return m.backend.ExpireBackup(ctx, id, m.now())
}

func validBackup(backup BackupSet) bool {
	if backup.ID == "" || len(backup.ID) > 255 || strings.ContainsAny(backup.ID, "\x00\r\n") ||
		len(backup.ArtifactSHA256) != sha256.Size*2 || backup.CreatedAt.IsZero() ||
		backup.RetainUntil.Before(backup.CreatedAt) || len(backup.KeyIDs) == 0 || len(backup.KeyIDs) > 2 {
		return false
	}
	if _, err := hex.DecodeString(backup.ArtifactSHA256); err != nil {
		return false
	}
	seen := map[string]bool{}
	for _, id := range backup.KeyIDs {
		if id == "" || len(id) > 255 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
