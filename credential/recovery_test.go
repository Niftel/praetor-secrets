package credential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRecoveryValidationAndBackupRetentionProof(t *testing.T) {
	manager := newTestManager(t)
	metadata, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.ValidateRecovery(context.Background(), 10)
	if err != nil || result.TotalRecords != 1 || result.ValidatedRecords != 1 || len(result.MetadataSHA256) != 64 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if strings.Contains(result.MetadataSHA256, "very-secret") {
		t.Fatal("digest leaked secret")
	}
	key := testMemory(t, manager).credentials[metadata.ID].records[metadata.Version].MasterKeyID
	backup := BackupSet{ID: "backup-1", ArtifactSHA256: strings.Repeat("a", 64), KeyIDs: []string{key}, CreatedAt: time.Now().UTC(), RetainUntil: time.Now().UTC().Add(24 * time.Hour)}
	if _, err := manager.RegisterBackup(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	status, err := manager.KeyStatus(context.Background())
	if err != nil || status.RetainedBackupReferences[key] != 1 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if _, err := manager.RegisterBackup(context.Background(), BackupSet{ID: "backup-1", ArtifactSHA256: strings.Repeat("b", 64), KeyIDs: []string{key}, CreatedAt: backup.CreatedAt, RetainUntil: backup.RetainUntil}); !errors.Is(err, ErrBackupConflict) {
		t.Fatalf("conflict=%v", err)
	}
	if _, err := manager.ExpireBackup(context.Background(), "backup-1"); err != nil {
		t.Fatal(err)
	}
	expired, err := manager.ExpireBackup(context.Background(), "backup-1")
	if err != nil || expired.ExpiredAt.IsZero() {
		t.Fatalf("expire replay=%+v err=%v", expired, err)
	}
	status, _ = manager.KeyStatus(context.Background())
	if status.RetainedBackupReferences[key] != 0 {
		t.Fatalf("expired retained: %+v", status)
	}
	if _, err := manager.ExpireBackup(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing backup: %v", err)
	}
}

func TestRecoveryWrongKeyFailsWithoutData(t *testing.T) {
	manager := newTestManager(t)
	metadata, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	record := testMemory(t, manager).credentials[metadata.ID].records[metadata.Version]
	record.MasterKeyID = "missing-key"
	testMemory(t, manager).credentials[metadata.ID].records[metadata.Version] = record
	result, err := manager.ValidateRecovery(context.Background(), 1)
	if !errors.Is(err, ErrRecoveryValidation) || result.ValidatedRecords != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestBackupValidationRejectsUnsafeMetadata(t *testing.T) {
	manager := newTestManager(t)
	for _, backup := range []BackupSet{{}, {ID: "x", ArtifactSHA256: "bad", KeyIDs: []string{"key"}, CreatedAt: time.Now(), RetainUntil: time.Now()}} {
		if _, err := manager.RegisterBackup(context.Background(), backup); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("backup=%+v err=%v", backup, err)
		}
	}
	if _, err := manager.ValidateRecovery(context.Background(), 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatal(err)
	}
}
