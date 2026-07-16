package credential

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Niftel/praetor-secrets/envelope"
	"github.com/Niftel/praetor-secrets/masterkey"
)

func rotationManager(t *testing.T) *Manager {
	t.Helper()
	directory := t.TempDir()
	currentPath := filepath.Join(directory, "current")
	previousPath := filepath.Join(directory, "previous")
	if err := os.WriteFile(currentPath, bytes.Repeat([]byte{0x81}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previousPath, bytes.Repeat([]byte{0x82}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	keys, err := masterkey.Load(masterkey.Config{CurrentPath: currentPath, PreviousPath: previousPath})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(keys, testSchemas{})
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{
		"98d977e4-3f0a-44cd-81cb-8965d5522996",
		"88d977e4-3f0a-44cd-81cb-8965d5522996",
		"78d977e4-3f0a-44cd-81cb-8965d5522996",
	}
	manager.newID = func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	return manager
}

func TestRotationBatchFailureRollsBackEveryRecord(t *testing.T) {
	manager := rotationManager(t)
	firstRequest := validCreate()
	first, err := manager.Create(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := validCreate()
	secondRequest.IdempotencyKey = "request-2"
	second, err := manager.Create(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	putCurrentRecordOnPreviousKey(t, manager, first)
	putCurrentRecordOnPreviousKey(t, manager, second)
	backend := testMemory(t, manager)
	tampered := backend.credentials[second.ID].records[second.Version]
	tampered.Ciphertext[0] ^= 1
	backend.credentials[second.ID].records[second.Version] = tampered
	beforeFirst := cloneEnvelopeRecord(backend.credentials[first.ID].records[first.Version])
	beforeSecond := cloneEnvelopeRecord(backend.credentials[second.ID].records[second.Version])

	rotation, err := manager.StartMasterKeyRotation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ResumeMasterKeyRotation(context.Background(), rotation.ID, 2); !errors.Is(err, ErrEncryption) {
		t.Fatalf("tampered batch: %v", err)
	}
	if !reflect.DeepEqual(beforeFirst, backend.credentials[first.ID].records[first.Version]) ||
		!reflect.DeepEqual(beforeSecond, backend.credentials[second.ID].records[second.Version]) {
		t.Fatal("failed batch partially changed credential records")
	}
	stored, err := manager.GetMasterKeyRotation(context.Background(), rotation.ID)
	if err != nil || stored.ProcessedRecords != 0 || stored.State != RotationPending {
		t.Fatalf("failed batch progress=%+v err=%v", stored, err)
	}
}

func cloneEnvelopeRecord(in envelope.Record) envelope.Record {
	out := in
	out.PayloadNonce = append([]byte(nil), in.PayloadNonce...)
	out.Ciphertext = append([]byte(nil), in.Ciphertext...)
	out.WrapNonce = append([]byte(nil), in.WrapNonce...)
	out.WrappedDataKey = append([]byte(nil), in.WrappedDataKey...)
	return out
}

func putCurrentRecordOnPreviousKey(t *testing.T, manager *Manager, metadata Metadata) {
	t.Helper()
	backend := testMemory(t, manager)
	record, err := envelope.Encrypt(
		[]byte(`{"password":"very-secret-value","username":"automation"}`),
		envelopeContext(metadata), *manager.keys.Previous, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	backend.credentials[metadata.ID].records[metadata.Version] = record
}

func TestMasterKeyRotationIsResumableAndFinalizationIsGated(t *testing.T) {
	manager := rotationManager(t)
	firstRequest := validCreate()
	first, err := manager.Create(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := validCreate()
	secondRequest.IdempotencyKey = "request-2"
	secondRequest.Name = "second-machine"
	second, err := manager.Create(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	putCurrentRecordOnPreviousKey(t, manager, first)
	putCurrentRecordOnPreviousKey(t, manager, second)

	rotation, err := manager.StartMasterKeyRotation(context.Background())
	if err != nil || rotation.TotalRecords != 2 || rotation.State != RotationPending {
		t.Fatalf("rotation=%+v err=%v", rotation, err)
	}
	if _, err := manager.FinalizeMasterKeyRotation(context.Background(), rotation.ID); !errors.Is(err, ErrRotationNotReady) {
		t.Fatalf("premature finalization: %v", err)
	}

	rotation, err = manager.ResumeMasterKeyRotation(context.Background(), rotation.ID, 1)
	if err != nil || rotation.ProcessedRecords != 1 || rotation.State != RotationRunning {
		t.Fatalf("first batch=%+v err=%v", rotation, err)
	}
	backend := testMemory(t, manager)
	currentCount, previousCount := 0, 0
	for _, stored := range backend.credentials {
		record := stored.records[stored.metadata.Version]
		switch record.MasterKeyID {
		case manager.keys.Current.ID():
			currentCount++
		case manager.keys.Previous.ID():
			previousCount++
		}
		plaintext, err := envelope.Decrypt(record, envelopeContext(stored.metadata), manager.keys.Keyring())
		if err != nil {
			t.Fatalf("mixed-key read failed: %v", err)
		}
		wipe(plaintext)
	}
	if currentCount != 1 || previousCount != 1 {
		t.Fatalf("mixed versions current=%d previous=%d", currentCount, previousCount)
	}

	rotation, err = manager.ResumeMasterKeyRotation(context.Background(), rotation.ID, 1)
	if err != nil || rotation.ProcessedRecords != 2 || rotation.State != RotationReady {
		t.Fatalf("second batch=%+v err=%v", rotation, err)
	}
	rotation, err = manager.FinalizeMasterKeyRotation(context.Background(), rotation.ID)
	if err != nil || rotation.State != RotationFinalized || rotation.FinalizedAt.IsZero() {
		t.Fatalf("finalized=%+v err=%v", rotation, err)
	}
	replayed, err := manager.ResumeMasterKeyRotation(context.Background(), rotation.ID, 1)
	if err != nil || replayed.State != RotationFinalized {
		t.Fatalf("finalized replay=%+v err=%v", replayed, err)
	}
	status, err := manager.KeyStatus(context.Background())
	if err != nil || !status.DatabaseReferencesCleared || status.RecordCounts[manager.keys.Previous.ID()] != 0 {
		t.Fatalf("key status=%+v err=%v", status, err)
	}
}

func TestPerCredentialRotationReplacesDEKWithoutChangingVersion(t *testing.T) {
	manager := rotationManager(t)
	metadata, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	backend := testMemory(t, manager)
	before := backend.credentials[metadata.ID].records[metadata.Version]

	err = manager.RotateCredentialKey(context.Background(), CredentialRotationRequest{
		OrganizationID: metadata.OrganizationID, CredentialID: metadata.ID, Version: metadata.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	after := backend.credentials[metadata.ID].records[metadata.Version]
	if before.RecordID == after.RecordID || bytes.Equal(before.Ciphertext, after.Ciphertext) ||
		metadata.Version != backend.credentials[metadata.ID].metadata.Version {
		t.Fatal("credential rotation did not replace envelope in place")
	}
	plaintext, err := envelope.Decrypt(after, envelopeContext(metadata), manager.keys.Keyring())
	if err != nil || !bytes.Contains(plaintext, []byte("very-secret-value")) {
		t.Fatalf("rotated credential unavailable: %v", err)
	}
	wipe(plaintext)
}

func TestRotationRequiresPreviousKey(t *testing.T) {
	manager := newTestManager(t)
	if _, err := manager.StartMasterKeyRotation(context.Background()); !errors.Is(err, ErrRotationUnavailable) {
		t.Fatalf("rotation without previous key: %v", err)
	}
	status, err := manager.KeyStatus(context.Background())
	if err != nil || status.CurrentKeyID == "" || status.PreviousKeyID != "" || status.DatabaseReferencesCleared {
		t.Fatalf("single-key status=%+v err=%v", status, err)
	}
}

func TestEmptyRotationIsImmediatelyFinalizable(t *testing.T) {
	manager := rotationManager(t)
	rotation, err := manager.StartMasterKeyRotation(context.Background())
	if err != nil || rotation.State != RotationReady || rotation.TotalRecords != 0 {
		t.Fatalf("empty rotation=%+v err=%v", rotation, err)
	}
	rotation, err = manager.FinalizeMasterKeyRotation(context.Background(), rotation.ID)
	if err != nil || rotation.State != RotationFinalized {
		t.Fatalf("empty finalize=%+v err=%v", rotation, err)
	}
	if _, err := manager.GetMasterKeyRotation(context.Background(), ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty rotation ID: %v", err)
	}
	if _, err := manager.ResumeMasterKeyRotation(context.Background(), rotation.ID, 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero batch: %v", err)
	}
	if err := manager.RotateCredentialKey(context.Background(), CredentialRotationRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty credential rotation: %v", err)
	}
	if _, err := manager.GetMasterKeyRotation(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rotation: %v", err)
	}
	if _, err := manager.FinalizeMasterKeyRotation(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing finalize: %v", err)
	}
}
