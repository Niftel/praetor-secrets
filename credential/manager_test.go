package credential

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Niftel/praetor-secrets/envelope"
	"github.com/Niftel/praetor-secrets/masterkey"
)

type testSchemas struct {
	err error
}

func (schema testSchemas) Validate(credentialType string, version uint32, inputs map[string]string) ([]string, error) {
	if schema.err != nil {
		return nil, schema.err
	}
	if credentialType != "machine" || version != 1 || inputs["username"] == "" || inputs["password"] == "" {
		return nil, ErrInvalidInput
	}
	return []string{"password"}, nil
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "master-key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x31}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	keys, err := masterkey.Load(masterkey.Config{CurrentPath: path})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(keys, testSchemas{})
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) }
	manager.newID = func() (string, error) { return "98d977e4-3f0a-44cd-81cb-8965d5522996", nil }
	return manager
}

func validCreate() CreateRequest {
	return CreateRequest{
		OrganizationID: "org-5", Name: "production-machine", CredentialType: "machine",
		SchemaVersion: 1, IdempotencyKey: "request-1",
		Inputs: map[string]string{"username": "automation", "password": "very-secret-value"},
	}
}

func TestCreateAndGetExposeOnlyRedactedMetadata(t *testing.T) {
	manager := newTestManager(t)
	metadata, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Version != 1 || metadata.State != StateActive || len(metadata.SecretFields) != 1 || metadata.SecretFields[0] != "password" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("very-secret-value")) || bytes.Contains(encoded, []byte("automation")) {
		t.Fatalf("metadata contains credential input: %s", encoded)
	}
	storedJSON, err := json.Marshal(manager.credentials[metadata.ID])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedJSON, []byte("very-secret-value")) || bytes.Contains(storedJSON, []byte("automation")) {
		t.Fatal("stored record contains plaintext")
	}

	got, err := manager.Get("org-5", metadata.ID)
	if err != nil || got.ID != metadata.ID {
		t.Fatalf("get: metadata=%+v err=%v", got, err)
	}
	got.SecretFields[0] = "mutated"
	again, _ := manager.Get("org-5", metadata.ID)
	if again.SecretFields[0] != "password" {
		t.Fatal("caller mutated stored metadata")
	}
}

func TestOrganizationOwnershipIsImmutableAndNonEnumerable(t *testing.T) {
	manager := newTestManager(t)
	metadata, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Get("org-other", metadata.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization get: %v", err)
	}
	if _, err := manager.ReplaceInputs(ReplaceInputsRequest{
		CredentialID: metadata.ID, OrganizationID: "org-other", ExpectedVersion: 1,
		Inputs: map[string]string{"username": "other", "password": "other-secret"},
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization replace: %v", err)
	}
	if _, err := manager.UpdateMetadata(UpdateMetadataRequest{
		CredentialID: metadata.ID, OrganizationID: "org-other", ExpectedVersion: 1, Name: "renamed",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization metadata update: %v", err)
	}
	stored, _ := manager.Get("org-5", metadata.ID)
	if stored.OrganizationID != "org-5" || stored.Version != 1 {
		t.Fatalf("ownership or version changed: %+v", stored)
	}
}

func TestReplaceInputsCreatesVersionAndConflictIsAtomic(t *testing.T) {
	manager := newTestManager(t)
	created, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	updated, err := manager.ReplaceInputs(ReplaceInputsRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1,
		Inputs: map[string]string{"username": "automation-2", "password": "replacement-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || len(manager.credentials[created.ID].records) != 2 {
		t.Fatalf("replacement not versioned: %+v", updated)
	}
	if _, err := manager.ReplaceInputs(ReplaceInputsRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1,
		Inputs: map[string]string{"username": "stale", "password": "must-not-persist"},
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale replacement: %v", err)
	}
	current, _ := manager.Get("org-5", created.ID)
	if current.Version != 2 || len(manager.credentials[created.ID].records) != 2 {
		t.Fatalf("conflict partially changed state: %+v", current)
	}
}

func TestMetadataUpdateReencryptsAsNewCredentialVersion(t *testing.T) {
	manager := newTestManager(t)
	created, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	oldRecord := manager.credentials[created.ID].records[1]
	updated, err := manager.UpdateMetadata(UpdateMetadataRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1, Name: "renamed-machine",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "renamed-machine" || updated.Version != 2 {
		t.Fatalf("unexpected metadata: %+v", updated)
	}
	newRecord := manager.credentials[created.ID].records[2]
	if newRecord.RecordID == oldRecord.RecordID || newRecord.MasterKeyID != manager.keys.Current.ID() {
		t.Fatal("metadata update did not create an independent encrypted version")
	}
	plaintext, err := envelope.Decrypt(newRecord, envelopeContext(updated), manager.keys.Keyring())
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(plaintext)
	if !bytes.Contains(plaintext, []byte("very-secret-value")) {
		t.Fatal("new encrypted version did not retain inputs")
	}

	same, err := manager.UpdateMetadata(UpdateMetadataRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 2, Name: "renamed-machine",
	})
	if err != nil || same.Version != 2 || len(manager.credentials[created.ID].records) != 2 {
		t.Fatal("no-op metadata update created a version")
	}
}

func TestCreateIdempotency(t *testing.T) {
	manager := newTestManager(t)
	first, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Create(validCreate())
	if err != nil || !reflect.DeepEqual(second, first) {
		t.Fatalf("idempotent replay: first=%+v second=%+v err=%v", first, second, err)
	}
	conflict := validCreate()
	conflict.Name = "different"
	if _, err := manager.Create(conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict: %v", err)
	}
	if len(manager.credentials) != 1 {
		t.Fatal("idempotency conflict created a credential")
	}
}

func TestConcurrentUpdatesAllowExactlyOneWinner(t *testing.T) {
	manager := newTestManager(t)
	created, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, name := range []string{"first", "second"} {
		wait.Add(1)
		go func(name string) {
			defer wait.Done()
			_, err := manager.UpdateMetadata(UpdateMetadataRequest{
				CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1, Name: name,
			})
			results <- err
		}(name)
	}
	wait.Wait()
	close(results)
	winners, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected result: %v", err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("winners=%d conflicts=%d", winners, conflicts)
	}
}

func TestValidationErrorsDoNotLeakInputs(t *testing.T) {
	manager := newTestManager(t)
	manager.schemas = testSchemas{err: errors.New("very-secret-value is invalid")}
	_, err := manager.Create(validCreate())
	if !errors.Is(err, ErrInvalidInput) || bytes.Contains([]byte(err.Error()), []byte("very-secret-value")) {
		t.Fatalf("unsafe validation error: %v", err)
	}
	if len(manager.credentials) != 0 {
		t.Fatal("invalid input changed state")
	}
}

func TestInvalidRequestsFailClosed(t *testing.T) {
	manager := newTestManager(t)
	tests := []CreateRequest{
		{},
		{OrganizationID: "org-5", Name: " padded ", CredentialType: "machine", SchemaVersion: 1, IdempotencyKey: "key", Inputs: validCreate().Inputs},
		{OrganizationID: "org-5", Name: "name", CredentialType: "machine", SchemaVersion: 1, IdempotencyKey: "key", Inputs: nil},
		{OrganizationID: "org-5", Name: "name", CredentialType: "machine", SchemaVersion: 1, IdempotencyKey: "key", Inputs: map[string]string{" bad ": "x"}},
	}
	for index, request := range tests {
		if _, err := manager.Create(request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("case %d: %v", index, err)
		}
	}
}
