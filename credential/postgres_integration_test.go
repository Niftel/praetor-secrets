package credential

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/Niftel/praetor-secrets/envelope"
	"github.com/Niftel/praetor-secrets/masterkey"
	"github.com/jackc/pgx/v5/pgxpool"
)

func postgresTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("PRAETOR_SECRETS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PRAETOR_SECRETS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "praetor_test_" + fmt.Sprintf("%x", suffix)
	if _, err := admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.ApplyMigration(ctx, pool); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func postgresTestManager(t *testing.T, pool *pgxpool.Pool) *Manager {
	t.Helper()
	path := writePostgresTestKey(t)
	keys, err := masterkey.Load(masterkey.Config{CurrentPath: path})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPostgresManager(keys, testSchemas{}, pool)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := audit.New(bytes.Repeat([]byte{0x24}, 32), 10000)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RequireAuditSpool(spool); err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return time.Date(2026, 7, 15, 14, 0, 0, 0, time.UTC) }
	return manager
}

func writePostgresTestKey(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/master-key"
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func postgresRotationManager(t *testing.T, pool *pgxpool.Pool, currentPath, previousPath string) *Manager {
	t.Helper()
	keys, err := masterkey.Load(masterkey.Config{CurrentPath: currentPath, PreviousPath: previousPath})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPostgresManager(keys, testSchemas{}, pool)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := audit.New(bytes.Repeat([]byte{0x25}, 32), 10000)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RequireAuditSpool(spool); err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestPostgresCredentialLifecycle(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatalf("migration was not idempotent: %v", err)
	}
	manager := postgresTestManager(t, pool)
	request := validCreate()
	created, err := manager.CreateContext(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := manager.CreateContext(ctx, request)
	if err != nil || replayed.ID != created.ID {
		t.Fatalf("idempotent replay: %+v %v", replayed, err)
	}
	request.Name = "conflicting-request"
	if _, err := manager.CreateContext(ctx, request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict: %v", err)
	}

	secondManager := postgresTestManager(t, pool)
	got, err := secondManager.GetContext(ctx, "org-5", created.ID)
	if err != nil || got.ID != created.ID {
		t.Fatalf("durable get: %+v %v", got, err)
	}
	if _, err := secondManager.GetContext(ctx, "other-org", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org get: %v", err)
	}

	updated, err := secondManager.ReplaceInputsContext(ctx, ReplaceInputsRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1,
		Inputs: map[string]string{"username": "updated", "password": "replacement-secret"},
	})
	if err != nil || updated.Version != 2 {
		t.Fatalf("replace: %+v %v", updated, err)
	}
	if _, err := manager.ReplaceInputsContext(ctx, ReplaceInputsRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1,
		Inputs: map[string]string{"username": "stale", "password": "stale-secret"},
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale update: %v", err)
	}

	renamed, err := manager.UpdateMetadataContext(ctx, UpdateMetadataRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 2, Name: "renamed",
	})
	if err != nil || renamed.Version != 3 {
		t.Fatalf("rename: %+v %v", renamed, err)
	}
	retired, err := manager.RetireContext(ctx, RetireRequest{CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 3})
	if err != nil || retired.Version != 4 || retired.State != StateRetired {
		t.Fatalf("retire: %+v %v", retired, err)
	}
	replayed, err = secondManager.RetireContext(ctx, RetireRequest{CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 3})
	if err != nil || replayed.Version != 4 || replayed.State != StateRetired {
		t.Fatalf("retire replay: %+v %v", replayed, err)
	}
	var envelopeText string
	if err := pool.QueryRow(ctx, "SELECT envelope::text FROM credential_versions WHERE credential_id = $1 AND version = 3", created.ID).Scan(&envelopeText); err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{"very-secret-value", "replacement-secret", "automation", "updated"} {
		if strings.Contains(envelopeText, plaintext) {
			t.Fatalf("database envelope contains plaintext %q", plaintext)
		}
	}
	if _, err := pool.Exec(ctx, "UPDATE credentials SET organization_id = 'other' WHERE id = $1", created.ID); err == nil {
		t.Fatal("database allowed immutable ownership change")
	}
	var versionCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM credential_versions WHERE credential_id = $1", created.ID).Scan(&versionCount); err != nil || versionCount != 4 {
		t.Fatalf("version history count=%d err=%v", versionCount, err)
	}
}

func TestPostgresMasterKeyRotationResumesAfterManagerRestart(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	oldPath := t.TempDir() + "/old-key"
	newPath := t.TempDir() + "/new-key"
	if err := os.WriteFile(oldPath, bytes.Repeat([]byte{0x61}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, bytes.Repeat([]byte{0x62}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	oldManager := postgresRotationManager(t, pool, oldPath, "")
	firstRequest := validCreate()
	firstRequest.IdempotencyKey = "rotation-create-1"
	first, err := oldManager.CreateContext(audit.WithRequest(ctx, audit.Request{
		ID: "create-1", WorkloadIdentity: "praetor-api", Operation: audit.OperationCredentialCreated, StartedAt: time.Now().UTC(),
	}), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := validCreate()
	secondRequest.IdempotencyKey = "rotation-create-2"
	secondRequest.Name = "second"
	second, err := oldManager.CreateContext(audit.WithRequest(ctx, audit.Request{
		ID: "create-2", WorkloadIdentity: "praetor-api", Operation: audit.OperationCredentialCreated, StartedAt: time.Now().UTC(),
	}), secondRequest)
	if err != nil {
		t.Fatal(err)
	}

	manager := postgresRotationManager(t, pool, newPath, oldPath)
	rotationContext := audit.WithRequest(ctx, audit.Request{
		ID: "rotation-start", WorkloadIdentity: "praetor-secrets-operator",
		Operation: audit.OperationMasterKeyRotationStarted, StartedAt: time.Now().UTC(),
	})
	rotation, err := manager.StartMasterKeyRotation(rotationContext)
	if err != nil || rotation.TotalRecords != 2 {
		t.Fatalf("start=%+v err=%v", rotation, err)
	}
	if _, err := manager.FinalizeMasterKeyRotation(rotationContext, rotation.ID); !errors.Is(err, ErrRotationNotReady) {
		t.Fatalf("premature finalize: %v", err)
	}
	resumeContext := audit.WithRequest(ctx, audit.Request{
		ID: "rotation-resume-1", WorkloadIdentity: "praetor-secrets-operator",
		Operation: audit.OperationMasterKeyRotationResumed, StartedAt: time.Now().UTC(),
	})
	rotation, err = manager.ResumeMasterKeyRotation(resumeContext, rotation.ID, 1)
	if err != nil || rotation.ProcessedRecords != 1 || rotation.State != RotationRunning {
		t.Fatalf("first resume=%+v err=%v", rotation, err)
	}

	// Reconstructing the manager simulates process interruption and proves that
	// progress is durable rather than held in memory.
	manager = postgresRotationManager(t, pool, newPath, oldPath)
	resumeContext = audit.WithRequest(ctx, audit.Request{
		ID: "rotation-resume-2", WorkloadIdentity: "praetor-secrets-operator",
		Operation: audit.OperationMasterKeyRotationResumed, StartedAt: time.Now().UTC(),
	})
	rotation, err = manager.ResumeMasterKeyRotation(resumeContext, rotation.ID, 10)
	if err != nil || rotation.State != RotationReady || rotation.ProcessedRecords != 2 {
		t.Fatalf("resumed after restart=%+v err=%v", rotation, err)
	}
	finalizeContext := audit.WithRequest(ctx, audit.Request{
		ID: "rotation-finalize", WorkloadIdentity: "praetor-secrets-operator",
		Operation: audit.OperationMasterKeyRotationFinalized, StartedAt: time.Now().UTC(),
	})
	rotation, err = manager.FinalizeMasterKeyRotation(finalizeContext, rotation.ID)
	if err != nil || rotation.State != RotationFinalized {
		t.Fatalf("finalize=%+v err=%v", rotation, err)
	}
	var oldCount int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM credential_versions WHERE master_key_id=$1`, manager.keys.Previous.ID()).Scan(&oldCount); err != nil || oldCount != 0 {
		t.Fatalf("old-key references=%d err=%v", oldCount, err)
	}
	for _, metadata := range []Metadata{first, second} {
		stored, record, err := manager.backend.Get(ctx, metadata.OrganizationID, metadata.ID)
		if err != nil || record.MasterKeyID != manager.keys.Current.ID() {
			t.Fatalf("stored=%+v key=%q err=%v", stored, record.MasterKeyID, err)
		}
		plaintext, err := envelope.Decrypt(record, envelopeContext(stored), manager.keys.Keyring())
		if err != nil || !bytes.Contains(plaintext, []byte("very-secret-value")) {
			t.Fatalf("rotated record unavailable: %v", err)
		}
		wipe(plaintext)
	}
}

func TestPostgresPerCredentialRotationAndKeyStatus(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyPath := writePostgresTestKey(t)
	manager := postgresRotationManager(t, pool, keyPath, "")
	createContext := audit.WithRequest(ctx, audit.Request{
		ID: "credential-create", WorkloadIdentity: "praetor-api",
		Operation: audit.OperationCredentialCreated, StartedAt: time.Now().UTC(),
	})
	metadata, err := manager.CreateContext(createContext, validCreate())
	if err != nil {
		t.Fatal(err)
	}
	_, before, err := manager.backend.Get(ctx, metadata.OrganizationID, metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	rotateContext := audit.WithRequest(ctx, audit.Request{
		ID: "credential-rotate", WorkloadIdentity: "praetor-secrets-operator",
		Operation: audit.OperationCredentialKeyRotated, StartedAt: time.Now().UTC(),
	})
	if err := manager.RotateCredentialKey(rotateContext, CredentialRotationRequest{
		OrganizationID: metadata.OrganizationID, CredentialID: metadata.ID, Version: metadata.Version,
	}); err != nil {
		t.Fatal(err)
	}
	stored, after, err := manager.backend.Get(ctx, metadata.OrganizationID, metadata.ID)
	if err != nil || before.RecordID == after.RecordID || bytes.Equal(before.Ciphertext, after.Ciphertext) {
		t.Fatalf("before=%q after=%q stored=%+v err=%v", before.RecordID, after.RecordID, stored, err)
	}
	plaintext, err := envelope.Decrypt(after, envelopeContext(stored), manager.keys.Keyring())
	if err != nil || !bytes.Contains(plaintext, []byte("very-secret-value")) {
		t.Fatalf("rotated plaintext unavailable: %v", err)
	}
	wipe(plaintext)
	status, err := manager.KeyStatus(ctx)
	if err != nil || status.RecordCounts[manager.keys.Current.ID()] != 1 || status.DatabaseReferencesCleared {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	var events int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_spool
        WHERE event->>'operation'=$1 AND event->>'credential_id'=$2
          AND event->>'event_type'=$3`,
		audit.OperationCredentialKeyRotated, metadata.ID, audit.EventTypeStateTransition).Scan(&events); err != nil || events != 1 {
		t.Fatalf("rotation audit events=%d err=%v", events, err)
	}
}

func TestPostgresRecoveryValidationAndBackupEvidence(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	manager := postgresTestManager(t, pool)
	createCtx := audit.WithRequest(ctx, audit.Request{ID: "create", WorkloadIdentity: "praetor-api", Operation: audit.OperationCredentialCreated, StartedAt: time.Now().UTC()})
	metadata, err := manager.CreateContext(createCtx, validCreate())
	if err != nil {
		t.Fatal(err)
	}
	recoveryCtx := audit.WithRequest(ctx, audit.Request{ID: "recovery", WorkloadIdentity: "praetor-secrets-operator", Operation: audit.OperationRecoveryValidationFinished, StartedAt: time.Now().UTC()})
	result, err := manager.ValidateRecovery(recoveryCtx, 10)
	if err != nil || result.ValidatedRecords != 1 || result.TotalRecords != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	_, record, err := manager.backend.Get(ctx, metadata.OrganizationID, metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	backup := BackupSet{ID: "backup-pg", ArtifactSHA256: strings.Repeat("c", 64), KeyIDs: []string{record.MasterKeyID}, CreatedAt: manager.now(), RetainUntil: manager.now().Add(time.Hour)}
	backupCtx := audit.WithRequest(ctx, audit.Request{ID: "backup", WorkloadIdentity: "praetor-secrets-operator", Operation: audit.OperationBackupRegistered, StartedAt: time.Now().UTC()})
	if _, err := manager.RegisterBackup(backupCtx, backup); err != nil {
		t.Fatal(err)
	}
	if replay, err := manager.RegisterBackup(backupCtx, backup); err != nil || replay.ID != backup.ID {
		t.Fatalf("backup replay=%+v err=%v", replay, err)
	}
	conflict := backup
	conflict.ArtifactSHA256 = strings.Repeat("d", 64)
	if _, err := manager.RegisterBackup(backupCtx, conflict); !errors.Is(err, ErrBackupConflict) {
		t.Fatalf("backup conflict=%v", err)
	}
	status, err := manager.KeyStatus(ctx)
	if err != nil || status.RetainedBackupReferences[record.MasterKeyID] != 1 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if _, err := manager.ExpireBackup(backupCtx, backup.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ExpireBackup(backupCtx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing backup=%v", err)
	}
	status, _ = manager.KeyStatus(ctx)
	if status.RetainedBackupReferences[record.MasterKeyID] != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestPostgresMutationFailsClosedWithoutAuditSpool(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	path := writePostgresTestKey(t)
	keys, err := masterkey.Load(masterkey.Config{CurrentPath: path})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPostgresManager(keys, testSchemas{}, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreateContext(ctx, validCreate()); !errors.Is(err, ErrStorage) {
		t.Fatalf("mutation did not fail closed: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM credentials").Scan(&count); err != nil || count != 0 {
		t.Fatalf("credential committed without audit count=%d err=%v", count, err)
	}
}

func TestPostgresMutationRollsBackWhenCompletionEventCannotFit(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keys, err := masterkey.Load(masterkey.Config{CurrentPath: writePostgresTestKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPostgresManager(keys, testSchemas{}, pool)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := audit.New(bytes.Repeat([]byte{0x31}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RequireAuditSpool(spool); err != nil {
		t.Fatal(err)
	}
	requestContext := audit.WithRequest(ctx, audit.Request{ID: "request-1", WorkloadIdentity: "praetor-api", Operation: "credential_created", StartedAt: time.Now().UTC()})
	if _, err := manager.CreateContext(requestContext, validCreate()); !errors.Is(err, ErrStorage) {
		t.Fatalf("mutation did not fail closed: %v", err)
	}
	var credentials, events int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM credentials").Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_spool").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if credentials != 0 || events != 0 {
		t.Fatalf("partial commit credentials=%d events=%d", credentials, events)
	}
}

func TestPostgresConcurrentVersionCheck(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	manager := postgresTestManager(t, pool)
	created, err := manager.CreateContext(ctx, validCreate())
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, name := range []string{"winner-a", "winner-b"} {
		wait.Add(1)
		go func(name string) {
			defer wait.Done()
			_, err := manager.UpdateMetadataContext(ctx, UpdateMetadataRequest{
				CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1, Name: name,
			})
			results <- err
		}(name)
	}
	wait.Wait()
	close(results)
	winners, conflicts := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, ErrVersionConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected update error: %v", err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("winners=%d conflicts=%d", winners, conflicts)
	}
}

func TestPostgresRunScopedResolution(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	manager := postgresTestManager(t, pool)
	manager.injector = testInjector{}
	now := manager.now()
	created, err := manager.CreateContext(ctx, validCreate())
	if err != nil {
		t.Fatal(err)
	}
	registration := testBinding(now, created.ID)
	binding, err := manager.RegisterBinding(ctx, schedulerIdentity(), registration)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := manager.RegisterBinding(ctx, schedulerIdentity(), registration)
	if err != nil || replayed.RunID != binding.RunID {
		t.Fatalf("registration replay: %+v %v", replayed, err)
	}
	if _, err := manager.ReplaceInputsContext(ctx, ReplaceInputsRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1,
		Inputs: map[string]string{"username": "new-user", "password": "new-secret"},
	}); err != nil {
		t.Fatal(err)
	}

	request := ResolveRequest{
		RunID: binding.RunID, AttemptID: "31024db7-0db8-446a-b049-dd9d172cde94", RequestedAt: now,
	}
	resolved, err := manager.Resolve(ctx, executorIdentity("worker-7"), request)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Environment["ANSIBLE_REMOTE_USER"] != "automation" || resolved.Files[0].Content != "very-secret-value" {
		t.Fatalf("did not resolve snapshot: %+v", resolved)
	}
	if _, err := manager.Resolve(ctx, executorIdentity("worker-7"), request); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := manager.Resolve(ctx, executorIdentity("other"), request); !errors.Is(err, ErrBindingNotActive) {
		t.Fatalf("wrong executor: %v", err)
	}

	second := request
	second.AttemptID = "41024db7-0db8-446a-b049-dd9d172cde95"
	third := request
	third.AttemptID = "51024db7-0db8-446a-b049-dd9d172cde96"
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, attempt := range []ResolveRequest{second, third} {
		wait.Add(1)
		go func(attempt ResolveRequest) {
			defer wait.Done()
			_, err := manager.Resolve(ctx, executorIdentity("worker-7"), attempt)
			results <- err
		}(attempt)
	}
	wait.Wait()
	close(results)
	winners, exhausted := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, ErrBindingNotActive) {
			exhausted++
		} else {
			t.Fatalf("concurrent resolution: %v", err)
		}
	}
	if winners != 1 || exhausted != 1 {
		t.Fatalf("winners=%d exhausted=%d", winners, exhausted)
	}
	inspected, err := manager.InspectBinding(ctx, schedulerIdentity(), binding.RunID)
	if err != nil || inspected.ResolutionCount != 2 || inspected.State != BindingExhausted {
		t.Fatalf("binding after resolution: %+v %v", inspected, err)
	}
	var attemptCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM resolution_attempts WHERE run_id = $1", binding.RunID).Scan(&attemptCount); err != nil || attemptCount != 2 {
		t.Fatalf("attempt count=%d err=%v", attemptCount, err)
	}
	var plaintextColumns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name IN ('run_bindings', 'resolution_attempts')
          AND column_name IN ('plaintext', 'inputs', 'secret', 'response')`).Scan(&plaintextColumns); err != nil || plaintextColumns != 0 {
		t.Fatalf("plaintext columns=%d err=%v", plaintextColumns, err)
	}
}

func TestPostgresCancellationAndBindingConflicts(t *testing.T) {
	pool := postgresTestPool(t)
	ctx := context.Background()
	if err := ApplyPostgresMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	manager := postgresTestManager(t, pool)
	manager.injector = testInjector{}
	now := manager.now()
	created, _ := manager.CreateContext(ctx, validCreate())
	registration := testBinding(now, created.ID)
	binding, err := manager.RegisterBinding(ctx, schedulerIdentity(), registration)
	if err != nil {
		t.Fatal(err)
	}
	registration.ExecutorIdentity = "praetor-executor:other"
	if _, err := manager.RegisterBinding(ctx, schedulerIdentity(), registration); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("binding conflict: %v", err)
	}
	if _, err := manager.CancelBinding(ctx, schedulerIdentity(), CancelBindingRequest{
		RunID: binding.RunID, DispatchID: "ffffffff-ffff-4fff-8fff-ffffffffffff", Reason: "stale_dispatch",
	}); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("stale dispatch canceled binding: %v", err)
	}
	canceled, err := manager.CancelBinding(ctx, schedulerIdentity(), CancelBindingRequest{RunID: binding.RunID, DispatchID: binding.DispatchID, Reason: "dispatch_canceled"})
	if err != nil || canceled.State != BindingCanceled {
		t.Fatalf("cancel: %+v %v", canceled, err)
	}
	again, err := manager.CancelBinding(ctx, schedulerIdentity(), CancelBindingRequest{RunID: binding.RunID, DispatchID: binding.DispatchID, Reason: "different_reason"})
	if err != nil || again.CancelReason != "dispatch_canceled" {
		t.Fatalf("cancel was not idempotent: %+v %v", again, err)
	}
	request := ResolveRequest{RunID: binding.RunID, AttemptID: "31024db7-0db8-446a-b049-dd9d172cde94", RequestedAt: now}
	if _, err := manager.Resolve(ctx, executorIdentity("worker-7"), request); !errors.Is(err, ErrBindingNotActive) {
		t.Fatalf("canceled resolution: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE run_bindings SET credential_id = $1 WHERE run_id = $2", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", binding.RunID); err == nil {
		t.Fatal("database allowed binding identity mutation")
	}
}

func TestPostgresHelpersFailClosed(t *testing.T) {
	if _, err := NewPostgresManager(masterkey.Set{}, testSchemas{}, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil pool manager: %v", err)
	}
	if err := ApplyPostgresMigrations(context.Background(), nil); !errors.Is(err, ErrStorage) {
		t.Fatalf("nil migration pool: %v", err)
	}
	if _, _, ok := splitIdempotencyID("invalid"); ok {
		t.Fatal("accepted invalid idempotency identifier")
	}
	metadata := Metadata{SecretFields: []string{"password"}}
	record := struct{ Value chan int }{Value: make(chan int)}
	if _, err := json.Marshal(record); err == nil {
		t.Fatal("test record unexpectedly marshaled")
	}
	if encoded, _, err := encodeStorage(metadata, envelope.Record{}); err != nil || len(encoded) == 0 {
		t.Fatalf("storage encoding: %v", err)
	}
}
