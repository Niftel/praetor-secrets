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
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM credential_versions WHERE credential_id = $1", created.ID).Scan(&versionCount); err != nil || versionCount != 3 {
		t.Fatalf("version history count=%d err=%v", versionCount, err)
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
