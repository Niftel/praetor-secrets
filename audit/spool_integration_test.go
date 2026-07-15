package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func auditTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("PRAETOR_SECRETS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PRAETOR_SECRETS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "audit_test_" + fmt.Sprintf("%x", suffix)
	if _, err := admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
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
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`)
		admin.Close()
	})
	if err := ApplyMigration(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigration(ctx, pool); err != nil {
		t.Fatal("migration not idempotent")
	}
	return pool
}

func TestAppendVerifyDeliverAndTamperProtection(t *testing.T) {
	pool := auditTestPool(t)
	spool, _ := New(bytes.Repeat([]byte{9}, 32), 2)
	ctx := context.Background()
	for index := 0; index < 2; index++ {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatal(err)
		}
		event := validEvent()
		event.Timestamp = event.Timestamp.Add(time.Duration(index) * time.Second)
		event.CredentialID = fmt.Sprintf("credential-%d", index)
		if err := spool.AppendTx(ctx, tx, event); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.Verify(ctx, pool); err != nil {
		t.Fatalf("verify: %v", err)
	}
	tx, _ := pool.BeginTx(ctx, pgx.TxOptions{})
	if err := spool.AppendTx(ctx, tx, validEvent()); err == nil {
		t.Fatal("full spool accepted event")
	}
	_ = tx.Rollback(ctx)
	records, err := spool.Pending(ctx, pool, 10)
	if err != nil || len(records) != 2 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	if err := spool.MarkDelivered(ctx, pool, records[0].Sequence, records[0].MAC, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_spool SET event='{}'::jsonb WHERE sequence=1`); err == nil {
		t.Fatal("audit event mutated")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_spool WHERE sequence=1`); err == nil {
		t.Fatal("audit event deleted")
	}
	if err := spool.MarkDelivered(ctx, pool, records[1].Sequence, make([]byte, 32), time.Now()); err == nil {
		t.Fatal("wrong MAC acknowledged")
	}
}
