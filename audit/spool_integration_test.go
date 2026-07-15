package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type collectingSink struct {
	records []Record
	fail    bool
}

func (sink *collectingSink) Deliver(_ context.Context, record Record) error {
	if sink.fail {
		return ErrSink
	}
	sink.records = append(sink.records, record)
	return nil
}

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
	if _, err := pool.Exec(ctx, `UPDATE audit_chain_state SET last_sequence=99 WHERE singleton=true`); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Pending(ctx, pool, 10); !errors.Is(err, ErrAudit) {
		t.Fatal("tampered chain head accepted")
	}
	if err := spool.MarkDelivered(ctx, pool, records[1].Sequence, make([]byte, 32), time.Now()); err == nil {
		t.Fatal("wrong MAC acknowledged")
	}
}

func TestDeliveryWorkerRetriesInOrder(t *testing.T) {
	pool := auditTestPool(t)
	spool, _ := New(bytes.Repeat([]byte{7}, 32), 10)
	ctx := context.Background()
	for index := 0; index < 2; index++ {
		tx, _ := pool.Begin(ctx)
		event := validEvent()
		event.CredentialID = fmt.Sprintf("delivery-%d", index)
		event.Timestamp = event.Timestamp.Add(time.Duration(index) * time.Second)
		if err := spool.AppendTx(ctx, tx, event); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	sink := &collectingSink{fail: true}
	worker, err := NewDeliveryWorker(spool, pool, sink, DeliveryConfig{BatchSize: 10, PollInterval: time.Second, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.deliverBatch(ctx); !errors.Is(err, ErrSink) {
		t.Fatalf("sink failure=%v", err)
	}
	pending, err := spool.Pending(ctx, pool, 10)
	if err != nil || len(pending) != 2 {
		t.Fatalf("failure acknowledged records=%d err=%v", len(pending), err)
	}
	sink.fail = false
	if err := worker.deliverBatch(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 2 || sink.records[0].Sequence != 1 || sink.records[1].Sequence != 2 {
		t.Fatalf("delivery order=%+v", sink.records)
	}
	pending, err = spool.Pending(ctx, pool, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending=%d err=%v", len(pending), err)
	}
	if worker.Status().Degraded || worker.Status().LastDelivered.IsZero() {
		t.Fatalf("status=%+v", worker.Status())
	}
}
