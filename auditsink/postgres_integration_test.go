package auditsink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresAppendOrderingReplayAndImmutability(t *testing.T) {
	databaseURL := os.Getenv("PRAETOR_SECRETS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PRAETOR_SECRETS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("audit_sink_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := ApplyMigration(ctx, pool); err != nil {
		t.Fatalf("ApplyMigration: %v", err)
	}
	store, _ := NewStore(pool)
	one := validRecord(1)
	if result, err := store.Append(ctx, one, key(one), "praetor-secrets"); err != nil || result != Created {
		t.Fatalf("first append result=%s err=%v", result, err)
	}
	if result, err := store.Append(ctx, one, key(one), "praetor-secrets"); err != nil || result != Replayed {
		t.Fatalf("replay result=%s err=%v", result, err)
	}
	conflict := one
	conflict.Event.ReasonCode = "different"
	if _, err := store.Append(ctx, conflict, key(conflict), "praetor-secrets"); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting replay error=%v", err)
	}
	three := validRecord(3)
	if _, err := store.Append(ctx, three, key(three), "praetor-secrets"); !errors.Is(err, ErrConflict) {
		t.Fatalf("gap error=%v", err)
	}
	two := validRecord(2)
	if result, err := store.Append(ctx, two, key(two), "praetor-secrets"); err != nil || result != Created {
		t.Fatalf("second append result=%s err=%v", result, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE remote_audit_records SET workload_identity='praetor-scheduler' WHERE sequence=1"); err == nil {
		t.Fatal("record update succeeded")
	}
	if _, err := pool.Exec(ctx, "DELETE FROM remote_audit_records WHERE sequence=1"); err == nil {
		t.Fatal("record delete succeeded")
	}
	var count, head int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM remote_audit_records").Scan(&count); err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if err := pool.QueryRow(ctx, "SELECT last_sequence FROM remote_audit_stream_head WHERE singleton=true").Scan(&head); err != nil || head != 2 {
		t.Fatalf("head=%d err=%v", head, err)
	}
}
