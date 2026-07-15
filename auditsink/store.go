// Package auditsink persists the remote, append-only copy of the Praetor
// Secrets Service audit stream.
package auditsink

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalid  = errors.New("invalid remote audit record")
	ErrConflict = errors.New("remote audit stream conflict")
	ErrStore    = errors.New("remote audit store unavailable")
)

//go:embed migrations/001_append_store.sql
var migration string

type AppendResult string

const (
	Created  AppendResult = "created"
	Replayed AppendResult = "replayed"
)

type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrStore
	}
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }}, nil
}

func ApplyMigration(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return ErrStore
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrStore
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x52656d4175646974)); err != nil {
		return ErrStore
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS remote_audit_schema_migrations (
		version integer PRIMARY KEY, applied_at timestamptz NOT NULL)`); err != nil {
		return ErrStore
	}
	var applied bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM remote_audit_schema_migrations WHERE version=1)").Scan(&applied); err != nil {
		return ErrStore
	}
	if !applied {
		if _, err := tx.Exec(ctx, migration); err != nil {
			return ErrStore
		}
		if _, err := tx.Exec(ctx, "INSERT INTO remote_audit_schema_migrations(version,applied_at) VALUES(1,$1)", time.Now().UTC()); err != nil {
			return ErrStore
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrStore
	}
	return nil
}

func (store *Store) Append(ctx context.Context, record audit.Record, idempotencyKey, workloadIdentity string) (AppendResult, error) {
	canonical, err := validate(record, idempotencyKey, workloadIdentity)
	if err != nil || store == nil || store.pool == nil || store.now == nil {
		return "", ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return "", ErrStore
	}
	defer tx.Rollback(ctx)
	var lastSequence int64
	var lastMAC []byte
	if err := tx.QueryRow(ctx, `SELECT last_sequence,last_mac FROM remote_audit_stream_head
		WHERE singleton=true FOR UPDATE`).Scan(&lastSequence, &lastMAC); err != nil {
		return "", ErrStore
	}
	if record.Sequence <= lastSequence {
		result, err := exactReplay(ctx, tx, record, canonical, idempotencyKey, workloadIdentity)
		if err != nil {
			return "", err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", ErrStore
		}
		return result, nil
	}
	if record.Sequence != lastSequence+1 {
		return "", ErrConflict
	}
	receivedAt := store.now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO remote_audit_records
		(sequence,event,mac,idempotency_key,workload_identity,received_at)
		VALUES($1,$2,$3,$4,$5,$6)`, record.Sequence, canonical, record.MAC, idempotencyKey, workloadIdentity, receivedAt); err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && strings.HasPrefix(postgresError.Code, "23") {
			return "", ErrConflict
		}
		return "", ErrStore
	}
	if _, err := tx.Exec(ctx, `UPDATE remote_audit_stream_head
		SET last_sequence=$1,last_mac=$2,updated_at=$3 WHERE singleton=true`, record.Sequence, record.MAC, receivedAt); err != nil {
		return "", ErrStore
	}
	if err := tx.Commit(ctx); err != nil {
		return "", ErrStore
	}
	return Created, nil
}

func exactReplay(ctx context.Context, tx pgx.Tx, record audit.Record, canonical []byte, idempotencyKey, workloadIdentity string) (AppendResult, error) {
	var storedEvent, storedMAC []byte
	var storedKey, storedIdentity string
	err := tx.QueryRow(ctx, `SELECT event,mac,idempotency_key,workload_identity
		FROM remote_audit_records WHERE sequence=$1`, record.Sequence).Scan(&storedEvent, &storedMAC, &storedKey, &storedIdentity)
	if err != nil {
		return "", ErrConflict
	}
	var event audit.Event
	if json.Unmarshal(storedEvent, &event) != nil {
		return "", ErrStore
	}
	storedCanonical, err := json.Marshal(event)
	if err != nil {
		return "", ErrStore
	}
	if !bytes.Equal(storedCanonical, canonical) || !bytes.Equal(storedMAC, record.MAC) || storedKey != idempotencyKey || storedIdentity != workloadIdentity {
		return "", ErrConflict
	}
	return Replayed, nil
}

func validate(record audit.Record, idempotencyKey, workloadIdentity string) ([]byte, error) {
	if record.Sequence < 1 || len(record.MAC) != 32 || workloadIdentity != "praetor-secrets" ||
		idempotencyKey != "audit-"+hex.EncodeToString(record.MAC) || record.Event.SchemaVersion != audit.SchemaVersion ||
		record.Event.Timestamp.IsZero() || strings.TrimSpace(record.Event.EventType) == "" ||
		strings.TrimSpace(record.Event.Operation) == "" || strings.TrimSpace(record.Event.Result) == "" ||
		strings.TrimSpace(record.Event.ReasonCode) == "" {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(record.Event)
	if err != nil || len(canonical) > 60<<10 {
		return nil, ErrInvalid
	}
	return canonical, nil
}
