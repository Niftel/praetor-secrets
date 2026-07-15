// Package audit provides a bounded, append-only, authenticated audit spool.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const SchemaVersion = 1

var (
	ErrAudit = errors.New("audit spool unavailable")
	ErrEvent = errors.New("invalid audit event")
)

//go:embed migrations/001_audit_spool.sql
var migration string

type Event struct {
	SchemaVersion     uint32    `json:"schema_version"`
	Timestamp         time.Time `json:"timestamp"`
	EventType         string    `json:"event_type"`
	Operation         string    `json:"operation"`
	Result            string    `json:"result"`
	ReasonCode        string    `json:"reason_code"`
	WorkloadIdentity  string    `json:"workload_identity,omitempty"`
	HumanActor        string    `json:"human_actor,omitempty"`
	OrganizationID    string    `json:"organization_id,omitempty"`
	CredentialID      string    `json:"credential_id,omitempty"`
	RunID             string    `json:"run_id,omitempty"`
	ExecutorIdentity  string    `json:"executor_identity,omitempty"`
	CredentialVersion uint64    `json:"credential_version,omitempty"`
	CredentialSchema  uint32    `json:"credential_schema_version,omitempty"`
	KeyVersion        string    `json:"key_version,omitempty"`
}

type Spool struct {
	key            [32]byte
	maximumPending int64
}

type Record struct {
	Sequence int64  `json:"sequence"`
	Event    Event  `json:"event"`
	MAC      []byte `json:"mac"`
}

func New(key []byte, maximumPending int64) (*Spool, error) {
	if len(key) != 32 || maximumPending < 1 {
		return nil, ErrAudit
	}
	spool := &Spool{maximumPending: maximumPending}
	copy(spool.key[:], key)
	return spool, nil
}

func LoadKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrAudit
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrAudit
	}
	value := make([]byte, 33)
	count, err := io.ReadFull(file, value)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(value)
		return nil, ErrAudit
	}
	if count != 32 {
		clear(value)
		return nil, ErrAudit
	}
	if _, err := file.Read(value[32:]); err != io.EOF {
		clear(value)
		return nil, ErrAudit
	}
	return value[:32], nil
}

func ApplyMigration(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return ErrAudit
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrAudit
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x41756469745370)); err != nil {
		return ErrAudit
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS praetor_audit_schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL)`); err != nil {
		return ErrAudit
	}
	var applied bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM praetor_audit_schema_migrations WHERE version=1)").Scan(&applied); err != nil {
		return ErrAudit
	}
	if !applied {
		if _, err := tx.Exec(ctx, migration); err != nil {
			return ErrAudit
		}
		if _, err := tx.Exec(ctx, "INSERT INTO praetor_audit_schema_migrations(version,applied_at) VALUES(1,$1)", time.Now().UTC()); err != nil {
			return ErrAudit
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrAudit
	}
	return nil
}

// AppendTx makes audit durability part of the caller's state-change transaction.
func (spool *Spool) AppendTx(ctx context.Context, tx pgx.Tx, event Event) error {
	if spool == nil || tx == nil || validate(event) != nil {
		return ErrAudit
	}
	var sequence, pending int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT last_sequence, last_mac FROM audit_chain_state WHERE singleton = true FOR UPDATE`).Scan(&sequence, &previous); err != nil {
		return ErrAudit
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_spool WHERE delivered_at IS NULL`).Scan(&pending); err != nil || pending >= spool.maximumPending {
		return ErrAudit
	}
	sequence++
	encoded, err := json.Marshal(event)
	if err != nil {
		return ErrAudit
	}
	mac := spool.authenticate(sequence, previous, encoded)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_spool (sequence, event, previous_mac, mac) VALUES ($1,$2,$3,$4)`, sequence, encoded, previous, mac); err != nil {
		return ErrAudit
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_chain_state SET last_sequence=$1,last_mac=$2 WHERE singleton=true`, sequence, mac); err != nil {
		return ErrAudit
	}
	return nil
}

func (spool *Spool) authenticate(sequence int64, previous, encoded []byte) []byte {
	mac := hmac.New(sha256.New, spool.key[:])
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(sequence))
	mac.Write(number[:])
	mac.Write(previous)
	mac.Write(encoded)
	return mac.Sum(nil)
}

// Pending returns a bounded delivery batch without exposing authentication keys.
func (spool *Spool) Pending(ctx context.Context, pool *pgxpool.Pool, limit int) ([]Record, error) {
	if spool == nil || pool == nil || limit < 1 || limit > 1000 {
		return nil, ErrAudit
	}
	rows, err := pool.Query(ctx, `SELECT sequence,event,mac FROM audit_spool WHERE delivered_at IS NULL ORDER BY sequence LIMIT $1`, limit)
	if err != nil {
		return nil, ErrAudit
	}
	defer rows.Close()
	var records []Record
	for rows.Next() {
		var record Record
		var encoded []byte
		if err := rows.Scan(&record.Sequence, &encoded, &record.MAC); err != nil || json.Unmarshal(encoded, &record.Event) != nil {
			return nil, ErrAudit
		}
		records = append(records, record)
	}
	if rows.Err() != nil {
		return nil, ErrAudit
	}
	return records, nil
}

// MarkDelivered acknowledges exactly the authenticated record delivered by a sink.
func (spool *Spool) MarkDelivered(ctx context.Context, pool *pgxpool.Pool, sequence int64, mac []byte, deliveredAt time.Time) error {
	if spool == nil || pool == nil || sequence < 1 || len(mac) != sha256.Size || deliveredAt.IsZero() {
		return ErrAudit
	}
	result, err := pool.Exec(ctx, `UPDATE audit_spool SET delivered_at=$1 WHERE sequence=$2 AND mac=$3 AND delivered_at IS NULL`, deliveredAt.UTC(), sequence, mac)
	if err != nil || result.RowsAffected() != 1 {
		return ErrAudit
	}
	return nil
}

// Verify checks the complete chain and its durable head before delivery starts.
func (spool *Spool) Verify(ctx context.Context, pool *pgxpool.Pool) error {
	if spool == nil || pool == nil {
		return ErrAudit
	}
	rows, err := pool.Query(ctx, `SELECT sequence,event,previous_mac,mac FROM audit_spool ORDER BY sequence`)
	if err != nil {
		return ErrAudit
	}
	defer rows.Close()
	var expectedSequence int64
	var previous []byte
	for rows.Next() {
		var sequence int64
		var encoded, storedPrevious, storedMAC []byte
		var event Event
		if err := rows.Scan(&sequence, &encoded, &storedPrevious, &storedMAC); err != nil || json.Unmarshal(encoded, &event) != nil {
			return ErrAudit
		}
		canonical, err := json.Marshal(event)
		if err != nil {
			return ErrAudit
		}
		expectedSequence++
		if sequence != expectedSequence || !hmac.Equal(storedPrevious, previous) || !hmac.Equal(storedMAC, spool.authenticate(sequence, previous, canonical)) {
			return ErrAudit
		}
		previous = append(previous[:0], storedMAC...)
	}
	if rows.Err() != nil {
		return ErrAudit
	}
	var headSequence int64
	var headMAC []byte
	if err := pool.QueryRow(ctx, `SELECT last_sequence,last_mac FROM audit_chain_state WHERE singleton=true`).Scan(&headSequence, &headMAC); err != nil || headSequence != expectedSequence || !hmac.Equal(headMAC, previous) {
		return ErrAudit
	}
	return nil
}

func validate(event Event) error {
	if event.SchemaVersion != SchemaVersion || event.Timestamp.IsZero() || !event.Timestamp.Equal(event.Timestamp.UTC()) ||
		!token(event.EventType) || !token(event.Operation) || !token(event.Result) || !token(event.ReasonCode) {
		return ErrEvent
	}
	for _, value := range []string{event.WorkloadIdentity, event.HumanActor, event.OrganizationID, event.CredentialID, event.RunID, event.ExecutorIdentity, event.KeyVersion} {
		if len(value) > 255 || strings.ContainsAny(value, "\x00\r\n") {
			return ErrEvent
		}
	}
	return nil
}

func token(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}
