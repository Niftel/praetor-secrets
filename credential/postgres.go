package credential

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"time"

	"github.com/Niftel/praetor-secrets/envelope"
	"github.com/Niftel/praetor-secrets/masterkey"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_credentials.sql
var credentialMigration string

//go:embed migrations/002_run_bindings.sql
var runBindingMigration string

var ErrStorage = errors.New("credential storage unavailable")

type postgresBackend struct {
	pool *pgxpool.Pool
}

// NewPostgresManager creates the production credential manager. Migrations must
// be applied explicitly during deployment before serving traffic.
func NewPostgresManager(keys masterkey.Set, schemas SchemaRegistry, pool *pgxpool.Pool, injectors ...InjectorRegistry) (*Manager, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	manager, err := NewManager(keys, schemas, injectors...)
	if err != nil {
		return nil, err
	}
	manager.backend = &postgresBackend{pool: pool}
	return manager, nil
}

// ApplyPostgresMigrations installs the credential schema exactly once. It uses
// an advisory transaction lock so concurrent service starts cannot race.
func ApplyPostgresMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return ErrStorage
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrStorage
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x50726165746f72)); err != nil {
		return ErrStorage
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS praetor_secrets_schema_migrations (
        version integer PRIMARY KEY,
        applied_at timestamptz NOT NULL
    )`); err != nil {
		return ErrStorage
	}
	for index, migration := range []string{credentialMigration, runBindingMigration} {
		version := index + 1
		var applied bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM praetor_secrets_schema_migrations WHERE version = $1)", version).Scan(&applied); err != nil {
			return ErrStorage
		}
		if !applied {
			if _, err := tx.Exec(ctx, migration); err != nil {
				return ErrStorage
			}
			if _, err := tx.Exec(ctx, "INSERT INTO praetor_secrets_schema_migrations (version, applied_at) VALUES ($1, $2)", version, time.Now().UTC()); err != nil {
				return ErrStorage
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrStorage
	}
	return nil
}

func (b *postgresBackend) Create(ctx context.Context, idempotencyID string, digest [32]byte, metadata Metadata, record envelope.Record) (Metadata, error) {
	organizationID, idempotencyKey, ok := splitIdempotencyID(idempotencyID)
	if !ok {
		return Metadata{}, ErrInvalidInput
	}
	metadataJSON, recordJSON, err := encodeStorage(metadata, record)
	if err != nil {
		return Metadata{}, ErrStorage
	}
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Metadata{}, ErrStorage
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0) # hashtextextended($2, 1))", organizationID, idempotencyKey); err != nil {
		return Metadata{}, ErrStorage
	}
	var existingDigest, responseJSON []byte
	err = tx.QueryRow(ctx, `
            SELECT request_digest, response_metadata
            FROM credential_idempotency
			WHERE organization_id = $1 AND idempotency_key = $2`, organizationID, idempotencyKey).Scan(&existingDigest, &responseJSON)
	if err == nil {
		if !bytes.Equal(existingDigest, digest[:]) {
			return Metadata{}, ErrIdempotencyConflict
		}
		var response Metadata
		if err := json.Unmarshal(responseJSON, &response); err != nil {
			return Metadata{}, ErrStorage
		}
		if err := tx.Commit(ctx); err != nil {
			return Metadata{}, ErrStorage
		}
		return cloneMetadata(response), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, ErrStorage
	}

	if _, err := tx.Exec(ctx, `
        INSERT INTO credentials
            (id, organization_id, name, credential_type, schema_version, version, state, secret_fields, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		metadata.ID, metadata.OrganizationID, metadata.Name, metadata.CredentialType,
		metadata.SchemaVersion, metadata.Version, metadata.State, metadata.SecretFields,
		metadata.CreatedAt, metadata.UpdatedAt); err != nil {
		return Metadata{}, ErrStorage
	}
	if _, err := tx.Exec(ctx, `
        INSERT INTO credential_versions (credential_id, version, envelope, master_key_id, created_at)
        VALUES ($1, $2, $3, $4, $5)`, metadata.ID, metadata.Version, recordJSON, record.MasterKeyID, metadata.UpdatedAt); err != nil {
		return Metadata{}, ErrStorage
	}
	if _, err := tx.Exec(ctx, `
        INSERT INTO credential_idempotency
            (organization_id, idempotency_key, request_digest, response_metadata, credential_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)`,
		organizationID, idempotencyKey, digest[:], metadataJSON, metadata.ID, metadata.CreatedAt); err != nil {
		return Metadata{}, ErrStorage
	}
	if err := tx.Commit(ctx); err != nil {
		return Metadata{}, ErrStorage
	}
	return cloneMetadata(metadata), nil
}

func (b *postgresBackend) Get(ctx context.Context, organizationID, credentialID string) (Metadata, envelope.Record, error) {
	var metadata Metadata
	var recordJSON []byte
	err := b.pool.QueryRow(ctx, `
        SELECT c.id, c.organization_id, c.name, c.credential_type, c.schema_version,
               c.version, c.state, c.secret_fields, c.created_at, c.updated_at, v.envelope
        FROM credentials c
        JOIN credential_versions v ON v.credential_id = c.id AND v.version = c.version
        WHERE c.organization_id = $1 AND c.id = $2`, organizationID, credentialID).Scan(
		&metadata.ID, &metadata.OrganizationID, &metadata.Name, &metadata.CredentialType,
		&metadata.SchemaVersion, &metadata.Version, &metadata.State, &metadata.SecretFields,
		&metadata.CreatedAt, &metadata.UpdatedAt, &recordJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, envelope.Record{}, ErrNotFound
	}
	if err != nil {
		return Metadata{}, envelope.Record{}, ErrStorage
	}
	var record envelope.Record
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return Metadata{}, envelope.Record{}, ErrStorage
	}
	return metadata, record, nil
}

func (b *postgresBackend) Update(ctx context.Context, organizationID, credentialID string, expectedVersion uint64, metadata Metadata, record envelope.Record) (Metadata, error) {
	_, recordJSON, err := encodeStorage(metadata, record)
	if err != nil {
		return Metadata{}, ErrStorage
	}
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Metadata{}, ErrStorage
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `
        UPDATE credentials
        SET name = $1, version = $2, state = $3, secret_fields = $4, updated_at = $5
        WHERE id = $6 AND organization_id = $7 AND version = $8`,
		metadata.Name, metadata.Version, metadata.State, metadata.SecretFields, metadata.UpdatedAt,
		credentialID, organizationID, expectedVersion)
	if err != nil {
		return Metadata{}, ErrStorage
	}
	if result.RowsAffected() == 0 {
		var current uint64
		err := tx.QueryRow(ctx, "SELECT version FROM credentials WHERE id = $1 AND organization_id = $2", credentialID, organizationID).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) {
			return Metadata{}, ErrNotFound
		}
		if err != nil {
			return Metadata{}, ErrStorage
		}
		return Metadata{}, ErrVersionConflict
	}
	if _, err := tx.Exec(ctx, `
        INSERT INTO credential_versions (credential_id, version, envelope, master_key_id, created_at)
        VALUES ($1, $2, $3, $4, $5)`, credentialID, metadata.Version, recordJSON, record.MasterKeyID, metadata.UpdatedAt); err != nil {
		return Metadata{}, ErrStorage
	}
	if err := tx.Commit(ctx); err != nil {
		return Metadata{}, ErrStorage
	}
	return cloneMetadata(metadata), nil
}

func encodeStorage(metadata Metadata, record envelope.Record) ([]byte, []byte, error) {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, nil, err
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, nil, err
	}
	return metadataJSON, recordJSON, nil
}

func splitIdempotencyID(value string) (string, string, bool) {
	for index := range value {
		if value[index] == 0 {
			return value[:index], value[index+1:], value[:index] != "" && value[index+1:] != ""
		}
	}
	return "", "", false
}
