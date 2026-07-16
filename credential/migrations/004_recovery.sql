CREATE TABLE backup_sets (
    id text PRIMARY KEY CHECK (id <> ''),
    artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    key_ids text[] NOT NULL CHECK (cardinality(key_ids) > 0),
    created_at timestamptz NOT NULL,
    retain_until timestamptz NOT NULL CHECK (retain_until >= created_at),
    expired_at timestamptz,
    CHECK (expired_at IS NULL OR expired_at >= created_at)
);

CREATE INDEX backup_sets_key_ids_idx ON backup_sets USING gin (key_ids);
REVOKE ALL ON backup_sets FROM PUBLIC;
