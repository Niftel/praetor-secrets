CREATE TABLE credentials (
    id uuid PRIMARY KEY,
    organization_id text NOT NULL CHECK (organization_id <> ''),
    name text NOT NULL CHECK (name <> ''),
    credential_type text NOT NULL CHECK (credential_type <> ''),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    version bigint NOT NULL CHECK (version > 0),
    state text NOT NULL CHECK (state IN ('active', 'retired')),
    secret_fields text[] NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at)
);

CREATE INDEX credentials_organization_id_idx ON credentials (organization_id, id);

CREATE TABLE credential_versions (
    credential_id uuid NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
    version bigint NOT NULL CHECK (version > 0),
    envelope jsonb NOT NULL,
    master_key_id text NOT NULL CHECK (master_key_id <> ''),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (credential_id, version),
    CHECK (jsonb_typeof(envelope) = 'object')
);

CREATE INDEX credential_versions_master_key_id_idx ON credential_versions (master_key_id);

CREATE TABLE credential_idempotency (
    organization_id text NOT NULL CHECK (organization_id <> ''),
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_metadata jsonb NOT NULL,
    credential_id uuid NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, idempotency_key),
    CHECK (jsonb_typeof(response_metadata) = 'object')
);

CREATE FUNCTION prevent_credential_identity_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.credential_type <> OLD.credential_type
       OR NEW.schema_version <> OLD.schema_version
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'credential identity fields are immutable' USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER credentials_identity_immutable
BEFORE UPDATE ON credentials
FOR EACH ROW EXECUTE FUNCTION prevent_credential_identity_change();

REVOKE ALL ON credentials, credential_versions, credential_idempotency FROM PUBLIC;
