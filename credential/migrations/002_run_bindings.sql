CREATE TABLE run_bindings (
    run_id uuid PRIMARY KEY,
    dispatch_id uuid NOT NULL UNIQUE,
    organization_id text NOT NULL CHECK (organization_id <> ''),
    credential_id uuid NOT NULL,
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    executor_identity text NOT NULL CHECK (executor_identity LIKE 'praetor-executor:%'),
    state text NOT NULL CHECK (state IN ('pending', 'active', 'canceled', 'expired', 'exhausted')),
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    max_resolutions integer NOT NULL CHECK (max_resolutions > 0),
    resolution_count integer NOT NULL DEFAULT 0 CHECK (resolution_count >= 0 AND resolution_count <= max_resolutions),
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    cancel_reason text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (organization_id, idempotency_key),
    FOREIGN KEY (credential_id, credential_version)
        REFERENCES credential_versions(credential_id, version) ON DELETE RESTRICT,
    CHECK (expires_at > not_before),
    CHECK (updated_at >= created_at),
    CHECK ((state = 'canceled') = (cancel_reason IS NOT NULL))
);

CREATE INDEX run_bindings_credential_version_idx
    ON run_bindings (credential_id, credential_version);
CREATE INDEX run_bindings_executor_state_idx
    ON run_bindings (executor_identity, state);

CREATE TABLE resolution_attempts (
    attempt_id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES run_bindings(run_id) ON DELETE RESTRICT,
    executor_identity text NOT NULL CHECK (executor_identity LIKE 'praetor-executor:%'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX resolution_attempts_run_id_idx ON resolution_attempts (run_id);

CREATE FUNCTION prevent_run_binding_identity_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.run_id <> OLD.run_id
       OR NEW.dispatch_id <> OLD.dispatch_id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.credential_id <> OLD.credential_id
       OR NEW.credential_version <> OLD.credential_version
       OR NEW.executor_identity <> OLD.executor_identity
       OR NEW.not_before <> OLD.not_before
       OR NEW.expires_at <> OLD.expires_at
       OR NEW.max_resolutions <> OLD.max_resolutions
       OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.request_digest <> OLD.request_digest
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'run binding identity fields are immutable' USING ERRCODE = '23000';
    END IF;
    IF NEW.resolution_count < OLD.resolution_count THEN
        RAISE EXCEPTION 'resolution count is monotonic' USING ERRCODE = '23000';
    END IF;
    IF OLD.state IN ('canceled', 'expired', 'exhausted') AND NEW.state <> OLD.state THEN
        RAISE EXCEPTION 'terminal binding state is immutable' USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER run_bindings_identity_immutable
BEFORE UPDATE ON run_bindings
FOR EACH ROW EXECUTE FUNCTION prevent_run_binding_identity_change();

REVOKE ALL ON run_bindings, resolution_attempts FROM PUBLIC;
