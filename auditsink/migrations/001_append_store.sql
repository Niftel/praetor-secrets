CREATE TABLE remote_audit_stream_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    last_mac bytea NOT NULL CHECK (octet_length(last_mac) IN (0, 32)),
    updated_at timestamptz NOT NULL
);

INSERT INTO remote_audit_stream_head(singleton, last_sequence, last_mac, updated_at)
VALUES (true, 0, ''::bytea, now());

CREATE TABLE remote_audit_records (
    sequence bigint PRIMARY KEY CHECK (sequence > 0),
    event jsonb NOT NULL,
    mac bytea NOT NULL UNIQUE CHECK (octet_length(mac) = 32),
    idempotency_key text NOT NULL UNIQUE CHECK (idempotency_key ~ '^audit-[0-9a-f]{64}$'),
    workload_identity text NOT NULL CHECK (workload_identity = 'praetor-secrets'),
    received_at timestamptz NOT NULL
);

CREATE FUNCTION reject_remote_audit_record_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'remote audit records are append-only' USING ERRCODE = '23000';
END;
$$;

CREATE TRIGGER remote_audit_records_no_update_or_delete
BEFORE UPDATE OR DELETE ON remote_audit_records
FOR EACH ROW EXECUTE FUNCTION reject_remote_audit_record_mutation();

CREATE TRIGGER remote_audit_records_no_truncate
BEFORE TRUNCATE ON remote_audit_records
FOR EACH STATEMENT EXECUTE FUNCTION reject_remote_audit_record_mutation();

CREATE FUNCTION prevent_remote_audit_head_rewind() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.last_sequence <> OLD.last_sequence + 1
       OR octet_length(NEW.last_mac) <> 32
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'remote audit stream head must advance exactly once' USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER remote_audit_stream_head_monotonic
BEFORE UPDATE ON remote_audit_stream_head
FOR EACH ROW EXECUTE FUNCTION prevent_remote_audit_head_rewind();

CREATE TRIGGER remote_audit_stream_head_no_delete
BEFORE DELETE OR TRUNCATE ON remote_audit_stream_head
FOR EACH STATEMENT EXECUTE FUNCTION reject_remote_audit_record_mutation();
