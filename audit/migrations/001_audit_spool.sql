CREATE TABLE audit_chain_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_sequence bigint NOT NULL DEFAULT 0,
    last_mac bytea NOT NULL CHECK (octet_length(last_mac) IN (0, 32))
);

INSERT INTO audit_chain_state (singleton, last_sequence, last_mac)
VALUES (true, 0, ''::bytea)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE audit_spool (
    sequence bigint PRIMARY KEY,
    event jsonb NOT NULL,
    previous_mac bytea NOT NULL CHECK (octet_length(previous_mac) IN (0, 32)),
    mac bytea NOT NULL CHECK (octet_length(mac) = 32),
    delivered_at timestamptz NULL
);

CREATE FUNCTION protect_audit_chain() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
	IF TG_OP = 'UPDATE' AND OLD.sequence = NEW.sequence AND OLD.event = NEW.event
	   AND OLD.previous_mac = NEW.previous_mac AND OLD.mac = NEW.mac
	   AND OLD.delivered_at IS NULL AND NEW.delivered_at IS NOT NULL THEN
		RETURN NEW;
	END IF;
    RAISE EXCEPTION 'audit chain rows are immutable';
END;
$$;

CREATE TRIGGER audit_spool_no_update_or_delete
BEFORE UPDATE OR DELETE ON audit_spool
FOR EACH ROW EXECUTE FUNCTION protect_audit_chain();

CREATE TRIGGER audit_spool_no_truncate
BEFORE TRUNCATE ON audit_spool
FOR EACH STATEMENT EXECUTE FUNCTION protect_audit_chain();

REVOKE ALL ON audit_spool FROM PUBLIC;
REVOKE ALL ON audit_chain_state FROM PUBLIC;
