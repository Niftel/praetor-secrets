CREATE TABLE master_key_rotations (
    id uuid PRIMARY KEY,
    source_key_id text NOT NULL CHECK (source_key_id <> ''),
    target_key_id text NOT NULL CHECK (target_key_id <> ''),
    state text NOT NULL CHECK (state IN ('pending', 'running', 'ready', 'finalized')),
    total_records bigint NOT NULL CHECK (total_records >= 0),
    processed_records bigint NOT NULL CHECK (processed_records >= 0 AND processed_records <= total_records),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    finalized_at timestamptz,
    CHECK (source_key_id <> target_key_id),
    CHECK (updated_at >= created_at),
    CHECK ((state = 'finalized') = (finalized_at IS NOT NULL))
);

CREATE UNIQUE INDEX master_key_rotations_one_active_idx
ON master_key_rotations ((true))
WHERE state <> 'finalized';

REVOKE ALL ON master_key_rotations FROM PUBLIC;
