CREATE TABLE tenant_root_command_replays (
    replay_key_digest_hex TEXT PRIMARY KEY CHECK (
        length(replay_key_digest_hex) = 64
        AND replay_key_digest_hex NOT GLOB '*[^0-9a-f]*'
    ),
    tenant_identity_digest_hex TEXT NOT NULL CHECK (
        length(tenant_identity_digest_hex) = 64
        AND tenant_identity_digest_hex NOT GLOB '*[^0-9a-f]*'
    ),
    custody_lineage_b64u TEXT NOT NULL CHECK (length(custody_lineage_b64u) = 22),
    session_id_hex TEXT NOT NULL CHECK (
        length(session_id_hex) = 32
        AND session_id_hex NOT GLOB '*[^0-9a-f]*'
    ),
    nonce_hex TEXT NOT NULL CHECK (
        length(nonce_hex) = 64
        AND nonce_hex NOT GLOB '*[^0-9a-f]*'
    ),
    role TEXT NOT NULL CHECK (role = 'deriver_b'),
    command_digest_hex TEXT NOT NULL CHECK (
        length(command_digest_hex) = 64
        AND command_digest_hex NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('reserved', 'completed', 'failed')),
    receipt_b64u TEXT,
    receipt_digest_hex TEXT CHECK (
        receipt_digest_hex IS NULL OR (
            length(receipt_digest_hex) = 64
            AND receipt_digest_hex NOT GLOB '*[^0-9a-f]*'
        )
    ),
    reserved_at_ms INTEGER NOT NULL CHECK (reserved_at_ms > 0),
    terminal_at_ms INTEGER,
    CHECK (
        (status = 'reserved' AND receipt_b64u IS NULL
            AND receipt_digest_hex IS NULL AND terminal_at_ms IS NULL)
        OR
        (status IN ('completed', 'failed') AND length(receipt_b64u) > 0
            AND receipt_digest_hex IS NOT NULL
            AND terminal_at_ms >= reserved_at_ms)
    )
);

CREATE INDEX tenant_root_command_replays_tenant_status
    ON tenant_root_command_replays (
        tenant_identity_digest_hex,
        custody_lineage_b64u,
        role,
        status
    );
