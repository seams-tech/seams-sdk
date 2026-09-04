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
    role TEXT NOT NULL CHECK (role = 'deriver_a'),
    command_digest_hex TEXT NOT NULL CHECK (
        length(command_digest_hex) = 64
        AND command_digest_hex NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('reserved', 'executed', 'completed', 'failed')),
    receipt_b64u TEXT,
    receipt_digest_hex TEXT CHECK (
        receipt_digest_hex IS NULL OR (
            length(receipt_digest_hex) = 64
            AND receipt_digest_hex NOT GLOB '*[^0-9a-f]*'
        )
    ),
    reserved_at_ms INTEGER NOT NULL CHECK (reserved_at_ms > 0),
    executed_at_ms INTEGER,
    terminal_at_ms INTEGER,
    CHECK (
        (status = 'reserved' AND receipt_b64u IS NULL
            AND receipt_digest_hex IS NULL AND executed_at_ms IS NULL
            AND terminal_at_ms IS NULL)
        OR (status = 'executed' AND receipt_b64u IS NULL
            AND receipt_digest_hex IS NULL AND executed_at_ms IS NOT NULL
            AND executed_at_ms >= reserved_at_ms
            AND terminal_at_ms IS NULL)
        OR (status = 'completed' AND receipt_b64u IS NOT NULL
            AND length(receipt_b64u) > 0
            AND receipt_digest_hex IS NOT NULL
            AND executed_at_ms IS NOT NULL
            AND executed_at_ms >= reserved_at_ms
            AND terminal_at_ms IS NOT NULL
            AND terminal_at_ms >= executed_at_ms)
        OR (status = 'failed' AND receipt_b64u IS NOT NULL
            AND length(receipt_b64u) > 0
            AND receipt_digest_hex IS NOT NULL AND executed_at_ms IS NULL
            AND terminal_at_ms IS NOT NULL
            AND terminal_at_ms >= reserved_at_ms)
    )
);

CREATE TABLE tenant_root_command_cas_guard (
    guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);

INSERT INTO tenant_root_command_cas_guard (guard_id) VALUES (1);

CREATE TRIGGER tenant_root_command_cas_guard_immutable
BEFORE DELETE ON tenant_root_command_cas_guard
BEGIN
    SELECT RAISE(ABORT, 'tenant_root_command_cas_guard is immutable');
END;

CREATE INDEX tenant_root_command_replays_tenant_status
    ON tenant_root_command_replays (
        tenant_identity_digest_hex,
        custody_lineage_b64u,
        role,
        status
    );
