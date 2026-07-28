CREATE TABLE yao_pair_sessions (
    session_hex TEXT PRIMARY KEY,
    pair_digest_hex TEXT NOT NULL,
    lifecycle TEXT NOT NULL CHECK (
        lifecycle IN ('prepared', 'running', 'completed', 'burned', 'expired')
    ),
    ciphertext_json TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    expires_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE INDEX yao_pair_sessions_expiry
    ON yao_pair_sessions (lifecycle, expires_at_ms);
