CREATE TABLE signing_worker_activations (
    material_key TEXT PRIMARY KEY,
    active_key TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    active_state_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE signing_worker_round1 (
    record_key TEXT PRIMARY KEY,
    record_json TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL
);

CREATE INDEX signing_worker_round1_expiry
    ON signing_worker_round1 (expires_at_ms);

CREATE TABLE signing_worker_ecdsa_pool (
    record_key TEXT PRIMARY KEY,
    record_json TEXT NOT NULL,
    version INTEGER NOT NULL,
    cleanup_deadline_ms INTEGER
);

CREATE INDEX signing_worker_ecdsa_pool_expiry
    ON signing_worker_ecdsa_pool (cleanup_deadline_ms);

CREATE TABLE signing_worker_terminal_responses (
    operation_key TEXT PRIMARY KEY,
    request_digest_hex TEXT NOT NULL,
    response_json TEXT NOT NULL,
    committed_at_ms INTEGER NOT NULL
);

CREATE TABLE signing_worker_secret_states (
    purpose TEXT NOT NULL,
    record_key TEXT NOT NULL,
    ciphertext_json TEXT NOT NULL,
    version INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (purpose, record_key)
);

CREATE TABLE signing_worker_wallet_budgets (
    signing_grant_id TEXT PRIMARY KEY,
    record_json TEXT NOT NULL,
    version INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
