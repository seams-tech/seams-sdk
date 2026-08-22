CREATE TABLE signing_worker_activations (
    material_key TEXT PRIMARY KEY,
    active_key TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    active_state_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE signing_worker_activation_revocation_fences (
    active_key TEXT PRIMARY KEY
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

CREATE TABLE signing_worker_effect_claims (
    operation_key TEXT PRIMARY KEY,
    authorization_key TEXT NOT NULL UNIQUE,
    request_digest_hex TEXT NOT NULL,
    authorization_json TEXT NOT NULL,
    claimed_at_ms INTEGER NOT NULL
);

CREATE TABLE signing_worker_secret_states (
    purpose TEXT NOT NULL,
    record_key TEXT NOT NULL,
    ciphertext_json TEXT NOT NULL,
    version INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (purpose, record_key)
);

CREATE TABLE signing_worker_lane_material (
    operation_key TEXT PRIMARY KEY,
    activation_id TEXT NOT NULL UNIQUE,
    wallet_key_id TEXT NOT NULL,
    target_lane_id TEXT NOT NULL,
    target_lane_share_epoch TEXT NOT NULL,
    identity_digest_b64u TEXT NOT NULL,
    record_json TEXT NOT NULL,
    version INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE (wallet_key_id, target_lane_id, target_lane_share_epoch)
);
