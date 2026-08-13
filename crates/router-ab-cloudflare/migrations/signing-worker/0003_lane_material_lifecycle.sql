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
