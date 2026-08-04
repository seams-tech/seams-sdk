CREATE TABLE IF NOT EXISTS signing_worker_effect_claims (
    operation_key TEXT PRIMARY KEY,
    authorization_key TEXT NOT NULL UNIQUE,
    request_digest_hex TEXT NOT NULL,
    authorization_json TEXT NOT NULL,
    claimed_at_ms INTEGER NOT NULL
);

DROP TABLE IF EXISTS signing_worker_wallet_budgets;
