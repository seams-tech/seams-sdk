CREATE TABLE IF NOT EXISTS bootstrap_tokens (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  publishable_key_id TEXT NOT NULL,
  new_account_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  allowed_paths_json TEXT NOT NULL,
  origin TEXT NOT NULL,
  request_hash_sha256 TEXT NOT NULL,
  max_uses INTEGER NOT NULL,
  used_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  risk_decision TEXT NOT NULL,
  payment_reference TEXT,
  replacement_for_token_id TEXT,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  redeemed_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (status IN ('issued', 'redeemed', 'expired', 'canceled')),
  CHECK (json_valid(allowed_paths_json)),
  CHECK (max_uses >= 1),
  CHECK (used_count >= 0),
  CHECK (used_count <= max_uses)
);

CREATE UNIQUE INDEX IF NOT EXISTS bootstrap_tokens_namespace_id_uidx
  ON bootstrap_tokens (namespace, id);

CREATE INDEX IF NOT EXISTS bootstrap_tokens_org_publishable_idx
  ON bootstrap_tokens (namespace, org_id, publishable_key_id, issued_at_ms DESC);

CREATE INDEX IF NOT EXISTS bootstrap_tokens_org_status_idx
  ON bootstrap_tokens (namespace, org_id, status, expires_at_ms);

CREATE INDEX IF NOT EXISTS bootstrap_tokens_org_prefix_idx
  ON bootstrap_tokens (namespace, org_id, token_prefix, id);
