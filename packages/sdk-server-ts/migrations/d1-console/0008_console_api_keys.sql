CREATE TABLE IF NOT EXISTS console_api_keys (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  ip_allowlist_json TEXT NOT NULL,
  allowed_origins_json TEXT NOT NULL,
  rate_limit_bucket TEXT NOT NULL,
  quota_bucket TEXT NOT NULL,
  risk_policy_json TEXT NOT NULL,
  payment_policy_json TEXT NOT NULL,
  status TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  secret_version INTEGER NOT NULL,
  secret_preview TEXT NOT NULL,
  last_used_at_ms INTEGER,
  expires_at_ms INTEGER,
  revoked_reason TEXT,
  endpoint_usage_counts_json TEXT NOT NULL,
  anomaly_flags_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (kind IN ('secret_key', 'publishable_key')),
  CHECK (status IN ('ACTIVE', 'REVOKED')),
  CHECK (secret_version >= 1),
  CHECK (json_valid(scopes_json)),
  CHECK (json_valid(ip_allowlist_json)),
  CHECK (json_valid(allowed_origins_json)),
  CHECK (json_valid(risk_policy_json)),
  CHECK (json_valid(payment_policy_json)),
  CHECK (json_valid(endpoint_usage_counts_json)),
  CHECK (json_valid(anomaly_flags_json)),
  CHECK (
    (kind = 'secret_key'
      AND allowed_origins_json = '[]'
      AND rate_limit_bucket = ''
      AND quota_bucket = ''
      AND risk_policy_json = '{}'
      AND payment_policy_json = '{}')
    OR
    (kind = 'publishable_key'
      AND scopes_json = '[]'
      AND ip_allowlist_json = '[]')
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS console_api_keys_namespace_id_uidx
  ON console_api_keys (namespace, id);

CREATE INDEX IF NOT EXISTS console_api_keys_org_updated_idx
  ON console_api_keys (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS console_api_keys_org_status_idx
  ON console_api_keys (namespace, org_id, status);

CREATE UNIQUE INDEX IF NOT EXISTS console_api_keys_auth_lookup_uidx
  ON console_api_keys (namespace, kind, key_prefix, secret_hash);
