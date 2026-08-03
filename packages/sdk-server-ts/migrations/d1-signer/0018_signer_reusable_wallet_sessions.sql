CREATE TABLE IF NOT EXISTS reusable_wallet_sessions (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  authority_digest TEXT NOT NULL,
  mint_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, wallet_session_id),
  UNIQUE (namespace, tenant_id, quota_id),
  FOREIGN KEY (namespace, tenant_id, quota_id)
    REFERENCES authorization_wallet_session_quotas(namespace, tenant_id, quota_id),
  UNIQUE (namespace, tenant_id, mint_id),
  CHECK (lifecycle_kind IN ('active', 'superseded')),
  CHECK (expires_at_ms > created_at_ms)
);

CREATE INDEX IF NOT EXISTS idx_reusable_wallet_sessions_principal
  ON reusable_wallet_sessions(namespace, tenant_id, principal_id, lifecycle_kind, expires_at_ms);

CREATE UNIQUE INDEX IF NOT EXISTS idx_reusable_wallet_sessions_active_authority
  ON reusable_wallet_sessions(namespace, tenant_id, wallet_id, authority_digest)
  WHERE lifecycle_kind = 'active';
