CREATE TABLE IF NOT EXISTS vault_proxy_secrets (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  destination TEXT NOT NULL,
  sealed_secret_b64u TEXT NOT NULL,
  nonce_b64u TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, vault_id, item_id),
  CHECK (length(destination) > 0),
  CHECK (length(sealed_secret_b64u) > 0),
  CHECK (length(nonce_b64u) > 0),
  CHECK (created_at_ms > 0)
);
