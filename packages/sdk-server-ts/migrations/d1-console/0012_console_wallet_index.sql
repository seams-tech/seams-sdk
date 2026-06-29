CREATE TABLE IF NOT EXISTS wallet_index (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  external_ref_id TEXT NOT NULL,
  address TEXT NOT NULL,
  chain TEXT NOT NULL,
  wallet_type TEXT NOT NULL,
  status TEXT NOT NULL,
  policy_id TEXT,
  balance_minor INTEGER NOT NULL,
  last_activity_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, address),
  CHECK (chain IN ('Ethereum', 'Base', 'Tempo', 'Arc Circle', 'NEAR')),
  CHECK (wallet_type IN ('EOA', 'SMART')),
  CHECK (status IN ('ACTIVE', 'FROZEN', 'ARCHIVED'))
);

CREATE INDEX IF NOT EXISTS wallet_index_org_created_idx
  ON wallet_index (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS wallet_index_org_project_env_idx
  ON wallet_index (namespace, org_id, project_id, environment_id);

CREATE INDEX IF NOT EXISTS wallet_index_org_status_type_chain_idx
  ON wallet_index (namespace, org_id, status, wallet_type, chain);

CREATE INDEX IF NOT EXISTS wallet_index_org_balance_idx
  ON wallet_index (namespace, org_id, balance_minor DESC, id DESC);

CREATE INDEX IF NOT EXISTS wallet_index_org_last_activity_idx
  ON wallet_index (namespace, org_id, COALESCE(last_activity_at_ms, 0) DESC, id DESC);

CREATE INDEX IF NOT EXISTS wallet_index_org_user_idx
  ON wallet_index (namespace, org_id, user_id);

CREATE INDEX IF NOT EXISTS wallet_index_org_external_ref_idx
  ON wallet_index (namespace, org_id, external_ref_id);
