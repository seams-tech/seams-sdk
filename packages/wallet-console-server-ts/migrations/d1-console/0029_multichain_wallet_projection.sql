PRAGMA foreign_keys = OFF;

CREATE TABLE wallet_index_multichain (
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
  CHECK (chain IN ('Multichain', 'Ethereum', 'Base', 'Tempo', 'Arc Circle', 'NEAR')),
  CHECK (wallet_type IN ('EOA', 'SMART')),
  CHECK (status IN ('ACTIVE', 'FROZEN', 'ARCHIVED'))
);

INSERT INTO wallet_index_multichain (
  namespace,
  org_id,
  id,
  project_id,
  environment_id,
  user_id,
  external_ref_id,
  address,
  chain,
  wallet_type,
  status,
  policy_id,
  balance_minor,
  last_activity_at_ms,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  id,
  project_id,
  environment_id,
  user_id,
  external_ref_id,
  address,
  CASE WHEN chain = 'NEAR' THEN 'Multichain' ELSE chain END,
  wallet_type,
  status,
  policy_id,
  balance_minor,
  last_activity_at_ms,
  created_at_ms,
  updated_at_ms
FROM wallet_index;

CREATE TABLE wallet_balance_snapshots_backup (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  near_account_id TEXT NOT NULL,
  evm_address TEXT NOT NULL,
  near_balance_yocto TEXT NOT NULL,
  tempo_alpha_usd_raw TEXT NOT NULL,
  arc_balance_wei TEXT NOT NULL,
  stablecoin_balance_minor INTEGER NOT NULL,
  funded INTEGER NOT NULL,
  observed_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, wallet_id),
  CHECK (funded IN (0, 1)),
  CHECK (observed_at_ms > 0)
);

INSERT INTO wallet_balance_snapshots_backup
SELECT * FROM wallet_balance_snapshots;

DROP TABLE wallet_balance_snapshots;
DROP TABLE wallet_index;
ALTER TABLE wallet_index_multichain RENAME TO wallet_index;

CREATE TABLE wallet_balance_snapshots (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  near_account_id TEXT NOT NULL,
  evm_address TEXT NOT NULL,
  near_balance_yocto TEXT NOT NULL,
  tempo_alpha_usd_raw TEXT NOT NULL,
  arc_balance_wei TEXT NOT NULL,
  stablecoin_balance_minor INTEGER NOT NULL,
  funded INTEGER NOT NULL,
  observed_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, wallet_id),
  FOREIGN KEY (namespace, org_id, wallet_id)
    REFERENCES wallet_index(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (funded IN (0, 1)),
  CHECK (observed_at_ms > 0)
);

INSERT INTO wallet_balance_snapshots
SELECT * FROM wallet_balance_snapshots_backup;
DROP TABLE wallet_balance_snapshots_backup;

CREATE INDEX wallet_index_org_created_idx
  ON wallet_index (namespace, org_id, created_at_ms DESC, id DESC);
CREATE INDEX wallet_index_org_project_env_idx
  ON wallet_index (namespace, org_id, project_id, environment_id);
CREATE INDEX wallet_index_org_status_type_chain_idx
  ON wallet_index (namespace, org_id, status, wallet_type, chain);
CREATE INDEX wallet_index_org_balance_idx
  ON wallet_index (namespace, org_id, balance_minor DESC, id DESC);
CREATE INDEX wallet_index_org_last_activity_idx
  ON wallet_index (namespace, org_id, COALESCE(last_activity_at_ms, 0) DESC, id DESC);
CREATE INDEX wallet_index_org_user_idx
  ON wallet_index (namespace, org_id, user_id);
CREATE INDEX wallet_index_org_external_ref_idx
  ON wallet_index (namespace, org_id, external_ref_id);
CREATE INDEX wallet_balance_snapshots_stale_idx
  ON wallet_balance_snapshots (namespace, org_id, observed_at_ms);

PRAGMA foreign_keys = ON;
