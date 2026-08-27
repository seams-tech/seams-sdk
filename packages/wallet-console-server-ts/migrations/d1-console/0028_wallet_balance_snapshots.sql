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

CREATE INDEX wallet_balance_snapshots_stale_idx
  ON wallet_balance_snapshots (namespace, org_id, observed_at_ms);
