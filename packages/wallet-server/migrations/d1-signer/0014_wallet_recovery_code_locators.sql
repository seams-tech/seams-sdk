CREATE TABLE wallet_recovery_code_locators (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  locator_b64u TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  recovery_key_id TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, locator_b64u),
  UNIQUE (namespace, org_id, project_id, env_id, wallet_id, recovery_key_id),
  CHECK (length(locator_b64u) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(recovery_key_id) > 0)
);

CREATE INDEX idx_wallet_recovery_code_locators_wallet
  ON wallet_recovery_code_locators (
    namespace, org_id, project_id, env_id, wallet_id
  );
