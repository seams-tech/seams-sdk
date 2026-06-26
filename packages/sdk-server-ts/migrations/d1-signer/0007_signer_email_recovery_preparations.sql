CREATE TABLE IF NOT EXISTS signer_email_recovery_preparations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, request_id),
  CHECK (length(request_id) > 0),
  CHECK (length(account_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(rp_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms)
);

CREATE INDEX IF NOT EXISTS signer_email_recovery_preparations_expires_idx
  ON signer_email_recovery_preparations (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE INDEX IF NOT EXISTS signer_email_recovery_preparations_account_idx
  ON signer_email_recovery_preparations (
    namespace,
    org_id,
    project_id,
    env_id,
    account_id,
    created_at_ms
  );
