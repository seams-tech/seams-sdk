CREATE TABLE IF NOT EXISTS signer_recovery_sessions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  near_account_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, session_id),
  CHECK (length(session_id) > 0),
  CHECK (length(near_account_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (expires_at_ms > 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_recovery_sessions_near_account_idx
  ON signer_recovery_sessions (
    namespace,
    org_id,
    project_id,
    env_id,
    near_account_id,
    updated_at_ms DESC
  );

CREATE INDEX IF NOT EXISTS signer_recovery_sessions_expiry_idx
  ON signer_recovery_sessions (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE IF NOT EXISTS signer_recovery_executions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  chain_id_key TEXT NOT NULL,
  account_address TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    session_id,
    chain_id_key,
    account_address,
    action
  ),
  CHECK (length(session_id) > 0),
  CHECK (length(chain_id_key) > 0),
  CHECK (length(account_address) > 0),
  CHECK (length(action) > 0),
  CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed', 'skipped')),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_recovery_executions_session_idx
  ON signer_recovery_executions (
    namespace,
    org_id,
    project_id,
    env_id,
    session_id,
    chain_id_key,
    account_address,
    action
  );

CREATE INDEX IF NOT EXISTS signer_recovery_executions_status_idx
  ON signer_recovery_executions (
    namespace,
    org_id,
    project_id,
    env_id,
    status,
    action,
    updated_at_ms
  );
