CREATE TABLE IF NOT EXISTS wallet_ecdsa_pending_session_activations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  lifecycle_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    lifecycle_id,
    request_id
  ),
  CHECK (json_valid(record_json)),
  CHECK (expires_at_ms > 0)
);
