CREATE TABLE IF NOT EXISTS signer_email_otp_rate_limits (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  rate_key TEXT NOT NULL,
  consumed_count INTEGER NOT NULL,
  reset_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, rate_key),
  CHECK (length(rate_key) > 0),
  CHECK (consumed_count > 0),
  CHECK (reset_at_ms > 0),
  CHECK (updated_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_email_otp_rate_limits_reset_idx
  ON signer_email_otp_rate_limits (
    namespace,
    org_id,
    project_id,
    env_id,
    reset_at_ms
  );
