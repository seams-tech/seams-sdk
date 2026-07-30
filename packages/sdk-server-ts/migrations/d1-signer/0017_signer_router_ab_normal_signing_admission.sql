CREATE TABLE IF NOT EXISTS router_ab_normal_signing_admission_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  signing_root_version TEXT NOT NULL,
  record_kind TEXT NOT NULL,
  record_key TEXT NOT NULL,
  decision TEXT,
  retry_after_ms INTEGER,
  request_id TEXT,
  lifecycle_id TEXT,
  expires_at_ms INTEGER,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    signing_root_version,
    record_kind,
    record_key
  ),
  CHECK (record_kind IN ('project_policy', 'abuse', 'quota')),
  CHECK (updated_at_ms >= 0),
  CHECK (
    (record_kind = 'project_policy'
      AND decision IN ('allowed', 'rejected')
      AND request_id IS NULL
      AND lifecycle_id IS NULL
      AND expires_at_ms IS NULL)
    OR
    (record_kind = 'abuse'
      AND decision IN ('allowed', 'rate_limited', 'rejected')
      AND request_id IS NULL
      AND lifecycle_id IS NULL
      AND expires_at_ms IS NULL)
    OR
    (record_kind = 'quota'
      AND decision IS NULL
      AND retry_after_ms IS NULL
      AND length(request_id) > 0
      AND length(lifecycle_id) > 0
      AND expires_at_ms > updated_at_ms)
  ),
  CHECK (
    (decision IN ('rejected', 'rate_limited') AND retry_after_ms > 0)
    OR
    (decision = 'allowed' AND retry_after_ms IS NULL)
    OR
    (record_kind = 'quota' AND retry_after_ms IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_router_ab_normal_signing_admission_expiry
  ON router_ab_normal_signing_admission_records (
    namespace,
    org_id,
    project_id,
    env_id,
    record_kind,
    expires_at_ms
  );
