CREATE TABLE IF NOT EXISTS approvals (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL,
  required_approvals INTEGER NOT NULL,
  require_mfa INTEGER NOT NULL,
  project_id TEXT,
  environment_id TEXT,
  resource_type TEXT,
  resource_id TEXT,
  metadata_json TEXT NOT NULL,
  decisions_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  resolved_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (operation_type IN ('POLICY_PUBLISH', 'KEY_EXPORT')),
  CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELED')),
  CHECK (required_approvals > 0),
  CHECK (require_mfa IN (0, 1)),
  CHECK (json_valid(metadata_json)),
  CHECK (json_valid(decisions_json))
);

CREATE INDEX IF NOT EXISTS approvals_org_updated_idx
  ON approvals (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS approvals_org_status_idx
  ON approvals (namespace, org_id, status, updated_at_ms DESC);

CREATE INDEX IF NOT EXISTS approvals_org_operation_idx
  ON approvals (namespace, org_id, operation_type, updated_at_ms DESC);
