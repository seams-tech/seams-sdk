CREATE TABLE IF NOT EXISTS key_exports (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  wallet_id TEXT,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL,
  required_approvals INTEGER NOT NULL,
  approvals_json TEXT NOT NULL,
  constraints_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (mode IN ('DISABLED', 'APPROVAL_REQUIRED', 'ALLOWED_WITH_CONSTRAINTS')),
  CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXECUTED', 'CANCELED')),
  CHECK (required_approvals > 0),
  CHECK (json_valid(approvals_json)),
  CHECK (json_valid(constraints_json))
);

CREATE INDEX IF NOT EXISTS key_exports_org_updated_idx
  ON key_exports (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS key_exports_org_status_idx
  ON key_exports (namespace, org_id, status, updated_at_ms DESC);

CREATE INDEX IF NOT EXISTS key_exports_org_environment_idx
  ON key_exports (namespace, org_id, environment_id, updated_at_ms DESC);
