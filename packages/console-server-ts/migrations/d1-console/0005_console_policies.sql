CREATE TABLE IF NOT EXISTS policies (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'TRANSACTION',
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL,
  version INTEGER NOT NULL,
  rules_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  published_at_ms INTEGER,
  is_system_default INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP')),
  CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
  CHECK (version >= 0),
  CHECK (is_system_default IN (0, 1)),
  CHECK (json_valid(rules_json))
);

CREATE UNIQUE INDEX IF NOT EXISTS policies_namespace_id_uidx
  ON policies (namespace, id);

CREATE UNIQUE INDEX IF NOT EXISTS policies_org_system_default_uidx
  ON policies (namespace, org_id)
  WHERE is_system_default = 1;

CREATE INDEX IF NOT EXISTS policies_org_updated_idx
  ON policies (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS policies_org_status_idx
  ON policies (namespace, org_id, status);

CREATE TABLE IF NOT EXISTS policy_versions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'TRANSACTION',
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  rules_json TEXT NOT NULL,
  published_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  actor_user_id TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, policy_id, version),
  FOREIGN KEY (namespace, org_id, policy_id)
    REFERENCES policies(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP')),
  CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
  CHECK (version >= 0),
  CHECK (json_valid(rules_json))
);

CREATE INDEX IF NOT EXISTS policy_versions_org_policy_created_idx
  ON policy_versions (namespace, org_id, policy_id, created_at_ms DESC);

CREATE TABLE IF NOT EXISTS policy_assignments (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, scope_type, scope_id),
  FOREIGN KEY (namespace, org_id, policy_id)
    REFERENCES policies(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (scope_type IN ('ORG', 'PROJECT', 'ENVIRONMENT', 'WALLET'))
);

CREATE INDEX IF NOT EXISTS policy_assignments_org_updated_idx
  ON policy_assignments (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS policy_assignments_org_scope_idx
  ON policy_assignments (namespace, org_id, scope_type, scope_id);
