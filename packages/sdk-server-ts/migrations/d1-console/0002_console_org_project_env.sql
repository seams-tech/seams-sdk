CREATE TABLE IF NOT EXISTS organizations (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  created_by_user_id TEXT,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, id),
  CHECK (status IN ('ACTIVE'))
);

CREATE TABLE IF NOT EXISTS projects (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, id),
  CHECK (status IN ('ACTIVE', 'ARCHIVED')),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS projects_org_updated_idx
  ON projects (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE UNIQUE INDEX IF NOT EXISTS projects_namespace_id_org_unique_idx
  ON projects (namespace, id, org_id);

CREATE TABLE IF NOT EXISTS environments (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_key TEXT NOT NULL,
  signing_root_version TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, id),
  CHECK (status IN ('ACTIVE', 'DISABLED', 'ARCHIVED')),
  CHECK (env_key IN ('dev', 'staging', 'prod')),
  UNIQUE (namespace, project_id, env_key),
  FOREIGN KEY (namespace, project_id, org_id)
    REFERENCES projects(namespace, id, org_id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS environments_org_project_updated_idx
  ON environments (namespace, org_id, project_id, updated_at_ms DESC, created_at_ms DESC);

CREATE UNIQUE INDEX IF NOT EXISTS environments_namespace_id_project_org_unique_idx
  ON environments (namespace, id, project_id, org_id);
