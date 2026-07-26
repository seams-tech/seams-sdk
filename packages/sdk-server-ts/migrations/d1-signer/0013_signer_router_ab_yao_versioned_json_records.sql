CREATE TABLE IF NOT EXISTS router_ab_yao_versioned_json_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  record_key TEXT NOT NULL,
  version INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  updated_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  PRIMARY KEY (namespace, org_id, project_id, env_id, record_key),
  CHECK (version > 0),
  CHECK (json_valid(record_json))
);

CREATE INDEX IF NOT EXISTS idx_router_ab_yao_versioned_json_records_updated
  ON router_ab_yao_versioned_json_records (
    namespace,
    org_id,
    project_id,
    env_id,
    updated_at_ms
  );

CREATE TABLE IF NOT EXISTS router_ab_yao_versioned_json_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);

INSERT OR IGNORE INTO router_ab_yao_versioned_json_cas_guard (guard_id) VALUES (1);

CREATE TRIGGER IF NOT EXISTS router_ab_yao_versioned_json_cas_guard_no_delete
BEFORE DELETE ON router_ab_yao_versioned_json_cas_guard
BEGIN
  SELECT RAISE(ABORT, 'router_ab_yao_versioned_json_cas_guard is immutable');
END;
