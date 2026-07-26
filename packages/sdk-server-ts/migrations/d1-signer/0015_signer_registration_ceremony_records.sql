CREATE TABLE IF NOT EXISTS registration_ceremony_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  record_scope TEXT NOT NULL,
  record_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  updated_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  PRIMARY KEY (namespace, org_id, project_id, env_id, record_scope, record_id),
  CHECK (version > 0),
  CHECK (expires_at_ms > 0),
  CHECK (json_valid(record_json))
);

CREATE INDEX IF NOT EXISTS idx_registration_ceremony_records_expiry
  ON registration_ceremony_records (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE IF NOT EXISTS registration_ceremony_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);

INSERT OR IGNORE INTO registration_ceremony_cas_guard (guard_id) VALUES (1);

CREATE TRIGGER IF NOT EXISTS registration_ceremony_cas_guard_no_delete
BEFORE DELETE ON registration_ceremony_cas_guard
BEGIN
  SELECT RAISE(ABORT, 'registration_ceremony_cas_guard is immutable');
END;
