CREATE TABLE IF NOT EXISTS user_profiles (
  namespace TEXT NOT NULL,
  user_id TEXT NOT NULL,
  display_name TEXT,
  primary_email TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, user_id)
);

CREATE TABLE IF NOT EXISTS user_backup_emails (
  namespace TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, user_id, email_normalized),
  CHECK (status IN ('PENDING', 'VERIFIED'))
);

CREATE INDEX IF NOT EXISTS org_created_by_user_idx
  ON organizations (namespace, created_by_user_id, updated_at_ms DESC, created_at_ms DESC);
