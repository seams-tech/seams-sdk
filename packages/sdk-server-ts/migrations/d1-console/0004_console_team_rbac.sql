CREATE TABLE IF NOT EXISTS console_team_members (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  display_name TEXT,
  status TEXT NOT NULL,
  roles_json TEXT NOT NULL,
  invited_by_user_id TEXT NOT NULL,
  invited_at_ms INTEGER NOT NULL,
  last_status_changed_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, id),
  CHECK (status IN ('INVITED', 'ACTIVE', 'SUSPENDED', 'REMOVED')),
  CHECK (json_valid(roles_json))
);

CREATE UNIQUE INDEX IF NOT EXISTS console_team_members_org_email_uidx
  ON console_team_members (namespace, org_id, email_normalized);

CREATE UNIQUE INDEX IF NOT EXISTS console_team_members_org_user_uidx
  ON console_team_members (namespace, org_id, user_id);

CREATE INDEX IF NOT EXISTS console_team_members_org_updated_idx
  ON console_team_members (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS console_team_members_org_status_idx
  ON console_team_members (namespace, org_id, status);
