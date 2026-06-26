CREATE TABLE IF NOT EXISTS signer_near_public_keys (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  kind TEXT NOT NULL,
  signer_slot INTEGER,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  removed_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, user_id, public_key),
  CHECK (length(user_id) > 0),
  CHECK (length(public_key) > 0),
  CHECK (kind IN ('threshold', 'local', 'backup', 'ephemeral')),
  CHECK (signer_slot IS NULL OR signer_slot >= 1),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0),
  CHECK (removed_at_ms IS NULL OR removed_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_near_public_keys_user_idx
  ON signer_near_public_keys (
    namespace,
    org_id,
    project_id,
    env_id,
    user_id,
    signer_slot,
    created_at_ms
  );
