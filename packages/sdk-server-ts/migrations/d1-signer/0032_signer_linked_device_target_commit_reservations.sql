-- R103 target-credential commit fence. The reservation is written before any
-- external R102 admission or protocol effect so concurrent credential POSTs
-- cannot duplicate a target commit.
CREATE TABLE IF NOT EXISTS linked_device_target_commit_reservations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  registration_digest_b64u TEXT NOT NULL,
  state TEXT NOT NULL,
  reserved_at_ms INTEGER NOT NULL,
  committed_at_ms INTEGER,
  key_manifest_digest_b64u TEXT,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(registration_digest_b64u) > 0),
  CHECK (state IN ('reserved', 'committed')),
  CHECK (
    (state = 'reserved' AND committed_at_ms IS NULL AND key_manifest_digest_b64u IS NULL)
    OR
    (state = 'committed' AND committed_at_ms IS NOT NULL AND length(key_manifest_digest_b64u) > 0)
  )
);
