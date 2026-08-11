-- R103 owner source handoff. Target-ready jobs stay public protocol records;
-- prepared deliveries retain only the encrypted holder package and receipts.
CREATE TABLE IF NOT EXISTS linked_device_source_handoffs (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  target_ready_json TEXT NOT NULL,
  target_ready_digest_b64u TEXT NOT NULL,
  manifest_digest_b64u TEXT NOT NULL,
  deliveries_json TEXT,
  deliveries_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(target_ready_digest_b64u) > 0),
  CHECK (length(manifest_digest_b64u) > 0),
  CHECK (json_valid(target_ready_json)),
  CHECK (
    (deliveries_json IS NULL AND deliveries_digest_b64u IS NULL)
    OR
    (deliveries_json IS NOT NULL AND json_valid(deliveries_json) AND length(deliveries_digest_b64u) > 0)
  )
);
