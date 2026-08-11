-- R103 encrypted delivery and public aggregate receipt replay records.
-- Holder packages remain ciphertext; no holder plaintext or private credential
-- material is written here.
CREATE TABLE IF NOT EXISTS linked_device_provisioning_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  manifest_digest_b64u TEXT NOT NULL,
  deliveries_json TEXT NOT NULL,
  aggregate_receipt_json TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(manifest_digest_b64u) > 0),
  CHECK (json_valid(deliveries_json)),
  CHECK (aggregate_receipt_json IS NULL OR json_valid(aggregate_receipt_json))
);
