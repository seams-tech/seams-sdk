-- R103 authenticated target deployment descriptor allocation ledger.
-- One row is the replay fence for one target child and credential registration.
CREATE TABLE IF NOT EXISTS linked_device_target_deployment_descriptors (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  target_preparation_digest_b64u TEXT NOT NULL,
  registration_digest_b64u TEXT NOT NULL,
  child_index INTEGER NOT NULL,
  request_digest_b64u TEXT NOT NULL,
  descriptor_digest_b64u TEXT NOT NULL,
  descriptor_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    link_session_id,
    target_preparation_digest_b64u,
    registration_digest_b64u,
    child_index
  ),
  CHECK (length(target_preparation_digest_b64u) > 0),
  CHECK (length(registration_digest_b64u) > 0),
  CHECK (child_index >= 0),
  CHECK (length(request_digest_b64u) > 0),
  CHECK (length(descriptor_digest_b64u) > 0),
  CHECK (json_valid(descriptor_json)),
  CHECK (issued_at_ms > 0 AND expires_at_ms > issued_at_ms)
);

CREATE INDEX IF NOT EXISTS linked_device_target_deployment_descriptors_wallet_idx
  ON linked_device_target_deployment_descriptors(
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
