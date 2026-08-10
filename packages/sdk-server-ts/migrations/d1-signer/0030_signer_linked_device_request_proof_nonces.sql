-- R103 one-use signed request proofs. This table intentionally has no foreign
-- key to linked_device_sessions because public create consumes its nonce before
-- the unclaimed session row is inserted.
CREATE TABLE IF NOT EXISTS linked_device_request_proof_nonces (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  request_nonce_b64u TEXT NOT NULL,
  proof_digest_b64u TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    link_session_id,
    request_nonce_b64u
  ),
  CHECK (length(link_session_id) > 0),
  CHECK (length(request_nonce_b64u) > 0),
  CHECK (length(proof_digest_b64u) > 0),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (consumed_at_ms >= issued_at_ms),
  CHECK (consumed_at_ms < expires_at_ms)
);

CREATE INDEX IF NOT EXISTS linked_device_request_proof_nonces_expiry_idx
  ON linked_device_request_proof_nonces(
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
