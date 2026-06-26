CREATE TABLE IF NOT EXISTS signer_signing_root_secret_shares (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  signing_root_id TEXT NOT NULL,
  signing_root_version TEXT NOT NULL,
  share_id INTEGER NOT NULL,
  sealed_share_b64u TEXT NOT NULL,
  storage_id TEXT,
  kek_id TEXT NOT NULL,
  envelope_version TEXT NOT NULL,
  aad_digest_b64u TEXT NOT NULL,
  ciphertext_digest_b64u TEXT NOT NULL,
  rotation_state TEXT NOT NULL,
  rotated_from_kek_id TEXT,
  rotated_at_ms INTEGER,
  retired_at_ms INTEGER,
  last_audit_event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    signing_root_id,
    signing_root_version,
    share_id
  ),
  CHECK (share_id IN (1, 2, 3)),
  CHECK (length(sealed_share_b64u) > 0),
  CHECK (length(kek_id) > 0),
  CHECK (length(envelope_version) > 0),
  CHECK (length(aad_digest_b64u) > 0),
  CHECK (length(ciphertext_digest_b64u) > 0),
  CHECK (rotation_state IN ('active', 'rotation_pending', 'rotated', 'retired')),
  CHECK (length(last_audit_event_id) > 0)
);

CREATE INDEX IF NOT EXISTS signer_signing_root_secret_shares_scope_idx
  ON signer_signing_root_secret_shares (
    namespace,
    org_id,
    project_id,
    env_id,
    signing_root_id,
    signing_root_version,
    share_id
  );
