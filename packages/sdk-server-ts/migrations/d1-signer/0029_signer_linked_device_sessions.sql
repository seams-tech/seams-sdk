-- R103 durable linked-device session and owner-approval ledger.
-- The session row contains public bootstrap material and lifecycle projections.
-- Claim and approval transcripts are immutable append-once facts; no secret,
-- wallet session token, root, share, or recovery material is persisted here.
CREATE TABLE IF NOT EXISTS linked_device_sessions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  link_public_key_b64u TEXT NOT NULL,
  device_public_key_b64u TEXT NOT NULL,
  state TEXT NOT NULL,
  record_json TEXT NOT NULL,
  revision INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  claim_expires_at_ms INTEGER,
  claim_digest_b64u TEXT,
  approval_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(link_session_id) > 0),
  CHECK (length(link_public_key_b64u) > 0),
  CHECK (length(device_public_key_b64u) > 0),
  CHECK (state IN (
    'displaying_qr',
    'claimed_by_owner',
    'awaiting_target_passkey',
    'provisioning',
    'active',
    'expired_unclaimed',
    'expired_claimed',
    'cancelled_unclaimed',
    'cancelled_claimed_precommit',
    'committed_completion_required'
  )),
  CHECK (json_valid(record_json)),
  CHECK (revision > 0),
  CHECK (expires_at_ms > 0),
  CHECK (claim_expires_at_ms IS NULL OR claim_expires_at_ms > 0),
  CHECK (claim_digest_b64u IS NULL OR length(claim_digest_b64u) > 0),
  CHECK (approval_digest_b64u IS NULL OR length(approval_digest_b64u) > 0),
  CHECK (created_at_ms > 0 AND updated_at_ms >= created_at_ms)
);

CREATE INDEX IF NOT EXISTS linked_device_sessions_state_idx
  ON linked_device_sessions(namespace, org_id, project_id, env_id, state, updated_at_ms);

CREATE TABLE IF NOT EXISTS linked_device_session_transcripts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  transcript_kind TEXT NOT NULL,
  digest_b64u TEXT NOT NULL,
  transcript_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    link_session_id,
    transcript_kind
  ),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (transcript_kind IN ('claim', 'approval')),
  CHECK (length(digest_b64u) > 0),
  CHECK (json_valid(transcript_json)),
  CHECK (created_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS linked_device_session_transcripts_digest_idx
  ON linked_device_session_transcripts(
    namespace,
    org_id,
    project_id,
    env_id,
    digest_b64u
  );
