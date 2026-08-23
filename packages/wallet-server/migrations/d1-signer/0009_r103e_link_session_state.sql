-- R103E link-session lifecycle and committed-authority identity.
--
-- R103E uses the repository's reset/new-environment policy. This migration
-- rebuilds the empty session table created by the historical schema; it does
-- not copy rows whose lifecycle facts belong to the retired contract.

PRAGMA defer_foreign_keys = ON;

DROP INDEX IF EXISTS linked_device_sessions_state_idx;

CREATE TABLE linked_device_sessions_next (
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
  authority_id TEXT,
  package_set_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(link_session_id) > 0),
  CHECK (length(link_public_key_b64u) > 0),
  CHECK (length(device_public_key_b64u) > 0),
  CHECK (
    state IN (
      'displaying_qr',
      'claimed',
      'awaiting_target_factor',
      'awaiting_source_contribution',
      'provisioning',
      'authority_pending_local_install',
      'active',
      'failed_before_commit',
      'cancelled',
      'expired'
    )
  ),
  CHECK (json_valid(record_json)),
  CHECK (json_extract(record_json, '$.state.state') = state),
  CHECK (revision > 0),
  CHECK (expires_at_ms > 0),
  CHECK (claim_expires_at_ms IS NULL OR claim_expires_at_ms > 0),
  CHECK (claim_digest_b64u IS NULL OR length(claim_digest_b64u) > 0),
  CHECK (approval_digest_b64u IS NULL OR length(approval_digest_b64u) > 0),
  CHECK (
    (
      state IN ('authority_pending_local_install', 'active')
      AND authority_id IS NOT NULL
      AND length(authority_id) > 0
      AND package_set_digest_b64u IS NOT NULL
      AND length(package_set_digest_b64u) > 0
      AND json_extract(record_json, '$.authorityId') = authority_id
      AND json_extract(record_json, '$.packageSetDigestB64u') = package_set_digest_b64u
    )
    OR
    (
      state NOT IN ('authority_pending_local_install', 'active')
      AND authority_id IS NULL
      AND package_set_digest_b64u IS NULL
      AND json_extract(record_json, '$.authorityId') IS NULL
      AND json_extract(record_json, '$.packageSetDigestB64u') IS NULL
    )
  ),
  CHECK (created_at_ms > 0 AND updated_at_ms >= created_at_ms)
);

DROP TABLE linked_device_sessions;
ALTER TABLE linked_device_sessions_next RENAME TO linked_device_sessions;

CREATE INDEX linked_device_sessions_state_idx
  ON linked_device_sessions(namespace, org_id, project_id, env_id, state, updated_at_ms);

PRAGMA defer_foreign_keys = OFF;
