-- Replace the applied pre-QR-v5 session state constraint. Existing sessions
-- used the Passkey-specific state name; the current protocol records the
-- selected target factor inside the state payload.

PRAGMA defer_foreign_keys = ON;

DROP INDEX linked_device_sessions_state_idx;

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
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(link_session_id) > 0),
  CHECK (length(link_public_key_b64u) > 0),
  CHECK (length(device_public_key_b64u) > 0),
  CHECK (state IN (
    'displaying_qr',
    'claimed_by_owner',
    'awaiting_target_factor',
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

INSERT INTO linked_device_sessions_next (
  namespace, org_id, project_id, env_id, link_session_id,
  link_public_key_b64u, device_public_key_b64u, state, record_json,
  revision, expires_at_ms, claim_expires_at_ms, claim_digest_b64u,
  approval_digest_b64u, created_at_ms, updated_at_ms
)
SELECT namespace, org_id, project_id, env_id, link_session_id,
       link_public_key_b64u, device_public_key_b64u,
       CASE state
         WHEN 'awaiting_target_passkey' THEN 'awaiting_target_factor'
         ELSE state
       END,
       CASE state
         WHEN 'awaiting_target_passkey'
           THEN json_set(record_json, '$.state.state', 'awaiting_target_factor')
         ELSE record_json
       END,
       revision, expires_at_ms, claim_expires_at_ms, claim_digest_b64u,
       approval_digest_b64u, created_at_ms, updated_at_ms
  FROM linked_device_sessions;

DROP TABLE linked_device_sessions;
ALTER TABLE linked_device_sessions_next RENAME TO linked_device_sessions;

CREATE INDEX linked_device_sessions_state_idx
  ON linked_device_sessions(namespace, org_id, project_id, env_id, state, updated_at_ms);

PRAGMA defer_foreign_keys = OFF;
