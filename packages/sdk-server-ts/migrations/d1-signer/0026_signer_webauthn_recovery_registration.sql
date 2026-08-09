-- Recovery replaces a wallet passkey through a one-shot WebAuthn create
-- challenge. Keep the challenge in the existing table so its consume is
-- atomic with the same tenant-scoped row machinery as login and sync.
-- SQLite requires rebuilding the table to change its CHECK constraint.

DROP INDEX IF EXISTS webauthn_challenges_expiry_idx;

DROP TABLE IF EXISTS webauthn_challenges_recovery_registration;

CREATE TABLE webauthn_challenges_recovery_registration (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  challenge_kind TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
  CHECK (length(challenge_id) > 0),
  CHECK (challenge_kind IN ('login', 'sync', 'recovery_registration')),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms)
);

INSERT INTO webauthn_challenges_recovery_registration (
  namespace,
  org_id,
  project_id,
  env_id,
  challenge_id,
  challenge_kind,
  record_json,
  created_at_ms,
  expires_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  challenge_id,
  challenge_kind,
  record_json,
  created_at_ms,
  expires_at_ms
FROM webauthn_challenges;

DROP TABLE webauthn_challenges;
ALTER TABLE webauthn_challenges_recovery_registration
  RENAME TO webauthn_challenges;

CREATE INDEX webauthn_challenges_expiry_idx
  ON webauthn_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    challenge_kind,
    expires_at_ms
  );
