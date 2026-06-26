CREATE TABLE IF NOT EXISTS signer_webauthn_authenticators (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  credential_id_b64u TEXT NOT NULL,
  credential_public_key_b64u TEXT NOT NULL,
  counter INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, user_id, credential_id_b64u),
  CHECK (length(user_id) > 0),
  CHECK (length(credential_id_b64u) > 0),
  CHECK (length(credential_public_key_b64u) > 0),
  CHECK (counter >= 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_webauthn_authenticators_user_idx
  ON signer_webauthn_authenticators (
    namespace,
    org_id,
    project_id,
    env_id,
    user_id,
    created_at_ms
  );

CREATE TABLE IF NOT EXISTS signer_webauthn_credential_bindings (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  credential_id_b64u TEXT NOT NULL,
  user_id TEXT NOT NULL,
  signer_slot INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, rp_id, credential_id_b64u),
  CHECK (length(rp_id) > 0),
  CHECK (length(credential_id_b64u) > 0),
  CHECK (length(user_id) > 0),
  CHECK (signer_slot >= 1),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_webauthn_credential_bindings_user_idx
  ON signer_webauthn_credential_bindings (
    namespace,
    org_id,
    project_id,
    env_id,
    user_id,
    rp_id,
    signer_slot
  );

CREATE TABLE IF NOT EXISTS signer_webauthn_challenges (
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
  CHECK (challenge_kind IN ('login', 'sync')),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms)
);

CREATE INDEX IF NOT EXISTS signer_webauthn_challenges_expiry_idx
  ON signer_webauthn_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    challenge_kind,
    expires_at_ms
  );
