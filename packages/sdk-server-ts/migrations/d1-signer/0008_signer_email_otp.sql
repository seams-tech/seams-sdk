CREATE TABLE IF NOT EXISTS signer_email_otp_challenges (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  challenge_subject_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  record_org_id TEXT NOT NULL,
  otp_channel TEXT NOT NULL,
  session_hash TEXT NOT NULL,
  app_session_version TEXT NOT NULL,
  action TEXT NOT NULL,
  operation TEXT NOT NULL,
  otp_code TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
  CHECK (length(challenge_id) > 0),
  CHECK (length(challenge_subject_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (otp_channel = 'email_otp'),
  CHECK (length(session_hash) > 0),
  CHECK (length(app_session_version) > 0),
  CHECK (length(action) > 0),
  CHECK (length(operation) > 0),
  CHECK (length(otp_code) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms)
);

CREATE INDEX IF NOT EXISTS signer_email_otp_challenges_context_idx
  ON signer_email_otp_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    challenge_subject_id,
    wallet_id,
    record_org_id,
    otp_channel,
    session_hash,
    app_session_version,
    action,
    operation,
    expires_at_ms
  );

CREATE INDEX IF NOT EXISTS signer_email_otp_challenges_expires_idx
  ON signer_email_otp_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE IF NOT EXISTS signer_email_otp_grants (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  grant_token TEXT NOT NULL,
  user_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  record_org_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  action TEXT NOT NULL,
  record_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, grant_token),
  CHECK (length(grant_token) > 0),
  CHECK (length(user_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(challenge_id) > 0),
  CHECK (length(action) > 0),
  CHECK (json_valid(record_json)),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms)
);

CREATE INDEX IF NOT EXISTS signer_email_otp_grants_expires_idx
  ON signer_email_otp_grants (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE IF NOT EXISTS signer_email_otp_wallet_enrollments (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  record_org_id TEXT NOT NULL,
  verified_email TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id),
  UNIQUE (namespace, org_id, project_id, env_id, record_org_id, provider_user_id),
  CHECK (length(wallet_id) > 0),
  CHECK (length(provider_user_id) > 0),
  CHECK (length(record_org_id) > 0),
  CHECK (length(verified_email) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_email_otp_wallet_enrollments_provider_idx
  ON signer_email_otp_wallet_enrollments (
    namespace,
    org_id,
    project_id,
    env_id,
    record_org_id,
    provider_user_id,
    updated_at_ms
  );

CREATE TABLE IF NOT EXISTS signer_email_otp_recovery_wrapped_enrollment_escrows (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  recovery_key_id TEXT NOT NULL,
  recovery_key_status TEXT NOT NULL,
  record_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id, recovery_key_id),
  CHECK (length(wallet_id) > 0),
  CHECK (length(recovery_key_id) > 0),
  CHECK (recovery_key_status IN ('active', 'consumed', 'revoked')),
  CHECK (json_valid(record_json)),
  CHECK (issued_at_ms > 0),
  CHECK (updated_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_email_otp_recovery_wrapped_escrows_wallet_idx
  ON signer_email_otp_recovery_wrapped_enrollment_escrows (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    recovery_key_status,
    updated_at_ms
  );

CREATE TABLE IF NOT EXISTS signer_email_otp_auth_states (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  record_org_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id),
  CHECK (length(wallet_id) > 0),
  CHECK (length(provider_user_id) > 0),
  CHECK (length(record_org_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0)
);

CREATE TABLE IF NOT EXISTS signer_email_otp_unlock_challenges (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  record_org_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
  CHECK (length(challenge_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(user_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms)
);

CREATE INDEX IF NOT EXISTS signer_email_otp_unlock_challenges_expires_idx
  ON signer_email_otp_unlock_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE IF NOT EXISTS signer_email_otp_registration_attempts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  provider_subject TEXT NOT NULL,
  email TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  state TEXT NOT NULL,
  app_session_version TEXT NOT NULL,
  runtime_org_id TEXT NOT NULL,
  runtime_policy_key TEXT NOT NULL,
  offer_wallet_ids_json TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, attempt_id),
  CHECK (length(attempt_id) > 0),
  CHECK (length(provider_subject) > 0),
  CHECK (length(email) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (state IN ('started', 'key_finalized', 'active', 'abandoned', 'failed', 'expired')),
  CHECK (length(app_session_version) > 0),
  CHECK (json_valid(offer_wallet_ids_json)),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0),
  CHECK (expires_at_ms > 0)
);

CREATE INDEX IF NOT EXISTS signer_email_otp_registration_attempts_subject_idx
  ON signer_email_otp_registration_attempts (
    namespace,
    org_id,
    project_id,
    env_id,
    provider_subject,
    email,
    state,
    expires_at_ms,
    app_session_version,
    runtime_org_id,
    runtime_policy_key,
    updated_at_ms
  );

CREATE INDEX IF NOT EXISTS signer_email_otp_registration_attempts_wallet_idx
  ON signer_email_otp_registration_attempts (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    state,
    expires_at_ms
  );
