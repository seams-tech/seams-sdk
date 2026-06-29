DROP INDEX IF EXISTS identity_links_user_idx;
DROP INDEX IF EXISTS recovery_sessions_near_account_idx;
DROP INDEX IF EXISTS recovery_sessions_expiry_idx;
DROP INDEX IF EXISTS recovery_executions_session_idx;
DROP INDEX IF EXISTS recovery_executions_status_idx;
DROP INDEX IF EXISTS email_recovery_preparations_expires_idx;
DROP INDEX IF EXISTS email_recovery_preparations_account_idx;
DROP INDEX IF EXISTS email_otp_challenges_context_idx;
DROP INDEX IF EXISTS email_otp_challenges_expires_idx;
DROP INDEX IF EXISTS email_otp_grants_expires_idx;
DROP INDEX IF EXISTS email_otp_wallet_enrollments_provider_idx;
DROP INDEX IF EXISTS email_otp_recovery_wrapped_escrows_wallet_idx;
DROP INDEX IF EXISTS email_otp_unlock_challenges_expires_idx;
DROP INDEX IF EXISTS email_otp_registration_attempts_subject_idx;
DROP INDEX IF EXISTS email_otp_registration_attempts_wallet_idx;
DROP INDEX IF EXISTS email_otp_rate_limits_reset_idx;
DROP TABLE IF EXISTS identity_links_constraints;
DROP TABLE IF EXISTS app_session_versions_constraints;
DROP TABLE IF EXISTS recovery_sessions_constraints;
DROP TABLE IF EXISTS recovery_executions_constraints;
DROP TABLE IF EXISTS email_recovery_preparations_constraints;
DROP TABLE IF EXISTS email_otp_challenges_constraints;
DROP TABLE IF EXISTS email_otp_grants_constraints;
DROP TABLE IF EXISTS email_otp_wallet_enrollments_constraints;
DROP TABLE IF EXISTS email_otp_recovery_wrapped_enrollment_escrows_constraints;
DROP TABLE IF EXISTS email_otp_auth_states_constraints;
DROP TABLE IF EXISTS email_otp_unlock_challenges_constraints;
DROP TABLE IF EXISTS email_otp_registration_attempts_constraints;
DROP TABLE IF EXISTS email_otp_rate_limits_constraints;

CREATE TABLE identity_links_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, subject),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(subject) > 0),
  CHECK (length(user_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'identity_subject_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.subject') = subject, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.userId') = user_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0))
);

INSERT INTO identity_links_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  subject,
  user_id,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  subject,
  user_id,
  record_json,
  created_at_ms,
  updated_at_ms
FROM identity_links;

DROP TABLE identity_links;
ALTER TABLE identity_links_constraints
  RENAME TO identity_links;

CREATE INDEX identity_links_user_idx
  ON identity_links (
    namespace,
    org_id,
    project_id,
    env_id,
    user_id,
    created_at_ms
  );

CREATE TABLE app_session_versions_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_version TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, user_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(user_id) > 0),
  CHECK (length(session_version) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'app_session_version_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.userId') = user_id, 0)),
  CHECK (
    COALESCE(json_extract(record_json, '$.appSessionVersion') = session_version, 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0))
);

INSERT INTO app_session_versions_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  user_id,
  session_version,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  user_id,
  session_version,
  record_json,
  created_at_ms,
  updated_at_ms
FROM app_session_versions;

DROP TABLE app_session_versions;
ALTER TABLE app_session_versions_constraints
  RENAME TO app_session_versions;

CREATE TABLE recovery_sessions_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  near_account_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, session_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(session_id) > 0),
  CHECK (length(near_account_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (expires_at_ms > 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'recovery_session_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.sessionId') = session_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.nearAccountId') = near_account_id, 0)),
  CHECK (
    COALESCE(
      json_extract(record_json, '$.status') IN (
        'prepared',
        'verified',
        'near_recovered',
        'evm_recovering',
        'completed',
        'failed',
        'cancelled'
      ),
      0
    )
  ),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

INSERT INTO recovery_sessions_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  session_id,
  near_account_id,
  record_json,
  expires_at_ms,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  session_id,
  near_account_id,
  record_json,
  expires_at_ms,
  created_at_ms,
  updated_at_ms
FROM recovery_sessions;

DROP TABLE recovery_sessions;
ALTER TABLE recovery_sessions_constraints
  RENAME TO recovery_sessions;

CREATE INDEX recovery_sessions_near_account_idx
  ON recovery_sessions (
    namespace,
    org_id,
    project_id,
    env_id,
    near_account_id,
    updated_at_ms DESC
  );

CREATE INDEX recovery_sessions_expiry_idx
  ON recovery_sessions (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE recovery_executions_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  chain_id_key TEXT NOT NULL,
  account_address TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    session_id,
    chain_id_key,
    account_address,
    action
  ),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(session_id) > 0),
  CHECK (length(chain_id_key) > 0),
  CHECK (length(account_address) > 0),
  CHECK (length(action) > 0),
  CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed', 'skipped')),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'recovery_execution_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.sessionId') = session_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.chainIdKey') = chain_id_key, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.accountAddress') = account_address, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.action') = action, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.status') = status, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0))
);

INSERT INTO recovery_executions_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  session_id,
  chain_id_key,
  account_address,
  action,
  status,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  session_id,
  chain_id_key,
  account_address,
  action,
  status,
  record_json,
  created_at_ms,
  updated_at_ms
FROM recovery_executions;

DROP TABLE recovery_executions;
ALTER TABLE recovery_executions_constraints
  RENAME TO recovery_executions;

CREATE INDEX recovery_executions_session_idx
  ON recovery_executions (
    namespace,
    org_id,
    project_id,
    env_id,
    session_id,
    chain_id_key,
    account_address,
    action
  );

CREATE INDEX recovery_executions_status_idx
  ON recovery_executions (
    namespace,
    org_id,
    project_id,
    env_id,
    status,
    action,
    updated_at_ms
  );

CREATE TABLE email_recovery_preparations_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, request_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(request_id) > 0),
  CHECK (length(account_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(rp_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (
    COALESCE(json_extract(record_json, '$.version') = 'email_recovery_preparation_v1', 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.requestId') = request_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.accountId') = account_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.rpId') = rp_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletBinding.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

INSERT INTO email_recovery_preparations_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  request_id,
  account_id,
  wallet_id,
  rp_id,
  record_json,
  created_at_ms,
  expires_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  request_id,
  account_id,
  wallet_id,
  rp_id,
  record_json,
  created_at_ms,
  expires_at_ms
FROM email_recovery_preparations;

DROP TABLE email_recovery_preparations;
ALTER TABLE email_recovery_preparations_constraints
  RENAME TO email_recovery_preparations;

CREATE INDEX email_recovery_preparations_expires_idx
  ON email_recovery_preparations (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE INDEX email_recovery_preparations_account_idx
  ON email_recovery_preparations (
    namespace,
    org_id,
    project_id,
    env_id,
    account_id,
    created_at_ms
  );

CREATE TABLE email_otp_challenges_constraints (
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
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(challenge_id) > 0),
  CHECK (length(challenge_subject_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(record_org_id) > 0),
  CHECK (otp_channel = 'email_otp'),
  CHECK (length(session_hash) > 0),
  CHECK (length(app_session_version) > 0),
  CHECK (
    action IN (
      'wallet_email_otp_login',
      'wallet_email_otp_registration',
      'wallet_email_otp_device_recovery'
    )
  ),
  CHECK (operation IN ('wallet_unlock', 'transaction_sign', 'export_key', 'registration')),
  CHECK (length(otp_code) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'email_otp_challenge_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.challengeId') = challenge_id, 0)),
  CHECK (
    COALESCE(json_extract(record_json, '$.challengeSubjectId') = challenge_subject_id, 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.orgId') = record_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.otpChannel') = otp_channel, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.sessionHash') = session_hash, 0)),
  CHECK (
    COALESCE(json_extract(record_json, '$.appSessionVersion') = app_session_version, 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.action') = action, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.operation') = operation, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.otpCode') = otp_code, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

INSERT INTO email_otp_challenges_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  challenge_id,
  challenge_subject_id,
  wallet_id,
  record_org_id,
  otp_channel,
  session_hash,
  app_session_version,
  action,
  operation,
  otp_code,
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
  challenge_subject_id,
  wallet_id,
  record_org_id,
  otp_channel,
  session_hash,
  app_session_version,
  action,
  operation,
  otp_code,
  record_json,
  created_at_ms,
  expires_at_ms
FROM email_otp_challenges;

DROP TABLE email_otp_challenges;
ALTER TABLE email_otp_challenges_constraints
  RENAME TO email_otp_challenges;

CREATE INDEX email_otp_challenges_context_idx
  ON email_otp_challenges (
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

CREATE INDEX email_otp_challenges_expires_idx
  ON email_otp_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE email_otp_grants_constraints (
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
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(grant_token) > 0),
  CHECK (length(user_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(challenge_id) > 0),
  CHECK (action IN ('wallet_email_otp_unseal', 'wallet_email_otp_device_recovery')),
  CHECK (json_valid(record_json)),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'email_otp_grant_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.grantToken') = grant_token, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.userId') = user_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (record_org_id = '' OR COALESCE(json_extract(record_json, '$.orgId') = record_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.challengeId') = challenge_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.otpChannel') = 'email_otp', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.action') = action, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.issuedAtMs') = issued_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

INSERT INTO email_otp_grants_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  grant_token,
  user_id,
  wallet_id,
  record_org_id,
  challenge_id,
  action,
  record_json,
  issued_at_ms,
  expires_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  grant_token,
  user_id,
  wallet_id,
  record_org_id,
  challenge_id,
  action,
  record_json,
  issued_at_ms,
  expires_at_ms
FROM email_otp_grants;

DROP TABLE email_otp_grants;
ALTER TABLE email_otp_grants_constraints
  RENAME TO email_otp_grants;

CREATE INDEX email_otp_grants_expires_idx
  ON email_otp_grants (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE email_otp_wallet_enrollments_constraints (
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
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(provider_user_id) > 0),
  CHECK (length(record_org_id) > 0),
  CHECK (length(verified_email) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (
    COALESCE(json_extract(record_json, '$.version') = 'email_otp_wallet_enrollment_v1', 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.providerUserId') = provider_user_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.orgId') = record_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.verifiedEmail') = verified_email, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0))
);

INSERT INTO email_otp_wallet_enrollments_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  provider_user_id,
  record_org_id,
  verified_email,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  provider_user_id,
  record_org_id,
  verified_email,
  record_json,
  created_at_ms,
  updated_at_ms
FROM email_otp_wallet_enrollments;

DROP TABLE email_otp_wallet_enrollments;
ALTER TABLE email_otp_wallet_enrollments_constraints
  RENAME TO email_otp_wallet_enrollments;

CREATE INDEX email_otp_wallet_enrollments_provider_idx
  ON email_otp_wallet_enrollments (
    namespace,
    org_id,
    project_id,
    env_id,
    record_org_id,
    provider_user_id,
    updated_at_ms
  );

CREATE TABLE email_otp_recovery_wrapped_enrollment_escrows_constraints (
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
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(recovery_key_id) > 0),
  CHECK (recovery_key_status IN ('active', 'consumed', 'revoked')),
  CHECK (json_valid(record_json)),
  CHECK (issued_at_ms > 0),
  CHECK (updated_at_ms >= issued_at_ms),
  CHECK (
    COALESCE(
      json_extract(record_json, '$.version') = 'email_otp_recovery_wrapped_enrollment_escrow_v1',
      0
    )
  ),
  CHECK (
    COALESCE(json_extract(record_json, '$.alg') = 'chacha20poly1305-hkdf-sha256-v1', 0)
  ),
  CHECK (
    COALESCE(
      json_extract(record_json, '$.secretKind') = 'email_otp_device_enrollment_escrow',
      0
    )
  ),
  CHECK (
    COALESCE(
      json_extract(record_json, '$.escrowKind') = 'recovery_wrapped_enrollment_escrow',
      0
    )
  ),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.recoveryKeyId') = recovery_key_id, 0)),
  CHECK (
    COALESCE(json_extract(record_json, '$.recoveryKeyStatus') = recovery_key_status, 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.authMethod') = 'google_sso_email_otp', 0)),
  CHECK (
    COALESCE(
      json_extract(record_json, '$.userId') = json_extract(record_json, '$.authSubjectId'),
      0
    )
  ),
  CHECK (COALESCE(json_extract(record_json, '$.issuedAtMs') = issued_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0)),
  CHECK (
    (
      recovery_key_status = 'active'
      AND json_type(record_json, '$.consumedAtMs') IS NULL
      AND json_type(record_json, '$.revokedAtMs') IS NULL
    )
    OR (
      recovery_key_status = 'consumed'
      AND COALESCE(json_extract(record_json, '$.consumedAtMs') >= issued_at_ms, 0)
      AND json_type(record_json, '$.revokedAtMs') IS NULL
    )
    OR (
      recovery_key_status = 'revoked'
      AND COALESCE(json_extract(record_json, '$.revokedAtMs') >= issued_at_ms, 0)
      AND json_type(record_json, '$.consumedAtMs') IS NULL
    )
  )
);

INSERT INTO email_otp_recovery_wrapped_enrollment_escrows_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  recovery_key_id,
  recovery_key_status,
  record_json,
  issued_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  recovery_key_id,
  recovery_key_status,
  record_json,
  issued_at_ms,
  updated_at_ms
FROM email_otp_recovery_wrapped_enrollment_escrows;

DROP TABLE email_otp_recovery_wrapped_enrollment_escrows;
ALTER TABLE email_otp_recovery_wrapped_enrollment_escrows_constraints
  RENAME TO email_otp_recovery_wrapped_enrollment_escrows;

CREATE INDEX email_otp_recovery_wrapped_escrows_wallet_idx
  ON email_otp_recovery_wrapped_enrollment_escrows (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    recovery_key_status,
    updated_at_ms
  );

CREATE TABLE email_otp_auth_states_constraints (
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
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(provider_user_id) > 0),
  CHECK (length(record_org_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'email_otp_auth_state_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.providerUserId') = provider_user_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.orgId') = record_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0))
);

INSERT INTO email_otp_auth_states_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  provider_user_id,
  record_org_id,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  provider_user_id,
  record_org_id,
  record_json,
  created_at_ms,
  updated_at_ms
FROM email_otp_auth_states;

DROP TABLE email_otp_auth_states;
ALTER TABLE email_otp_auth_states_constraints
  RENAME TO email_otp_auth_states;

CREATE TABLE email_otp_unlock_challenges_constraints (
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
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(challenge_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(user_id) > 0),
  CHECK (record_org_id = '' OR length(record_org_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (
    COALESCE(json_extract(record_json, '$.version') = 'email_otp_unlock_challenge_v1', 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.challengeId') = challenge_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.userId') = user_id, 0)),
  CHECK (record_org_id = '' OR COALESCE(json_extract(record_json, '$.orgId') = record_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

INSERT INTO email_otp_unlock_challenges_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  challenge_id,
  wallet_id,
  user_id,
  record_org_id,
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
  wallet_id,
  user_id,
  record_org_id,
  record_json,
  created_at_ms,
  expires_at_ms
FROM email_otp_unlock_challenges;

DROP TABLE email_otp_unlock_challenges;
ALTER TABLE email_otp_unlock_challenges_constraints
  RENAME TO email_otp_unlock_challenges;

CREATE INDEX email_otp_unlock_challenges_expires_idx
  ON email_otp_unlock_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE email_otp_registration_attempts_constraints (
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
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(attempt_id) > 0),
  CHECK (length(provider_subject) > 0),
  CHECK (length(email) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (state IN ('started', 'key_finalized', 'active', 'abandoned', 'failed', 'expired')),
  CHECK (length(app_session_version) > 0),
  CHECK (json_valid(offer_wallet_ids_json)),
  CHECK (json_type(offer_wallet_ids_json) = 'array'),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (
    COALESCE(
      json_extract(record_json, '$.version') = 'google_email_otp_registration_attempt_v1',
      0
    )
  ),
  CHECK (COALESCE(json_extract(record_json, '$.attemptId') = attempt_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.providerSubject') = provider_subject, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.email') = email, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.state') = state, 0)),
  CHECK (
    COALESCE(json_extract(record_json, '$.appSessionVersion') = app_session_version, 0)
  ),
  CHECK (runtime_org_id = '' OR COALESCE(json_extract(record_json, '$.runtimePolicyScope.orgId') = runtime_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

INSERT INTO email_otp_registration_attempts_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  attempt_id,
  provider_subject,
  email,
  wallet_id,
  state,
  app_session_version,
  runtime_org_id,
  runtime_policy_key,
  offer_wallet_ids_json,
  record_json,
  created_at_ms,
  updated_at_ms,
  expires_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  attempt_id,
  provider_subject,
  email,
  wallet_id,
  state,
  app_session_version,
  runtime_org_id,
  runtime_policy_key,
  offer_wallet_ids_json,
  record_json,
  created_at_ms,
  updated_at_ms,
  expires_at_ms
FROM email_otp_registration_attempts;

DROP TABLE email_otp_registration_attempts;
ALTER TABLE email_otp_registration_attempts_constraints
  RENAME TO email_otp_registration_attempts;

CREATE INDEX email_otp_registration_attempts_subject_idx
  ON email_otp_registration_attempts (
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

CREATE INDEX email_otp_registration_attempts_wallet_idx
  ON email_otp_registration_attempts (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    state,
    expires_at_ms
  );

CREATE TABLE email_otp_rate_limits_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  rate_key TEXT NOT NULL,
  consumed_count INTEGER NOT NULL,
  reset_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, rate_key),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(rate_key) > 0),
  CHECK (consumed_count > 0),
  CHECK (reset_at_ms > 0),
  CHECK (updated_at_ms > 0),
  CHECK (reset_at_ms > updated_at_ms)
);

INSERT INTO email_otp_rate_limits_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  rate_key,
  consumed_count,
  reset_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  rate_key,
  consumed_count,
  reset_at_ms,
  updated_at_ms
FROM email_otp_rate_limits;

DROP TABLE email_otp_rate_limits;
ALTER TABLE email_otp_rate_limits_constraints
  RENAME TO email_otp_rate_limits;

CREATE INDEX email_otp_rate_limits_reset_idx
  ON email_otp_rate_limits (
    namespace,
    org_id,
    project_id,
    env_id,
    reset_at_ms
  );

DROP INDEX IF EXISTS wallet_auth_methods_passkey_uidx;
DROP INDEX IF EXISTS wallet_auth_methods_email_uidx;
DROP INDEX IF EXISTS wallet_auth_methods_identifier_idx;
DROP INDEX IF EXISTS wallet_auth_methods_wallet_idx;
DROP INDEX IF EXISTS wallet_signers_chain_target_idx;
DROP INDEX IF EXISTS wallet_signers_wallet_idx;
DROP TABLE IF EXISTS wallet_auth_methods_branch_constraints;
DROP TABLE IF EXISTS wallet_signers_branch_constraints;
DROP TABLE IF EXISTS wallets_identity_constraints;

CREATE TABLE wallets_identity_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id),
  CHECK (length(wallet_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms >= 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'wallet_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0))
);

INSERT INTO wallets_identity_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  record_json,
  created_at_ms,
  updated_at_ms
FROM wallets;

DROP TABLE wallets;
ALTER TABLE wallets_identity_constraints
  RENAME TO wallets;

CREATE TABLE wallet_signers_branch_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  signer_family TEXT NOT NULL,
  signer_id TEXT NOT NULL,
  chain_target_key TEXT,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    signer_family,
    signer_id
  ),
  CHECK (length(wallet_id) > 0),
  CHECK (signer_family IN ('ed25519', 'ecdsa')),
  CHECK (length(signer_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms >= 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.signerId') = signer_id, 0)),
  CHECK (
    (
      signer_family = 'ed25519'
      AND chain_target_key IS NULL
      AND substr(signer_id, 1, 8) = 'ed25519:'
      AND COALESCE(
        json_extract(record_json, '$.version') = 'wallet_signer_ed25519_v1',
        0
      )
    )
    OR
    (
      signer_family = 'ecdsa'
      AND chain_target_key IS NOT NULL
      AND length(chain_target_key) > 0
      AND signer_id = 'ecdsa:' || chain_target_key
      AND COALESCE(
        json_extract(record_json, '$.version') = 'wallet_signer_ecdsa_v1',
        0
      )
      AND COALESCE(json_extract(record_json, '$.chainTargetKey') = chain_target_key, 0)
    )
  )
);

INSERT INTO wallet_signers_branch_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  signer_family,
  signer_id,
  chain_target_key,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  signer_family,
  signer_id,
  chain_target_key,
  record_json,
  created_at_ms,
  updated_at_ms
FROM wallet_signers;

DROP TABLE wallet_signers;
ALTER TABLE wallet_signers_branch_constraints
  RENAME TO wallet_signers;

CREATE INDEX wallet_signers_wallet_idx
  ON wallet_signers (namespace, org_id, project_id, env_id, wallet_id, signer_family);

CREATE INDEX wallet_signers_chain_target_idx
  ON wallet_signers (
    namespace,
    org_id,
    project_id,
    env_id,
    signer_family,
    chain_target_key
  );

CREATE TABLE wallet_auth_methods_branch_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  rp_id TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  auth_identifier_key TEXT NOT NULL,
  credential_id_b64u TEXT,
  credential_public_key_b64u TEXT,
  email_hash_hex TEXT,
  registration_authority_id TEXT,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_auth_method_id),
  CHECK (length(wallet_id) > 0),
  CHECK (kind IN ('passkey', 'email_otp')),
  CHECK (status IN ('active', 'revoked')),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (length(auth_identifier_key) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms >= 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (
    (
      kind = 'passkey'
      AND length(rp_id) > 0
      AND credential_id_b64u IS NOT NULL
      AND length(credential_id_b64u) > 0
      AND credential_public_key_b64u IS NOT NULL
      AND length(credential_public_key_b64u) > 0
      AND email_hash_hex IS NULL
      AND registration_authority_id IS NULL
      AND auth_identifier_key = credential_id_b64u
      AND wallet_auth_method_id = 'passkey:' || rp_id || ':' || credential_id_b64u
    )
    OR
    (
      kind = 'email_otp'
      AND rp_id = ''
      AND credential_id_b64u IS NULL
      AND credential_public_key_b64u IS NULL
      AND email_hash_hex IS NOT NULL
      AND length(email_hash_hex) > 0
      AND registration_authority_id IS NOT NULL
      AND length(registration_authority_id) > 0
      AND auth_identifier_key = email_hash_hex
      AND wallet_auth_method_id = 'email_otp:' || wallet_id || ':' || email_hash_hex
    )
  )
);

INSERT INTO wallet_auth_methods_branch_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  rp_id,
  kind,
  status,
  wallet_auth_method_id,
  auth_identifier_key,
  credential_id_b64u,
  credential_public_key_b64u,
  email_hash_hex,
  registration_authority_id,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  wallet_id,
  rp_id,
  kind,
  status,
  wallet_auth_method_id,
  auth_identifier_key,
  credential_id_b64u,
  credential_public_key_b64u,
  email_hash_hex,
  registration_authority_id,
  record_json,
  created_at_ms,
  updated_at_ms
FROM wallet_auth_methods;

DROP TABLE wallet_auth_methods;
ALTER TABLE wallet_auth_methods_branch_constraints
  RENAME TO wallet_auth_methods;

CREATE INDEX wallet_auth_methods_wallet_idx
  ON wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    rp_id,
    status
  );

CREATE INDEX wallet_auth_methods_identifier_idx
  ON wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    kind,
    auth_identifier_key
  );

CREATE UNIQUE INDEX wallet_auth_methods_passkey_uidx
  ON wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    rp_id,
    credential_id_b64u
  )
  WHERE kind = 'passkey' AND credential_id_b64u IS NOT NULL;

CREATE UNIQUE INDEX wallet_auth_methods_email_uidx
  ON wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    email_hash_hex
  )
  WHERE kind = 'email_otp' AND email_hash_hex IS NOT NULL;

DROP INDEX IF EXISTS signing_root_secret_shares_scope_idx;
DROP TABLE IF EXISTS signing_root_secret_shares_constraints;

CREATE TABLE signing_root_secret_shares_constraints (
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
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(signing_root_id) > 0),
  CHECK (share_id IN (1, 2, 3)),
  CHECK (length(sealed_share_b64u) > 0),
  CHECK (sealed_share_b64u NOT GLOB '*[^A-Za-z0-9_-]*'),
  CHECK (storage_id IS NULL OR length(storage_id) > 0),
  CHECK (length(kek_id) > 0),
  CHECK (length(envelope_version) > 0),
  CHECK (length(aad_digest_b64u) = 43),
  CHECK (aad_digest_b64u NOT GLOB '*[^A-Za-z0-9_-]*'),
  CHECK (length(ciphertext_digest_b64u) = 43),
  CHECK (ciphertext_digest_b64u NOT GLOB '*[^A-Za-z0-9_-]*'),
  CHECK (rotation_state IN ('active', 'rotation_pending', 'rotated', 'retired')),
  CHECK (rotated_from_kek_id IS NULL OR length(rotated_from_kek_id) > 0),
  CHECK (rotated_at_ms IS NULL OR rotated_at_ms >= created_at_ms),
  CHECK (retired_at_ms IS NULL OR retired_at_ms >= created_at_ms),
  CHECK (length(last_audit_event_id) > 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

INSERT INTO signing_root_secret_shares_constraints (
  namespace,
  org_id,
  project_id,
  env_id,
  signing_root_id,
  signing_root_version,
  share_id,
  sealed_share_b64u,
  storage_id,
  kek_id,
  envelope_version,
  aad_digest_b64u,
  ciphertext_digest_b64u,
  rotation_state,
  rotated_from_kek_id,
  rotated_at_ms,
  retired_at_ms,
  last_audit_event_id,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  signing_root_id,
  signing_root_version,
  share_id,
  sealed_share_b64u,
  storage_id,
  kek_id,
  envelope_version,
  aad_digest_b64u,
  ciphertext_digest_b64u,
  rotation_state,
  rotated_from_kek_id,
  rotated_at_ms,
  retired_at_ms,
  last_audit_event_id,
  created_at_ms,
  updated_at_ms
FROM signing_root_secret_shares;

DROP TABLE signing_root_secret_shares;
ALTER TABLE signing_root_secret_shares_constraints
  RENAME TO signing_root_secret_shares;

CREATE INDEX signing_root_secret_shares_scope_idx
  ON signing_root_secret_shares (
    namespace,
    org_id,
    project_id,
    env_id,
    signing_root_id,
    signing_root_version,
    share_id
  );
