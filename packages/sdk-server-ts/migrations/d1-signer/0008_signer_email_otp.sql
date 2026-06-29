CREATE TABLE IF NOT EXISTS email_otp_challenges (
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

CREATE INDEX IF NOT EXISTS email_otp_challenges_context_idx
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

CREATE INDEX IF NOT EXISTS email_otp_challenges_expires_idx
  ON email_otp_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE IF NOT EXISTS email_otp_grants (
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

CREATE INDEX IF NOT EXISTS email_otp_grants_expires_idx
  ON email_otp_grants (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE IF NOT EXISTS email_otp_wallet_enrollments (
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

CREATE INDEX IF NOT EXISTS email_otp_wallet_enrollments_provider_idx
  ON email_otp_wallet_enrollments (
    namespace,
    org_id,
    project_id,
    env_id,
    record_org_id,
    provider_user_id,
    updated_at_ms
  );

CREATE TABLE IF NOT EXISTS email_otp_recovery_wrapped_enrollment_escrows (
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

CREATE INDEX IF NOT EXISTS email_otp_recovery_wrapped_escrows_wallet_idx
  ON email_otp_recovery_wrapped_enrollment_escrows (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    recovery_key_status,
    updated_at_ms
  );

CREATE TABLE IF NOT EXISTS email_otp_auth_states (
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

CREATE TABLE IF NOT EXISTS email_otp_unlock_challenges (
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

CREATE INDEX IF NOT EXISTS email_otp_unlock_challenges_expires_idx
  ON email_otp_unlock_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );

CREATE TABLE IF NOT EXISTS email_otp_registration_attempts (
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

CREATE INDEX IF NOT EXISTS email_otp_registration_attempts_subject_idx
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

CREATE INDEX IF NOT EXISTS email_otp_registration_attempts_wallet_idx
  ON email_otp_registration_attempts (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    state,
    expires_at_ms
  );
