-- Canonical D1 schema.
CREATE TABLE "app_session_versions" (
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
CREATE TABLE authorization_sessions (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  auth_source_kind TEXT NOT NULL,
  auth_source_json TEXT NOT NULL,
  device_id TEXT NOT NULL,
  audience_kind TEXT NOT NULL,
  audience_json TEXT NOT NULL,
  app_session_version TEXT NOT NULL,
  assurance TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, session_id),
  CHECK (assurance IN ('session', 'step_up')),
  CHECK (auth_source_kind IN ('oidc_provider', 'passkey')),
  CHECK (audience_kind IN ('first_party_web', 'hosted_wallet_iframe')),
  CHECK (json_valid(auth_source_json)),
  CHECK (json_valid(audience_json)),
  CHECK (lifecycle_kind = 'active'),
  CHECK (expires_at_ms > created_at_ms)
);
CREATE TABLE authorization_wallet_session_quotas (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  remaining_uses INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, quota_id),
  UNIQUE (namespace, tenant_id, wallet_session_id),
  CHECK (remaining_uses >= 0),
  CHECK (lifecycle_kind IN ('active', 'exhausted')),
  CHECK (
    (lifecycle_kind = 'active' AND remaining_uses > 0)
    OR (lifecycle_kind = 'exhausted' AND remaining_uses = 0)
  )
);
CREATE TABLE authorized_operation_audit_events (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  audit_event_id TEXT NOT NULL,
  authorized_operation_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  authorization_source_kind TEXT NOT NULL,
  authorization_id TEXT,
  evidence_set_digest TEXT,
  quota_id TEXT,
  material_activation_id TEXT,
  result_kind TEXT NOT NULL,
  claimed_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER, authorization_grant_kind TEXT, material_activation_capability TEXT, material_activation_owner TEXT, material_activation_key_binding TEXT, material_activation_lifecycle_binding TEXT, material_activation_signing_worker TEXT, linked_wallet_id TEXT, linked_enrollment_id TEXT, linked_device_id TEXT, linked_wallet_key_id TEXT, linked_lane_id TEXT, linked_lane_share_epoch TEXT, linked_revocation_epoch INTEGER, linked_scope_org_id TEXT, linked_scope_project_id TEXT, linked_scope_env_id TEXT,
  PRIMARY KEY (namespace, tenant_id, audit_event_id),
  UNIQUE (namespace, tenant_id, authorized_operation_id),
  CHECK (authorization_source_kind IN ('authorization_grant', 'verified_step_up')),
  CHECK (
    (authorization_source_kind = 'authorization_grant'
      AND authorization_id IS NOT NULL
      AND evidence_set_digest IS NULL)
    OR (authorization_source_kind = 'verified_step_up'
      AND authorization_id IS NULL
      AND evidence_set_digest IS NOT NULL)
  ),
  CHECK (result_kind IN ('pending', 'succeeded', 'failed_before_side_effect', 'failed_after_side_effect')),
  CHECK (
    (result_kind = 'pending' AND completed_at_ms IS NULL)
    OR (result_kind != 'pending' AND completed_at_ms IS NOT NULL)
  )
);
CREATE TABLE "authorized_operations" (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  authorized_operation_id TEXT NOT NULL,
  audit_event_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  lane_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  display_digest TEXT NOT NULL,
  authorization_source_kind TEXT NOT NULL,
  authorization_id TEXT,
  evidence_set_digest TEXT,
  quota_id TEXT,
  quota_kind TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  result_kind TEXT NOT NULL,
  result_digest TEXT,
  result_status INTEGER,
  result_content_type TEXT,
  result_body_text TEXT,
  claimed_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  material_activation_id TEXT, authorization_grant_kind TEXT, material_activation_capability TEXT, material_activation_owner TEXT, material_activation_key_binding TEXT, material_activation_lifecycle_binding TEXT, material_activation_signing_worker TEXT, linked_wallet_id TEXT, linked_enrollment_id TEXT, linked_device_id TEXT, linked_wallet_key_id TEXT, linked_lane_id TEXT, linked_lane_share_epoch TEXT, linked_revocation_epoch INTEGER, linked_scope_org_id TEXT, linked_scope_project_id TEXT, linked_scope_env_id TEXT,
  PRIMARY KEY (namespace, tenant_id, authorized_operation_id),
  UNIQUE (namespace, tenant_id, operation_fingerprint_digest),
  CHECK (authorization_source_kind IN ('authorization_grant', 'verified_step_up')),
  CHECK (
    (authorization_source_kind = 'authorization_grant'
      AND authorization_id IS NOT NULL
      AND evidence_set_digest IS NULL)
    OR (authorization_source_kind = 'verified_step_up'
      AND authorization_id IS NULL
      AND evidence_set_digest IS NOT NULL)
  ),
  CHECK (quota_kind IN ('consume_reusable_wallet_session', 'quota_neutral')),
  CHECK (
    (quota_kind = 'consume_reusable_wallet_session'
      AND authorization_source_kind = 'authorization_grant'
      AND operation_kind NOT IN ('near.export_key', 'evm.export_key')
      AND capability_kind != 'vault_access')
    OR (quota_kind = 'quota_neutral'
      AND (
        operation_kind IN ('near.export_key', 'evm.export_key')
        OR capability_kind = 'vault_access'
        OR authorization_source_kind = 'verified_step_up'
      ))
  ),
  CHECK (
    (quota_kind = 'consume_reusable_wallet_session' AND quota_id IS NOT NULL)
    OR (quota_kind = 'quota_neutral' AND quota_id IS NULL)
  ),
  CHECK (lifecycle_kind IN ('claimed', 'completed')),
  CHECK (
    (lifecycle_kind = 'claimed'
      AND result_kind = 'pending'
      AND result_digest IS NULL
      AND result_status IS NULL
      AND result_content_type IS NULL
      AND result_body_text IS NULL
      AND completed_at_ms IS NULL)
    OR (lifecycle_kind = 'completed'
      AND result_kind IN ('succeeded', 'failed_before_side_effect', 'failed_after_side_effect')
      AND result_digest IS NOT NULL
      AND result_status BETWEEN 100 AND 599
      AND result_content_type IS NOT NULL
      AND trim(result_content_type) = result_content_type
      AND length(result_content_type) BETWEEN 1 AND 255
      AND result_body_text IS NOT NULL
      AND length(CAST(result_body_text AS BLOB)) <= 65536
      AND completed_at_ms IS NOT NULL)
  )
);
CREATE TABLE ecdsa_authorization_atomic_guards (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  matched INTEGER NOT NULL CHECK (matched = 1),
  PRIMARY KEY (namespace, tenant_id, check_id)
);
CREATE TABLE "email_otp_auth_states" (
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
CREATE TABLE "email_otp_challenges" (
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
CREATE TABLE "email_otp_grants" (
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
CREATE TABLE "email_otp_rate_limits" (
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
CREATE TABLE "email_otp_recovery_wrapped_enrollment_escrows" (
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
CREATE TABLE "email_otp_registration_attempts" (
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
CREATE TABLE "email_otp_unlock_challenges" (
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
CREATE TABLE "email_otp_wallet_enrollments" (
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
CREATE TABLE "email_recovery_preparations" (
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
CREATE TABLE google_email_otp_session_exchange_journals (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  account_mode TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  phase TEXT NOT NULL,
  version INTEGER NOT NULL,
  phase_data_json TEXT NOT NULL,
  prepared_seams_session_id TEXT NOT NULL,
  prepared_device_id TEXT NOT NULL,
  prepared_created_at_ms INTEGER NOT NULL,
  response_status INTEGER,
  response_body_text TEXT,
  response_set_cookie TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, idempotency_key),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(idempotency_key) BETWEEN 1 AND 512),
  CHECK (length(request_fingerprint) BETWEEN 1 AND 512),
  CHECK (account_mode = 'login'),
  CHECK (lifecycle_kind IN ('in_progress', 'completed')),
  CHECK (
    phase IN (
      'claimed',
      'session_prepared',
      'completed'
    )
  ),
  CHECK (version >= 1),
  CHECK (json_valid(phase_data_json)),
  CHECK (length(CAST(phase_data_json AS BLOB)) <= 65536),
  CHECK (length(prepared_seams_session_id) > 0),
  CHECK (length(prepared_device_id) > 0),
  CHECK (prepared_created_at_ms > 0),
  CHECK (prepared_created_at_ms = created_at_ms),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (
    (lifecycle_kind = 'in_progress'
      AND phase != 'completed'
      AND response_status IS NULL
      AND response_body_text IS NULL
      AND response_set_cookie IS NULL)
    OR (lifecycle_kind = 'completed'
      AND phase = 'completed'
      AND response_status BETWEEN 100 AND 599
      AND response_body_text IS NOT NULL
      AND length(CAST(response_body_text AS BLOB)) <= 65536)
  ),
  CHECK (response_set_cookie IS NULL OR length(CAST(response_set_cookie AS BLOB)) <= 8192)
);
CREATE TABLE hosted_wallet_session_exchange_codes (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  exchange_code_id TEXT NOT NULL,
  source_session_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  nonce_digest TEXT NOT NULL,
  app_origin TEXT NOT NULL,
  wallet_origin TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  target_session_id TEXT,
  consumed_at_ms INTEGER,
  PRIMARY KEY (namespace, tenant_id, exchange_code_id),
  UNIQUE (namespace, code_hash),
  FOREIGN KEY (namespace, tenant_id, source_session_id)
    REFERENCES authorization_sessions(namespace, tenant_id, session_id),
  CHECK (lifecycle_kind IN ('issued', 'consumed')),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (
    (lifecycle_kind = 'issued' AND target_session_id IS NULL AND consumed_at_ms IS NULL)
    OR
    (lifecycle_kind = 'consumed' AND target_session_id IS NOT NULL AND consumed_at_ms IS NOT NULL)
  )
);
CREATE TABLE "identity_links" (
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
CREATE TABLE lane_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
CREATE TABLE lane_effect_journal (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  effect_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_key_id TEXT NOT NULL,
  lane_id TEXT NOT NULL,
  lane_share_epoch TEXT NOT NULL,
  effect_kind TEXT NOT NULL,
  request_digest_b64u TEXT NOT NULL,
  status TEXT NOT NULL,
  response_digest_b64u TEXT,
  recorded_at_ms INTEGER NOT NULL,
  confirmed_at_ms INTEGER,
  version INTEGER NOT NULL,
  command_digest_b64u TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, effect_id),
  UNIQUE (namespace, org_id, project_id, env_id, operation_id, effect_kind),
  FOREIGN KEY (namespace, org_id, project_id, env_id, enrollment_id)
    REFERENCES lane_enrollments(namespace, org_id, project_id, env_id, enrollment_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, operation_id)
    REFERENCES lane_protocol_operations(namespace, org_id, project_id, env_id, operation_id),
  CHECK (effect_kind IN ('activate_server_material', 'retire_server_material', 'invalidate_holder_material')),
  CHECK (status IN ('recorded', 'confirmed')),
  CHECK (
    (status = 'recorded' AND response_digest_b64u IS NULL AND confirmed_at_ms IS NULL)
    OR (status = 'confirmed' AND response_digest_b64u IS NOT NULL AND confirmed_at_ms IS NOT NULL AND confirmed_at_ms >= recorded_at_ms)
  ),
  CHECK (version > 0),
  CHECK (recorded_at_ms >= 0)
);
CREATE TABLE lane_enrollments (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  manifest_digest_b64u TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  lifecycle_json TEXT NOT NULL,
  version INTEGER NOT NULL,
  command_digest_b64u TEXT NOT NULL,
  revocation_fence_command_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, enrollment_id),
  UNIQUE (namespace, org_id, project_id, env_id, manifest_digest_b64u),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(manifest_digest_b64u) > 0),
  CHECK (json_valid(manifest_json)),
  CHECK (json_valid(lifecycle_json)),
  CHECK (version > 0),
  CHECK (created_at_ms >= 0 AND updated_at_ms >= created_at_ms)
);
CREATE TABLE lane_locks (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  lock_key TEXT NOT NULL,
  lock_kind TEXT NOT NULL,
  enrollment_id TEXT,
  wallet_key_id TEXT,
  lane_id TEXT,
  lock_id TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  acquired_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, lock_key),
  CHECK (lock_kind IN ('wallet_key', 'enrollment')),
  CHECK (length(lock_id) > 0),
  CHECK (expires_at_ms > acquired_at_ms),
  CHECK ((lock_kind = 'wallet_key' AND wallet_key_id IS NOT NULL AND enrollment_id IS NULL AND lane_id IS NULL) OR
         (lock_kind = 'enrollment' AND enrollment_id IS NOT NULL AND wallet_key_id IS NULL AND lane_id IS NULL))
);
CREATE TABLE lane_product_epochs (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_key_id TEXT NOT NULL,
  lane_id TEXT NOT NULL,
  lane_share_epoch TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  target_material_activation_id TEXT NOT NULL,
  material_activation_json TEXT NOT NULL,
  holder_participant_json TEXT NOT NULL,
  signing_worker_participant_json TEXT NOT NULL,
  participant_set_binding_digest_b64u TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL,
  lane_kind TEXT NOT NULL,
  key_family TEXT NOT NULL,
  public_identity_digest_b64u TEXT NOT NULL,
  state TEXT NOT NULL,
  product_json TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  command_digest_b64u TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_key_id, lane_id, lane_share_epoch),
  UNIQUE (namespace, org_id, project_id, env_id, target_material_activation_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, enrollment_id)
    REFERENCES lane_enrollments(namespace, org_id, project_id, env_id, enrollment_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, operation_id)
    REFERENCES lane_protocol_operations(namespace, org_id, project_id, env_id, operation_id),
  CHECK (json_valid(material_activation_json)),
  CHECK (json_valid(holder_participant_json)),
  CHECK (json_valid(signing_worker_participant_json)),
  CHECK (length(participant_set_binding_digest_b64u) > 0),
  CHECK (revocation_epoch >= 0),
  CHECK (json_valid(product_json)),
  CHECK (state IN ('pending_visibility', 'active', 'retired', 'revocation_pending', 'revoked')),
  CHECK (lane_kind IN ('owner_passkey', 'owner_email_otp', 'linked_device', 'delegated_execution', 'recovery', 'break_glass')),
  CHECK (length(command_digest_b64u) > 0),
  CHECK (version > 0),
  CHECK (key_family IN ('ed25519', 'ecdsa_secp256k1')),
  CHECK (created_at_ms >= 0 AND updated_at_ms >= created_at_ms)
);
CREATE TABLE lane_protocol_operations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_key_id TEXT NOT NULL,
  source_lane_id TEXT NOT NULL,
  source_lane_share_epoch TEXT NOT NULL,
  source_revocation_epoch INTEGER NOT NULL,
  target_lane_id TEXT NOT NULL,
  target_lane_share_epoch TEXT NOT NULL,
  target_material_activation_id TEXT NOT NULL,
  key_family TEXT NOT NULL,
  job_json TEXT NOT NULL,
  lifecycle_json TEXT NOT NULL,
  version INTEGER NOT NULL,
  command_digest_b64u TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, operation_id),
  UNIQUE (namespace, org_id, project_id, env_id, target_material_activation_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, enrollment_id)
    REFERENCES lane_enrollments(namespace, org_id, project_id, env_id, enrollment_id),
  CHECK (source_revocation_epoch >= 0),
  CHECK (key_family IN ('ed25519', 'ecdsa_secp256k1')),
  CHECK (json_valid(job_json)),
  CHECK (json_valid(lifecycle_json)),
  CHECK (version > 0),
  CHECK (created_at_ms >= 0 AND updated_at_ms >= created_at_ms)
);
CREATE TABLE lane_receipts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  operation_id TEXT,
  receipt_kind TEXT NOT NULL,
  receipt_digest_b64u TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, receipt_id),
  UNIQUE (namespace, org_id, project_id, env_id, operation_id, receipt_kind),
  FOREIGN KEY (namespace, org_id, project_id, env_id, enrollment_id)
    REFERENCES lane_enrollments(namespace, org_id, project_id, env_id, enrollment_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, operation_id)
    REFERENCES lane_protocol_operations(namespace, org_id, project_id, env_id, operation_id),
  CHECK (json_valid(receipt_json)),
  CHECK (created_at_ms >= 0)
);
CREATE TABLE linked_device_owner_planning_snapshots (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  owner_context_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  policy_digest_b64u TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  ordered_key_bindings_json TEXT NOT NULL,
  protocol_versions_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  source_children_json TEXT NOT NULL,
  ordered_owner_source_lane_hints_json TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  snapshot_digest_b64u TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(link_session_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(policy_digest_b64u) > 0),
  CHECK (length(operation_id) > 0),
  CHECK (length(idempotency_key) > 0),
  CHECK (json_valid(owner_context_json)),
  CHECK (json_valid(payload_json)),
  CHECK (json_valid(ordered_key_bindings_json)),
  CHECK (json_valid(protocol_versions_json)),
  CHECK (json_valid(source_children_json)),
  CHECK (json_valid(ordered_owner_source_lane_hints_json)),
  CHECK (json_valid(snapshot_json)),
  CHECK (expires_at_ms > 0),
  CHECK (created_at_ms > 0 AND updated_at_ms >= created_at_ms)
);
CREATE TABLE linked_device_provisioning_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  manifest_digest_b64u TEXT NOT NULL,
  deliveries_json TEXT NOT NULL,
  aggregate_receipt_json TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(manifest_digest_b64u) > 0),
  CHECK (json_valid(deliveries_json)),
  CHECK (aggregate_receipt_json IS NULL OR json_valid(aggregate_receipt_json))
);
CREATE TABLE linked_device_request_proof_nonces (
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
CREATE TABLE linked_device_session_transcripts (
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
CREATE TABLE linked_device_sessions (
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
CREATE TABLE linked_device_source_handoffs (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  target_ready_json TEXT NOT NULL,
  target_ready_digest_b64u TEXT NOT NULL,
  manifest_digest_b64u TEXT NOT NULL,
  deliveries_json TEXT,
  deliveries_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(target_ready_digest_b64u) > 0),
  CHECK (length(manifest_digest_b64u) > 0),
  CHECK (json_valid(target_ready_json)),
  CHECK (
    (deliveries_json IS NULL AND deliveries_digest_b64u IS NULL)
    OR
    (deliveries_json IS NOT NULL AND json_valid(deliveries_json) AND length(deliveries_digest_b64u) > 0)
  )
);
CREATE TABLE linked_device_target_commit_reservations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  registration_digest_b64u TEXT NOT NULL,
  state TEXT NOT NULL,
  reserved_at_ms INTEGER NOT NULL,
  committed_at_ms INTEGER,
  key_manifest_digest_b64u TEXT,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(registration_digest_b64u) > 0),
  CHECK (state IN ('reserved', 'committed')),
  CHECK (
    (state = 'reserved' AND committed_at_ms IS NULL AND key_manifest_digest_b64u IS NULL)
    OR
    (state = 'committed' AND committed_at_ms IS NOT NULL AND length(key_manifest_digest_b64u) > 0)
  )
);
CREATE TABLE linked_device_target_credentials (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  state TEXT NOT NULL,
  preparation_digest_b64u TEXT NOT NULL,
  preparation_json TEXT NOT NULL,
  registration_json TEXT,
  credential_id_b64u TEXT,
  credential_public_key_b64u TEXT,
  credential_counter INTEGER,
  key_manifest_digest_b64u TEXT,
  prepared_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  registered_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(wallet_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (state IN ('prepared', 'registered')),
  CHECK (length(preparation_digest_b64u) > 0),
  CHECK (json_valid(preparation_json)),
  CHECK (expires_at_ms > prepared_at_ms),
  CHECK (
    (state = 'prepared'
      AND registration_json IS NULL
      AND credential_id_b64u IS NULL
      AND credential_public_key_b64u IS NULL
      AND credential_counter IS NULL
      AND key_manifest_digest_b64u IS NULL
      AND registered_at_ms IS NULL)
    OR
    (state = 'registered'
      AND json_valid(registration_json)
      AND length(credential_id_b64u) > 0
      AND length(credential_public_key_b64u) > 0
      AND credential_counter >= 0
      AND length(key_manifest_digest_b64u) > 0
      AND registered_at_ms > 0)
  )
);
CREATE TABLE linked_device_target_deployment_descriptors (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  target_preparation_digest_b64u TEXT NOT NULL,
  registration_digest_b64u TEXT NOT NULL,
  child_index INTEGER NOT NULL,
  request_digest_b64u TEXT NOT NULL,
  descriptor_digest_b64u TEXT NOT NULL,
  descriptor_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    link_session_id,
    target_preparation_digest_b64u,
    registration_digest_b64u,
    child_index
  ),
  CHECK (length(target_preparation_digest_b64u) > 0),
  CHECK (length(registration_digest_b64u) > 0),
  CHECK (child_index >= 0),
  CHECK (length(request_digest_b64u) > 0),
  CHECK (length(descriptor_digest_b64u) > 0),
  CHECK (json_valid(descriptor_json)),
  CHECK (issued_at_ms > 0 AND expires_at_ms > issued_at_ms)
);
CREATE TABLE linked_device_wallet_session_authorizations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  key_manifest_digest_b64u TEXT NOT NULL,
  permission_json TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  revoked_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, tenant_id, authorization_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, wallet_session_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, quota_id),
  CHECK (length(authorization_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(quota_id) > 0),
  CHECK (length(key_manifest_digest_b64u) > 0),
  CHECK (json_valid(permission_json)),
  CHECK (revocation_epoch >= 0),
  CHECK (lifecycle_kind IN ('active', 'revoked')),
  CHECK (issued_at_ms > 0 AND expires_at_ms > issued_at_ms),
  CHECK (
    (lifecycle_kind = 'active' AND revoked_at_ms IS NULL)
    OR (lifecycle_kind = 'revoked' AND revoked_at_ms IS NOT NULL AND revoked_at_ms >= issued_at_ms)
  )
);
CREATE TABLE linked_device_wallet_session_quotas (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  remaining_uses INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, tenant_id, quota_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, wallet_session_id),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id, tenant_id, authorization_id
  ) REFERENCES linked_device_wallet_session_authorizations(
    namespace, org_id, project_id, env_id, tenant_id, authorization_id
  ),
  CHECK (length(quota_id) > 0),
  CHECK (length(authorization_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (remaining_uses >= 0),
  CHECK (lifecycle_kind IN ('active', 'exhausted', 'revoked')),
  CHECK (
    (remaining_uses > 0 AND lifecycle_kind = 'active')
    OR (remaining_uses = 0 AND lifecycle_kind IN ('exhausted', 'revoked'))
  ),
  CHECK (expires_at_ms > 0)
);
CREATE TABLE near_public_keys (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  kind TEXT NOT NULL,
  signer_slot INTEGER,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  removed_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, user_id, public_key),
  CHECK (length(user_id) > 0),
  CHECK (length(public_key) > 0),
  CHECK (kind IN ('threshold', 'local', 'backup', 'ephemeral')),
  CHECK (signer_slot IS NULL OR signer_slot >= 1),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0),
  CHECK (removed_at_ms IS NULL OR removed_at_ms > 0)
);
CREATE TABLE "recovery_executions" (
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
CREATE TABLE "recovery_sessions" (
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
CREATE TABLE registration_ceremony_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
CREATE TABLE registration_ceremony_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  record_scope TEXT NOT NULL,
  record_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  updated_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  PRIMARY KEY (namespace, org_id, project_id, env_id, record_scope, record_id),
  CHECK (version > 0),
  CHECK (expires_at_ms > 0),
  CHECK (json_valid(record_json))
);
CREATE TABLE reusable_wallet_sessions (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  authority_digest TEXT NOT NULL,
  mint_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL, authorization_id TEXT,
  PRIMARY KEY (namespace, tenant_id, wallet_session_id),
  UNIQUE (namespace, tenant_id, quota_id),
  FOREIGN KEY (namespace, tenant_id, quota_id)
    REFERENCES authorization_wallet_session_quotas(namespace, tenant_id, quota_id),
  UNIQUE (namespace, tenant_id, mint_id),
  CHECK (lifecycle_kind IN ('active', 'superseded')),
  CHECK (expires_at_ms > created_at_ms)
);
CREATE TABLE router_ab_normal_signing_admission_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  signing_root_version TEXT NOT NULL,
  record_kind TEXT NOT NULL,
  record_key TEXT NOT NULL,
  decision TEXT,
  retry_after_ms INTEGER,
  request_id TEXT,
  lifecycle_id TEXT,
  expires_at_ms INTEGER,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    signing_root_version,
    record_kind,
    record_key
  ),
  CHECK (record_kind IN ('project_policy', 'abuse', 'quota')),
  CHECK (updated_at_ms >= 0),
  CHECK (
    (record_kind = 'project_policy'
      AND decision IN ('allowed', 'rejected')
      AND request_id IS NULL
      AND lifecycle_id IS NULL
      AND expires_at_ms IS NULL)
    OR
    (record_kind = 'abuse'
      AND decision IN ('allowed', 'rate_limited', 'rejected')
      AND request_id IS NULL
      AND lifecycle_id IS NULL
      AND expires_at_ms IS NULL)
    OR
    (record_kind = 'quota'
      AND decision IS NULL
      AND retry_after_ms IS NULL
      AND length(request_id) > 0
      AND length(lifecycle_id) > 0
      AND expires_at_ms > updated_at_ms)
  ),
  CHECK (
    (decision IN ('rejected', 'rate_limited') AND retry_after_ms > 0)
    OR
    (decision = 'allowed' AND retry_after_ms IS NULL)
    OR
    (record_kind = 'quota' AND retry_after_ms IS NULL)
  )
);
CREATE TABLE router_ab_yao_capability_replacements (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation_fingerprint TEXT NOT NULL,
  previous_capability_binding_json TEXT NOT NULL,
  next_capability_binding_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, operation_id),
  CHECK (length(operation_id) > 0),
  CHECK (length(operation_fingerprint) > 0),
  CHECK (json_valid(previous_capability_binding_json)),
  CHECK (json_valid(next_capability_binding_json)),
  CHECK (created_at_ms >= 0)
);
CREATE TABLE router_ab_yao_versioned_json_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
CREATE TABLE router_ab_yao_versioned_json_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  record_key TEXT NOT NULL,
  version INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  updated_at_ms INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  PRIMARY KEY (namespace, org_id, project_id, env_id, record_key),
  CHECK (version > 0),
  CHECK (json_valid(record_json))
);
CREATE TABLE vault_proxy_secrets (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  destination TEXT NOT NULL,
  sealed_secret_b64u TEXT NOT NULL,
  nonce_b64u TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, vault_id, item_id),
  CHECK (length(destination) > 0),
  CHECK (length(sealed_secret_b64u) > 0),
  CHECK (length(nonce_b64u) > 0),
  CHECK (created_at_ms > 0)
);
CREATE TABLE verified_grant_evidence_sets (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  evidence_set_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  evidence_set_digest TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  lane_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  display_digest TEXT NOT NULL,
  assurance TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, evidence_set_id),
  FOREIGN KEY (namespace, tenant_id, session_id)
    REFERENCES authorization_sessions(namespace, tenant_id, session_id),
  CHECK (json_valid(evidence_json)),
  CHECK (assurance IN ('session', 'step_up')),
  CHECK (
    (capability_kind = 'vault_access'
      AND operation_kind IN ('vault.proxy_use', 'vault.reveal'))
    OR (capability_kind = 'near_ed25519_mpc_signing'
      AND operation_kind IN (
        'near.sign_transaction',
        'near.sign_delegate_action',
        'near.sign_nep413_message',
        'near.export_key'
      ))
    OR (capability_kind = 'evm_ecdsa_mpc_signing'
      AND operation_kind IN ('evm.sign_transaction', 'evm.export_key'))
  )
);
CREATE TABLE "wallet_auth_methods" (
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
CREATE TABLE wallet_ecdsa_pending_session_activations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  lifecycle_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    lifecycle_id,
    request_id
  ),
  CHECK (json_valid(record_json)),
  CHECK (expires_at_ms > 0)
);
CREATE TABLE "wallet_signers" (
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
CREATE TABLE "wallets" (
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
CREATE TABLE webauthn_authenticators (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  credential_id_b64u TEXT NOT NULL,
  credential_public_key_b64u TEXT NOT NULL,
  counter INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL, device_info_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (namespace, org_id, project_id, env_id, user_id, credential_id_b64u),
  CHECK (length(user_id) > 0),
  CHECK (length(credential_id_b64u) > 0),
  CHECK (length(credential_public_key_b64u) > 0),
  CHECK (counter >= 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0)
);
CREATE TABLE "webauthn_challenges" (
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
CREATE TABLE "webauthn_credential_bindings" (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  credential_id_b64u TEXT NOT NULL,
  user_id TEXT NOT NULL,
  signer_slot INTEGER,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, rp_id, credential_id_b64u),
  CHECK (length(rp_id) > 0),
  CHECK (length(credential_id_b64u) > 0),
  CHECK (length(user_id) > 0),
  CHECK (signer_slot IS NULL OR signer_slot >= 1),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0)
);
CREATE INDEX authorized_operation_audit_fingerprint_idx
  ON authorized_operation_audit_events(namespace, tenant_id, operation_fingerprint_digest);
CREATE INDEX authorized_operation_audit_linked_device_activity_idx
  ON authorized_operation_audit_events(
    namespace,
    authorization_grant_kind,
    linked_scope_org_id,
    linked_scope_project_id,
    linked_scope_env_id,
    linked_wallet_id,
    linked_enrollment_id,
    linked_device_id
  );
CREATE INDEX authorized_operations_tenant_fingerprint_idx
  ON authorized_operations(namespace, tenant_id, operation_fingerprint_digest);
CREATE INDEX authorized_operations_tenant_lifecycle_idx
  ON authorized_operations(namespace, tenant_id, lifecycle_kind);
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
CREATE INDEX email_otp_grants_expires_idx
  ON email_otp_grants (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE INDEX email_otp_rate_limits_reset_idx
  ON email_otp_rate_limits (
    namespace,
    org_id,
    project_id,
    env_id,
    reset_at_ms
  );
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
CREATE INDEX email_otp_unlock_challenges_expires_idx
  ON email_otp_unlock_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
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
CREATE INDEX email_recovery_preparations_account_idx
  ON email_recovery_preparations (
    namespace,
    org_id,
    project_id,
    env_id,
    account_id,
    created_at_ms
  );
CREATE INDEX email_recovery_preparations_expires_idx
  ON email_recovery_preparations (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE INDEX google_email_otp_session_exchange_journals_expires_idx
  ON google_email_otp_session_exchange_journals (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE INDEX identity_links_user_idx
  ON identity_links (
    namespace,
    org_id,
    project_id,
    env_id,
    user_id,
    created_at_ms
  );
CREATE INDEX idx_authorization_sessions_expiry
  ON authorization_sessions(namespace, tenant_id, expires_at_ms);
CREATE INDEX idx_registration_ceremony_records_expiry
  ON registration_ceremony_records (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE UNIQUE INDEX idx_reusable_wallet_sessions_active_authority
  ON reusable_wallet_sessions(namespace, tenant_id, wallet_id, authority_digest)
  WHERE lifecycle_kind = 'active';
CREATE INDEX idx_reusable_wallet_sessions_principal
  ON reusable_wallet_sessions(namespace, tenant_id, principal_id, lifecycle_kind, expires_at_ms);
CREATE INDEX idx_router_ab_normal_signing_admission_expiry
  ON router_ab_normal_signing_admission_records (
    namespace,
    org_id,
    project_id,
    env_id,
    record_kind,
    expires_at_ms
  );
CREATE INDEX idx_router_ab_yao_versioned_json_records_updated
  ON router_ab_yao_versioned_json_records (
    namespace,
    org_id,
    project_id,
    env_id,
    updated_at_ms
  );
CREATE INDEX idx_verified_grant_evidence_sets_expiry
  ON verified_grant_evidence_sets(namespace, tenant_id, expires_at_ms);
CREATE INDEX lane_enrollments_wallet_idx
  ON lane_enrollments(namespace, org_id, project_id, env_id, wallet_id, updated_at_ms);
CREATE UNIQUE INDEX lane_product_epochs_one_active_idx
  ON lane_product_epochs(namespace, org_id, project_id, env_id, wallet_key_id, lane_id)
  WHERE state = 'active';
CREATE INDEX lane_product_epochs_wallet_active_idx
  ON lane_product_epochs(namespace, org_id, project_id, env_id, wallet_id, state, updated_at_ms);
CREATE INDEX lane_protocol_operations_enrollment_idx
  ON lane_protocol_operations(namespace, org_id, project_id, env_id, enrollment_id, operation_id);
CREATE UNIQUE INDEX linked_device_owner_planning_snapshots_operation_idx
  ON linked_device_owner_planning_snapshots(
    namespace, org_id, project_id, env_id, operation_id
  );
CREATE INDEX linked_device_owner_planning_snapshots_wallet_idx
  ON linked_device_owner_planning_snapshots(
    namespace, org_id, project_id, env_id, wallet_id, expires_at_ms
  );
CREATE INDEX linked_device_request_proof_nonces_expiry_idx
  ON linked_device_request_proof_nonces(
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE INDEX linked_device_session_transcripts_digest_idx
  ON linked_device_session_transcripts(
    namespace,
    org_id,
    project_id,
    env_id,
    digest_b64u
  );
CREATE INDEX linked_device_sessions_state_idx
  ON linked_device_sessions(namespace, org_id, project_id, env_id, state, updated_at_ms);
CREATE UNIQUE INDEX linked_device_target_credentials_credential_idx
  ON linked_device_target_credentials(
    namespace,
    org_id,
    project_id,
    env_id,
    credential_id_b64u
  )
  WHERE credential_id_b64u IS NOT NULL;
CREATE INDEX linked_device_target_deployment_descriptors_wallet_idx
  ON linked_device_target_deployment_descriptors(
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE INDEX linked_device_wallet_session_authorizations_identity_idx
  ON linked_device_wallet_session_authorizations(
    namespace, org_id, project_id, env_id, tenant_id, device_id, wallet_session_id
  );
CREATE INDEX linked_device_wallet_session_quotas_identity_idx
  ON linked_device_wallet_session_quotas(
    namespace, org_id, project_id, env_id, tenant_id, authorization_id, wallet_session_id
  );
CREATE INDEX near_public_keys_user_idx
  ON near_public_keys (
    namespace,
    org_id,
    project_id,
    env_id,
    user_id,
    signer_slot,
    created_at_ms
  );
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
CREATE INDEX recovery_sessions_expiry_idx
  ON recovery_sessions (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE INDEX recovery_sessions_near_account_idx
  ON recovery_sessions (
    namespace,
    org_id,
    project_id,
    env_id,
    near_account_id,
    updated_at_ms DESC
  );
CREATE UNIQUE INDEX reusable_wallet_sessions_authorization_idx
  ON reusable_wallet_sessions(namespace, tenant_id, authorization_id);
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
CREATE INDEX wallet_signers_chain_target_idx
  ON wallet_signers (
    namespace,
    org_id,
    project_id,
    env_id,
    signer_family,
    chain_target_key
  );
CREATE INDEX wallet_signers_wallet_idx
  ON wallet_signers (namespace, org_id, project_id, env_id, wallet_id, signer_family);
CREATE INDEX webauthn_authenticators_user_idx
  ON webauthn_authenticators (
    namespace,
    org_id,
    project_id,
    env_id,
    user_id,
    created_at_ms
  );
CREATE INDEX webauthn_challenges_expiry_idx
  ON webauthn_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    challenge_kind,
    expires_at_ms
  );
CREATE INDEX webauthn_credential_bindings_user_idx
  ON webauthn_credential_bindings (
    namespace,
    org_id,
    project_id,
    env_id,
    user_id,
    rp_id,
    signer_slot
  );
CREATE TRIGGER authorized_operation_audit_claim
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
BEGIN
  INSERT INTO authorized_operation_audit_events (
    namespace, tenant_id, audit_event_id, authorized_operation_id,
    operation_fingerprint_digest, authorization_source_kind, authorization_id,
    authorization_grant_kind, evidence_set_digest, quota_id, material_activation_id,
    material_activation_capability, material_activation_owner,
    material_activation_key_binding, material_activation_lifecycle_binding,
    material_activation_signing_worker, linked_wallet_id, linked_enrollment_id,
    linked_device_id, linked_wallet_key_id, linked_lane_id, linked_lane_share_epoch,
    linked_revocation_epoch, linked_scope_org_id, linked_scope_project_id,
    linked_scope_env_id, result_kind, claimed_at_ms, completed_at_ms
  ) VALUES (
    NEW.namespace, NEW.tenant_id, NEW.audit_event_id, NEW.authorized_operation_id,
    NEW.operation_fingerprint_digest, NEW.authorization_source_kind, NEW.authorization_id,
    NEW.authorization_grant_kind, NEW.evidence_set_digest, NEW.quota_id,
    NEW.material_activation_id, NEW.material_activation_capability,
    NEW.material_activation_owner, NEW.material_activation_key_binding,
    NEW.material_activation_lifecycle_binding, NEW.material_activation_signing_worker,
    NEW.linked_wallet_id, NEW.linked_enrollment_id, NEW.linked_device_id,
    NEW.linked_wallet_key_id, NEW.linked_lane_id, NEW.linked_lane_share_epoch,
    NEW.linked_revocation_epoch, NEW.linked_scope_org_id, NEW.linked_scope_project_id,
    NEW.linked_scope_env_id, NEW.result_kind, NEW.claimed_at_ms, NEW.completed_at_ms
  );
END;
CREATE TRIGGER authorized_operation_audit_complete
AFTER UPDATE OF lifecycle_kind ON authorized_operations
WHEN OLD.lifecycle_kind = 'claimed' AND NEW.lifecycle_kind = 'completed'
BEGIN
  UPDATE authorized_operation_audit_events
     SET result_kind = NEW.result_kind,
         completed_at_ms = NEW.completed_at_ms
   WHERE namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND authorized_operation_id = NEW.authorized_operation_id;

  SELECT CASE
    WHEN changes() != 1
    THEN RAISE(ABORT, 'authorized_operation_audit_completion_rejected')
  END;
END;
CREATE TRIGGER authorized_operation_complete_atomic
BEFORE UPDATE OF lifecycle_kind ON authorized_operations
WHEN OLD.lifecycle_kind = 'completed' OR NEW.lifecycle_kind != 'completed'
BEGIN
  SELECT RAISE(ABORT, 'authorized_operation_lifecycle_transition_rejected');
END;
CREATE TRIGGER authorized_operation_grant_shape_guard
BEFORE INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND (
    NEW.authorization_source_kind NOT IN ('authorization_grant', 'verified_step_up')
    OR (NEW.authorization_source_kind = 'authorization_grant'
      AND (NEW.authorization_grant_kind IS NULL OR NEW.authorization_grant_kind NOT IN (
        'wallet_session_authorization',
        'linked_device_wallet_session_authorization_v1'
      )))
    OR (NEW.authorization_source_kind = 'authorization_grant'
      AND NEW.authorization_grant_kind = 'linked_device_wallet_session_authorization_v1'
      AND (NEW.linked_scope_org_id IS NULL
        OR NEW.linked_scope_project_id IS NULL
        OR NEW.linked_scope_env_id IS NULL))
    OR (NEW.authorization_source_kind = 'verified_step_up'
      AND NEW.authorization_grant_kind IS NOT NULL)
  )
BEGIN
  SELECT RAISE(ABORT, 'authorization_grant_kind_rejected');
END;
CREATE TRIGGER authorized_operation_linked_grant_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND NEW.authorization_source_kind = 'authorization_grant'
  AND NEW.authorization_grant_kind = 'linked_device_wallet_session_authorization_v1'
BEGIN
  SELECT CASE
    WHEN NEW.quota_kind != 'consume_reusable_wallet_session'
      OR NEW.capability_kind NOT IN ('near_ed25519_mpc_signing', 'evm_ecdsa_mpc_signing')
      OR NEW.operation_kind IN ('near.export_key', 'evm.export_key')
      OR NOT EXISTS (
        SELECT 1
          FROM linked_device_wallet_session_authorizations AS grant_record
          JOIN lane_enrollments AS enrollment
            ON enrollment.namespace = grant_record.namespace
           AND enrollment.org_id = grant_record.org_id
           AND enrollment.project_id = grant_record.project_id
           AND enrollment.env_id = grant_record.env_id
           AND enrollment.org_id = NEW.linked_scope_org_id
           AND enrollment.project_id = NEW.linked_scope_project_id
           AND enrollment.env_id = NEW.linked_scope_env_id
           AND enrollment.enrollment_id = grant_record.enrollment_id
           AND enrollment.wallet_id = grant_record.wallet_id
           AND json_extract(enrollment.lifecycle_json, '$.state') = 'active'
           AND json_extract(enrollment.lifecycle_json, '$.manifestDigestB64u') = grant_record.key_manifest_digest_b64u
         JOIN lane_product_epochs AS product
            ON product.namespace = grant_record.namespace
           AND product.org_id = grant_record.org_id
           AND product.project_id = grant_record.project_id
           AND product.env_id = grant_record.env_id
           AND product.org_id = NEW.linked_scope_org_id
           AND product.project_id = NEW.linked_scope_project_id
           AND product.env_id = NEW.linked_scope_env_id
           AND product.enrollment_id = grant_record.enrollment_id
           AND product.wallet_id = grant_record.wallet_id
           AND product.wallet_id = NEW.linked_wallet_id
           AND product.enrollment_id = NEW.linked_enrollment_id
           AND product.wallet_key_id = NEW.linked_wallet_key_id
           AND product.lane_id = NEW.linked_lane_id
           AND product.lane_share_epoch = NEW.linked_lane_share_epoch
           AND product.target_material_activation_id = NEW.material_activation_id
           AND product.revocation_epoch = NEW.linked_revocation_epoch
           AND product.state = 'active'
           AND product.lane_kind = 'linked_device'
           AND (
             (NEW.capability_kind = 'near_ed25519_mpc_signing' AND product.key_family = 'ed25519')
             OR (NEW.capability_kind = 'evm_ecdsa_mpc_signing' AND product.key_family = 'ecdsa_secp256k1')
           )
           AND json_extract(product.material_activation_json, '$.activationId') = NEW.material_activation_id
           AND json_extract(product.material_activation_json, '$.capability') = NEW.material_activation_capability
           AND json_extract(product.material_activation_json, '$.materialOwner') = NEW.material_activation_owner
           AND json_extract(product.material_activation_json, '$.keyBinding') = NEW.material_activation_key_binding
           AND json_extract(product.material_activation_json, '$.lifecycleBinding') = NEW.material_activation_lifecycle_binding
           AND json_extract(product.material_activation_json, '$.signingWorker') = NEW.material_activation_signing_worker
         JOIN lane_protocol_operations AS protocol
          ON protocol.namespace = product.namespace
          AND protocol.org_id = product.org_id
          AND protocol.project_id = product.project_id
          AND protocol.env_id = product.env_id
          AND protocol.org_id = NEW.linked_scope_org_id
          AND protocol.project_id = NEW.linked_scope_project_id
          AND protocol.env_id = NEW.linked_scope_env_id
          AND protocol.operation_id = product.operation_id
          AND protocol.enrollment_id = product.enrollment_id
          AND protocol.enrollment_id = NEW.linked_enrollment_id
          AND protocol.wallet_id = NEW.linked_wallet_id
          AND protocol.wallet_key_id = NEW.linked_wallet_key_id
          AND protocol.target_lane_id = NEW.linked_lane_id
          AND protocol.target_lane_share_epoch = NEW.linked_lane_share_epoch
          AND protocol.target_material_activation_id = product.target_material_activation_id
          AND protocol.target_material_activation_id = NEW.material_activation_id
          AND json_extract(protocol.lifecycle_json, '$.state') = 'active'
         WHERE grant_record.namespace = NEW.namespace
           AND grant_record.org_id = NEW.linked_scope_org_id
           AND grant_record.project_id = NEW.linked_scope_project_id
           AND grant_record.env_id = NEW.linked_scope_env_id
           AND grant_record.org_id = product.org_id
           AND grant_record.project_id = product.project_id
           AND grant_record.env_id = product.env_id
           AND grant_record.tenant_id = NEW.tenant_id
           AND grant_record.authorization_id = NEW.authorization_id
           AND grant_record.principal_id = NEW.principal_id
           AND grant_record.quota_id = NEW.quota_id
           AND grant_record.wallet_id = NEW.linked_wallet_id
           AND grant_record.enrollment_id = NEW.linked_enrollment_id
           AND grant_record.device_id = NEW.linked_device_id
           AND grant_record.lifecycle_kind = 'active'
           AND grant_record.expires_at_ms > NEW.claimed_at_ms
           AND json_extract(grant_record.permission_json, '$.kind') = 'owner_equivalent_signing'
           AND json_extract(grant_record.permission_json, '$.administrationScope') = 'signing_only'
           AND json_extract(grant_record.permission_json, '$.localUserPresence') = 'required'
      )
    THEN RAISE(ABORT, 'authorization_linked_device_rejected')
  END;

  UPDATE linked_device_wallet_session_quotas
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'exhausted' ELSE 'active' END
   WHERE NEW.quota_kind = 'consume_reusable_wallet_session'
     AND namespace = NEW.namespace
     AND org_id = NEW.linked_scope_org_id
     AND project_id = NEW.linked_scope_project_id
     AND env_id = NEW.linked_scope_env_id
     AND tenant_id = NEW.tenant_id
     AND quota_id = NEW.quota_id
     AND authorization_id = NEW.authorization_id
     AND principal_id = NEW.principal_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;
END;
CREATE TRIGGER authorized_operation_owner_grant_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND NEW.authorization_source_kind = 'authorization_grant'
  AND NEW.authorization_grant_kind = 'wallet_session_authorization'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
        SELECT 1
          FROM reusable_wallet_sessions AS session
         WHERE session.namespace = NEW.namespace
           AND session.tenant_id = NEW.tenant_id
           AND session.authorization_id = NEW.authorization_id
           AND session.principal_id = NEW.principal_id
           AND (NEW.quota_kind = 'quota_neutral' OR session.quota_id = NEW.quota_id)
           AND session.lifecycle_kind = 'active'
           AND session.expires_at_ms > NEW.claimed_at_ms
      )
    THEN RAISE(ABORT, 'authorization_wallet_session_rejected')
  END;

  UPDATE authorization_wallet_session_quotas
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'exhausted' ELSE 'active' END
   WHERE NEW.quota_kind = 'consume_reusable_wallet_session'
     AND namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND quota_id = NEW.quota_id
     AND wallet_session_id = (
       SELECT session.wallet_session_id
         FROM reusable_wallet_sessions AS session
        WHERE session.namespace = NEW.namespace
          AND session.tenant_id = NEW.tenant_id
          AND session.authorization_id = NEW.authorization_id
          AND session.quota_id = NEW.quota_id
     )
     AND principal_id = NEW.principal_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;
END;
CREATE TRIGGER authorized_operation_step_up_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND NEW.authorization_source_kind = 'verified_step_up'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
        SELECT 1
          FROM verified_grant_evidence_sets AS evidence
          JOIN authorization_sessions AS session
            ON session.namespace = evidence.namespace
           AND session.tenant_id = evidence.tenant_id
           AND session.session_id = evidence.session_id
           AND session.principal_id = evidence.principal_id
         WHERE evidence.namespace = NEW.namespace
           AND evidence.tenant_id = NEW.tenant_id
           AND evidence.evidence_set_digest = NEW.evidence_set_digest
           AND evidence.principal_id = NEW.principal_id
           AND evidence.capability_kind = NEW.capability_kind
           AND evidence.operation_kind = NEW.operation_kind
           AND evidence.lane_digest = NEW.lane_digest
           AND evidence.intent_digest = NEW.intent_digest
           AND evidence.display_digest = NEW.display_digest
           AND evidence.assurance = 'step_up'
           AND evidence.expires_at_ms > NEW.claimed_at_ms
           AND session.lifecycle_kind = 'active'
           AND session.expires_at_ms > NEW.claimed_at_ms
      )
    THEN RAISE(ABORT, 'authorization_evidence_claim_rejected')
  END;
END;
CREATE TRIGGER lane_cas_guard_no_delete
BEFORE DELETE ON lane_cas_guard
BEGIN
  SELECT RAISE(ABORT, 'lane_cas_guard is immutable');
END;
CREATE TRIGGER linked_device_wallet_session_authorization_identity_insert
BEFORE INSERT ON linked_device_wallet_session_authorizations
WHEN NEW.principal_id != 'linked-device:' || NEW.device_id
  OR NEW.wallet_session_id = NEW.authorization_id
  OR NEW.wallet_session_id = NEW.quota_id
  OR NEW.authorization_id = NEW.quota_id
  OR json_extract(NEW.permission_json, '$.kind') IS NOT 'owner_equivalent_signing'
  OR json_extract(NEW.permission_json, '$.administrationScope') IS NOT 'signing_only'
  OR json_extract(NEW.permission_json, '$.localUserPresence') IS NOT 'required'
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_authorization_identity_rejected');
END;
CREATE TRIGGER linked_device_wallet_session_authorization_identity_update
BEFORE UPDATE OF principal_id, device_id, authorization_id, wallet_session_id, quota_id, permission_json
ON linked_device_wallet_session_authorizations
WHEN NEW.principal_id != 'linked-device:' || NEW.device_id
  OR NEW.wallet_session_id = NEW.authorization_id
  OR NEW.wallet_session_id = NEW.quota_id
  OR NEW.authorization_id = NEW.quota_id
  OR json_extract(NEW.permission_json, '$.kind') IS NOT 'owner_equivalent_signing'
  OR json_extract(NEW.permission_json, '$.administrationScope') IS NOT 'signing_only'
  OR json_extract(NEW.permission_json, '$.localUserPresence') IS NOT 'required'
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_authorization_identity_rejected');
END;
CREATE TRIGGER linked_device_wallet_session_authorization_revoke_atomic
AFTER UPDATE OF lifecycle_kind ON linked_device_wallet_session_authorizations
WHEN OLD.lifecycle_kind = 'active' AND NEW.lifecycle_kind = 'revoked'
BEGIN
  UPDATE linked_device_wallet_session_quotas
     SET remaining_uses = 0,
         lifecycle_kind = 'revoked'
   WHERE namespace = NEW.namespace
     AND org_id = NEW.org_id
     AND project_id = NEW.project_id
     AND env_id = NEW.env_id
     AND tenant_id = NEW.tenant_id
     AND authorization_id = NEW.authorization_id
     AND quota_id = NEW.quota_id
     AND lifecycle_kind != 'revoked';

  SELECT CASE
    WHEN changes() != 1
    THEN RAISE(ABORT, 'linked_device_wallet_session_quota_revoke_rejected')
  END;
END;
CREATE TRIGGER linked_device_wallet_session_quota_revoke_guard
BEFORE UPDATE OF lifecycle_kind, remaining_uses ON linked_device_wallet_session_quotas
WHEN NEW.lifecycle_kind = 'revoked'
  AND NOT EXISTS (
    SELECT 1
      FROM linked_device_wallet_session_authorizations AS authorization
     WHERE authorization.namespace = NEW.namespace
       AND authorization.org_id = NEW.org_id
       AND authorization.project_id = NEW.project_id
       AND authorization.env_id = NEW.env_id
       AND authorization.tenant_id = NEW.tenant_id
       AND authorization.authorization_id = NEW.authorization_id
       AND authorization.quota_id = NEW.quota_id
       AND authorization.lifecycle_kind = 'revoked'
  )
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_quota_revoke_rejected');
END;
CREATE TRIGGER registration_ceremony_cas_guard_no_delete
BEFORE DELETE ON registration_ceremony_cas_guard
BEGIN
  SELECT RAISE(ABORT, 'registration_ceremony_cas_guard is immutable');
END;
CREATE TRIGGER reusable_wallet_session_authorization_identity_insert
BEFORE INSERT ON reusable_wallet_sessions
WHEN NEW.authorization_id IS NULL
  OR trim(NEW.authorization_id) = ''
  OR NEW.authorization_id = NEW.wallet_session_id
  OR NEW.authorization_id = NEW.quota_id
  OR NEW.wallet_session_id = NEW.quota_id
BEGIN
  SELECT RAISE(ABORT, 'reusable_wallet_session_authorization_identity_rejected');
END;
CREATE TRIGGER reusable_wallet_session_authorization_identity_update
BEFORE UPDATE OF authorization_id, wallet_session_id ON reusable_wallet_sessions
WHEN NEW.authorization_id IS NULL
  OR trim(NEW.authorization_id) = ''
  OR NEW.authorization_id = NEW.wallet_session_id
  OR NEW.authorization_id = NEW.quota_id
  OR NEW.wallet_session_id = NEW.quota_id
BEGIN
  SELECT RAISE(ABORT, 'reusable_wallet_session_authorization_identity_rejected');
END;
CREATE TRIGGER router_ab_yao_versioned_json_cas_guard_no_delete
BEFORE DELETE ON router_ab_yao_versioned_json_cas_guard
BEGIN
  SELECT RAISE(ABORT, 'router_ab_yao_versioned_json_cas_guard is immutable');
END;
CREATE TRIGGER trg_hosted_wallet_exchange_create_target_session
AFTER UPDATE OF lifecycle_kind ON hosted_wallet_session_exchange_codes
WHEN OLD.lifecycle_kind = 'issued' AND NEW.lifecycle_kind = 'consumed'
BEGIN
  INSERT INTO authorization_sessions (
    namespace,
    tenant_id,
    session_id,
    principal_id,
    auth_source_kind,
    auth_source_json,
    device_id,
    audience_kind,
    audience_json,
    app_session_version,
    assurance,
    lifecycle_kind,
    created_at_ms,
    expires_at_ms
  )
  SELECT
    source.namespace,
    source.tenant_id,
    NEW.target_session_id,
    source.principal_id,
    source.auth_source_kind,
    source.auth_source_json,
    source.device_id,
    'hosted_wallet_iframe',
    json_object('appOrigin', NEW.app_origin, 'walletOrigin', NEW.wallet_origin),
    source.app_session_version,
    source.assurance,
    'active',
    NEW.consumed_at_ms,
    source.expires_at_ms
  FROM authorization_sessions AS source
  WHERE source.namespace = NEW.namespace
    AND source.tenant_id = NEW.tenant_id
    AND source.session_id = NEW.source_session_id
    AND source.lifecycle_kind = 'active'
    AND source.expires_at_ms > NEW.consumed_at_ms;

  SELECT CASE
    WHEN changes() != 1
    THEN RAISE(ABORT, 'hosted_wallet_source_session_unavailable')
  END;
END;
