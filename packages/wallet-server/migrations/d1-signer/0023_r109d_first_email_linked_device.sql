-- Refactor 109D: a linked Email OTP target may establish the wallet's first
-- Email enrollment. The old grant shape required a base Email method and
-- cannot represent that branch, so in-flight grants are discarded at the
-- persistence boundary and the table is recreated with an explicit branch.

DROP INDEX IF EXISTS linked_device_email_otp_grants_session_idx;
DROP INDEX IF EXISTS linked_device_email_otp_grants_expiry_idx;
DROP TABLE IF EXISTS linked_device_email_otp_grants;

CREATE TABLE linked_device_email_otp_grants (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  grant_token_digest_b64u TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  target_factor TEXT NOT NULL,
  target_preparation_digest_b64u TEXT NOT NULL,
  target_email TEXT NOT NULL,
  enrollment_kind TEXT NOT NULL,
  email_hash_hex TEXT NOT NULL,
  registration_authority_id TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  base_wallet_auth_method_id TEXT,
  linked_owner_auth_method_id TEXT NOT NULL,
  authority_digest_b64u TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  state TEXT NOT NULL,
  record_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, grant_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, base_wallet_auth_method_id)
    REFERENCES wallet_auth_methods(namespace, org_id, project_id, env_id, wallet_auth_method_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(grant_id) > 0),
  CHECK (length(grant_token_digest_b64u) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(link_session_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (target_factor = 'email_otp'),
  CHECK (length(target_preparation_digest_b64u) > 0),
  CHECK (length(target_email) > 0),
  CHECK (enrollment_kind IN ('existing_enrollment', 'new_enrollment')),
  CHECK (length(email_hash_hex) > 0),
  CHECK (length(registration_authority_id) > 0),
  CHECK (length(provider_user_id) > 0),
  CHECK (enrollment_kind = 'new_enrollment' OR length(base_wallet_auth_method_id) > 0),
  CHECK (enrollment_kind = 'new_enrollment' OR base_wallet_auth_method_id IS NOT NULL),
  CHECK (enrollment_kind = 'existing_enrollment' OR base_wallet_auth_method_id IS NULL),
  CHECK (length(linked_owner_auth_method_id) > 0),
  CHECK (length(authority_digest_b64u) > 0),
  CHECK (length(challenge_id) > 0),
  CHECK (state IN ('issued', 'consumed')),
  CHECK (json_valid(record_json)),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (
    (state = 'issued' AND consumed_at_ms IS NULL)
    OR (state = 'consumed' AND consumed_at_ms >= issued_at_ms)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.kind') = 'linked_device_email_otp_grant_record_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.grantId') = grant_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.grantTokenDigestB64u') = grant_token_digest_b64u, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.linkSessionId') = link_session_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.enrollmentId') = enrollment_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.deviceId') = device_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.targetFactor.kind') = target_factor, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.targetPreparationDigestB64u') = target_preparation_digest_b64u, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.targetEmail') = target_email, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.enrollment.kind') = enrollment_kind, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.emailHashHex') = email_hash_hex, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.registrationAuthorityId') = registration_authority_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.providerUserId') = provider_user_id, 0)),
  CHECK (
    (enrollment_kind = 'existing_enrollment'
      AND COALESCE(json_extract(record_json, '$.baseWalletAuthMethodId') = base_wallet_auth_method_id, 0))
    OR
    (enrollment_kind = 'new_enrollment'
      AND json_type(record_json, '$.baseWalletAuthMethodId') IS NULL)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.linkedOwnerAuthMethodId') = linked_owner_auth_method_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.authorityDigestB64u') = authority_digest_b64u, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.challengeId') = challenge_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.state.kind') = state, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.issuedAtMs') = issued_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0)),
  CHECK (
    consumed_at_ms IS NULL
    OR COALESCE(json_extract(record_json, '$.state.consumedAtMs') = consumed_at_ms, 0)
  )
);

CREATE INDEX linked_device_email_otp_grants_session_idx
  ON linked_device_email_otp_grants (
    namespace, org_id, project_id, env_id, link_session_id, state, expires_at_ms
  );
CREATE INDEX linked_device_email_otp_grants_expiry_idx
  ON linked_device_email_otp_grants (namespace, org_id, project_id, env_id, expires_at_ms);
