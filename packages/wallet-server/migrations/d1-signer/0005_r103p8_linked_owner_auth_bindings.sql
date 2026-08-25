-- Refactor 103 Phase 8: bind each linked-device enrollment to the canonical
-- owner auth method it created.
--
-- Device 2 becomes an ordinary owner credential, so device management, unlock,
-- Wallet Session issuance, and revocation all need to resolve one exact
-- `wallet_auth_methods` row from one exact enrollment. The foreign key makes
-- that resolution a schema guarantee rather than a nearest-match join, and the
-- unique indexes make "one device, one owner credential, one enrollment"
-- unrepresentable in the other direction too.
--
-- The identity CHECKs mirror `wallet_auth_methods` exactly: the same derived
-- `wallet_auth_method_id` format, the same mutually exclusive Passkey and
-- Email OTP columns. A row that names one credential and points at another
-- cannot be written.
CREATE TABLE linked_device_owner_auth_bindings (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  factor_kind TEXT NOT NULL,
  rp_id TEXT,
  credential_id_b64u TEXT,
  email_hash_hex TEXT,
  registration_authority_id TEXT,
  key_manifest_digest_b64u TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, enrollment_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, wallet_auth_method_id)
    REFERENCES wallet_auth_methods(namespace, org_id, project_id, env_id, wallet_auth_method_id),
  CHECK (length(tenant_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (length(key_manifest_digest_b64u) > 0),
  CHECK (factor_kind IN ('passkey', 'email_otp')),
  CHECK (lifecycle_state IN ('active', 'paused', 'revoked')),
  CHECK (revocation_epoch >= 0),
  CHECK (lifecycle_state <> 'revoked' OR revocation_epoch >= 1),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.kind') = 'linked_device_owner_auth_binding_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.enrollmentId') = enrollment_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.deviceId') = device_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletAuthMethodId') = wallet_auth_method_id, 0)),
  CHECK (
    (
      factor_kind = 'passkey'
      AND rp_id IS NOT NULL
      AND length(rp_id) > 0
      AND credential_id_b64u IS NOT NULL
      AND length(credential_id_b64u) > 0
      AND email_hash_hex IS NULL
      AND registration_authority_id IS NULL
      AND wallet_auth_method_id = 'passkey:' || rp_id || ':' || credential_id_b64u
    )
    OR
    (
      factor_kind = 'email_otp'
      AND rp_id IS NULL
      AND credential_id_b64u IS NULL
      AND email_hash_hex IS NOT NULL
      AND length(email_hash_hex) > 0
      AND registration_authority_id IS NOT NULL
      AND length(registration_authority_id) > 0
      AND wallet_auth_method_id = 'email_otp:' || wallet_id || ':' || email_hash_hex
    )
  )
);

-- One owner credential per linked device, and one linked device per owner
-- credential. Device management fails closed on a duplicate rather than
-- choosing between two cards that claim the same credential.
CREATE UNIQUE INDEX linked_device_owner_auth_bindings_device_idx
  ON linked_device_owner_auth_bindings (namespace, org_id, project_id, env_id, wallet_id, device_id);

CREATE UNIQUE INDEX linked_device_owner_auth_bindings_method_idx
  ON linked_device_owner_auth_bindings (namespace, org_id, project_id, env_id, wallet_id, wallet_auth_method_id);

CREATE INDEX linked_device_owner_auth_bindings_wallet_idx
  ON linked_device_owner_auth_bindings (namespace, org_id, project_id, env_id, wallet_id, lifecycle_state);
