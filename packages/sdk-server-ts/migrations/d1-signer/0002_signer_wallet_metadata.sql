CREATE TABLE IF NOT EXISTS wallets (
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

CREATE TABLE IF NOT EXISTS wallet_signers (
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

CREATE INDEX IF NOT EXISTS wallet_signers_wallet_idx
  ON wallet_signers (namespace, org_id, project_id, env_id, wallet_id, signer_family);

CREATE INDEX IF NOT EXISTS wallet_signers_chain_target_idx
  ON wallet_signers (
    namespace,
    org_id,
    project_id,
    env_id,
    signer_family,
    chain_target_key
  );

CREATE TABLE IF NOT EXISTS wallet_auth_methods (
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

CREATE INDEX IF NOT EXISTS wallet_auth_methods_wallet_idx
  ON wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    rp_id,
    status
  );

CREATE INDEX IF NOT EXISTS wallet_auth_methods_identifier_idx
  ON wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    kind,
    auth_identifier_key
  );

CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_passkey_uidx
  ON wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    rp_id,
    credential_id_b64u
  )
  WHERE kind = 'passkey' AND credential_id_b64u IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_email_uidx
  ON wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    email_hash_hex
  )
  WHERE kind = 'email_otp' AND email_hash_hex IS NOT NULL;
