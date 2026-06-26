CREATE TABLE IF NOT EXISTS signer_wallets (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id),
  CHECK (length(wallet_id) > 0),
  CHECK (length(rp_id) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms >= 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE INDEX IF NOT EXISTS signer_wallets_rp_idx
  ON signer_wallets (namespace, org_id, project_id, env_id, rp_id, created_at_ms);

CREATE TABLE IF NOT EXISTS signer_wallet_signers (
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
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE INDEX IF NOT EXISTS signer_wallet_signers_wallet_idx
  ON signer_wallet_signers (namespace, org_id, project_id, env_id, wallet_id, signer_family);

CREATE INDEX IF NOT EXISTS signer_wallet_signers_chain_target_idx
  ON signer_wallet_signers (
    namespace,
    org_id,
    project_id,
    env_id,
    signer_family,
    chain_target_key
  );

CREATE TABLE IF NOT EXISTS signer_wallet_auth_methods (
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
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE INDEX IF NOT EXISTS signer_wallet_auth_methods_wallet_idx
  ON signer_wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    rp_id,
    status
  );

CREATE INDEX IF NOT EXISTS signer_wallet_auth_methods_identifier_idx
  ON signer_wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    kind,
    auth_identifier_key
  );

CREATE UNIQUE INDEX IF NOT EXISTS signer_wallet_auth_methods_passkey_uidx
  ON signer_wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    rp_id,
    credential_id_b64u
  )
  WHERE kind = 'passkey' AND credential_id_b64u IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS signer_wallet_auth_methods_email_uidx
  ON signer_wallet_auth_methods (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_id,
    email_hash_hex
  )
  WHERE kind = 'email_otp' AND email_hash_hex IS NOT NULL;
