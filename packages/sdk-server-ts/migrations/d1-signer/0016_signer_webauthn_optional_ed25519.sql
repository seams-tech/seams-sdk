-- Non-blocking Ed25519 provisioning (refactor 94): a passkey wallet may exist
-- before its Ed25519 Yao ceremony has settled, so a credential binding must be
-- writable without an Ed25519 signer.
--
-- `signer_slot` becomes nullable and its `>= 1` check becomes conditional. The
-- denormalized Ed25519 facts (nearAccountId, nearEd25519SigningKeyId,
-- signerSlot) live in record_json and are already absent-tolerant there; this
-- migration only relaxes the column that made the row impossible to insert.
--
-- SQLite cannot drop NOT NULL or a CHECK in place, so the table is rebuilt
-- following the pattern established by 0010_signer_constraint_hardening.sql.

DROP INDEX IF EXISTS webauthn_credential_bindings_user_idx;

DROP TABLE IF EXISTS webauthn_credential_bindings_optional_ed25519;

CREATE TABLE webauthn_credential_bindings_optional_ed25519 (
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

INSERT INTO webauthn_credential_bindings_optional_ed25519 (
  namespace,
  org_id,
  project_id,
  env_id,
  rp_id,
  credential_id_b64u,
  user_id,
  signer_slot,
  record_json,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  rp_id,
  credential_id_b64u,
  user_id,
  signer_slot,
  record_json,
  created_at_ms,
  updated_at_ms
FROM webauthn_credential_bindings;

DROP TABLE webauthn_credential_bindings;
ALTER TABLE webauthn_credential_bindings_optional_ed25519
  RENAME TO webauthn_credential_bindings;

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
