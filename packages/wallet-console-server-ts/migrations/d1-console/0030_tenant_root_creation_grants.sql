CREATE TABLE tenant_root_creation_grants (
  namespace TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  signing_root_id TEXT NOT NULL,
  signing_root_version TEXT NOT NULL,
  identity_digest_b64u TEXT NOT NULL,
  custody_lineage_b64u TEXT NOT NULL,
  grant_nonce_b64u TEXT NOT NULL,
  grant_key_id TEXT NOT NULL,
  grant_b64u TEXT NOT NULL,
  grant_digest_b64u TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  status TEXT NOT NULL,
  active_revision INTEGER,
  root_commitment_b64u TEXT,
  journal_digest_b64u TEXT,
  capability_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, operation_id),
  UNIQUE (namespace, identity_digest_b64u),
  CHECK (status IN ('ISSUED', 'ACTIVE')),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (
    (status = 'ISSUED'
      AND active_revision IS NULL
      AND root_commitment_b64u IS NULL
      AND journal_digest_b64u IS NULL
      AND capability_digest_b64u IS NULL)
    OR
    (status = 'ACTIVE'
      AND active_revision > 0
      AND root_commitment_b64u IS NOT NULL
      AND journal_digest_b64u IS NOT NULL
      AND capability_digest_b64u IS NOT NULL)
  )
);

CREATE INDEX tenant_root_creation_grants_active_identity_idx
  ON tenant_root_creation_grants (namespace, identity_digest_b64u, status);
