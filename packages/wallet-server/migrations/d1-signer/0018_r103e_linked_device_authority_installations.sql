-- R103E: durable pending-authority package and installation-receipt journal.
CREATE TABLE linked_device_authority_installations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  auth_method_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  package_set_digest_b64u TEXT NOT NULL,
  target_factor_verification_digest_b64u TEXT NOT NULL,
  target_factor_verified_at_ms INTEGER NOT NULL,
  source_manifest_digest_b64u TEXT NOT NULL,
  packages_json TEXT NOT NULL,
  server_reservation_ids_json TEXT NOT NULL,
  installed_record_set_digest_b64u TEXT,
  activated_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  UNIQUE (namespace, org_id, project_id, env_id, authority_id),
  CHECK (json_valid(packages_json)),
  CHECK (json_valid(server_reservation_ids_json)),
  CHECK (target_factor_verified_at_ms >= 0),
  CHECK (created_at_ms >= 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE INDEX linked_device_authority_installations_authority_idx
  ON linked_device_authority_installations (
    namespace, org_id, project_id, env_id, authority_id
  );
