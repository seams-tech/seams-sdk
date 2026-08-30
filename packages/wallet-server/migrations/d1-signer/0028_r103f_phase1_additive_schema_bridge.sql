-- R103F Phase 1: additive schema bridge for the exact Wallet Session cutover.
--
-- The old worker writes all-null linked scope and resolves its V1 session.
-- The bridge worker writes the full D1 scope and resolves the exact V2
-- authority/method snapshot. Partial scope is never meaningful at this
-- boundary.

PRAGMA defer_foreign_keys = ON;

DROP TRIGGER IF EXISTS authorized_operation_grant_shape_guard;
DROP TRIGGER IF EXISTS authorized_operation_owner_grant_claim_atomic;

CREATE TRIGGER authorized_operation_grant_shape_guard
BEFORE INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND (
    NEW.authorization_source_kind NOT IN ('authorization_grant', 'verified_step_up')
    OR (
      NEW.authorization_source_kind = 'authorization_grant'
      AND (
        NEW.authorization_grant_kind IS NULL
        OR NEW.authorization_grant_kind NOT IN ('wallet_session_authorization')
        OR (
          (NEW.linked_scope_org_id IS NULL
            OR NEW.linked_scope_project_id IS NULL
            OR NEW.linked_scope_env_id IS NULL)
          AND NOT (
            NEW.linked_scope_org_id IS NULL
            AND NEW.linked_scope_project_id IS NULL
            AND NEW.linked_scope_env_id IS NULL
          )
        )
        OR (
          NEW.linked_scope_org_id IS NOT NULL
          AND NEW.linked_scope_project_id IS NOT NULL
          AND NEW.linked_scope_env_id IS NOT NULL
          AND (
            length(NEW.linked_scope_org_id) = 0
            OR length(NEW.linked_scope_project_id) = 0
            OR length(NEW.linked_scope_env_id) = 0
          )
        )
      )
    )
    OR (
      NEW.authorization_source_kind = 'verified_step_up'
      AND (
        NEW.authorization_grant_kind IS NOT NULL
        OR NEW.linked_scope_org_id IS NOT NULL
        OR NEW.linked_scope_project_id IS NOT NULL
        OR NEW.linked_scope_env_id IS NOT NULL
      )
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'authorization_grant_kind_rejected');
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
       WHERE NEW.linked_scope_org_id IS NULL
         AND NEW.linked_scope_project_id IS NULL
         AND NEW.linked_scope_env_id IS NULL
         AND session.namespace = NEW.namespace
         AND session.tenant_id = NEW.tenant_id
         AND session.authorization_id = NEW.authorization_id
         AND session.principal_id = NEW.principal_id
         AND (NEW.quota_kind = 'quota_neutral' OR session.quota_id = NEW.quota_id)
         AND session.lifecycle_kind = 'active'
         AND session.expires_at_ms > NEW.claimed_at_ms
    )
    AND NOT EXISTS (
      SELECT 1
        FROM wallet_session_authorizations_v2 AS session
        JOIN wallet_authorities AS authority
          ON authority.namespace = session.namespace
         AND authority.org_id = session.org_id
         AND authority.project_id = session.project_id
         AND authority.env_id = session.env_id
         AND authority.authority_id = session.authority_id
         AND authority.wallet_id = session.wallet_id
        JOIN wallet_auth_methods AS auth_method
          ON auth_method.namespace = session.namespace
         AND auth_method.org_id = session.org_id
         AND auth_method.project_id = session.project_id
         AND auth_method.env_id = session.env_id
         AND auth_method.wallet_auth_method_id = session.wallet_auth_method_id
         AND auth_method.wallet_id = session.wallet_id
         AND auth_method.wallet_authority_id = session.authority_id
       WHERE NEW.linked_scope_org_id IS NOT NULL
         AND NEW.linked_scope_project_id IS NOT NULL
         AND NEW.linked_scope_env_id IS NOT NULL
         AND session.namespace = NEW.namespace
         AND session.org_id = NEW.linked_scope_org_id
         AND session.project_id = NEW.linked_scope_project_id
         AND session.env_id = NEW.linked_scope_env_id
         AND session.tenant_id = NEW.tenant_id
         AND session.authorization_id = NEW.authorization_id
         AND session.principal_id = NEW.principal_id
         AND (NEW.quota_kind = 'quota_neutral' OR session.quota_id = NEW.quota_id)
         AND session.operation_credential_hash IS NOT NULL
         AND session.retired_at_ms IS NULL
         AND session.expires_at_ms > NEW.claimed_at_ms
         AND authority.lifecycle_state = 'active'
         AND authority.authority_digest_b64u = session.authority_digest_b64u
         AND authority.revocation_epoch = session.authority_revocation_epoch
         AND auth_method.status = 'active'
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
     AND principal_id = NEW.principal_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms
     AND (
       wallet_session_id = (
         SELECT session.wallet_session_id
           FROM reusable_wallet_sessions AS session
          WHERE NEW.linked_scope_org_id IS NULL
            AND NEW.linked_scope_project_id IS NULL
            AND NEW.linked_scope_env_id IS NULL
            AND session.namespace = NEW.namespace
            AND session.tenant_id = NEW.tenant_id
            AND session.authorization_id = NEW.authorization_id
            AND session.principal_id = NEW.principal_id
            AND session.quota_id = NEW.quota_id
            AND session.lifecycle_kind = 'active'
            AND session.expires_at_ms > NEW.claimed_at_ms
          LIMIT 1
       )
       OR wallet_session_id = (
         SELECT session.wallet_session_id
           FROM wallet_session_authorizations_v2 AS session
           JOIN wallet_authorities AS authority
             ON authority.namespace = session.namespace
            AND authority.org_id = session.org_id
            AND authority.project_id = session.project_id
            AND authority.env_id = session.env_id
            AND authority.authority_id = session.authority_id
            AND authority.wallet_id = session.wallet_id
           JOIN wallet_auth_methods AS auth_method
             ON auth_method.namespace = session.namespace
            AND auth_method.org_id = session.org_id
            AND auth_method.project_id = session.project_id
            AND auth_method.env_id = session.env_id
            AND auth_method.wallet_auth_method_id = session.wallet_auth_method_id
            AND auth_method.wallet_id = session.wallet_id
            AND auth_method.wallet_authority_id = session.authority_id
          WHERE NEW.linked_scope_org_id IS NOT NULL
            AND NEW.linked_scope_project_id IS NOT NULL
            AND NEW.linked_scope_env_id IS NOT NULL
            AND session.namespace = NEW.namespace
            AND session.org_id = NEW.linked_scope_org_id
            AND session.project_id = NEW.linked_scope_project_id
            AND session.env_id = NEW.linked_scope_env_id
            AND session.tenant_id = NEW.tenant_id
            AND session.authorization_id = NEW.authorization_id
            AND session.principal_id = NEW.principal_id
            AND session.quota_id = NEW.quota_id
            AND session.operation_credential_hash IS NOT NULL
            AND session.retired_at_ms IS NULL
            AND session.expires_at_ms > NEW.claimed_at_ms
            AND authority.lifecycle_state = 'active'
            AND authority.authority_digest_b64u = session.authority_digest_b64u
            AND authority.revocation_epoch = session.authority_revocation_epoch
            AND auth_method.status = 'active'
          LIMIT 1
       )
     );

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;
END;

CREATE UNIQUE INDEX wallet_session_authorizations_v2_exact_identity_uidx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id, authorization_id,
    wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  );

CREATE TABLE wallet_session_hosted_credentials_v2 (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  hosted_credential_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  credential_digest_b64u TEXT NOT NULL,
  app_origin TEXT NOT NULL,
  wallet_origin TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  retired_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, tenant_id, hosted_credential_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, credential_digest_b64u),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id, tenant_id, authorization_id,
    wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  ) REFERENCES wallet_session_authorizations_v2(
    namespace, org_id, project_id, env_id, tenant_id, authorization_id,
    wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  ),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(tenant_id) > 0),
  CHECK (length(hosted_credential_id) > 0),
  CHECK (length(authorization_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(quota_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(authority_id) > 0),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (length(credential_digest_b64u) > 0),
  CHECK (length(trim(app_origin)) > 0),
  CHECK (length(trim(wallet_origin)) > 0),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (lifecycle_kind IN ('active', 'retired')),
  CHECK (
    (lifecycle_kind = 'active' AND retired_at_ms IS NULL)
    OR (lifecycle_kind = 'retired' AND retired_at_ms IS NOT NULL AND retired_at_ms >= issued_at_ms)
  )
);

CREATE INDEX wallet_session_hosted_credentials_v2_parent_idx
  ON wallet_session_hosted_credentials_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    authorization_id, lifecycle_kind, expires_at_ms
  );

CREATE INDEX wallet_session_hosted_credentials_v2_expiry_idx
  ON wallet_session_hosted_credentials_v2 (
    namespace, org_id, project_id, env_id, tenant_id, expires_at_ms, lifecycle_kind
  );

CREATE UNIQUE INDEX wallet_session_hosted_credentials_v2_exact_identity_uidx
  ON wallet_session_hosted_credentials_v2 (
    namespace, org_id, project_id, env_id, tenant_id, hosted_credential_id,
    authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  );

CREATE TRIGGER wallet_session_hosted_credentials_v2_insert_lifecycle_guard
BEFORE INSERT ON wallet_session_hosted_credentials_v2
WHEN NEW.lifecycle_kind != 'active' OR NEW.retired_at_ms IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_credential_initial_state_rejected');
END;

CREATE TRIGGER wallet_session_hosted_credentials_v2_parent_guard
BEFORE INSERT ON wallet_session_hosted_credentials_v2
WHEN NOT EXISTS (
  SELECT 1
    FROM wallet_session_authorizations_v2 AS session
   WHERE session.namespace = NEW.namespace
     AND session.org_id = NEW.org_id
     AND session.project_id = NEW.project_id
     AND session.env_id = NEW.env_id
     AND session.tenant_id = NEW.tenant_id
     AND session.authorization_id = NEW.authorization_id
     AND session.wallet_session_id = NEW.wallet_session_id
     AND session.quota_id = NEW.quota_id
     AND session.principal_id = NEW.principal_id
     AND session.wallet_id = NEW.wallet_id
     AND session.authority_id = NEW.authority_id
     AND session.wallet_auth_method_id = NEW.wallet_auth_method_id
     AND session.operation_credential_hash IS NOT NULL
     AND session.retired_at_ms IS NULL
     AND session.expires_at_ms >= NEW.expires_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_credential_parent_rejected');
END;

CREATE TRIGGER wallet_session_hosted_credentials_v2_parent_update_guard
BEFORE UPDATE OF lifecycle_kind
ON wallet_session_hosted_credentials_v2
WHEN NOT EXISTS (
  SELECT 1
    FROM wallet_session_authorizations_v2 AS session
   WHERE session.namespace = NEW.namespace
     AND session.org_id = NEW.org_id
     AND session.project_id = NEW.project_id
     AND session.env_id = NEW.env_id
     AND session.tenant_id = NEW.tenant_id
     AND session.authorization_id = NEW.authorization_id
     AND session.wallet_session_id = NEW.wallet_session_id
     AND session.quota_id = NEW.quota_id
     AND session.principal_id = NEW.principal_id
     AND session.wallet_id = NEW.wallet_id
     AND session.authority_id = NEW.authority_id
     AND session.wallet_auth_method_id = NEW.wallet_auth_method_id
     AND session.operation_credential_hash IS NOT NULL
     AND session.retired_at_ms IS NULL
     AND session.expires_at_ms >= NEW.expires_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_credential_parent_rejected');
END;

CREATE TRIGGER wallet_session_hosted_credentials_v2_identity_guard
BEFORE UPDATE OF
  namespace, org_id, project_id, env_id, tenant_id, hosted_credential_id,
  authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
  authority_id, wallet_auth_method_id, credential_digest_b64u, app_origin,
  wallet_origin, issued_at_ms, expires_at_ms
ON wallet_session_hosted_credentials_v2
WHEN OLD.namespace IS NOT NEW.namespace
  OR OLD.org_id IS NOT NEW.org_id
  OR OLD.project_id IS NOT NEW.project_id
  OR OLD.env_id IS NOT NEW.env_id
  OR OLD.tenant_id IS NOT NEW.tenant_id
  OR OLD.hosted_credential_id IS NOT NEW.hosted_credential_id
  OR OLD.authorization_id IS NOT NEW.authorization_id
  OR OLD.wallet_session_id IS NOT NEW.wallet_session_id
  OR OLD.quota_id IS NOT NEW.quota_id
  OR OLD.principal_id IS NOT NEW.principal_id
  OR OLD.wallet_id IS NOT NEW.wallet_id
  OR OLD.authority_id IS NOT NEW.authority_id
  OR OLD.wallet_auth_method_id IS NOT NEW.wallet_auth_method_id
  OR OLD.credential_digest_b64u IS NOT NEW.credential_digest_b64u
  OR OLD.app_origin IS NOT NEW.app_origin
  OR OLD.wallet_origin IS NOT NEW.wallet_origin
  OR OLD.issued_at_ms IS NOT NEW.issued_at_ms
  OR OLD.expires_at_ms IS NOT NEW.expires_at_ms
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_credential_identity_rejected');
END;

CREATE TRIGGER wallet_session_hosted_credentials_v2_lifecycle_guard
BEFORE UPDATE OF lifecycle_kind
ON wallet_session_hosted_credentials_v2
WHEN (OLD.lifecycle_kind = 'retired' AND NEW.lifecycle_kind != 'retired')
  OR (OLD.lifecycle_kind = 'active' AND NEW.lifecycle_kind NOT IN ('active', 'retired'))
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_credential_transition_rejected');
END;

CREATE TRIGGER wallet_session_hosted_credentials_v2_retirement_guard
BEFORE UPDATE OF retired_at_ms
ON wallet_session_hosted_credentials_v2
WHEN OLD.retired_at_ms IS NOT NEW.retired_at_ms
  AND NOT (
    OLD.lifecycle_kind = 'active'
    AND NEW.lifecycle_kind = 'retired'
    AND OLD.retired_at_ms IS NULL
    AND NEW.retired_at_ms IS NOT NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_credential_retirement_rejected');
END;

CREATE TABLE wallet_session_hosted_exchange_codes_v2 (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  exchange_code_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  nonce_digest TEXT NOT NULL,
  app_origin TEXT NOT NULL,
  wallet_origin TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  hosted_credential_id TEXT,
  consumed_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, tenant_id, exchange_code_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, code_hash),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, nonce_digest),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id, tenant_id, authorization_id,
    wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  ) REFERENCES wallet_session_authorizations_v2(
    namespace, org_id, project_id, env_id, tenant_id, authorization_id,
    wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  ),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id, tenant_id, hosted_credential_id,
    authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  )
    REFERENCES wallet_session_hosted_credentials_v2(
      namespace, org_id, project_id, env_id, tenant_id, hosted_credential_id,
      authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
      authority_id, wallet_auth_method_id
    ),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(tenant_id) > 0),
  CHECK (length(exchange_code_id) > 0),
  CHECK (length(authorization_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(quota_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(authority_id) > 0),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (length(code_hash) > 0),
  CHECK (length(nonce_digest) > 0),
  CHECK (length(trim(app_origin)) > 0),
  CHECK (length(trim(wallet_origin)) > 0),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (lifecycle_kind IN ('issued', 'consumed')),
  CHECK (
    (lifecycle_kind = 'issued' AND hosted_credential_id IS NULL AND consumed_at_ms IS NULL)
    OR (
      lifecycle_kind = 'consumed'
      AND hosted_credential_id IS NOT NULL
      AND consumed_at_ms IS NOT NULL
      AND consumed_at_ms >= issued_at_ms
      AND consumed_at_ms <= expires_at_ms
    )
  )
);

CREATE INDEX wallet_session_hosted_exchange_codes_v2_parent_idx
  ON wallet_session_hosted_exchange_codes_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    authorization_id, lifecycle_kind, expires_at_ms
  );

CREATE INDEX wallet_session_hosted_exchange_codes_v2_expiry_idx
  ON wallet_session_hosted_exchange_codes_v2 (
    namespace, org_id, project_id, env_id, tenant_id, expires_at_ms, lifecycle_kind
  );

CREATE TRIGGER wallet_session_hosted_exchange_codes_v2_insert_lifecycle_guard
BEFORE INSERT ON wallet_session_hosted_exchange_codes_v2
WHEN NEW.lifecycle_kind != 'issued'
  OR NEW.hosted_credential_id IS NOT NULL
  OR NEW.consumed_at_ms IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_exchange_initial_state_rejected');
END;

CREATE TRIGGER wallet_session_hosted_exchange_codes_v2_parent_guard
BEFORE INSERT ON wallet_session_hosted_exchange_codes_v2
WHEN NOT EXISTS (
  SELECT 1
    FROM wallet_session_authorizations_v2 AS session
   WHERE session.namespace = NEW.namespace
     AND session.org_id = NEW.org_id
     AND session.project_id = NEW.project_id
     AND session.env_id = NEW.env_id
     AND session.tenant_id = NEW.tenant_id
     AND session.authorization_id = NEW.authorization_id
     AND session.wallet_session_id = NEW.wallet_session_id
     AND session.quota_id = NEW.quota_id
     AND session.principal_id = NEW.principal_id
     AND session.wallet_id = NEW.wallet_id
     AND session.authority_id = NEW.authority_id
     AND session.wallet_auth_method_id = NEW.wallet_auth_method_id
     AND session.operation_credential_hash IS NOT NULL
     AND session.retired_at_ms IS NULL
     AND session.expires_at_ms >= NEW.expires_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_exchange_parent_rejected');
END;

CREATE TRIGGER wallet_session_hosted_exchange_codes_v2_parent_update_guard
BEFORE UPDATE OF lifecycle_kind, hosted_credential_id
ON wallet_session_hosted_exchange_codes_v2
WHEN NOT EXISTS (
  SELECT 1
    FROM wallet_session_authorizations_v2 AS session
   WHERE session.namespace = NEW.namespace
     AND session.org_id = NEW.org_id
     AND session.project_id = NEW.project_id
     AND session.env_id = NEW.env_id
     AND session.tenant_id = NEW.tenant_id
     AND session.authorization_id = NEW.authorization_id
     AND session.wallet_session_id = NEW.wallet_session_id
     AND session.quota_id = NEW.quota_id
     AND session.principal_id = NEW.principal_id
     AND session.wallet_id = NEW.wallet_id
     AND session.authority_id = NEW.authority_id
     AND session.wallet_auth_method_id = NEW.wallet_auth_method_id
     AND session.operation_credential_hash IS NOT NULL
     AND session.retired_at_ms IS NULL
     AND session.expires_at_ms >= NEW.expires_at_ms
     AND session.expires_at_ms > COALESCE(NEW.consumed_at_ms, NEW.issued_at_ms)
)
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_exchange_parent_rejected');
END;

CREATE TRIGGER wallet_session_hosted_exchange_codes_v2_child_update_guard
BEFORE UPDATE OF lifecycle_kind, hosted_credential_id
ON wallet_session_hosted_exchange_codes_v2
WHEN NEW.hosted_credential_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
      FROM wallet_session_hosted_credentials_v2 AS credential
     WHERE credential.namespace = NEW.namespace
       AND credential.org_id = NEW.org_id
       AND credential.project_id = NEW.project_id
       AND credential.env_id = NEW.env_id
       AND credential.tenant_id = NEW.tenant_id
       AND credential.hosted_credential_id = NEW.hosted_credential_id
       AND credential.authorization_id = NEW.authorization_id
       AND credential.wallet_session_id = NEW.wallet_session_id
       AND credential.quota_id = NEW.quota_id
       AND credential.principal_id = NEW.principal_id
       AND credential.wallet_id = NEW.wallet_id
       AND credential.authority_id = NEW.authority_id
       AND credential.wallet_auth_method_id = NEW.wallet_auth_method_id
       AND credential.lifecycle_kind = 'active'
       AND credential.retired_at_ms IS NULL
       AND credential.expires_at_ms >= NEW.expires_at_ms
       AND credential.expires_at_ms > COALESCE(NEW.consumed_at_ms, NEW.issued_at_ms)
  )
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_exchange_child_rejected');
END;

CREATE TRIGGER wallet_session_hosted_exchange_codes_v2_identity_guard
BEFORE UPDATE OF
  namespace, org_id, project_id, env_id, tenant_id, exchange_code_id,
  authorization_id, wallet_session_id, quota_id, principal_id, wallet_id,
  authority_id, wallet_auth_method_id, code_hash, nonce_digest, app_origin,
  wallet_origin, issued_at_ms, expires_at_ms
ON wallet_session_hosted_exchange_codes_v2
WHEN OLD.namespace IS NOT NEW.namespace
  OR OLD.org_id IS NOT NEW.org_id
  OR OLD.project_id IS NOT NEW.project_id
  OR OLD.env_id IS NOT NEW.env_id
  OR OLD.tenant_id IS NOT NEW.tenant_id
  OR OLD.exchange_code_id IS NOT NEW.exchange_code_id
  OR OLD.authorization_id IS NOT NEW.authorization_id
  OR OLD.wallet_session_id IS NOT NEW.wallet_session_id
  OR OLD.quota_id IS NOT NEW.quota_id
  OR OLD.principal_id IS NOT NEW.principal_id
  OR OLD.wallet_id IS NOT NEW.wallet_id
  OR OLD.authority_id IS NOT NEW.authority_id
  OR OLD.wallet_auth_method_id IS NOT NEW.wallet_auth_method_id
  OR OLD.code_hash IS NOT NEW.code_hash
  OR OLD.nonce_digest IS NOT NEW.nonce_digest
  OR OLD.app_origin IS NOT NEW.app_origin
  OR OLD.wallet_origin IS NOT NEW.wallet_origin
  OR OLD.issued_at_ms IS NOT NEW.issued_at_ms
  OR OLD.expires_at_ms IS NOT NEW.expires_at_ms
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_exchange_identity_rejected');
END;

CREATE TRIGGER wallet_session_hosted_exchange_codes_v2_lifecycle_guard
BEFORE UPDATE OF lifecycle_kind, hosted_credential_id, consumed_at_ms
ON wallet_session_hosted_exchange_codes_v2
WHEN (
  OLD.lifecycle_kind IS NOT NEW.lifecycle_kind
  OR OLD.hosted_credential_id IS NOT NEW.hosted_credential_id
  OR OLD.consumed_at_ms IS NOT NEW.consumed_at_ms
)
AND NOT (
  OLD.lifecycle_kind = 'issued'
  AND NEW.lifecycle_kind = 'consumed'
  AND OLD.hosted_credential_id IS NULL
  AND NEW.hosted_credential_id IS NOT NULL
  AND OLD.consumed_at_ms IS NULL
  AND NEW.consumed_at_ms IS NOT NULL
)
BEGIN
  SELECT RAISE(ABORT, 'wallet_session_hosted_exchange_transition_rejected');
END;

CREATE UNIQUE INDEX linked_device_authority_installations_exact_identity_uidx
  ON linked_device_authority_installations (
    namespace, org_id, project_id, env_id, link_session_id,
    authority_id, wallet_id, auth_method_id
  );

CREATE TABLE linked_device_wallet_session_credential_deliveries_v1 (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  credential_digest_b64u TEXT NOT NULL,
  recipient_kind TEXT NOT NULL,
  recipient_public_key_b64u TEXT NOT NULL,
  recipient_binding_digest_b64u TEXT NOT NULL,
  envelope_alg TEXT NOT NULL,
  aad_digest_b64u TEXT NOT NULL,
  sealed_envelope_json TEXT,
  sealed_envelope_digest_b64u TEXT NOT NULL,
  installation_receipt_digest_b64u TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  acknowledged_at_ms INTEGER,
  acknowledgement_receipt_json TEXT,
  cleanup_state TEXT NOT NULL,
  cleanup_receipt_json TEXT,
  cleanup_completed_at_ms INTEGER,
  acknowledgement_auth_binding_digest_b64u TEXT,
  acknowledgement_auth_package_set_digest_b64u TEXT,
  acknowledgement_auth_expires_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, credential_digest_b64u),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id, link_session_id,
    authority_id, wallet_id, wallet_auth_method_id
  )
    REFERENCES linked_device_authority_installations(
      namespace, org_id, project_id, env_id, link_session_id,
      authority_id, wallet_id, auth_method_id
    ),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id, tenant_id, authorization_id,
    wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  )
    REFERENCES wallet_session_authorizations_v2(
      namespace, org_id, project_id, env_id, tenant_id, authorization_id,
      wallet_session_id, quota_id, principal_id, wallet_id,
      authority_id, wallet_auth_method_id
    ),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(link_session_id) > 0),
  CHECK (length(tenant_id) > 0),
  CHECK (length(authorization_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(quota_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (length(authority_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (length(credential_digest_b64u) > 0),
  CHECK (recipient_kind = 'p256_ecdh'),
  CHECK (length(recipient_public_key_b64u) > 0),
  CHECK (length(recipient_binding_digest_b64u) > 0),
  CHECK (envelope_alg = 'p256-ecdh-aes256gcm-v1'),
  CHECK (length(aad_digest_b64u) > 0),
  CHECK (sealed_envelope_json IS NULL OR json_valid(sealed_envelope_json)),
  CHECK (length(sealed_envelope_digest_b64u) > 0),
  CHECK (length(installation_receipt_digest_b64u) > 0),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (lifecycle_kind IN ('issued', 'acknowledged', 'cleanup_complete')),
  CHECK (cleanup_state IN ('pending', 'allocation_removed', 'session_removed', 'complete')),
  CHECK (
    (
      lifecycle_kind = 'issued'
      AND sealed_envelope_json IS NOT NULL
      AND acknowledged_at_ms IS NULL
      AND acknowledgement_receipt_json IS NULL
      AND cleanup_state = 'pending'
      AND cleanup_receipt_json IS NULL
      AND cleanup_completed_at_ms IS NULL
    )
    OR (
      lifecycle_kind = 'acknowledged'
      AND sealed_envelope_json IS NULL
      AND acknowledged_at_ms IS NOT NULL
      AND acknowledged_at_ms >= issued_at_ms
      AND acknowledged_at_ms <= expires_at_ms
      AND acknowledgement_receipt_json IS NOT NULL
      AND json_valid(acknowledgement_receipt_json)
      AND cleanup_state IN ('pending', 'allocation_removed', 'session_removed')
      AND cleanup_receipt_json IS NOT NULL
      AND json_valid(cleanup_receipt_json)
      AND cleanup_completed_at_ms IS NULL
    )
    OR (
      lifecycle_kind = 'cleanup_complete'
      AND sealed_envelope_json IS NULL
      AND acknowledged_at_ms IS NOT NULL
      AND acknowledged_at_ms >= issued_at_ms
      AND acknowledged_at_ms <= expires_at_ms
      AND acknowledgement_receipt_json IS NOT NULL
      AND json_valid(acknowledgement_receipt_json)
      AND cleanup_state = 'complete'
      AND cleanup_receipt_json IS NOT NULL
      AND json_valid(cleanup_receipt_json)
      AND cleanup_completed_at_ms IS NOT NULL
      AND cleanup_completed_at_ms >= acknowledged_at_ms
    )
  ),
  CHECK (
    acknowledgement_auth_binding_digest_b64u IS NULL
    OR length(acknowledgement_auth_binding_digest_b64u) > 0
  ),
  CHECK (
    acknowledgement_auth_package_set_digest_b64u IS NULL
    OR length(acknowledgement_auth_package_set_digest_b64u) > 0
  ),
  CHECK (
    acknowledgement_auth_expires_at_ms IS NULL
    OR acknowledgement_auth_expires_at_ms >= issued_at_ms
  ),
  CHECK (
    (
      lifecycle_kind = 'issued'
      AND acknowledgement_auth_binding_digest_b64u IS NULL
      AND acknowledgement_auth_package_set_digest_b64u IS NULL
      AND acknowledgement_auth_expires_at_ms IS NULL
    )
    OR (
      lifecycle_kind IN ('acknowledged', 'cleanup_complete')
      AND acknowledgement_auth_binding_digest_b64u IS NOT NULL
      AND acknowledgement_auth_package_set_digest_b64u IS NOT NULL
      AND acknowledgement_auth_expires_at_ms IS NOT NULL
      AND acknowledgement_auth_expires_at_ms >= acknowledged_at_ms
      AND acknowledgement_auth_expires_at_ms <= expires_at_ms
      AND acknowledgement_auth_binding_digest_b64u = recipient_binding_digest_b64u
    )
  )
);

CREATE TRIGGER linked_device_wallet_session_credential_delivery_insert_lifecycle_guard
BEFORE INSERT ON linked_device_wallet_session_credential_deliveries_v1
WHEN NEW.lifecycle_kind != 'issued'
  OR NEW.acknowledged_at_ms IS NOT NULL
  OR NEW.acknowledgement_receipt_json IS NOT NULL
  OR NEW.cleanup_state != 'pending'
  OR NEW.cleanup_receipt_json IS NOT NULL
  OR NEW.cleanup_completed_at_ms IS NOT NULL
  OR NEW.acknowledgement_auth_binding_digest_b64u IS NOT NULL
  OR NEW.acknowledgement_auth_package_set_digest_b64u IS NOT NULL
  OR NEW.acknowledgement_auth_expires_at_ms IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_credential_delivery_initial_state_rejected');
END;

CREATE TRIGGER linked_device_wallet_session_credential_delivery_identity_guard
BEFORE UPDATE OF
  namespace, org_id, project_id, env_id, link_session_id, tenant_id,
  authorization_id, wallet_session_id, quota_id, principal_id, authority_id,
  wallet_id, wallet_auth_method_id, credential_digest_b64u, recipient_kind,
  recipient_public_key_b64u, recipient_binding_digest_b64u, envelope_alg,
  aad_digest_b64u, sealed_envelope_digest_b64u, installation_receipt_digest_b64u,
  issued_at_ms, expires_at_ms
ON linked_device_wallet_session_credential_deliveries_v1
WHEN OLD.namespace IS NOT NEW.namespace
  OR OLD.org_id IS NOT NEW.org_id
  OR OLD.project_id IS NOT NEW.project_id
  OR OLD.env_id IS NOT NEW.env_id
  OR OLD.link_session_id IS NOT NEW.link_session_id
  OR OLD.tenant_id IS NOT NEW.tenant_id
  OR OLD.authorization_id IS NOT NEW.authorization_id
  OR OLD.wallet_session_id IS NOT NEW.wallet_session_id
  OR OLD.quota_id IS NOT NEW.quota_id
  OR OLD.principal_id IS NOT NEW.principal_id
  OR OLD.authority_id IS NOT NEW.authority_id
  OR OLD.wallet_id IS NOT NEW.wallet_id
  OR OLD.wallet_auth_method_id IS NOT NEW.wallet_auth_method_id
  OR OLD.credential_digest_b64u IS NOT NEW.credential_digest_b64u
  OR OLD.recipient_kind IS NOT NEW.recipient_kind
  OR OLD.recipient_public_key_b64u IS NOT NEW.recipient_public_key_b64u
  OR OLD.recipient_binding_digest_b64u IS NOT NEW.recipient_binding_digest_b64u
  OR OLD.envelope_alg IS NOT NEW.envelope_alg
  OR OLD.aad_digest_b64u IS NOT NEW.aad_digest_b64u
  OR OLD.sealed_envelope_digest_b64u IS NOT NEW.sealed_envelope_digest_b64u
  OR OLD.installation_receipt_digest_b64u IS NOT NEW.installation_receipt_digest_b64u
  OR OLD.issued_at_ms IS NOT NEW.issued_at_ms
  OR OLD.expires_at_ms IS NOT NEW.expires_at_ms
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_credential_delivery_identity_rejected');
END;

CREATE TRIGGER linked_device_wallet_session_credential_delivery_envelope_guard
BEFORE UPDATE OF sealed_envelope_json
ON linked_device_wallet_session_credential_deliveries_v1
WHEN NOT (
  OLD.lifecycle_kind = 'issued'
  AND NEW.lifecycle_kind = 'acknowledged'
  AND OLD.sealed_envelope_json IS NOT NULL
  AND NEW.sealed_envelope_json IS NULL
)
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_credential_delivery_envelope_rejected');
END;

CREATE TRIGGER linked_device_wallet_session_credential_delivery_acknowledgement_guard
BEFORE UPDATE OF
  acknowledged_at_ms, acknowledgement_receipt_json,
  acknowledgement_auth_binding_digest_b64u,
  acknowledgement_auth_package_set_digest_b64u,
  acknowledgement_auth_expires_at_ms
ON linked_device_wallet_session_credential_deliveries_v1
WHEN (
  OLD.acknowledged_at_ms IS NOT NEW.acknowledged_at_ms
  OR OLD.acknowledgement_receipt_json IS NOT NEW.acknowledgement_receipt_json
  OR OLD.acknowledgement_auth_binding_digest_b64u IS NOT NEW.acknowledgement_auth_binding_digest_b64u
  OR OLD.acknowledgement_auth_package_set_digest_b64u IS NOT NEW.acknowledgement_auth_package_set_digest_b64u
  OR OLD.acknowledgement_auth_expires_at_ms IS NOT NEW.acknowledgement_auth_expires_at_ms
)
AND NOT (
  OLD.lifecycle_kind = 'issued'
  AND NEW.lifecycle_kind = 'acknowledged'
  AND OLD.acknowledged_at_ms IS NULL
  AND OLD.acknowledgement_receipt_json IS NULL
  AND OLD.acknowledgement_auth_binding_digest_b64u IS NULL
  AND OLD.acknowledgement_auth_package_set_digest_b64u IS NULL
  AND OLD.acknowledgement_auth_expires_at_ms IS NULL
  AND NEW.acknowledged_at_ms IS NOT NULL
  AND NEW.acknowledgement_receipt_json IS NOT NULL
  AND NEW.acknowledgement_auth_binding_digest_b64u IS NOT NULL
  AND NEW.acknowledgement_auth_package_set_digest_b64u IS NOT NULL
  AND NEW.acknowledgement_auth_expires_at_ms IS NOT NULL
)
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_credential_delivery_acknowledgement_rejected');
END;

CREATE TRIGGER linked_device_wallet_session_credential_delivery_cleanup_receipt_guard
BEFORE UPDATE OF cleanup_receipt_json
ON linked_device_wallet_session_credential_deliveries_v1
WHEN OLD.cleanup_receipt_json IS NOT NEW.cleanup_receipt_json
  AND NOT (
    OLD.lifecycle_kind = 'issued'
    AND NEW.lifecycle_kind = 'acknowledged'
    AND OLD.cleanup_receipt_json IS NULL
    AND NEW.cleanup_receipt_json IS NOT NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_credential_delivery_cleanup_receipt_rejected');
END;

CREATE TRIGGER linked_device_wallet_session_credential_delivery_cleanup_completion_guard
BEFORE UPDATE OF cleanup_completed_at_ms
ON linked_device_wallet_session_credential_deliveries_v1
WHEN OLD.cleanup_completed_at_ms IS NOT NEW.cleanup_completed_at_ms
  AND NOT (
    OLD.lifecycle_kind = 'acknowledged'
    AND NEW.lifecycle_kind = 'cleanup_complete'
    AND OLD.cleanup_completed_at_ms IS NULL
    AND NEW.cleanup_completed_at_ms IS NOT NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_credential_delivery_cleanup_completion_rejected');
END;

CREATE INDEX linked_device_wallet_session_credential_deliveries_v1_lifecycle_idx
  ON linked_device_wallet_session_credential_deliveries_v1 (
    namespace, org_id, project_id, env_id, lifecycle_kind, cleanup_state, expires_at_ms
  );

CREATE INDEX linked_device_wallet_session_credential_deliveries_v1_parent_idx
  ON linked_device_wallet_session_credential_deliveries_v1 (
    namespace, org_id, project_id, env_id, tenant_id, authorization_id, wallet_id
  );

CREATE TRIGGER linked_device_wallet_session_credential_delivery_parent_guard
BEFORE INSERT ON linked_device_wallet_session_credential_deliveries_v1
WHEN NOT EXISTS (
  SELECT 1
    FROM wallet_session_authorizations_v2 AS session
    JOIN linked_device_authority_installations AS installation
      ON installation.namespace = NEW.namespace
     AND installation.org_id = NEW.org_id
     AND installation.project_id = NEW.project_id
     AND installation.env_id = NEW.env_id
     AND installation.link_session_id = NEW.link_session_id
   WHERE session.namespace = NEW.namespace
     AND session.org_id = NEW.org_id
     AND session.project_id = NEW.project_id
     AND session.env_id = NEW.env_id
     AND session.tenant_id = NEW.tenant_id
     AND session.authorization_id = NEW.authorization_id
     AND session.wallet_session_id = NEW.wallet_session_id
     AND session.quota_id = NEW.quota_id
     AND session.principal_id = NEW.principal_id
     AND session.wallet_id = NEW.wallet_id
     AND session.authority_id = NEW.authority_id
     AND session.wallet_auth_method_id = NEW.wallet_auth_method_id
     AND session.operation_credential_hash IS NOT NULL
     AND session.retired_at_ms IS NULL
     AND session.expires_at_ms >= NEW.expires_at_ms
     AND installation.authority_id = NEW.authority_id
     AND installation.wallet_id = NEW.wallet_id
     AND installation.auth_method_id = NEW.wallet_auth_method_id
)
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_credential_delivery_parent_rejected');
END;

CREATE TRIGGER linked_device_wallet_session_credential_delivery_lifecycle_guard
BEFORE UPDATE OF lifecycle_kind, cleanup_state, sealed_envelope_json,
  acknowledged_at_ms, acknowledgement_receipt_json, cleanup_receipt_json,
  cleanup_completed_at_ms
ON linked_device_wallet_session_credential_deliveries_v1
WHEN (
  (OLD.lifecycle_kind = 'issued' AND NEW.lifecycle_kind NOT IN ('issued', 'acknowledged'))
  OR (OLD.lifecycle_kind = 'acknowledged' AND NEW.lifecycle_kind NOT IN ('acknowledged', 'cleanup_complete'))
  OR (OLD.lifecycle_kind = 'cleanup_complete' AND NEW.lifecycle_kind != 'cleanup_complete')
  OR (
    CASE OLD.cleanup_state
      WHEN 'pending' THEN 0
      WHEN 'allocation_removed' THEN 1
      WHEN 'session_removed' THEN 2
      WHEN 'complete' THEN 3
    END
    != CASE NEW.cleanup_state
      WHEN 'pending' THEN 0
      WHEN 'allocation_removed' THEN 1
      WHEN 'session_removed' THEN 2
      WHEN 'complete' THEN 3
    END
    AND (
      CASE NEW.cleanup_state
        WHEN 'pending' THEN 0
        WHEN 'allocation_removed' THEN 1
        WHEN 'session_removed' THEN 2
        WHEN 'complete' THEN 3
      END
      NOT IN (
        CASE OLD.cleanup_state
          WHEN 'pending' THEN 0
          WHEN 'allocation_removed' THEN 1
          WHEN 'session_removed' THEN 2
          WHEN 'complete' THEN 3
        END + 1
      )
    )
  )
  OR (
    OLD.lifecycle_kind = 'issued'
    AND NEW.lifecycle_kind = 'acknowledged'
    AND NEW.cleanup_state != 'pending'
  )
)
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_credential_delivery_transition_rejected');
END;

CREATE INDEX wallet_session_authorizations_v2_credential_lifecycle_idx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    wallet_id, authority_id, wallet_auth_method_id,
    retired_at_ms, expires_at_ms, operation_credential_hash
  );

CREATE INDEX authorized_operations_v1_pending_scope_idx
  ON authorized_operations (
    namespace, tenant_id, authorization_id, quota_id, claimed_at_ms
  )
  WHERE lifecycle_kind = 'claimed'
    AND authorization_source_kind = 'authorization_grant'
    AND authorization_grant_kind = 'wallet_session_authorization'
    AND linked_scope_org_id IS NULL
    AND linked_scope_project_id IS NULL
    AND linked_scope_env_id IS NULL;

CREATE INDEX authorization_wallet_session_quotas_lifecycle_idx
  ON authorization_wallet_session_quotas (
    namespace, tenant_id, lifecycle_kind, expires_at_ms
  );

CREATE INDEX hosted_wallet_session_exchange_codes_v1_lifecycle_idx
  ON hosted_wallet_session_exchange_codes (
    namespace, tenant_id, lifecycle_kind, expires_at_ms
  );

CREATE INDEX registration_completion_credential_inventory_idx
  ON router_ab_yao_versioned_json_records (
    namespace, org_id, project_id, env_id, record_key, updated_at_ms
  )
  WHERE record_key LIKE 'wallet-registration-activate:%'
     OR record_key LIKE 'wallet-registration-near-provisioning:%';

-- A duplicate exact tuple cannot be resolved by this additive bridge. A row
-- without a credential or an expired row is retired deterministically before
-- the bridge is usable; multiple active credential-bearing rows still abort.
UPDATE wallet_session_authorizations_v2
   SET retired_at_ms = CASE
     WHEN operation_credential_hash IS NULL THEN issued_at_ms
     ELSE expires_at_ms
   END
 WHERE retired_at_ms IS NULL
   AND (
     operation_credential_hash IS NULL
     OR expires_at_ms <= (unixepoch() * 1000)
   );

CREATE TABLE r103f_phase1_duplicate_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
INSERT INTO r103f_phase1_duplicate_guard (guard_id) VALUES (1);
INSERT INTO r103f_phase1_duplicate_guard (guard_id)
SELECT 1
 WHERE EXISTS (
   SELECT 1
     FROM wallet_session_authorizations_v2
    WHERE retired_at_ms IS NULL
      AND operation_credential_hash IS NOT NULL
      AND expires_at_ms > (unixepoch() * 1000)
    GROUP BY namespace, org_id, project_id, env_id,
      tenant_id, wallet_id, authority_id, wallet_auth_method_id
   HAVING COUNT(*) > 1
 );
DROP TABLE r103f_phase1_duplicate_guard;

-- If an allocation table was created by an older worker, it must already be
-- the same shape as the forward schema. The guard intentionally runs before
-- CREATE TABLE IF NOT EXISTS can mask drift.
CREATE TABLE r103f_phase1_allocation_schema_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
INSERT INTO r103f_phase1_allocation_schema_guard (guard_id) VALUES (1);
INSERT INTO r103f_phase1_allocation_schema_guard (guard_id)
SELECT 1
 WHERE EXISTS (
   SELECT 1
     FROM sqlite_master AS schema
    WHERE schema.type = 'table'
      AND schema.name = 'linked_device_authority_allocations'
      AND (
        COALESCE(
          (
            SELECT group_concat(column_name, ',')
              FROM (
                SELECT name AS column_name
                  FROM pragma_table_info('linked_device_authority_allocations')
                 ORDER BY cid
              )
          ),
          ''
        ) != 'namespace,org_id,project_id,env_id,link_session_id,authority_id,wallet_id,enrollment_id,device_id,created_at_ms'
        OR COALESCE(
          (
            SELECT group_concat(column_signature, ',')
              FROM (
                SELECT
                  name || ':' || type || ':' || "notnull" || ':' || pk AS column_signature
                  FROM pragma_table_info('linked_device_authority_allocations')
                 ORDER BY cid
              )
          ),
          ''
        ) != 'namespace:TEXT:1:1,org_id:TEXT:1:2,project_id:TEXT:1:3,env_id:TEXT:1:4,link_session_id:TEXT:1:5,authority_id:TEXT:1:0,wallet_id:TEXT:1:0,enrollment_id:TEXT:1:0,device_id:TEXT:1:0,created_at_ms:INTEGER:1:0'
        OR schema.sql IS NULL
        OR schema.sql NOT LIKE '%PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id)%'
        OR schema.sql NOT LIKE '%UNIQUE (namespace, org_id, project_id, env_id, authority_id)%'
        OR schema.sql NOT LIKE '%CHECK (created_at_ms >= 0)%'
      )
 );
DROP TABLE r103f_phase1_allocation_schema_guard;

CREATE TABLE IF NOT EXISTS linked_device_authority_allocations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  UNIQUE (namespace, org_id, project_id, env_id, authority_id),
  CHECK (created_at_ms >= 0)
);

CREATE INDEX linked_device_authority_allocations_authority_idx
  ON linked_device_authority_allocations (
    namespace, org_id, project_id, env_id, authority_id
  );

PRAGMA defer_foreign_keys = OFF;
