-- R103F exact authorized-operation enforcement.
--
-- Wallet Session grants are admitted only from a fully scoped V2
-- authorization. The scope and the authorization's quota, authority, and
-- auth-method identities must resolve as one exact row.

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
        OR NEW.linked_scope_org_id IS NULL
        OR NEW.linked_scope_project_id IS NULL
        OR NEW.linked_scope_env_id IS NULL
        OR length(NEW.linked_scope_org_id) = 0
        OR length(NEW.linked_scope_project_id) = 0
        OR length(NEW.linked_scope_env_id) = 0
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
        FROM wallet_session_authorizations_v2 AS session
        JOIN authorization_wallet_session_quotas AS quota
          ON quota.namespace = session.namespace
         AND quota.tenant_id = session.tenant_id
         AND quota.quota_id = session.quota_id
         AND quota.wallet_session_id = session.wallet_session_id
         AND quota.principal_id = session.principal_id
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
       WHERE session.namespace = NEW.namespace
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
     AND wallet_session_id = (
       SELECT session.wallet_session_id
         FROM wallet_session_authorizations_v2 AS session
         JOIN authorization_wallet_session_quotas AS quota
           ON quota.namespace = session.namespace
          AND quota.tenant_id = session.tenant_id
          AND quota.quota_id = session.quota_id
          AND quota.wallet_session_id = session.wallet_session_id
          AND quota.principal_id = session.principal_id
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
        WHERE session.namespace = NEW.namespace
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
     );

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;
END;
