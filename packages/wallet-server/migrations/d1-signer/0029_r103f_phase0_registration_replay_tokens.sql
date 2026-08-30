-- R103F Phase 0: retain the legacy registration replay boundary without
-- changing the one-token-per-session invariant used by ordinary V1 callers.
-- Only token digests are stored. The bearer is returned to the old client
-- after this row commits and can never be reconstructed from this table.

CREATE TABLE registration_replay_opaque_wallet_session_tokens_v1 (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  curve TEXT NOT NULL,
  registration_ceremony_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  operation_fingerprint TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  authority_digest TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  binding_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  session_expires_at_ms INTEGER NOT NULL,
  token_expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, token_hash),
  FOREIGN KEY (namespace, tenant_id, wallet_session_id)
    REFERENCES reusable_wallet_sessions(namespace, tenant_id, wallet_session_id),
  CHECK (length(namespace) > 0),
  CHECK (length(tenant_id) > 0),
  CHECK (length(token_hash) > 0),
  CHECK (curve IN ('ecdsa', 'ed25519')),
  CHECK (length(registration_ceremony_id) > 0),
  CHECK (operation IN ('registration_activate', 'near_provisioning')),
  CHECK (length(operation_fingerprint) > 0),
  CHECK (length(authorization_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(quota_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(authority_digest) > 0),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (json_valid(binding_json)),
  CHECK (
    COALESCE(
      json_extract(binding_json, '$.kind') = 'opaque_owner_wallet_session_binding_v1',
      0
    )
  ),
  CHECK (COALESCE(json_extract(binding_json, '$.curve') = curve, 0)),
  CHECK (COALESCE(json_extract(binding_json, '$.authorizationId') = authorization_id, 0)),
  CHECK (COALESCE(json_extract(binding_json, '$.walletSessionId') = wallet_session_id, 0)),
  CHECK (COALESCE(json_extract(binding_json, '$.quotaId') = quota_id, 0)),
  CHECK (COALESCE(json_extract(binding_json, '$.walletId') = wallet_id, 0)),
  CHECK (issued_at_ms > 0),
  CHECK (session_expires_at_ms > issued_at_ms),
  CHECK (
    COALESCE(json_extract(binding_json, '$.thresholdExpiresAtMs') = session_expires_at_ms, 0)
  ),
  CHECK (token_expires_at_ms > issued_at_ms),
  CHECK (token_expires_at_ms <= session_expires_at_ms),
  CHECK (token_expires_at_ms <= issued_at_ms + 300000)
);

CREATE TRIGGER registration_replay_opaque_wallet_session_tokens_v1_parent_guard
BEFORE INSERT ON registration_replay_opaque_wallet_session_tokens_v1
WHEN NOT EXISTS (
  SELECT 1
    FROM reusable_wallet_sessions AS session
    JOIN authorization_wallet_session_quotas AS quota
      ON quota.namespace = session.namespace
     AND quota.tenant_id = session.tenant_id
     AND quota.quota_id = session.quota_id
   WHERE session.namespace = NEW.namespace
     AND session.tenant_id = NEW.tenant_id
     AND session.wallet_session_id = NEW.wallet_session_id
     AND session.authorization_id = NEW.authorization_id
     AND session.quota_id = NEW.quota_id
     AND session.principal_id = NEW.principal_id
     AND session.wallet_id = NEW.wallet_id
     AND session.authority_digest = NEW.authority_digest
     AND session.wallet_auth_method_id = NEW.wallet_auth_method_id
     AND session.lifecycle_kind = 'active'
     AND session.expires_at_ms = NEW.session_expires_at_ms
     AND quota.namespace = NEW.namespace
     AND quota.tenant_id = NEW.tenant_id
     AND quota.quota_id = NEW.quota_id
     AND quota.wallet_session_id = NEW.wallet_session_id
     AND quota.principal_id = NEW.principal_id
     AND quota.lifecycle_kind = 'active'
     AND quota.remaining_uses > 0
     AND quota.expires_at_ms = NEW.session_expires_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'registration_replay_parent_rejected');
END;

CREATE TRIGGER registration_replay_opaque_wallet_session_tokens_v1_immutable_guard
BEFORE UPDATE ON registration_replay_opaque_wallet_session_tokens_v1
BEGIN
  SELECT RAISE(ABORT, 'registration_replay_identity_rejected');
END;

CREATE INDEX registration_replay_opaque_wallet_session_tokens_v1_identity_idx
  ON registration_replay_opaque_wallet_session_tokens_v1 (
    namespace,
    tenant_id,
    registration_ceremony_id,
    operation,
    operation_fingerprint,
    wallet_session_id,
    authorization_id,
    quota_id,
    principal_id,
    wallet_id,
    authority_digest,
    wallet_auth_method_id,
    curve,
    token_expires_at_ms
  );

CREATE INDEX registration_replay_opaque_wallet_session_tokens_v1_session_idx
  ON registration_replay_opaque_wallet_session_tokens_v1 (
    namespace,
    tenant_id,
    wallet_session_id,
    curve,
    token_expires_at_ms
  );

CREATE INDEX registration_replay_opaque_wallet_session_tokens_v1_expiry_idx
  ON registration_replay_opaque_wallet_session_tokens_v1 (
    namespace,
    tenant_id,
    token_expires_at_ms
  );
