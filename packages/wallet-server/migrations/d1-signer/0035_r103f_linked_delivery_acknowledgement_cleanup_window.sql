-- R103F linked-delivery acknowledgement cleanup window.
--
-- Acknowledgement and cleanup authorization may be issued by an exact-method
-- successor after the original delivery/session expires. Keep the original
-- delivery expiry as durable identity, while allowing the server-owned,
-- acknowledgement-anchored cleanup window to extend beyond it. Every other
-- delivery constraint remains unchanged.

PRAGMA defer_foreign_keys = ON;

DROP TRIGGER IF EXISTS linked_device_wallet_session_credential_delivery_insert_lifecycle_guard;
DROP TRIGGER IF EXISTS linked_device_wallet_session_credential_delivery_identity_guard;
DROP TRIGGER IF EXISTS linked_device_wallet_session_credential_delivery_envelope_guard;
DROP TRIGGER IF EXISTS linked_device_wallet_session_credential_delivery_acknowledgement_guard;
DROP TRIGGER IF EXISTS linked_device_wallet_session_credential_delivery_cleanup_receipt_guard;
DROP TRIGGER IF EXISTS linked_device_wallet_session_credential_delivery_cleanup_completion_guard;
DROP TRIGGER IF EXISTS linked_device_wallet_session_credential_delivery_parent_guard;
DROP TRIGGER IF EXISTS linked_device_wallet_session_credential_delivery_lifecycle_guard;

DROP INDEX IF EXISTS linked_device_wallet_session_credential_deliveries_v1_lifecycle_idx;
DROP INDEX IF EXISTS linked_device_wallet_session_credential_deliveries_v1_parent_idx;

CREATE TABLE linked_device_wallet_session_credential_deliveries_v1_next (
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
      AND acknowledgement_auth_binding_digest_b64u = recipient_binding_digest_b64u
    )
  )
);

INSERT INTO linked_device_wallet_session_credential_deliveries_v1_next (
  namespace, org_id, project_id, env_id, link_session_id, tenant_id,
  authorization_id, wallet_session_id, quota_id, principal_id, authority_id,
  wallet_id, wallet_auth_method_id, credential_digest_b64u, recipient_kind,
  recipient_public_key_b64u, recipient_binding_digest_b64u, envelope_alg,
  aad_digest_b64u, sealed_envelope_json, sealed_envelope_digest_b64u,
  installation_receipt_digest_b64u, issued_at_ms, expires_at_ms, lifecycle_kind,
  acknowledged_at_ms, acknowledgement_receipt_json, cleanup_state,
  cleanup_receipt_json, cleanup_completed_at_ms, acknowledgement_auth_binding_digest_b64u,
  acknowledgement_auth_package_set_digest_b64u, acknowledgement_auth_expires_at_ms
)
SELECT
  namespace, org_id, project_id, env_id, link_session_id, tenant_id,
  authorization_id, wallet_session_id, quota_id, principal_id, authority_id,
  wallet_id, wallet_auth_method_id, credential_digest_b64u, recipient_kind,
  recipient_public_key_b64u, recipient_binding_digest_b64u, envelope_alg,
  aad_digest_b64u, sealed_envelope_json, sealed_envelope_digest_b64u,
  installation_receipt_digest_b64u, issued_at_ms, expires_at_ms, lifecycle_kind,
  acknowledged_at_ms, acknowledgement_receipt_json, cleanup_state,
  cleanup_receipt_json, cleanup_completed_at_ms, acknowledgement_auth_binding_digest_b64u,
  acknowledgement_auth_package_set_digest_b64u, acknowledgement_auth_expires_at_ms
FROM linked_device_wallet_session_credential_deliveries_v1;

DROP TABLE linked_device_wallet_session_credential_deliveries_v1;
ALTER TABLE linked_device_wallet_session_credential_deliveries_v1_next
  RENAME TO linked_device_wallet_session_credential_deliveries_v1;

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

PRAGMA defer_foreign_keys = OFF;
