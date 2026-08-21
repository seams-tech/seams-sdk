DROP TRIGGER authorized_operation_linked_grant_claim_atomic;

CREATE TRIGGER authorized_operation_linked_grant_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND NEW.authorization_source_kind = 'authorization_grant'
  AND NEW.authorization_grant_kind = 'linked_device_wallet_session_authorization_v1'
BEGIN
  SELECT CASE
    WHEN (
        (NEW.operation_kind IN ('near.export_key', 'evm.export_key')
          AND NEW.quota_kind != 'quota_neutral')
        OR (NEW.operation_kind NOT IN ('near.export_key', 'evm.export_key')
          AND NEW.quota_kind != 'consume_reusable_wallet_session')
      )
      OR NEW.capability_kind NOT IN ('near_ed25519_mpc_signing', 'evm_ecdsa_mpc_signing')
      OR NOT EXISTS (
        SELECT 1
          FROM linked_device_wallet_session_authorizations AS grant_record
          JOIN lane_enrollments AS enrollment
            ON enrollment.namespace = grant_record.namespace
           AND enrollment.org_id = grant_record.org_id
           AND enrollment.project_id = grant_record.project_id
           AND enrollment.env_id = grant_record.env_id
           AND enrollment.org_id = NEW.linked_scope_org_id
           AND enrollment.project_id = NEW.linked_scope_project_id
           AND enrollment.env_id = NEW.linked_scope_env_id
           AND enrollment.enrollment_id = grant_record.enrollment_id
           AND enrollment.wallet_id = grant_record.wallet_id
           AND json_extract(enrollment.lifecycle_json, '$.state') = 'active'
           AND json_extract(enrollment.lifecycle_json, '$.manifestDigestB64u') = grant_record.key_manifest_digest_b64u
         JOIN lane_product_epochs AS product
            ON product.namespace = grant_record.namespace
           AND product.org_id = grant_record.org_id
           AND product.project_id = grant_record.project_id
           AND product.env_id = grant_record.env_id
           AND product.org_id = NEW.linked_scope_org_id
           AND product.project_id = NEW.linked_scope_project_id
           AND product.env_id = NEW.linked_scope_env_id
           AND product.enrollment_id = grant_record.enrollment_id
           AND product.wallet_id = grant_record.wallet_id
           AND product.wallet_id = NEW.linked_wallet_id
           AND product.enrollment_id = NEW.linked_enrollment_id
           AND product.wallet_key_id = NEW.linked_wallet_key_id
           AND product.lane_id = NEW.linked_lane_id
           AND product.lane_share_epoch = NEW.linked_lane_share_epoch
           AND product.target_material_activation_id = NEW.material_activation_id
           AND product.revocation_epoch = NEW.linked_revocation_epoch
           AND product.state = 'active'
           AND product.lane_kind = 'linked_device'
           AND (
             (NEW.capability_kind = 'near_ed25519_mpc_signing' AND product.key_family = 'ed25519')
             OR (NEW.capability_kind = 'evm_ecdsa_mpc_signing' AND product.key_family = 'ecdsa_secp256k1')
           )
           AND json_extract(product.material_activation_json, '$.activationId') = NEW.material_activation_id
           AND json_extract(product.material_activation_json, '$.capability') = NEW.material_activation_capability
           AND json_extract(product.material_activation_json, '$.materialOwner') = NEW.material_activation_owner
           AND json_extract(product.material_activation_json, '$.keyBinding') = NEW.material_activation_key_binding
           AND json_extract(product.material_activation_json, '$.lifecycleBinding') = NEW.material_activation_lifecycle_binding
           AND json_extract(product.material_activation_json, '$.signingWorker') = NEW.material_activation_signing_worker
         JOIN lane_protocol_operations AS protocol
          ON protocol.namespace = product.namespace
          AND protocol.org_id = product.org_id
          AND protocol.project_id = product.project_id
          AND protocol.env_id = product.env_id
          AND protocol.org_id = NEW.linked_scope_org_id
          AND protocol.project_id = NEW.linked_scope_project_id
          AND protocol.env_id = NEW.linked_scope_env_id
          AND protocol.operation_id = product.operation_id
          AND protocol.enrollment_id = product.enrollment_id
          AND protocol.enrollment_id = NEW.linked_enrollment_id
          AND protocol.wallet_id = NEW.linked_wallet_id
          AND protocol.wallet_key_id = NEW.linked_wallet_key_id
          AND protocol.target_lane_id = NEW.linked_lane_id
          AND protocol.target_lane_share_epoch = NEW.linked_lane_share_epoch
          AND protocol.target_material_activation_id = product.target_material_activation_id
          AND protocol.target_material_activation_id = NEW.material_activation_id
          AND json_extract(protocol.lifecycle_json, '$.state') = 'active'
         WHERE grant_record.namespace = NEW.namespace
           AND grant_record.org_id = NEW.linked_scope_org_id
           AND grant_record.project_id = NEW.linked_scope_project_id
           AND grant_record.env_id = NEW.linked_scope_env_id
           AND grant_record.org_id = product.org_id
           AND grant_record.project_id = product.project_id
           AND grant_record.env_id = product.env_id
           AND grant_record.tenant_id = NEW.tenant_id
           AND grant_record.authorization_id = NEW.authorization_id
           AND grant_record.principal_id = NEW.principal_id
           AND (
             NEW.quota_kind = 'quota_neutral'
             OR grant_record.quota_id = NEW.quota_id
           )
           AND grant_record.wallet_id = NEW.linked_wallet_id
           AND grant_record.enrollment_id = NEW.linked_enrollment_id
           AND grant_record.device_id = NEW.linked_device_id
           AND grant_record.lifecycle_kind = 'active'
           AND grant_record.expires_at_ms > NEW.claimed_at_ms
           AND json_extract(grant_record.permission_json, '$.kind') = 'delegated_wallet_authority_v1'
           AND json_type(grant_record.permission_json, '$.permissions') = 'array'
           AND EXISTS (
             SELECT 1
               FROM json_each(grant_record.permission_json, '$.permissions') AS permission
              WHERE permission.value = CASE
                WHEN NEW.operation_kind IN ('near.export_key', 'evm.export_key')
                THEN 'export_keys'
                ELSE 'sign'
              END
           )
      )
    THEN RAISE(ABORT, 'authorization_linked_device_rejected')
  END;

  UPDATE linked_device_wallet_session_quotas
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'exhausted' ELSE 'active' END
   WHERE NEW.quota_kind = 'consume_reusable_wallet_session'
     AND namespace = NEW.namespace
     AND org_id = NEW.linked_scope_org_id
     AND project_id = NEW.linked_scope_project_id
     AND env_id = NEW.linked_scope_env_id
     AND tenant_id = NEW.tenant_id
     AND quota_id = NEW.quota_id
     AND authorization_id = NEW.authorization_id
     AND principal_id = NEW.principal_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;
END;
