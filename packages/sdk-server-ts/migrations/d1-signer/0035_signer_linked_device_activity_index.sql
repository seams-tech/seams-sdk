CREATE INDEX IF NOT EXISTS authorized_operation_audit_linked_device_activity_idx
  ON authorized_operation_audit_events(
    namespace,
    authorization_grant_kind,
    linked_scope_org_id,
    linked_scope_project_id,
    linked_scope_env_id,
    linked_wallet_id,
    linked_enrollment_id,
    linked_device_id
  );
