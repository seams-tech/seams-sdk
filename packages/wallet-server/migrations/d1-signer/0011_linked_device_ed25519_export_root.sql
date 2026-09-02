ALTER TABLE linked_device_custody_transfers
  RENAME TO linked_device_ed25519_export_root_transfers;

DROP INDEX linked_device_custody_transfers_enrollment_idx;

CREATE UNIQUE INDEX linked_device_ed25519_export_root_transfers_enrollment_idx
  ON linked_device_ed25519_export_root_transfers (
    namespace, org_id, project_id, env_id, wallet_id, enrollment_id, device_id
  );
