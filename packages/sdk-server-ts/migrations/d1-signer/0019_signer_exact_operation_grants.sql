ALTER TABLE capability_grants ADD COLUMN operation_id TEXT;
ALTER TABLE authorization_audit_events ADD COLUMN operation_id TEXT;

CREATE TRIGGER capability_grant_exact_operation_insert
BEFORE INSERT ON capability_grants
WHEN NEW.operation_id IS NULL
  OR length(trim(NEW.operation_id)) = 0
  OR NEW.remaining_uses != 1
BEGIN
  SELECT RAISE(ABORT, 'capability_grant_requires_exact_one_use_operation');
END;

CREATE TRIGGER authorization_audit_exact_operation
AFTER INSERT ON authorization_audit_events
BEGIN
  UPDATE authorization_audit_events
     SET operation_id = (
       SELECT operation_id
         FROM capability_grant_uses AS use_record
        WHERE use_record.namespace = NEW.namespace
          AND use_record.tenant_id = NEW.tenant_id
          AND use_record.use_id = NEW.use_id
     )
   WHERE namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND event_id = NEW.event_id;

  SELECT CASE
    WHEN (
      SELECT operation_id
        FROM authorization_audit_events
       WHERE namespace = NEW.namespace
         AND tenant_id = NEW.tenant_id
         AND event_id = NEW.event_id
    ) IS NULL
    THEN RAISE(ABORT, 'authorization_audit_operation_missing')
  END;
END;

CREATE TRIGGER capability_grant_use_exact_operation
BEFORE INSERT ON capability_grant_uses
WHEN NOT EXISTS (
  SELECT 1
    FROM capability_grants AS grant
   WHERE grant.namespace = NEW.namespace
     AND grant.tenant_id = NEW.tenant_id
     AND grant.grant_id = NEW.grant_id
     AND grant.operation_id = NEW.operation_id
)
BEGIN
  SELECT RAISE(ABORT, 'capability_grant_operation_mismatch');
END;
