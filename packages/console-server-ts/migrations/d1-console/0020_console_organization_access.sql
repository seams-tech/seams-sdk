ALTER TABLE organizations ADD COLUMN owner_anchor_membership_id TEXT;
ALTER TABLE organizations ADD COLUMN owner_set_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN authorization_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE organization_access_migration_guard (
  valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO organization_access_migration_guard (valid)
SELECT CASE
  WHEN EXISTS (
    SELECT 1
    FROM team_members AS legacy_member,
         json_each(legacy_member.roles_json) AS legacy_role
    WHERE json_extract(legacy_role.value, '$.role') IS NULL
       OR json_extract(legacy_role.value, '$.role') NOT IN (
         'owner',
         'admin',
         'admin_manage_admins',
         'admin_manage_members',
         'overview_read',
         'overview_write',
         'administration_read',
         'administration_write',
         'wallet_operations_read',
         'wallet_operations_write',
         'integrations_read',
         'integrations_write',
         'billing_read',
         'billing_write'
       )
  )
  THEN 0
  ELSE 1
END;

CREATE TABLE organization_memberships (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  display_name TEXT,
  kind TEXT NOT NULL,
  role TEXT NOT NULL,
  suspended_at_ms INTEGER,
  removed_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE,
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(id) > 0),
  CHECK (length(user_id) > 0),
  CHECK (length(email) > 0),
  CHECK (email = email_normalized),
  CHECK (kind IN ('ACTIVE', 'SUSPENDED', 'REMOVED')),
  CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER')),
  CHECK (role <> 'OWNER' OR kind = 'ACTIVE'),
  CHECK (
    (kind = 'ACTIVE' AND suspended_at_ms IS NULL AND removed_at_ms IS NULL)
    OR
    (kind = 'SUSPENDED' AND suspended_at_ms IS NOT NULL AND removed_at_ms IS NULL)
    OR
    (kind = 'REMOVED' AND suspended_at_ms IS NULL AND removed_at_ms IS NOT NULL)
  ),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE UNIQUE INDEX organization_memberships_current_user_uidx
  ON organization_memberships (namespace, org_id, user_id)
  WHERE kind <> 'REMOVED';

CREATE UNIQUE INDEX organization_memberships_current_email_uidx
  ON organization_memberships (namespace, org_id, email_normalized)
  WHERE kind <> 'REMOVED';

CREATE INDEX organization_memberships_org_kind_idx
  ON organization_memberships (namespace, org_id, kind, updated_at_ms DESC);

CREATE INDEX organization_memberships_org_role_idx
  ON organization_memberships (namespace, org_id, role, kind);

CREATE TABLE organization_admin_permissions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  membership_id TEXT NOT NULL,
  permission TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, membership_id, permission),
  FOREIGN KEY (namespace, org_id, membership_id)
    REFERENCES organization_memberships(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (permission IN ('members.manage', 'projects.manage', 'billing.view', 'billing.manage')),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE organization_invitations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  invited_by_user_id TEXT NOT NULL,
  role TEXT NOT NULL,
  admin_permissions_json TEXT NOT NULL DEFAULT '[]',
  project_access_json TEXT NOT NULL DEFAULT '[]',
  kind TEXT NOT NULL,
  token_hash TEXT,
  expires_at_ms INTEGER,
  membership_id TEXT,
  accepted_at_ms INTEGER,
  declined_at_ms INTEGER,
  revoked_at_ms INTEGER,
  expired_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE,
  FOREIGN KEY (namespace, org_id, membership_id)
    REFERENCES organization_memberships(namespace, org_id, id),
  CHECK (length(email) > 0),
  CHECK (email = email_normalized),
  CHECK (length(invited_by_user_id) > 0),
  CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER')),
  CHECK (json_valid(admin_permissions_json)),
  CHECK (json_type(admin_permissions_json) = 'array'),
  CHECK (json_valid(project_access_json)),
  CHECK (json_type(project_access_json) = 'array'),
  CHECK (
    (role = 'OWNER' AND json_array_length(admin_permissions_json) = 0 AND json_array_length(project_access_json) = 0)
    OR (role = 'ADMIN' AND json_array_length(project_access_json) = 0)
    OR (role = 'MEMBER' AND json_array_length(admin_permissions_json) = 0)
  ),
  CHECK (kind IN ('PENDING', 'ACCEPTED', 'DECLINED', 'REVOKED', 'EXPIRED')),
  CHECK (
    (
      kind = 'PENDING'
      AND token_hash IS NOT NULL
      AND expires_at_ms IS NOT NULL
      AND membership_id IS NULL
      AND accepted_at_ms IS NULL
      AND declined_at_ms IS NULL
      AND revoked_at_ms IS NULL
      AND expired_at_ms IS NULL
    )
    OR
    (
      kind = 'ACCEPTED'
      AND token_hash IS NULL
      AND expires_at_ms IS NULL
      AND membership_id IS NOT NULL
      AND accepted_at_ms IS NOT NULL
      AND declined_at_ms IS NULL
      AND revoked_at_ms IS NULL
      AND expired_at_ms IS NULL
    )
    OR
    (
      kind = 'DECLINED'
      AND token_hash IS NULL
      AND expires_at_ms IS NULL
      AND membership_id IS NULL
      AND accepted_at_ms IS NULL
      AND declined_at_ms IS NOT NULL
      AND revoked_at_ms IS NULL
      AND expired_at_ms IS NULL
    )
    OR
    (
      kind = 'REVOKED'
      AND token_hash IS NULL
      AND expires_at_ms IS NULL
      AND membership_id IS NULL
      AND accepted_at_ms IS NULL
      AND declined_at_ms IS NULL
      AND revoked_at_ms IS NOT NULL
      AND expired_at_ms IS NULL
    )
    OR
    (
      kind = 'EXPIRED'
      AND token_hash IS NULL
      AND expires_at_ms IS NULL
      AND membership_id IS NULL
      AND accepted_at_ms IS NULL
      AND declined_at_ms IS NULL
      AND revoked_at_ms IS NULL
      AND expired_at_ms IS NOT NULL
    )
  ),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE UNIQUE INDEX organization_invitations_namespace_id_uidx
  ON organization_invitations (namespace, id);

CREATE UNIQUE INDEX organization_invitations_pending_email_uidx
  ON organization_invitations (namespace, org_id, email_normalized)
  WHERE kind = 'PENDING';

CREATE INDEX organization_invitations_org_kind_idx
  ON organization_invitations (namespace, org_id, kind, updated_at_ms DESC);

CREATE TABLE project_member_access (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  membership_id TEXT NOT NULL,
  access_level TEXT NOT NULL,
  granted_by_user_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, membership_id),
  FOREIGN KEY (namespace, org_id, membership_id)
    REFERENCES organization_memberships(namespace, org_id, id)
    ON DELETE CASCADE,
  FOREIGN KEY (namespace, project_id, org_id)
    REFERENCES projects(namespace, id, org_id)
    ON DELETE CASCADE,
  CHECK (access_level IN ('viewer', 'editor')),
  CHECK (length(granted_by_user_id) > 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE INDEX project_member_access_membership_idx
  ON project_member_access (namespace, org_id, membership_id, project_id);

CREATE TABLE organization_owner_events (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  membership_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  actor_user_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE,
  CHECK (kind IN ('OWNER_ADDED', 'OWNER_REMOVED')),
  CHECK (length(owner_user_id) > 0),
  CHECK (length(actor_user_id) > 0),
  CHECK (created_at_ms > 0)
);

CREATE INDEX organization_owner_events_org_created_idx
  ON organization_owner_events (namespace, org_id, created_at_ms DESC, id DESC);

INSERT INTO organization_memberships (
  namespace,
  org_id,
  id,
  user_id,
  email,
  email_normalized,
  display_name,
  kind,
  role,
  suspended_at_ms,
  removed_at_ms,
  created_at_ms,
  updated_at_ms
)
SELECT
  legacy.namespace,
  legacy.org_id,
  legacy.id,
  legacy.user_id,
  lower(trim(legacy.email)),
  lower(trim(legacy.email)),
  legacy.display_name,
  CASE legacy.status
    WHEN 'ACTIVE' THEN 'ACTIVE'
    WHEN 'SUSPENDED' THEN 'SUSPENDED'
    WHEN 'REMOVED' THEN 'REMOVED'
  END,
  CASE
    WHEN legacy.status = 'ACTIVE' AND EXISTS (
      SELECT 1 FROM json_each(legacy.roles_json)
      WHERE json_extract(value, '$.role') = 'owner'
    ) THEN 'OWNER'
    WHEN EXISTS (
      SELECT 1 FROM json_each(legacy.roles_json)
      WHERE json_extract(value, '$.role') = 'admin'
    ) THEN 'ADMIN'
    ELSE 'MEMBER'
  END,
  CASE WHEN legacy.status = 'SUSPENDED' THEN legacy.last_status_changed_at_ms END,
  CASE WHEN legacy.status = 'REMOVED' THEN legacy.last_status_changed_at_ms END,
  legacy.created_at_ms,
  legacy.updated_at_ms
FROM team_members AS legacy
WHERE legacy.status IN ('ACTIVE', 'SUSPENDED', 'REMOVED');

INSERT OR IGNORE INTO organization_admin_permissions (
  namespace,
  org_id,
  membership_id,
  permission,
  created_at_ms,
  updated_at_ms
)
SELECT
  membership.namespace,
  membership.org_id,
  membership.id,
  'members.manage',
  membership.created_at_ms,
  membership.updated_at_ms
FROM organization_memberships AS membership
JOIN team_members AS legacy
  ON legacy.namespace = membership.namespace
 AND legacy.org_id = membership.org_id
 AND legacy.id = membership.id
WHERE membership.role = 'ADMIN'
  AND EXISTS (
    SELECT 1 FROM json_each(legacy.roles_json)
    WHERE json_extract(value, '$.role') = 'admin_manage_members'
  );

INSERT OR IGNORE INTO organization_admin_permissions (
  namespace,
  org_id,
  membership_id,
  permission,
  created_at_ms,
  updated_at_ms
)
SELECT
  membership.namespace,
  membership.org_id,
  membership.id,
  'projects.manage',
  membership.created_at_ms,
  membership.updated_at_ms
FROM organization_memberships AS membership
JOIN team_members AS legacy
  ON legacy.namespace = membership.namespace
 AND legacy.org_id = membership.org_id
 AND legacy.id = membership.id
WHERE membership.role = 'ADMIN'
  AND EXISTS (
    SELECT 1 FROM json_each(legacy.roles_json)
    WHERE json_extract(value, '$.role') IN (
      'administration_write',
      'wallet_operations_write',
      'integrations_write'
    )
  );

INSERT OR IGNORE INTO organization_admin_permissions (
  namespace,
  org_id,
  membership_id,
  permission,
  created_at_ms,
  updated_at_ms
)
SELECT
  membership.namespace,
  membership.org_id,
  membership.id,
  'billing.view',
  membership.created_at_ms,
  membership.updated_at_ms
FROM organization_memberships AS membership
JOIN team_members AS legacy
  ON legacy.namespace = membership.namespace
 AND legacy.org_id = membership.org_id
 AND legacy.id = membership.id
WHERE membership.role = 'ADMIN'
  AND EXISTS (
    SELECT 1 FROM json_each(legacy.roles_json)
    WHERE json_extract(value, '$.role') IN ('billing_read', 'billing_write')
  );

INSERT OR IGNORE INTO organization_admin_permissions (
  namespace,
  org_id,
  membership_id,
  permission,
  created_at_ms,
  updated_at_ms
)
SELECT
  membership.namespace,
  membership.org_id,
  membership.id,
  'billing.manage',
  membership.created_at_ms,
  membership.updated_at_ms
FROM organization_memberships AS membership
JOIN team_members AS legacy
  ON legacy.namespace = membership.namespace
 AND legacy.org_id = membership.org_id
 AND legacy.id = membership.id
WHERE membership.role = 'ADMIN'
  AND EXISTS (
    SELECT 1 FROM json_each(legacy.roles_json)
    WHERE json_extract(value, '$.role') = 'billing_write'
  );

INSERT INTO project_member_access (
  namespace,
  org_id,
  project_id,
  membership_id,
  access_level,
  granted_by_user_id,
  created_at_ms,
  updated_at_ms
)
SELECT
  membership.namespace,
  membership.org_id,
  project.id,
  membership.id,
  CASE
    WHEN EXISTS (
      SELECT 1 FROM json_each(legacy.roles_json)
      WHERE json_extract(value, '$.role') IN (
        'overview_write',
        'administration_write',
        'wallet_operations_write',
        'integrations_write'
      )
    ) THEN 'editor'
    ELSE 'viewer'
  END,
  legacy.invited_by_user_id,
  membership.created_at_ms,
  membership.updated_at_ms
FROM organization_memberships AS membership
JOIN team_members AS legacy
  ON legacy.namespace = membership.namespace
 AND legacy.org_id = membership.org_id
 AND legacy.id = membership.id
JOIN projects AS project
  ON project.namespace = membership.namespace
 AND project.org_id = membership.org_id
WHERE membership.role = 'MEMBER'
  AND membership.kind <> 'REMOVED';

INSERT INTO organization_invitations (
  namespace,
  org_id,
  id,
  email,
  email_normalized,
  invited_by_user_id,
  role,
  admin_permissions_json,
  project_access_json,
  kind,
  token_hash,
  expires_at_ms,
  membership_id,
  accepted_at_ms,
  declined_at_ms,
  revoked_at_ms,
  expired_at_ms,
  created_at_ms,
  updated_at_ms
)
SELECT
  legacy.namespace,
  legacy.org_id,
  'legacy_' || legacy.id,
  lower(trim(legacy.email)),
  lower(trim(legacy.email)),
  legacy.invited_by_user_id,
  CASE
    WHEN EXISTS (
      SELECT 1 FROM json_each(legacy.roles_json)
      WHERE json_extract(value, '$.role') = 'owner'
    ) THEN 'OWNER'
    WHEN EXISTS (
      SELECT 1 FROM json_each(legacy.roles_json)
      WHERE json_extract(value, '$.role') = 'admin'
    ) THEN 'ADMIN'
    ELSE 'MEMBER'
  END,
  '[]',
  '[]',
  'REVOKED',
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  legacy.updated_at_ms,
  NULL,
  legacy.created_at_ms,
  legacy.updated_at_ms
FROM team_members AS legacy
WHERE legacy.status = 'INVITED';

INSERT INTO organization_owner_events (
  namespace,
  org_id,
  id,
  membership_id,
  owner_user_id,
  actor_user_id,
  kind,
  created_at_ms
)
SELECT
  membership.namespace,
  membership.org_id,
  'migrated_owner_' || membership.id,
  membership.id,
  membership.user_id,
  membership.user_id,
  'OWNER_ADDED',
  membership.created_at_ms
FROM organization_memberships AS membership
WHERE membership.kind = 'ACTIVE'
  AND membership.role = 'OWNER';

UPDATE organizations
SET owner_anchor_membership_id = (
      SELECT membership.id
      FROM organization_memberships AS membership
      WHERE membership.namespace = organizations.namespace
        AND membership.org_id = organizations.id
        AND membership.kind = 'ACTIVE'
        AND membership.role = 'OWNER'
      ORDER BY membership.created_at_ms ASC, membership.id ASC
      LIMIT 1
    ),
    owner_set_version = (
      SELECT COUNT(*)
      FROM organization_memberships AS membership
      WHERE membership.namespace = organizations.namespace
        AND membership.org_id = organizations.id
        AND membership.kind = 'ACTIVE'
        AND membership.role = 'OWNER'
    ),
    authorization_version = 1;

DROP TABLE team_members;
DROP TABLE organization_access_migration_guard;

CREATE TRIGGER organization_memberships_last_owner_update
BEFORE UPDATE OF kind, role ON organization_memberships
WHEN OLD.kind = 'ACTIVE'
 AND OLD.role = 'OWNER'
 AND (NEW.kind <> 'ACTIVE' OR NEW.role <> 'OWNER')
 AND (
   SELECT COUNT(*)
   FROM organization_memberships
   WHERE namespace = OLD.namespace
     AND org_id = OLD.org_id
     AND kind = 'ACTIVE'
     AND role = 'OWNER'
 ) <= 1
BEGIN
  SELECT RAISE(ABORT, 'last_owner_required');
END;

CREATE TRIGGER organization_memberships_last_owner_delete
BEFORE DELETE ON organization_memberships
WHEN OLD.kind = 'ACTIVE'
 AND OLD.role = 'OWNER'
 AND (
   SELECT COUNT(*)
   FROM organization_memberships
   WHERE namespace = OLD.namespace
     AND org_id = OLD.org_id
     AND kind = 'ACTIVE'
     AND role = 'OWNER'
 ) <= 1
BEGIN
  SELECT RAISE(ABORT, 'last_owner_required');
END;

CREATE TRIGGER organizations_owner_anchor_update
BEFORE UPDATE OF owner_anchor_membership_id ON organizations
WHEN NEW.owner_anchor_membership_id IS NOT NULL
 AND NOT EXISTS (
   SELECT 1
   FROM organization_memberships
   WHERE namespace = NEW.namespace
     AND org_id = NEW.id
     AND id = NEW.owner_anchor_membership_id
     AND kind = 'ACTIVE'
     AND role = 'OWNER'
 )
BEGIN
  SELECT RAISE(ABORT, 'owner_anchor_invalid');
END;

CREATE TRIGGER organization_memberships_owner_anchor_update
BEFORE UPDATE OF kind, role ON organization_memberships
WHEN OLD.id = (
   SELECT owner_anchor_membership_id
   FROM organizations
   WHERE namespace = OLD.namespace
     AND id = OLD.org_id
 )
 AND (NEW.kind <> 'ACTIVE' OR NEW.role <> 'OWNER')
BEGIN
  SELECT RAISE(ABORT, 'owner_anchor_required');
END;

CREATE TRIGGER organization_admin_permissions_role_insert
BEFORE INSERT ON organization_admin_permissions
WHEN NOT EXISTS (
  SELECT 1
  FROM organization_memberships
  WHERE namespace = NEW.namespace
    AND org_id = NEW.org_id
    AND id = NEW.membership_id
    AND role = 'ADMIN'
    AND kind <> 'REMOVED'
)
BEGIN
  SELECT RAISE(ABORT, 'admin_permission_membership_invalid');
END;

CREATE TRIGGER project_member_access_role_insert
BEFORE INSERT ON project_member_access
WHEN NOT EXISTS (
  SELECT 1
  FROM organization_memberships
  WHERE namespace = NEW.namespace
    AND org_id = NEW.org_id
    AND id = NEW.membership_id
    AND role = 'MEMBER'
    AND kind = 'ACTIVE'
)
BEGIN
  SELECT RAISE(ABORT, 'project_access_membership_invalid');
END;

CREATE TRIGGER organization_memberships_authorization_insert
AFTER INSERT ON organization_memberships
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1,
      owner_set_version = owner_set_version + CASE
        WHEN NEW.kind = 'ACTIVE' AND NEW.role = 'OWNER' THEN 1
        ELSE 0
      END
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER organization_memberships_authorization_update
AFTER UPDATE OF kind, role ON organization_memberships
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1,
      owner_set_version = owner_set_version + CASE
        WHEN OLD.kind = 'ACTIVE' AND OLD.role = 'OWNER'
         AND (NEW.kind <> 'ACTIVE' OR NEW.role <> 'OWNER') THEN 1
        WHEN (OLD.kind <> 'ACTIVE' OR OLD.role <> 'OWNER')
         AND NEW.kind = 'ACTIVE' AND NEW.role = 'OWNER' THEN 1
        ELSE 0
      END
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER organization_memberships_authorization_delete
AFTER DELETE ON organization_memberships
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1,
      owner_set_version = owner_set_version + CASE
        WHEN OLD.kind = 'ACTIVE' AND OLD.role = 'OWNER' THEN 1
        ELSE 0
      END
  WHERE namespace = OLD.namespace
    AND id = OLD.org_id;
END;

CREATE TRIGGER organization_admin_permissions_authorization_insert
AFTER INSERT ON organization_admin_permissions
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER organization_admin_permissions_authorization_delete
AFTER DELETE ON organization_admin_permissions
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = OLD.namespace
    AND id = OLD.org_id;
END;

CREATE TRIGGER project_member_access_authorization_insert
AFTER INSERT ON project_member_access
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER project_member_access_authorization_update
AFTER UPDATE OF access_level ON project_member_access
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER project_member_access_authorization_delete
AFTER DELETE ON project_member_access
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = OLD.namespace
    AND id = OLD.org_id;
END;

CREATE VIEW organization_access_ownerless_organizations AS
SELECT
  organization.namespace,
  organization.id AS org_id
FROM organizations AS organization
WHERE organization.owner_anchor_membership_id IS NULL
   OR NOT EXISTS (
     SELECT 1
     FROM organization_memberships AS owner
     WHERE owner.namespace = organization.namespace
       AND owner.org_id = organization.id
       AND owner.kind = 'ACTIVE'
       AND owner.role = 'OWNER'
   );
