import { secureRandomBase36 } from '../boundary';
import {
  d1ChangedRows,
  d1Number,
  parseD1JsonArrayColumn,
  queryD1All,
  queryD1One,
  type D1Row,
  type D1ResultLike,
} from '../boundary';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../boundary';
import {
  createConsoleEmailOutboxInsertStatement,
  createConsoleInvitationEmailCancellationStatement,
} from '../email/d1';
import type { ConsoleInvitationSecretCipher } from '../email/secrets';
import {
  buildMembershipAccessChangedEmailV1,
  buildOrganizationInvitationEmailV1,
  buildOwnerMembershipChangedEmailV1,
} from '../email/templates';
import { ConsoleOrganizationAccessError } from './errors';
import { createOrganizationInvitationToken, hashOrganizationInvitationToken } from './secret';
import type {
  BootstrapInitialOwnerInput,
  ConsoleOrganizationAccessService,
  OrganizationAccessContext,
  OrganizationAuthorizationLookup,
  VerifiedInvitationAccount,
} from './service';
import {
  ORGANIZATION_ADMIN_PERMISSIONS,
  type ActiveOrganizationMembership,
  type ActiveOwnerMembership,
  type ChangeOrganizationMembershipRoleRequest,
  type InviteOrganizationMemberRequest,
  type IssuedOrganizationInvitation,
  type ListOrganizationInvitationsRequest,
  type ListOrganizationMembershipsRequest,
  type OrganizationAdminPermission,
  type OrganizationAuthorization,
  type OrganizationInvitation,
  type OrganizationInvitationGrant,
  type OrganizationMembership,
  type OrganizationMembershipWithAccess,
  type OrganizationOwnerEvent,
  type ProjectAccessAssignment,
  type ProjectAccessLevel,
  type RedeemOrganizationInvitationRequest,
  type SetOrganizationAdminPermissionsRequest,
  type SetProjectMemberAccessRequest,
} from './types';

const DEFAULT_INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1_000;

const REQUIRED_ORGANIZATION_ACCESS_TABLES = [
  'organizations',
  'organization_memberships',
  'organization_admin_permissions',
  'organization_invitations',
  'project_member_access',
  'organization_owner_events',
] as const;

export const CONSOLE_ORGANIZATION_ACCESS_D1_RUNTIME = Symbol('consoleOrganizationAccessD1Runtime');

export interface ConsoleOrganizationAccessD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleOrganizationAccessD1Service = ConsoleOrganizationAccessService & {
  readonly [CONSOLE_ORGANIZATION_ACCESS_D1_RUNTIME]: ConsoleOrganizationAccessD1Runtime;
};

export interface D1ConsoleOrganizationAccessSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleOrganizationAccessServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
  readonly invitationTtlMs?: number;
  readonly createInvitationToken?: () => string;
  readonly hashInvitationToken?: (token: string) => Promise<string>;
  readonly email?: D1ConsoleOrganizationEmailOptions;
}

export interface D1ConsoleOrganizationEmailOptions {
  readonly invitationSecretCipher: ConsoleInvitationSecretCipher;
  readonly consoleBaseUrl: string;
}

interface D1OrganizationAccessState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
  readonly invitationTtlMs: number;
  readonly createToken: () => string;
  readonly hashToken: (token: string) => Promise<string>;
  readonly email: D1ConsoleOrganizationEmailOptions | null;
}

interface OrganizationRowState {
  readonly name: string;
  readonly ownerAnchorMembershipId: string | null;
  readonly ownerSetVersion: number;
  readonly authorizationVersion: number;
}

interface InvitationRecord {
  readonly id: string;
  readonly orgId: string;
  readonly email: string;
  readonly invitedByUserId: string;
  readonly role: 'OWNER' | 'ADMIN' | 'MEMBER';
  readonly adminPermissions: readonly OrganizationAdminPermission[];
  readonly projectAccess: readonly ProjectAccessAssignment[];
  readonly kind: 'pending' | 'accepted' | 'declined' | 'revoked' | 'expired';
  readonly tokenHash: string | null;
  readonly expiresAtMs: number | null;
  readonly membershipId: string | null;
  readonly acceptedAtMs: number | null;
  readonly declinedAtMs: number | null;
  readonly revokedAtMs: number | null;
  readonly expiredAtMs: number | null;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}

function accessError(
  code: string,
  status: number,
  message: string,
): ConsoleOrganizationAccessError {
  return new ConsoleOrganizationAccessError(code, status, message);
}

function assertNever(value: never): never {
  throw new Error(`Unhandled D1 organization access branch: ${JSON.stringify(value)}`);
}

function defaultNow(): Date {
  return new Date();
}

function normalizeNamespace(value: string | undefined): string {
  return value?.trim() || 'default';
}

function normalizeOrganizationEmailOptions(
  value: D1ConsoleOrganizationEmailOptions | undefined,
): D1ConsoleOrganizationEmailOptions | null {
  if (!value) return null;
  const consoleBaseUrl = value.consoleBaseUrl.trim();
  let parsed: URL;
  try {
    parsed = new URL(consoleBaseUrl);
  } catch {
    throw new Error('organization email consoleBaseUrl must be a valid URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('organization email consoleBaseUrl must use http or https');
  }
  return {
    invitationSecretCipher: value.invitationSecretCipher,
    consoleBaseUrl: parsed.toString(),
  };
}

function normalizeRequired(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw accessError('invalid_body', 400, `${field} is required`);
  return normalized;
}

function normalizeEmail(value: string): string {
  const normalized = normalizeRequired(value, 'email').toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(normalized)) {
    throw accessError('invalid_body', 400, 'email must be a valid email address');
  }
  return normalized;
}

function normalizeRowString(value: unknown): string {
  return String(value ?? '').trim();
}

function nullableRowString(value: unknown): string | null {
  const normalized = normalizeRowString(value);
  return normalized || null;
}

function nullableRowNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  return Math.trunc(parsed);
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(
    10,
    'organization access IDs',
  )}`;
}

function membershipDisplayName(membership: OrganizationMembership): string {
  return membership.displayName?.trim() || membership.email;
}

async function createInvitationEmailStatement(
  state: D1OrganizationAccessState,
  input: {
    readonly orgId: string;
    readonly organizationName: string;
    readonly invitationId: string;
    readonly invitationSecret: string;
    readonly recipientEmail: string;
    readonly inviterDisplayName: string;
    readonly invitedRole: 'OWNER' | 'ADMIN' | 'MEMBER';
    readonly expiresAt: Date;
    readonly now: Date;
  },
): Promise<D1PreparedStatementLike | null> {
  if (!state.email) return null;
  const outboxId = makeId('console_email', input.now);
  return await createConsoleEmailOutboxInsertStatement({
    database: state.database,
    namespace: state.namespace,
    invitationSecretCipher: state.email.invitationSecretCipher,
    insertGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE',
    email: {
      outboxId,
      dedupeKey: outboxId,
      orgId: input.orgId,
      recipient: {
        email: input.recipientEmail,
        displayName: input.recipientEmail,
      },
      template: buildOrganizationInvitationEmailV1({
        invitationId: input.invitationId,
        organizationName: input.organizationName,
        inviterDisplayName: input.inviterDisplayName,
        invitedRole: input.invitedRole,
        consoleBaseUrl: state.email.consoleBaseUrl,
        expiresAt: input.expiresAt.toISOString(),
      }),
      invitationSecret: input.invitationSecret,
      createdAt: input.now,
      availableAt: input.now,
    },
  });
}

async function createOwnerMembershipChangedEmailStatement(
  state: D1OrganizationAccessState,
  input: {
    readonly orgId: string;
    readonly organizationName: string;
    readonly ownerEmail: string;
    readonly ownerDisplayName: string;
    readonly changedByDisplayName: string;
    readonly change: 'ADDED' | 'REMOVED';
    readonly now: Date;
  },
): Promise<D1PreparedStatementLike | null> {
  if (!state.email) return null;
  const outboxId = makeId('console_email', input.now);
  return await createConsoleEmailOutboxInsertStatement({
    database: state.database,
    namespace: state.namespace,
    invitationSecretCipher: state.email.invitationSecretCipher,
    insertGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE',
    email: {
      outboxId,
      dedupeKey: outboxId,
      orgId: input.orgId,
      recipient: {
        email: input.ownerEmail,
        displayName: input.ownerDisplayName,
      },
      template: buildOwnerMembershipChangedEmailV1({
        change: input.change,
        organizationName: input.organizationName,
        ownerDisplayName: input.ownerDisplayName,
        changedByDisplayName: input.changedByDisplayName,
      }),
      createdAt: input.now,
      availableAt: input.now,
    },
  });
}

async function createMembershipAccessChangedEmailStatement(
  state: D1OrganizationAccessState,
  input: {
    readonly orgId: string;
    readonly organizationName: string;
    readonly memberEmail: string;
    readonly memberDisplayName: string;
    readonly changedByDisplayName: string;
    readonly change: 'SUSPENDED' | 'REMOVED';
    readonly now: Date;
  },
): Promise<D1PreparedStatementLike | null> {
  if (!state.email) return null;
  const outboxId = makeId('console_email', input.now);
  return await createConsoleEmailOutboxInsertStatement({
    database: state.database,
    namespace: state.namespace,
    invitationSecretCipher: state.email.invitationSecretCipher,
    insertGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE',
    email: {
      outboxId,
      dedupeKey: outboxId,
      orgId: input.orgId,
      recipient: {
        email: input.memberEmail,
        displayName: input.memberDisplayName,
      },
      template: buildMembershipAccessChangedEmailV1({
        change: input.change,
        organizationName: input.organizationName,
        memberDisplayName: input.memberDisplayName,
        changedByDisplayName: input.changedByDisplayName,
      }),
      createdAt: input.now,
      availableAt: input.now,
    },
  });
}

function createInvitationCancellationStatement(
  state: D1OrganizationAccessState,
  input: {
    readonly orgId: string;
    readonly invitationId: string;
    readonly now: Date;
    readonly guarded: boolean;
  },
): D1PreparedStatementLike | null {
  if (!state.email) return null;
  return createConsoleInvitationEmailCancellationStatement({
    database: state.database,
    namespace: state.namespace,
    orgId: input.orgId,
    invitationId: input.invitationId,
    canceledAt: input.now,
    ...(input.guarded ? { cancellationGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE' as const } : {}),
  });
}

function parseMembershipRole(value: unknown): 'OWNER' | 'ADMIN' | 'MEMBER' {
  switch (normalizeRowString(value)) {
    case 'OWNER':
      return 'OWNER';
    case 'ADMIN':
      return 'ADMIN';
    case 'MEMBER':
      return 'MEMBER';
    default:
      throw new Error(`Invalid organization membership role row: ${String(value)}`);
  }
}

function parseAdminPermission(value: unknown): OrganizationAdminPermission {
  switch (normalizeRowString(value)) {
    case 'members.manage':
      return 'members.manage';
    case 'projects.manage':
      return 'projects.manage';
    case 'billing.view':
      return 'billing.view';
    case 'billing.manage':
      return 'billing.manage';
    default:
      throw new Error(`Invalid organization administrator permission row: ${String(value)}`);
  }
}

function normalizeAdminPermissions(
  permissions: readonly OrganizationAdminPermission[],
): readonly OrganizationAdminPermission[] {
  const values = new Set<OrganizationAdminPermission>(permissions);
  if (values.has('billing.manage')) values.add('billing.view');
  return ORGANIZATION_ADMIN_PERMISSIONS.filter((permission) => values.has(permission));
}

function parseAdminPermissionsJson(value: unknown): readonly OrganizationAdminPermission[] {
  const permissions: OrganizationAdminPermission[] = [];
  for (const rawPermission of parseD1JsonArrayColumn(value)) {
    permissions.push(parseAdminPermission(rawPermission));
  }
  return normalizeAdminPermissions(permissions);
}

function parseProjectAccessLevel(value: unknown): ProjectAccessLevel {
  switch (normalizeRowString(value)) {
    case 'viewer':
      return 'viewer';
    case 'editor':
      return 'editor';
    default:
      throw new Error(`Invalid project access level row: ${String(value)}`);
  }
}

function parseProjectAccessJson(value: unknown): readonly ProjectAccessAssignment[] {
  const assignments = new Map<string, ProjectAccessAssignment>();
  for (const rawAssignment of parseD1JsonArrayColumn(value)) {
    if (!rawAssignment || typeof rawAssignment !== 'object' || Array.isArray(rawAssignment)) {
      throw new Error('Invalid project access invitation row');
    }
    const row = rawAssignment as Record<string, unknown>;
    const projectId = normalizeRowString(row.projectId);
    if (!projectId) throw new Error('Project access invitation row is missing projectId');
    assignments.set(projectId, {
      projectId,
      accessLevel: parseProjectAccessLevel(row.accessLevel),
    });
  }
  return Array.from(assignments.values()).sort((left, right) =>
    left.projectId.localeCompare(right.projectId),
  );
}

function parseMembershipRow(row: D1Row): OrganizationMembership {
  const id = normalizeRowString(row.id);
  const orgId = normalizeRowString(row.org_id);
  const userId = normalizeRowString(row.user_id);
  const email = normalizeRowString(row.email);
  const displayName = nullableRowString(row.display_name);
  const createdAt = toIso(d1Number(row.created_at_ms));
  const updatedAt = toIso(d1Number(row.updated_at_ms));
  const role = parseMembershipRole(row.role);
  const kind = normalizeRowString(row.kind);
  switch (kind) {
    case 'ACTIVE':
      switch (role) {
        case 'OWNER':
          return {
            id,
            orgId,
            userId,
            email,
            displayName,
            createdAt,
            updatedAt,
            kind: 'active',
            role: 'OWNER',
          };
        case 'ADMIN':
          return {
            id,
            orgId,
            userId,
            email,
            displayName,
            createdAt,
            updatedAt,
            kind: 'active',
            role: 'ADMIN',
          };
        case 'MEMBER':
          return {
            id,
            orgId,
            userId,
            email,
            displayName,
            createdAt,
            updatedAt,
            kind: 'active',
            role: 'MEMBER',
          };
        default:
          return assertNever(role);
      }
    case 'SUSPENDED': {
      const suspendedAtMs = nullableRowNumber(row.suspended_at_ms);
      if (suspendedAtMs === null) throw new Error(`Membership ${id} is missing suspended_at_ms`);
      switch (role) {
        case 'ADMIN':
          return {
            id,
            orgId,
            userId,
            email,
            displayName,
            createdAt,
            updatedAt,
            kind: 'suspended',
            role: 'ADMIN',
            suspendedAt: toIso(suspendedAtMs),
          };
        case 'MEMBER':
          return {
            id,
            orgId,
            userId,
            email,
            displayName,
            createdAt,
            updatedAt,
            kind: 'suspended',
            role: 'MEMBER',
            suspendedAt: toIso(suspendedAtMs),
          };
        case 'OWNER':
          throw new Error(`Owner membership ${id} cannot be suspended`);
        default:
          return assertNever(role);
      }
    }
    case 'REMOVED': {
      const removedAtMs = nullableRowNumber(row.removed_at_ms);
      if (removedAtMs === null) throw new Error(`Membership ${id} is missing removed_at_ms`);
      switch (role) {
        case 'ADMIN':
          return {
            id,
            orgId,
            userId,
            email,
            displayName,
            createdAt,
            updatedAt,
            kind: 'removed',
            role: 'ADMIN',
            removedAt: toIso(removedAtMs),
          };
        case 'MEMBER':
          return {
            id,
            orgId,
            userId,
            email,
            displayName,
            createdAt,
            updatedAt,
            kind: 'removed',
            role: 'MEMBER',
            removedAt: toIso(removedAtMs),
          };
        case 'OWNER':
          throw new Error(`Owner membership ${id} cannot be removed`);
        default:
          return assertNever(role);
      }
    }
    default:
      throw new Error(`Invalid organization membership kind row: ${kind}`);
  }
}

function parseInvitationKind(
  value: unknown,
): 'pending' | 'accepted' | 'declined' | 'revoked' | 'expired' {
  switch (normalizeRowString(value)) {
    case 'PENDING':
      return 'pending';
    case 'ACCEPTED':
      return 'accepted';
    case 'DECLINED':
      return 'declined';
    case 'REVOKED':
      return 'revoked';
    case 'EXPIRED':
      return 'expired';
    default:
      throw new Error(`Invalid organization invitation kind row: ${String(value)}`);
  }
}

function parseInvitationRecord(row: D1Row): InvitationRecord {
  return {
    id: normalizeRowString(row.id),
    orgId: normalizeRowString(row.org_id),
    email: normalizeRowString(row.email),
    invitedByUserId: normalizeRowString(row.invited_by_user_id),
    role: parseMembershipRole(row.role),
    adminPermissions: parseAdminPermissionsJson(row.admin_permissions_json),
    projectAccess: parseProjectAccessJson(row.project_access_json),
    kind: parseInvitationKind(row.kind),
    tokenHash: nullableRowString(row.token_hash),
    expiresAtMs: nullableRowNumber(row.expires_at_ms),
    membershipId: nullableRowString(row.membership_id),
    acceptedAtMs: nullableRowNumber(row.accepted_at_ms),
    declinedAtMs: nullableRowNumber(row.declined_at_ms),
    revokedAtMs: nullableRowNumber(row.revoked_at_ms),
    expiredAtMs: nullableRowNumber(row.expired_at_ms),
    createdAtMs: d1Number(row.created_at_ms),
    updatedAtMs: d1Number(row.updated_at_ms),
  };
}

function invitationDomain(record: InvitationRecord): OrganizationInvitation {
  switch (record.kind) {
    case 'pending':
      if (record.expiresAtMs === null) {
        throw new Error(`Pending invitation ${record.id} is missing expires_at_ms`);
      }
      return pendingInvitationDomain(record, toIso(record.expiresAtMs));
    case 'accepted':
      if (!record.membershipId || record.acceptedAtMs === null) {
        throw new Error(`Accepted invitation ${record.id} is missing acceptance state`);
      }
      return acceptedInvitationDomain(record, record.membershipId, toIso(record.acceptedAtMs));
    case 'declined':
      if (record.declinedAtMs === null) {
        throw new Error(`Declined invitation ${record.id} is missing declined_at_ms`);
      }
      return declinedInvitationDomain(record, toIso(record.declinedAtMs));
    case 'revoked':
      if (record.revokedAtMs === null) {
        throw new Error(`Revoked invitation ${record.id} is missing revoked_at_ms`);
      }
      return revokedInvitationDomain(record, toIso(record.revokedAtMs));
    case 'expired':
      if (record.expiredAtMs === null) {
        throw new Error(`Expired invitation ${record.id} is missing expired_at_ms`);
      }
      return expiredInvitationDomain(record, toIso(record.expiredAtMs));
    default:
      return assertNever(record.kind);
  }
}

function pendingInvitationDomain(
  record: InvitationRecord,
  expiresAt: string,
): OrganizationInvitation {
  switch (record.role) {
    case 'OWNER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'OWNER',
        kind: 'pending',
        expiresAt,
      };
    case 'ADMIN':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'ADMIN',
        adminPermissions: record.adminPermissions,
        kind: 'pending',
        expiresAt,
      };
    case 'MEMBER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'MEMBER',
        projectAccess: record.projectAccess,
        kind: 'pending',
        expiresAt,
      };
    default:
      return assertNever(record.role);
  }
}

function acceptedInvitationDomain(
  record: InvitationRecord,
  membershipId: string,
  acceptedAt: string,
): OrganizationInvitation {
  switch (record.role) {
    case 'OWNER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'OWNER',
        kind: 'accepted',
        membershipId,
        acceptedAt,
      };
    case 'ADMIN':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'ADMIN',
        adminPermissions: record.adminPermissions,
        kind: 'accepted',
        membershipId,
        acceptedAt,
      };
    case 'MEMBER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'MEMBER',
        projectAccess: record.projectAccess,
        kind: 'accepted',
        membershipId,
        acceptedAt,
      };
    default:
      return assertNever(record.role);
  }
}

function declinedInvitationDomain(
  record: InvitationRecord,
  declinedAt: string,
): OrganizationInvitation {
  switch (record.role) {
    case 'OWNER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'OWNER',
        kind: 'declined',
        declinedAt,
      };
    case 'ADMIN':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'ADMIN',
        adminPermissions: record.adminPermissions,
        kind: 'declined',
        declinedAt,
      };
    case 'MEMBER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'MEMBER',
        projectAccess: record.projectAccess,
        kind: 'declined',
        declinedAt,
      };
    default:
      return assertNever(record.role);
  }
}

function revokedInvitationDomain(
  record: InvitationRecord,
  revokedAt: string,
): OrganizationInvitation {
  switch (record.role) {
    case 'OWNER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'OWNER',
        kind: 'revoked',
        revokedAt,
      };
    case 'ADMIN':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'ADMIN',
        adminPermissions: record.adminPermissions,
        kind: 'revoked',
        revokedAt,
      };
    case 'MEMBER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'MEMBER',
        projectAccess: record.projectAccess,
        kind: 'revoked',
        revokedAt,
      };
    default:
      return assertNever(record.role);
  }
}

function expiredInvitationDomain(
  record: InvitationRecord,
  expiredAt: string,
): OrganizationInvitation {
  switch (record.role) {
    case 'OWNER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'OWNER',
        kind: 'expired',
        expiredAt,
      };
    case 'ADMIN':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'ADMIN',
        adminPermissions: record.adminPermissions,
        kind: 'expired',
        expiredAt,
      };
    case 'MEMBER':
      return {
        id: record.id,
        orgId: record.orgId,
        email: record.email,
        invitedByUserId: record.invitedByUserId,
        createdAt: toIso(record.createdAtMs),
        updatedAt: toIso(record.updatedAtMs),
        role: 'MEMBER',
        projectAccess: record.projectAccess,
        kind: 'expired',
        expiredAt,
      };
    default:
      return assertNever(record.role);
  }
}

function invitationGrant(request: OrganizationInvitationGrant): OrganizationInvitationGrant {
  switch (request.role) {
    case 'OWNER':
      return { role: 'OWNER' };
    case 'ADMIN':
      return {
        role: 'ADMIN',
        adminPermissions: normalizeAdminPermissions(request.adminPermissions),
      };
    case 'MEMBER':
      return {
        role: 'MEMBER',
        projectAccess: request.projectAccess.map((assignment) => ({
          projectId: assignment.projectId,
          accessLevel: assignment.accessLevel,
        })),
      };
    default:
      return assertNever(request);
  }
}

function grantAdminPermissions(
  grant: OrganizationInvitationGrant,
): readonly OrganizationAdminPermission[] {
  return grant.role === 'ADMIN' ? grant.adminPermissions : [];
}

function grantProjectAccess(
  grant: OrganizationInvitationGrant,
): readonly ProjectAccessAssignment[] {
  return grant.role === 'MEMBER' ? grant.projectAccess : [];
}

function adminPermissionsJson(grant: OrganizationInvitationGrant): string {
  return JSON.stringify(grantAdminPermissions(grant));
}

function projectAccessJson(grant: OrganizationInvitationGrant): string {
  return JSON.stringify(grantProjectAccess(grant));
}

async function loadOrganizationState(
  state: D1OrganizationAccessState,
  orgId: string,
): Promise<OrganizationRowState | null> {
  const row = await queryD1One(
    state.database,
    `SELECT name, owner_anchor_membership_id, owner_set_version, authorization_version
       FROM organizations
      WHERE namespace = ?
        AND id = ?
      LIMIT 1`,
    [state.namespace, orgId],
  );
  if (!row) return null;
  return {
    name: normalizeRowString(row.name),
    ownerAnchorMembershipId: nullableRowString(row.owner_anchor_membership_id),
    ownerSetVersion: d1Number(row.owner_set_version),
    authorizationVersion: d1Number(row.authorization_version),
  };
}

async function requireOrganizationState(
  state: D1OrganizationAccessState,
  orgId: string,
): Promise<OrganizationRowState> {
  const organization = await loadOrganizationState(state, orgId);
  if (!organization) {
    throw accessError('organization_not_found', 404, 'Organization was not found');
  }
  return organization;
}

async function loadMembershipById(
  state: D1OrganizationAccessState,
  orgId: string,
  membershipId: string,
): Promise<OrganizationMembership | null> {
  const row = await queryD1One(
    state.database,
    `SELECT *
       FROM organization_memberships
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [state.namespace, orgId, membershipId],
  );
  return row ? parseMembershipRow(row) : null;
}

async function loadCurrentMembershipByUserId(
  state: D1OrganizationAccessState,
  orgId: string,
  userId: string,
): Promise<OrganizationMembership | null> {
  const row = await queryD1One(
    state.database,
    `SELECT *
       FROM organization_memberships
      WHERE namespace = ?
        AND org_id = ?
        AND user_id = ?
        AND kind <> 'REMOVED'
      LIMIT 1`,
    [state.namespace, orgId, userId],
  );
  return row ? parseMembershipRow(row) : null;
}

async function loadLatestMembershipByUserId(
  state: D1OrganizationAccessState,
  orgId: string,
  userId: string,
): Promise<OrganizationMembership | null> {
  const row = await queryD1One(
    state.database,
    `SELECT *
       FROM organization_memberships
      WHERE namespace = ?
        AND org_id = ?
        AND user_id = ?
      ORDER BY created_at_ms DESC, id DESC
      LIMIT 1`,
    [state.namespace, orgId, userId],
  );
  return row ? parseMembershipRow(row) : null;
}

async function loadAdminPermissions(
  state: D1OrganizationAccessState,
  orgId: string,
  membershipId: string,
): Promise<readonly OrganizationAdminPermission[]> {
  const rows = await queryD1All(
    state.database,
    `SELECT permission
       FROM organization_admin_permissions
      WHERE namespace = ?
        AND org_id = ?
        AND membership_id = ?
      ORDER BY permission ASC`,
    [state.namespace, orgId, membershipId],
  );
  return normalizeAdminPermissions(rows.map((row) => parseAdminPermission(row.permission)));
}

async function loadProjectAccess(
  state: D1OrganizationAccessState,
  orgId: string,
  membershipId: string,
): Promise<readonly ProjectAccessAssignment[]> {
  const rows = await queryD1All(
    state.database,
    `SELECT project_id, access_level
       FROM project_member_access
      WHERE namespace = ?
        AND org_id = ?
        AND membership_id = ?
      ORDER BY project_id ASC`,
    [state.namespace, orgId, membershipId],
  );
  return rows.map((row) => ({
    projectId: normalizeRowString(row.project_id),
    accessLevel: parseProjectAccessLevel(row.access_level),
  }));
}

async function membershipWithAccess(
  state: D1OrganizationAccessState,
  membership: OrganizationMembership,
): Promise<OrganizationMembershipWithAccess> {
  return {
    membership,
    adminPermissions:
      membership.role === 'ADMIN'
        ? await loadAdminPermissions(state, membership.orgId, membership.id)
        : [],
    projectAccess:
      membership.role === 'MEMBER'
        ? await loadProjectAccess(state, membership.orgId, membership.id)
        : [],
  };
}

async function loadActor(
  state: D1OrganizationAccessState,
  ctx: OrganizationAccessContext,
): Promise<OrganizationMembership> {
  const actor = await loadCurrentMembershipByUserId(
    state,
    normalizeRequired(ctx.orgId, 'orgId'),
    normalizeRequired(ctx.actorUserId, 'actorUserId'),
  );
  if (!actor || actor.kind !== 'active') {
    throw accessError('forbidden', 403, 'An active membership is required');
  }
  return actor;
}

async function requireOwner(
  state: D1OrganizationAccessState,
  ctx: OrganizationAccessContext,
): Promise<OrganizationMembership> {
  const actor = await loadActor(state, ctx);
  if (actor.role !== 'OWNER') throw accessError('forbidden', 403, 'Owner access is required');
  return actor;
}

async function actorHasPermission(
  state: D1OrganizationAccessState,
  actor: OrganizationMembership,
  permission: OrganizationAdminPermission,
): Promise<boolean> {
  if (actor.role !== 'ADMIN') return false;
  const permissions = await loadAdminPermissions(state, actor.orgId, actor.id);
  return permissions.includes(permission);
}

async function requireMembershipManager(
  state: D1OrganizationAccessState,
  ctx: OrganizationAccessContext,
): Promise<OrganizationMembership> {
  const actor = await loadActor(state, ctx);
  if (actor.role === 'OWNER') return actor;
  if (await actorHasPermission(state, actor, 'members.manage')) return actor;
  throw accessError('forbidden', 403, 'Membership management access is required');
}

async function requireProjectManager(
  state: D1OrganizationAccessState,
  ctx: OrganizationAccessContext,
): Promise<OrganizationMembership> {
  const actor = await loadActor(state, ctx);
  if (actor.role === 'OWNER') return actor;
  if (await actorHasPermission(state, actor, 'projects.manage')) return actor;
  throw accessError('forbidden', 403, 'Project management access is required');
}

async function requireInvitationAuthority(
  state: D1OrganizationAccessState,
  ctx: OrganizationAccessContext,
  role: 'OWNER' | 'ADMIN' | 'MEMBER',
): Promise<OrganizationMembership> {
  const actor = await loadActor(state, ctx);
  if (actor.role === 'OWNER') return actor;
  if (
    actor.role === 'ADMIN' &&
    role === 'MEMBER' &&
    (await actorHasPermission(state, actor, 'members.manage'))
  ) {
    return actor;
  }
  throw accessError(
    'forbidden',
    403,
    'This membership cannot issue or manage the requested invitation',
  );
}

async function requireLifecycleAuthority(
  state: D1OrganizationAccessState,
  ctx: OrganizationAccessContext,
  target: OrganizationMembership,
): Promise<OrganizationMembership> {
  const actor = await loadActor(state, ctx);
  if (actor.role === 'OWNER') return actor;
  if (
    actor.role === 'ADMIN' &&
    target.role === 'MEMBER' &&
    (await actorHasPermission(state, actor, 'members.manage'))
  ) {
    return actor;
  }
  throw accessError('forbidden', 403, 'This membership cannot change the target membership');
}

async function expireInvitations(
  state: D1OrganizationAccessState,
  orgId: string | null,
): Promise<void> {
  const nowMs = state.now().getTime();
  if (!state.email && orgId) {
    await state.database
      .prepare(
        `UPDATE organization_invitations
            SET kind = 'EXPIRED',
                token_hash = NULL,
                expires_at_ms = NULL,
                expired_at_ms = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND kind = 'PENDING'
            AND expires_at_ms <= ?`,
      )
      .bind(nowMs, nowMs, state.namespace, orgId, nowMs)
      .run();
    return;
  }
  if (!state.email) {
    await state.database
      .prepare(
        `UPDATE organization_invitations
            SET kind = 'EXPIRED',
                token_hash = NULL,
                expires_at_ms = NULL,
                expired_at_ms = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND kind = 'PENDING'
            AND expires_at_ms <= ?`,
      )
      .bind(nowMs, nowMs, state.namespace, nowMs)
      .run();
    return;
  }
  const values: unknown[] = [state.namespace, nowMs];
  const organizationFilter = orgId ? ' AND org_id = ?' : '';
  if (orgId) values.push(orgId);
  const rows = await queryD1All(
    state.database,
    `SELECT org_id, id
       FROM organization_invitations
      WHERE namespace = ?
        AND kind = 'PENDING'
        AND expires_at_ms <= ?${organizationFilter}`,
    values,
  );
  if (rows.length === 0) return;
  const now = new Date(nowMs);
  const statements: D1PreparedStatementLike[] = [];
  for (const row of rows) {
    const expiredOrgId = normalizeRowString(row.org_id);
    const invitationId = normalizeRowString(row.id);
    statements.push(
      state.database
        .prepare(
          `UPDATE organization_invitations
              SET kind = 'EXPIRED',
                  token_hash = NULL,
                  expires_at_ms = NULL,
                  expired_at_ms = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND kind = 'PENDING'
              AND expires_at_ms <= ?`,
        )
        .bind(nowMs, nowMs, state.namespace, expiredOrgId, invitationId, nowMs),
    );
    const cancellation = createInvitationCancellationStatement(state, {
      orgId: expiredOrgId,
      invitationId,
      now,
      guarded: true,
    });
    if (cancellation) statements.push(cancellation);
  }
  await state.database.batch(statements);
}

async function loadInvitationByOrg(
  state: D1OrganizationAccessState,
  orgId: string,
  invitationId: string,
): Promise<InvitationRecord | null> {
  const row = await queryD1One(
    state.database,
    `SELECT *
       FROM organization_invitations
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [state.namespace, orgId, invitationId],
  );
  return row ? parseInvitationRecord(row) : null;
}

async function loadInvitationAcrossOrganizations(
  state: D1OrganizationAccessState,
  invitationId: string,
): Promise<InvitationRecord | null> {
  const row = await queryD1One(
    state.database,
    `SELECT *
       FROM organization_invitations
      WHERE namespace = ?
        AND id = ?
      LIMIT 1`,
    [state.namespace, invitationId],
  );
  return row ? parseInvitationRecord(row) : null;
}

function requirePendingInvitation(record: InvitationRecord): void {
  if (record.kind !== 'pending') {
    throw accessError('invitation_not_pending', 409, `Invitation is already ${record.kind}`);
  }
}

function activeMembership(membership: OrganizationMembership): ActiveOrganizationMembership {
  if (membership.kind !== 'active') {
    throw new Error(`Expected active membership ${membership.id}`);
  }
  return membership;
}

function ownerMembership(membership: OrganizationMembership): ActiveOwnerMembership {
  if (membership.kind !== 'active' || membership.role !== 'OWNER') {
    throw new Error(`Expected owner membership ${membership.id}`);
  }
  return membership;
}

async function validateProjectAssignments(
  state: D1OrganizationAccessState,
  orgId: string,
  assignments: readonly ProjectAccessAssignment[],
): Promise<void> {
  for (const assignment of assignments) {
    const row = await queryD1One(
      state.database,
      `SELECT id
         FROM projects
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?
        LIMIT 1`,
      [state.namespace, orgId, assignment.projectId],
    );
    if (!row) {
      throw accessError('project_not_found', 404, `Project ${assignment.projectId} was not found`);
    }
  }
}

function ownerEventStatement(
  state: D1OrganizationAccessState,
  input: {
    readonly orgId: string;
    readonly membershipId: string;
    readonly ownerUserId: string;
    readonly actorUserId: string;
    readonly kind: 'OWNER_ADDED' | 'OWNER_REMOVED';
    readonly now: Date;
  },
): D1PreparedStatementLike {
  return state.database
    .prepare(
      `INSERT INTO organization_owner_events
        (namespace, org_id, id, membership_id, owner_user_id, actor_user_id, kind, created_at_ms)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?
       WHERE EXISTS (
         SELECT 1
         FROM organization_memberships
         WHERE namespace = ?
           AND org_id = ?
           AND id = ?
       )`,
    )
    .bind(
      state.namespace,
      input.orgId,
      makeId('org_owner_evt', input.now),
      input.membershipId,
      input.ownerUserId,
      input.actorUserId,
      input.kind,
      input.now.getTime(),
      state.namespace,
      input.orgId,
      input.membershipId,
    );
}

function permissionInsertStatements(
  state: D1OrganizationAccessState,
  input: {
    readonly orgId: string;
    readonly membershipId: string;
    readonly permissions: readonly OrganizationAdminPermission[];
    readonly nowMs: number;
  },
): readonly D1PreparedStatementLike[] {
  return input.permissions.map((permission) =>
    state.database
      .prepare(
        `INSERT INTO organization_admin_permissions
          (namespace, org_id, membership_id, permission, created_at_ms, updated_at_ms)
         SELECT ?, ?, ?, ?, ?, ?
         WHERE EXISTS (
           SELECT 1
           FROM organization_memberships
           WHERE namespace = ?
             AND org_id = ?
             AND id = ?
             AND role = 'ADMIN'
             AND kind <> 'REMOVED'
         )
         ON CONFLICT (namespace, org_id, membership_id, permission)
         DO UPDATE SET updated_at_ms = excluded.updated_at_ms`,
      )
      .bind(
        state.namespace,
        input.orgId,
        input.membershipId,
        permission,
        input.nowMs,
        input.nowMs,
        state.namespace,
        input.orgId,
        input.membershipId,
      ),
  );
}

function projectAccessInsertStatements(
  state: D1OrganizationAccessState,
  input: {
    readonly orgId: string;
    readonly membershipId: string;
    readonly assignments: readonly ProjectAccessAssignment[];
    readonly actorUserId: string;
    readonly nowMs: number;
  },
): readonly D1PreparedStatementLike[] {
  return input.assignments.map((assignment) =>
    state.database
      .prepare(
        `INSERT INTO project_member_access
          (namespace, org_id, project_id, membership_id, access_level, granted_by_user_id, created_at_ms, updated_at_ms)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (
           SELECT 1
           FROM organization_memberships
           WHERE namespace = ?
             AND org_id = ?
             AND id = ?
             AND role = 'MEMBER'
             AND kind = 'ACTIVE'
         )
         ON CONFLICT (namespace, org_id, project_id, membership_id)
         DO UPDATE SET
           access_level = excluded.access_level,
           granted_by_user_id = excluded.granted_by_user_id,
           updated_at_ms = excluded.updated_at_ms`,
      )
      .bind(
        state.namespace,
        input.orgId,
        assignment.projectId,
        input.membershipId,
        assignment.accessLevel,
        input.actorUserId,
        input.nowMs,
        input.nowMs,
        state.namespace,
        input.orgId,
        input.membershipId,
      ),
  );
}

class D1ConsoleOrganizationAccessService implements ConsoleOrganizationAccessD1Service {
  readonly [CONSOLE_ORGANIZATION_ACCESS_D1_RUNTIME]: ConsoleOrganizationAccessD1Runtime;

  constructor(private readonly state: D1OrganizationAccessState) {
    this[CONSOLE_ORGANIZATION_ACCESS_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
  }

  async bootstrapInitialOwner(input: BootstrapInitialOwnerInput): Promise<ActiveOwnerMembership> {
    const orgId = normalizeRequired(input.orgId, 'orgId');
    const userId = normalizeRequired(input.userId, 'userId');
    const email = normalizeEmail(input.email);
    const organization = await requireOrganizationState(this.state, orgId);
    const existing = await loadCurrentMembershipByUserId(this.state, orgId, userId);
    if (existing?.kind === 'active' && existing.role === 'OWNER') {
      return ownerMembership(existing);
    }
    if (organization.ownerAnchorMembershipId) {
      throw accessError(
        'owner_already_exists',
        409,
        'The organization already has its initial owner',
      );
    }
    const now = this.state.now();
    const nowMs = now.getTime();
    const membershipId = makeId('org_mbr', now);
    const ownerDisplayName = input.displayName?.trim() || email;
    const ownerEmail = await createOwnerMembershipChangedEmailStatement(this.state, {
      orgId,
      organizationName: organization.name,
      ownerEmail: email,
      ownerDisplayName,
      changedByDisplayName: ownerDisplayName,
      change: 'ADDED',
      now,
    });
    const statements: D1PreparedStatementLike[] = [
      this.state.database
        .prepare(
          `INSERT INTO organization_memberships
            (namespace, org_id, id, user_id, email, email_normalized, display_name, kind, role, suspended_at_ms, removed_at_ms, created_at_ms, updated_at_ms)
           SELECT ?, ?, ?, ?, ?, ?, NULLIF(?, ''), 'ACTIVE', 'OWNER', NULL, NULL, ?, ?
           FROM organizations
           WHERE namespace = ?
             AND id = ?
             AND owner_anchor_membership_id IS NULL`,
        )
        .bind(
          this.state.namespace,
          orgId,
          membershipId,
          userId,
          email,
          email,
          input.displayName?.trim() || '',
          nowMs,
          nowMs,
          this.state.namespace,
          orgId,
        ),
    ];
    if (ownerEmail) statements.push(ownerEmail);
    statements.push(
      ownerEventStatement(this.state, {
        orgId,
        membershipId,
        ownerUserId: userId,
        actorUserId: userId,
        kind: 'OWNER_ADDED',
        now,
      }),
      this.state.database
        .prepare(
          `UPDATE organizations
              SET owner_anchor_membership_id = ?
            WHERE namespace = ?
              AND id = ?
              AND owner_anchor_membership_id IS NULL
              AND EXISTS (
                SELECT 1
                FROM organization_memberships
                WHERE namespace = ?
                  AND org_id = ?
                  AND id = ?
                  AND kind = 'ACTIVE'
                  AND role = 'OWNER'
              )`,
        )
        .bind(membershipId, this.state.namespace, orgId, this.state.namespace, orgId, membershipId),
    );
    await this.state.database.batch(statements);
    const created = await loadMembershipById(this.state, orgId, membershipId);
    if (created) return ownerMembership(created);
    const concurrent = await loadCurrentMembershipByUserId(this.state, orgId, userId);
    if (concurrent?.kind === 'active' && concurrent.role === 'OWNER') {
      return ownerMembership(concurrent);
    }
    throw accessError(
      'owner_already_exists',
      409,
      'The organization already has its initial owner',
    );
  }

  async listMemberships(
    ctx: OrganizationAccessContext,
    request: ListOrganizationMembershipsRequest,
  ): Promise<readonly OrganizationMembershipWithAccess[]> {
    await requireMembershipManager(this.state, ctx);
    const values: unknown[] = [this.state.namespace, ctx.orgId];
    let filter = '';
    if (request.kind !== 'all') {
      filter = ' AND kind = ?';
      values.push(request.kind.toUpperCase());
    }
    const rows = await queryD1All(
      this.state.database,
      `SELECT *
         FROM organization_memberships
        WHERE namespace = ?
          AND org_id = ?${filter}
        ORDER BY
          CASE kind WHEN 'ACTIVE' THEN 0 WHEN 'SUSPENDED' THEN 1 ELSE 2 END,
          email_normalized ASC`,
      values,
    );
    const memberships: OrganizationMembershipWithAccess[] = [];
    for (const row of rows) {
      memberships.push(await membershipWithAccess(this.state, parseMembershipRow(row)));
    }
    return memberships;
  }

  async listInvitations(
    ctx: OrganizationAccessContext,
    request: ListOrganizationInvitationsRequest,
  ): Promise<readonly OrganizationInvitation[]> {
    await requireMembershipManager(this.state, ctx);
    await expireInvitations(this.state, ctx.orgId);
    const values: unknown[] = [this.state.namespace, ctx.orgId];
    let filter = '';
    if (request.kind !== 'all') {
      filter = ' AND kind = ?';
      values.push(request.kind.toUpperCase());
    }
    const rows = await queryD1All(
      this.state.database,
      `SELECT *
         FROM organization_invitations
        WHERE namespace = ?
          AND org_id = ?${filter}
        ORDER BY updated_at_ms DESC, id DESC`,
      values,
    );
    return rows.map((row) => invitationDomain(parseInvitationRecord(row)));
  }

  async invite(
    ctx: OrganizationAccessContext,
    request: InviteOrganizationMemberRequest,
  ): Promise<IssuedOrganizationInvitation> {
    const grant = invitationGrant(request);
    const actor = await requireInvitationAuthority(this.state, ctx, grant.role);
    const email = normalizeEmail(request.email);
    await expireInvitations(this.state, ctx.orgId);
    const duplicate = await queryD1One(
      this.state.database,
      `SELECT 1
       WHERE EXISTS (
         SELECT 1
         FROM organization_memberships
         WHERE namespace = ?
           AND org_id = ?
           AND email_normalized = ?
           AND kind <> 'REMOVED'
       )
       OR EXISTS (
         SELECT 1
         FROM organization_invitations
         WHERE namespace = ?
           AND org_id = ?
           AND email_normalized = ?
           AND kind = 'PENDING'
       )`,
      [this.state.namespace, ctx.orgId, email, this.state.namespace, ctx.orgId, email],
    );
    if (duplicate) {
      throw accessError(
        'invitation_already_exists',
        409,
        'A current membership or pending invitation already uses this email address',
      );
    }
    await validateProjectAssignments(this.state, ctx.orgId, grantProjectAccess(grant));
    const organization = await requireOrganizationState(this.state, ctx.orgId);
    const token = this.state.createToken();
    const tokenHash = await this.state.hashToken(token);
    const now = this.state.now();
    const nowMs = now.getTime();
    const invitationId = makeId('org_inv', now);
    const expiresAtMs = nowMs + this.state.invitationTtlMs;
    const invitationStatement = this.state.database
      .prepare(
        `INSERT INTO organization_invitations
          (namespace, org_id, id, email, email_normalized, invited_by_user_id, role, admin_permissions_json, project_access_json, kind, token_hash, expires_at_ms, membership_id, accepted_at_ms, declined_at_ms, revoked_at_ms, expired_at_ms, created_at_ms, updated_at_ms)
         VALUES
          (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?)`,
      )
      .bind(
        this.state.namespace,
        ctx.orgId,
        invitationId,
        email,
        email,
        actor.userId,
        grant.role,
        adminPermissionsJson(grant),
        projectAccessJson(grant),
        tokenHash,
        expiresAtMs,
        nowMs,
        nowMs,
      );
    const invitationEmail = await createInvitationEmailStatement(this.state, {
      orgId: ctx.orgId,
      organizationName: organization.name,
      invitationId,
      invitationSecret: token,
      recipientEmail: email,
      inviterDisplayName: membershipDisplayName(actor),
      invitedRole: grant.role,
      expiresAt: new Date(expiresAtMs),
      now,
    });
    const statements = [invitationStatement];
    if (invitationEmail) statements.push(invitationEmail);
    await this.state.database.batch(statements);
    const record = await loadInvitationByOrg(this.state, ctx.orgId, invitationId);
    if (!record) throw new Error(`Failed to create invitation ${invitationId}`);
    const invitation = invitationDomain(record);
    if (invitation.kind !== 'pending') {
      throw new Error(`Created invitation ${invitationId} is not pending`);
    }
    return { invitation, token };
  }

  async resendInvitation(
    ctx: OrganizationAccessContext,
    invitationId: string,
  ): Promise<IssuedOrganizationInvitation> {
    await expireInvitations(this.state, ctx.orgId);
    const existing = await this.requireInvitation(ctx.orgId, invitationId);
    const actor = await requireInvitationAuthority(this.state, ctx, existing.role);
    requirePendingInvitation(existing);
    const organization = await requireOrganizationState(this.state, ctx.orgId);
    const token = this.state.createToken();
    const tokenHash = await this.state.hashToken(token);
    const now = this.state.now();
    const nowMs = now.getTime();
    const expiresAtMs = nowMs + this.state.invitationTtlMs;
    const statements: D1PreparedStatementLike[] = [];
    const cancellation = createInvitationCancellationStatement(this.state, {
      orgId: ctx.orgId,
      invitationId,
      now,
      guarded: false,
    });
    if (cancellation) statements.push(cancellation);
    const updateIndex = statements.length;
    statements.push(
      this.state.database
        .prepare(
          `UPDATE organization_invitations
            SET token_hash = ?,
                expires_at_ms = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND kind = 'PENDING'`,
        )
        .bind(tokenHash, expiresAtMs, nowMs, this.state.namespace, ctx.orgId, invitationId),
    );
    const invitationEmail = await createInvitationEmailStatement(this.state, {
      orgId: ctx.orgId,
      organizationName: organization.name,
      invitationId,
      invitationSecret: token,
      recipientEmail: existing.email,
      inviterDisplayName: membershipDisplayName(actor),
      invitedRole: existing.role,
      expiresAt: new Date(expiresAtMs),
      now,
    });
    if (invitationEmail) statements.push(invitationEmail);
    const results = await this.state.database.batch<D1ResultLike>(statements);
    const updateResult = results[updateIndex];
    if (!updateResult || d1ChangedRows(updateResult) !== 1) {
      throw accessError('invitation_not_pending', 409, 'Invitation is no longer pending');
    }
    const refreshed = await this.requireInvitation(ctx.orgId, invitationId);
    const invitation = invitationDomain(refreshed);
    if (invitation.kind !== 'pending') throw new Error(`Invitation ${invitationId} is not pending`);
    return { invitation, token };
  }

  async revokeInvitation(
    ctx: OrganizationAccessContext,
    invitationId: string,
  ): Promise<OrganizationInvitation> {
    await expireInvitations(this.state, ctx.orgId);
    const existing = await this.requireInvitation(ctx.orgId, invitationId);
    await requireInvitationAuthority(this.state, ctx, existing.role);
    requirePendingInvitation(existing);
    const now = this.state.now();
    const nowMs = now.getTime();
    const statements: D1PreparedStatementLike[] = [
      this.state.database
        .prepare(
          `UPDATE organization_invitations
            SET kind = 'REVOKED',
                token_hash = NULL,
                expires_at_ms = NULL,
                revoked_at_ms = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND kind = 'PENDING'`,
        )
        .bind(nowMs, nowMs, this.state.namespace, ctx.orgId, invitationId),
    ];
    const cancellation = createInvitationCancellationStatement(this.state, {
      orgId: ctx.orgId,
      invitationId,
      now,
      guarded: true,
    });
    if (cancellation) statements.push(cancellation);
    const results = await this.state.database.batch<D1ResultLike>(statements);
    const mutationResult = results[0];
    if (!mutationResult || d1ChangedRows(mutationResult) !== 1) {
      throw accessError('invitation_not_pending', 409, 'Invitation is no longer pending');
    }
    return invitationDomain(await this.requireInvitation(ctx.orgId, invitationId));
  }

  async acceptInvitation(
    account: VerifiedInvitationAccount,
    invitationId: string,
    request: RedeemOrganizationInvitationRequest,
  ): Promise<ActiveOrganizationMembership> {
    await expireInvitations(this.state, null);
    const existing = await this.requireGlobalInvitation(invitationId);
    requirePendingInvitation(existing);
    const email = normalizeEmail(account.verifiedEmail);
    if (email !== existing.email) {
      throw accessError(
        'invitation_email_mismatch',
        403,
        'The authenticated verified email does not match the invitation',
      );
    }
    const tokenHash = await this.state.hashToken(normalizeRequired(request.token, 'token'));
    if (!existing.tokenHash || tokenHash !== existing.tokenHash) {
      throw accessError('invalid_invitation_token', 403, 'Invitation token is invalid');
    }
    const userId = normalizeRequired(account.userId, 'userId');
    const now = this.state.now();
    const nowMs = now.getTime();
    const membershipId = makeId('org_mbr', now);
    const grant: OrganizationInvitationGrant =
      existing.role === 'OWNER'
        ? { role: 'OWNER' }
        : existing.role === 'ADMIN'
          ? { role: 'ADMIN', adminPermissions: existing.adminPermissions }
          : { role: 'MEMBER', projectAccess: existing.projectAccess };
    const statements: D1PreparedStatementLike[] = [
      this.state.database
        .prepare(
          `INSERT INTO organization_memberships
            (namespace, org_id, id, user_id, email, email_normalized, display_name, kind, role, suspended_at_ms, removed_at_ms, created_at_ms, updated_at_ms)
           SELECT ?, org_id, ?, ?, email, email_normalized, NULL, 'ACTIVE', role, NULL, NULL, ?, ?
           FROM organization_invitations
           WHERE namespace = ?
             AND id = ?
             AND kind = 'PENDING'
             AND token_hash = ?
             AND email_normalized = ?
             AND expires_at_ms > ?
             AND NOT EXISTS (
               SELECT 1
               FROM organization_memberships
               WHERE namespace = ?
                 AND org_id = organization_invitations.org_id
                 AND kind <> 'REMOVED'
                 AND (user_id = ? OR email_normalized = ?)
             )`,
        )
        .bind(
          this.state.namespace,
          membershipId,
          userId,
          nowMs,
          nowMs,
          this.state.namespace,
          invitationId,
          tokenHash,
          email,
          nowMs,
          this.state.namespace,
          userId,
          email,
        ),
      ...permissionInsertStatements(this.state, {
        orgId: existing.orgId,
        membershipId,
        permissions: grantAdminPermissions(grant),
        nowMs,
      }),
      ...projectAccessInsertStatements(this.state, {
        orgId: existing.orgId,
        membershipId,
        assignments: grantProjectAccess(grant),
        actorUserId: userId,
        nowMs,
      }),
      this.state.database
        .prepare(
          `UPDATE organization_invitations
              SET kind = 'ACCEPTED',
                  token_hash = NULL,
                  expires_at_ms = NULL,
                  membership_id = ?,
                  accepted_at_ms = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND id = ?
              AND kind = 'PENDING'
              AND token_hash = ?
              AND EXISTS (
                SELECT 1
                FROM organization_memberships
                WHERE namespace = ?
                  AND org_id = organization_invitations.org_id
                  AND id = ?
              )`,
        )
        .bind(
          membershipId,
          nowMs,
          nowMs,
          this.state.namespace,
          invitationId,
          tokenHash,
          this.state.namespace,
          membershipId,
        ),
    ];
    const cancellation = createInvitationCancellationStatement(this.state, {
      orgId: existing.orgId,
      invitationId,
      now,
      guarded: true,
    });
    if (cancellation) statements.push(cancellation);
    if (existing.role === 'OWNER') {
      const organization = await requireOrganizationState(this.state, existing.orgId);
      statements.push(
        ownerEventStatement(this.state, {
          orgId: existing.orgId,
          membershipId,
          ownerUserId: userId,
          actorUserId: userId,
          kind: 'OWNER_ADDED',
          now,
        }),
      );
      const ownerEmail = await createOwnerMembershipChangedEmailStatement(this.state, {
        orgId: existing.orgId,
        organizationName: organization.name,
        ownerEmail: email,
        ownerDisplayName: email,
        changedByDisplayName: email,
        change: 'ADDED',
        now,
      });
      if (ownerEmail) statements.push(ownerEmail);
    }
    try {
      await this.state.database.batch(statements);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('UNIQUE constraint failed')) {
        throw accessError(
          'membership_already_exists',
          409,
          'This account or email already has a current membership',
        );
      }
      throw error;
    }
    const membership = await loadMembershipById(this.state, existing.orgId, membershipId);
    if (membership) return activeMembership(membership);
    const refreshed = await this.requireGlobalInvitation(invitationId);
    if (refreshed.kind !== 'pending') {
      throw accessError('invitation_not_pending', 409, `Invitation is already ${refreshed.kind}`);
    }
    throw accessError(
      'membership_already_exists',
      409,
      'This account or email already has a current membership',
    );
  }

  async declineInvitation(
    account: VerifiedInvitationAccount,
    invitationId: string,
    request: RedeemOrganizationInvitationRequest,
  ): Promise<OrganizationInvitation> {
    normalizeRequired(account.userId, 'userId');
    await expireInvitations(this.state, null);
    const existing = await this.requireGlobalInvitation(invitationId);
    requirePendingInvitation(existing);
    const email = normalizeEmail(account.verifiedEmail);
    if (email !== existing.email) {
      throw accessError(
        'invitation_email_mismatch',
        403,
        'The authenticated verified email does not match the invitation',
      );
    }
    const tokenHash = await this.state.hashToken(normalizeRequired(request.token, 'token'));
    if (!existing.tokenHash || tokenHash !== existing.tokenHash) {
      throw accessError('invalid_invitation_token', 403, 'Invitation token is invalid');
    }
    const now = this.state.now();
    const nowMs = now.getTime();
    const statements: D1PreparedStatementLike[] = [
      this.state.database
        .prepare(
          `UPDATE organization_invitations
            SET kind = 'DECLINED',
                token_hash = NULL,
                expires_at_ms = NULL,
                declined_at_ms = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND id = ?
            AND kind = 'PENDING'
            AND token_hash = ?
            AND email_normalized = ?
            AND expires_at_ms > ?`,
        )
        .bind(nowMs, nowMs, this.state.namespace, invitationId, tokenHash, email, nowMs),
    ];
    const cancellation = createInvitationCancellationStatement(this.state, {
      orgId: existing.orgId,
      invitationId,
      now,
      guarded: true,
    });
    if (cancellation) statements.push(cancellation);
    const results = await this.state.database.batch<D1ResultLike>(statements);
    const mutationResult = results[0];
    if (!mutationResult || d1ChangedRows(mutationResult) !== 1) {
      throw accessError('invitation_not_pending', 409, 'Invitation is no longer pending');
    }
    return invitationDomain(await this.requireGlobalInvitation(invitationId));
  }

  async changeRole(
    ctx: OrganizationAccessContext,
    membershipId: string,
    request: ChangeOrganizationMembershipRoleRequest,
  ): Promise<OrganizationMembershipWithAccess> {
    const actor = await requireOwner(this.state, ctx);
    const target = await this.requireMembership(ctx.orgId, membershipId);
    if (target.userId === ctx.actorUserId) {
      throw accessError('self_role_change_forbidden', 409, 'Owners cannot change their own role');
    }
    if (target.kind !== 'active') {
      throw accessError('membership_not_active', 409, 'Only an active membership can change role');
    }
    const grant = invitationGrant(request);
    await validateProjectAssignments(this.state, ctx.orgId, grantProjectAccess(grant));
    const organization = await requireOrganizationState(this.state, ctx.orgId);
    const now = this.state.now();
    const nowMs = now.getTime();
    const ownerChange =
      target.role === 'OWNER' && grant.role !== 'OWNER'
        ? 'REMOVED'
        : target.role !== 'OWNER' && grant.role === 'OWNER'
          ? 'ADDED'
          : null;
    const ownerEmail = ownerChange
      ? await createOwnerMembershipChangedEmailStatement(this.state, {
          orgId: ctx.orgId,
          organizationName: organization.name,
          ownerEmail: target.email,
          ownerDisplayName: membershipDisplayName(target),
          changedByDisplayName: membershipDisplayName(actor),
          change: ownerChange,
          now,
        })
      : null;
    const statements: D1PreparedStatementLike[] = [];
    if (target.role === 'OWNER' && grant.role !== 'OWNER') {
      const nextOwner = await queryD1One(
        this.state.database,
        `SELECT id
           FROM organization_memberships
          WHERE namespace = ?
            AND org_id = ?
            AND kind = 'ACTIVE'
            AND role = 'OWNER'
            AND id <> ?
          ORDER BY created_at_ms ASC, id ASC
          LIMIT 1`,
        [this.state.namespace, ctx.orgId, target.id],
      );
      if (!nextOwner) {
        throw accessError('last_owner_required', 409, 'The final owner cannot change role');
      }
      if (organization.ownerAnchorMembershipId === target.id) {
        statements.push(
          this.state.database
            .prepare(
              `UPDATE organizations
                  SET owner_anchor_membership_id = ?
                WHERE namespace = ?
                  AND id = ?
                  AND owner_anchor_membership_id = ?`,
            )
            .bind(normalizeRowString(nextOwner.id), this.state.namespace, ctx.orgId, target.id),
        );
      }
    }
    statements.push(
      this.state.database
        .prepare(
          `UPDATE organization_memberships
              SET role = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND kind = 'ACTIVE'
              AND role = ?`,
        )
        .bind(grant.role, nowMs, this.state.namespace, ctx.orgId, target.id, target.role),
    );
    if (ownerEmail) statements.push(ownerEmail);
    statements.push(
      this.state.database
        .prepare(
          `DELETE FROM organization_admin_permissions
            WHERE namespace = ?
              AND org_id = ?
              AND membership_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, target.id),
      this.state.database
        .prepare(
          `DELETE FROM project_member_access
            WHERE namespace = ?
              AND org_id = ?
              AND membership_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, target.id),
      ...permissionInsertStatements(this.state, {
        orgId: ctx.orgId,
        membershipId: target.id,
        permissions: grantAdminPermissions(grant),
        nowMs,
      }),
      ...projectAccessInsertStatements(this.state, {
        orgId: ctx.orgId,
        membershipId: target.id,
        assignments: grantProjectAccess(grant),
        actorUserId: ctx.actorUserId,
        nowMs,
      }),
    );
    if (target.role === 'OWNER' && grant.role !== 'OWNER') {
      statements.push(
        ownerEventStatement(this.state, {
          orgId: ctx.orgId,
          membershipId: target.id,
          ownerUserId: target.userId,
          actorUserId: ctx.actorUserId,
          kind: 'OWNER_REMOVED',
          now,
        }),
      );
    } else if (target.role !== 'OWNER' && grant.role === 'OWNER') {
      statements.push(
        ownerEventStatement(this.state, {
          orgId: ctx.orgId,
          membershipId: target.id,
          ownerUserId: target.userId,
          actorUserId: ctx.actorUserId,
          kind: 'OWNER_ADDED',
          now,
        }),
      );
    }
    try {
      await this.state.database.batch(statements);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('last_owner_required') || message.includes('owner_anchor_required')) {
        throw accessError('last_owner_required', 409, 'The final owner cannot change role');
      }
      throw error;
    }
    return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, target.id));
  }

  async setAdminPermissions(
    ctx: OrganizationAccessContext,
    membershipId: string,
    request: SetOrganizationAdminPermissionsRequest,
  ): Promise<OrganizationMembershipWithAccess> {
    await requireOwner(this.state, ctx);
    const target = await this.requireMembership(ctx.orgId, membershipId);
    if (target.role !== 'ADMIN' || target.kind === 'removed') {
      throw accessError(
        'membership_not_administrator',
        409,
        'Administrator permissions require a current administrator membership',
      );
    }
    const nowMs = this.state.now().getTime();
    await this.state.database.batch([
      this.state.database
        .prepare(
          `DELETE FROM organization_admin_permissions
            WHERE namespace = ?
              AND org_id = ?
              AND membership_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, target.id),
      ...permissionInsertStatements(this.state, {
        orgId: ctx.orgId,
        membershipId: target.id,
        permissions: normalizeAdminPermissions(request.permissions),
        nowMs,
      }),
      this.state.database
        .prepare(
          `UPDATE organization_memberships
              SET updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(nowMs, this.state.namespace, ctx.orgId, target.id),
    ]);
    return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, target.id));
  }

  async suspendMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess> {
    const target = await this.requireMembership(ctx.orgId, membershipId);
    const actor = await requireLifecycleAuthority(this.state, ctx, target);
    this.rejectSelfLifecycle(ctx, target);
    if (target.kind !== 'active') {
      throw accessError('membership_not_active', 409, 'Only an active membership can be suspended');
    }
    if (target.role === 'OWNER') {
      throw accessError(
        'owner_must_be_demoted',
        409,
        'An owner must become an administrator before suspension',
      );
    }
    const organization = await requireOrganizationState(this.state, ctx.orgId);
    const now = this.state.now();
    const nowMs = now.getTime();
    const membershipEmail = await createMembershipAccessChangedEmailStatement(this.state, {
      orgId: ctx.orgId,
      organizationName: organization.name,
      memberEmail: target.email,
      memberDisplayName: membershipDisplayName(target),
      changedByDisplayName: membershipDisplayName(actor),
      change: 'SUSPENDED',
      now,
    });
    const statements: D1PreparedStatementLike[] = [
      this.state.database
        .prepare(
          `UPDATE organization_memberships
            SET kind = 'SUSPENDED',
                suspended_at_ms = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND kind = 'ACTIVE'
            AND role <> 'OWNER'`,
        )
        .bind(nowMs, nowMs, this.state.namespace, ctx.orgId, target.id),
    ];
    if (membershipEmail) statements.push(membershipEmail);
    const results = await this.state.database.batch<D1ResultLike>(statements);
    const mutationResult = results[0];
    if (!mutationResult || d1ChangedRows(mutationResult) !== 1) {
      throw accessError('membership_not_active', 409, 'Membership is no longer active');
    }
    return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, target.id));
  }

  async reactivateMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess> {
    const target = await this.requireMembership(ctx.orgId, membershipId);
    await requireLifecycleAuthority(this.state, ctx, target);
    this.rejectSelfLifecycle(ctx, target);
    if (target.kind !== 'suspended') {
      throw accessError(
        'membership_not_suspended',
        409,
        'Only a suspended membership can be reactivated',
      );
    }
    const nowMs = this.state.now().getTime();
    const result = await this.state.database
      .prepare(
        `UPDATE organization_memberships
            SET kind = 'ACTIVE',
                suspended_at_ms = NULL,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND kind = 'SUSPENDED'`,
      )
      .bind(nowMs, this.state.namespace, ctx.orgId, target.id)
      .run();
    if (d1ChangedRows(result) !== 1) {
      throw accessError('membership_not_suspended', 409, 'Membership is no longer suspended');
    }
    return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, target.id));
  }

  async removeMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess> {
    const target = await this.requireMembership(ctx.orgId, membershipId);
    const actor = await requireLifecycleAuthority(this.state, ctx, target);
    this.rejectSelfLifecycle(ctx, target);
    if (target.kind === 'removed') return membershipWithAccess(this.state, target);
    if (target.role === 'OWNER') {
      throw accessError(
        'owner_must_be_demoted',
        409,
        'An owner must become an administrator before removal',
      );
    }
    await this.removeNonOwner(target, actor);
    return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, target.id));
  }

  async leaveOrganization(
    ctx: OrganizationAccessContext,
  ): Promise<OrganizationMembershipWithAccess> {
    const actor = await loadActor(this.state, ctx);
    if (actor.role !== 'OWNER') {
      await this.removeNonOwner(actor, actor);
      return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, actor.id));
    }
    const organization = await requireOrganizationState(this.state, ctx.orgId);
    const nextOwner = await queryD1One(
      this.state.database,
      `SELECT id
         FROM organization_memberships
        WHERE namespace = ?
          AND org_id = ?
          AND kind = 'ACTIVE'
          AND role = 'OWNER'
          AND id <> ?
        ORDER BY created_at_ms ASC, id ASC
        LIMIT 1`,
      [this.state.namespace, ctx.orgId, actor.id],
    );
    if (!nextOwner) {
      throw accessError('last_owner_required', 409, 'The final owner cannot leave');
    }
    const now = this.state.now();
    const nowMs = now.getTime();
    const ownerEmail = await createOwnerMembershipChangedEmailStatement(this.state, {
      orgId: ctx.orgId,
      organizationName: organization.name,
      ownerEmail: actor.email,
      ownerDisplayName: membershipDisplayName(actor),
      changedByDisplayName: membershipDisplayName(actor),
      change: 'REMOVED',
      now,
    });
    const statements: D1PreparedStatementLike[] = [];
    if (organization.ownerAnchorMembershipId === actor.id) {
      statements.push(
        this.state.database
          .prepare(
            `UPDATE organizations
                SET owner_anchor_membership_id = ?
              WHERE namespace = ?
                AND id = ?
                AND owner_anchor_membership_id = ?`,
          )
          .bind(normalizeRowString(nextOwner.id), this.state.namespace, ctx.orgId, actor.id),
      );
    }
    statements.push(
      this.state.database
        .prepare(
          `UPDATE organization_memberships
              SET kind = 'REMOVED',
                  role = 'ADMIN',
                  suspended_at_ms = NULL,
                  removed_at_ms = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND kind = 'ACTIVE'
              AND role = 'OWNER'`,
        )
        .bind(nowMs, nowMs, this.state.namespace, ctx.orgId, actor.id),
    );
    if (ownerEmail) statements.push(ownerEmail);
    statements.push(
      this.state.database
        .prepare(
          `DELETE FROM organization_admin_permissions
            WHERE namespace = ?
              AND org_id = ?
              AND membership_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, actor.id),
      this.state.database
        .prepare(
          `DELETE FROM project_member_access
            WHERE namespace = ?
              AND org_id = ?
              AND membership_id = ?`,
        )
        .bind(this.state.namespace, ctx.orgId, actor.id),
      ownerEventStatement(this.state, {
        orgId: ctx.orgId,
        membershipId: actor.id,
        ownerUserId: actor.userId,
        actorUserId: actor.userId,
        kind: 'OWNER_REMOVED',
        now,
      }),
    );
    try {
      await this.state.database.batch(statements);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('last_owner_required') || message.includes('owner_anchor_required')) {
        throw accessError('last_owner_required', 409, 'The final owner cannot leave');
      }
      throw error;
    }
    return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, actor.id));
  }

  async setProjectAccess(
    ctx: OrganizationAccessContext,
    projectId: string,
    membershipId: string,
    request: SetProjectMemberAccessRequest,
  ): Promise<OrganizationMembershipWithAccess> {
    await requireProjectManager(this.state, ctx);
    const target = await this.requireActiveMember(ctx.orgId, membershipId);
    const assignment = {
      projectId: normalizeRequired(projectId, 'projectId'),
      accessLevel: request.accessLevel,
    } satisfies ProjectAccessAssignment;
    await validateProjectAssignments(this.state, ctx.orgId, [assignment]);
    const nowMs = this.state.now().getTime();
    await this.state.database.batch(
      projectAccessInsertStatements(this.state, {
        orgId: ctx.orgId,
        membershipId: target.id,
        assignments: [assignment],
        actorUserId: ctx.actorUserId,
        nowMs,
      }),
    );
    return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, target.id));
  }

  async removeProjectAccess(
    ctx: OrganizationAccessContext,
    projectId: string,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess> {
    await requireProjectManager(this.state, ctx);
    const target = await this.requireActiveMember(ctx.orgId, membershipId);
    await this.state.database
      .prepare(
        `DELETE FROM project_member_access
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND membership_id = ?`,
      )
      .bind(this.state.namespace, ctx.orgId, normalizeRequired(projectId, 'projectId'), target.id)
      .run();
    return membershipWithAccess(this.state, await this.requireMembership(ctx.orgId, target.id));
  }

  async lookupAuthorization(
    lookup: OrganizationAuthorizationLookup,
  ): Promise<OrganizationAuthorization | null> {
    const orgId = normalizeRequired(lookup.orgId, 'orgId');
    const userId = normalizeRequired(lookup.userId, 'userId');
    const organization = await loadOrganizationState(this.state, orgId);
    if (!organization) return null;
    const membership = await loadLatestMembershipByUserId(this.state, orgId, userId);
    if (!membership) {
      return {
        kind: 'denied',
        orgId,
        userId,
        authorizationVersion: organization.authorizationVersion,
        membershipId: null,
        reason: 'membership_not_found',
      };
    }
    if (membership.kind === 'suspended') {
      return {
        kind: 'denied',
        orgId,
        userId,
        authorizationVersion: organization.authorizationVersion,
        membershipId: membership.id,
        reason: 'membership_suspended',
      };
    }
    if (membership.kind === 'removed') {
      return {
        kind: 'denied',
        orgId,
        userId,
        authorizationVersion: organization.authorizationVersion,
        membershipId: membership.id,
        reason: 'membership_removed',
      };
    }
    const role = membership.role;
    switch (role) {
      case 'OWNER':
        return {
          kind: 'authorized',
          orgId,
          userId,
          membershipId: membership.id,
          role: 'OWNER',
          authorizationVersion: organization.authorizationVersion,
          adminPermissions: ORGANIZATION_ADMIN_PERMISSIONS,
          projectAccess: { kind: 'all' },
        };
      case 'ADMIN':
        return {
          kind: 'authorized',
          orgId,
          userId,
          membershipId: membership.id,
          role: 'ADMIN',
          authorizationVersion: organization.authorizationVersion,
          adminPermissions: await loadAdminPermissions(this.state, orgId, membership.id),
          projectAccess: { kind: 'all' },
        };
      case 'MEMBER':
        return {
          kind: 'authorized',
          orgId,
          userId,
          membershipId: membership.id,
          role: 'MEMBER',
          authorizationVersion: organization.authorizationVersion,
          adminPermissions: [],
          projectAccess: {
            kind: 'assigned',
            assignments: await loadProjectAccess(this.state, orgId, membership.id),
          },
        };
      default:
        return assertNever(role);
    }
  }

  async getAuthorizationVersion(orgId: string): Promise<number | null> {
    const organization = await loadOrganizationState(this.state, normalizeRequired(orgId, 'orgId'));
    return organization?.authorizationVersion ?? null;
  }

  async listOwnerEvents(
    ctx: OrganizationAccessContext,
  ): Promise<readonly OrganizationOwnerEvent[]> {
    await requireOwner(this.state, ctx);
    const rows = await queryD1All(
      this.state.database,
      `SELECT *
         FROM organization_owner_events
        WHERE namespace = ?
          AND org_id = ?
        ORDER BY created_at_ms DESC, id DESC`,
      [this.state.namespace, ctx.orgId],
    );
    return rows.map((row) => {
      const kind = normalizeRowString(row.kind);
      if (kind !== 'OWNER_ADDED' && kind !== 'OWNER_REMOVED') {
        throw new Error(`Invalid owner event kind row: ${kind}`);
      }
      return {
        id: normalizeRowString(row.id),
        orgId: normalizeRowString(row.org_id),
        membershipId: normalizeRowString(row.membership_id),
        ownerUserId: normalizeRowString(row.owner_user_id),
        actorUserId: normalizeRowString(row.actor_user_id),
        kind,
        createdAt: toIso(d1Number(row.created_at_ms)),
      };
    });
  }

  async purgeOrganization(orgId: string): Promise<void> {
    await this.state.database
      .prepare(
        `DELETE FROM organizations
          WHERE namespace = ?
            AND id = ?`,
      )
      .bind(this.state.namespace, normalizeRequired(orgId, 'orgId'))
      .run();
  }

  private async requireMembership(
    orgId: string,
    membershipId: string,
  ): Promise<OrganizationMembership> {
    const membership = await loadMembershipById(
      this.state,
      normalizeRequired(orgId, 'orgId'),
      normalizeRequired(membershipId, 'membershipId'),
    );
    if (!membership) throw accessError('membership_not_found', 404, 'Membership was not found');
    return membership;
  }

  private async requireActiveMember(
    orgId: string,
    membershipId: string,
  ): Promise<OrganizationMembership> {
    const membership = await this.requireMembership(orgId, membershipId);
    if (membership.kind !== 'active' || membership.role !== 'MEMBER') {
      throw accessError(
        'membership_not_member',
        409,
        'Project access requires an active member membership',
      );
    }
    return membership;
  }

  private async requireInvitation(orgId: string, invitationId: string): Promise<InvitationRecord> {
    const invitation = await loadInvitationByOrg(
      this.state,
      normalizeRequired(orgId, 'orgId'),
      normalizeRequired(invitationId, 'invitationId'),
    );
    if (!invitation) throw accessError('invitation_not_found', 404, 'Invitation was not found');
    return invitation;
  }

  private async requireGlobalInvitation(invitationId: string): Promise<InvitationRecord> {
    const invitation = await loadInvitationAcrossOrganizations(
      this.state,
      normalizeRequired(invitationId, 'invitationId'),
    );
    if (!invitation) throw accessError('invitation_not_found', 404, 'Invitation was not found');
    return invitation;
  }

  private rejectSelfLifecycle(
    ctx: OrganizationAccessContext,
    target: OrganizationMembership,
  ): void {
    if (target.userId === ctx.actorUserId) {
      throw accessError(
        'self_membership_change_forbidden',
        409,
        'Use the organization leave operation for your own membership',
      );
    }
  }

  private async removeNonOwner(
    target: OrganizationMembership,
    changedBy: OrganizationMembership,
  ): Promise<void> {
    const organization = await requireOrganizationState(this.state, target.orgId);
    const now = this.state.now();
    const nowMs = now.getTime();
    const membershipEmail = await createMembershipAccessChangedEmailStatement(this.state, {
      orgId: target.orgId,
      organizationName: organization.name,
      memberEmail: target.email,
      memberDisplayName: membershipDisplayName(target),
      changedByDisplayName: membershipDisplayName(changedBy),
      change: 'REMOVED',
      now,
    });
    const statements: D1PreparedStatementLike[] = [
      this.state.database
        .prepare(
          `UPDATE organization_memberships
              SET kind = 'REMOVED',
                  suspended_at_ms = NULL,
                  removed_at_ms = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND kind <> 'REMOVED'
              AND role <> 'OWNER'`,
        )
        .bind(nowMs, nowMs, this.state.namespace, target.orgId, target.id),
    ];
    if (membershipEmail) statements.push(membershipEmail);
    statements.push(
      this.state.database
        .prepare(
          `DELETE FROM organization_admin_permissions
            WHERE namespace = ?
              AND org_id = ?
              AND membership_id = ?`,
        )
        .bind(this.state.namespace, target.orgId, target.id),
      this.state.database
        .prepare(
          `DELETE FROM project_member_access
            WHERE namespace = ?
              AND org_id = ?
              AND membership_id = ?`,
        )
        .bind(this.state.namespace, target.orgId, target.id),
    );
    await this.state.database.batch(statements);
  }
}

export async function ensureConsoleOrganizationAccessD1Schema(
  options: D1ConsoleOrganizationAccessSchemaOptions,
): Promise<void> {
  const rows = await queryD1All(
    options.database,
    `SELECT name
       FROM sqlite_master
      WHERE type = 'table'`,
    [],
  );
  const tables = new Set(rows.map((row) => normalizeRowString(row.name)));
  const missing = REQUIRED_ORGANIZATION_ACCESS_TABLES.filter((table) => !tables.has(table));
  if (missing.length > 0) {
    throw new Error(
      `Console organization access migration 0020 is required; missing tables: ${missing.join(', ')}`,
    );
  }
  const organizationColumns = await queryD1All(
    options.database,
    'PRAGMA table_info(organizations)',
    [],
  );
  const columns = new Set(organizationColumns.map((row) => normalizeRowString(row.name)));
  for (const required of [
    'owner_anchor_membership_id',
    'owner_set_version',
    'authorization_version',
  ]) {
    if (!columns.has(required)) {
      throw new Error(
        `Console organization access migration 0020 is required; missing organizations.${required}`,
      );
    }
  }
}

export function getConsoleOrganizationAccessD1Runtime(
  service: ConsoleOrganizationAccessService | null | undefined,
): ConsoleOrganizationAccessD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleOrganizationAccessD1Service>)[
      CONSOLE_ORGANIZATION_ACCESS_D1_RUNTIME
    ] ?? null
  );
}

export async function createD1ConsoleOrganizationAccessService(
  options: D1ConsoleOrganizationAccessServiceOptions,
): Promise<ConsoleOrganizationAccessService> {
  if (options.ensureSchema) {
    await ensureConsoleOrganizationAccessD1Schema({ database: options.database });
  }
  const invitationTtlMs = options.invitationTtlMs ?? DEFAULT_INVITATION_TTL_MS;
  if (!Number.isSafeInteger(invitationTtlMs) || invitationTtlMs <= 0) {
    throw new Error('invitationTtlMs must be a positive integer');
  }
  return new D1ConsoleOrganizationAccessService({
    database: options.database,
    namespace: normalizeNamespace(options.namespace),
    now: options.now ?? defaultNow,
    invitationTtlMs,
    createToken: options.createInvitationToken ?? createOrganizationInvitationToken,
    hashToken: options.hashInvitationToken ?? hashOrganizationInvitationToken,
    email: normalizeOrganizationEmailOptions(options.email),
  });
}
