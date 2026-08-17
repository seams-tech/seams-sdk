import { secureRandomBase36 } from '../boundary';
import { ConsoleOrganizationAccessError } from './errors';
import { createOrganizationInvitationToken, hashOrganizationInvitationToken } from './secret';
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
  type OrganizationMembershipRole,
  type OrganizationMembershipWithAccess,
  type OrganizationOwnerEvent,
  type ProjectAccessAssignment,
  type RedeemOrganizationInvitationRequest,
  type SetOrganizationAdminPermissionsRequest,
  type SetProjectMemberAccessRequest,
} from './types';

const DEFAULT_INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1_000;

export interface OrganizationAccessContext {
  readonly orgId: string;
  readonly actorUserId: string;
}

export interface BootstrapInitialOwnerInput {
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly displayName: string | null;
}

export interface VerifiedInvitationAccount {
  readonly userId: string;
  readonly verifiedEmail: string;
}

export interface OrganizationAuthorizationLookup {
  readonly orgId: string;
  readonly userId: string;
}

export interface ConsoleOrganizationAccessService {
  bootstrapInitialOwner(input: BootstrapInitialOwnerInput): Promise<ActiveOwnerMembership>;
  listMemberships(
    ctx: OrganizationAccessContext,
    request: ListOrganizationMembershipsRequest,
  ): Promise<readonly OrganizationMembershipWithAccess[]>;
  listInvitations(
    ctx: OrganizationAccessContext,
    request: ListOrganizationInvitationsRequest,
  ): Promise<readonly OrganizationInvitation[]>;
  invite(
    ctx: OrganizationAccessContext,
    request: InviteOrganizationMemberRequest,
  ): Promise<IssuedOrganizationInvitation>;
  resendInvitation(
    ctx: OrganizationAccessContext,
    invitationId: string,
  ): Promise<IssuedOrganizationInvitation>;
  revokeInvitation(
    ctx: OrganizationAccessContext,
    invitationId: string,
  ): Promise<OrganizationInvitation>;
  acceptInvitation(
    account: VerifiedInvitationAccount,
    invitationId: string,
    request: RedeemOrganizationInvitationRequest,
  ): Promise<ActiveOrganizationMembership>;
  declineInvitation(
    account: VerifiedInvitationAccount,
    invitationId: string,
    request: RedeemOrganizationInvitationRequest,
  ): Promise<OrganizationInvitation>;
  changeRole(
    ctx: OrganizationAccessContext,
    membershipId: string,
    request: ChangeOrganizationMembershipRoleRequest,
  ): Promise<OrganizationMembershipWithAccess>;
  setAdminPermissions(
    ctx: OrganizationAccessContext,
    membershipId: string,
    request: SetOrganizationAdminPermissionsRequest,
  ): Promise<OrganizationMembershipWithAccess>;
  suspendMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess>;
  reactivateMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess>;
  removeMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess>;
  leaveOrganization(ctx: OrganizationAccessContext): Promise<OrganizationMembershipWithAccess>;
  setProjectAccess(
    ctx: OrganizationAccessContext,
    projectId: string,
    membershipId: string,
    request: SetProjectMemberAccessRequest,
  ): Promise<OrganizationMembershipWithAccess>;
  removeProjectAccess(
    ctx: OrganizationAccessContext,
    projectId: string,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess>;
  lookupAuthorization(
    lookup: OrganizationAuthorizationLookup,
  ): Promise<OrganizationAuthorization | null>;
  getAuthorizationVersion(orgId: string): Promise<number | null>;
  listOwnerEvents(ctx: OrganizationAccessContext): Promise<readonly OrganizationOwnerEvent[]>;
  purgeOrganization(orgId: string): Promise<void>;
}

export interface InMemoryConsoleOrganizationAccessServiceOptions {
  readonly now?: () => Date;
  readonly invitationTtlMs?: number;
  readonly createInvitationToken?: () => string;
  readonly hashInvitationToken?: (token: string) => Promise<string>;
}

interface StoredMembership {
  readonly id: string;
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly displayName: string | null;
  kind: 'active' | 'suspended' | 'removed';
  role: OrganizationMembershipRole;
  suspendedAt: string | null;
  removedAt: string | null;
  readonly createdAt: string;
  updatedAt: string;
}

interface StoredInvitation {
  readonly id: string;
  readonly orgId: string;
  readonly email: string;
  readonly invitedByUserId: string;
  readonly role: OrganizationMembershipRole;
  adminPermissions: readonly OrganizationAdminPermission[];
  projectAccess: readonly ProjectAccessAssignment[];
  kind: 'pending' | 'accepted' | 'declined' | 'revoked' | 'expired';
  tokenHash: string | null;
  expiresAt: string | null;
  membershipId: string | null;
  acceptedAt: string | null;
  declinedAt: string | null;
  revokedAt: string | null;
  expiredAt: string | null;
  readonly createdAt: string;
  updatedAt: string;
}

interface OrganizationAccessStore {
  readonly orgId: string;
  readonly memberships: Map<string, StoredMembership>;
  readonly invitations: Map<string, StoredInvitation>;
  readonly adminPermissions: Map<string, readonly OrganizationAdminPermission[]>;
  readonly projectAccess: Map<string, Map<string, ProjectAccessAssignment>>;
  readonly ownerEvents: OrganizationOwnerEvent[];
  ownerAnchorMembershipId: string;
  ownerSetVersion: number;
  authorizationVersion: number;
}

function organizationAccessError(
  code: string,
  status: number,
  message: string,
): ConsoleOrganizationAccessError {
  return new ConsoleOrganizationAccessError(code, status, message);
}

function assertNever(value: never): never {
  throw new Error(`Unhandled organization access branch: ${JSON.stringify(value)}`);
}

function normalizeRequiredString(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw organizationAccessError('invalid_body', 400, `${field} is required`);
  }
  return normalized;
}

function normalizeEmail(value: string): string {
  const normalized = normalizeRequiredString(value, 'email').toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(normalized)) {
    throw organizationAccessError('invalid_body', 400, 'email must be a valid email address');
  }
  return normalized;
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(
    10,
    'organization access IDs',
  )}`;
}

function cloneProjectAccess(
  assignments: readonly ProjectAccessAssignment[],
): readonly ProjectAccessAssignment[] {
  return assignments
    .map((assignment) => ({
      projectId: assignment.projectId,
      accessLevel: assignment.accessLevel,
    }))
    .sort((left, right) => left.projectId.localeCompare(right.projectId));
}

function normalizeAdminPermissions(
  permissions: readonly OrganizationAdminPermission[],
): readonly OrganizationAdminPermission[] {
  const set = new Set<OrganizationAdminPermission>(permissions);
  if (set.has('billing.manage')) set.add('billing.view');
  return ORGANIZATION_ADMIN_PERMISSIONS.filter((permission) => set.has(permission));
}

function membershipFromStored(stored: StoredMembership): OrganizationMembership {
  switch (stored.kind) {
    case 'active':
      switch (stored.role) {
        case 'OWNER':
          return {
            id: stored.id,
            orgId: stored.orgId,
            userId: stored.userId,
            email: stored.email,
            displayName: stored.displayName,
            createdAt: stored.createdAt,
            updatedAt: stored.updatedAt,
            kind: 'active',
            role: 'OWNER',
          };
        case 'ADMIN':
          return {
            id: stored.id,
            orgId: stored.orgId,
            userId: stored.userId,
            email: stored.email,
            displayName: stored.displayName,
            createdAt: stored.createdAt,
            updatedAt: stored.updatedAt,
            kind: 'active',
            role: 'ADMIN',
          };
        case 'MEMBER':
          return {
            id: stored.id,
            orgId: stored.orgId,
            userId: stored.userId,
            email: stored.email,
            displayName: stored.displayName,
            createdAt: stored.createdAt,
            updatedAt: stored.updatedAt,
            kind: 'active',
            role: 'MEMBER',
          };
        default:
          return assertNever(stored.role);
      }
    case 'suspended':
      if (!stored.suspendedAt) {
        throw new Error(`Suspended membership ${stored.id} is missing suspendedAt`);
      }
      switch (stored.role) {
        case 'ADMIN':
          return {
            id: stored.id,
            orgId: stored.orgId,
            userId: stored.userId,
            email: stored.email,
            displayName: stored.displayName,
            createdAt: stored.createdAt,
            updatedAt: stored.updatedAt,
            kind: 'suspended',
            role: 'ADMIN',
            suspendedAt: stored.suspendedAt,
          };
        case 'MEMBER':
          return {
            id: stored.id,
            orgId: stored.orgId,
            userId: stored.userId,
            email: stored.email,
            displayName: stored.displayName,
            createdAt: stored.createdAt,
            updatedAt: stored.updatedAt,
            kind: 'suspended',
            role: 'MEMBER',
            suspendedAt: stored.suspendedAt,
          };
        case 'OWNER':
          throw new Error(`Owner membership ${stored.id} cannot be suspended`);
        default:
          return assertNever(stored.role);
      }
    case 'removed':
      if (!stored.removedAt) {
        throw new Error(`Removed membership ${stored.id} is missing removedAt`);
      }
      switch (stored.role) {
        case 'ADMIN':
          return {
            id: stored.id,
            orgId: stored.orgId,
            userId: stored.userId,
            email: stored.email,
            displayName: stored.displayName,
            createdAt: stored.createdAt,
            updatedAt: stored.updatedAt,
            kind: 'removed',
            role: 'ADMIN',
            removedAt: stored.removedAt,
          };
        case 'MEMBER':
          return {
            id: stored.id,
            orgId: stored.orgId,
            userId: stored.userId,
            email: stored.email,
            displayName: stored.displayName,
            createdAt: stored.createdAt,
            updatedAt: stored.updatedAt,
            kind: 'removed',
            role: 'MEMBER',
            removedAt: stored.removedAt,
          };
        case 'OWNER':
          throw new Error(`Owner membership ${stored.id} cannot be removed`);
        default:
          return assertNever(stored.role);
      }
    default:
      return assertNever(stored.kind);
  }
}

function invitationGrantFromStored(stored: StoredInvitation): OrganizationInvitationGrant {
  switch (stored.role) {
    case 'OWNER':
      return { role: 'OWNER' };
    case 'ADMIN':
      return {
        role: 'ADMIN',
        adminPermissions: normalizeAdminPermissions(stored.adminPermissions),
      };
    case 'MEMBER':
      return {
        role: 'MEMBER',
        projectAccess: cloneProjectAccess(stored.projectAccess),
      };
    default:
      return assertNever(stored.role);
  }
}

function invitationFromStored(stored: StoredInvitation): OrganizationInvitation {
  const common = {
    id: stored.id,
    orgId: stored.orgId,
    email: stored.email,
    invitedByUserId: stored.invitedByUserId,
    createdAt: stored.createdAt,
    updatedAt: stored.updatedAt,
  };
  const grant = invitationGrantFromStored(stored);
  switch (stored.kind) {
    case 'pending':
      if (!stored.expiresAt) {
        throw new Error(`Pending invitation ${stored.id} is missing expiresAt`);
      }
      return invitationWithPendingState(common, grant, stored.expiresAt);
    case 'accepted':
      if (!stored.membershipId || !stored.acceptedAt) {
        throw new Error(`Accepted invitation ${stored.id} is missing acceptance state`);
      }
      return invitationWithAcceptedState(common, grant, stored.membershipId, stored.acceptedAt);
    case 'declined':
      if (!stored.declinedAt) {
        throw new Error(`Declined invitation ${stored.id} is missing declinedAt`);
      }
      return invitationWithDeclinedState(common, grant, stored.declinedAt);
    case 'revoked':
      if (!stored.revokedAt) {
        throw new Error(`Revoked invitation ${stored.id} is missing revokedAt`);
      }
      return invitationWithRevokedState(common, grant, stored.revokedAt);
    case 'expired':
      if (!stored.expiredAt) {
        throw new Error(`Expired invitation ${stored.id} is missing expiredAt`);
      }
      return invitationWithExpiredState(common, grant, stored.expiredAt);
    default:
      return assertNever(stored.kind);
  }
}

type InvitationIdentitySnapshot = {
  readonly id: string;
  readonly orgId: string;
  readonly email: string;
  readonly invitedByUserId: string;
  readonly createdAt: string;
  readonly updatedAt: string;
};

function invitationWithPendingState(
  identity: InvitationIdentitySnapshot,
  grant: OrganizationInvitationGrant,
  expiresAt: string,
): OrganizationInvitation {
  switch (grant.role) {
    case 'OWNER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'OWNER',
        kind: 'pending',
        expiresAt,
      };
    case 'ADMIN':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'ADMIN',
        adminPermissions: grant.adminPermissions,
        kind: 'pending',
        expiresAt,
      };
    case 'MEMBER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'MEMBER',
        projectAccess: grant.projectAccess,
        kind: 'pending',
        expiresAt,
      };
    default:
      return assertNever(grant);
  }
}

function invitationWithAcceptedState(
  identity: InvitationIdentitySnapshot,
  grant: OrganizationInvitationGrant,
  membershipId: string,
  acceptedAt: string,
): OrganizationInvitation {
  switch (grant.role) {
    case 'OWNER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'OWNER',
        kind: 'accepted',
        membershipId,
        acceptedAt,
      };
    case 'ADMIN':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'ADMIN',
        adminPermissions: grant.adminPermissions,
        kind: 'accepted',
        membershipId,
        acceptedAt,
      };
    case 'MEMBER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'MEMBER',
        projectAccess: grant.projectAccess,
        kind: 'accepted',
        membershipId,
        acceptedAt,
      };
    default:
      return assertNever(grant);
  }
}

function invitationWithDeclinedState(
  identity: InvitationIdentitySnapshot,
  grant: OrganizationInvitationGrant,
  declinedAt: string,
): OrganizationInvitation {
  switch (grant.role) {
    case 'OWNER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'OWNER',
        kind: 'declined',
        declinedAt,
      };
    case 'ADMIN':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'ADMIN',
        adminPermissions: grant.adminPermissions,
        kind: 'declined',
        declinedAt,
      };
    case 'MEMBER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'MEMBER',
        projectAccess: grant.projectAccess,
        kind: 'declined',
        declinedAt,
      };
    default:
      return assertNever(grant);
  }
}

function invitationWithRevokedState(
  identity: InvitationIdentitySnapshot,
  grant: OrganizationInvitationGrant,
  revokedAt: string,
): OrganizationInvitation {
  switch (grant.role) {
    case 'OWNER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'OWNER',
        kind: 'revoked',
        revokedAt,
      };
    case 'ADMIN':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'ADMIN',
        adminPermissions: grant.adminPermissions,
        kind: 'revoked',
        revokedAt,
      };
    case 'MEMBER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'MEMBER',
        projectAccess: grant.projectAccess,
        kind: 'revoked',
        revokedAt,
      };
    default:
      return assertNever(grant);
  }
}

function invitationWithExpiredState(
  identity: InvitationIdentitySnapshot,
  grant: OrganizationInvitationGrant,
  expiredAt: string,
): OrganizationInvitation {
  switch (grant.role) {
    case 'OWNER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'OWNER',
        kind: 'expired',
        expiredAt,
      };
    case 'ADMIN':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'ADMIN',
        adminPermissions: grant.adminPermissions,
        kind: 'expired',
        expiredAt,
      };
    case 'MEMBER':
      return {
        id: identity.id,
        orgId: identity.orgId,
        email: identity.email,
        invitedByUserId: identity.invitedByUserId,
        createdAt: identity.createdAt,
        updatedAt: identity.updatedAt,
        role: 'MEMBER',
        projectAccess: grant.projectAccess,
        kind: 'expired',
        expiredAt,
      };
    default:
      return assertNever(grant);
  }
}

function projectAccessForMembership(
  store: OrganizationAccessStore,
  membershipId: string,
): readonly ProjectAccessAssignment[] {
  const assignments = store.projectAccess.get(membershipId);
  if (!assignments) return [];
  return cloneProjectAccess(Array.from(assignments.values()));
}

function membershipWithAccess(
  store: OrganizationAccessStore,
  stored: StoredMembership,
): OrganizationMembershipWithAccess {
  return {
    membership: membershipFromStored(stored),
    adminPermissions:
      stored.role === 'ADMIN'
        ? normalizeAdminPermissions(store.adminPermissions.get(stored.id) ?? [])
        : [],
    projectAccess: stored.role === 'MEMBER' ? projectAccessForMembership(store, stored.id) : [],
  };
}

function findMembershipByUserId(
  store: OrganizationAccessStore,
  userId: string,
): StoredMembership | null {
  for (const membership of store.memberships.values()) {
    if (membership.userId === userId && membership.kind !== 'removed') return membership;
  }
  return null;
}

function findMembershipByEmail(
  store: OrganizationAccessStore,
  email: string,
): StoredMembership | null {
  for (const membership of store.memberships.values()) {
    if (membership.email === email && membership.kind !== 'removed') return membership;
  }
  return null;
}

function countActiveOwners(store: OrganizationAccessStore): number {
  let count = 0;
  for (const membership of store.memberships.values()) {
    if (membership.kind === 'active' && membership.role === 'OWNER') count += 1;
  }
  return count;
}

function hasAdminPermission(
  store: OrganizationAccessStore,
  membershipId: string,
  permission: OrganizationAdminPermission,
): boolean {
  return (store.adminPermissions.get(membershipId) ?? []).includes(permission);
}

function sortMemberships(
  memberships: readonly OrganizationMembershipWithAccess[],
): readonly OrganizationMembershipWithAccess[] {
  const rank = { active: 0, suspended: 1, removed: 2 } as const;
  return [...memberships].sort((left, right) => {
    const kindDifference = rank[left.membership.kind] - rank[right.membership.kind];
    if (kindDifference !== 0) return kindDifference;
    return left.membership.email.localeCompare(right.membership.email);
  });
}

function sortInvitations(
  invitations: readonly OrganizationInvitation[],
): readonly OrganizationInvitation[] {
  return [...invitations].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
}

class InMemoryConsoleOrganizationAccessService implements ConsoleOrganizationAccessService {
  private readonly stores = new Map<string, OrganizationAccessStore>();

  private readonly now: () => Date;

  private readonly invitationTtlMs: number;

  private readonly createToken: () => string;

  private readonly hashToken: (token: string) => Promise<string>;

  constructor(options: InMemoryConsoleOrganizationAccessServiceOptions) {
    this.now = options.now ?? (() => new Date());
    this.invitationTtlMs = options.invitationTtlMs ?? DEFAULT_INVITATION_TTL_MS;
    if (!Number.isSafeInteger(this.invitationTtlMs) || this.invitationTtlMs <= 0) {
      throw new Error('invitationTtlMs must be a positive integer');
    }
    this.createToken = options.createInvitationToken ?? createOrganizationInvitationToken;
    this.hashToken = options.hashInvitationToken ?? hashOrganizationInvitationToken;
  }

  async bootstrapInitialOwner(input: BootstrapInitialOwnerInput): Promise<ActiveOwnerMembership> {
    const orgId = normalizeRequiredString(input.orgId, 'orgId');
    const userId = normalizeRequiredString(input.userId, 'userId');
    const email = normalizeEmail(input.email);
    const existingStore = this.stores.get(orgId);
    if (existingStore) {
      const existing = findMembershipByUserId(existingStore, userId);
      if (existing?.kind === 'active' && existing.role === 'OWNER') {
        return this.requireOwnerMembership(existing);
      }
      throw organizationAccessError(
        'owner_already_exists',
        409,
        'The organization already has its initial owner',
      );
    }
    const createdAt = this.now().toISOString();
    const membershipId = makeId('org_mbr', new Date(createdAt));
    const owner: StoredMembership = {
      id: membershipId,
      orgId,
      userId,
      email,
      displayName: input.displayName?.trim() || null,
      kind: 'active',
      role: 'OWNER',
      suspendedAt: null,
      removedAt: null,
      createdAt,
      updatedAt: createdAt,
    };
    const store: OrganizationAccessStore = {
      orgId,
      memberships: new Map([[owner.id, owner]]),
      invitations: new Map(),
      adminPermissions: new Map(),
      projectAccess: new Map(),
      ownerEvents: [],
      ownerAnchorMembershipId: owner.id,
      ownerSetVersion: 1,
      authorizationVersion: 1,
    };
    this.stores.set(orgId, store);
    this.appendOwnerEvent(store, owner, userId, 'OWNER_ADDED', createdAt);
    return this.requireOwnerMembership(owner);
  }

  async listMemberships(
    ctx: OrganizationAccessContext,
    request: ListOrganizationMembershipsRequest,
  ): Promise<readonly OrganizationMembershipWithAccess[]> {
    const store = this.requireStore(ctx.orgId);
    this.requireMembershipManager(store, ctx.actorUserId);
    const memberships: OrganizationMembershipWithAccess[] = [];
    for (const membership of store.memberships.values()) {
      if (request.kind !== 'all' && membership.kind !== request.kind) continue;
      memberships.push(membershipWithAccess(store, membership));
    }
    return sortMemberships(memberships);
  }

  async listInvitations(
    ctx: OrganizationAccessContext,
    request: ListOrganizationInvitationsRequest,
  ): Promise<readonly OrganizationInvitation[]> {
    const store = this.requireStore(ctx.orgId);
    this.requireMembershipManager(store, ctx.actorUserId);
    this.expireInvitations(store);
    const invitations: OrganizationInvitation[] = [];
    for (const invitation of store.invitations.values()) {
      if (request.kind !== 'all' && invitation.kind !== request.kind) continue;
      invitations.push(invitationFromStored(invitation));
    }
    return sortInvitations(invitations);
  }

  async invite(
    ctx: OrganizationAccessContext,
    request: InviteOrganizationMemberRequest,
  ): Promise<IssuedOrganizationInvitation> {
    const store = this.requireStore(ctx.orgId);
    const actor = this.requireInvitationAuthority(store, ctx.actorUserId, request.role);
    this.expireInvitations(store);
    const email = normalizeEmail(request.email);
    if (findMembershipByEmail(store, email)) {
      throw organizationAccessError(
        'membership_already_exists',
        409,
        'A current membership already uses this email address',
      );
    }
    for (const invitation of store.invitations.values()) {
      if (invitation.kind === 'pending' && invitation.email === email) {
        throw organizationAccessError(
          'invitation_already_exists',
          409,
          'A pending invitation already uses this email address',
        );
      }
    }
    const token = this.createToken();
    const tokenHash = await this.hashToken(token);
    const createdAtDate = this.now();
    const createdAt = createdAtDate.toISOString();
    const expiresAt = new Date(createdAtDate.getTime() + this.invitationTtlMs).toISOString();
    const grant = this.copyGrant(request);
    const invitation: StoredInvitation = {
      id: makeId('org_inv', createdAtDate),
      orgId: store.orgId,
      email,
      invitedByUserId: actor.userId,
      role: grant.role,
      adminPermissions: grant.role === 'ADMIN' ? grant.adminPermissions : [],
      projectAccess: grant.role === 'MEMBER' ? grant.projectAccess : [],
      kind: 'pending',
      tokenHash,
      expiresAt,
      membershipId: null,
      acceptedAt: null,
      declinedAt: null,
      revokedAt: null,
      expiredAt: null,
      createdAt,
      updatedAt: createdAt,
    };
    store.invitations.set(invitation.id, invitation);
    return {
      invitation: this.requirePendingInvitation(invitation),
      token,
    };
  }

  async resendInvitation(
    ctx: OrganizationAccessContext,
    invitationId: string,
  ): Promise<IssuedOrganizationInvitation> {
    const store = this.requireStore(ctx.orgId);
    const invitation = this.requireInvitation(store, invitationId);
    this.requireInvitationAuthority(store, ctx.actorUserId, invitation.role);
    this.expireInvitation(invitation);
    this.requirePendingStoredInvitation(invitation);
    const token = this.createToken();
    const tokenHash = await this.hashToken(token);
    const updatedAtDate = this.now();
    invitation.tokenHash = tokenHash;
    invitation.expiresAt = new Date(updatedAtDate.getTime() + this.invitationTtlMs).toISOString();
    invitation.updatedAt = updatedAtDate.toISOString();
    return {
      invitation: this.requirePendingInvitation(invitation),
      token,
    };
  }

  async revokeInvitation(
    ctx: OrganizationAccessContext,
    invitationId: string,
  ): Promise<OrganizationInvitation> {
    const store = this.requireStore(ctx.orgId);
    const invitation = this.requireInvitation(store, invitationId);
    this.requireInvitationAuthority(store, ctx.actorUserId, invitation.role);
    this.expireInvitation(invitation);
    this.requirePendingStoredInvitation(invitation);
    const revokedAt = this.now().toISOString();
    invitation.kind = 'revoked';
    invitation.tokenHash = null;
    invitation.expiresAt = null;
    invitation.revokedAt = revokedAt;
    invitation.updatedAt = revokedAt;
    return invitationFromStored(invitation);
  }

  async acceptInvitation(
    account: VerifiedInvitationAccount,
    invitationId: string,
    request: RedeemOrganizationInvitationRequest,
  ): Promise<ActiveOrganizationMembership> {
    const located = this.requireInvitationAcrossOrganizations(invitationId);
    const invitation = located.invitation;
    this.expireInvitation(invitation);
    this.requirePendingStoredInvitation(invitation);
    await this.verifyInvitationRedemption(account, invitation, request.token);
    const userId = normalizeRequiredString(account.userId, 'userId');
    const email = normalizeEmail(account.verifiedEmail);
    if (findMembershipByUserId(located.store, userId)) {
      throw organizationAccessError(
        'membership_already_exists',
        409,
        'This account already has a current membership',
      );
    }
    if (findMembershipByEmail(located.store, email)) {
      throw organizationAccessError(
        'membership_already_exists',
        409,
        'A current membership already uses this email address',
      );
    }
    const acceptedAtDate = this.now();
    const acceptedAt = acceptedAtDate.toISOString();
    const membership: StoredMembership = {
      id: makeId('org_mbr', acceptedAtDate),
      orgId: located.store.orgId,
      userId,
      email,
      displayName: null,
      kind: 'active',
      role: invitation.role,
      suspendedAt: null,
      removedAt: null,
      createdAt: acceptedAt,
      updatedAt: acceptedAt,
    };
    located.store.memberships.set(membership.id, membership);
    this.applyGrant(located.store, membership, invitationGrantFromStored(invitation));
    invitation.kind = 'accepted';
    invitation.tokenHash = null;
    invitation.expiresAt = null;
    invitation.membershipId = membership.id;
    invitation.acceptedAt = acceptedAt;
    invitation.updatedAt = acceptedAt;
    located.store.authorizationVersion += 1;
    if (membership.role === 'OWNER') {
      located.store.ownerSetVersion += 1;
      this.appendOwnerEvent(
        located.store,
        membership,
        membership.userId,
        'OWNER_ADDED',
        acceptedAt,
      );
    }
    return this.requireActiveMembership(membership);
  }

  async declineInvitation(
    account: VerifiedInvitationAccount,
    invitationId: string,
    request: RedeemOrganizationInvitationRequest,
  ): Promise<OrganizationInvitation> {
    normalizeRequiredString(account.userId, 'userId');
    const located = this.requireInvitationAcrossOrganizations(invitationId);
    const invitation = located.invitation;
    this.expireInvitation(invitation);
    this.requirePendingStoredInvitation(invitation);
    await this.verifyInvitationRedemption(account, invitation, request.token);
    const declinedAt = this.now().toISOString();
    invitation.kind = 'declined';
    invitation.tokenHash = null;
    invitation.expiresAt = null;
    invitation.declinedAt = declinedAt;
    invitation.updatedAt = declinedAt;
    return invitationFromStored(invitation);
  }

  async changeRole(
    ctx: OrganizationAccessContext,
    membershipId: string,
    request: ChangeOrganizationMembershipRoleRequest,
  ): Promise<OrganizationMembershipWithAccess> {
    const store = this.requireStore(ctx.orgId);
    this.requireOwner(store, ctx.actorUserId);
    const target = this.requireMembership(store, membershipId);
    if (target.userId === ctx.actorUserId) {
      throw organizationAccessError(
        'self_role_change_forbidden',
        409,
        'Owners cannot change their own role',
      );
    }
    if (target.kind !== 'active') {
      throw organizationAccessError(
        'membership_not_active',
        409,
        'Only an active membership can change role',
      );
    }
    const wasOwner = target.role === 'OWNER';
    const willBeOwner = request.role === 'OWNER';
    if (wasOwner && !willBeOwner && countActiveOwners(store) <= 1) {
      throw organizationAccessError(
        'last_owner_required',
        409,
        'The final owner cannot change role',
      );
    }
    const changedAt = this.now().toISOString();
    if (wasOwner && !willBeOwner) {
      this.moveOwnerAnchorBeforeRemoval(store, target.id);
      store.ownerSetVersion += 1;
      this.appendOwnerEvent(store, target, ctx.actorUserId, 'OWNER_REMOVED', changedAt);
    }
    target.role = request.role;
    target.updatedAt = changedAt;
    this.applyGrant(store, target, request);
    if (!wasOwner && willBeOwner) {
      store.ownerSetVersion += 1;
      this.appendOwnerEvent(store, target, ctx.actorUserId, 'OWNER_ADDED', changedAt);
    }
    store.authorizationVersion += 1;
    return membershipWithAccess(store, target);
  }

  async setAdminPermissions(
    ctx: OrganizationAccessContext,
    membershipId: string,
    request: SetOrganizationAdminPermissionsRequest,
  ): Promise<OrganizationMembershipWithAccess> {
    const store = this.requireStore(ctx.orgId);
    this.requireOwner(store, ctx.actorUserId);
    const target = this.requireMembership(store, membershipId);
    if (target.role !== 'ADMIN' || target.kind === 'removed') {
      throw organizationAccessError(
        'membership_not_administrator',
        409,
        'Administrator permissions require a current administrator membership',
      );
    }
    store.adminPermissions.set(target.id, normalizeAdminPermissions(request.permissions));
    target.updatedAt = this.now().toISOString();
    store.authorizationVersion += 1;
    return membershipWithAccess(store, target);
  }

  async suspendMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess> {
    const store = this.requireStore(ctx.orgId);
    const target = this.requireMembership(store, membershipId);
    this.requireTargetLifecycleAuthority(store, ctx.actorUserId, target);
    this.rejectSelfLifecycleMutation(ctx, target);
    if (target.kind !== 'active') {
      throw organizationAccessError(
        'membership_not_active',
        409,
        'Only an active membership can be suspended',
      );
    }
    if (target.role === 'OWNER') {
      throw organizationAccessError(
        'owner_must_be_demoted',
        409,
        'An owner must become an administrator before suspension',
      );
    }
    const suspendedAt = this.now().toISOString();
    target.kind = 'suspended';
    target.suspendedAt = suspendedAt;
    target.updatedAt = suspendedAt;
    store.authorizationVersion += 1;
    return membershipWithAccess(store, target);
  }

  async reactivateMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess> {
    const store = this.requireStore(ctx.orgId);
    const target = this.requireMembership(store, membershipId);
    this.requireTargetLifecycleAuthority(store, ctx.actorUserId, target);
    this.rejectSelfLifecycleMutation(ctx, target);
    if (target.kind !== 'suspended') {
      throw organizationAccessError(
        'membership_not_suspended',
        409,
        'Only a suspended membership can be reactivated',
      );
    }
    target.kind = 'active';
    target.suspendedAt = null;
    target.updatedAt = this.now().toISOString();
    store.authorizationVersion += 1;
    return membershipWithAccess(store, target);
  }

  async removeMembership(
    ctx: OrganizationAccessContext,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess> {
    const store = this.requireStore(ctx.orgId);
    const target = this.requireMembership(store, membershipId);
    this.requireTargetLifecycleAuthority(store, ctx.actorUserId, target);
    this.rejectSelfLifecycleMutation(ctx, target);
    if (target.kind === 'removed') {
      return membershipWithAccess(store, target);
    }
    if (target.role === 'OWNER') {
      throw organizationAccessError(
        'owner_must_be_demoted',
        409,
        'An owner must become an administrator before removal',
      );
    }
    this.markRemoved(store, target, this.now().toISOString());
    return membershipWithAccess(store, target);
  }

  async leaveOrganization(
    ctx: OrganizationAccessContext,
  ): Promise<OrganizationMembershipWithAccess> {
    const store = this.requireStore(ctx.orgId);
    const actor = this.requireActiveActor(store, ctx.actorUserId);
    const removedAt = this.now().toISOString();
    if (actor.role === 'OWNER') {
      if (countActiveOwners(store) <= 1) {
        throw organizationAccessError(
          'last_owner_required',
          409,
          'The final owner cannot leave the organization',
        );
      }
      this.moveOwnerAnchorBeforeRemoval(store, actor.id);
      this.appendOwnerEvent(store, actor, actor.userId, 'OWNER_REMOVED', removedAt);
      store.ownerSetVersion += 1;
      actor.role = 'ADMIN';
    }
    this.markRemoved(store, actor, removedAt);
    return membershipWithAccess(store, actor);
  }

  async setProjectAccess(
    ctx: OrganizationAccessContext,
    projectId: string,
    membershipId: string,
    request: SetProjectMemberAccessRequest,
  ): Promise<OrganizationMembershipWithAccess> {
    const store = this.requireStore(ctx.orgId);
    this.requireProjectManager(store, ctx.actorUserId);
    const target = this.requireActiveMember(store, membershipId);
    const normalizedProjectId = normalizeRequiredString(projectId, 'projectId');
    const assignments = store.projectAccess.get(target.id) ?? new Map();
    assignments.set(normalizedProjectId, {
      projectId: normalizedProjectId,
      accessLevel: request.accessLevel,
    });
    store.projectAccess.set(target.id, assignments);
    target.updatedAt = this.now().toISOString();
    store.authorizationVersion += 1;
    return membershipWithAccess(store, target);
  }

  async removeProjectAccess(
    ctx: OrganizationAccessContext,
    projectId: string,
    membershipId: string,
  ): Promise<OrganizationMembershipWithAccess> {
    const store = this.requireStore(ctx.orgId);
    this.requireProjectManager(store, ctx.actorUserId);
    const target = this.requireActiveMember(store, membershipId);
    const assignments = store.projectAccess.get(target.id);
    const changed = assignments?.delete(normalizeRequiredString(projectId, 'projectId')) ?? false;
    if (changed) {
      target.updatedAt = this.now().toISOString();
      store.authorizationVersion += 1;
    }
    return membershipWithAccess(store, target);
  }

  async lookupAuthorization(
    lookup: OrganizationAuthorizationLookup,
  ): Promise<OrganizationAuthorization | null> {
    const orgId = normalizeRequiredString(lookup.orgId, 'orgId');
    const userId = normalizeRequiredString(lookup.userId, 'userId');
    const store = this.stores.get(orgId);
    if (!store) return null;
    let removed: StoredMembership | null = null;
    for (const membership of store.memberships.values()) {
      if (membership.userId !== userId) continue;
      if (membership.kind === 'removed') {
        removed = membership;
        continue;
      }
      if (membership.kind === 'suspended') {
        return {
          kind: 'denied',
          orgId,
          userId,
          membershipId: membership.id,
          authorizationVersion: store.authorizationVersion,
          reason: 'membership_suspended',
        };
      }
      return this.authorizedLookup(store, membership);
    }
    if (removed) {
      return {
        kind: 'denied',
        orgId,
        userId,
        membershipId: removed.id,
        authorizationVersion: store.authorizationVersion,
        reason: 'membership_removed',
      };
    }
    return {
      kind: 'denied',
      orgId,
      userId,
      membershipId: null,
      authorizationVersion: store.authorizationVersion,
      reason: 'membership_not_found',
    };
  }

  async getAuthorizationVersion(orgId: string): Promise<number | null> {
    return this.stores.get(normalizeRequiredString(orgId, 'orgId'))?.authorizationVersion ?? null;
  }

  async listOwnerEvents(
    ctx: OrganizationAccessContext,
  ): Promise<readonly OrganizationOwnerEvent[]> {
    const store = this.requireStore(ctx.orgId);
    this.requireOwner(store, ctx.actorUserId);
    return store.ownerEvents.map((event) => ({
      id: event.id,
      orgId: event.orgId,
      membershipId: event.membershipId,
      ownerUserId: event.ownerUserId,
      actorUserId: event.actorUserId,
      kind: event.kind,
      createdAt: event.createdAt,
    }));
  }

  async purgeOrganization(orgId: string): Promise<void> {
    this.stores.delete(normalizeRequiredString(orgId, 'orgId'));
  }

  private requireStore(orgId: string): OrganizationAccessStore {
    const normalizedOrgId = normalizeRequiredString(orgId, 'orgId');
    const store = this.stores.get(normalizedOrgId);
    if (!store) {
      throw organizationAccessError('organization_not_found', 404, 'Organization was not found');
    }
    return store;
  }

  private requireMembership(
    store: OrganizationAccessStore,
    membershipId: string,
  ): StoredMembership {
    const normalizedMembershipId = normalizeRequiredString(membershipId, 'membershipId');
    const membership = store.memberships.get(normalizedMembershipId);
    if (!membership) {
      throw organizationAccessError('membership_not_found', 404, 'Membership was not found');
    }
    return membership;
  }

  private requireActiveActor(
    store: OrganizationAccessStore,
    actorUserId: string,
  ): StoredMembership {
    const actor = findMembershipByUserId(
      store,
      normalizeRequiredString(actorUserId, 'actorUserId'),
    );
    if (!actor || actor.kind !== 'active') {
      throw organizationAccessError('forbidden', 403, 'An active membership is required');
    }
    return actor;
  }

  private requireOwner(store: OrganizationAccessStore, actorUserId: string): StoredMembership {
    const actor = this.requireActiveActor(store, actorUserId);
    if (actor.role !== 'OWNER') {
      throw organizationAccessError('forbidden', 403, 'Owner access is required');
    }
    return actor;
  }

  private requireMembershipManager(
    store: OrganizationAccessStore,
    actorUserId: string,
  ): StoredMembership {
    const actor = this.requireActiveActor(store, actorUserId);
    if (
      actor.role !== 'OWNER' &&
      !(actor.role === 'ADMIN' && hasAdminPermission(store, actor.id, 'members.manage'))
    ) {
      throw organizationAccessError('forbidden', 403, 'Membership management access is required');
    }
    return actor;
  }

  private requireProjectManager(
    store: OrganizationAccessStore,
    actorUserId: string,
  ): StoredMembership {
    const actor = this.requireActiveActor(store, actorUserId);
    if (
      actor.role !== 'OWNER' &&
      !(actor.role === 'ADMIN' && hasAdminPermission(store, actor.id, 'projects.manage'))
    ) {
      throw organizationAccessError('forbidden', 403, 'Project management access is required');
    }
    return actor;
  }

  private requireInvitationAuthority(
    store: OrganizationAccessStore,
    actorUserId: string,
    invitedRole: OrganizationMembershipRole,
  ): StoredMembership {
    const actor = this.requireActiveActor(store, actorUserId);
    if (actor.role === 'OWNER') return actor;
    if (
      actor.role === 'ADMIN' &&
      invitedRole === 'MEMBER' &&
      hasAdminPermission(store, actor.id, 'members.manage')
    ) {
      return actor;
    }
    throw organizationAccessError(
      'forbidden',
      403,
      'This membership cannot issue or manage the requested invitation',
    );
  }

  private requireTargetLifecycleAuthority(
    store: OrganizationAccessStore,
    actorUserId: string,
    target: StoredMembership,
  ): StoredMembership {
    const actor = this.requireActiveActor(store, actorUserId);
    if (actor.role === 'OWNER') return actor;
    if (
      actor.role === 'ADMIN' &&
      target.role === 'MEMBER' &&
      hasAdminPermission(store, actor.id, 'members.manage')
    ) {
      return actor;
    }
    throw organizationAccessError(
      'forbidden',
      403,
      'This membership cannot change the target membership',
    );
  }

  private rejectSelfLifecycleMutation(
    ctx: OrganizationAccessContext,
    target: StoredMembership,
  ): void {
    if (target.userId === ctx.actorUserId) {
      throw organizationAccessError(
        'self_membership_change_forbidden',
        409,
        'Use the organization leave operation for your own membership',
      );
    }
  }

  private requireActiveMember(
    store: OrganizationAccessStore,
    membershipId: string,
  ): StoredMembership {
    const target = this.requireMembership(store, membershipId);
    if (target.kind !== 'active' || target.role !== 'MEMBER') {
      throw organizationAccessError(
        'membership_not_member',
        409,
        'Project access requires an active member membership',
      );
    }
    return target;
  }

  private requireInvitation(
    store: OrganizationAccessStore,
    invitationId: string,
  ): StoredInvitation {
    const normalizedInvitationId = normalizeRequiredString(invitationId, 'invitationId');
    const invitation = store.invitations.get(normalizedInvitationId);
    if (!invitation) {
      throw organizationAccessError('invitation_not_found', 404, 'Invitation was not found');
    }
    return invitation;
  }

  private requireInvitationAcrossOrganizations(invitationId: string): {
    readonly store: OrganizationAccessStore;
    readonly invitation: StoredInvitation;
  } {
    const normalizedInvitationId = normalizeRequiredString(invitationId, 'invitationId');
    for (const store of this.stores.values()) {
      const invitation = store.invitations.get(normalizedInvitationId);
      if (invitation) return { store, invitation };
    }
    throw organizationAccessError('invitation_not_found', 404, 'Invitation was not found');
  }

  private expireInvitation(invitation: StoredInvitation): void {
    if (invitation.kind !== 'pending' || !invitation.expiresAt) return;
    const now = this.now();
    if (Date.parse(invitation.expiresAt) > now.getTime()) return;
    const expiredAt = now.toISOString();
    invitation.kind = 'expired';
    invitation.tokenHash = null;
    invitation.expiresAt = null;
    invitation.expiredAt = expiredAt;
    invitation.updatedAt = expiredAt;
  }

  private expireInvitations(store: OrganizationAccessStore): void {
    for (const invitation of store.invitations.values()) {
      this.expireInvitation(invitation);
    }
  }

  private requirePendingStoredInvitation(invitation: StoredInvitation): void {
    if (invitation.kind !== 'pending') {
      throw organizationAccessError(
        'invitation_not_pending',
        409,
        `Invitation is already ${invitation.kind}`,
      );
    }
  }

  private requirePendingInvitation(
    invitation: StoredInvitation,
  ): IssuedOrganizationInvitation['invitation'] {
    const domain = invitationFromStored(invitation);
    if (domain.kind !== 'pending') {
      throw new Error(`Expected pending invitation ${invitation.id}`);
    }
    return domain;
  }

  private async verifyInvitationRedemption(
    account: VerifiedInvitationAccount,
    invitation: StoredInvitation,
    token: string,
  ): Promise<void> {
    const verifiedEmail = normalizeEmail(account.verifiedEmail);
    if (verifiedEmail !== invitation.email) {
      throw organizationAccessError(
        'invitation_email_mismatch',
        403,
        'The authenticated verified email does not match the invitation',
      );
    }
    const tokenHash = await this.hashToken(normalizeRequiredString(token, 'token'));
    if (!invitation.tokenHash || tokenHash !== invitation.tokenHash) {
      throw organizationAccessError('invalid_invitation_token', 403, 'Invitation token is invalid');
    }
  }

  private copyGrant(grant: OrganizationInvitationGrant): OrganizationInvitationGrant {
    switch (grant.role) {
      case 'OWNER':
        return { role: 'OWNER' };
      case 'ADMIN':
        return {
          role: 'ADMIN',
          adminPermissions: normalizeAdminPermissions(grant.adminPermissions),
        };
      case 'MEMBER':
        return {
          role: 'MEMBER',
          projectAccess: cloneProjectAccess(grant.projectAccess),
        };
      default:
        return assertNever(grant);
    }
  }

  private applyGrant(
    store: OrganizationAccessStore,
    membership: StoredMembership,
    grant: OrganizationInvitationGrant,
  ): void {
    store.adminPermissions.delete(membership.id);
    store.projectAccess.delete(membership.id);
    switch (grant.role) {
      case 'OWNER':
        return;
      case 'ADMIN':
        store.adminPermissions.set(
          membership.id,
          normalizeAdminPermissions(grant.adminPermissions),
        );
        return;
      case 'MEMBER': {
        const assignments = new Map<string, ProjectAccessAssignment>();
        for (const assignment of grant.projectAccess) {
          assignments.set(assignment.projectId, {
            projectId: assignment.projectId,
            accessLevel: assignment.accessLevel,
          });
        }
        store.projectAccess.set(membership.id, assignments);
        return;
      }
      default:
        return assertNever(grant);
    }
  }

  private markRemoved(
    store: OrganizationAccessStore,
    membership: StoredMembership,
    removedAt: string,
  ): void {
    membership.kind = 'removed';
    membership.suspendedAt = null;
    membership.removedAt = removedAt;
    membership.updatedAt = removedAt;
    store.adminPermissions.delete(membership.id);
    store.projectAccess.delete(membership.id);
    store.authorizationVersion += 1;
  }

  private moveOwnerAnchorBeforeRemoval(store: OrganizationAccessStore, membershipId: string): void {
    if (store.ownerAnchorMembershipId !== membershipId) return;
    for (const membership of store.memberships.values()) {
      if (
        membership.id !== membershipId &&
        membership.kind === 'active' &&
        membership.role === 'OWNER'
      ) {
        store.ownerAnchorMembershipId = membership.id;
        return;
      }
    }
    throw organizationAccessError('last_owner_required', 409, 'The final owner must remain');
  }

  private appendOwnerEvent(
    store: OrganizationAccessStore,
    membership: StoredMembership,
    actorUserId: string,
    kind: OrganizationOwnerEvent['kind'],
    createdAt: string,
  ): void {
    store.ownerEvents.push({
      id: makeId('org_owner_evt', new Date(createdAt)),
      orgId: store.orgId,
      membershipId: membership.id,
      ownerUserId: membership.userId,
      actorUserId,
      kind,
      createdAt,
    });
  }

  private requireActiveMembership(stored: StoredMembership): ActiveOrganizationMembership {
    const membership = membershipFromStored(stored);
    if (membership.kind !== 'active') {
      throw new Error(`Expected active membership ${stored.id}`);
    }
    return membership;
  }

  private requireOwnerMembership(stored: StoredMembership): ActiveOwnerMembership {
    const membership = membershipFromStored(stored);
    if (membership.kind !== 'active' || membership.role !== 'OWNER') {
      throw new Error(`Expected owner membership ${stored.id}`);
    }
    return membership;
  }

  private authorizedLookup(
    store: OrganizationAccessStore,
    membership: StoredMembership,
  ): OrganizationAuthorization {
    if (membership.kind !== 'active') {
      throw new Error(`Expected active authorization membership ${membership.id}`);
    }
    switch (membership.role) {
      case 'OWNER':
        return {
          kind: 'authorized',
          orgId: store.orgId,
          userId: membership.userId,
          membershipId: membership.id,
          role: 'OWNER',
          authorizationVersion: store.authorizationVersion,
          adminPermissions: ORGANIZATION_ADMIN_PERMISSIONS,
          projectAccess: { kind: 'all' },
        };
      case 'ADMIN':
        return {
          kind: 'authorized',
          orgId: store.orgId,
          userId: membership.userId,
          membershipId: membership.id,
          role: 'ADMIN',
          authorizationVersion: store.authorizationVersion,
          adminPermissions: normalizeAdminPermissions(
            store.adminPermissions.get(membership.id) ?? [],
          ),
          projectAccess: { kind: 'all' },
        };
      case 'MEMBER':
        return {
          kind: 'authorized',
          orgId: store.orgId,
          userId: membership.userId,
          membershipId: membership.id,
          role: 'MEMBER',
          authorizationVersion: store.authorizationVersion,
          adminPermissions: [],
          projectAccess: {
            kind: 'assigned',
            assignments: projectAccessForMembership(store, membership.id),
          },
        };
      default:
        return assertNever(membership.role);
    }
  }
}

export function createInMemoryConsoleOrganizationAccessService(
  options: InMemoryConsoleOrganizationAccessServiceOptions = {},
): ConsoleOrganizationAccessService {
  return new InMemoryConsoleOrganizationAccessService(options);
}
