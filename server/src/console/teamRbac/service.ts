import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import { ConsoleTeamRbacError } from './errors';
import {
  CONSOLE_ORG_SCOPED_TEAM_ROLES,
  type ConsoleTeamMember,
  type ConsoleTeamRole,
  type ConsoleTeamRoleAssignment,
  type InviteConsoleTeamMemberRequest,
  type ListConsoleTeamMembersRequest,
  type UpdateConsoleTeamMemberRolesRequest,
} from './types';

export interface ConsoleTeamRbacContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  actorEmail?: string;
  actorDisplayName?: string;
  projectId?: string;
}

export interface ConsoleTeamRbacService {
  bootstrapOwner(ctx: ConsoleTeamRbacContext): Promise<ConsoleTeamMember>;
  listMembers(
    ctx: ConsoleTeamRbacContext,
    request?: ListConsoleTeamMembersRequest,
  ): Promise<ConsoleTeamMember[]>;
  listOrganizationMembers?(
    orgId: string,
    request?: ListConsoleTeamMembersRequest,
  ): Promise<ConsoleTeamMember[]>;
  purgeOrganization(ctx: ConsoleTeamRbacContext): Promise<void>;
  transferOwner(
    ctx: ConsoleTeamRbacContext,
    targetMemberId: string,
  ): Promise<{ previousOwner: ConsoleTeamMember; nextOwner: ConsoleTeamMember }>;
  inviteMember(
    ctx: ConsoleTeamRbacContext,
    request: InviteConsoleTeamMemberRequest,
  ): Promise<ConsoleTeamMember>;
  updateMemberRoles(
    ctx: ConsoleTeamRbacContext,
    memberId: string,
    request: UpdateConsoleTeamMemberRolesRequest,
  ): Promise<ConsoleTeamMember | null>;
  removeMember(
    ctx: ConsoleTeamRbacContext,
    memberId: string,
  ): Promise<{ removed: boolean; member: ConsoleTeamMember | null }>;
}

export interface InMemoryConsoleTeamRbacServiceOptions {
  now?: () => Date;
}

interface OrgStore {
  members: Map<string, ConsoleTeamMember>;
}

const ORG_ROLE_SET = new Set<string>(CONSOLE_ORG_SCOPED_TEAM_ROLES);

function toIso(now: Date): string {
  return now.toISOString();
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}

function normalizeRole(raw: unknown): ConsoleTeamRole | null {
  const role = String(raw || '')
    .trim()
    .toLowerCase();
  if (!ORG_ROLE_SET.has(role)) return null;
  return role as ConsoleTeamRole;
}

function cloneRoleAssignment(input: ConsoleTeamRoleAssignment): ConsoleTeamRoleAssignment {
  return {
    role: input.role,
    scope: 'ORG',
  };
}

function cloneMember(input: ConsoleTeamMember): ConsoleTeamMember {
  return {
    id: input.id,
    orgId: input.orgId,
    userId: input.userId,
    email: input.email,
    ...(input.displayName ? { displayName: input.displayName } : {}),
    status: input.status,
    roles: input.roles.map(cloneRoleAssignment),
    invitedByUserId: input.invitedByUserId,
    invitedAt: input.invitedAt,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    lastStatusChangedAt: input.lastStatusChangedAt,
  };
}

function normalizeRoleAssignments(input: ConsoleTeamRoleAssignment[]): ConsoleTeamRoleAssignment[] {
  const out: ConsoleTeamRoleAssignment[] = [];
  const seen = new Set<string>();
  for (const assignment of input) {
    const role = normalizeRole(assignment.role);
    if (!role) continue;
    const key = `ORG:${role}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      role,
      scope: 'ORG',
    });
  }

  return out.sort((a, b) => a.role.localeCompare(b.role));
}

function deriveActorRoleAssignments(ctx: ConsoleTeamRbacContext): ConsoleTeamRoleAssignment[] {
  const out: ConsoleTeamRoleAssignment[] = [];
  for (const rawRole of ctx.roles) {
    const role = normalizeRole(rawRole);
    if (!role) continue;
    out.push({ role, scope: 'ORG' });
  }
  return normalizeRoleAssignments(out);
}

function hasOwnerRole(member: ConsoleTeamMember): boolean {
  return member.roles.some((entry) => entry.role === 'owner');
}

function countActiveOwners(store: OrgStore): number {
  let count = 0;
  for (const member of store.members.values()) {
    if (member.status !== 'ACTIVE') continue;
    if (hasOwnerRole(member)) count += 1;
  }
  return count;
}

function findMemberByUserId(store: OrgStore, userId: string): ConsoleTeamMember | null {
  for (const member of store.members.values()) {
    if (member.userId === userId) return member;
  }
  return null;
}

function findMemberByEmail(store: OrgStore, email: string): ConsoleTeamMember | null {
  const key = email.toLowerCase();
  for (const member of store.members.values()) {
    if (
      String(member.email || '')
        .trim()
        .toLowerCase() === key
    )
      return member;
  }
  return null;
}

function hasOwnerClaim(ctx: ConsoleTeamRbacContext): boolean {
  return ctx.roles.some(
    (entry) =>
      String(entry || '')
        .trim()
        .toLowerCase() === 'owner',
  );
}

function isConsoleLocalEmail(value: string): boolean {
  return String(value || '')
    .trim()
    .toLowerCase()
    .endsWith('@console.local');
}

function resolveActorEmail(ctx: ConsoleTeamRbacContext): string {
  const claimed = String(ctx.actorEmail || '')
    .trim()
    .toLowerCase();
  if (claimed && claimed.includes('@')) return claimed;
  return `${String(ctx.actorUserId || '').trim()}@console.local`;
}

function resolveActorDisplayName(ctx: ConsoleTeamRbacContext): string {
  const claimed = String(ctx.actorDisplayName || '').trim();
  if (claimed) return claimed;
  return String(ctx.actorUserId || '').trim();
}

function memberHasAdminEligibility(member: ConsoleTeamMember): boolean {
  return member.roles.some((entry) => entry.role === 'owner' || entry.role === 'admin');
}

function sortMembers(items: ConsoleTeamMember[]): ConsoleTeamMember[] {
  const rank = (status: ConsoleTeamMember['status']): number => {
    if (status === 'ACTIVE') return 0;
    if (status === 'INVITED') return 1;
    if (status === 'SUSPENDED') return 2;
    return 3;
  };

  return [...items].sort((a, b) => {
    const statusRankDiff = rank(a.status) - rank(b.status);
    if (statusRankDiff !== 0) return statusRankDiff;
    return b.updatedAt.localeCompare(a.updatedAt);
  });
}

export function createInMemoryConsoleTeamRbacService(
  opts: InMemoryConsoleTeamRbacServiceOptions = {},
): ConsoleTeamRbacService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, OrgStore>();

  function ensureOrgStore(orgId: string): OrgStore {
    let store = stores.get(orgId);
    if (!store) {
      store = {
        members: new Map<string, ConsoleTeamMember>(),
      };
      stores.set(orgId, store);
    }
    return store;
  }

  function ensureActorMembership(ctx: ConsoleTeamRbacContext): void {
    const store = ensureOrgStore(ctx.orgId);
    const currentNow = now();
    const actorUserId = String(ctx.actorUserId || '').trim();
    if (!actorUserId) return;

    const actorRoles = deriveActorRoleAssignments(ctx);
    const actorEmail = resolveActorEmail(ctx);
    const actorDisplayName = resolveActorDisplayName(ctx);
    const existing = findMemberByUserId(store, actorUserId);
    if (!existing) {
      const ts = toIso(currentNow);
      const memberId = makeId('mbr', currentNow);
      store.members.set(memberId, {
        id: memberId,
        orgId: ctx.orgId,
        userId: actorUserId,
        email: actorEmail,
        displayName: actorDisplayName,
        status: 'ACTIVE',
        roles: actorRoles,
        invitedByUserId: actorUserId,
        invitedAt: ts,
        createdAt: ts,
        updatedAt: ts,
        lastStatusChangedAt: ts,
      });
      return;
    }

    if (existing.status === 'REMOVED') {
      existing.status = 'ACTIVE';
      existing.lastStatusChangedAt = toIso(currentNow);
    }
    if (
      actorEmail &&
      (isConsoleLocalEmail(existing.email) || !String(existing.email || '').trim())
    ) {
      existing.email = actorEmail;
    }
    if (
      actorDisplayName &&
      (!String(existing.displayName || '').trim() ||
        String(existing.displayName || '').trim() === actorUserId)
    ) {
      existing.displayName = actorDisplayName;
    }
    if (actorRoles.length > 0) {
      existing.roles = normalizeRoleAssignments([...existing.roles, ...actorRoles]);
    }
    existing.updatedAt = toIso(currentNow);
  }

  return {
    async bootstrapOwner(ctx: ConsoleTeamRbacContext): Promise<ConsoleTeamMember> {
      ensureActorMembership(ctx);
      const store = ensureOrgStore(ctx.orgId);
      const actorUserId = String(ctx.actorUserId || '').trim();
      if (!actorUserId) {
        throw new ConsoleTeamRbacError('invalid_body', 400, 'Actor user id is required');
      }
      const actor = findMemberByUserId(store, actorUserId);
      if (!actor) {
        throw new ConsoleTeamRbacError(
          'member_not_found',
          404,
          `Actor member for user ${actorUserId} was not found`,
        );
      }
      const ts = toIso(now());
      if (hasOwnerRole(actor)) {
        if (actor.status !== 'ACTIVE') {
          actor.status = 'ACTIVE';
          actor.lastStatusChangedAt = ts;
        }
        actor.updatedAt = ts;
        return cloneMember(actor);
      }
      if (countActiveOwners(store) > 0) {
        throw new ConsoleTeamRbacError(
          'owner_already_exists',
          409,
          'Owner membership already exists for this organization',
        );
      }
      actor.roles = normalizeRoleAssignments([...actor.roles, { role: 'owner', scope: 'ORG' }]);
      if (actor.status !== 'ACTIVE') {
        actor.status = 'ACTIVE';
        actor.lastStatusChangedAt = ts;
      }
      actor.updatedAt = ts;
      return cloneMember(actor);
    },

    async listMembers(
      ctx: ConsoleTeamRbacContext,
      request?: ListConsoleTeamMembersRequest,
    ): Promise<ConsoleTeamMember[]> {
      ensureActorMembership(ctx);
      const store = ensureOrgStore(ctx.orgId);
      const status = request?.status;
      return sortMembers(Array.from(store.members.values()))
        .filter((member) => (!status ? true : member.status === status))
        .map(cloneMember);
    },

    async listOrganizationMembers(
      orgId: string,
      request?: ListConsoleTeamMembersRequest,
    ): Promise<ConsoleTeamMember[]> {
      const store = ensureOrgStore(orgId);
      const status = request?.status;
      return sortMembers(Array.from(store.members.values()))
        .filter((member) => (!status ? true : member.status === status))
        .map(cloneMember);
    },

    async purgeOrganization(ctx: ConsoleTeamRbacContext): Promise<void> {
      stores.delete(ctx.orgId);
    },

    async transferOwner(
      ctx: ConsoleTeamRbacContext,
      targetMemberId: string,
    ): Promise<{ previousOwner: ConsoleTeamMember; nextOwner: ConsoleTeamMember }> {
      ensureActorMembership(ctx);
      const store = ensureOrgStore(ctx.orgId);
      const actorUserId = String(ctx.actorUserId || '').trim();
      if (!actorUserId) {
        throw new ConsoleTeamRbacError('invalid_body', 400, 'Actor user id is required');
      }
      const actor = findMemberByUserId(store, actorUserId);
      if (!actor) {
        throw new ConsoleTeamRbacError(
          'member_not_found',
          404,
          `Actor member for user ${actorUserId} was not found`,
        );
      }
      if (actor.status !== 'ACTIVE' || !hasOwnerRole(actor)) {
        throw new ConsoleTeamRbacError(
          'forbidden',
          403,
          'Only the current owner can transfer organization ownership',
        );
      }

      const target = store.members.get(targetMemberId);
      if (!target) {
        throw new ConsoleTeamRbacError(
          'member_not_found',
          404,
          `Member ${targetMemberId} was not found`,
        );
      }
      if (target.status !== 'ACTIVE') {
        throw new ConsoleTeamRbacError(
          'invalid_body',
          409,
          'Owner transfer target must be an active organization member',
        );
      }
      if (!memberHasAdminEligibility(target)) {
        throw new ConsoleTeamRbacError(
          'invalid_body',
          409,
          'Owner transfer target must already have admin eligibility',
        );
      }
      if (target.id === actor.id) {
        return {
          previousOwner: cloneMember(actor),
          nextOwner: cloneMember(actor),
        };
      }

      const ts = toIso(now());
      target.roles = normalizeRoleAssignments([
        ...target.roles,
        { role: 'owner', scope: 'ORG' },
        { role: 'admin', scope: 'ORG' },
      ]);
      target.updatedAt = ts;

      actor.roles = normalizeRoleAssignments([
        ...actor.roles.filter((entry) => entry.role !== 'owner'),
        { role: 'admin', scope: 'ORG' },
      ]);
      actor.updatedAt = ts;

      return {
        previousOwner: cloneMember(actor),
        nextOwner: cloneMember(target),
      };
    },

    async inviteMember(
      ctx: ConsoleTeamRbacContext,
      request: InviteConsoleTeamMemberRequest,
    ): Promise<ConsoleTeamMember> {
      ensureActorMembership(ctx);
      const store = ensureOrgStore(ctx.orgId);
      const currentNow = now();
      const ts = toIso(currentNow);
      const userId = String(request.userId || '').trim();
      const email = String(request.email || '')
        .trim()
        .toLowerCase();
      const displayName = String(request.displayName || '').trim();
      if (!userId) {
        throw new ConsoleTeamRbacError('invalid_body', 400, 'Field userId is required');
      }
      if (!email) {
        throw new ConsoleTeamRbacError('invalid_body', 400, 'Field email is required');
      }

      const roles = normalizeRoleAssignments(request.roles);
      if (roles.length === 0) {
        throw new ConsoleTeamRbacError(
          'invalid_body',
          400,
          'At least one role assignment is required',
        );
      }
      if (roles.some((entry) => entry.role === 'owner') && !hasOwnerClaim(ctx)) {
        throw new ConsoleTeamRbacError(
          'forbidden',
          403,
          'Only owner can assign owner role memberships',
        );
      }

      const existingByUserId = findMemberByUserId(store, userId);
      if (existingByUserId && existingByUserId.status !== 'REMOVED') {
        throw new ConsoleTeamRbacError(
          'member_already_exists',
          409,
          `Member with userId ${userId} already exists`,
        );
      }
      const existingByEmail = findMemberByEmail(store, email);
      if (
        existingByEmail &&
        existingByEmail.status !== 'REMOVED' &&
        (!existingByUserId || existingByUserId.id !== existingByEmail.id)
      ) {
        throw new ConsoleTeamRbacError(
          'member_already_exists',
          409,
          `Member with email ${email} already exists`,
        );
      }

      const removedMember =
        (existingByUserId && existingByUserId.status === 'REMOVED' ? existingByUserId : null) ||
        (existingByEmail && existingByEmail.status === 'REMOVED' ? existingByEmail : null);
      if (removedMember) {
        removedMember.userId = userId;
        removedMember.email = email;
        removedMember.displayName = displayName || removedMember.displayName;
        removedMember.status = 'ACTIVE';
        removedMember.roles = roles;
        removedMember.invitedByUserId = ctx.actorUserId;
        removedMember.invitedAt = ts;
        removedMember.updatedAt = ts;
        removedMember.lastStatusChangedAt = ts;
        return cloneMember(removedMember);
      }

      const member: ConsoleTeamMember = {
        id: makeId('mbr', currentNow),
        orgId: ctx.orgId,
        userId,
        email,
        ...(displayName ? { displayName } : {}),
        status: 'ACTIVE',
        roles,
        invitedByUserId: ctx.actorUserId,
        invitedAt: ts,
        createdAt: ts,
        updatedAt: ts,
        lastStatusChangedAt: ts,
      };
      store.members.set(member.id, member);
      return cloneMember(member);
    },

    async updateMemberRoles(
      ctx: ConsoleTeamRbacContext,
      memberId: string,
      request: UpdateConsoleTeamMemberRolesRequest,
    ): Promise<ConsoleTeamMember | null> {
      ensureActorMembership(ctx);
      const store = ensureOrgStore(ctx.orgId);
      const member = store.members.get(memberId);
      if (!member) return null;
      if (member.status === 'REMOVED') {
        throw new ConsoleTeamRbacError(
          'member_removed',
          409,
          `Member ${memberId} is removed and cannot be mutated`,
        );
      }

      const roles = normalizeRoleAssignments(request.roles);
      if (roles.length === 0) {
        throw new ConsoleTeamRbacError(
          'invalid_body',
          400,
          'At least one role assignment is required',
        );
      }
      if (roles.some((entry) => entry.role === 'owner') && !hasOwnerClaim(ctx)) {
        throw new ConsoleTeamRbacError(
          'forbidden',
          403,
          'Only owner can assign owner role memberships',
        );
      }

      const wasOwner = hasOwnerRole(member);
      const willBeOwner = roles.some((entry) => entry.role === 'owner');
      if (wasOwner && !willBeOwner && member.status === 'ACTIVE' && countActiveOwners(store) <= 1) {
        throw new ConsoleTeamRbacError(
          'last_owner_required',
          409,
          'Cannot remove owner role from the last active owner in the organization',
        );
      }

      if (String(member.userId || '').trim() === String(ctx.actorUserId || '').trim()) {
        const actorEmail = resolveActorEmail(ctx);
        const actorDisplayName = resolveActorDisplayName(ctx);
        if (
          actorEmail &&
          (isConsoleLocalEmail(member.email) || !String(member.email || '').trim())
        ) {
          member.email = actorEmail;
        }
        if (
          actorDisplayName &&
          (!String(member.displayName || '').trim() ||
            String(member.displayName || '').trim() === String(ctx.actorUserId || '').trim())
        ) {
          member.displayName = actorDisplayName;
        }
      }
      member.roles = roles;
      member.updatedAt = toIso(now());
      return cloneMember(member);
    },

    async removeMember(
      ctx: ConsoleTeamRbacContext,
      memberId: string,
    ): Promise<{ removed: boolean; member: ConsoleTeamMember | null }> {
      ensureActorMembership(ctx);
      const store = ensureOrgStore(ctx.orgId);
      const member = store.members.get(memberId);
      if (!member) return { removed: false, member: null };
      if (member.status === 'REMOVED') {
        return { removed: true, member: cloneMember(member) };
      }
      if (hasOwnerRole(member) && member.status === 'ACTIVE' && countActiveOwners(store) <= 1) {
        throw new ConsoleTeamRbacError(
          'last_owner_required',
          409,
          'Cannot remove the last active owner in the organization',
        );
      }

      const ts = toIso(now());
      member.status = 'REMOVED';
      member.roles = [];
      member.updatedAt = ts;
      member.lastStatusChangedAt = ts;
      return { removed: true, member: cloneMember(member) };
    },
  };
}
