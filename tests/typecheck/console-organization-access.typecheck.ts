import type {
  ChangeOrganizationMembershipRoleRequest,
  OrganizationInvitation,
  OrganizationMembership,
} from '../../packages/console-server-ts/src/teamRbac/types';

declare const membershipIdentity: {
  readonly id: string;
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly displayName: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
};

const ownerRole: ChangeOrganizationMembershipRoleRequest = {
  role: 'OWNER',
};
void ownerRole;

const memberRole: ChangeOrganizationMembershipRoleRequest = {
  role: 'MEMBER',
  projectAccess: [],
};
void memberRole;

const ownerWithPermissions: ChangeOrganizationMembershipRoleRequest = {
  role: 'OWNER',
  // @ts-expect-error Owners cannot carry administrator permission state.
  adminPermissions: ['members.manage'],
};
void ownerWithPermissions;

// @ts-expect-error Member role changes require explicit project access.
const memberWithoutProjectAccess: ChangeOrganizationMembershipRoleRequest = {
  role: 'MEMBER',
};
void memberWithoutProjectAccess;

// @ts-expect-error Owners cannot enter the suspended lifecycle branch.
const suspendedOwner: OrganizationMembership = {
  ...membershipIdentity,
  kind: 'suspended',
  role: 'OWNER',
  suspendedAt: '2026-07-26T00:00:00.000Z',
};
void suspendedOwner;

// @ts-expect-error Accepted invitations require the created membership identity.
const acceptedInvitationWithoutMembership: OrganizationInvitation = {
  id: 'invitation',
  orgId: 'organization',
  email: 'member@example.com',
  invitedByUserId: 'owner',
  createdAt: '2026-07-26T00:00:00.000Z',
  updatedAt: '2026-07-26T00:00:00.000Z',
  role: 'MEMBER',
  projectAccess: [],
  kind: 'accepted',
  acceptedAt: '2026-07-26T00:00:00.000Z',
};
void acceptedInvitationWithoutMembership;
