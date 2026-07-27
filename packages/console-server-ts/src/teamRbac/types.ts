export const ORGANIZATION_MEMBERSHIP_ROLES = ['OWNER', 'ADMIN', 'MEMBER'] as const;

export const ORGANIZATION_ADMIN_PERMISSIONS = [
  'members.manage',
  'projects.manage',
  'billing.view',
  'billing.manage',
] as const;

export const PROJECT_ACCESS_LEVELS = ['viewer', 'editor'] as const;

export const ORGANIZATION_MEMBERSHIP_KINDS = ['active', 'suspended', 'removed'] as const;

export const ORGANIZATION_INVITATION_KINDS = [
  'pending',
  'accepted',
  'declined',
  'revoked',
  'expired',
] as const;

export type OrganizationMembershipRole = (typeof ORGANIZATION_MEMBERSHIP_ROLES)[number];
export type OrganizationAdminPermission = (typeof ORGANIZATION_ADMIN_PERMISSIONS)[number];
export type ProjectAccessLevel = (typeof PROJECT_ACCESS_LEVELS)[number];
export type OrganizationMembershipKind = (typeof ORGANIZATION_MEMBERSHIP_KINDS)[number];
export type OrganizationInvitationKind = (typeof ORGANIZATION_INVITATION_KINDS)[number];

export interface ProjectAccessAssignment {
  readonly projectId: string;
  readonly accessLevel: ProjectAccessLevel;
}

interface OrganizationMembershipIdentity {
  readonly id: string;
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly displayName: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type ActiveOwnerMembership = OrganizationMembershipIdentity & {
  readonly kind: 'active';
  readonly role: 'OWNER';
  readonly suspendedAt?: never;
  readonly removedAt?: never;
};

export type ActiveAdministratorMembership = OrganizationMembershipIdentity & {
  readonly kind: 'active';
  readonly role: 'ADMIN';
  readonly suspendedAt?: never;
  readonly removedAt?: never;
};

export type ActiveMemberMembership = OrganizationMembershipIdentity & {
  readonly kind: 'active';
  readonly role: 'MEMBER';
  readonly suspendedAt?: never;
  readonly removedAt?: never;
};

export type SuspendedAdministratorMembership = OrganizationMembershipIdentity & {
  readonly kind: 'suspended';
  readonly role: 'ADMIN';
  readonly suspendedAt: string;
  readonly removedAt?: never;
};

export type SuspendedMemberMembership = OrganizationMembershipIdentity & {
  readonly kind: 'suspended';
  readonly role: 'MEMBER';
  readonly suspendedAt: string;
  readonly removedAt?: never;
};

export type RemovedAdministratorMembership = OrganizationMembershipIdentity & {
  readonly kind: 'removed';
  readonly role: 'ADMIN';
  readonly removedAt: string;
  readonly suspendedAt?: never;
};

export type RemovedMemberMembership = OrganizationMembershipIdentity & {
  readonly kind: 'removed';
  readonly role: 'MEMBER';
  readonly removedAt: string;
  readonly suspendedAt?: never;
};

export type ActiveOrganizationMembership =
  | ActiveOwnerMembership
  | ActiveAdministratorMembership
  | ActiveMemberMembership;

export type OrganizationMembership =
  | ActiveOrganizationMembership
  | SuspendedAdministratorMembership
  | SuspendedMemberMembership
  | RemovedAdministratorMembership
  | RemovedMemberMembership;

export type OrganizationInvitationGrant =
  | {
      readonly role: 'OWNER';
      readonly adminPermissions?: never;
      readonly projectAccess?: never;
    }
  | {
      readonly role: 'ADMIN';
      readonly adminPermissions: readonly OrganizationAdminPermission[];
      readonly projectAccess?: never;
    }
  | {
      readonly role: 'MEMBER';
      readonly projectAccess: readonly ProjectAccessAssignment[];
      readonly adminPermissions?: never;
    };

interface OrganizationInvitationIdentity {
  readonly id: string;
  readonly orgId: string;
  readonly email: string;
  readonly invitedByUserId: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type PendingOrganizationInvitation = OrganizationInvitationIdentity &
  OrganizationInvitationGrant & {
    readonly kind: 'pending';
    readonly expiresAt: string;
    readonly membershipId?: never;
    readonly acceptedAt?: never;
    readonly declinedAt?: never;
    readonly revokedAt?: never;
    readonly expiredAt?: never;
  };

export type AcceptedOrganizationInvitation = OrganizationInvitationIdentity &
  OrganizationInvitationGrant & {
    readonly kind: 'accepted';
    readonly membershipId: string;
    readonly acceptedAt: string;
    readonly expiresAt?: never;
    readonly declinedAt?: never;
    readonly revokedAt?: never;
    readonly expiredAt?: never;
  };

export type DeclinedOrganizationInvitation = OrganizationInvitationIdentity &
  OrganizationInvitationGrant & {
    readonly kind: 'declined';
    readonly declinedAt: string;
    readonly expiresAt?: never;
    readonly membershipId?: never;
    readonly acceptedAt?: never;
    readonly revokedAt?: never;
    readonly expiredAt?: never;
  };

export type RevokedOrganizationInvitation = OrganizationInvitationIdentity &
  OrganizationInvitationGrant & {
    readonly kind: 'revoked';
    readonly revokedAt: string;
    readonly expiresAt?: never;
    readonly membershipId?: never;
    readonly acceptedAt?: never;
    readonly declinedAt?: never;
    readonly expiredAt?: never;
  };

export type ExpiredOrganizationInvitation = OrganizationInvitationIdentity &
  OrganizationInvitationGrant & {
    readonly kind: 'expired';
    readonly expiredAt: string;
    readonly expiresAt?: never;
    readonly membershipId?: never;
    readonly acceptedAt?: never;
    readonly declinedAt?: never;
    readonly revokedAt?: never;
  };

export type OrganizationInvitation =
  | PendingOrganizationInvitation
  | AcceptedOrganizationInvitation
  | DeclinedOrganizationInvitation
  | RevokedOrganizationInvitation
  | ExpiredOrganizationInvitation;

export interface IssuedOrganizationInvitation {
  readonly invitation: PendingOrganizationInvitation;
  readonly token: string;
}

export interface OrganizationMembershipWithAccess {
  readonly membership: OrganizationMembership;
  readonly adminPermissions: readonly OrganizationAdminPermission[];
  readonly projectAccess: readonly ProjectAccessAssignment[];
}

export interface OrganizationOwnerEvent {
  readonly id: string;
  readonly orgId: string;
  readonly membershipId: string;
  readonly ownerUserId: string;
  readonly actorUserId: string;
  readonly kind: 'OWNER_ADDED' | 'OWNER_REMOVED';
  readonly createdAt: string;
}

export type OrganizationAuthorization =
  | {
      readonly kind: 'authorized';
      readonly orgId: string;
      readonly userId: string;
      readonly membershipId: string;
      readonly role: 'OWNER';
      readonly authorizationVersion: number;
      readonly adminPermissions: readonly OrganizationAdminPermission[];
      readonly projectAccess: { readonly kind: 'all' };
    }
  | {
      readonly kind: 'authorized';
      readonly orgId: string;
      readonly userId: string;
      readonly membershipId: string;
      readonly role: 'ADMIN';
      readonly authorizationVersion: number;
      readonly adminPermissions: readonly OrganizationAdminPermission[];
      readonly projectAccess: { readonly kind: 'all' };
    }
  | {
      readonly kind: 'authorized';
      readonly orgId: string;
      readonly userId: string;
      readonly membershipId: string;
      readonly role: 'MEMBER';
      readonly authorizationVersion: number;
      readonly adminPermissions: readonly [];
      readonly projectAccess: {
        readonly kind: 'assigned';
        readonly assignments: readonly ProjectAccessAssignment[];
      };
    }
  | {
      readonly kind: 'denied';
      readonly orgId: string;
      readonly userId: string;
      readonly authorizationVersion: number;
      readonly reason: 'membership_not_found' | 'membership_suspended' | 'membership_removed';
      readonly membershipId: string | null;
      readonly role?: never;
      readonly adminPermissions?: never;
      readonly projectAccess?: never;
    };

export type ActiveOrganizationAuthorization = Extract<
  OrganizationAuthorization,
  { readonly kind: 'authorized' }
>;

export interface ListOrganizationMembershipsRequest {
  readonly kind: OrganizationMembershipKind | 'all';
}

export interface ListOrganizationInvitationsRequest {
  readonly kind: OrganizationInvitationKind | 'all';
}

export type InviteOrganizationMemberRequest = {
  readonly email: string;
} & OrganizationInvitationGrant;

export type ChangeOrganizationMembershipRoleRequest = OrganizationInvitationGrant;

export interface SetOrganizationAdminPermissionsRequest {
  readonly permissions: readonly OrganizationAdminPermission[];
}

export interface SetProjectMemberAccessRequest {
  readonly accessLevel: ProjectAccessLevel;
}

export interface RedeemOrganizationInvitationRequest {
  readonly token: string;
}
