import React from 'react';
import { createPortal } from 'react-dom';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import {
  useDashboardConsoleSession,
  type DashboardConsoleSessionClaims,
} from '../../consoleSession';
import {
  inviteDashboardTeamMember,
  listDashboardTeamMembers,
  removeDashboardTeamMember,
  updateDashboardTeamMemberRoles,
  type DashboardConsoleTeamMember,
  type DashboardConsoleTeamMembershipStatus,
  type DashboardConsoleTeamPermissionCategory,
  type DashboardConsoleTeamRole,
  type DashboardConsoleTeamRoleAssignment,
} from './consoleTeamRbacApi';

type TeamMemberListStatusFilter = DashboardConsoleTeamMembershipStatus | 'ALL';
type TeamMemberPermissionFilter =
  | 'ALL'
  | 'OWNER'
  | 'ADMIN'
  | 'MANAGE_ADMINS'
  | 'MANAGE_MEMBERS'
  | DashboardConsoleTeamPermissionCategory;
type TeamPermissionAccessLevel = 'NONE' | 'READ' | 'WRITE';
type TeamCategoryAccessMap = Record<
  DashboardConsoleTeamPermissionCategory,
  TeamPermissionAccessLevel
>;

interface TeamPermissionEditorState {
  isAdmin: boolean;
  canManageAdmins: boolean;
  canManageMembers: boolean;
  categoryAccess: TeamCategoryAccessMap;
}

interface TeamPermissionCategoryConfig {
  category: DashboardConsoleTeamPermissionCategory;
  label: string;
  readRole: DashboardConsoleTeamRole;
  writeRole: DashboardConsoleTeamRole;
}

interface TeamPermissionFilterOption {
  value: TeamMemberPermissionFilter;
  label: string;
}

interface TeamPermissionEditorProps extends TeamPermissionEditorState {
  disabled: boolean;
  ownerRolePresent: boolean;
  onIsAdminChange(next: boolean): void;
  onCanManageAdminsChange(next: boolean): void;
  onCanManageMembersChange(next: boolean): void;
  onCategoryAccessChange(
    category: DashboardConsoleTeamPermissionCategory,
    level: TeamPermissionAccessLevel,
  ): void;
}

const TEAM_PERMISSION_CATEGORIES: TeamPermissionCategoryConfig[] = [
  {
    category: 'overview',
    label: 'Overview',
    readRole: 'overview_read',
    writeRole: 'overview_write',
  },
  {
    category: 'administration',
    label: 'Administration',
    readRole: 'administration_read',
    writeRole: 'administration_write',
  },
  {
    category: 'wallet_operations',
    label: 'Wallet operations',
    readRole: 'wallet_operations_read',
    writeRole: 'wallet_operations_write',
  },
  {
    category: 'billing',
    label: 'Billing',
    readRole: 'billing_read',
    writeRole: 'billing_write',
  },
  {
    category: 'integrations',
    label: 'Integrations',
    readRole: 'integrations_read',
    writeRole: 'integrations_write',
  },
];

const DEFAULT_CATEGORY_ACCESS: TeamCategoryAccessMap = {
  overview: 'READ',
  administration: 'NONE',
  wallet_operations: 'READ',
  integrations: 'NONE',
  billing: 'NONE',
};
const TEAM_PERMISSION_FILTER_OPTIONS: TeamPermissionFilterOption[] = [
  { value: 'ALL', label: 'Permission: All' },
  { value: 'OWNER', label: 'Permission: Owner' },
  { value: 'ADMIN', label: 'Permission: Admin' },
  { value: 'MANAGE_ADMINS', label: 'Permission: Manage admins' },
  { value: 'MANAGE_MEMBERS', label: 'Permission: Manage team members' },
  ...TEAM_PERMISSION_CATEGORIES.map((category) => ({
    value: category.category,
    label: `Permission: ${category.label}`,
  })),
];
const TEAM_MEMBERS_TABLE_COLUMNS = dashboardTableColumns(1.35, 0.8, 1.5, 0.85, 1.2);

function makeDefaultCategoryAccess(): TeamCategoryAccessMap {
  return { ...DEFAULT_CATEGORY_ACCESS };
}

function makeDefaultPermissionEditorState(): TeamPermissionEditorState {
  return {
    isAdmin: false,
    canManageAdmins: false,
    canManageMembers: false,
    categoryAccess: makeDefaultCategoryAccess(),
  };
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function roleSetFromAssignments(
  input: DashboardConsoleTeamRoleAssignment[],
): Set<DashboardConsoleTeamRole> {
  const out = new Set<DashboardConsoleTeamRole>();
  for (const entry of input) {
    out.add(entry.role);
  }
  return out;
}

function resolvePermissionEditorState(
  input: DashboardConsoleTeamRoleAssignment[],
): TeamPermissionEditorState {
  const roles = roleSetFromAssignments(input);
  const ownerRolePresent = roles.has('owner');
  const categoryAccess = makeDefaultCategoryAccess();
  for (const category of TEAM_PERMISSION_CATEGORIES) {
    if (roles.has(category.writeRole)) {
      categoryAccess[category.category] = 'WRITE';
      continue;
    }
    if (roles.has(category.readRole)) {
      categoryAccess[category.category] = 'READ';
      continue;
    }
    categoryAccess[category.category] = 'NONE';
  }
  return {
    isAdmin: ownerRolePresent || roles.has('admin'),
    canManageAdmins: ownerRolePresent || roles.has('admin_manage_admins'),
    canManageMembers: ownerRolePresent || roles.has('admin_manage_members'),
    categoryAccess,
  };
}

function buildRoleAssignments(input: {
  permissions: TeamPermissionEditorState;
  preserveOwnerRole: boolean;
}): DashboardConsoleTeamRoleAssignment[] {
  const out = new Map<string, DashboardConsoleTeamRoleAssignment>();
  const addRole = (role: DashboardConsoleTeamRole): void => {
    out.set(role, { role, scope: 'ORG' });
  };

  const normalizedIsAdmin =
    input.permissions.isAdmin ||
    input.permissions.canManageAdmins ||
    input.permissions.canManageMembers;

  if (input.preserveOwnerRole) addRole('owner');
  if (normalizedIsAdmin) addRole('admin');
  if (input.permissions.canManageAdmins) addRole('admin_manage_admins');
  if (input.permissions.canManageMembers) addRole('admin_manage_members');

  for (const category of TEAM_PERMISSION_CATEGORIES) {
    const level = input.permissions.categoryAccess[category.category];
    if (level === 'WRITE') {
      addRole(category.writeRole);
      continue;
    }
    if (level === 'READ') {
      addRole(category.readRole);
    }
  }

  return Array.from(out.values()).sort((a, b) => a.role.localeCompare(b.role));
}

function formatPermissionSummary(input: DashboardConsoleTeamRoleAssignment[]): string {
  const state = resolvePermissionEditorState(input);
  const roleSet = roleSetFromAssignments(input);
  const parts: string[] = [];
  if (roleSet.has('owner')) parts.push('Owner');
  if (state.isAdmin) parts.push('Admin');
  if (state.canManageAdmins) parts.push('Manage admins');
  if (state.canManageMembers) parts.push('Manage team members');

  const categoryEntries = TEAM_PERMISSION_CATEGORIES.map((category) => {
    const level = state.categoryAccess[category.category];
    if (level === 'NONE') return '';
    return `${category.label}:${level.toLowerCase()}`;
  }).filter(Boolean);
  if (categoryEntries.length > 0) {
    parts.push(categoryEntries.join(' | '));
  }

  if (parts.length === 0) return 'No permissions';
  return parts.join(' | ');
}

function canMutateTeamFromRoles(rolesRaw: unknown): boolean {
  if (!Array.isArray(rolesRaw)) return false;
  return rolesRaw.some((entry) => {
    const role = String(entry || '')
      .trim()
      .toLowerCase();
    return role === 'owner' || role === 'admin';
  });
}

function isConsoleLocalEmail(value: string): boolean {
  return String(value || '')
    .trim()
    .toLowerCase()
    .endsWith('@console.local');
}

function resolveMemberEmail(
  member: DashboardConsoleTeamMember,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): string {
  const email = String(member.email || '').trim();
  const sessionUserId = String(sessionClaims?.userId || '').trim();
  const sessionEmail = String(sessionClaims?.email || '').trim();
  if (
    sessionUserId &&
    sessionEmail &&
    String(member.userId || '').trim() === sessionUserId &&
    isConsoleLocalEmail(email)
  ) {
    return sessionEmail;
  }
  return email;
}

function resolveMemberDisplayName(
  member: DashboardConsoleTeamMember,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): string {
  const displayName = String(member.displayName || '').trim();
  if (displayName) return displayName;
  const sessionUserId = String(sessionClaims?.userId || '').trim();
  const sessionName = String(sessionClaims?.name || '').trim();
  if (sessionUserId && sessionName && String(member.userId || '').trim() === sessionUserId) {
    return sessionName;
  }
  return '';
}

function matchesMemberQuery(
  member: DashboardConsoleTeamMember,
  queryRaw: string,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): boolean {
  const query = String(queryRaw || '')
    .trim()
    .toLowerCase();
  if (!query) return true;
  const primaryIdentity = formatMemberPrimaryIdentity(member, sessionClaims);
  return [
    resolveMemberDisplayName(member, sessionClaims),
    resolveMemberEmail(member, sessionClaims),
    member.userId,
    primaryIdentity,
    member.status,
    member.invitedByUserId,
    formatPermissionSummary(member.roles),
  ].some((value) =>
    String(value || '')
      .toLowerCase()
      .includes(query),
  );
}

function matchesMemberPermissionFilter(
  member: DashboardConsoleTeamMember,
  filter: TeamMemberPermissionFilter,
): boolean {
  if (filter === 'ALL') return true;
  const state = resolvePermissionEditorState(member.roles);
  const roles = roleSetFromAssignments(member.roles);
  switch (filter) {
    case 'OWNER':
      return roles.has('owner');
    case 'ADMIN':
      return state.isAdmin;
    case 'MANAGE_ADMINS':
      return state.canManageAdmins;
    case 'MANAGE_MEMBERS':
      return state.canManageMembers;
    default:
      return state.categoryAccess[filter] !== 'NONE';
  }
}

function formatMemberPrimaryIdentity(
  member: DashboardConsoleTeamMember,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): string {
  const userId = String(member.userId || '').trim();
  const email = resolveMemberEmail(member, sessionClaims);
  if (!email) return userId || '-';
  if (!userId) return email;
  const normalizedUserId = userId.toLowerCase();
  const normalizedEmail = email.toLowerCase();
  if (
    normalizedEmail === normalizedUserId ||
    normalizedEmail === `${normalizedUserId}@console.local` ||
    normalizedEmail.endsWith('@console.local')
  ) {
    return userId;
  }
  return email;
}

function buildMemberProfile(
  member: DashboardConsoleTeamMember,
  sessionClaims?: DashboardConsoleSessionClaims | null,
): {
  title: string;
  subtitle: string;
  detail: string;
} {
  const displayName = resolveMemberDisplayName(member, sessionClaims);
  const email = resolveMemberEmail(member, sessionClaims);
  const userId = String(member.userId || '').trim();
  const normalizedDisplayName = displayName.toLowerCase();
  const normalizedEmail = email.toLowerCase();
  const normalizedUserId = userId.toLowerCase();
  const title = displayName || email || userId || '-';

  if (!displayName) {
    const nextLine =
      email && email !== title ? email : userId && normalizedUserId !== title.toLowerCase() ? userId : '';
    return {
      title,
      detail: nextLine,
      subtitle: '',
    };
  }

  const detail =
    email && normalizedEmail !== normalizedDisplayName
      ? email
      : userId && normalizedUserId !== normalizedDisplayName
        ? userId
        : '';
  const subtitle =
    userId &&
    normalizedUserId !== normalizedDisplayName &&
    normalizedUserId !== normalizedEmail &&
    userId !== detail
      ? userId
      : '';
  return {
    title,
    detail,
    subtitle,
  };
}

function generateInviteUserId(emailRaw: string): string {
  const email = String(emailRaw || '')
    .trim()
    .toLowerCase();
  const localPart = email.includes('@') ? email.slice(0, email.indexOf('@')) : email;
  const normalized = localPart.replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  if (!normalized) return 'user_member';
  return normalized.startsWith('user_') ? normalized : `user_${normalized}`;
}

function TeamPermissionEditor(props: TeamPermissionEditorProps): React.JSX.Element {
  return (
    <div className="dashboard-team-members-permission-editor dashboard-form-field--full">
      <section className="dashboard-team-members-permission-editor__section">
        <p className="dashboard-team-members-permission-editor__title">Admin controls</p>
        <div className="dashboard-team-members-permission-flags">
          <div className="dashboard-team-members-permission-flag dashboard-team-members-permission-flag--with-description">
            <label className="dashboard-team-members-permission-flag__toggle dashboard-team-members-permission-flag__toggle-card">
              <input
                type="checkbox"
                checked={props.isAdmin}
                onChange={(event) => props.onIsAdminChange(event.target.checked)}
                disabled={props.disabled || props.ownerRolePresent}
              />
              <span className="dashboard-team-members-permission-flag__label">Admin member</span>
            </label>
            <p className="dashboard-team-members-permission-flag__description">
              Allows inviting members, editing member permissions, and removing members.
            </p>
          </div>
          <div className="dashboard-team-members-permission-flag">
            <label className="dashboard-team-members-permission-flag__toggle">
              <input
                type="checkbox"
                checked={props.canManageAdmins}
                onChange={(event) => props.onCanManageAdminsChange(event.target.checked)}
                disabled={props.disabled || props.ownerRolePresent}
              />
              <span className="dashboard-team-members-permission-flag__label">
                Can add/remove admins
              </span>
            </label>
          </div>
          <div className="dashboard-team-members-permission-flag">
            <label className="dashboard-team-members-permission-flag__toggle">
              <input
                type="checkbox"
                checked={props.canManageMembers}
                onChange={(event) => props.onCanManageMembersChange(event.target.checked)}
                disabled={props.disabled || props.ownerRolePresent}
              />
              <span className="dashboard-team-members-permission-flag__label">
                Can add/remove team members
              </span>
            </label>
          </div>
        </div>
      </section>

      <section className="dashboard-team-members-permission-editor__section">
        <p className="dashboard-team-members-permission-editor__title">
          Sidebar Access Permissions
        </p>
        <div className="dashboard-team-members-access-list">
          {TEAM_PERMISSION_CATEGORIES.map((category) => (
            <div className="dashboard-team-members-access-item" key={category.category}>
              <span>{category.label}</span>
              <div
                className="dashboard-team-members-access-segmented"
                role="group"
                aria-label={`${category.label} access level`}
              >
                {(['NONE', 'READ', 'WRITE'] as TeamPermissionAccessLevel[]).map((level) => (
                  <button
                    key={level}
                    type="button"
                    className={[
                      'dashboard-team-members-access-segmented__button',
                      props.categoryAccess[category.category] === level
                        ? 'dashboard-team-members-access-segmented__button--active'
                        : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                    aria-pressed={props.categoryAccess[category.category] === level}
                    onClick={() => props.onCategoryAccessChange(category.category, level)}
                    disabled={props.disabled || props.ownerRolePresent}
                  >
                    {level === 'NONE' ? 'None' : level === 'READ' ? 'Read' : 'Write'}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
        {props.ownerRolePresent ? (
          <p className="dashboard-pagination-note">
            Owner permission is system-managed and preserved automatically.
          </p>
        ) : null}
      </section>
    </div>
  );
}

export function TeamMembersPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const viewRef = React.useRef<HTMLDivElement | null>(null);

  const [members, setMembers] = React.useState<DashboardConsoleTeamMember[]>([]);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [memberQuery, setMemberQuery] = React.useState<string>('');
  const [statusFilter, setStatusFilter] = React.useState<TeamMemberListStatusFilter>('ALL');
  const [permissionFilter, setPermissionFilter] =
    React.useState<TeamMemberPermissionFilter>('ALL');
  const [busyMemberId, setBusyMemberId] = React.useState<string>('');
  const [activeModal, setActiveModal] = React.useState<'invite' | 'update' | null>(null);
  const [inviting, setInviting] = React.useState<boolean>(false);
  const [updating, setUpdating] = React.useState<boolean>(false);
  const [detailMemberId, setDetailMemberId] = React.useState<string>('');

  const [inviteEmail, setInviteEmail] = React.useState<string>('');
  const [inviteDisplayName, setInviteDisplayName] = React.useState<string>('');
  const [invitePermissions, setInvitePermissions] = React.useState<TeamPermissionEditorState>(
    makeDefaultPermissionEditorState(),
  );

  const [editingMemberId, setEditingMemberId] = React.useState<string>('');
  const [updatePermissions, setUpdatePermissions] = React.useState<TeamPermissionEditorState>(
    makeDefaultPermissionEditorState(),
  );
  const [modalHost, setModalHost] = React.useState<HTMLElement | null>(null);

  const canMutateTeam = React.useMemo(
    () => canMutateTeamFromRoles(session.claims?.roles),
    [session.claims?.roles],
  );

  const loadMembers = React.useCallback(() => {
    if (!session.claims) {
      setMembers([]);
      setLoading(false);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    listDashboardTeamMembers(statusFilter === 'ALL' ? {} : { status: statusFilter })
      .then((rows) => {
        if (cancelled) return;
        setMembers(rows);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setMembers([]);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [session.claims, session.errorMessage, statusFilter]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadMembers();
    return cleanup;
  }, [loadMembers, session.loading]);

  React.useEffect(() => {
    setModalHost(viewRef.current?.closest('.dashboard-main') as HTMLElement | null);
  }, []);

  const orderedMembers = React.useMemo(
    () => [...members].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)),
    [members],
  );

  const visibleMembers = React.useMemo(
    () =>
      orderedMembers.filter(
        (member) =>
          matchesMemberQuery(member, memberQuery, session.claims) &&
          matchesMemberPermissionFilter(member, permissionFilter),
      ),
    [memberQuery, orderedMembers, permissionFilter, session.claims],
  );
  const membersPagination = useDashboardTablePagination(visibleMembers, {
    disabled: session.loading || loading,
    itemLabel: 'member',
    itemLabelPlural: 'members',
  });
  const hasClientSideFilters = memberQuery.trim().length > 0 || permissionFilter !== 'ALL';

  const selectedMember = React.useMemo(
    () => members.find((entry) => entry.id === editingMemberId) || null,
    [editingMemberId, members],
  );
  const detailMember = React.useMemo(
    () => members.find((entry) => entry.id === detailMemberId) || null,
    [detailMemberId, members],
  );

  const generatedInviteUserId = React.useMemo(
    () => (inviteEmail.trim() ? generateInviteUserId(inviteEmail) : ''),
    [inviteEmail],
  );
  const detailMemberEmail = detailMember ? resolveMemberEmail(detailMember, session.claims) : '';
  const detailMemberDisplayName = detailMember
    ? resolveMemberDisplayName(detailMember, session.claims)
    : '';

  const resetInviteForm = React.useCallback(() => {
    setInviteEmail('');
    setInviteDisplayName('');
    setInvitePermissions(makeDefaultPermissionEditorState());
  }, []);

  const resetUpdateForm = React.useCallback(() => {
    setEditingMemberId('');
    setUpdatePermissions(makeDefaultPermissionEditorState());
  }, []);

  const resetDetailMember = React.useCallback(() => {
    setDetailMemberId('');
  }, []);

  const onOpenInviteModal = React.useCallback(() => {
    resetInviteForm();
    setMutationError('');
    setActiveModal('invite');
  }, [resetInviteForm]);

  const onOpenUpdateModal = React.useCallback((member: DashboardConsoleTeamMember) => {
    setEditingMemberId(member.id);
    setUpdatePermissions(resolvePermissionEditorState(member.roles));
    setMutationError('');
    setActiveModal('update');
  }, []);

  const onOpenDetailModal = React.useCallback((member: DashboardConsoleTeamMember) => {
    setDetailMemberId(member.id);
    setMutationError('');
  }, []);

  const onCloseModal = React.useCallback(() => {
    if (inviting || updating) return;
    setActiveModal(null);
    setMutationError('');
    resetInviteForm();
    resetUpdateForm();
    resetDetailMember();
  }, [inviting, resetDetailMember, resetInviteForm, resetUpdateForm, updating]);

  const onInviteMember = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateTeam) {
        setMutationError('Only owner/admin role can invite members.');
        return;
      }
      const email = String(inviteEmail || '').trim();
      const userId = generatedInviteUserId;
      if (!email) {
        setMutationError('Email is required.');
        return;
      }
      setInviting(true);
      setMutationError('');
      try {
        const roles = buildRoleAssignments({
          permissions: invitePermissions,
          preserveOwnerRole: false,
        });
        if (roles.length === 0) {
          throw new Error('At least one permission is required.');
        }
        await inviteDashboardTeamMember({
          userId,
          ...(inviteDisplayName.trim() ? { displayName: inviteDisplayName.trim() } : {}),
          email,
          roles,
        });
        resetInviteForm();
        setActiveModal(null);
        loadMembers();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setInviting(false);
      }
    },
    [
      canMutateTeam,
      generatedInviteUserId,
      inviteDisplayName,
      inviteEmail,
      invitePermissions,
      loadMembers,
      resetInviteForm,
      session.claims,
      session.errorMessage,
    ],
  );

  const onApplyRoles = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateTeam) {
        setMutationError('Only owner/admin role can update member permissions.');
        return;
      }
      if (!selectedMember) {
        setMutationError('Select a member from the table before updating permissions.');
        return;
      }
      setUpdating(true);
      setMutationError('');
      try {
        const roles = buildRoleAssignments({
          permissions: updatePermissions,
          preserveOwnerRole: selectedMember.roles.some((entry) => entry.role === 'owner'),
        });
        if (roles.length === 0) {
          throw new Error('At least one permission is required.');
        }
        await updateDashboardTeamMemberRoles({ memberId: selectedMember.id, roles });
        setActiveModal(null);
        resetUpdateForm();
        loadMembers();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setUpdating(false);
      }
    },
    [
      canMutateTeam,
      loadMembers,
      resetUpdateForm,
      session.claims,
      session.errorMessage,
      selectedMember,
      updatePermissions,
    ],
  );

  const onRemoveMember = React.useCallback(
    async (member: DashboardConsoleTeamMember) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateTeam) {
        setMutationError('Only owner/admin role can remove members.');
        return;
      }
      if (!window.confirm(`Remove member ${member.userId}?`)) return;
      setBusyMemberId(member.id);
      setMutationError('');
      try {
        await removeDashboardTeamMember({ memberId: member.id });
        if (editingMemberId === member.id) {
          setActiveModal(null);
          resetUpdateForm();
        }
        loadMembers();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyMemberId('');
      }
    },
    [
      canMutateTeam,
      editingMemberId,
      loadMembers,
      resetUpdateForm,
      session.claims,
      session.errorMessage,
    ],
  );

  const inviteModal =
    activeModal === 'invite' ? (
      <div className="dashboard-inline-modal-backdrop" role="presentation" onClick={onCloseModal}>
        <section
          className="dashboard-modal dashboard-modal--wide"
          role="dialog"
          aria-modal="true"
          aria-label="Add team member modal"
          onClick={(event) => event.stopPropagation()}
        >
          <h2>Invite member</h2>
          <form className="dashboard-view-grid" onSubmit={onInviteMember}>
            <label className="dashboard-form-field">
              <span>Email</span>
              <input
                className="dashboard-input"
                value={inviteEmail}
                onChange={(event) => setInviteEmail(event.target.value)}
                placeholder="member@example.com"
                disabled={inviting || !canMutateTeam}
              />
            </label>
            <label className="dashboard-form-field">
              <span>Display name (optional)</span>
              <input
                className="dashboard-input"
                value={inviteDisplayName}
                onChange={(event) => setInviteDisplayName(event.target.value)}
                placeholder="Jane Doe"
                disabled={inviting || !canMutateTeam}
              />
            </label>
            <TeamPermissionEditor
              isAdmin={invitePermissions.isAdmin}
              canManageAdmins={invitePermissions.canManageAdmins}
              canManageMembers={invitePermissions.canManageMembers}
              categoryAccess={invitePermissions.categoryAccess}
              ownerRolePresent={false}
              disabled={inviting || !canMutateTeam}
              onIsAdminChange={(next) =>
                setInvitePermissions((prev) => ({
                  ...prev,
                  isAdmin: next,
                }))
              }
              onCanManageAdminsChange={(next) =>
                setInvitePermissions((prev) => ({
                  ...prev,
                  canManageAdmins: next,
                }))
              }
              onCanManageMembersChange={(next) =>
                setInvitePermissions((prev) => ({
                  ...prev,
                  canManageMembers: next,
                }))
              }
              onCategoryAccessChange={(category, level) =>
                setInvitePermissions((prev) => ({
                  ...prev,
                  categoryAccess: {
                    ...prev.categoryAccess,
                    [category]: level,
                  },
                }))
              }
            />
            {mutationError ? (
              <p className="dashboard-form-alert" role="alert">
                {mutationError}
              </p>
            ) : null}
            <div className="dashboard-form-actions">
              <button
                type="button"
                className="dashboard-pagination-button dashboard-pagination-button--secondary"
                onClick={onCloseModal}
                disabled={inviting}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="dashboard-pagination-button"
                disabled={inviting || !canMutateTeam}
              >
                {inviting ? 'Inviting...' : 'Invite member'}
              </button>
            </div>
          </form>
        </section>
      </div>
    ) : null;

  const updateModal =
    activeModal === 'update' && selectedMember ? (
      <div className="dashboard-inline-modal-backdrop" role="presentation" onClick={onCloseModal}>
        <section
          className="dashboard-modal dashboard-modal--wide"
          role="dialog"
          aria-modal="true"
          aria-label="Update member permissions modal"
          onClick={(event) => event.stopPropagation()}
        >
          <h2>Update member permissions</h2>
          <p className="dashboard-pagination-note">
            {formatMemberPrimaryIdentity(selectedMember, session.claims)} · {selectedMember.status}
          </p>
          <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onApplyRoles}>
            <label className="dashboard-form-field dashboard-form-field--full">
              <span>User ID</span>
              <input className="dashboard-input" value={selectedMember.userId} disabled />
            </label>
            <TeamPermissionEditor
              isAdmin={updatePermissions.isAdmin}
              canManageAdmins={updatePermissions.canManageAdmins}
              canManageMembers={updatePermissions.canManageMembers}
              categoryAccess={updatePermissions.categoryAccess}
              ownerRolePresent={selectedMember.roles.some((entry) => entry.role === 'owner')}
              disabled={updating || !canMutateTeam}
              onIsAdminChange={(next) =>
                setUpdatePermissions((prev) => ({
                  ...prev,
                  isAdmin: next,
                }))
              }
              onCanManageAdminsChange={(next) =>
                setUpdatePermissions((prev) => ({
                  ...prev,
                  canManageAdmins: next,
                }))
              }
              onCanManageMembersChange={(next) =>
                setUpdatePermissions((prev) => ({
                  ...prev,
                  canManageMembers: next,
                }))
              }
              onCategoryAccessChange={(category, level) =>
                setUpdatePermissions((prev) => ({
                  ...prev,
                  categoryAccess: {
                    ...prev.categoryAccess,
                    [category]: level,
                  },
                }))
              }
            />
            {mutationError ? (
              <p className="dashboard-form-alert" role="alert">
                {mutationError}
              </p>
            ) : null}
            <div className="dashboard-form-actions">
              <button
                type="button"
                className="dashboard-pagination-button dashboard-pagination-button--secondary"
                onClick={onCloseModal}
                disabled={updating}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="dashboard-pagination-button"
                disabled={updating || !canMutateTeam}
              >
                {updating ? 'Applying...' : 'Apply permissions'}
              </button>
            </div>
          </form>
        </section>
      </div>
    ) : null;

  const detailsModal = detailMember ? (
    <div className="dashboard-inline-modal-backdrop" role="presentation" onClick={onCloseModal}>
      <section
        className="dashboard-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Team member details modal"
        onClick={(event) => event.stopPropagation()}
      >
        <h2>Member details</h2>
        <div className="dashboard-team-member-details">
          <div className="dashboard-team-member-details__item">
            <span>Email</span>
            <strong>{detailMemberEmail || '-'}</strong>
          </div>
          <div className="dashboard-team-member-details__item">
            <span>User ID</span>
            <strong>{detailMember.userId || '-'}</strong>
          </div>
          <div className="dashboard-team-member-details__item">
            <span>Display name</span>
            <strong>{detailMemberDisplayName || '-'}</strong>
          </div>
          <div className="dashboard-team-member-details__item">
            <span>Status</span>
            <strong>{detailMember.status}</strong>
          </div>
          <div className="dashboard-team-member-details__item">
            <span>Invited by</span>
            <strong>{detailMember.invitedByUserId || '-'}</strong>
          </div>
          <div className="dashboard-team-member-details__item">
            <span>Invited at</span>
            <strong>{formatTimestamp(detailMember.invitedAt)}</strong>
          </div>
          <div className="dashboard-team-member-details__item">
            <span>Created at</span>
            <strong>{formatTimestamp(detailMember.createdAt)}</strong>
          </div>
          <div className="dashboard-team-member-details__item">
            <span>Updated at</span>
            <strong>{formatTimestamp(detailMember.updatedAt || detailMember.createdAt)}</strong>
          </div>
          <div className="dashboard-team-member-details__item dashboard-team-member-details__item--full">
            <span>Permissions</span>
            <strong>{formatPermissionSummary(detailMember.roles)}</strong>
          </div>
        </div>
        <div className="dashboard-form-actions">
          <button
            type="button"
            className="dashboard-pagination-button dashboard-pagination-button--secondary"
            onClick={onCloseModal}
          >
            Close
          </button>
        </div>
      </section>
    </div>
  ) : null;

  return (
    <div ref={viewRef} className="dashboard-view" aria-label="Team members and roles page">
      <section className="dashboard-view__section" aria-label="Team member controls section">
        <div className="dashboard-section-toolbar dashboard-team-members-toolbar">
          <div className="dashboard-section-toolbar__copy">
            <h2>Team members</h2>
            <p className="dashboard-pagination-note">
              {canMutateTeam
                ? 'Owner/admin role enabled for invite, permission update, and member removal actions.'
                : 'Only owner/admin can mutate team membership. You currently have read-only access.'}
            </p>
          </div>
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={onOpenInviteModal}
            disabled={!canMutateTeam}
          >
            Add Team Member
          </button>
        </div>
        {mutationError && !activeModal ? (
          <p className="dashboard-form-alert" role="alert">
            {mutationError}
          </p>
        ) : null}
      </section>

      <section className="dashboard-view__section" aria-label="Team member filters section">
        <div className="dashboard-filters dashboard-team-members-filters">
          <label className="dashboard-search-control dashboard-search-control--compact dashboard-team-members-search-control">
            <span className="dashboard-search-icon" aria-hidden="true" />
            <input
              type="search"
              aria-label="Search team members"
              placeholder="Search by name, email, user ID, or permission"
              value={memberQuery}
              onChange={(event) => setMemberQuery(event.target.value)}
            />
          </label>
          <label className="dashboard-form-field dashboard-team-members-status-filter">
            <select
              className="dashboard-input"
              aria-label="Filter team members by status"
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(event.target.value as TeamMemberListStatusFilter)
              }
            >
              <option value="ALL">Status: All</option>
              <option value="INVITED">Status: Invited</option>
              <option value="ACTIVE">Status: Active</option>
              <option value="SUSPENDED">Status: Suspended</option>
              <option value="REMOVED">Status: Removed</option>
            </select>
          </label>
          <label className="dashboard-form-field dashboard-team-members-permission-filter">
            <select
              className="dashboard-input"
              aria-label="Filter team members by permission"
              value={permissionFilter}
              onChange={(event) =>
                setPermissionFilter(event.target.value as TeamMemberPermissionFilter)
              }
            >
              {TEAM_PERMISSION_FILTER_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </section>

      <DashboardTable
        ariaLabel="Team members table"
        className="dashboard-team-members-table"
        columns={TEAM_MEMBERS_TABLE_COLUMNS}
        pagination={membersPagination.pagination}
      >
        <DashboardTableHeader className="dashboard-team-members-table__row">
          <DashboardTableHeaderCell>Member</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Permissions</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Updated</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
        </DashboardTableHeader>
        {session.loading || loading ? (
          <DashboardTableState>Loading team members...</DashboardTableState>
        ) : !session.claims ? (
          <DashboardTableState>
            Team members unavailable: {session.errorMessage || 'unauthorized'}.
          </DashboardTableState>
        ) : errorMessage ? (
          <DashboardTableState>Team members unavailable: {errorMessage}</DashboardTableState>
        ) : visibleMembers.length === 0 ? (
          <DashboardTableState>
            {orderedMembers.length === 0
              ? 'No members found for the selected filter.'
              : hasClientSideFilters
                ? 'No members matched the current filters.'
                : 'No members matched the selected filter.'}
          </DashboardTableState>
        ) : (
          <>
            {membersPagination.rows.map((member) => {
              const memberIdentity = formatMemberPrimaryIdentity(member, session.claims);
              const memberProfile = buildMemberProfile(member, session.claims);
              const permissionSummary = formatPermissionSummary(member.roles);
              return (
                <DashboardTableRow className="dashboard-team-members-table__row" key={member.id}>
                  <DashboardTableCell
                    className="dashboard-team-members-table__member"
                    title={memberIdentity}
                  >
                    <span className="dashboard-team-members-table__member-title">
                      {memberProfile.title}
                    </span>
                    {memberProfile.detail ? (
                      <span className="dashboard-team-members-table__member-detail">
                        {memberProfile.detail}
                      </span>
                    ) : null}
                    {memberProfile.subtitle ? (
                      <span className="dashboard-team-members-table__member-subtitle">
                        {memberProfile.subtitle}
                      </span>
                    ) : null}
                  </DashboardTableCell>
                  <DashboardTableCell>{member.status}</DashboardTableCell>
                  <DashboardTableCell
                    className="dashboard-team-members-table__permissions"
                    title={permissionSummary}
                  >
                    {permissionSummary}
                  </DashboardTableCell>
                  <DashboardTableCell truncate>
                    {formatTimestamp(member.updatedAt || member.createdAt)}
                  </DashboardTableCell>
                  <DashboardTableCell>
                    <DashboardTableActionGroup>
                      <DashboardTableActionButton onClick={() => onOpenDetailModal(member)}>
                        Details
                      </DashboardTableActionButton>
                      <DashboardTableActionButton
                        onClick={() => onOpenUpdateModal(member)}
                        disabled={!canMutateTeam || member.status === 'REMOVED'}
                      >
                        Edit
                      </DashboardTableActionButton>
                      <DashboardTableActionButton
                        tone="danger"
                        onClick={() => onRemoveMember(member)}
                        disabled={
                          !canMutateTeam ||
                          busyMemberId === member.id ||
                          member.status === 'REMOVED'
                        }
                      >
                        {busyMemberId === member.id ? 'Deleting...' : 'Delete'}
                      </DashboardTableActionButton>
                    </DashboardTableActionGroup>
                  </DashboardTableCell>
                </DashboardTableRow>
              );
            })}
          </>
        )}
      </DashboardTable>
      {modalHost ? createPortal(inviteModal, modalHost) : inviteModal}
      {modalHost ? createPortal(updateModal, modalHost) : updateModal}
      {modalHost ? createPortal(detailsModal, modalHost) : detailsModal}
    </div>
  );
}
