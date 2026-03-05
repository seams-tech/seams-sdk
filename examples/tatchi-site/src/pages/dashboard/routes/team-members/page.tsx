import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
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
    category: 'integrations',
    label: 'Integrations',
    readRole: 'integrations_read',
    writeRole: 'integrations_write',
  },
  {
    category: 'billing',
    label: 'Billing',
    readRole: 'billing_read',
    writeRole: 'billing_write',
  },
];

const DEFAULT_CATEGORY_ACCESS: TeamCategoryAccessMap = {
  overview: 'READ',
  administration: 'NONE',
  wallet_operations: 'READ',
  integrations: 'NONE',
  billing: 'NONE',
};

function makeDefaultCategoryAccess(): TeamCategoryAccessMap {
  return { ...DEFAULT_CATEGORY_ACCESS };
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

function TeamPermissionEditor(props: TeamPermissionEditorProps): React.JSX.Element {
  return (
    <>
      <div className="dashboard-view-grid dashboard-view-grid--two">
        <label className="dashboard-form-field">
          <span>Admin member</span>
          <input
            type="checkbox"
            checked={props.isAdmin}
            onChange={(event) => props.onIsAdminChange(event.target.checked)}
            disabled={props.disabled || props.ownerRolePresent}
          />
        </label>
        <label className="dashboard-form-field">
          <span>Can add/remove admins</span>
          <input
            type="checkbox"
            checked={props.canManageAdmins}
            onChange={(event) => props.onCanManageAdminsChange(event.target.checked)}
            disabled={props.disabled || props.ownerRolePresent}
          />
        </label>
        <label className="dashboard-form-field">
          <span>Can add/remove team members</span>
          <input
            type="checkbox"
            checked={props.canManageMembers}
            onChange={(event) => props.onCanManageMembersChange(event.target.checked)}
            disabled={props.disabled || props.ownerRolePresent}
          />
        </label>
      </div>

      <p>Sidebar category access levels</p>
      <div className="dashboard-view-grid dashboard-view-grid--two">
        {TEAM_PERMISSION_CATEGORIES.map((category) => (
          <label className="dashboard-form-field" key={category.category}>
            <span>{category.label}</span>
            <select
              className="dashboard-input"
              value={props.categoryAccess[category.category]}
              onChange={(event) =>
                props.onCategoryAccessChange(
                  category.category,
                  event.target.value as TeamPermissionAccessLevel,
                )
              }
              disabled={props.disabled || props.ownerRolePresent}
            >
              <option value="NONE">None</option>
              <option value="READ">Read</option>
              <option value="WRITE">Write</option>
            </select>
          </label>
        ))}
      </div>
      {props.ownerRolePresent ? (
        <p className="dashboard-pagination-note">
          Owner permission is system-managed and preserved automatically.
        </p>
      ) : null}
    </>
  );
}

export function TeamMembersPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();

  const [members, setMembers] = React.useState<DashboardConsoleTeamMember[]>([]);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [statusFilter, setStatusFilter] = React.useState<TeamMemberListStatusFilter>('ALL');
  const [busyUserId, setBusyUserId] = React.useState<string>('');
  const [inviting, setInviting] = React.useState<boolean>(false);
  const [updating, setUpdating] = React.useState<boolean>(false);

  const [inviteUserId, setInviteUserId] = React.useState<string>('');
  const [inviteEmail, setInviteEmail] = React.useState<string>('');
  const [inviteDisplayName, setInviteDisplayName] = React.useState<string>('');
  const [invitePermissions, setInvitePermissions] = React.useState<TeamPermissionEditorState>({
    isAdmin: false,
    canManageAdmins: false,
    canManageMembers: false,
    categoryAccess: makeDefaultCategoryAccess(),
  });

  const [updateUserId, setUpdateUserId] = React.useState<string>('');
  const [updatePermissions, setUpdatePermissions] = React.useState<TeamPermissionEditorState>({
    isAdmin: false,
    canManageAdmins: false,
    canManageMembers: false,
    categoryAccess: makeDefaultCategoryAccess(),
  });

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

  const orderedMembers = React.useMemo(
    () => [...members].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)),
    [members],
  );

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
      const userId = String(inviteUserId || '').trim();
      if (!email) {
        setMutationError('Email is required.');
        return;
      }
      if (!userId) {
        setMutationError('User ID is required.');
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
        const created = await inviteDashboardTeamMember({
          userId,
          ...(inviteDisplayName.trim() ? { displayName: inviteDisplayName.trim() } : {}),
          email,
          roles,
        });
        setInviteUserId('');
        setInviteEmail('');
        setInviteDisplayName('');
        setInvitePermissions({
          isAdmin: false,
          canManageAdmins: false,
          canManageMembers: false,
          categoryAccess: makeDefaultCategoryAccess(),
        });
        setUpdateUserId(created.userId);
        setUpdatePermissions(resolvePermissionEditorState(created.roles));
        loadMembers();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setInviting(false);
      }
    },
    [
      canMutateTeam,
      inviteDisplayName,
      inviteEmail,
      invitePermissions,
      inviteUserId,
      loadMembers,
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
      const userId = String(updateUserId || '').trim();
      if (!userId) {
        setMutationError('User ID is required for permission updates.');
        return;
      }
      const targetMember = members.find((entry) => String(entry.userId).trim() === userId);
      if (!targetMember) {
        setMutationError(`Member with user ID ${userId} was not found in the current list.`);
        return;
      }
      setUpdating(true);
      setMutationError('');
      try {
        const roles = buildRoleAssignments({
          permissions: updatePermissions,
          preserveOwnerRole: targetMember.roles.some((entry) => entry.role === 'owner'),
        });
        if (roles.length === 0) {
          throw new Error('At least one permission is required.');
        }
        await updateDashboardTeamMemberRoles({ memberId: targetMember.id, roles });
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
      members,
      session.claims,
      session.errorMessage,
      updatePermissions,
      updateUserId,
    ],
  );

  const onSelectMember = React.useCallback((member: DashboardConsoleTeamMember) => {
    setUpdateUserId(member.userId);
    setUpdatePermissions(resolvePermissionEditorState(member.roles));
  }, []);

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
      setBusyUserId(member.userId);
      setMutationError('');
      try {
        await removeDashboardTeamMember({ memberId: member.id });
        if (updateUserId === member.userId) {
          setUpdateUserId('');
          setUpdatePermissions({
            isAdmin: false,
            canManageAdmins: false,
            canManageMembers: false,
            categoryAccess: makeDefaultCategoryAccess(),
          });
        }
        loadMembers();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyUserId('');
      }
    },
    [canMutateTeam, loadMembers, session.claims, session.errorMessage, updateUserId],
  );

  const selectedMember = React.useMemo(
    () =>
      members.find(
        (entry) => String(entry.userId || '').trim() === String(updateUserId || '').trim(),
      ) || null,
    [members, updateUserId],
  );

  return (
    <div className="dashboard-view" aria-label="Team members and roles page">
      <section className="dashboard-view__section" aria-label="Invite member section">
        <h2>Invite member</h2>
        <p>
          {canMutateTeam
            ? 'Owner/admin role enabled for invite, permission update, and remove actions.'
            : 'Only owner/admin can mutate team membership. You currently have read-only access.'}
        </p>
        <p>Use admin controls plus per-category read/write access levels.</p>
        <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onInviteMember}>
          <label className="dashboard-form-field">
            <span>User ID</span>
            <input
              className="dashboard-input"
              value={inviteUserId}
              onChange={(event) => setInviteUserId(event.target.value)}
              placeholder="user_abc123"
            />
          </label>
          <label className="dashboard-form-field">
            <span>Email</span>
            <input
              className="dashboard-input"
              value={inviteEmail}
              onChange={(event) => setInviteEmail(event.target.value)}
              placeholder="member@example.com"
            />
          </label>
          <label className="dashboard-form-field">
            <span>Display name (optional)</span>
            <input
              className="dashboard-input"
              value={inviteDisplayName}
              onChange={(event) => setInviteDisplayName(event.target.value)}
              placeholder="Jane Doe"
            />
          </label>
          <div />
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
          <div className="dashboard-form-actions">
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

      <section className="dashboard-view__section" aria-label="Update member roles section">
        <h2>Update member permissions</h2>
        <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onApplyRoles}>
          <label className="dashboard-form-field">
            <span>User ID</span>
            <input
              className="dashboard-input"
              value={updateUserId}
              onChange={(event) => setUpdateUserId(event.target.value)}
              placeholder="user_abc123"
            />
          </label>
          <div />
          <TeamPermissionEditor
            isAdmin={updatePermissions.isAdmin}
            canManageAdmins={updatePermissions.canManageAdmins}
            canManageMembers={updatePermissions.canManageMembers}
            categoryAccess={updatePermissions.categoryAccess}
            ownerRolePresent={Boolean(
              selectedMember?.roles.some((entry) => entry.role === 'owner'),
            )}
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
          <div className="dashboard-form-actions">
            <button
              type="submit"
              className="dashboard-pagination-button"
              disabled={updating || !canMutateTeam}
            >
              {updating ? 'Applying...' : 'Apply permissions'}
            </button>
          </div>
        </form>
        {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
      </section>

      <section className="dashboard-view__section" aria-label="Team member filters section">
        <h2>Member filters</h2>
        <div className="dashboard-view-grid dashboard-view-grid--two">
          <label className="dashboard-form-field">
            <span>Status</span>
            <select
              className="dashboard-input"
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(event.target.value as TeamMemberListStatusFilter)
              }
            >
              <option value="ALL">ALL</option>
              <option value="INVITED">INVITED</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="SUSPENDED">SUSPENDED</option>
              <option value="REMOVED">REMOVED</option>
            </select>
          </label>
        </div>
      </section>

      <section className="dashboard-table-wrapper" aria-label="Team members table">
        <div className="dashboard-table-header" role="row">
          <span>Member</span>
          <span>Status</span>
          <span>Permissions</span>
          <span>Invited by</span>
          <span>Updated</span>
          <span>Actions</span>
        </div>
        {session.loading || loading ? (
          <p className="dashboard-table-limit">Loading team members...</p>
        ) : !session.claims ? (
          <p className="dashboard-table-limit">
            Team members unavailable: {session.errorMessage || 'unauthorized'}.
          </p>
        ) : errorMessage ? (
          <p className="dashboard-table-limit">Team members unavailable: {errorMessage}</p>
        ) : orderedMembers.length === 0 ? (
          <p className="dashboard-table-limit">No members found for selected filter.</p>
        ) : (
          <>
            {orderedMembers.map((member) => (
              <div className="dashboard-table-row" key={member.id} role="row">
                <span title={member.id}>
                  {member.displayName || member.email}
                  <br />
                  <small>{member.email}</small>
                  <br />
                  <small>{member.userId}</small>
                </span>
                <span>{member.status}</span>
                <span title={formatPermissionSummary(member.roles)}>
                  {formatPermissionSummary(member.roles)}
                </span>
                <span title={member.invitedByUserId || '-'}>{member.invitedByUserId || '-'}</span>
                <span>{formatTimestamp(member.updatedAt || member.createdAt)}</span>
                <span>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => onSelectMember(member)}
                  >
                    Edit permissions
                  </button>
                  <button
                    type="button"
                    className="dashboard-inline-link dashboard-inline-link--danger"
                    onClick={() => onRemoveMember(member)}
                    disabled={
                      !canMutateTeam || busyUserId === member.userId || member.status === 'REMOVED'
                    }
                  >
                    {busyUserId === member.userId ? 'Removing...' : 'Remove'}
                  </button>
                </span>
              </div>
            ))}
          </>
        )}
      </section>
    </div>
  );
}
