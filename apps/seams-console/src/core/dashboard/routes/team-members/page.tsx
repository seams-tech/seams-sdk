import React from 'react';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableActionMenu,
  DashboardTableBadge,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  DashboardTableStatus,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import { dashboardStatusLabel, dashboardStatusTone } from '../../utils/statusTone';
import { DashboardInlineModal } from '../../components/DashboardInlineModal';
import { DashboardPageActions } from '../../components/DashboardPageActions';
import { listDashboardProjects, type DashboardConsoleProject } from '../../consoleContextApi';
import { useDashboardConsoleSession } from '../../consoleSession';
import { formatDashboardTimestamp } from '../../utils/timestamps';
import {
  changeDashboardOrganizationMembershipRole,
  DASHBOARD_ORGANIZATION_ADMIN_PERMISSIONS,
  inviteDashboardOrganizationMember,
  listDashboardOrganizationInvitations,
  listDashboardOrganizationMemberships,
  reactivateDashboardOrganizationMembership,
  removeDashboardProjectMemberAccess,
  removeDashboardOrganizationMembership,
  resendDashboardOrganizationInvitation,
  revokeDashboardOrganizationInvitation,
  setDashboardOrganizationAdminPermissions,
  setDashboardProjectMemberAccess,
  suspendDashboardOrganizationMembership,
  type DashboardOrganizationAdminPermission,
  type DashboardOrganizationGrant,
  type DashboardOrganizationInvitation,
  type DashboardOrganizationMembership,
  type DashboardOrganizationRole,
  type DashboardProjectAccessAssignment,
  type DashboardProjectAccessLevel,
} from './consoleTeamRbacApi';

const MEMBERSHIP_COLUMNS = dashboardTableColumns(2, 1.25, 0.8, 1.05);
const INVITATION_COLUMNS = dashboardTableColumns(2, 1.2, 0.9, 1.05);

interface GrantEditorProps {
  grant: DashboardOrganizationGrant;
  projects: DashboardConsoleProject[];
  allowPrivilegedRoles: boolean;
  disabled: boolean;
  onChange(grant: DashboardOrganizationGrant): void;
}

function defaultGrant(): DashboardOrganizationGrant {
  return { role: 'MEMBER', projectAccess: [] };
}

function grantFromMembership(
  membership: DashboardOrganizationMembership,
): DashboardOrganizationGrant {
  switch (membership.role) {
    case 'OWNER':
      return { role: membership.role };
    case 'ADMIN':
      return {
        role: membership.role,
        adminPermissions: [...membership.adminPermissions],
      };
    case 'MEMBER':
      return {
        role: membership.role,
        projectAccess: membership.projectAccess.map((assignment) => ({ ...assignment })),
      };
  }
}

function grantForRole(role: DashboardOrganizationRole): DashboardOrganizationGrant {
  switch (role) {
    case 'OWNER':
      return { role };
    case 'ADMIN':
      return { role, adminPermissions: [] };
    case 'MEMBER':
      return { role, projectAccess: [] };
  }
}

function toggleAdminPermission(
  grant: Extract<DashboardOrganizationGrant, { role: 'ADMIN' }>,
  permission: DashboardOrganizationAdminPermission,
  checked: boolean,
): DashboardOrganizationGrant {
  const permissions = new Set(grant.adminPermissions);
  if (checked) permissions.add(permission);
  else permissions.delete(permission);
  if (permissions.has('billing.manage')) permissions.add('billing.view');
  if (permission === 'billing.view' && !checked) permissions.delete('billing.manage');
  return {
    role: grant.role,
    adminPermissions: DASHBOARD_ORGANIZATION_ADMIN_PERMISSIONS.filter((entry) =>
      permissions.has(entry),
    ),
  };
}

function updateProjectAccess(
  grant: Extract<DashboardOrganizationGrant, { role: 'MEMBER' }>,
  projectId: string,
  accessLevel: DashboardProjectAccessLevel | 'none',
): DashboardOrganizationGrant {
  const assignments = new Map<string, DashboardProjectAccessAssignment>();
  for (const assignment of grant.projectAccess) {
    assignments.set(assignment.projectId, assignment);
  }
  if (accessLevel === 'none') assignments.delete(projectId);
  else assignments.set(projectId, { projectId, accessLevel });
  return {
    role: grant.role,
    projectAccess: Array.from(assignments.values()).sort((left, right) =>
      left.projectId.localeCompare(right.projectId),
    ),
  };
}

function projectAccessLevel(
  assignments: DashboardProjectAccessAssignment[],
  projectId: string,
): DashboardProjectAccessLevel | 'none' {
  return (
    assignments.find((assignment) => assignment.projectId === projectId)?.accessLevel ?? 'none'
  );
}

function permissionLabel(permission: DashboardOrganizationAdminPermission): string {
  switch (permission) {
    case 'members.manage':
      return 'Manage members';
    case 'projects.manage':
      return 'Manage projects';
    case 'billing.view':
      return 'View billing';
    case 'billing.manage':
      return 'Manage billing';
  }
}

function roleSummary(membership: DashboardOrganizationMembership): string {
  if (membership.role === 'OWNER') return 'Full organization access';
  if (membership.role === 'ADMIN') {
    if (membership.adminPermissions.length === 0) return 'Read-only administrator';
    return membership.adminPermissions.map(permissionLabel).join(', ');
  }
  if (membership.projectAccess.length === 0) return 'No project access';
  return `${membership.projectAccess.length} project${
    membership.projectAccess.length === 1 ? '' : 's'
  }`;
}

function invitationSummary(invitation: DashboardOrganizationInvitation): string {
  if (invitation.role === 'OWNER') return 'Full organization access';
  if (invitation.role === 'ADMIN') {
    return invitation.adminPermissions.length
      ? invitation.adminPermissions.map(permissionLabel).join(', ')
      : 'Read-only administrator';
  }
  return `${invitation.projectAccess.length} project${
    invitation.projectAccess.length === 1 ? '' : 's'
  }`;
}

function membershipMatchesQuery(
  membership: DashboardOrganizationMembership,
  queryRaw: string,
): boolean {
  const query = queryRaw.trim().toLowerCase();
  if (!query) return true;
  return [
    membership.email,
    membership.displayName,
    membership.userId,
    membership.role,
    membership.kind,
    roleSummary(membership),
  ].some((value) =>
    String(value ?? '')
      .toLowerCase()
      .includes(query),
  );
}

function roleFromSelect(value: string): DashboardOrganizationRole {
  if (value === 'OWNER' || value === 'ADMIN') return value;
  return 'MEMBER';
}

function GrantEditor(props: GrantEditorProps): React.JSX.Element {
  const adminGrant = props.grant.role === 'ADMIN' ? props.grant : null;
  const memberGrant = props.grant.role === 'MEMBER' ? props.grant : null;
  const onRoleChange = React.useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>) => {
      props.onChange(grantForRole(roleFromSelect(event.target.value)));
    },
    [props],
  );

  return (
    <div className="dashboard-team-members-permission-editor dashboard-form-field--full">
      <label className="dashboard-form-field">
        <span>Organization role</span>
        <select
          className="dashboard-input"
          value={props.grant.role}
          onChange={onRoleChange}
          disabled={props.disabled}
        >
          <option value="MEMBER">Member</option>
          {props.allowPrivilegedRoles ? <option value="ADMIN">Administrator</option> : null}
          {props.allowPrivilegedRoles ? <option value="OWNER">Owner</option> : null}
        </select>
      </label>

      {props.grant.role === 'OWNER' ? (
        <p className="dashboard-pagination-note">
          Owners have full organization, project, member, and billing access.
        </p>
      ) : null}

      {adminGrant ? (
        <section className="dashboard-team-members-permission-editor__section">
          <p className="dashboard-team-members-permission-editor__title">
            Administrator permissions
          </p>
          <div className="dashboard-team-members-permission-flags">
            {DASHBOARD_ORGANIZATION_ADMIN_PERMISSIONS.map((permission) => (
              <label className="dashboard-team-members-permission-flag__toggle" key={permission}>
                <input
                  type="checkbox"
                  checked={adminGrant.adminPermissions.includes(permission)}
                  onChange={(event) =>
                    props.onChange(
                      toggleAdminPermission(adminGrant, permission, event.target.checked),
                    )
                  }
                  disabled={
                    props.disabled ||
                    (permission === 'billing.view' &&
                      adminGrant.adminPermissions.includes('billing.manage'))
                  }
                />
                <span className="dashboard-team-members-permission-flag__label">
                  {permissionLabel(permission)}
                </span>
              </label>
            ))}
          </div>
        </section>
      ) : null}

      {memberGrant ? (
        <section className="dashboard-team-members-permission-editor__section">
          <p className="dashboard-team-members-permission-editor__title">Project access</p>
          {props.projects.length === 0 ? (
            <p className="dashboard-pagination-note">No active projects are available.</p>
          ) : (
            <div className="dashboard-team-members-access-list">
              {props.projects.map((project) => (
                <label className="dashboard-team-members-access-item" key={project.id}>
                  <span>{project.name}</span>
                  <select
                    className="dashboard-input"
                    value={projectAccessLevel(memberGrant.projectAccess, project.id)}
                    onChange={(event) =>
                      props.onChange(
                        updateProjectAccess(
                          memberGrant,
                          project.id,
                          event.target.value as DashboardProjectAccessLevel | 'none',
                        ),
                      )
                    }
                    disabled={props.disabled}
                  >
                    <option value="none">No access</option>
                    <option value="viewer">Viewer</option>
                    <option value="editor">Editor</option>
                  </select>
                </label>
              ))}
            </div>
          )}
        </section>
      ) : null}
    </div>
  );
}

export function TeamMembersPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const [memberships, setMemberships] = React.useState<DashboardOrganizationMembership[]>([]);
  const [invitations, setInvitations] = React.useState<DashboardOrganizationInvitation[]>([]);
  const [projects, setProjects] = React.useState<DashboardConsoleProject[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [errorMessage, setErrorMessage] = React.useState('');
  const [mutationError, setMutationError] = React.useState('');
  const [notice, setNotice] = React.useState('');
  const [query, setQuery] = React.useState('');
  const [busyId, setBusyId] = React.useState('');
  const [modal, setModal] = React.useState<'invite' | 'edit' | null>(null);
  const [inviteEmail, setInviteEmail] = React.useState('');
  const [inviteGrant, setInviteGrant] = React.useState<DashboardOrganizationGrant>(defaultGrant);
  const [editingMembershipId, setEditingMembershipId] = React.useState('');
  const [editingGrant, setEditingGrant] = React.useState<DashboardOrganizationGrant>(defaultGrant);

  const role = session.claims?.role;
  const adminPermissions = session.claims?.adminPermissions ?? [];
  const isOwner = role === 'OWNER';
  const canManageMembers =
    isOwner || (role === 'ADMIN' && adminPermissions.includes('members.manage'));
  const canManageProjects =
    isOwner || (role === 'ADMIN' && adminPermissions.includes('projects.manage'));
  const canOpenTeamPage = canManageMembers || canManageProjects;

  const reload = React.useCallback(() => {
    if (!session.claims || !canOpenTeamPage) {
      setMemberships([]);
      setInvitations([]);
      setProjects([]);
      setLoading(false);
      return;
    }
    let canceled = false;
    setLoading(true);
    setErrorMessage('');
    Promise.all([
      listDashboardOrganizationMemberships('all'),
      listDashboardOrganizationInvitations('pending'),
      listDashboardProjects({ status: 'ACTIVE' }),
    ])
      .then(([nextMemberships, nextInvitations, nextProjects]) => {
        if (canceled) return;
        setMemberships(nextMemberships);
        setInvitations(nextInvitations);
        setProjects(nextProjects);
      })
      .catch((error: unknown) => {
        if (canceled) return;
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (!canceled) setLoading(false);
      });
    return () => {
      canceled = true;
    };
  }, [canOpenTeamPage, session.claims]);

  React.useEffect(() => {
    if (session.loading) return;
    return reload();
  }, [reload, session.loading]);

  const activeMemberships = React.useMemo(
    () =>
      memberships
        .filter((membership) => membershipMatchesQuery(membership, query))
        .sort((left, right) => {
          if (left.role === 'OWNER' && right.role !== 'OWNER') return -1;
          if (right.role === 'OWNER' && left.role !== 'OWNER') return 1;
          return left.email.localeCompare(right.email);
        }),
    [memberships, query],
  );
  const pagination = useDashboardTablePagination(activeMemberships, {
    disabled: loading || session.loading,
    itemLabel: 'membership',
    itemLabelPlural: 'memberships',
  });
  const ownerCount = memberships.filter(
    (membership) => membership.kind === 'active' && membership.role === 'OWNER',
  ).length;
  const editingMembership =
    memberships.find((membership) => membership.id === editingMembershipId) ?? null;

  const closeModal = React.useCallback(() => {
    setModal(null);
    setMutationError('');
    setInviteEmail('');
    setInviteGrant(defaultGrant());
    setEditingMembershipId('');
    setEditingGrant(defaultGrant());
  }, []);

  const openInviteModal = React.useCallback(() => {
    setMutationError('');
    setInviteGrant(defaultGrant());
    setModal('invite');
  }, []);

  const openEditModal = React.useCallback((membership: DashboardOrganizationMembership) => {
    setMutationError('');
    setEditingMembershipId(membership.id);
    setEditingGrant(grantFromMembership(membership));
    setModal('edit');
  }, []);

  const submitInvitation = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!canManageMembers) return;
      setBusyId('invite');
      setMutationError('');
      try {
        await inviteDashboardOrganizationMember({
          email: inviteEmail,
          ...inviteGrant,
        });
        setNotice(`Invitation sent to ${inviteEmail.trim().toLowerCase()}.`);
        closeModal();
        reload();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyId('');
      }
    },
    [canManageMembers, closeModal, inviteEmail, inviteGrant, reload],
  );

  const submitMembership = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!editingMembership) return;
      setBusyId(editingMembership.id);
      setMutationError('');
      try {
        if (editingMembership.role !== editingGrant.role) {
          await changeDashboardOrganizationMembershipRole(editingMembership.id, editingGrant);
        } else if (editingGrant.role === 'ADMIN') {
          await setDashboardOrganizationAdminPermissions(
            editingMembership.id,
            editingGrant.adminPermissions,
          );
        } else if (editingGrant.role === 'MEMBER') {
          const existing = new Map(
            editingMembership.projectAccess.map((assignment) => [
              assignment.projectId,
              assignment.accessLevel,
            ]),
          );
          for (const assignment of editingGrant.projectAccess) {
            if (existing.get(assignment.projectId) === assignment.accessLevel) continue;
            await setDashboardProjectMemberAccess({
              projectId: assignment.projectId,
              membershipId: editingMembership.id,
              accessLevel: assignment.accessLevel,
            });
          }
          const nextProjectIds = new Set(
            editingGrant.projectAccess.map((assignment) => assignment.projectId),
          );
          for (const assignment of editingMembership.projectAccess) {
            if (nextProjectIds.has(assignment.projectId)) continue;
            await removeDashboardProjectMemberAccess({
              projectId: assignment.projectId,
              membershipId: editingMembership.id,
            });
          }
        }
        setNotice(`Updated ${editingMembership.email}.`);
        closeModal();
        reload();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyId('');
      }
    },
    [closeModal, editingGrant, editingMembership, reload],
  );

  const mutateMembershipLifecycle = React.useCallback(
    async (
      membership: DashboardOrganizationMembership,
      action: 'suspend' | 'reactivate' | 'remove',
    ) => {
      const pastTense =
        action === 'suspend' ? 'suspended' : action === 'reactivate' ? 'reactivated' : 'removed';
      if (
        action === 'remove' &&
        !window.confirm(`Remove ${membership.email} from this organization?`)
      ) {
        return;
      }
      setBusyId(membership.id);
      setMutationError('');
      try {
        if (action === 'suspend') {
          await suspendDashboardOrganizationMembership(membership.id);
        } else if (action === 'reactivate') {
          await reactivateDashboardOrganizationMembership(membership.id);
        } else {
          await removeDashboardOrganizationMembership(membership.id);
        }
        setNotice(`${membership.email} was ${pastTense}.`);
        reload();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyId('');
      }
    },
    [reload],
  );

  const mutateInvitation = React.useCallback(
    async (invitation: DashboardOrganizationInvitation, action: 'resend' | 'revoke') => {
      setBusyId(invitation.id);
      setMutationError('');
      try {
        if (action === 'resend') {
          await resendDashboardOrganizationInvitation(invitation.id);
          setNotice(`Invitation resent to ${invitation.email}.`);
        } else {
          await revokeDashboardOrganizationInvitation(invitation.id);
          setNotice(`Invitation to ${invitation.email} was revoked.`);
        }
        reload();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyId('');
      }
    },
    [reload],
  );

  const inviteModal =
    modal === 'invite' ? (
      <DashboardInlineModal
        isOpen
        ariaLabel="Invite organization member"
        onRequestClose={closeModal}
      >
        <h2>Invite member</h2>
        <form className="dashboard-view-grid" onSubmit={submitInvitation}>
          <label className="dashboard-form-field">
            <span>Verified email</span>
            <input
              className="dashboard-input"
              type="email"
              required
              value={inviteEmail}
              onChange={(event) => setInviteEmail(event.target.value)}
              disabled={busyId === 'invite'}
            />
          </label>
          <GrantEditor
            grant={inviteGrant}
            projects={projects}
            allowPrivilegedRoles={isOwner}
            disabled={busyId === 'invite'}
            onChange={setInviteGrant}
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
              onClick={closeModal}
              disabled={busyId === 'invite'}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="dashboard-pagination-button dashboard-pagination-button--primary"
              disabled={busyId === 'invite'}
            >
              {busyId === 'invite' ? 'Sending…' : 'Send invitation'}
            </button>
          </div>
        </form>
      </DashboardInlineModal>
    ) : null;

  const editModal =
    modal === 'edit' && editingMembership ? (
      <DashboardInlineModal
        isOpen
        ariaLabel="Edit organization membership"
        onRequestClose={closeModal}
      >
        <h2>Edit membership</h2>
        <p className="dashboard-pagination-note">{editingMembership.email}</p>
        <form className="dashboard-view-grid" onSubmit={submitMembership}>
          <GrantEditor
            grant={editingGrant}
            projects={projects}
            allowPrivilegedRoles={isOwner}
            disabled={
              busyId === editingMembership.id || editingMembership.userId === session.claims?.userId
            }
            onChange={setEditingGrant}
          />
          {editingMembership.userId === session.claims?.userId ? (
            <p className="dashboard-pagination-note">
              Use “Leave organization” in account settings to change your own membership.
            </p>
          ) : null}
          {mutationError ? (
            <p className="dashboard-form-alert" role="alert">
              {mutationError}
            </p>
          ) : null}
          <div className="dashboard-form-actions">
            <button
              type="button"
              className="dashboard-pagination-button dashboard-pagination-button--secondary"
              onClick={closeModal}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="dashboard-pagination-button dashboard-pagination-button--primary"
              disabled={
                busyId === editingMembership.id ||
                editingMembership.userId === session.claims?.userId
              }
            >
              {busyId === editingMembership.id ? 'Saving…' : 'Save'}
            </button>
          </div>
        </form>
      </DashboardInlineModal>
    ) : null;

  return (
    <div
      className="dashboard-view dashboard-team-members-view"
      aria-label="Organization team management page"
    >
      <section className="dashboard-team-members-view__intro">
        <DashboardPageActions>
          <button
            type="button"
            className="dashboard-pagination-button dashboard-pagination-button--primary"
            onClick={openInviteModal}
            disabled={!canManageMembers}
          >
            Invite member
          </button>
        </DashboardPageActions>
        {ownerCount < 2 ? (
          <p className="dashboard-form-alert dashboard-form-alert--notice" role="status">
            Add a second owner to protect organization access if the current owner becomes
            unavailable.
          </p>
        ) : null}
        {notice ? <p className="dashboard-pagination-note">{notice}</p> : null}
        {mutationError && !modal ? (
          <p className="dashboard-form-alert" role="alert">
            {mutationError}
          </p>
        ) : null}
      </section>

      {!canOpenTeamPage && !session.loading ? (
        <DashboardTableState>
          Team administration requires owner access or an administrator permission.
        </DashboardTableState>
      ) : (
        <>
          <section className="dashboard-team-members-view__members">
            <label className="dashboard-search-control dashboard-search-control--compact">
              <span className="dashboard-search-icon" aria-hidden="true" />
              <input
                type="search"
                aria-label="Search memberships"
                placeholder="Search members"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </label>
            <DashboardTable
              ariaLabel="Organization memberships"
              className="dashboard-team-members-table"
              columns={MEMBERSHIP_COLUMNS}
              pagination={pagination.pagination}
            >
              <DashboardTableHeader className="dashboard-team-members-table__row">
                <DashboardTableHeaderCell>Member</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Access</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
              </DashboardTableHeader>
              {loading || session.loading ? (
                <DashboardTableState>Loading memberships…</DashboardTableState>
              ) : errorMessage ? (
                <DashboardTableState>{errorMessage}</DashboardTableState>
              ) : pagination.rows.length === 0 ? (
                <DashboardTableState>No memberships matched.</DashboardTableState>
              ) : (
                pagination.rows.map((membership) => {
                  const self = membership.userId === session.claims?.userId;
                  const owner = membership.role === 'OWNER';
                  const canEditTarget =
                    !self &&
                    (isOwner ||
                      (membership.role === 'MEMBER' && (canManageMembers || canManageProjects)));
                  return (
                    <DashboardTableRow
                      className="dashboard-team-members-table__row"
                      key={membership.id}
                    >
                      <DashboardTableCell
                        title={`${membership.displayName || membership.email} · ${membership.email}`}
                        className="dashboard-data-table__cell--lead"
                      >
                        <div className="dashboard-lead">
                          <span className="dashboard-lead__icon" aria-hidden="true">
                            {(membership.displayName || membership.email).trim().charAt(0)}
                          </span>
                          <span className="dashboard-lead__copy">
                            <span className="dashboard-lead__title">
                              <span className="dashboard-data-table__summary">
                                {membership.displayName || membership.email}
                              </span>
                              <DashboardTableBadge>
                                {dashboardStatusLabel(membership.role)}
                              </DashboardTableBadge>
                            </span>
                            <span className="dashboard-lead__sub">{membership.email}</span>
                          </span>
                        </div>
                      </DashboardTableCell>
                      <DashboardTableCell
                        title={roleSummary(membership)}
                        className="dashboard-data-table__cell--nowrap"
                      >
                        {roleSummary(membership)}
                      </DashboardTableCell>
                      <DashboardTableCell>
                        <DashboardTableStatus tone={dashboardStatusTone(membership.kind)}>
                          {dashboardStatusLabel(membership.kind)}
                        </DashboardTableStatus>
                      </DashboardTableCell>
                      <DashboardTableCell>
                        <DashboardTableActionGroup>
                          <DashboardTableActionButton
                            onClick={() => openEditModal(membership)}
                            disabled={!canEditTarget || membership.kind === 'removed'}
                          >
                            Edit
                          </DashboardTableActionButton>
                          <DashboardTableActionMenu
                            ariaLabel={`More actions for ${membership.email}`}
                            items={[
                              membership.kind === 'suspended'
                                ? {
                                    label: 'Reactivate',
                                    onSelect: () =>
                                      mutateMembershipLifecycle(membership, 'reactivate'),
                                    disabled: !canManageMembers || busyId === membership.id,
                                  }
                                : {
                                    label: 'Suspend',
                                    onSelect: () =>
                                      mutateMembershipLifecycle(membership, 'suspend'),
                                    disabled:
                                      !canManageMembers ||
                                      owner ||
                                      self ||
                                      membership.kind !== 'active' ||
                                      busyId === membership.id,
                                  },
                              {
                                label: 'Remove',
                                onSelect: () => mutateMembershipLifecycle(membership, 'remove'),
                                tone: 'danger',
                                disabled:
                                  !canManageMembers ||
                                  owner ||
                                  self ||
                                  membership.kind === 'removed' ||
                                  busyId === membership.id,
                              },
                            ]}
                          />
                        </DashboardTableActionGroup>
                      </DashboardTableCell>
                    </DashboardTableRow>
                  );
                })
              )}
            </DashboardTable>
          </section>

          <section className="dashboard-team-members-view__invitations">
            <div className="dashboard-team-members-view__section-heading">
              <h2>Pending invitations</h2>
              <p className="dashboard-pagination-note">
                Invitations expire after seven days and create membership only after acceptance.
              </p>
            </div>
            <DashboardTable
              ariaLabel="Pending organization invitations"
              className="dashboard-team-members-table"
              columns={INVITATION_COLUMNS}
            >
              <DashboardTableHeader className="dashboard-team-members-table__row">
                <DashboardTableHeaderCell>Invitee</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Access</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Expires</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
              </DashboardTableHeader>
              {loading ? (
                <DashboardTableState>Loading invitations…</DashboardTableState>
              ) : invitations.length === 0 ? (
                <DashboardTableState>No pending invitations.</DashboardTableState>
              ) : (
                invitations.map((invitation) => (
                  <DashboardTableRow
                    className="dashboard-team-members-table__row"
                    key={invitation.id}
                  >
                    <DashboardTableCell
                      title={invitation.email}
                      className="dashboard-data-table__cell--lead"
                    >
                      <div className="dashboard-lead">
                        <span className="dashboard-lead__icon" aria-hidden="true">
                          {invitation.email.trim().charAt(0)}
                        </span>
                        <span className="dashboard-lead__copy">
                          <span className="dashboard-lead__title">
                            <span className="dashboard-data-table__summary">
                              {invitation.email}
                            </span>
                            <DashboardTableBadge>
                              {dashboardStatusLabel(invitation.role)}
                            </DashboardTableBadge>
                          </span>
                        </span>
                      </div>
                    </DashboardTableCell>
                    <DashboardTableCell title={invitationSummary(invitation)}>
                      {invitationSummary(invitation)}
                    </DashboardTableCell>
                    <DashboardTableCell>
                      {formatDashboardTimestamp(invitation.expiresAt || '', '—')}
                    </DashboardTableCell>
                    <DashboardTableCell>
                      <DashboardTableActionGroup>
                        <DashboardTableActionButton
                          onClick={() => mutateInvitation(invitation, 'resend')}
                          disabled={!canManageMembers || busyId === invitation.id}
                        >
                          Resend
                        </DashboardTableActionButton>
                        <DashboardTableActionMenu
                          ariaLabel={`More actions for invitation ${invitation.email}`}
                          items={[
                            {
                              label: 'Revoke',
                              onSelect: () => mutateInvitation(invitation, 'revoke'),
                              tone: 'danger',
                              disabled: !canManageMembers || busyId === invitation.id,
                            },
                          ]}
                        />
                      </DashboardTableActionGroup>
                    </DashboardTableCell>
                  </DashboardTableRow>
                ))
              )}
            </DashboardTable>
          </section>
        </>
      )}
      {inviteModal}
      {editModal}
    </div>
  );
}
