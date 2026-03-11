import React from 'react';
import { createPortal } from 'react-dom';
import { toast } from 'sonner';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableBadge,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
} from '../../components/DashboardTable';
import { DashboardInlineModal } from '../../components/DashboardInlineModal';
import { useDashboardConsoleSession } from '../../consoleSession';
import {
  clearDashboardUiState,
  persistDashboardSelectedContext,
} from '../../useDashboardUiPreferences';
import {
  createDashboardAccountOrganization,
  deleteDashboardAccountOrganization,
  getDashboardAccountProfile,
  listDashboardAccountOrganizations,
  switchDashboardAccountOrganizationContext,
  transferDashboardAccountOrganizationOwner,
  updateDashboardAccountOrganization,
  updateDashboardAccountProfile,
  type DashboardAccountOrganization,
  type DashboardAccountProfile,
} from './consoleAccountApi';

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error || 'Unknown error');
}

const ACCOUNT_ORGANIZATIONS_TABLE_COLUMNS = dashboardTableColumns(1.75, 0.85, 1.15, 1.15, 0.95);

export function AccountSettingsPage(): React.JSX.Element {
  const { go } = useSiteRouter();
  const session = useDashboardConsoleSession();
  const viewRef = React.useRef<HTMLDivElement | null>(null);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [noticeMessage, setNoticeMessage] = React.useState<string>('');
  const [actionErrorMessage, setActionErrorMessage] = React.useState<string>('');
  const [profile, setProfile] = React.useState<DashboardAccountProfile | null>(null);
  const [organizations, setOrganizations] = React.useState<DashboardAccountOrganization[]>([]);

  const [displayNameDraft, setDisplayNameDraft] = React.useState<string>('');
  const [primaryEmailDraft, setPrimaryEmailDraft] = React.useState<string>('');
  const [newBackupEmail, setNewBackupEmail] = React.useState<string>('');
  const [createNameDraft, setCreateNameDraft] = React.useState<string>('');
  const [createSlugDraft, setCreateSlugDraft] = React.useState<string>('');
  const [renameDrafts, setRenameDrafts] = React.useState<Record<string, string>>({});
  const [transferTargets, setTransferTargets] = React.useState<Record<string, string>>({});

  const [savingProfile, setSavingProfile] = React.useState<boolean>(false);
  const [addingBackupEmail, setAddingBackupEmail] = React.useState<boolean>(false);
  const [removingBackupEmail, setRemovingBackupEmail] = React.useState<string>('');
  const [creatingOrganization, setCreatingOrganization] = React.useState<boolean>(false);
  const [renamingOrganizationId, setRenamingOrganizationId] = React.useState<string>('');
  const [transferringOrganizationId, setTransferringOrganizationId] = React.useState<string>('');
  const [switchingOrganizationId, setSwitchingOrganizationId] = React.useState<string>('');
  const [deletingOrganizationId, setDeletingOrganizationId] = React.useState<string>('');
  const [renameModalOrganizationId, setRenameModalOrganizationId] = React.useState<string>('');
  const [modalHost, setModalHost] = React.useState<HTMLElement | null>(null);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }

    let cancelled = false;
    const run = async () => {
      try {
        if (!session.claims) {
          setProfile(null);
          setOrganizations([]);
          setErrorMessage(session.errorMessage || 'Console session is unavailable');
          return;
        }
        setLoading(true);
        setErrorMessage('');
        const profileResult = await getDashboardAccountProfile();
        const organizationsResult = await listDashboardAccountOrganizations();
        if (cancelled) return;
        setProfile(profileResult);
        setOrganizations(organizationsResult);
      } catch (error: unknown) {
        if (cancelled) return;
        setProfile(null);
        setOrganizations([]);
        setErrorMessage(toErrorMessage(error));
      } finally {
        if (cancelled) return;
        setLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [session.claims, session.errorMessage, session.loading]);

  const reloadAccountSettings = React.useCallback(async () => {
    if (!session.claims) return;
    const profileResult = await getDashboardAccountProfile();
    const organizationsResult = await listDashboardAccountOrganizations();
    setProfile(profileResult);
    setOrganizations(organizationsResult);
  }, [session.claims]);

  React.useEffect(() => {
    setDisplayNameDraft(profile?.displayName || '');
    setPrimaryEmailDraft(profile?.primaryEmail || '');
  }, [profile?.displayName, profile?.primaryEmail, profile?.updatedAt]);

  React.useEffect(() => {
    setRenameDrafts(
      Object.fromEntries(organizations.map((organization) => [organization.id, organization.name])),
    );
    setTransferTargets((current) => {
      const next: Record<string, string> = {};
      for (const organization of organizations) {
        const previousValue = current[organization.id];
        const defaultCandidate =
          organization.adminCandidates.find(
            (candidate) => candidate.userId !== session.claims?.userId && !candidate.isOwner,
          )?.memberId || '';
        next[organization.id] = previousValue || defaultCandidate;
      }
      return next;
    });
  }, [organizations, session.claims?.userId]);

  React.useEffect(() => {
    setModalHost(viewRef.current?.closest('.dashboard-main') as HTMLElement | null);
  }, []);

  const renameOrganization = React.useMemo(
    () =>
      organizations.find((organization) => organization.id === renameModalOrganizationId) || null,
    [organizations, renameModalOrganizationId],
  );

  const onSaveProfile = React.useCallback(async () => {
    setSavingProfile(true);
    setActionErrorMessage('');
    setNoticeMessage('');
    try {
      const nextProfile = await updateDashboardAccountProfile({
        displayName: displayNameDraft,
        ...(profile?.canEditPrimaryEmail !== false ? { primaryEmail: primaryEmailDraft } : {}),
      });
      setProfile(nextProfile);
      toast.success('Profile updated.');
    } catch (error: unknown) {
      setActionErrorMessage(toErrorMessage(error));
    } finally {
      setSavingProfile(false);
    }
  }, [displayNameDraft, primaryEmailDraft, profile?.canEditPrimaryEmail]);

  const onAddBackupEmail = React.useCallback(async () => {
    setAddingBackupEmail(true);
    setActionErrorMessage('');
    setNoticeMessage('');
    try {
      const nextProfile = await updateDashboardAccountProfile({
        addBackupEmail: newBackupEmail,
      });
      setProfile(nextProfile);
      setNewBackupEmail('');
      setNoticeMessage('Backup email added.');
    } catch (error: unknown) {
      setActionErrorMessage(toErrorMessage(error));
    } finally {
      setAddingBackupEmail(false);
    }
  }, [newBackupEmail]);

  const onRemoveBackupEmail = React.useCallback(async (email: string) => {
    setRemovingBackupEmail(email);
    setActionErrorMessage('');
    setNoticeMessage('');
    try {
      const nextProfile = await updateDashboardAccountProfile({
        removeBackupEmail: email,
      });
      setProfile(nextProfile);
      setNoticeMessage('Backup email removed.');
    } catch (error: unknown) {
      setActionErrorMessage(toErrorMessage(error));
    } finally {
      setRemovingBackupEmail('');
    }
  }, []);

  const onCreateOrganization = React.useCallback(async () => {
    setCreatingOrganization(true);
    setActionErrorMessage('');
    setNoticeMessage('');
    try {
      await createDashboardAccountOrganization({
        name: createNameDraft,
        ...(createSlugDraft.trim() ? { slug: createSlugDraft.trim() } : {}),
      });
      setCreateNameDraft('');
      setCreateSlugDraft('');
      await reloadAccountSettings();
      setNoticeMessage('Organization created.');
    } catch (error: unknown) {
      setActionErrorMessage(toErrorMessage(error));
    } finally {
      setCreatingOrganization(false);
    }
  }, [createNameDraft, createSlugDraft, reloadAccountSettings]);

  const onRenameOrganization = React.useCallback(
    async (organization: DashboardAccountOrganization) => {
      const nextName = String(renameDrafts[organization.id] || '').trim();
      setRenamingOrganizationId(organization.id);
      setActionErrorMessage('');
      setNoticeMessage('');
      try {
        await updateDashboardAccountOrganization(organization.id, {
          name: nextName,
        });
        await reloadAccountSettings();
        setRenameModalOrganizationId('');
        setNoticeMessage(`Updated ${organization.name}.`);
      } catch (error: unknown) {
        setActionErrorMessage(toErrorMessage(error));
      } finally {
        setRenamingOrganizationId('');
      }
    },
    [reloadAccountSettings, renameDrafts],
  );

  const onOpenRenameModal = React.useCallback((organization: DashboardAccountOrganization) => {
    setActionErrorMessage('');
    setRenameDrafts((current) => ({
      ...current,
      [organization.id]: organization.name,
    }));
    setRenameModalOrganizationId(organization.id);
  }, []);

  const onCloseRenameModal = React.useCallback(() => {
    setActionErrorMessage('');
    setRenameModalOrganizationId('');
  }, []);

  const onTransferOwner = React.useCallback(
    async (organization: DashboardAccountOrganization) => {
      const targetMemberId = String(transferTargets[organization.id] || '').trim();
      setTransferringOrganizationId(organization.id);
      setActionErrorMessage('');
      setNoticeMessage('');
      try {
        await transferDashboardAccountOrganizationOwner(organization.id, { targetMemberId });
        await reloadAccountSettings();
        setNoticeMessage(`Transferred ownership for ${organization.name}.`);
      } catch (error: unknown) {
        setActionErrorMessage(toErrorMessage(error));
      } finally {
        setTransferringOrganizationId('');
      }
    },
    [reloadAccountSettings, transferTargets],
  );

  const onOpenOrganization = React.useCallback(
    async (organization: DashboardAccountOrganization) => {
      setSwitchingOrganizationId(organization.id);
      setActionErrorMessage('');
      setNoticeMessage('');
      try {
        if (!organization.isCurrentOrg) {
          const nextContext = await switchDashboardAccountOrganizationContext(organization.id);
          clearDashboardUiState();
          persistDashboardSelectedContext({
            organization: nextContext.orgId,
            project: nextContext.projectId || '',
            environment: nextContext.environmentId || '',
          });
          session.refresh();
          go(nextContext.onboardingComplete ? '/dashboard' : '/dashboard/onboarding');
          return;
        }
        go(organization.onboardingComplete ? '/dashboard' : '/dashboard/onboarding');
      } catch (error: unknown) {
        setActionErrorMessage(toErrorMessage(error));
      } finally {
        setSwitchingOrganizationId('');
      }
    },
    [go, session],
  );

  const onDeleteOrganization = React.useCallback(
    async (organization: DashboardAccountOrganization) => {
      if (typeof window !== 'undefined') {
        const confirmed = window.confirm(
          `Delete ${organization.name}? This permanently removes the organization if no other members or wallets exist.`,
        );
        if (!confirmed) return;
      }
      setDeletingOrganizationId(organization.id);
      setActionErrorMessage('');
      setNoticeMessage('');
      try {
        await deleteDashboardAccountOrganization(organization.id);
        await reloadAccountSettings();
        setNoticeMessage(`Deleted ${organization.name}.`);
      } catch (error: unknown) {
        setActionErrorMessage(toErrorMessage(error));
      } finally {
        setDeletingOrganizationId('');
      }
    },
    [reloadAccountSettings],
  );

  if (loading) {
    return (
      <section className="dashboard-account-settings" aria-label="Account settings loading state">
        <p className="dashboard-pagination-note">Loading account settings...</p>
      </section>
    );
  }

  if (errorMessage) {
    return (
      <section className="dashboard-account-settings" aria-label="Account settings error state">
        <p className="dashboard-form-alert" role="alert">
          {errorMessage}
        </p>
      </section>
    );
  }

  const renameModal =
    renameOrganization !== null ? (
      <DashboardInlineModal
        isOpen
        ariaLabel="Rename organization modal"
        onRequestClose={onCloseRenameModal}
      >
        <h2>Rename organization</h2>
        <p className="dashboard-pagination-note">
          {renameOrganization.slug || renameOrganization.id}
        </p>
        <form
          className="dashboard-view-grid"
          onSubmit={(event) => {
            event.preventDefault();
            void onRenameOrganization(renameOrganization);
          }}
        >
          <label className="dashboard-form-field">
            <span>Organization name</span>
            <input
              className="dashboard-input"
              value={renameDrafts[renameOrganization.id] || ''}
              onChange={(event) =>
                setRenameDrafts((current) => ({
                  ...current,
                  [renameOrganization.id]: event.target.value,
                }))
              }
              disabled={renamingOrganizationId === renameOrganization.id}
              placeholder="Organization name"
              autoFocus
            />
          </label>
          {actionErrorMessage ? (
            <p className="dashboard-form-alert" role="alert">
              {actionErrorMessage}
            </p>
          ) : null}
          <div className="dashboard-form-actions">
            <button
              type="button"
              className="dashboard-pagination-button dashboard-pagination-button--secondary"
              onClick={onCloseRenameModal}
              disabled={renamingOrganizationId === renameOrganization.id}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="dashboard-pagination-button"
              disabled={
                renamingOrganizationId === renameOrganization.id ||
                !String(renameDrafts[renameOrganization.id] || '').trim()
              }
            >
              {renamingOrganizationId === renameOrganization.id ? 'Saving...' : 'Rename'}
            </button>
          </div>
        </form>
      </DashboardInlineModal>
    ) : null;

  return (
    <div ref={viewRef} className="dashboard-account-settings" aria-label="Account settings page">
      {noticeMessage ? (
        <p className="dashboard-form-alert dashboard-account-alert--success" role="status">
          {noticeMessage}
        </p>
      ) : null}
      {actionErrorMessage ? (
        <p className="dashboard-form-alert" role="alert">
          {actionErrorMessage}
        </p>
      ) : null}

      <section className="dashboard-account-panel dashboard-account-panel--profile">
        <div className="dashboard-account-profile-card">
          <div className="dashboard-section-toolbar dashboard-account-section-header">
            <div className="dashboard-section-toolbar__copy">
              <h2>Profile</h2>
            </div>
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={() => void onSaveProfile()}
              disabled={savingProfile}
            >
              {savingProfile ? 'Saving...' : 'Save'}
            </button>
          </div>
          <div className="dashboard-view-grid dashboard-view-grid--two dashboard-account-grid">
            <label className="dashboard-form-field">
              <span>Display name</span>
              <input
                className="dashboard-input"
                value={displayNameDraft}
                onChange={(event) => setDisplayNameDraft(event.target.value)}
                placeholder="Display name"
              />
            </label>
            <label className="dashboard-form-field">
              <span>
                {profile?.canEditPrimaryEmail === false
                  ? 'Primary email (read-only)'
                  : 'Primary email'}
              </span>
              <input
                className="dashboard-input"
                value={primaryEmailDraft}
                onChange={(event) => setPrimaryEmailDraft(event.target.value)}
                disabled={profile?.canEditPrimaryEmail === false}
                placeholder="name@example.com"
              />
            </label>
          </div>
          <div className="dashboard-account-subsection dashboard-account-subsection--compact">
            <div className="dashboard-section-toolbar dashboard-account-subsection-header">
              <div className="dashboard-section-toolbar__copy">
                <h3>Backup Emails</h3>
              </div>
            </div>
            {profile?.backupEmails.length ? (
              <div className="dashboard-account-backup-list">
                {profile.backupEmails.map((backupEmail) => (
                  <article className="dashboard-account-backup-item" key={backupEmail.email}>
                    <div className="dashboard-account-backup-item__content">
                      <strong>{backupEmail.email}</strong>
                      <p className="dashboard-pagination-note">
                        {backupEmail.status} • added {formatTimestamp(backupEmail.createdAt)}
                      </p>
                    </div>
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--danger dashboard-account-backup-item__action"
                      onClick={() => void onRemoveBackupEmail(backupEmail.email)}
                      disabled={removingBackupEmail === backupEmail.email}
                    >
                      {removingBackupEmail === backupEmail.email ? 'Removing...' : 'Remove'}
                    </button>
                  </article>
                ))}
              </div>
            ) : null}
            <div className="dashboard-account-inline-form">
              <label className="dashboard-form-field">
                <span className="dashboard-visually-hidden">Backup email</span>
                <input
                  className="dashboard-input"
                  value={newBackupEmail}
                  onChange={(event) => setNewBackupEmail(event.target.value)}
                  placeholder="recovery@example.com"
                />
              </label>
              <button
                type="button"
                className="dashboard-pagination-button"
                onClick={() => void onAddBackupEmail()}
                disabled={addingBackupEmail}
              >
                {addingBackupEmail ? 'Adding...' : 'Add'}
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="dashboard-account-panel dashboard-account-panel--organizations">
        <div className="dashboard-section-toolbar dashboard-account-section-header">
          <div className="dashboard-section-toolbar__copy">
            <h2>My Organisations</h2>
            <p className="dashboard-pagination-note">
              Create new organizations, rename the ones you manage, delete empty orgs, or transfer
              ownership.
            </p>
          </div>
        </div>
        <div className="dashboard-account-org-create">
          <div className="dashboard-view-grid dashboard-view-grid--two dashboard-account-grid">
            <label className="dashboard-form-field">
              <span>Organization name</span>
              <input
                className="dashboard-input"
                value={createNameDraft}
                onChange={(event) => setCreateNameDraft(event.target.value)}
                placeholder="Northwind Labs"
              />
            </label>
            <label className="dashboard-form-field">
              <span>Slug</span>
              <input
                className="dashboard-input"
                value={createSlugDraft}
                onChange={(event) => setCreateSlugDraft(event.target.value)}
                placeholder="northwind-labs"
              />
            </label>
            <div className="dashboard-form-actions">
              <button
                type="button"
                className="dashboard-pagination-button"
                onClick={() => void onCreateOrganization()}
                disabled={creatingOrganization}
              >
                {creatingOrganization ? 'Creating...' : 'Create organization'}
              </button>
            </div>
          </div>
        </div>

        <DashboardTable
          ariaLabel="Organizations"
          columns={ACCOUNT_ORGANIZATIONS_TABLE_COLUMNS}
          className="dashboard-account-org-table"
        >
          <DashboardTableHeader>
            <DashboardTableHeaderCell>Organization</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Rename</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Transfer</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {organizations.length ? (
            organizations.map((organization) => {
              const transferOptions = organization.adminCandidates.filter(
                (candidate) => candidate.userId !== session.claims?.userId && !candidate.isOwner,
              );
              return (
                <DashboardTableRow key={organization.id}>
                  <DashboardTableCell className="dashboard-account-org-table__organization">
                    <strong className="dashboard-data-table__summary">{organization.name}</strong>
                    <span className="dashboard-pagination-note">
                      {organization.slug || organization.id}
                    </span>
                    <div className="dashboard-account-org-meta">
                      <span>Created {formatTimestamp(organization.createdAt)}</span>
                      <span>Updated {formatTimestamp(organization.updatedAt)}</span>
                      <span>
                        Scope {organization.selectedProjectId || 'No project'} /{' '}
                        {organization.selectedEnvironmentId || 'No environment'}
                      </span>
                    </div>
                  </DashboardTableCell>
                  <DashboardTableCell>
                    <div className="dashboard-account-org-table__badges">
                      {organization.isCurrentOrg ? (
                        <DashboardTableBadge>Current</DashboardTableBadge>
                      ) : null}
                      <DashboardTableBadge
                        tone={organization.onboardingComplete ? 'success' : 'warning'}
                      >
                        {organization.onboardingComplete ? 'Ready' : 'Needs onboarding'}
                      </DashboardTableBadge>
                    </div>
                  </DashboardTableCell>
                  <DashboardTableCell>
                    {organization.actorIsAdmin ? (
                      <DashboardTableActionButton
                        onClick={() => onOpenRenameModal(organization)}
                        disabled={renamingOrganizationId === organization.id}
                      >
                        {renamingOrganizationId === organization.id ? 'Saving...' : 'Rename'}
                      </DashboardTableActionButton>
                    ) : (
                      <span className="dashboard-pagination-note">Admin only</span>
                    )}
                  </DashboardTableCell>
                  <DashboardTableCell>
                    {organization.actorIsOwner && transferOptions.length ? (
                      <div className="dashboard-account-table-form">
                        <label className="dashboard-form-field">
                          <span className="dashboard-visually-hidden">
                            Transfer ownership for {organization.name}
                          </span>
                          <select
                            className="dashboard-input dashboard-account-table-input"
                            value={transferTargets[organization.id] || ''}
                            onChange={(event) =>
                              setTransferTargets((current) => ({
                                ...current,
                                [organization.id]: event.target.value,
                              }))
                            }
                          >
                            <option value="">Select an admin</option>
                            {transferOptions.map((candidate) => (
                              <option key={candidate.memberId} value={candidate.memberId}>
                                {candidate.displayName || candidate.email || candidate.userId}
                              </option>
                            ))}
                          </select>
                        </label>
                        <DashboardTableActionButton
                          onClick={() => void onTransferOwner(organization)}
                          disabled={
                            transferringOrganizationId === organization.id ||
                            !String(transferTargets[organization.id] || '').trim()
                          }
                        >
                          {transferringOrganizationId === organization.id
                            ? 'Transferring...'
                            : 'Transfer'}
                        </DashboardTableActionButton>
                      </div>
                    ) : (
                      <span className="dashboard-pagination-note">
                        {organization.actorIsOwner ? 'No eligible admins' : 'Owner only'}
                      </span>
                    )}
                  </DashboardTableCell>
                  <DashboardTableCell>
                    <DashboardTableActionGroup className="dashboard-account-org-table__actions">
                      <DashboardTableActionButton
                        onClick={() => void onOpenOrganization(organization)}
                        disabled={switchingOrganizationId === organization.id}
                      >
                        {switchingOrganizationId === organization.id ? 'Opening...' : 'Open'}
                      </DashboardTableActionButton>
                      {organization.actorIsOwner ? (
                        <DashboardTableActionButton
                          tone="danger"
                          onClick={() => void onDeleteOrganization(organization)}
                          disabled={
                            deletingOrganizationId === organization.id || organization.isCurrentOrg
                          }
                          title={
                            organization.isCurrentOrg
                              ? 'Switch to a different organization before deleting it.'
                              : undefined
                          }
                        >
                          {deletingOrganizationId === organization.id ? 'Deleting...' : 'Delete'}
                        </DashboardTableActionButton>
                      ) : null}
                    </DashboardTableActionGroup>
                    {organization.actorIsOwner && organization.isCurrentOrg ? (
                      <span className="dashboard-pagination-note">
                        Switch away before deleting.
                      </span>
                    ) : null}
                  </DashboardTableCell>
                </DashboardTableRow>
              );
            })
          ) : (
            <DashboardTableState>No organizations created by this account yet.</DashboardTableState>
          )}
        </DashboardTable>
      </section>
      {renameModal ? (modalHost ? createPortal(renameModal, modalHost) : renameModal) : null}
    </div>
  );
}

export default AccountSettingsPage;
