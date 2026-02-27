import React from 'react';
import DashboardSidebar from './layout/DashboardSidebar';
import DashboardTopbar from './layout/DashboardTopbar';
import {
  DASHBOARD_ACCOUNT_SETTINGS_OPTIONS,
  DEFAULT_DASHBOARD_ROUTE,
  getRouteFromPathname,
  getViewForRoute,
  SIDEBAR_GROUPS,
} from './dashboardConfig';
import type { DashboardRoute, TopbarContextState, TopbarMenuKey, TopbarOption } from './types';
import {
  DashboardConsoleSessionProvider,
  useDashboardConsoleSession,
} from './consoleSession';
import { DashboardSelectedContextProvider } from './selectedContext';
import {
  getDashboardOrganization,
  listDashboardEnvironments,
  listDashboardProjects,
} from './consoleContextApi';
import { useDashboardUiPreferences } from './useDashboardUiPreferences';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { FRONTEND_CONFIG } from '@/config';
import './styles.css';

type DashboardPageProps = {
  pathname?: string;
};

function dedupeOptions(options: TopbarOption[]): TopbarOption[] {
  const seen = new Set<string>();
  const deduped: TopbarOption[] = [];
  for (const option of options) {
    const value = String(option.value || '').trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    deduped.push({
      value,
      label: String(option.label || value).trim() || value,
    });
  }
  return deduped;
}

function DashboardPageInner({ pathname = '/dashboard' }: DashboardPageProps): React.JSX.Element {
  const docsOrigin = FRONTEND_CONFIG.docsOrigin;
  const { go, linkProps } = useSiteRouter();
  const homeProps = linkProps('/');
  const consoleSession = useDashboardConsoleSession();
  const [contextLoading, setContextLoading] = React.useState<boolean>(false);
  const [contextError, setContextError] = React.useState<string>('');
  const [environmentLoading, setEnvironmentLoading] = React.useState<boolean>(false);
  const [environmentError, setEnvironmentError] = React.useState<string>('');
  const [organizationOption, setOrganizationOption] = React.useState<TopbarOption | null>(null);
  const [projectOptions, setProjectOptions] = React.useState<TopbarOption[]>([]);
  const [selectedProjectId, setSelectedProjectId] = React.useState<string>('');
  const [environmentOptions, setEnvironmentOptions] = React.useState<TopbarOption[]>([]);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      setOrganizationOption(null);
      setProjectOptions([]);
      setSelectedProjectId('');
      setEnvironmentOptions([]);
      setContextError('');
      setEnvironmentError('');
      setContextLoading(false);
      setEnvironmentLoading(false);
      return;
    }
    let cancelled = false;
    setContextLoading(true);
    setContextError('');
    setEnvironmentError('');
    Promise.all([getDashboardOrganization(), listDashboardProjects({ status: 'ACTIVE' })])
      .then(([organization, projects]) => {
        if (cancelled) return;
        setOrganizationOption({
          value: organization.id,
          label: organization.name || organization.id,
        });
        const nextProjectOptions = dedupeOptions(
          projects.map((entry) => ({
            value: entry.id,
            label: entry.name || entry.id,
          })),
        );
        if (
          claims.projectId &&
          !nextProjectOptions.some((entry) => entry.value === claims.projectId)
        ) {
          nextProjectOptions.unshift({
            value: claims.projectId,
            label: claims.projectId,
          });
        }
        setProjectOptions(nextProjectOptions);
        setSelectedProjectId(claims.projectId || nextProjectOptions[0]?.value || '');
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setOrganizationOption({
          value: claims.orgId,
          label: claims.orgId,
        });
        setProjectOptions(claims.projectId ? [{ value: claims.projectId, label: claims.projectId }] : []);
        setSelectedProjectId(claims.projectId || '');
        setContextError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setContextLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [consoleSession.claims]);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      setEnvironmentOptions([]);
      setEnvironmentError('');
      setEnvironmentLoading(false);
      return;
    }
    const projectId = String(selectedProjectId || '').trim();
    if (!projectId) {
      setEnvironmentOptions([]);
      setEnvironmentError('');
      setEnvironmentLoading(false);
      return;
    }
    let cancelled = false;
    setEnvironmentLoading(true);
    setEnvironmentError('');
    setEnvironmentOptions([]);
    listDashboardEnvironments({ projectId, status: 'ACTIVE' })
      .then((environments) => {
        if (cancelled) return;
        const nextEnvironmentOptions = dedupeOptions(
          environments.map((entry) => ({
            value: entry.id,
            label: entry.name || entry.id,
          })),
        );
        if (
          claims.projectId === projectId &&
          claims.environmentId &&
          !nextEnvironmentOptions.some((entry) => entry.value === claims.environmentId)
        ) {
          nextEnvironmentOptions.unshift({
            value: claims.environmentId,
            label: claims.environmentId,
          });
        }
        setEnvironmentOptions(nextEnvironmentOptions);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setEnvironmentOptions(
          claims.projectId === projectId && claims.environmentId
            ? [{ value: claims.environmentId, label: claims.environmentId }]
            : [],
        );
        setEnvironmentError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setEnvironmentLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [consoleSession.claims, selectedProjectId]);

  const dropdownOptions = React.useMemo(
    () => ({
      organization: dedupeOptions(
        organizationOption
          ? [organizationOption]
          : consoleSession.claims
            ? [{ value: consoleSession.claims.orgId, label: consoleSession.claims.orgId }]
            : [],
      ),
      project: dedupeOptions(
        projectOptions.length > 0
          ? projectOptions
          : consoleSession.claims?.projectId
            ? [{ value: consoleSession.claims.projectId, label: consoleSession.claims.projectId }]
            : [],
      ),
      environment: dedupeOptions(
        environmentOptions.length > 0
          ? environmentOptions
          : consoleSession.claims?.environmentId &&
              selectedProjectId &&
              consoleSession.claims.projectId === selectedProjectId
            ? [{
                value: consoleSession.claims.environmentId,
                label: consoleSession.claims.environmentId,
              }]
            : [],
      ),
      accountSettings: DASHBOARD_ACCOUNT_SETTINGS_OPTIONS.map((entry) => ({
        value: entry,
        label: entry,
      })),
    }),
    [consoleSession.claims, environmentOptions, organizationOption, projectOptions, selectedProjectId],
  );

  const defaultTopbarContext = React.useMemo<TopbarContextState>(
    () => {
      const preferredProjectId = String(selectedProjectId || consoleSession.claims?.projectId || '').trim();
      const projectValue =
        dropdownOptions.project.find((entry) => entry.value === preferredProjectId)?.value ||
        dropdownOptions.project[0]?.value ||
        preferredProjectId;
      const preferredEnvironmentId = String(
        projectValue && consoleSession.claims?.projectId === projectValue
          ? consoleSession.claims.environmentId || ''
          : '',
      ).trim();
      return {
        organization:
          dropdownOptions.organization[0]?.value ||
          consoleSession.claims?.orgId ||
          '',
        project: projectValue,
        environment:
          dropdownOptions.environment.find((entry) => entry.value === preferredEnvironmentId)?.value ||
          dropdownOptions.environment[0]?.value ||
          preferredEnvironmentId,
        accountSettings: dropdownOptions.accountSettings[0]?.value || '',
      };
    },
    [consoleSession.claims, dropdownOptions, selectedProjectId],
  );

  const {
    isSidebarExpanded,
    expandedGroups,
    selectedContext,
    toggleSidebar,
    toggleGroup,
    onSelectContext: onSelectContextRaw,
  } = useDashboardUiPreferences(pathname, {
    dropdownOptions,
    defaultContext: defaultTopbarContext,
  });

  React.useEffect(() => {
    const project = String(selectedContext.project || '').trim();
    if (!project || project === selectedProjectId) return;
    setSelectedProjectId(project);
  }, [selectedContext.project, selectedProjectId]);

  const onSelectContext = React.useCallback(
    (menu: TopbarMenuKey, value: string) => {
      onSelectContextRaw(menu, value);
      if (menu === 'project') {
        setSelectedProjectId(value);
      }
    },
    [onSelectContextRaw],
  );

  React.useEffect(() => {
    if (pathname === '/dashboard') {
      go(DEFAULT_DASHBOARD_ROUTE);
    }
  }, [go, pathname]);

  React.useEffect(() => {
    if (
      pathname !== '/dashboard' &&
      pathname.startsWith('/dashboard/') &&
      !getRouteFromPathname(pathname)
    ) {
      go(DEFAULT_DASHBOARD_ROUTE);
    }
  }, [go, pathname]);

  const activeRoute = React.useMemo<DashboardRoute>(() => {
    const resolved = getRouteFromPathname(pathname);
    return resolved ?? DEFAULT_DASHBOARD_ROUTE;
  }, [pathname]);

  const activeView = React.useMemo(() => getViewForRoute(activeRoute), [activeRoute]);
  const ActiveViewComponent = activeView.component;

  return (
    <main
      className={`dashboard-shell${isSidebarExpanded ? '' : ' dashboard-shell--sidebar-collapsed'}`}
      aria-label="Dashboard workspace"
    >
      <DashboardTopbar
        isSidebarExpanded={isSidebarExpanded}
        onToggleSidebar={toggleSidebar}
        homeProps={homeProps}
        selectedContext={selectedContext}
        onSelectContext={onSelectContext}
        dropdownOptions={dropdownOptions}
      />

      <DashboardSidebar
        groups={SIDEBAR_GROUPS}
        isSidebarExpanded={isSidebarExpanded}
        expandedGroups={expandedGroups}
        activeRoute={activeRoute}
        onToggleGroup={toggleGroup}
        linkProps={linkProps}
      />

      <section className="dashboard-main" aria-labelledby="dashboard-main-title">
        <h1 id="dashboard-main-title" className="dashboard-main__title">
          {activeView.label}
        </h1>

        <p className="dashboard-info-banner">
          Build target for <strong>{activeView.label}</strong> from dashboard requirements. For more
          information, see the docs{' '}
          <a href={docsOrigin} target="_blank" rel="noreferrer">
            here
          </a>
          .
          <span className="dashboard-session-status">
            {consoleSession.loading
              ? ' Verifying console session...'
              : consoleSession.claims
                ? ` Console session active for org ${consoleSession.claims.orgId}.`
                : ` Console session unavailable: ${consoleSession.errorMessage || 'unauthorized'}.`}
            {consoleSession.claims
              ? contextLoading || environmentLoading
                ? ' Loading organization/project/environment context...'
                : contextError || environmentError
                  ? ` Context fallback active: ${contextError || environmentError}.`
                  : ' Context loaded.'
              : ''}
          </span>
          {!consoleSession.loading && !consoleSession.claims ? (
            <button
              type="button"
              className="dashboard-session-retry"
              onClick={consoleSession.refresh}
            >
              Retry session
            </button>
          ) : null}
        </p>

        <DashboardSelectedContextProvider value={selectedContext}>
          <ActiveViewComponent />
        </DashboardSelectedContextProvider>
      </section>
    </main>
  );
}

export function DashboardPage(props: DashboardPageProps): React.JSX.Element {
  return (
    <DashboardConsoleSessionProvider>
      <DashboardPageInner {...props} />
    </DashboardConsoleSessionProvider>
  );
}

export default DashboardPage;
