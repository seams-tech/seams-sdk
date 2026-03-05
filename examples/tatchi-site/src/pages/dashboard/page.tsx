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
import {
  getDashboardOnboardingState,
  isDashboardConsoleApiErrorCode,
  type DashboardOnboardingState,
} from './routes/onboarding/consoleOnboardingApi';
import {
  readPersistedDashboardSelectedContext,
  useDashboardUiPreferences,
} from './useDashboardUiPreferences';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import './styles.css';

type DashboardPageProps = {
  pathname?: string;
};

const DASHBOARD_ONBOARDING_ROUTE: DashboardRoute = '/dashboard/onboarding';

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
  const { go, linkProps } = useSiteRouter();
  const homeProps = linkProps('/');
  const consoleSession = useDashboardConsoleSession();
  const persistedSelectedContext = React.useMemo(
    () => readPersistedDashboardSelectedContext(),
    [pathname],
  );
  const persistedProjectId = String(persistedSelectedContext.project || '').trim();
  const persistedEnvironmentId = String(persistedSelectedContext.environment || '').trim();
  const [onboardingLoading, setOnboardingLoading] = React.useState<boolean>(false);
  const [onboardingState, setOnboardingState] = React.useState<DashboardOnboardingState | null>(null);
  const [onboardingGateEnabled, setOnboardingGateEnabled] = React.useState<boolean>(true);
  const [organizationOption, setOrganizationOption] = React.useState<TopbarOption | null>(null);
  const [projectOptions, setProjectOptions] = React.useState<TopbarOption[]>([]);
  const [selectedProjectId, setSelectedProjectId] = React.useState<string>(persistedProjectId);
  const [environmentOptions, setEnvironmentOptions] = React.useState<TopbarOption[]>([]);
  const onboardingComplete = onboardingState
    ? onboardingState.onboardingComplete === undefined
      ? onboardingState.complete === true
      : onboardingState.onboardingComplete
    : false;

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      setOnboardingLoading(false);
      setOnboardingState(null);
      setOnboardingGateEnabled(true);
      setOrganizationOption(null);
      setProjectOptions([]);
      setSelectedProjectId(persistedProjectId);
      setEnvironmentOptions([]);
      return;
    }

    let cancelled = false;
    setOnboardingLoading(true);
    setOnboardingGateEnabled(true);
    getDashboardOnboardingState()
      .then((state) => {
        if (cancelled) return;
        setOnboardingState(state);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        if (isDashboardConsoleApiErrorCode(error, 'onboarding_not_configured')) {
          setOnboardingState(null);
          setOnboardingGateEnabled(false);
          return;
        }
        setOnboardingState(null);
        setOnboardingGateEnabled(false);
      })
      .finally(() => {
        if (cancelled) return;
        setOnboardingLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [consoleSession.claims, persistedProjectId]);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) return;
    if (consoleSession.loading || onboardingLoading) return;
    if (!onboardingGateEnabled || !onboardingState) return;
    const isOnboardingRoute = pathname === DASHBOARD_ONBOARDING_ROUTE;
    if (!onboardingComplete && !isOnboardingRoute) {
      go(DASHBOARD_ONBOARDING_ROUTE);
      return;
    }
    if (onboardingComplete && isOnboardingRoute) {
      go(DEFAULT_DASHBOARD_ROUTE);
    }
  }, [
    consoleSession.claims,
    consoleSession.loading,
    go,
    onboardingGateEnabled,
    onboardingLoading,
    onboardingComplete,
    onboardingState,
    pathname,
  ]);

  const dashboardEntryRoute = React.useMemo<DashboardRoute>(() => {
    if (onboardingGateEnabled && onboardingState && onboardingComplete) return DEFAULT_DASHBOARD_ROUTE;
    return DASHBOARD_ONBOARDING_ROUTE;
  }, [onboardingComplete, onboardingGateEnabled, onboardingState]);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      return;
    }
    let cancelled = false;
    Promise.all([getDashboardOrganization(), listDashboardProjects({ status: 'ACTIVE' })])
      .then(([organization, projects]) => {
        if (cancelled) return;
        const persisted = readPersistedDashboardSelectedContext();
        const preferredProjectId = String(persisted.project || '').trim();
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
        if (
          preferredProjectId &&
          !nextProjectOptions.some((entry) => entry.value === preferredProjectId)
        ) {
          nextProjectOptions.unshift({
            value: preferredProjectId,
            label: preferredProjectId,
          });
        }
        setProjectOptions(nextProjectOptions);
        const nextSelectedProjectId =
          (preferredProjectId &&
            nextProjectOptions.find((entry) => entry.value === preferredProjectId)?.value) ||
          (claims.projectId &&
            nextProjectOptions.find((entry) => entry.value === claims.projectId)?.value) ||
          nextProjectOptions[0]?.value ||
          claims.projectId ||
          '';
        setSelectedProjectId(nextSelectedProjectId);
      })
      .catch(() => {
        if (cancelled) return;
        const persisted = readPersistedDashboardSelectedContext();
        const preferredProjectId = String(persisted.project || '').trim();
        setOrganizationOption({
          value: claims.orgId,
          label: claims.orgId,
        });
        const fallbackProjects = dedupeOptions([
          ...(preferredProjectId ? [{ value: preferredProjectId, label: preferredProjectId }] : []),
          ...(claims.projectId ? [{ value: claims.projectId, label: claims.projectId }] : []),
        ]);
        setProjectOptions(fallbackProjects);
        setSelectedProjectId(preferredProjectId || claims.projectId || '');
      });
    return () => {
      cancelled = true;
    };
  }, [consoleSession.claims, pathname]);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      setEnvironmentOptions([]);
      return;
    }
    const projectId = String(selectedProjectId || '').trim();
    if (!projectId) {
      setEnvironmentOptions([]);
      return;
    }
    let cancelled = false;
    setEnvironmentOptions([]);
    listDashboardEnvironments({ projectId, status: 'ACTIVE' })
      .then((environments) => {
        if (cancelled) return;
        const persisted = readPersistedDashboardSelectedContext();
        const preferredEnvironmentId = String(persisted.environment || '').trim();
        const nextEnvironmentOptions = dedupeOptions(
          environments.map((entry) => ({
            value: entry.id,
            label: entry.name || entry.id,
          })),
        );
        if (
          preferredEnvironmentId &&
          !nextEnvironmentOptions.some((entry) => entry.value === preferredEnvironmentId)
        ) {
          nextEnvironmentOptions.unshift({
            value: preferredEnvironmentId,
            label: preferredEnvironmentId,
          });
        }
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
      .catch(() => {
        if (cancelled) return;
        const persisted = readPersistedDashboardSelectedContext();
        const preferredEnvironmentId = String(persisted.environment || '').trim();
        setEnvironmentOptions(
          dedupeOptions([
            ...(preferredEnvironmentId
              ? [{ value: preferredEnvironmentId, label: preferredEnvironmentId }]
              : []),
            ...(claims.projectId === projectId && claims.environmentId
              ? [{ value: claims.environmentId, label: claims.environmentId }]
              : []),
          ]),
        );
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
          : dedupeOptions([
              ...(persistedProjectId
                ? [{ value: persistedProjectId, label: persistedProjectId }]
                : []),
              ...(consoleSession.claims?.projectId
                ? [{ value: consoleSession.claims.projectId, label: consoleSession.claims.projectId }]
                : []),
            ]),
      ),
      environment: dedupeOptions(
        environmentOptions.length > 0
          ? environmentOptions
          : dedupeOptions([
              ...(persistedEnvironmentId
                ? [{ value: persistedEnvironmentId, label: persistedEnvironmentId }]
                : []),
              ...(consoleSession.claims?.environmentId &&
              selectedProjectId &&
              consoleSession.claims.projectId === selectedProjectId
                ? [{
                    value: consoleSession.claims.environmentId,
                    label: consoleSession.claims.environmentId,
                  }]
                : []),
            ]),
      ),
      accountSettings: DASHBOARD_ACCOUNT_SETTINGS_OPTIONS.map((entry) => ({
        value: entry,
        label: entry,
      })),
    }),
    [
      consoleSession.claims,
      environmentOptions,
      organizationOption,
      persistedEnvironmentId,
      persistedProjectId,
      projectOptions,
      selectedProjectId,
    ],
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
      go(dashboardEntryRoute);
    }
  }, [dashboardEntryRoute, go, pathname]);

  React.useEffect(() => {
    if (
      pathname !== '/dashboard' &&
      pathname.startsWith('/dashboard/') &&
      !getRouteFromPathname(pathname)
    ) {
      go(dashboardEntryRoute);
    }
  }, [dashboardEntryRoute, go, pathname]);

  React.useEffect(() => {
    if (consoleSession.loading || consoleSession.claims) return;
    if (pathname === DASHBOARD_ONBOARDING_ROUTE) return;
    if (pathname === '/dashboard' || pathname.startsWith('/dashboard/')) {
      go(DASHBOARD_ONBOARDING_ROUTE);
    }
  }, [consoleSession.claims, consoleSession.loading, go, pathname]);

  const activeRoute = React.useMemo<DashboardRoute>(() => {
    const resolved = getRouteFromPathname(pathname);
    if (resolved) return resolved;
    if (pathname === '/dashboard') return dashboardEntryRoute;
    return DEFAULT_DASHBOARD_ROUTE;
  }, [dashboardEntryRoute, pathname]);

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
