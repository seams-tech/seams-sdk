import React from 'react';
import { useTheme } from '@tatchi-xyz/sdk/react';
import DashboardSidebar from './layout/DashboardSidebar';
import DashboardTopbar from './layout/DashboardTopbar';
import {
  DASHBOARD_ACCOUNT_SETTINGS_ACCOUNT_OPTION,
  DASHBOARD_ACCOUNT_SETTINGS_THEME_TOGGLE_OPTION,
  DASHBOARD_ACCOUNT_SETTINGS_SIGN_OUT_OPTION,
  DASHBOARD_ACCOUNT_SETTINGS_OPTIONS,
  DEFAULT_DASHBOARD_ROUTE,
  getRouteFromPathname,
  getViewForRoute,
  SIDEBAR_GROUPS,
} from './dashboardConfig';
import type { DashboardRoute, TopbarContextState, TopbarMenuKey, TopbarOption } from './types';
import {
  DashboardConsoleSessionProvider,
  revokeDashboardConsoleSession,
  useDashboardConsoleSession,
} from './consoleSession';
import { DashboardSelectedContextProvider } from './selectedContext';
import {
  listDashboardEnvironments,
  listDashboardProjects,
} from './consoleContextApi';
import {
  getDashboardOnboardingState,
  isDashboardConsoleApiErrorCode,
  type DashboardOnboardingState,
} from './routes/onboarding/consoleOnboardingApi';
import {
  clearDashboardUiState,
  readPersistedDashboardSelectedContext,
  replaceDashboardSelectedContext,
  useDashboardUiPreferences,
} from './useDashboardUiPreferences';
import { isDashboardDefaultOrganizationName } from './utils/organizationIdentity';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import {
  listDashboardAccountOrganizations,
  switchDashboardAccountOrganizationContext,
} from './routes/account-settings/consoleAccountApi';
import './styles.css';

type DashboardPageProps = {
  pathname?: string;
};

const DASHBOARD_ONBOARDING_ROUTE: DashboardRoute = '/dashboard/onboarding';
const DASHBOARD_ACCOUNT_SETTINGS_ROUTE: DashboardRoute = '/dashboard/account-settings';
const PLATFORM_BILLING_ROUTE: DashboardRoute = '/platform/billing';
const DASHBOARD_LOGIN_ROUTE = '/dashboard/login';
const DASHBOARD_ONBOARDING_STATE_UPDATED_EVENT = 'dashboard:onboarding-state-updated';
const LOCKED_PRODUCTION_OPTION_PREFIX = '__production_locked__:';
const SIDEBAR_COLLAPSE_SETTLE_MS = 280;

function isSelectableOption(option: TopbarOption): boolean {
  return option.disabled !== true;
}

function dedupeOptions(options: TopbarOption[]): TopbarOption[] {
  const seen = new Map<string, number>();
  const deduped: TopbarOption[] = [];
  for (const option of options) {
    const value = String(option.value || '').trim();
    if (!value) continue;
    const normalized: TopbarOption = {
      value,
      label: String(option.label || value).trim() || value,
      ...(option.disabled === true ? { disabled: true } : {}),
    };
    const existingIndex = seen.get(value);
    if (existingIndex === undefined) {
      seen.set(value, deduped.length);
      deduped.push(normalized);
      continue;
    }
    const existing = deduped[existingIndex];
    if (existing.disabled === true && normalized.disabled !== true) {
      deduped[existingIndex] = normalized;
      continue;
    }
    if ((existing.label === value || !existing.label) && normalized.label !== value) {
      deduped[existingIndex] = { ...existing, label: normalized.label };
    }
  }
  return deduped;
}

function DashboardPageInner({ pathname = '/dashboard' }: DashboardPageProps): React.JSX.Element {
  const { theme, setTheme } = useTheme();
  const { go, linkProps } = useSiteRouter();
  const homeProps = linkProps('/');
  const consoleSession = useDashboardConsoleSession();
  const persistedSelectedContext = React.useMemo(
    () => readPersistedDashboardSelectedContext(),
    [pathname],
  );
  const persistedProjectId = String(persistedSelectedContext.project || '').trim();
  const [onboardingLoading, setOnboardingLoading] = React.useState<boolean>(false);
  const [onboardingState, setOnboardingState] = React.useState<DashboardOnboardingState | null>(
    null,
  );
  const [onboardingGateEnabled, setOnboardingGateEnabled] = React.useState<boolean>(true);
  const [logoutPending, setLogoutPending] = React.useState<boolean>(false);
  const [logoutErrorMessage, setLogoutErrorMessage] = React.useState<string>('');
  const [contextActionErrorMessage, setContextActionErrorMessage] = React.useState<string>('');
  const [organizationOptions, setOrganizationOptions] = React.useState<TopbarOption[]>([]);
  const [projectOptions, setProjectOptions] = React.useState<TopbarOption[]>([]);
  const [selectedProjectId, setSelectedProjectId] = React.useState<string>(persistedProjectId);
  const [environmentOptions, setEnvironmentOptions] = React.useState<TopbarOption[]>([]);
  const onboardingComplete = onboardingState
    ? onboardingState.onboardingComplete === undefined
      ? onboardingState.complete === true
      : onboardingState.onboardingComplete
    : false;
  const hasExistingOrganization = onboardingState?.hasOrganization === true;
  const resolvedTheme: 'light' | 'dark' = theme === 'light' ? 'light' : 'dark';
  const sessionForbidden =
    !consoleSession.loading &&
    !consoleSession.claims &&
    (consoleSession.errorCode === 'forbidden' || consoleSession.errorStatus === 403);
  const currentOrgId = String(consoleSession.claims?.orgId || '').trim();
  const onboardingSelectedProjectId = String(onboardingState?.selectedProjectId || '').trim();
  const onboardingSelectedEnvironmentId = String(
    onboardingState?.selectedEnvironmentId || '',
  ).trim();
  const onboardingOrganizationName = String(onboardingState?.organization?.name || '').trim();
  const onboardingOrganizationId = String(
    onboardingState?.orgId || consoleSession.claims?.orgId || '',
  ).trim();
  const onboardingHasConfiguredOrganizationName =
    onboardingOrganizationName.length > 0 &&
    !isDashboardDefaultOrganizationName({
      name: onboardingOrganizationName,
      orgId: onboardingOrganizationId,
    });
  const hasConfiguredOrganization = hasExistingOrganization && onboardingHasConfiguredOrganizationName;
  const focusedOnboardingOrganizationValue = onboardingHasConfiguredOrganizationName
    ? onboardingOrganizationName
    : '';
  const billingReady = onboardingState?.billingReady === true;
  const isPlatformRoute = pathname === PLATFORM_BILLING_ROUTE || pathname.startsWith('/platform/');
  const isPlatformAdmin = React.useMemo(
    () =>
      (consoleSession.claims?.roles || []).some(
        (role) =>
          String(role || '')
            .trim()
            .toLowerCase() === 'platform_admin',
      ),
    [consoleSession.claims?.roles],
  );
  const isSidebarNavigationLocked =
    !isPlatformRoute &&
    onboardingGateEnabled &&
    (onboardingLoading ||
      !onboardingState ||
      onboardingState.hasOrganization !== true ||
      onboardingState.hasProject !== true);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      setOnboardingLoading(false);
      setOnboardingState(null);
      setOnboardingGateEnabled(true);
      setOrganizationOptions([]);
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
    if (typeof window === 'undefined') return;
    const expectedOrgId = String(consoleSession.claims?.orgId || '').trim();
    if (!expectedOrgId) return;

    const onOnboardingStateUpdated = (event: Event) => {
      const custom = event as CustomEvent<DashboardOnboardingState | null>;
      const detail = custom.detail;
      if (!detail || typeof detail !== 'object') return;
      const nextOrgId = String(detail.orgId || '').trim();
      if (!nextOrgId || nextOrgId !== expectedOrgId) return;
      setOnboardingState(detail);
      setOnboardingGateEnabled(true);
      setOnboardingLoading(false);
    };

    window.addEventListener(
      DASHBOARD_ONBOARDING_STATE_UPDATED_EVENT,
      onOnboardingStateUpdated as EventListener,
    );
    return () => {
      window.removeEventListener(
        DASHBOARD_ONBOARDING_STATE_UPDATED_EVENT,
        onOnboardingStateUpdated as EventListener,
      );
    };
  }, [consoleSession.claims?.orgId]);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) return;
    if (consoleSession.loading || onboardingLoading) return;
    if (!onboardingGateEnabled || !onboardingState) return;
    const isOnboardingRoute = pathname === DASHBOARD_ONBOARDING_ROUTE;
    const isAccountSettingsRoute = pathname === DASHBOARD_ACCOUNT_SETTINGS_ROUTE;
    const isPlatformBillingRoute = pathname === PLATFORM_BILLING_ROUTE;
    if (
      !hasConfiguredOrganization &&
      !isOnboardingRoute &&
      !isAccountSettingsRoute &&
      !isPlatformBillingRoute
    ) {
      go(DASHBOARD_ONBOARDING_ROUTE);
    }
  }, [
    consoleSession.claims,
    consoleSession.loading,
    go,
    hasConfiguredOrganization,
    onboardingGateEnabled,
    onboardingLoading,
    onboardingState,
    pathname,
  ]);

  const dashboardEntryRoute = React.useMemo<DashboardRoute>(() => {
    if (onboardingGateEnabled && onboardingState && hasConfiguredOrganization)
      return DEFAULT_DASHBOARD_ROUTE;
    return DASHBOARD_ONBOARDING_ROUTE;
  }, [hasConfiguredOrganization, onboardingGateEnabled, onboardingState]);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      return;
    }
    let cancelled = false;
    Promise.all([
      listDashboardAccountOrganizations(),
      listDashboardProjects({ status: 'ACTIVE' }),
    ])
      .then(([organizations, projects]) => {
        if (cancelled) return;
        const nextOrganizationOptions = dedupeOptions(
          organizations
            .filter((entry) => {
              const status = String(entry.status || '')
                .trim()
                .toUpperCase();
              return status === 'ACTIVE' || entry.isCurrentOrg;
            })
            .sort((left, right) => {
              if (left.isCurrentOrg !== right.isCurrentOrg) {
                return left.isCurrentOrg ? -1 : 1;
              }
              const nameDiff = (left.name || left.id).localeCompare(right.name || right.id);
              if (nameDiff !== 0) return nameDiff;
              return left.id.localeCompare(right.id);
            })
            .map((entry) => ({
              value: entry.id,
              label: entry.name || entry.id,
            })),
        );
        setOrganizationOptions(
          nextOrganizationOptions,
        );
        const nextProjectOptions = dedupeOptions(
          projects.map((entry) => ({
            value: entry.id,
            label: entry.name || entry.id,
          })),
        );
        setProjectOptions(nextProjectOptions);
        const nextSelectedProjectId =
          (onboardingSelectedProjectId &&
            nextProjectOptions.find((entry) => entry.value === onboardingSelectedProjectId)
              ?.value) ||
          nextProjectOptions[0]?.value ||
          onboardingSelectedProjectId ||
          '';
        setSelectedProjectId(nextSelectedProjectId);
      })
      .catch(() => {
        if (cancelled) return;
        const persisted = readPersistedDashboardSelectedContext();
        const preferredProjectId = String(persisted.project || '').trim();
        setOrganizationOptions([]);
        const fallbackProjects = dedupeOptions([
          ...(preferredProjectId ? [{ value: preferredProjectId, label: preferredProjectId }] : []),
          ...(onboardingSelectedProjectId
            ? [{ value: onboardingSelectedProjectId, label: onboardingSelectedProjectId }]
            : []),
        ]);
        setProjectOptions(fallbackProjects);
        setSelectedProjectId(preferredProjectId || onboardingSelectedProjectId || '');
      });
    return () => {
      cancelled = true;
    };
  }, [consoleSession.claims, onboardingSelectedProjectId, pathname]);

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
    listDashboardEnvironments({ projectId })
      .then((environments) => {
        if (cancelled) return;
        const visibleEnvironmentRows = environments
          .filter((entry) => {
            const status = String(entry.status || '')
              .trim()
              .toUpperCase();
            if (status === 'ARCHIVED') return false;
            if (status === 'ACTIVE') return true;
            return (
              String(entry.key || '')
                .trim()
                .toLowerCase() === 'prod'
            );
          })
          .sort((left, right) => {
            const leftDisabled =
              String(left.status || '')
                .trim()
                .toUpperCase() !== 'ACTIVE';
            const rightDisabled =
              String(right.status || '')
                .trim()
                .toUpperCase() !== 'ACTIVE';
            if (leftDisabled === rightDisabled) return 0;
            return leftDisabled ? 1 : -1;
          });
        const hasProductionEnvironment = visibleEnvironmentRows.some(
          (entry) =>
            String(entry.key || '')
              .trim()
              .toLowerCase() === 'prod',
        );
        const nextEnvironmentOptions = dedupeOptions([
          ...visibleEnvironmentRows.map((entry) => ({
            value: entry.id,
            label: entry.name || entry.id,
            disabled:
              String(entry.status || '')
                .trim()
                .toUpperCase() !== 'ACTIVE',
          })),
          ...(!billingReady && !hasProductionEnvironment
            ? [
                {
                  value: `${LOCKED_PRODUCTION_OPTION_PREFIX}${projectId}`,
                  label: 'Production',
                  disabled: true,
                },
              ]
            : []),
        ]);
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
            ...(onboardingSelectedProjectId === projectId && onboardingSelectedEnvironmentId
              ? [{ value: onboardingSelectedEnvironmentId, label: onboardingSelectedEnvironmentId }]
              : []),
          ]),
        );
      });
    return () => {
      cancelled = true;
    };
  }, [
    consoleSession.claims,
    onboardingSelectedEnvironmentId,
    onboardingSelectedProjectId,
    selectedProjectId,
    billingReady,
  ]);

  const dropdownOptions = React.useMemo<Record<TopbarMenuKey, TopbarOption[]>>(
    () => ({
      organization: dedupeOptions(organizationOptions),
      project: dedupeOptions(
        projectOptions.length > 0
          ? projectOptions
          : dedupeOptions([
              ...(onboardingSelectedProjectId
                ? [{ value: onboardingSelectedProjectId, label: onboardingSelectedProjectId }]
                : []),
            ]),
      ),
      environment: dedupeOptions(
        environmentOptions.length > 0
          ? environmentOptions
          : dedupeOptions([
              ...(onboardingSelectedEnvironmentId &&
              selectedProjectId &&
              onboardingSelectedProjectId === selectedProjectId
                ? [
                    {
                      value: onboardingSelectedEnvironmentId,
                      label: onboardingSelectedEnvironmentId,
                    },
                  ]
                : []),
            ]),
      ),
      accountSettings: DASHBOARD_ACCOUNT_SETTINGS_OPTIONS.map((entry): TopbarOption => {
        if (entry === DASHBOARD_ACCOUNT_SETTINGS_THEME_TOGGLE_OPTION) {
          return {
            value: entry,
            label: 'Toggle Theme',
            keepMenuOpen: true,
            icon: resolvedTheme === 'dark' ? 'sun' : 'moon',
          };
        }
        return {
          value: entry,
          label: entry,
        };
      }),
    }),
    [
      consoleSession.claims,
      environmentOptions,
      onboardingSelectedEnvironmentId,
      onboardingSelectedProjectId,
      organizationOptions,
      persistedProjectId,
      projectOptions,
      resolvedTheme,
      selectedProjectId,
    ],
  );

  const defaultTopbarContext = React.useMemo<TopbarContextState>(() => {
    const preferredProjectId = String(
      selectedProjectId || onboardingSelectedProjectId || '',
    ).trim();
    const projectValue =
      dropdownOptions.project.find((entry) => entry.value === preferredProjectId)?.value ||
      dropdownOptions.project[0]?.value ||
      preferredProjectId;
    const preferredEnvironmentId = String(
      projectValue && onboardingSelectedProjectId === projectValue
        ? onboardingSelectedEnvironmentId || ''
        : '',
    ).trim();
    const preferredEnvironmentOption = dropdownOptions.environment.find(
      (entry) => entry.value === preferredEnvironmentId && isSelectableOption(entry),
    );
    const firstSelectableEnvironmentOption = dropdownOptions.environment.find((entry) =>
      isSelectableOption(entry),
    );
    return {
      organization: dropdownOptions.organization[0]?.value || consoleSession.claims?.orgId || '',
      project: projectValue,
      environment:
        preferredEnvironmentOption?.value ||
        firstSelectableEnvironmentOption?.value ||
        (dropdownOptions.environment.length === 0 ? preferredEnvironmentId : ''),
      accountSettings: dropdownOptions.accountSettings[0]?.value || '',
    };
  }, [
    consoleSession.claims,
    dropdownOptions,
    onboardingSelectedEnvironmentId,
    onboardingSelectedProjectId,
    selectedProjectId,
  ]);

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

  const selectedContextDisplay = React.useMemo<TopbarContextState>(
    () => ({
      organization:
        dropdownOptions.organization.find((entry) => entry.value === selectedContext.organization)
          ?.label || '',
      project:
        dropdownOptions.project.find((entry) => entry.value === selectedContext.project)?.label ||
        selectedContext.project ||
        '',
      environment:
        dropdownOptions.environment.find((entry) => entry.value === selectedContext.environment)
          ?.label ||
        selectedContext.environment ||
        '',
      accountSettings:
        dropdownOptions.accountSettings.find(
          (entry) => entry.value === selectedContext.accountSettings,
        )?.label ||
        selectedContext.accountSettings ||
        '',
    }),
    [dropdownOptions, selectedContext],
  );

  React.useEffect(() => {
    if (!currentOrgId) return;
    if (selectedContext.organization === currentOrgId) return;
    onSelectContextRaw('organization', currentOrgId);
  }, [currentOrgId, onSelectContextRaw, selectedContext.organization]);

  React.useEffect(() => {
    const project = String(selectedContext.project || '').trim();
    if (!project || project === selectedProjectId) return;
    setSelectedProjectId(project);
  }, [selectedContext.project, selectedProjectId]);

  const onSelectContext = React.useCallback(
    (menu: TopbarMenuKey, value: string) => {
      if (menu === 'organization') {
        const nextOrgId = String(value || '').trim();
        if (!nextOrgId) return;
        setContextActionErrorMessage('');
        if (!currentOrgId || nextOrgId === currentOrgId) {
          onSelectContextRaw(menu, nextOrgId);
          return;
        }
        void switchDashboardAccountOrganizationContext(nextOrgId)
          .then((nextContext) => {
            clearDashboardUiState();
            replaceDashboardSelectedContext({
              organization: nextContext.orgId,
              project: nextContext.projectId || '',
              environment: nextContext.environmentId || '',
            });
            setSelectedProjectId(nextContext.projectId || '');
            consoleSession.refresh();
          })
          .catch((error: unknown) => {
            setContextActionErrorMessage(
              `Organization switch failed: ${error instanceof Error ? error.message : String(error)}`,
            );
          });
        return;
      }
      if (menu === 'accountSettings' && value === DASHBOARD_ACCOUNT_SETTINGS_ACCOUNT_OPTION) {
        go(DASHBOARD_ACCOUNT_SETTINGS_ROUTE);
        return;
      }
      if (menu === 'accountSettings' && value === DASHBOARD_ACCOUNT_SETTINGS_THEME_TOGGLE_OPTION) {
        if (typeof setTheme === 'function') {
          setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
        }
        return;
      }
      if (menu === 'accountSettings' && value === DASHBOARD_ACCOUNT_SETTINGS_SIGN_OUT_OPTION) {
        if (logoutPending) return;
        setLogoutPending(true);
        setLogoutErrorMessage('');
        void revokeDashboardConsoleSession()
          .then(() => {
            clearDashboardUiState();
            consoleSession.refresh();
            go(DASHBOARD_LOGIN_ROUTE);
          })
          .catch((error: unknown) => {
            setLogoutErrorMessage(error instanceof Error ? error.message : String(error));
          })
          .finally(() => {
            setLogoutPending(false);
          });
        return;
      }
      if (
        menu === 'environment' &&
        (String(value || '')
          .trim()
          .startsWith(LOCKED_PRODUCTION_OPTION_PREFIX) ||
          dropdownOptions.environment.find((entry) => entry.value === value)?.disabled === true)
      ) {
        go('/dashboard/billing/account?billing=production_required');
        return;
      }
      onSelectContextRaw(menu, value);
      if (menu === 'project') {
        setSelectedProjectId(value);
      }
    },
    [
      currentOrgId,
      consoleSession,
      dropdownOptions.environment,
      go,
      logoutPending,
      onSelectContextRaw,
      resolvedTheme,
      setTheme,
    ],
  );

  React.useEffect(() => {
    if (!consoleSession.claims) return;
    if (onboardingGateEnabled && onboardingLoading) return;
    if (onboardingGateEnabled && !onboardingState) return;
    if (pathname === '/dashboard') {
      go(dashboardEntryRoute);
    }
  }, [
    consoleSession.claims,
    dashboardEntryRoute,
    go,
    onboardingGateEnabled,
    onboardingLoading,
    onboardingState,
    pathname,
  ]);

  React.useEffect(() => {
    if (!consoleSession.claims) return;
    if (onboardingGateEnabled && onboardingLoading) return;
    if (onboardingGateEnabled && !onboardingState) return;
    if (
      pathname !== '/dashboard' &&
      (pathname.startsWith('/dashboard/') || pathname.startsWith('/platform/')) &&
      !getRouteFromPathname(pathname)
    ) {
      go(dashboardEntryRoute);
    }
  }, [
    consoleSession.claims,
    dashboardEntryRoute,
    go,
    onboardingGateEnabled,
    onboardingLoading,
    onboardingState,
    pathname,
  ]);

  React.useEffect(() => {
    if (consoleSession.loading || consoleSession.claims) return;
    if (sessionForbidden) return;
    if (
      pathname === '/dashboard' ||
      pathname.startsWith('/dashboard/') ||
      pathname.startsWith('/platform/')
    ) {
      go(DASHBOARD_LOGIN_ROUTE);
    }
  }, [consoleSession.claims, consoleSession.loading, go, pathname, sessionForbidden]);

  const activeRoute = React.useMemo<DashboardRoute>(() => {
    const resolved = getRouteFromPathname(pathname);
    if (resolved) return resolved;
    if (pathname === '/dashboard') return dashboardEntryRoute;
    return DEFAULT_DASHBOARD_ROUTE;
  }, [dashboardEntryRoute, pathname]);

  const activeView = React.useMemo(() => getViewForRoute(activeRoute), [activeRoute]);
  const ActiveViewComponent = activeView.component;
  const onboardingRouteActive = activeRoute === DASHBOARD_ONBOARDING_ROUTE;
  const focusedOnboardingMode = onboardingRouteActive;
  const isSidebarCollapsed = !focusedOnboardingMode && !isSidebarExpanded;
  const [isSidebarCollapsedSettled, setIsSidebarCollapsedSettled] = React.useState<boolean>(
    isSidebarCollapsed,
  );
  const wasSidebarCollapsedRef = React.useRef<boolean>(isSidebarCollapsed);

  React.useEffect(() => {
    const wasSidebarCollapsed = wasSidebarCollapsedRef.current;
    wasSidebarCollapsedRef.current = isSidebarCollapsed;

    if (!isSidebarCollapsed) {
      setIsSidebarCollapsedSettled(false);
      return;
    }
    if (wasSidebarCollapsed) {
      setIsSidebarCollapsedSettled(true);
      return;
    }

    setIsSidebarCollapsedSettled(false);
    const timeoutId = window.setTimeout(() => {
      setIsSidebarCollapsedSettled(true);
    }, SIDEBAR_COLLAPSE_SETTLE_MS);
    return () => window.clearTimeout(timeoutId);
  }, [isSidebarCollapsed]);

  const sidebarExpanded = focusedOnboardingMode ? true : isSidebarExpanded;
  const shellClassName = `dashboard-shell${focusedOnboardingMode ? ' dashboard-shell--onboarding-focus' : ''}${isSidebarCollapsed ? ' dashboard-shell--sidebar-collapsed' : ''}${isSidebarCollapsedSettled ? ' dashboard-shell--sidebar-collapsed-settled' : ''}`;
  const navigationLockExemptPaths = React.useMemo<ReadonlySet<DashboardRoute>>(
    () =>
      new Set<DashboardRoute>(
        isPlatformAdmin
          ? [DASHBOARD_ACCOUNT_SETTINGS_ROUTE, PLATFORM_BILLING_ROUTE]
          : [DASHBOARD_ACCOUNT_SETTINGS_ROUTE],
      ),
    [isPlatformAdmin],
  );
  const visibleSidebarGroups = React.useMemo(
    () => SIDEBAR_GROUPS.filter((group) => group.key !== 'platform' || isPlatformAdmin),
    [isPlatformAdmin],
  );

  return (
    <main className={shellClassName} aria-label="Dashboard workspace">
      <DashboardTopbar
        isSidebarExpanded={isSidebarExpanded}
        onToggleSidebar={toggleSidebar}
        homeProps={homeProps}
        selectedContext={selectedContext}
        onSelectContext={onSelectContext}
        dropdownOptions={dropdownOptions}
        focusedMode={focusedOnboardingMode}
        focusedContextValue={focusedOnboardingMode ? focusedOnboardingOrganizationValue : undefined}
      />

      <DashboardSidebar
        groups={visibleSidebarGroups}
        isSidebarExpanded={sidebarExpanded}
        expandedGroups={expandedGroups}
        activeRoute={activeRoute}
        disableNavigationItems={isSidebarNavigationLocked}
        enabledWhenLockedPaths={navigationLockExemptPaths}
        onToggleGroup={toggleGroup}
        linkProps={linkProps}
      />

      <section className="dashboard-main" aria-labelledby="dashboard-main-title">
        <h1 id="dashboard-main-title" className="dashboard-main__title">
          {activeView.label}
        </h1>
        {isSidebarNavigationLocked ? (
          <p className="dashboard-lock-banner" role="status">
            Finish organization + project setup to unlock navigation.
          </p>
        ) : null}
        {sessionForbidden ? (
          <p className="dashboard-table-limit" role="alert">
            Access to this dashboard is forbidden for your current session.
          </p>
        ) : null}
        {logoutErrorMessage ? (
          <p className="dashboard-table-limit" role="alert">
            Sign out failed: {logoutErrorMessage}
          </p>
        ) : null}
        {contextActionErrorMessage ? (
          <p className="dashboard-table-limit" role="alert">
            {contextActionErrorMessage}
          </p>
        ) : null}

        <DashboardSelectedContextProvider
          value={selectedContext}
          displayValue={selectedContextDisplay}
        >
          <ActiveViewComponent />
        </DashboardSelectedContextProvider>
      </section>
      <div className="dashboard-overlay-layer" aria-hidden="true" />
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
