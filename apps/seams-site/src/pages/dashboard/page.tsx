import React from 'react';
import { useTheme } from '@seams/sdk/react';
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
  type DashboardAccountOrganization,
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

function buildFallbackOptions(value: string, label?: string | null): TopbarOption[] {
  const normalizedValue = String(value || '').trim();
  if (!normalizedValue) return [];
  return [
    {
      value: normalizedValue,
      label: String(label || '').trim() || normalizedValue,
    },
  ];
}

function findPreferredOrganizationSummary(input: {
  organizations: DashboardAccountOrganization[];
  currentOrgId: string;
  preferredOrganizationId: string;
}): DashboardAccountOrganization | null {
  const { organizations, currentOrgId, preferredOrganizationId } = input;
  if (!organizations.length) return null;
  const currentMatch =
    (currentOrgId && organizations.find((entry) => entry.id === currentOrgId)) || null;
  if (currentMatch) return currentMatch;
  const preferredMatch =
    (preferredOrganizationId &&
      organizations.find((entry) => entry.id === preferredOrganizationId)) ||
    null;
  if (preferredMatch) return preferredMatch;
  return organizations.find((entry) => entry.isCurrentOrg) || organizations[0] || null;
}

function buildOrglessOnboardingState(): DashboardOnboardingState {
  return {
    orgId: '',
    organization: null,
    activeProjectCount: 0,
    activeEnvironmentCount: 0,
    activeApiKeyCount: 0,
    hasOrganization: false,
    hasProject: false,
    hasEnvironment: false,
    hasApiKey: false,
    accountReady: true,
    organizationReady: false,
    billingReady: false,
    projectReady: false,
    onboardingComplete: false,
    currentStep: 'organization',
    complete: false,
    selectedProjectId: null,
    selectedEnvironmentId: null,
  };
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
  const persistedOrganizationId = String(persistedSelectedContext.organization || '').trim();
  const persistedProjectId = String(persistedSelectedContext.project || '').trim();
  const persistedEnvironmentId = String(persistedSelectedContext.environment || '').trim();
  const [onboardingLoading, setOnboardingLoading] = React.useState<boolean>(false);
  const [onboardingState, setOnboardingState] = React.useState<DashboardOnboardingState | null>(
    null,
  );
  const [onboardingGateEnabled, setOnboardingGateEnabled] = React.useState<boolean>(true);
  const [logoutPending, setLogoutPending] = React.useState<boolean>(false);
  const [logoutErrorMessage, setLogoutErrorMessage] = React.useState<string>('');
  const [contextActionErrorMessage, setContextActionErrorMessage] = React.useState<string>('');
  const [accountOrganizations, setAccountOrganizations] = React.useState<DashboardAccountOrganization[]>(
    [],
  );
  const [accountOrganizationsResolved, setAccountOrganizationsResolved] = React.useState<boolean>(
    false,
  );
  const [pendingOrganizationContextOrgId, setPendingOrganizationContextOrgId] = React.useState<string>(
    '',
  );
  const [organizationOptions, setOrganizationOptions] = React.useState<TopbarOption[]>([]);
  const [projectOptions, setProjectOptions] = React.useState<TopbarOption[]>([]);
  const [selectedProjectId, setSelectedProjectId] = React.useState<string>(persistedProjectId);
  const [environmentOptions, setEnvironmentOptions] = React.useState<TopbarOption[]>([]);
  const organizationRecoveryAttemptRef = React.useRef<string>('');
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
  const onboardingStateOrgId = String(onboardingState?.orgId || '').trim();
  const onboardingSelectedProjectId = String(onboardingState?.selectedProjectId || '').trim();
  const onboardingSelectedEnvironmentId = String(
    onboardingState?.selectedEnvironmentId || '',
  ).trim();
  const onboardingSelectionMatchesCurrentOrg = Boolean(
    currentOrgId && onboardingStateOrgId === currentOrgId,
  );
  const scopedOnboardingSelectedProjectId = onboardingSelectionMatchesCurrentOrg
    ? onboardingSelectedProjectId
    : '';
  const scopedOnboardingSelectedEnvironmentId = onboardingSelectionMatchesCurrentOrg
    ? onboardingSelectedEnvironmentId
    : '';
  const persistedSelectionMatchesCurrentOrg = Boolean(
    currentOrgId && persistedOrganizationId === currentOrgId,
  );
  const scopedPersistedProjectId = persistedSelectionMatchesCurrentOrg ? persistedProjectId : '';
  const scopedPersistedEnvironmentId = persistedSelectionMatchesCurrentOrg
    ? persistedEnvironmentId
    : '';
  const currentOrganizationSummary = React.useMemo(
    () =>
      findPreferredOrganizationSummary({
        organizations: accountOrganizations,
        currentOrgId,
        preferredOrganizationId: persistedOrganizationId,
      }),
    [accountOrganizations, currentOrgId, persistedOrganizationId],
  );
  const currentOrganizationProjectId = String(
    currentOrganizationSummary?.selectedProjectId || '',
  ).trim();
  const currentOrganizationProjectLabel = String(
    currentOrganizationSummary?.selectedProjectName || '',
  ).trim();
  const currentOrganizationEnvironmentId = String(
    currentOrganizationSummary?.selectedEnvironmentId || '',
  ).trim();
  const currentOrganizationEnvironmentLabel = String(
    currentOrganizationSummary?.selectedEnvironmentName || '',
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
  const recoveryTargetOrgId = !currentOrgId
    ? String(currentOrganizationSummary?.id || '').trim()
    : '';
  const recoveryAttemptKey =
    recoveryTargetOrgId && consoleSession.claims?.userId
      ? `${consoleSession.claims.userId}:${recoveryTargetOrgId}`
      : '';
  const isRecoveringOrganizationContext =
    Boolean(consoleSession.claims) &&
    !currentOrgId &&
    (!accountOrganizationsResolved ||
      Boolean(pendingOrganizationContextOrgId) ||
      (Boolean(recoveryTargetOrgId) && organizationRecoveryAttemptRef.current !== recoveryAttemptKey));
  const isWaitingForCurrentOrgOnboardingState = Boolean(
    currentOrgId && onboardingGateEnabled && onboardingStateOrgId !== currentOrgId,
  );

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      setOnboardingLoading(false);
      setOnboardingState(null);
      setOnboardingGateEnabled(true);
      setAccountOrganizations([]);
      setAccountOrganizationsResolved(false);
      setPendingOrganizationContextOrgId('');
      setOrganizationOptions([]);
      setProjectOptions([]);
      setSelectedProjectId(persistedProjectId);
      setEnvironmentOptions([]);
      return;
    }
    if (!currentOrgId) {
      setOnboardingLoading(false);
      setOnboardingState(buildOrglessOnboardingState());
      setOnboardingGateEnabled(true);
      setSelectedProjectId('');
      setProjectOptions([]);
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
  }, [consoleSession.claims, currentOrgId, persistedProjectId]);

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
    if (isRecoveringOrganizationContext) return;
    if (isWaitingForCurrentOrgOnboardingState) return;
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
    isRecoveringOrganizationContext,
    isWaitingForCurrentOrgOnboardingState,
    onboardingGateEnabled,
    onboardingLoading,
    onboardingState,
    pathname,
  ]);

  const dashboardEntryRoute = React.useMemo<DashboardRoute>(() => {
    if (onboardingGateEnabled && onboardingState && hasConfiguredOrganization)
      return DEFAULT_DASHBOARD_ROUTE;
    return DASHBOARD_ONBOARDING_ROUTE;
  }, [
    hasConfiguredOrganization,
    onboardingGateEnabled,
    onboardingState,
  ]);

  React.useEffect(() => {
    const claims = consoleSession.claims;
    if (!claims) {
      setAccountOrganizationsResolved(false);
      return;
    }
    let cancelled = false;
    setAccountOrganizationsResolved(false);
    Promise.allSettled([
      listDashboardAccountOrganizations(),
      currentOrgId
        ? listDashboardProjects({ status: 'ACTIVE' })
        : Promise.resolve([]),
    ])
      .then(([organizationsResult, projectsResult]) => {
        if (cancelled) return;
        const organizations =
          organizationsResult.status === 'fulfilled' ? organizationsResult.value : [];
        const projects = projectsResult.status === 'fulfilled' ? projectsResult.value : [];
        const preferredOrganization = findPreferredOrganizationSummary({
          organizations,
          currentOrgId,
          preferredOrganizationId: persistedOrganizationId,
        });
        const preferredOrganizationProjectId = String(
          preferredOrganization?.selectedProjectId || '',
        ).trim();
        const preferredOrganizationProjectLabel = String(
          preferredOrganization?.selectedProjectName || '',
        ).trim();
        const hasScopedProjectFallback = Boolean(
          preferredOrganizationProjectId ||
            scopedOnboardingSelectedProjectId ||
            scopedPersistedProjectId,
        );
        setAccountOrganizations(organizations);
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
        setOrganizationOptions(nextOrganizationOptions);
        const nextProjectOptions = dedupeOptions(
          [
            ...projects.map((entry) => ({
              value: entry.id,
              label: entry.name || entry.id,
            })),
            ...buildFallbackOptions(
              preferredOrganizationProjectId,
              preferredOrganizationProjectLabel,
            ),
            ...buildFallbackOptions(scopedOnboardingSelectedProjectId),
            ...(scopedPersistedProjectId ? buildFallbackOptions(scopedPersistedProjectId) : []),
          ],
        );
        setProjectOptions(nextProjectOptions);
        const nextSelectedProjectId =
          (scopedOnboardingSelectedProjectId &&
            nextProjectOptions.find((entry) => entry.value === scopedOnboardingSelectedProjectId)
              ?.value) ||
          (preferredOrganizationProjectId &&
            nextProjectOptions.find((entry) => entry.value === preferredOrganizationProjectId)
              ?.value) ||
          (scopedPersistedProjectId &&
            nextProjectOptions.find((entry) => entry.value === scopedPersistedProjectId)?.value) ||
          nextProjectOptions[0]?.value ||
          scopedOnboardingSelectedProjectId ||
          preferredOrganizationProjectId ||
          scopedPersistedProjectId ||
          '';
        setSelectedProjectId(nextSelectedProjectId);
        setAccountOrganizationsResolved(true);
      })
      .catch(() => {
        if (cancelled) return;
        setAccountOrganizationsResolved(true);
      });
    return () => {
      cancelled = true;
    };
  }, [
    consoleSession.claims,
    currentOrgId,
    scopedOnboardingSelectedProjectId,
    pathname,
    persistedOrganizationId,
    scopedPersistedProjectId,
  ]);

  const switchOrganizationContext = React.useCallback(
    (nextOrgId: string, failurePrefix: string) => {
      const normalizedOrgId = String(nextOrgId || '').trim();
      if (!normalizedOrgId) return;
      setContextActionErrorMessage('');
      setPendingOrganizationContextOrgId(normalizedOrgId);
      void switchDashboardAccountOrganizationContext(normalizedOrgId)
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
          setPendingOrganizationContextOrgId('');
          setContextActionErrorMessage(
            `${failurePrefix}: ${error instanceof Error ? error.message : String(error)}`,
          );
        });
    },
    [consoleSession],
  );

  React.useEffect(() => {
    if (!consoleSession.claims) {
      organizationRecoveryAttemptRef.current = '';
      return;
    }
    if (currentOrgId) {
      organizationRecoveryAttemptRef.current = '';
      return;
    }
    if (!accountOrganizationsResolved) return;
    const preferredOrganizationId = recoveryTargetOrgId;
    if (!preferredOrganizationId) return;
    const recoveryKey = recoveryAttemptKey;
    if (organizationRecoveryAttemptRef.current === recoveryKey) return;
    organizationRecoveryAttemptRef.current = recoveryKey;
    switchOrganizationContext(preferredOrganizationId, 'Organization context recovery failed');
  }, [
    accountOrganizationsResolved,
    consoleSession.claims,
    currentOrgId,
    recoveryAttemptKey,
    recoveryTargetOrgId,
    switchOrganizationContext,
  ]);

  React.useEffect(() => {
    if (!consoleSession.claims) {
      setPendingOrganizationContextOrgId('');
      return;
    }
    if (!pendingOrganizationContextOrgId) return;
    if (currentOrgId === pendingOrganizationContextOrgId) {
      setPendingOrganizationContextOrgId('');
    }
  }, [consoleSession.claims, currentOrgId, pendingOrganizationContextOrgId]);

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
    if (!currentOrgId) {
      setEnvironmentOptions(
        dedupeOptions(
          currentOrganizationProjectId === projectId
            ? buildFallbackOptions(
                currentOrganizationEnvironmentId,
                currentOrganizationEnvironmentLabel,
              )
            : [],
        ),
      );
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
          ...(currentOrganizationProjectId === projectId
            ? buildFallbackOptions(
                currentOrganizationEnvironmentId,
                currentOrganizationEnvironmentLabel,
              )
            : []),
          ...(scopedOnboardingSelectedProjectId === projectId
            ? buildFallbackOptions(scopedOnboardingSelectedEnvironmentId)
            : []),
        ]);
        setEnvironmentOptions(nextEnvironmentOptions);
      })
      .catch(() => {
        if (cancelled) return;
        setEnvironmentOptions(
          dedupeOptions([
            ...buildFallbackOptions(scopedPersistedEnvironmentId),
            ...(currentOrganizationProjectId === projectId
              ? buildFallbackOptions(
                  currentOrganizationEnvironmentId,
                  currentOrganizationEnvironmentLabel,
                )
              : []),
            ...(scopedOnboardingSelectedProjectId === projectId
              ? buildFallbackOptions(scopedOnboardingSelectedEnvironmentId)
              : []),
          ]),
        );
      });
    return () => {
      cancelled = true;
    };
  }, [
    consoleSession.claims,
    currentOrgId,
    scopedOnboardingSelectedEnvironmentId,
    scopedOnboardingSelectedProjectId,
    currentOrganizationEnvironmentId,
    currentOrganizationEnvironmentLabel,
    currentOrganizationProjectId,
    scopedPersistedEnvironmentId,
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
              ...(scopedOnboardingSelectedProjectId
                ? [
                    {
                      value: scopedOnboardingSelectedProjectId,
                      label: scopedOnboardingSelectedProjectId,
                    },
                  ]
                : []),
            ]),
      ),
      environment: dedupeOptions(
        environmentOptions.length > 0
          ? environmentOptions
          : dedupeOptions([
              ...(scopedOnboardingSelectedEnvironmentId &&
              selectedProjectId &&
              scopedOnboardingSelectedProjectId === selectedProjectId
                ? [
                    {
                      value: scopedOnboardingSelectedEnvironmentId,
                      label: scopedOnboardingSelectedEnvironmentId,
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
      scopedOnboardingSelectedEnvironmentId,
      scopedOnboardingSelectedProjectId,
      organizationOptions,
      projectOptions,
      resolvedTheme,
      selectedProjectId,
    ],
  );

  const defaultTopbarContext = React.useMemo<TopbarContextState>(() => {
    const preferredProjectId = String(
      selectedProjectId || currentOrganizationProjectId || scopedOnboardingSelectedProjectId || '',
    ).trim();
    const projectValue =
      dropdownOptions.project.find((entry) => entry.value === preferredProjectId)?.value ||
      dropdownOptions.project[0]?.value ||
      preferredProjectId;
    const preferredEnvironmentId = String(
      (projectValue && currentOrganizationProjectId === projectValue
        ? currentOrganizationEnvironmentId || ''
        : '') ||
        (projectValue && scopedOnboardingSelectedProjectId === projectValue
          ? scopedOnboardingSelectedEnvironmentId || ''
          : ''),
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
    currentOrganizationEnvironmentId,
    currentOrganizationProjectId,
    dropdownOptions,
    scopedOnboardingSelectedEnvironmentId,
    scopedOnboardingSelectedProjectId,
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
    if (!consoleSession.claims) return;
    if (currentOrgId) return;
    if (accountOrganizations.length > 0) return;
    const hasStaleScope =
      String(selectedContext.organization || '').trim().length > 0 ||
      String(selectedContext.project || '').trim().length > 0 ||
      String(selectedContext.environment || '').trim().length > 0;
    if (!hasStaleScope) return;
    replaceDashboardSelectedContext({
      organization: '',
      project: '',
      environment: '',
    });
  }, [
    accountOrganizations.length,
    consoleSession.claims,
    currentOrgId,
    selectedContext.environment,
    selectedContext.organization,
    selectedContext.project,
  ]);

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
        switchOrganizationContext(nextOrgId, 'Organization switch failed');
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
      dropdownOptions.environment,
      go,
      logoutPending,
      onSelectContextRaw,
      resolvedTheme,
      setTheme,
      switchOrganizationContext,
    ],
  );

  React.useEffect(() => {
    if (!consoleSession.claims) return;
    if (onboardingGateEnabled && onboardingLoading) return;
    if (isWaitingForCurrentOrgOnboardingState) return;
    if (onboardingGateEnabled && !onboardingState) return;
    if (isRecoveringOrganizationContext) return;
    if (pathname === '/dashboard') {
      go(dashboardEntryRoute);
    }
  }, [
    consoleSession.claims,
    dashboardEntryRoute,
    go,
    isRecoveringOrganizationContext,
    isWaitingForCurrentOrgOnboardingState,
    onboardingGateEnabled,
    onboardingLoading,
    onboardingState,
    pathname,
  ]);

  React.useEffect(() => {
    if (!consoleSession.claims) return;
    if (onboardingGateEnabled && onboardingLoading) return;
    if (isWaitingForCurrentOrgOnboardingState) return;
    if (onboardingGateEnabled && !onboardingState) return;
    if (isRecoveringOrganizationContext) return;
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
    isRecoveringOrganizationContext,
    isWaitingForCurrentOrgOnboardingState,
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
  const shellClassName = `dashboard-shell dashboard-shell--route-${activeView.key}${focusedOnboardingMode ? ' dashboard-shell--onboarding-focus' : ''}${isSidebarCollapsed ? ' dashboard-shell--sidebar-collapsed' : ''}${isSidebarCollapsedSettled ? ' dashboard-shell--sidebar-collapsed-settled' : ''}`;
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
