import React from 'react';
import {
  DASHBOARD_TOPBAR_DROPDOWN_OPTIONS,
  DEFAULT_EXPANDED_SIDEBAR_GROUPS,
  DEFAULT_TOPBAR_CONTEXT_STATE,
  SIDEBAR_GROUP_KEYS,
} from './dashboardConfig';
import type {
  ExpandedSidebarGroupsState,
  SidebarGroupKey,
  TopbarContextState,
  TopbarMenuKey,
} from './types';

const UI_STATE_STORAGE_KEY = 'tatchi-dashboard-ui-state-v1';

const QUERY_KEYS = {
  sidebarExpanded: 'db_sb',
  expandedGroups: 'db_groups',
  organization: 'db_org',
  project: 'db_project',
  environment: 'db_env',
  accountSettings: 'db_acct',
} as const;

type PersistedUiState = {
  isSidebarExpanded: boolean;
  expandedGroups: ExpandedSidebarGroupsState;
  selectedContext: TopbarContextState;
};

function isTopbarOption(menu: TopbarMenuKey, value: string): boolean {
  return DASHBOARD_TOPBAR_DROPDOWN_OPTIONS[menu].includes(value);
}

function sanitizeSelectedContext(
  input: Partial<TopbarContextState> | undefined,
): TopbarContextState {
  return {
    organization:
      input?.organization && isTopbarOption('organization', input.organization)
        ? input.organization
        : DEFAULT_TOPBAR_CONTEXT_STATE.organization,
    project:
      input?.project && isTopbarOption('project', input.project)
        ? input.project
        : DEFAULT_TOPBAR_CONTEXT_STATE.project,
    environment:
      input?.environment && isTopbarOption('environment', input.environment)
        ? input.environment
        : DEFAULT_TOPBAR_CONTEXT_STATE.environment,
    accountSettings:
      input?.accountSettings && isTopbarOption('accountSettings', input.accountSettings)
        ? input.accountSettings
        : DEFAULT_TOPBAR_CONTEXT_STATE.accountSettings,
  };
}

function sanitizeExpandedGroups(
  input: Partial<ExpandedSidebarGroupsState> | undefined,
): ExpandedSidebarGroupsState {
  return {
    walletInfrastructure:
      input?.walletInfrastructure ?? DEFAULT_EXPANDED_SIDEBAR_GROUPS.walletInfrastructure,
    securityPolicy: input?.securityPolicy ?? DEFAULT_EXPANDED_SIDEBAR_GROUPS.securityPolicy,
    integrationsAutomation:
      input?.integrationsAutomation ?? DEFAULT_EXPANDED_SIDEBAR_GROUPS.integrationsAutomation,
    environmentSettings:
      input?.environmentSettings ?? DEFAULT_EXPANDED_SIDEBAR_GROUPS.environmentSettings,
  };
}

function readStoredState(): Partial<PersistedUiState> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(UI_STATE_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Partial<PersistedUiState>;
    return {
      isSidebarExpanded:
        typeof parsed.isSidebarExpanded === 'boolean' ? parsed.isSidebarExpanded : undefined,
      expandedGroups: sanitizeExpandedGroups(parsed.expandedGroups),
      selectedContext: sanitizeSelectedContext(parsed.selectedContext),
    };
  } catch {
    return {};
  }
}

function parseExpandedGroupsParam(
  raw: string | null,
): Partial<ExpandedSidebarGroupsState> | undefined {
  if (!raw) return undefined;
  const active = new Set(
    raw
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean),
  );
  const result: Partial<ExpandedSidebarGroupsState> = {};
  for (const key of SIDEBAR_GROUP_KEYS) {
    result[key] = active.has(key);
  }
  return result;
}

function readUrlState(): Partial<PersistedUiState> {
  if (typeof window === 'undefined') return {};
  const params = new URLSearchParams(window.location.search);

  const sidebarExpandedRaw = params.get(QUERY_KEYS.sidebarExpanded);
  const sidebarExpanded =
    sidebarExpandedRaw === '1' ? true : sidebarExpandedRaw === '0' ? false : undefined;

  return {
    isSidebarExpanded: sidebarExpanded,
    expandedGroups: sanitizeExpandedGroups(
      parseExpandedGroupsParam(params.get(QUERY_KEYS.expandedGroups)),
    ),
    selectedContext: sanitizeSelectedContext({
      organization: params.get(QUERY_KEYS.organization) || undefined,
      project: params.get(QUERY_KEYS.project) || undefined,
      environment: params.get(QUERY_KEYS.environment) || undefined,
      accountSettings: params.get(QUERY_KEYS.accountSettings) || undefined,
    }),
  };
}

function readInitialState(): PersistedUiState {
  const defaults: PersistedUiState = {
    isSidebarExpanded: true,
    expandedGroups: { ...DEFAULT_EXPANDED_SIDEBAR_GROUPS },
    selectedContext: { ...DEFAULT_TOPBAR_CONTEXT_STATE },
  };
  const stored = readStoredState();
  const fromUrl = readUrlState();

  return {
    isSidebarExpanded:
      fromUrl.isSidebarExpanded ?? stored.isSidebarExpanded ?? defaults.isSidebarExpanded,
    expandedGroups: sanitizeExpandedGroups({
      ...defaults.expandedGroups,
      ...stored.expandedGroups,
      ...fromUrl.expandedGroups,
    }),
    selectedContext: sanitizeSelectedContext({
      ...defaults.selectedContext,
      ...stored.selectedContext,
      ...fromUrl.selectedContext,
    }),
  };
}

function writeStoredState(state: PersistedUiState): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(UI_STATE_STORAGE_KEY, JSON.stringify(state));
  } catch {}
}

function writeUrlState(pathname: string, state: PersistedUiState): void {
  if (typeof window === 'undefined') return;
  const params = new URLSearchParams(window.location.search);

  params.set(QUERY_KEYS.sidebarExpanded, state.isSidebarExpanded ? '1' : '0');
  params.set(
    QUERY_KEYS.expandedGroups,
    SIDEBAR_GROUP_KEYS.filter((key) => state.expandedGroups[key]).join(','),
  );
  params.set(QUERY_KEYS.organization, state.selectedContext.organization);
  params.set(QUERY_KEYS.project, state.selectedContext.project);
  params.set(QUERY_KEYS.environment, state.selectedContext.environment);
  params.set(QUERY_KEYS.accountSettings, state.selectedContext.accountSettings);

  const nextSearch = params.toString();
  const nextUrl = `${pathname}${nextSearch ? `?${nextSearch}` : ''}${window.location.hash}`;
  const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (nextUrl !== currentUrl) {
    window.history.replaceState({}, '', nextUrl);
  }
}

type UseDashboardUiPreferencesResult = {
  isSidebarExpanded: boolean;
  expandedGroups: ExpandedSidebarGroupsState;
  selectedContext: TopbarContextState;
  toggleSidebar: () => void;
  toggleGroup: (group: SidebarGroupKey) => void;
  onSelectContext: (menu: TopbarMenuKey, value: string) => void;
};

export function useDashboardUiPreferences(pathname: string): UseDashboardUiPreferencesResult {
  const initialState = React.useMemo(() => readInitialState(), []);

  const [isSidebarExpanded, setIsSidebarExpanded] = React.useState<boolean>(
    initialState.isSidebarExpanded,
  );
  const [expandedGroups, setExpandedGroups] = React.useState<ExpandedSidebarGroupsState>(
    initialState.expandedGroups,
  );
  const [selectedContext, setSelectedContext] = React.useState<TopbarContextState>(
    initialState.selectedContext,
  );

  const toggleSidebar = React.useCallback(() => {
    setIsSidebarExpanded((current) => !current);
  }, []);

  const toggleGroup = React.useCallback((group: SidebarGroupKey) => {
    setExpandedGroups((current) => ({
      ...current,
      [group]: !current[group],
    }));
  }, []);

  const onSelectContext = React.useCallback((menu: TopbarMenuKey, value: string) => {
    if (!isTopbarOption(menu, value)) return;
    setSelectedContext((current) => ({
      ...current,
      [menu]: value,
    }));
  }, []);

  React.useEffect(() => {
    const nextState: PersistedUiState = {
      isSidebarExpanded,
      expandedGroups,
      selectedContext,
    };
    writeStoredState(nextState);
    writeUrlState(pathname, nextState);
  }, [expandedGroups, isSidebarExpanded, pathname, selectedContext]);

  return {
    isSidebarExpanded,
    expandedGroups,
    selectedContext,
    toggleSidebar,
    toggleGroup,
    onSelectContext,
  };
}

export default useDashboardUiPreferences;
