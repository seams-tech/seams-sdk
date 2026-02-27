import React from 'react';
import {
  DEFAULT_EXPANDED_SIDEBAR_GROUPS,
  SIDEBAR_GROUP_KEYS,
} from './dashboardConfig';
import type {
  ExpandedSidebarGroupsState,
  SidebarGroupKey,
  TopbarOption,
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

type TopbarDropdownOptions = Record<TopbarMenuKey, TopbarOption[]>;

type UseDashboardUiPreferencesInput = {
  dropdownOptions: TopbarDropdownOptions;
  defaultContext: TopbarContextState;
};

function hasTopbarOption(
  menu: TopbarMenuKey,
  value: string,
  dropdownOptions: TopbarDropdownOptions,
): boolean {
  return dropdownOptions[menu].some((option) => option.value === value);
}

function resolveContextValue(
  menu: TopbarMenuKey,
  input: Partial<TopbarContextState> | undefined,
  dropdownOptions: TopbarDropdownOptions,
  defaults: TopbarContextState,
): string {
  const rawValue = String(input?.[menu] || '').trim();
  if (rawValue && hasTopbarOption(menu, rawValue, dropdownOptions)) return rawValue;
  const defaultValue = String(defaults[menu] || '').trim();
  if (defaultValue && hasTopbarOption(menu, defaultValue, dropdownOptions)) return defaultValue;
  return String(dropdownOptions[menu][0]?.value || '').trim();
}

function sanitizeSelectedContext(
  input: Partial<TopbarContextState> | undefined,
  dropdownOptions: TopbarDropdownOptions,
  defaults: TopbarContextState,
): TopbarContextState {
  return {
    organization: resolveContextValue('organization', input, dropdownOptions, defaults),
    project: resolveContextValue('project', input, dropdownOptions, defaults),
    environment: resolveContextValue('environment', input, dropdownOptions, defaults),
    accountSettings: resolveContextValue('accountSettings', input, dropdownOptions, defaults),
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

function readStoredState(
  dropdownOptions: TopbarDropdownOptions,
  defaultContext: TopbarContextState,
): Partial<PersistedUiState> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(UI_STATE_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Partial<PersistedUiState>;
    return {
      isSidebarExpanded:
        typeof parsed.isSidebarExpanded === 'boolean' ? parsed.isSidebarExpanded : undefined,
      expandedGroups: sanitizeExpandedGroups(parsed.expandedGroups),
      selectedContext: sanitizeSelectedContext(parsed.selectedContext, dropdownOptions, defaultContext),
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

function readUrlState(
  dropdownOptions: TopbarDropdownOptions,
  defaultContext: TopbarContextState,
): Partial<PersistedUiState> {
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
    }, dropdownOptions, defaultContext),
  };
}

function readInitialState(
  dropdownOptions: TopbarDropdownOptions,
  defaultContext: TopbarContextState,
): PersistedUiState {
  const baseState: PersistedUiState = {
    isSidebarExpanded: true,
    expandedGroups: { ...DEFAULT_EXPANDED_SIDEBAR_GROUPS },
    selectedContext: sanitizeSelectedContext(undefined, dropdownOptions, defaultContext),
  };
  const stored = readStoredState(dropdownOptions, defaultContext);
  const fromUrl = readUrlState(dropdownOptions, defaultContext);

  return {
    isSidebarExpanded:
      fromUrl.isSidebarExpanded ?? stored.isSidebarExpanded ?? baseState.isSidebarExpanded,
    expandedGroups: sanitizeExpandedGroups({
      ...baseState.expandedGroups,
      ...stored.expandedGroups,
      ...fromUrl.expandedGroups,
    }),
    selectedContext: sanitizeSelectedContext({
      ...baseState.selectedContext,
      ...stored.selectedContext,
      ...fromUrl.selectedContext,
    }, dropdownOptions, defaultContext),
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

export function useDashboardUiPreferences(
  pathname: string,
  input: UseDashboardUiPreferencesInput,
): UseDashboardUiPreferencesResult {
  const { dropdownOptions, defaultContext } = input;
  const initialState = React.useMemo(
    () => readInitialState(dropdownOptions, defaultContext),
    [defaultContext, dropdownOptions],
  );

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
    if (!hasTopbarOption(menu, value, dropdownOptions)) return;
    setSelectedContext((current) => ({
      ...current,
      [menu]: value,
    }));
  }, [dropdownOptions]);

  React.useEffect(() => {
    setSelectedContext((current) => {
      const sanitized = sanitizeSelectedContext(current, dropdownOptions, defaultContext);
      if (
        sanitized.organization === current.organization &&
        sanitized.project === current.project &&
        sanitized.environment === current.environment &&
        sanitized.accountSettings === current.accountSettings
      ) {
        return current;
      }
      return sanitized;
    });
  }, [defaultContext, dropdownOptions]);

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
