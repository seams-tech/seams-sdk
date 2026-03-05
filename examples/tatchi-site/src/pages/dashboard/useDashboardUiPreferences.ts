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

export const DASHBOARD_UI_QUERY_KEYS = {
  sidebarExpanded: 'db_sb',
  expandedGroups: 'db_groups',
  organization: 'db_org',
  project: 'db_project',
  environment: 'db_env',
  accountSettings: 'db_acct',
} as const;
const DASHBOARD_UI_QUERY_PARAM_KEYS = Object.values(DASHBOARD_UI_QUERY_KEYS);

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
  const options = dropdownOptions[menu];
  const rawValue = String(input?.[menu] || '').trim();
  if (rawValue && (options.length === 0 || hasTopbarOption(menu, rawValue, dropdownOptions))) {
    return rawValue;
  }
  const defaultValue = String(defaults[menu] || '').trim();
  if (
    defaultValue &&
    (options.length === 0 || hasTopbarOption(menu, defaultValue, dropdownOptions))
  ) {
    return defaultValue;
  }
  return String(options[0]?.value || '').trim();
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
  const resolved = {} as ExpandedSidebarGroupsState;
  for (const key of SIDEBAR_GROUP_KEYS) {
    resolved[key] = input?.[key] ?? DEFAULT_EXPANDED_SIDEBAR_GROUPS[key];
  }
  return resolved;
}

function readExplicitSelectedContext(
  input: Partial<TopbarContextState> | undefined,
): Partial<TopbarContextState> {
  const organization = String(input?.organization || '').trim();
  const project = String(input?.project || '').trim();
  const environment = String(input?.environment || '').trim();
  const accountSettings = String(input?.accountSettings || '').trim();
  return {
    ...(organization ? { organization } : {}),
    ...(project ? { project } : {}),
    ...(environment ? { environment } : {}),
    ...(accountSettings ? { accountSettings } : {}),
  };
}

function readRawStoredState(): Partial<PersistedUiState> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(UI_STATE_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return parsed as Partial<PersistedUiState>;
  } catch {
    return {};
  }
}

function readStoredState(
  dropdownOptions: TopbarDropdownOptions,
  defaultContext: TopbarContextState,
): Partial<PersistedUiState> {
  const parsed = readRawStoredState();
  const explicitStoredContext = readExplicitSelectedContext(parsed.selectedContext);
  const sanitizedSelectedContext = sanitizeSelectedContext(
    parsed.selectedContext,
    dropdownOptions,
    defaultContext,
  );
  return {
    isSidebarExpanded:
      typeof parsed.isSidebarExpanded === 'boolean' ? parsed.isSidebarExpanded : undefined,
    expandedGroups: sanitizeExpandedGroups(parsed.expandedGroups),
    // Preserve explicit stored selections even before dropdown options hydrate.
    selectedContext: {
      ...sanitizedSelectedContext,
      ...explicitStoredContext,
    },
  };
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

  const sidebarExpandedRaw = params.get(DASHBOARD_UI_QUERY_KEYS.sidebarExpanded);
  const sidebarExpanded =
    sidebarExpandedRaw === '1' ? true : sidebarExpandedRaw === '0' ? false : undefined;
  const expandedGroupsRaw = params.get(DASHBOARD_UI_QUERY_KEYS.expandedGroups);
  const hasExpandedGroupOverride = expandedGroupsRaw !== null;
  const hasContextOverride =
    params.has(DASHBOARD_UI_QUERY_KEYS.organization) ||
    params.has(DASHBOARD_UI_QUERY_KEYS.project) ||
    params.has(DASHBOARD_UI_QUERY_KEYS.environment) ||
    params.has(DASHBOARD_UI_QUERY_KEYS.accountSettings);

  return {
    isSidebarExpanded: sidebarExpanded,
    ...(hasExpandedGroupOverride
      ? {
          expandedGroups: sanitizeExpandedGroups(parseExpandedGroupsParam(expandedGroupsRaw)),
        }
      : {}),
    ...(hasContextOverride
      ? {
          selectedContext: sanitizeSelectedContext({
            organization: params.get(DASHBOARD_UI_QUERY_KEYS.organization) || undefined,
            project: params.get(DASHBOARD_UI_QUERY_KEYS.project) || undefined,
            environment: params.get(DASHBOARD_UI_QUERY_KEYS.environment) || undefined,
            accountSettings: params.get(DASHBOARD_UI_QUERY_KEYS.accountSettings) || undefined,
          }, dropdownOptions, defaultContext),
        }
      : {}),
  };
}

function readUrlSelectedContext(
  dropdownOptions: TopbarDropdownOptions,
  defaultContext: TopbarContextState,
): TopbarContextState | null {
  if (typeof window === 'undefined') return null;
  const params = new URLSearchParams(window.location.search);
  const hasContextOverride =
    params.has(DASHBOARD_UI_QUERY_KEYS.organization) ||
    params.has(DASHBOARD_UI_QUERY_KEYS.project) ||
    params.has(DASHBOARD_UI_QUERY_KEYS.environment) ||
    params.has(DASHBOARD_UI_QUERY_KEYS.accountSettings);
  if (!hasContextOverride) return null;
  const explicitContext = readExplicitSelectedContext({
    organization: params.get(DASHBOARD_UI_QUERY_KEYS.organization) || undefined,
    project: params.get(DASHBOARD_UI_QUERY_KEYS.project) || undefined,
    environment: params.get(DASHBOARD_UI_QUERY_KEYS.environment) || undefined,
    accountSettings: params.get(DASHBOARD_UI_QUERY_KEYS.accountSettings) || undefined,
  });

  const sanitized = sanitizeSelectedContext({
    organization: params.get(DASHBOARD_UI_QUERY_KEYS.organization) || undefined,
    project: params.get(DASHBOARD_UI_QUERY_KEYS.project) || undefined,
    environment: params.get(DASHBOARD_UI_QUERY_KEYS.environment) || undefined,
    accountSettings: params.get(DASHBOARD_UI_QUERY_KEYS.accountSettings) || undefined,
  }, dropdownOptions, defaultContext);
  return {
    ...sanitized,
    // Preserve explicit context overrides from URL even before dropdown options hydrate.
    ...explicitContext,
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
  const explicitStoredContext = readExplicitSelectedContext(stored.selectedContext);
  const explicitUrlContext = readExplicitSelectedContext(fromUrl.selectedContext);

  return {
    isSidebarExpanded:
      fromUrl.isSidebarExpanded ?? stored.isSidebarExpanded ?? baseState.isSidebarExpanded,
    expandedGroups: sanitizeExpandedGroups({
      ...baseState.expandedGroups,
      ...stored.expandedGroups,
      ...fromUrl.expandedGroups,
    }),
    selectedContext: {
      ...sanitizeSelectedContext({
        ...baseState.selectedContext,
        ...stored.selectedContext,
        ...fromUrl.selectedContext,
      }, dropdownOptions, defaultContext),
      ...explicitStoredContext,
      ...explicitUrlContext,
    },
  };
}

function writeStoredState(state: PersistedUiState): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(UI_STATE_STORAGE_KEY, JSON.stringify(state));
  } catch {}
}

function clearDashboardUiQueryState(pathname: string): void {
  if (typeof window === 'undefined') return;
  const params = new URLSearchParams(window.location.search);
  let changed = false;
  if (params.has('onboarding')) {
    params.delete('onboarding');
    changed = true;
  }
  for (const key of DASHBOARD_UI_QUERY_PARAM_KEYS) {
    if (!params.has(key)) continue;
    params.delete(key);
    changed = true;
  }
  if (!changed) return;

  const nextSearch = params.toString();
  const nextUrl = `${pathname}${nextSearch ? `?${nextSearch}` : ''}${window.location.hash}`;
  const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (nextUrl !== currentUrl) {
    window.history.replaceState({}, '', nextUrl);
  }
}

export function clearDashboardUiState(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(UI_STATE_STORAGE_KEY);
  } catch {}
  clearDashboardUiQueryState(window.location.pathname || '/dashboard');
}

export function persistDashboardSelectedContext(
  selectedContext: Partial<TopbarContextState>,
): void {
  if (typeof window === 'undefined') return;
  const current = readRawStoredState();
  const currentSelected = current.selectedContext;
  const normalize = (value: unknown): string => String(value || '').trim();
  const nextSelectedContext: TopbarContextState = {
    organization:
      normalize(selectedContext.organization) || normalize(currentSelected?.organization),
    project: normalize(selectedContext.project) || normalize(currentSelected?.project),
    environment:
      normalize(selectedContext.environment) || normalize(currentSelected?.environment),
    accountSettings:
      normalize(selectedContext.accountSettings) || normalize(currentSelected?.accountSettings),
  };
  const nextState: PersistedUiState = {
    isSidebarExpanded:
      typeof current.isSidebarExpanded === 'boolean' ? current.isSidebarExpanded : true,
    expandedGroups: sanitizeExpandedGroups(current.expandedGroups),
    selectedContext: nextSelectedContext,
  };
  writeStoredState(nextState);
}

export function readPersistedDashboardSelectedContext(): Partial<TopbarContextState> {
  const current = readRawStoredState();
  const selected = current.selectedContext;
  if (!selected) return {};
  return readExplicitSelectedContext(selected);
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
  const [preferencesHydrated, setPreferencesHydrated] = React.useState<boolean>(false);

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
    const persisted = readPersistedDashboardSelectedContext();
    const organization = String(persisted.organization || '').trim();
    const project = String(persisted.project || '').trim();
    const environment = String(persisted.environment || '').trim();
    const accountSettings = String(persisted.accountSettings || '').trim();
    if (!organization && !project && !environment && !accountSettings) return;
    setSelectedContext((current) => {
      const next: TopbarContextState = {
        ...current,
        ...(organization ? { organization } : {}),
        ...(project ? { project } : {}),
        ...(environment ? { environment } : {}),
        ...(accountSettings ? { accountSettings } : {}),
      };
      if (
        next.organization === current.organization &&
        next.project === current.project &&
        next.environment === current.environment &&
        next.accountSettings === current.accountSettings
      ) {
        return current;
      }
      return next;
    });
    setPreferencesHydrated(true);
  }, [pathname]);

  React.useEffect(() => {
    const fromUrl = readUrlSelectedContext(dropdownOptions, defaultContext);
    if (!fromUrl) return;
    setSelectedContext((current) => {
      if (
        current.organization === fromUrl.organization &&
        current.project === fromUrl.project &&
        current.environment === fromUrl.environment &&
        current.accountSettings === fromUrl.accountSettings
      ) {
        return current;
      }
      return fromUrl;
    });
  }, [defaultContext, dropdownOptions, pathname]);

  React.useEffect(() => {
    if (!preferencesHydrated) return;
    const nextState: PersistedUiState = {
      isSidebarExpanded,
      expandedGroups,
      selectedContext,
    };
    writeStoredState(nextState);
  }, [expandedGroups, isSidebarExpanded, preferencesHydrated, selectedContext]);

  React.useEffect(() => {
    clearDashboardUiQueryState(pathname);
  }, [pathname]);

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
