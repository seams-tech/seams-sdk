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
const DASHBOARD_SELECTED_CONTEXT_REPLACED_EVENT = 'dashboard:selected-context-replaced';

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

function isSelectableTopbarOption(option: TopbarOption): boolean {
  return option.disabled !== true;
}

function hasTopbarOption(
  menu: TopbarMenuKey,
  value: string,
  dropdownOptions: TopbarDropdownOptions,
): boolean {
  return dropdownOptions[menu].some(
    (option) => option.value === value && isSelectableTopbarOption(option),
  );
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
  return String(options.find((option) => isSelectableTopbarOption(option))?.value || '').trim();
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

function areSelectedContextsEqual(
  left: TopbarContextState,
  right: TopbarContextState,
): boolean {
  return (
    left.organization === right.organization &&
    left.project === right.project &&
    left.environment === right.environment &&
    left.accountSettings === right.accountSettings
  );
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

function mergeSelectedContextState(
  current: Partial<TopbarContextState> | undefined,
  next: Partial<TopbarContextState>,
): TopbarContextState {
  const normalize = (value: unknown): string => String(value || '').trim();
  const hasSelectedContextKey = (key: keyof TopbarContextState): boolean =>
    Object.prototype.hasOwnProperty.call(next, key);
  return {
    organization: hasSelectedContextKey('organization')
      ? normalize(next.organization)
      : normalize(current?.organization),
    project: hasSelectedContextKey('project')
      ? normalize(next.project)
      : normalize(current?.project),
    environment: hasSelectedContextKey('environment')
      ? normalize(next.environment)
      : normalize(current?.environment),
    accountSettings: hasSelectedContextKey('accountSettings')
      ? normalize(next.accountSettings)
      : normalize(current?.accountSettings),
  };
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
  const nextSelectedContext = mergeSelectedContextState(current.selectedContext, selectedContext);
  const nextState: PersistedUiState = {
    isSidebarExpanded:
      typeof current.isSidebarExpanded === 'boolean' ? current.isSidebarExpanded : true,
    expandedGroups: sanitizeExpandedGroups(current.expandedGroups),
    selectedContext: nextSelectedContext,
  };
  writeStoredState(nextState);
}

export function replaceDashboardSelectedContext(
  selectedContext: Partial<TopbarContextState>,
): void {
  if (typeof window === 'undefined') return;
  persistDashboardSelectedContext(selectedContext);
  window.dispatchEvent(
    new CustomEvent<Partial<TopbarContextState>>(DASHBOARD_SELECTED_CONTEXT_REPLACED_EVENT, {
      detail: selectedContext,
    }),
  );
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
      return areSelectedContextsEqual(current, sanitized) ? current : sanitized;
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
      const sanitized = sanitizeSelectedContext(next, dropdownOptions, defaultContext);
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
    setPreferencesHydrated(true);
  }, [defaultContext, dropdownOptions, pathname]);

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const onSelectedContextReplaced = (event: Event) => {
      const custom = event as CustomEvent<Partial<TopbarContextState> | null>;
      const detail = custom.detail;
      if (!detail || typeof detail !== 'object' || Array.isArray(detail)) return;
      setSelectedContext((current) => mergeSelectedContextState(current, detail));
    };
    window.addEventListener(
      DASHBOARD_SELECTED_CONTEXT_REPLACED_EVENT,
      onSelectedContextReplaced as EventListener,
    );
    return () => {
      window.removeEventListener(
        DASHBOARD_SELECTED_CONTEXT_REPLACED_EVENT,
        onSelectedContextReplaced as EventListener,
      );
    };
  }, []);

  React.useEffect(() => {
    const fromUrl = readUrlSelectedContext(dropdownOptions, defaultContext);
    if (!fromUrl) return;
    const sanitized = sanitizeSelectedContext(fromUrl, dropdownOptions, defaultContext);
    setSelectedContext((current) => {
      if (
        current.organization === sanitized.organization &&
        current.project === sanitized.project &&
        current.environment === sanitized.environment &&
        current.accountSettings === sanitized.accountSettings
      ) {
        return current;
      }
      return sanitized;
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
