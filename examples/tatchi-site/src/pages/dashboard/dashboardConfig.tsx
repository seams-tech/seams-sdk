import { ApiKeyManagementPage } from './routes/api-keys/page';
import { AppSettingsPage } from './routes/app-settings/page';
import { BillingPage } from './routes/billing/page';
import { AuditLogsPage } from './routes/audit/page';
import { EnterpriseIsolationPage } from './routes/enterprise-isolation/page';
import { ExportKeysSettingsPage } from './routes/export-keys/page';
import { GasSponsorshipSmartWalletsPage } from './routes/gas-smart-wallets/page';
import { PolicyEnginePage } from './routes/policy-engine/page';
import { TeamMembersPage } from './routes/team-members/page';
import { DashboardOnboardingPage } from './routes/onboarding/page';
import { OpsCockpitPage } from './routes/ops-cockpit/page';
import { ObservabilityPage } from './routes/observability/page';
import { UserWalletsListPage } from './routes/wallets-list/page';
import { WebhooksPage } from './routes/webhooks/page';
import { FRONTEND_CONFIG } from '@/config';
import type {
  DashboardRoute,
  ExpandedSidebarGroupsState,
  SidebarGroup,
  SidebarItem,
} from './types';

const walletsRoutesEnabled = FRONTEND_CONFIG.dashboardFlags.walletsRoutesEnabled;

const gasSmartWalletsItem: SidebarItem = {
  key: 'gas-smart-wallets',
  label: 'Gas sponsorship and smart wallets',
  path: '/dashboard/gas-smart-wallets',
  iconClass: 'dashboard-nav-icon--gas-smart',
  component: GasSponsorshipSmartWalletsPage,
};

const walletsListItem: SidebarItem = {
  key: 'wallets-list',
  label: 'User wallets list',
  path: '/dashboard/wallets-list',
  iconClass: 'dashboard-nav-icon--wallet-list',
  component: UserWalletsListPage,
};

const securityControlItems: SidebarItem[] = [
  {
    key: 'policy-engine',
    label: 'Policy engine',
    path: '/dashboard/policy-engine',
    iconClass: 'dashboard-nav-icon--policy-engine',
    component: PolicyEnginePage,
  },
  {
    key: 'enterprise-isolation',
    label: 'Enterprise isolation',
    path: '/dashboard/enterprise-isolation',
    iconClass: 'dashboard-nav-icon--app-settings',
    component: EnterpriseIsolationPage,
  },
];

const auditLogsItem: SidebarItem = {
  key: 'audit',
  label: 'Audit logs',
  path: '/dashboard/audit',
  iconClass: 'dashboard-nav-icon--app-settings',
  component: AuditLogsPage,
};

const observabilityItem: SidebarItem = {
  key: 'observability',
  label: 'Observability',
  path: '/dashboard/observability',
  iconClass: 'dashboard-nav-icon--app-settings',
  component: ObservabilityPage,
};

const operationsSecurityItems: SidebarItem[] = [
  ...(walletsRoutesEnabled ? [walletsListItem] : []),
  gasSmartWalletsItem,
  ...securityControlItems,
  auditLogsItem,
  observabilityItem,
];

const sidebarGroups: SidebarGroup[] = [
  {
    key: 'overview',
    label: 'Overview',
    items: [
      {
        key: 'ops-cockpit',
        label: 'Overview',
        path: '/dashboard/ops-cockpit',
        iconClass: 'dashboard-nav-icon--app-settings',
        component: OpsCockpitPage,
      },
    ],
  },
  {
    key: 'administration',
    label: 'Administration',
    items: [
      {
        key: 'team-members',
        label: 'Team members and roles',
        path: '/dashboard/team-members',
        iconClass: 'dashboard-nav-icon--app-settings',
        component: TeamMembersPage,
      },
      {
        key: 'app-settings',
        label: 'App settings (origins, cookies, JWT)',
        path: '/dashboard/app-settings',
        iconClass: 'dashboard-nav-icon--app-settings',
        component: AppSettingsPage,
      },
    ],
  },
  {
    key: 'operationsSecurity',
    label: 'Wallet Operations',
    items: operationsSecurityItems,
  },
  {
    key: 'integrations',
    label: 'Integrations',
    items: [
      {
        key: 'api-keys',
        label: 'API key management',
        path: '/dashboard/api-keys',
        iconClass: 'dashboard-nav-icon--api-keys',
        component: ApiKeyManagementPage,
      },
      {
        key: 'webhooks',
        label: 'Webhooks',
        path: '/dashboard/webhooks',
        iconClass: 'dashboard-nav-icon--webhooks',
        component: WebhooksPage,
      },
    ],
  },
  {
    key: 'billing',
    label: 'Billing',
    items: [
      {
        key: 'billing',
        label: 'Billing',
        path: '/dashboard/billing',
        iconClass: 'dashboard-nav-icon--app-settings',
        component: BillingPage,
      },
    ],
  },
];

export const SIDEBAR_GROUPS: SidebarGroup[] = sidebarGroups.filter(
  (group) => group.items.length > 0,
);

export const DASHBOARD_ACCOUNT_SETTINGS_SIGN_OUT_OPTION = 'Sign out';
export const DASHBOARD_ACCOUNT_SETTINGS_OPTIONS = [
  'Account & Settings',
  'Team members',
  'Roles and permissions',
  'Audit logs',
  DASHBOARD_ACCOUNT_SETTINGS_SIGN_OUT_OPTION,
];

export const DEFAULT_EXPANDED_SIDEBAR_GROUPS: ExpandedSidebarGroupsState = {
  overview: true,
  administration: true,
  operationsSecurity: true,
  integrations: true,
  billing: true,
};

export const SIDEBAR_GROUP_KEYS = Object.keys(DEFAULT_EXPANDED_SIDEBAR_GROUPS) as Array<
  keyof ExpandedSidebarGroupsState
>;

const HIDDEN_DASHBOARD_ROUTES: SidebarItem[] = [
  {
    key: 'onboarding',
    label: 'Onboarding wizard',
    path: '/dashboard/onboarding',
    iconClass: 'dashboard-nav-icon--app-settings',
    component: DashboardOnboardingPage,
  },
  {
    key: 'export-keys',
    label: 'Export keys settings',
    path: '/dashboard/export-keys',
    iconClass: 'dashboard-nav-icon--export-keys',
    component: ExportKeysSettingsPage,
  },
];

function resolveDefaultDashboardRoute(groups: SidebarGroup[]): DashboardRoute {
  for (const group of groups) {
    if (group.items[0]) return group.items[0].path;
  }
  return '/dashboard/ops-cockpit';
}

export const DEFAULT_DASHBOARD_ROUTE: DashboardRoute = resolveDefaultDashboardRoute(SIDEBAR_GROUPS);

export function getRouteFromPathname(pathname: string): DashboardRoute | null {
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === pathname) return item.path;
    }
  }
  for (const item of HIDDEN_DASHBOARD_ROUTES) {
    if (item.path === pathname) return item.path;
  }
  return null;
}

export function getViewForRoute(route: DashboardRoute): SidebarItem {
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === route) return item;
    }
  }
  for (const item of HIDDEN_DASHBOARD_ROUTES) {
    if (item.path === route) return item;
  }
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === DEFAULT_DASHBOARD_ROUTE) return item;
    }
  }
  return {
    key: 'ops-cockpit',
    label: 'Overview',
    path: '/dashboard/ops-cockpit',
    iconClass: 'dashboard-nav-icon--app-settings',
    component: OpsCockpitPage,
  };
}
