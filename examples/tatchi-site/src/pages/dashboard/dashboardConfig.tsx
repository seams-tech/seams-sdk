import { ApiKeyManagementPage } from './routes/api-keys/page';
import { AppSettingsPage } from './routes/app-settings/page';
import { BillingPage } from './routes/billing/page';
import { ExportKeysSettingsPage } from './routes/export-keys/page';
import { GasSponsorshipSmartWalletsPage } from './routes/gas-smart-wallets/page';
import { PolicyEnginePage } from './routes/policy-engine/page';
import { SearchUserWalletsPage } from './routes/wallets-search/page';
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

const walletInfrastructureItems: SidebarItem[] = walletsRoutesEnabled
  ? [
      {
        key: 'wallets-list',
        label: 'User wallets list',
        path: '/dashboard/wallets-list',
        iconClass: 'dashboard-nav-icon--wallet-list',
        component: UserWalletsListPage,
      },
      {
        key: 'wallets-search',
        label: 'Search for user wallets',
        path: '/dashboard/wallets-search',
        iconClass: 'dashboard-nav-icon--wallet-search',
        component: SearchUserWalletsPage,
      },
    ]
  : [];

const sidebarGroups: SidebarGroup[] = [
  {
    key: 'walletInfrastructure',
    label: 'Wallet Infrastructure',
    items: walletInfrastructureItems,
  },
  {
    key: 'securityPolicy',
    label: 'Security and Policy',
    items: [
      {
        key: 'policy-engine',
        label: 'Policy engine',
        path: '/dashboard/policy-engine',
        iconClass: 'dashboard-nav-icon--policy-engine',
        component: PolicyEnginePage,
      },
      {
        key: 'gas-smart-wallets',
        label: 'Gas sponsorship and smart wallets',
        path: '/dashboard/gas-smart-wallets',
        iconClass: 'dashboard-nav-icon--gas-smart',
        component: GasSponsorshipSmartWalletsPage,
      },
      {
        key: 'export-keys',
        label: 'Export keys settings',
        path: '/dashboard/export-keys',
        iconClass: 'dashboard-nav-icon--export-keys',
        component: ExportKeysSettingsPage,
      },
    ],
  },
  {
    key: 'integrationsAutomation',
    label: 'Integrations and Automation',
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
      {
        key: 'billing',
        label: 'Billing',
        path: '/dashboard/billing',
        iconClass: 'dashboard-nav-icon--app-settings',
        component: BillingPage,
      },
    ],
  },
  {
    key: 'environmentSettings',
    label: 'Environment Settings',
    items: [
      {
        key: 'app-settings',
        label: 'App settings (origins, cookies, JWT)',
        path: '/dashboard/app-settings',
        iconClass: 'dashboard-nav-icon--app-settings',
        component: AppSettingsPage,
      },
    ],
  },
];

export const SIDEBAR_GROUPS: SidebarGroup[] = sidebarGroups.filter(
  (group) => group.items.length > 0,
);

export const DASHBOARD_ACCOUNT_SETTINGS_OPTIONS = [
  'Account & Settings',
  'Team members',
  'Roles and permissions',
  'Audit logs',
];

export const DEFAULT_EXPANDED_SIDEBAR_GROUPS: ExpandedSidebarGroupsState = {
  walletInfrastructure: true,
  securityPolicy: true,
  integrationsAutomation: true,
  environmentSettings: true,
};

export const SIDEBAR_GROUP_KEYS = Object.keys(DEFAULT_EXPANDED_SIDEBAR_GROUPS) as Array<
  keyof ExpandedSidebarGroupsState
>;

function resolveDefaultDashboardRoute(groups: SidebarGroup[]): DashboardRoute {
  for (const group of groups) {
    if (group.items[0]) return group.items[0].path;
  }
  return '/dashboard/policy-engine';
}

export const DEFAULT_DASHBOARD_ROUTE: DashboardRoute = resolveDefaultDashboardRoute(SIDEBAR_GROUPS);

export function getRouteFromPathname(pathname: string): DashboardRoute | null {
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === pathname) return item.path;
    }
  }
  return null;
}

export function getViewForRoute(route: DashboardRoute): SidebarItem {
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === route) return item;
    }
  }
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === DEFAULT_DASHBOARD_ROUTE) return item;
    }
  }
  return {
    key: 'policy-engine',
    label: 'Policy engine',
    path: '/dashboard/policy-engine',
    iconClass: 'dashboard-nav-icon--policy-engine',
    component: PolicyEnginePage,
  };
}
