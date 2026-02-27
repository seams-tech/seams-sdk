import { ApiKeyManagementPage } from './routes/api-keys/page';
import { AppSettingsPage } from './routes/app-settings/page';
import { ExportKeysSettingsPage } from './routes/export-keys/page';
import { GasSponsorshipSmartWalletsPage } from './routes/gas-smart-wallets/page';
import { PolicyEnginePage } from './routes/policy-engine/page';
import { SearchUserWalletsPage } from './routes/wallets-search/page';
import { UserWalletsListPage } from './routes/wallets-list/page';
import { WebhooksPage } from './routes/webhooks/page';
import type {
  DashboardRoute,
  ExpandedSidebarGroupsState,
  SidebarGroup,
  SidebarItem,
  TopbarContextState,
  TopbarMenuKey,
} from './types';

export const SIDEBAR_GROUPS: SidebarGroup[] = [
  {
    key: 'walletInfrastructure',
    label: 'Wallet Infrastructure',
    items: [
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
    ],
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

export const DASHBOARD_TOPBAR_DROPDOWN_OPTIONS: Record<TopbarMenuKey, string[]> = {
  organization: ['Game1', 'Arc Labs', 'Nova Studio'],
  project: ['Game1', 'Wallet Ops', 'Payments Infra'],
  environment: ['Sandbox', 'Staging', 'Production'],
  accountSettings: ['Account & Settings', 'Team members', 'Roles and permissions', 'Audit logs'],
};

export const DEFAULT_TOPBAR_CONTEXT_STATE: TopbarContextState = {
  organization: DASHBOARD_TOPBAR_DROPDOWN_OPTIONS.organization[0]!,
  project: DASHBOARD_TOPBAR_DROPDOWN_OPTIONS.project[0]!,
  environment: DASHBOARD_TOPBAR_DROPDOWN_OPTIONS.environment[0]!,
  accountSettings: DASHBOARD_TOPBAR_DROPDOWN_OPTIONS.accountSettings[0]!,
};

export const DEFAULT_EXPANDED_SIDEBAR_GROUPS: ExpandedSidebarGroupsState = {
  walletInfrastructure: true,
  securityPolicy: true,
  integrationsAutomation: true,
  environmentSettings: true,
};

export const SIDEBAR_GROUP_KEYS = Object.keys(DEFAULT_EXPANDED_SIDEBAR_GROUPS) as Array<
  keyof ExpandedSidebarGroupsState
>;

export const DEFAULT_DASHBOARD_ROUTE: DashboardRoute = '/dashboard/wallets-list';

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
  return SIDEBAR_GROUPS[0]!.items[0]!;
}
