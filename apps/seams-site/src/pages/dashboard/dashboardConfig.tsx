import { ApiKeyManagementPage } from './routes/api-keys/page';
import { BillingAccountPage } from './routes/billing/page';
import { AccountSettingsPage } from './routes/account-settings/page';
import { AuditLogsPage } from './routes/audit/page';
import { GasSponsorshipPage } from './routes/gas-sponsorship/page';
import { InvoicesPage } from './routes/invoices/page';
import { PlatformBillingPage } from './routes/platform-billing/page';
import { PolicyEnginePage } from './routes/policy-engine/page';
import { TeamMembersPage } from './routes/team-members/page';
import { DashboardOnboardingPage } from './routes/onboarding/page';
import { OpsCockpitPage } from './routes/ops-cockpit/page';
import { ObservabilityPage } from './routes/observability/page';
import { UserWalletsListPage } from './routes/wallets-list/page';
import { WebhooksPage } from './routes/webhooks/page';
import { FRONTEND_CONFIG } from '@/config';
import {
  ActivityIcon,
  CogIcon,
  CreditCardIcon,
  FileTextIcon,
  FuelIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  ScaleIcon,
  ScrollTextIcon,
  UserCogIcon,
  WalletCardsIcon,
  WebhookIcon,
} from './icons/SidebarIcons';
import type {
  DashboardRoute,
  ExpandedSidebarGroupsState,
  SidebarGroup,
  SidebarItem,
} from './types';

const walletsRoutesEnabled = FRONTEND_CONFIG.dashboardFlags.walletsRoutesEnabled;

const gasSponsorshipItem: SidebarItem = {
  key: 'gas-sponsorship',
  label: 'Gas sponsorship',
  path: '/dashboard/gas-sponsorship',
  icon: FuelIcon,
  component: GasSponsorshipPage,
};

const walletsListItem: SidebarItem = {
  key: 'wallets-list',
  label: 'User wallets list',
  path: '/dashboard/wallets-list',
  icon: WalletCardsIcon,
  component: UserWalletsListPage,
};

const securityControlItems: SidebarItem[] = [
  {
    key: 'policy-engine',
    label: 'Policy engine',
    path: '/dashboard/policy-engine',
    icon: ScaleIcon,
    component: PolicyEnginePage,
  },
];

const auditLogsItem: SidebarItem = {
  key: 'audit',
  label: 'Audit logs',
  path: '/dashboard/audit',
  icon: ScrollTextIcon,
  component: AuditLogsPage,
};

const observabilityItem: SidebarItem = {
  key: 'observability',
  label: 'Observability',
  path: '/dashboard/observability',
  icon: ActivityIcon,
  component: ObservabilityPage,
};

const operationsSecurityItems: SidebarItem[] = [
  ...(walletsRoutesEnabled ? [walletsListItem] : []),
  gasSponsorshipItem,
  ...securityControlItems,
  auditLogsItem,
];

const sidebarGroups: SidebarGroup[] = [
  {
    key: 'overview',
    label: 'Overview',
    items: [
      {
        key: 'overview',
        label: 'Overview',
        path: '/dashboard/overview',
        icon: LayoutDashboardIcon,
        component: OpsCockpitPage,
      },
      observabilityItem,
    ],
  },
  {
    key: 'administration',
    label: 'Administration',
    items: [
      {
        key: 'account-settings',
        label: 'Account settings',
        path: '/dashboard/account-settings',
        icon: CogIcon,
        component: AccountSettingsPage,
      },
      {
        key: 'team-members',
        label: 'Team members and roles',
        path: '/dashboard/team-members',
        icon: UserCogIcon,
        component: TeamMembersPage,
      },
      {
        key: 'api-keys',
        label: 'API Keys',
        path: '/dashboard/api-keys',
        icon: KeyRoundIcon,
        component: ApiKeyManagementPage,
      },
    ],
  },
  {
    key: 'operationsSecurity',
    label: 'Wallet Operations',
    items: operationsSecurityItems,
  },
  {
    key: 'billing',
    label: 'Billing',
    items: [
      {
        key: 'billing-account',
        label: 'Billing account',
        path: '/dashboard/billing/account',
        icon: CreditCardIcon,
        component: BillingAccountPage,
      },
      {
        key: 'invoices',
        label: 'Invoices',
        path: '/dashboard/invoices',
        icon: FileTextIcon,
        component: InvoicesPage,
      },
    ],
  },
  {
    key: 'integrations',
    label: 'Integrations',
    items: [
      {
        key: 'webhooks',
        label: 'Webhooks',
        path: '/dashboard/webhooks',
        icon: WebhookIcon,
        component: WebhooksPage,
      },
    ],
  },
  {
    key: 'platform',
    label: 'Platform',
    items: [
      {
        key: 'platform-billing',
        label: 'Customer Accounts',
        path: '/platform/billing',
        icon: CreditCardIcon,
        component: PlatformBillingPage,
      },
    ],
  },
];

export const SIDEBAR_GROUPS: SidebarGroup[] = sidebarGroups.filter(
  (group) => group.items.length > 0,
);

export const DASHBOARD_ACCOUNT_SETTINGS_ACCOUNT_OPTION = 'Account Settings';
export const DASHBOARD_ACCOUNT_SETTINGS_THEME_TOGGLE_OPTION = '__toggle-theme__';
export const DASHBOARD_ACCOUNT_SETTINGS_SIGN_OUT_OPTION = 'Sign out';
export const DASHBOARD_ACCOUNT_SETTINGS_OPTIONS = [
  DASHBOARD_ACCOUNT_SETTINGS_ACCOUNT_OPTION,
  DASHBOARD_ACCOUNT_SETTINGS_THEME_TOGGLE_OPTION,
  DASHBOARD_ACCOUNT_SETTINGS_SIGN_OUT_OPTION,
];

export const DEFAULT_EXPANDED_SIDEBAR_GROUPS: ExpandedSidebarGroupsState = {
  overview: true,
  administration: true,
  operationsSecurity: true,
  billing: true,
  integrations: true,
  platform: true,
};

export const SIDEBAR_GROUP_KEYS = Object.keys(DEFAULT_EXPANDED_SIDEBAR_GROUPS) as Array<
  keyof ExpandedSidebarGroupsState
>;

const HIDDEN_DASHBOARD_ROUTES: SidebarItem[] = [
  {
    key: 'onboarding',
    label: 'Onboarding wizard',
    path: '/dashboard/onboarding',
    icon: LayoutDashboardIcon,
    component: DashboardOnboardingPage,
  },
];

function resolveDefaultDashboardRoute(groups: SidebarGroup[]): DashboardRoute {
  for (const group of groups) {
    if (group.items[0]) return group.items[0].path;
  }
  return '/dashboard/overview';
}

export const DEFAULT_DASHBOARD_ROUTE: DashboardRoute = resolveDefaultDashboardRoute(SIDEBAR_GROUPS);

export function getRouteFromPathname(pathname: string): DashboardRoute | null {
  const normalizedPathname =
    pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;

  if (
    normalizedPathname === '/dashboard/billing' ||
    normalizedPathname === '/dashboard/billing/account'
  ) {
    return '/dashboard/billing/account';
  }
  if (
    normalizedPathname === '/dashboard/invoices' ||
    normalizedPathname.startsWith('/dashboard/invoices/') ||
    normalizedPathname === '/dashboard/billing/invoices' ||
    normalizedPathname.startsWith('/dashboard/billing/invoices/')
  ) {
    return '/dashboard/invoices';
  }
  if (normalizedPathname === '/platform/billing') {
    return '/platform/billing';
  }
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === normalizedPathname) return item.path;
    }
  }
  for (const item of HIDDEN_DASHBOARD_ROUTES) {
    if (item.path === normalizedPathname) return item.path;
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
    key: 'overview',
    label: 'Overview',
    path: '/dashboard/overview',
    icon: LayoutDashboardIcon,
    component: OpsCockpitPage,
  };
}
