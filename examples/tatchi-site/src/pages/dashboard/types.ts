import React from 'react';

export type SidebarGroupKey =
  | 'overview'
  | 'administration'
  | 'operationsSecurity'
  | 'integrations'
  | 'billing';

export type DashboardRoute =
  | '/dashboard/onboarding'
  | '/dashboard/wallets-list'
  | '/dashboard/policy-engine'
  | '/dashboard/gas-sponsorship'
  | '/dashboard/overview'
  | '/dashboard/observability'
  | '/dashboard/billing/account'
  | '/dashboard/invoices'
  | '/dashboard/team-members'
  | '/dashboard/audit'
  | '/dashboard/integrations/self-hosting'
  | '/dashboard/export-keys'
  | '/dashboard/api-keys'
  | '/dashboard/webhooks';

export type TopbarMenuKey = 'organization' | 'project' | 'environment' | 'accountSettings';
export type TopbarOption = {
  value: string;
  label: string;
  disabled?: boolean;
  keepMenuOpen?: boolean;
  icon?: 'sun' | 'moon';
};

export type DashboardViewComponent = () => React.JSX.Element;

export type SidebarIconProps = React.SVGProps<SVGSVGElement> & {
  size?: number | string;
  strokeWidth?: number;
};

export type SidebarIconComponent = React.ComponentType<SidebarIconProps>;

export type SidebarItem = {
  key: string;
  label: string;
  path: DashboardRoute;
  icon: SidebarIconComponent;
  component: DashboardViewComponent;
};

export type SidebarGroup = {
  key: SidebarGroupKey;
  label: string;
  items: SidebarItem[];
};

export type TopbarContextState = Record<TopbarMenuKey, string>;

export type ExpandedSidebarGroupsState = Record<SidebarGroupKey, boolean>;
