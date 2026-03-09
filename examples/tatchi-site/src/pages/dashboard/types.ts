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
  | '/dashboard/gas-smart-wallets'
  | '/dashboard/overview'
  | '/dashboard/observability'
  | '/dashboard/billing'
  | '/dashboard/team-members'
  | '/dashboard/audit'
  | '/dashboard/enterprise-isolation'
  | '/dashboard/export-keys'
  | '/dashboard/api-keys'
  | '/dashboard/webhooks';

export type TopbarMenuKey = 'organization' | 'project' | 'environment' | 'accountSettings';
export type TopbarOption = {
  value: string;
  label: string;
};

export type DashboardViewComponent = () => React.JSX.Element;

export type SidebarItem = {
  key: string;
  label: string;
  path: DashboardRoute;
  iconClass: string;
  component: DashboardViewComponent;
};

export type SidebarGroup = {
  key: SidebarGroupKey;
  label: string;
  items: SidebarItem[];
};

export type TopbarContextState = Record<TopbarMenuKey, string>;

export type ExpandedSidebarGroupsState = Record<SidebarGroupKey, boolean>;
