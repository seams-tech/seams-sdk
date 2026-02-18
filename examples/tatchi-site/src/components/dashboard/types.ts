import React from 'react'

export type SidebarGroupKey =
  | 'walletInfrastructure'
  | 'securityPolicy'
  | 'integrationsAutomation'
  | 'environmentSettings'

export type DashboardRoute =
  | '/dashboard/wallets-list'
  | '/dashboard/wallets-search'
  | '/dashboard/policy-engine'
  | '/dashboard/gas-smart-wallets'
  | '/dashboard/app-settings'
  | '/dashboard/export-keys'
  | '/dashboard/api-keys'
  | '/dashboard/webhooks'

export type TopbarMenuKey = 'organization' | 'project' | 'environment' | 'accountSettings'

export type DashboardViewComponent = () => React.JSX.Element

export type SidebarItem = {
  key: string
  label: string
  path: DashboardRoute
  iconClass: string
  component: DashboardViewComponent
}

export type SidebarGroup = {
  key: SidebarGroupKey
  label: string
  items: SidebarItem[]
}

export type TopbarContextState = Record<TopbarMenuKey, string>

export type ExpandedSidebarGroupsState = Record<SidebarGroupKey, boolean>
