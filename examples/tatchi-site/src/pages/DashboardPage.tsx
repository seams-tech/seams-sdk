import React from 'react'
import { useSiteRouter } from '../hooks/useSiteRouter'
import TatchiLogo from '../components/icons/TatchiLogo'
import { ApiKeyManagementPage } from './dashboard/ApiKeyManagementPage'
import { AppSettingsPage } from './dashboard/AppSettingsPage'
import { ExportKeysSettingsPage } from './dashboard/ExportKeysSettingsPage'
import { GasSponsorshipSmartWalletsPage } from './dashboard/GasSponsorshipSmartWalletsPage'
import { PolicyEnginePage } from './dashboard/PolicyEnginePage'
import { SearchUserWalletsPage } from './dashboard/SearchUserWalletsPage'
import { UserWalletsListPage } from './dashboard/UserWalletsListPage'
import { WebhooksPage } from './dashboard/WebhooksPage'

type SidebarGroupKey =
  | 'walletInfrastructure'
  | 'securityPolicy'
  | 'integrationsAutomation'
  | 'environmentSettings'

type DashboardRoute =
  | '/dashboard/wallets-list'
  | '/dashboard/wallets-search'
  | '/dashboard/policy-engine'
  | '/dashboard/gas-smart-wallets'
  | '/dashboard/app-settings'
  | '/dashboard/export-keys'
  | '/dashboard/api-keys'
  | '/dashboard/webhooks'

type TopbarMenuKey = 'organization' | 'project' | 'environment' | 'accountSettings'
type DashboardViewComponent = () => React.JSX.Element

type SidebarItem = {
  key: string
  label: string
  path: DashboardRoute
  iconClass: string
  component: DashboardViewComponent
}

type SidebarGroup = {
  key: SidebarGroupKey
  label: string
  items: SidebarItem[]
}

const SIDEBAR_GROUPS: SidebarGroup[] = [
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
]

const DEFAULT_DASHBOARD_ROUTE: DashboardRoute = '/dashboard/wallets-list'

function getRouteFromPathname(pathname: string): DashboardRoute | null {
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === pathname) return item.path
    }
  }
  return null
}

function getViewForRoute(route: DashboardRoute): SidebarItem {
  for (const group of SIDEBAR_GROUPS) {
    for (const item of group.items) {
      if (item.path === route) return item
    }
  }
  return SIDEBAR_GROUPS[0]!.items[0]!
}

type DashboardPageProps = {
  pathname?: string
}

export function DashboardPage({ pathname = '/dashboard' }: DashboardPageProps): React.JSX.Element {
  const docsOrigin = import.meta.env.VITE_DOCS_ORIGIN || 'https://docs.example.localhost'
  const { go, linkProps } = useSiteRouter()
  const homeProps = linkProps('/')
  const topbarRef = React.useRef<HTMLElement | null>(null)

  const [isSidebarExpanded, setIsSidebarExpanded] = React.useState<boolean>(true)
  const [expandedGroups, setExpandedGroups] = React.useState<Record<SidebarGroupKey, boolean>>({
    walletInfrastructure: true,
    securityPolicy: true,
    integrationsAutomation: true,
    environmentSettings: true,
  })
  const [activeTopbarMenu, setActiveTopbarMenu] = React.useState<TopbarMenuKey | null>(null)
  const [selectedContext, setSelectedContext] = React.useState<Record<TopbarMenuKey, string>>({
    organization: 'Game1',
    project: 'Game1',
    environment: 'Sandbox',
    accountSettings: 'Account & Settings',
  })

  React.useEffect(() => {
    if (pathname === '/dashboard') {
      go(DEFAULT_DASHBOARD_ROUTE)
    }
  }, [go, pathname])

  React.useEffect(() => {
    if (pathname !== '/dashboard' && pathname.startsWith('/dashboard/') && !getRouteFromPathname(pathname)) {
      go(DEFAULT_DASHBOARD_ROUTE)
    }
  }, [go, pathname])

  React.useEffect(() => {
    if (!activeTopbarMenu) return

    const onPointerDown = (event: PointerEvent) => {
      const next = event.target
      if (next instanceof Node && topbarRef.current?.contains(next)) return
      setActiveTopbarMenu(null)
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setActiveTopbarMenu(null)
    }

    window.addEventListener('pointerdown', onPointerDown)
    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('pointerdown', onPointerDown)
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [activeTopbarMenu])

  const activeRoute = React.useMemo<DashboardRoute>(() => {
    const resolved = getRouteFromPathname(pathname)
    return resolved ?? DEFAULT_DASHBOARD_ROUTE
  }, [pathname])

  const activeView = React.useMemo(() => getViewForRoute(activeRoute), [activeRoute])
  const ActiveViewComponent = activeView.component

  const toggleSidebar = React.useCallback(() => {
    setIsSidebarExpanded((current) => !current)
  }, [])

  const toggleGroup = React.useCallback((group: SidebarGroupKey) => {
    setExpandedGroups((current) => ({
      ...current,
      [group]: !current[group],
    }))
  }, [])

  const topbarDropdownOptions: Record<TopbarMenuKey, string[]> = React.useMemo(() => ({
    organization: ['Game1', 'Arc Labs', 'Nova Studio'],
    project: ['Game1', 'Wallet Ops', 'Payments Infra'],
    environment: ['Sandbox', 'Staging', 'Production'],
    accountSettings: ['Account & Settings', 'Team members', 'Roles and permissions', 'Audit logs'],
  }), [])

  const onSelectTopbarOption = React.useCallback((menu: TopbarMenuKey, value: string) => {
    setSelectedContext((current) => ({
      ...current,
      [menu]: value,
    }))
    setActiveTopbarMenu(null)
  }, [])

  const renderTopbarDropdown = React.useCallback((
    menu: TopbarMenuKey,
    label: string,
    options: string[],
    optionsAreHighlighted: boolean = false,
    compact: boolean = false,
  ): React.JSX.Element => {
    const isOpen = activeTopbarMenu === menu
    const currentValue = selectedContext[menu]
    return (
      <div className="dashboard-context-dropdown">
        <button
          type="button"
          className={`dashboard-context-card${optionsAreHighlighted ? ' dashboard-context-card--highlight' : ''}${compact ? ' dashboard-context-card--compact' : ''}`}
          aria-haspopup="menu"
          aria-expanded={isOpen}
          onClick={() => setActiveTopbarMenu((current) => (current === menu ? null : menu))}
        >
          {!compact ? <span className="dashboard-context-card__label">{label}</span> : null}
          <span className="dashboard-context-card__value">{currentValue}</span>
          <span className={`dashboard-chevron${isOpen ? ' dashboard-chevron--open' : ''}`} aria-hidden="true" />
        </button>

        {isOpen ? (
          <div className={`dashboard-context-menu${optionsAreHighlighted ? ' dashboard-context-menu--highlight' : ''}`} role="menu" aria-label={`${label} options`}>
            {options.map((option) => {
              const isSelected = option === currentValue
              return (
                <button
                  key={option}
                  type="button"
                  className={`dashboard-context-menu__item${isSelected ? ' is-active' : ''}`}
                  role="menuitemradio"
                  aria-checked={isSelected}
                  onClick={() => onSelectTopbarOption(menu, option)}
                >
                  {option}
                </button>
              )
            })}
          </div>
        ) : null}
      </div>
    )
  }, [activeTopbarMenu, onSelectTopbarOption, selectedContext])

  return (
    <main
      className={`dashboard-shell${isSidebarExpanded ? '' : ' dashboard-shell--sidebar-collapsed'}`}
      aria-label="Dashboard workspace"
    >
      <header ref={topbarRef} className="dashboard-topbar" aria-label="Workspace context">
        <div className="dashboard-topbar__brand">
          <button
            type="button"
            className="dashboard-sidebar-toggle"
            aria-label={isSidebarExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
            aria-expanded={isSidebarExpanded}
            onClick={toggleSidebar}
          >
            <span />
            <span />
            <span />
          </button>
          <a className="navbar-static__brand dashboard-home-link" href={homeProps.href} onClick={homeProps.onClick} aria-label="Tatchi home">
            <TatchiLogo size={22} strokeWidth={1.2} />
            <span>Tatchi</span>
          </a>
        </div>

        {renderTopbarDropdown('organization', 'Organization', topbarDropdownOptions.organization)}
        {renderTopbarDropdown('project', 'Project', topbarDropdownOptions.project)}
        {renderTopbarDropdown('environment', 'Environment', topbarDropdownOptions.environment, true)}

        <div className="dashboard-context-card dashboard-context-card--id" role="group" aria-label="Environment id">
          <span className="dashboard-context-card__label">Environment ID</span>
          <span className="dashboard-context-card__value">7f5a014f-d3f2-4ac8-911e-12db113d20...</span>
          <button type="button" className="dashboard-copy-button" aria-label="Copy environment id">
            <span aria-hidden="true" />
          </button>
        </div>

        {renderTopbarDropdown('accountSettings', 'Account and Settings', topbarDropdownOptions.accountSettings, false, true)}
      </header>

      <aside className="dashboard-sidebar" aria-label="Primary dashboard navigation">
        {SIDEBAR_GROUPS.map((group) => (
          <section className="dashboard-sidebar-group" key={group.key}>
            <button
              type="button"
              className="dashboard-group-toggle"
              onClick={() => toggleGroup(group.key)}
              aria-expanded={expandedGroups[group.key]}
            >
              <span className="dashboard-sidebar-group__title">{group.label}</span>
              <span className={`dashboard-nav-caret${expandedGroups[group.key] ? ' dashboard-nav-caret--open' : ''}`} aria-hidden="true" />
            </button>

            {expandedGroups[group.key] || !isSidebarExpanded ? (
              <ul className="dashboard-nav-list">
                {group.items.map((item) => {
                  const navProps = linkProps(item.path)
                  const isActive = item.path === activeRoute
                  return (
                    <li key={item.key}>
                      <a
                        className={`dashboard-nav-item${isActive ? ' dashboard-nav-item--active' : ''}`}
                        href={navProps.href}
                        onClick={navProps.onClick}
                        aria-current={isActive ? 'page' : undefined}
                      >
                        <span className={`dashboard-nav-icon ${item.iconClass}`} aria-hidden="true" />
                        <span className="dashboard-nav-label">{item.label}</span>
                      </a>
                    </li>
                  )
                })}
              </ul>
            ) : null}
          </section>
        ))}
      </aside>

      <section className="dashboard-main" aria-labelledby="dashboard-main-title">
        <h1 id="dashboard-main-title" className="dashboard-main__title">{activeView.label}</h1>

        <p className="dashboard-info-banner">
          Build target for <strong>{activeView.label}</strong> from dashboard requirements. For more information,
          see the docs <a href={docsOrigin} target="_blank" rel="noreferrer">here</a>.
        </p>

        <ActiveViewComponent />
      </section>
    </main>
  )
}

export default DashboardPage
