import React from 'react'
import DashboardSidebar from '../components/dashboard/DashboardSidebar'
import DashboardTopbar from '../components/dashboard/DashboardTopbar'
import {
  DASHBOARD_TOPBAR_DROPDOWN_OPTIONS,
  DEFAULT_DASHBOARD_ROUTE,
  getRouteFromPathname,
  getViewForRoute,
  SIDEBAR_GROUPS,
} from '../components/dashboard/dashboardConfig'
import type { DashboardRoute } from '../components/dashboard/types'
import { useDashboardUiPreferences } from '../components/dashboard/useDashboardUiPreferences'
import { useSiteRouter } from '../hooks/useSiteRouter'
import { FRONTEND_CONFIG } from '../config'

type DashboardPageProps = {
  pathname?: string
}

export function DashboardPage({ pathname = '/dashboard' }: DashboardPageProps): React.JSX.Element {
  const docsOrigin = FRONTEND_CONFIG.docsOrigin
  const { go, linkProps } = useSiteRouter()
  const homeProps = linkProps('/')

  const {
    isSidebarExpanded,
    expandedGroups,
    selectedContext,
    toggleSidebar,
    toggleGroup,
    onSelectContext,
  } = useDashboardUiPreferences(pathname)

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

  const activeRoute = React.useMemo<DashboardRoute>(() => {
    const resolved = getRouteFromPathname(pathname)
    return resolved ?? DEFAULT_DASHBOARD_ROUTE
  }, [pathname])

  const activeView = React.useMemo(() => getViewForRoute(activeRoute), [activeRoute])
  const ActiveViewComponent = activeView.component

  return (
    <main
      className={`dashboard-shell${isSidebarExpanded ? '' : ' dashboard-shell--sidebar-collapsed'}`}
      aria-label="Dashboard workspace"
    >
      <DashboardTopbar
        isSidebarExpanded={isSidebarExpanded}
        onToggleSidebar={toggleSidebar}
        homeProps={homeProps}
        selectedContext={selectedContext}
        onSelectContext={onSelectContext}
        dropdownOptions={DASHBOARD_TOPBAR_DROPDOWN_OPTIONS}
      />

      <DashboardSidebar
        groups={SIDEBAR_GROUPS}
        isSidebarExpanded={isSidebarExpanded}
        expandedGroups={expandedGroups}
        activeRoute={activeRoute}
        onToggleGroup={toggleGroup}
        linkProps={linkProps}
      />

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
