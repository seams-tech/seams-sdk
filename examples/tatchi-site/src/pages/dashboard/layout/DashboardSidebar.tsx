import React from 'react';
import type {
  DashboardRoute,
  ExpandedSidebarGroupsState,
  SidebarGroup,
  SidebarGroupKey,
} from '../types';

type LinkPropsFactory = (to: string) => {
  href: string;
  onClick: (event: React.MouseEvent<HTMLAnchorElement>) => void;
};

type DashboardSidebarProps = {
  groups: SidebarGroup[];
  isSidebarExpanded: boolean;
  expandedGroups: ExpandedSidebarGroupsState;
  activeRoute: DashboardRoute;
  disableNavigationItems?: boolean;
  onToggleGroup: (group: SidebarGroupKey) => void;
  linkProps: LinkPropsFactory;
};

export function DashboardSidebar({
  groups,
  isSidebarExpanded,
  expandedGroups,
  activeRoute,
  disableNavigationItems = false,
  onToggleGroup,
  linkProps,
}: DashboardSidebarProps): React.JSX.Element {
  return (
    <aside className="dashboard-sidebar" aria-label="Primary dashboard navigation">
      {groups.map((group) => (
        <section className="dashboard-sidebar-group" key={group.key}>
          <button
            type="button"
            className="dashboard-group-toggle"
            onClick={() => onToggleGroup(group.key)}
            aria-expanded={expandedGroups[group.key]}
          >
            <span className="dashboard-sidebar-group__title">{group.label}</span>
            <span
              className={`dashboard-nav-caret${expandedGroups[group.key] ? ' dashboard-nav-caret--open' : ''}`}
              aria-hidden="true"
            />
          </button>

          {expandedGroups[group.key] || !isSidebarExpanded ? (
            <ul className="dashboard-nav-list">
              {group.items.map((item) => {
                const navProps = linkProps(item.path);
                const isActive = item.path === activeRoute;
                const isDisabled = disableNavigationItems;
                return (
                  <li key={item.key}>
                    <a
                      className={`dashboard-nav-item${isActive ? ' dashboard-nav-item--active' : ''}${isDisabled ? ' dashboard-nav-item--disabled' : ''}`}
                      href={navProps.href}
                      onClick={
                        isDisabled
                          ? (event) => {
                              event.preventDefault();
                            }
                          : navProps.onClick
                      }
                      aria-current={isActive ? 'page' : undefined}
                      aria-disabled={isDisabled || undefined}
                      tabIndex={isDisabled ? -1 : undefined}
                    >
                      <span className={`dashboard-nav-icon ${item.iconClass}`} aria-hidden="true" />
                      <span className="dashboard-nav-label">{item.label}</span>
                    </a>
                  </li>
                );
              })}
            </ul>
          ) : null}
        </section>
      ))}
    </aside>
  );
}

export default DashboardSidebar;
