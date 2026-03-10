import React from 'react';
import { ChevronDownIcon } from '../icons/SidebarIcons';
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
      {groups.map((group) => {
        const isGroupExpanded = expandedGroups[group.key] || !isSidebarExpanded;
        const groupPanelId = `dashboard-sidebar-group-panel-${group.key}`;
        return (
          <section className="dashboard-sidebar-group" key={group.key}>
            <button
              type="button"
              className="dashboard-group-toggle"
              onClick={() => onToggleGroup(group.key)}
              aria-expanded={expandedGroups[group.key]}
              aria-controls={groupPanelId}
            >
              <span className="dashboard-sidebar-group__title">{group.label}</span>
              <ChevronDownIcon
                className={`dashboard-nav-caret${expandedGroups[group.key] ? ' is-expanded' : ''}`}
                size={16}
                strokeWidth={2.2}
              />
            </button>

            <div
              id={groupPanelId}
              className={`dashboard-sidebar-group__panel${isGroupExpanded ? ' is-expanded' : ''}`}
              aria-hidden={!isGroupExpanded}
            >
              <div className="dashboard-sidebar-group__panel-inner">
                <ul className="dashboard-nav-list">
                  {group.items.map((item) => {
                    const ItemIcon = item.icon;
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
                          tabIndex={isDisabled || !isGroupExpanded ? -1 : undefined}
                        >
                          <span className="dashboard-nav-icon" aria-hidden="true">
                            <ItemIcon size={20} />
                          </span>
                          <span className="dashboard-nav-label">{item.label}</span>
                        </a>
                      </li>
                    );
                  })}
                </ul>
              </div>
            </div>
          </section>
        );
      })}
    </aside>
  );
}

export default DashboardSidebar;
