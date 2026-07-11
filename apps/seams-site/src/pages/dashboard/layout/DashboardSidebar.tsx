import React from 'react';
import CopyButton from '@/components/CopyButton';
import SeamsWordmark from '@/components/icons/SeamsWordmark';
import type {
  DashboardRoute,
  ExpandedSidebarGroupsState,
  SidebarGroup,
  SidebarGroupKey,
  TopbarOption,
} from '../types';

type LinkPropsFactory = (to: string) => {
  href: string;
  onClick: (event: React.MouseEvent<HTMLAnchorElement>) => void;
};

export type SidebarWorkspaceProps = {
  options: TopbarOption[];
  currentValue: string;
  onSelect: (value: string) => void;
};

export type SidebarContextCardProps = {
  projectOptions: TopbarOption[];
  projectValue: string;
  onSelectProject: (value: string) => void;
  environmentOptions: TopbarOption[];
  environmentValue: string;
  onSelectEnvironment: (value: string) => void;
};

type DashboardSidebarProps = {
  groups: SidebarGroup[];
  isSidebarExpanded: boolean;
  expandedGroups: ExpandedSidebarGroupsState;
  activeRoute: DashboardRoute;
  disableNavigationItems?: boolean;
  enabledWhenLockedPaths?: ReadonlySet<DashboardRoute>;
  onToggleGroup: (group: SidebarGroupKey) => void;
  linkProps: LinkPropsFactory;
  workspace?: SidebarWorkspaceProps;
  contextCard?: SidebarContextCardProps;
  homeProps?: {
    href: string;
    onClick: (event: React.MouseEvent<HTMLAnchorElement>) => void;
  };
};

/* Org (workspace) switcher card pinned at the sidebar top, reference-app
   style: letter avatar + name + chevron opening a menu of organizations. */
function SidebarWorkspaceSwitcher({
  options,
  currentValue,
  onSelect,
}: SidebarWorkspaceProps): React.JSX.Element {
  const [open, setOpen] = React.useState(false);
  const rootRef = React.useRef<HTMLDivElement | null>(null);
  const currentLabel =
    options.find((option) => option.value === currentValue)?.label ||
    options[0]?.label ||
    'Workspace';
  const initial = (currentLabel.trim().charAt(0) || 'W').toUpperCase();

  React.useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  return (
    <div ref={rootRef} className="dashboard-workspace-switcher">
      <button
        type="button"
        className="dashboard-workspace-switcher__trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        <span className="dashboard-workspace-switcher__avatar" aria-hidden="true">
          {initial}
        </span>
        <span className="dashboard-workspace-switcher__label">{currentLabel}</span>
        <svg
          className="dashboard-workspace-switcher__caret"
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="m7 15 5 5 5-5" />
          <path d="m7 9 5-5 5 5" />
        </svg>
      </button>
      {open ? (
        <div
          className="dashboard-context-menu dashboard-workspace-switcher__menu"
          role="menu"
          aria-label="Organizations"
        >
          {options.map((option) => (
            <button
              key={option.value}
              type="button"
              role="menuitemradio"
              aria-checked={option.value === currentValue}
              className={`dashboard-context-menu__item${option.value === currentValue ? ' is-active' : ''}`}
              onClick={() => {
                setOpen(false);
                onSelect(option.value);
              }}
            >
              {option.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function DashboardSidebar({
  groups,
  activeRoute,
  disableNavigationItems = false,
  enabledWhenLockedPaths,
  linkProps,
  workspace,
  contextCard,
  homeProps,
}: DashboardSidebarProps): React.JSX.Element {
  return (
    <aside className="dashboard-sidebar" aria-label="Primary dashboard navigation">
      {homeProps ? (
        <a
          className="dashboard-home-link dashboard-sidebar__brand"
          href={homeProps.href}
          onClick={homeProps.onClick}
          aria-label="Seams home"
        >
          <SeamsWordmark height={24} theme="light" />
        </a>
      ) : null}
      {workspace ? <SidebarWorkspaceSwitcher {...workspace} /> : null}
      {groups.map((group, groupIndex) => (
        <section className="dashboard-sidebar-group" key={group.key}>
          {/* First section is header-less, reference-app style; the rest get
              static muted labels (no collapse affordance). */}
          {groupIndex > 0 ? (
            <p className="dashboard-sidebar-group__title">{group.label}</p>
          ) : null}
          <ul className="dashboard-nav-list">
            {group.items.map((item) => {
              const ItemIcon = item.icon;
              const navProps = linkProps(item.path);
              const isActive = item.path === activeRoute;
              const isDisabled = disableNavigationItems && !enabledWhenLockedPaths?.has(item.path);
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
                    <span className="dashboard-nav-icon" aria-hidden="true">
                      <ItemIcon size={20} />
                    </span>
                    <span className="dashboard-nav-label">{item.label}</span>
                  </a>
                </li>
              );
            })}
          </ul>
        </section>
      ))}
      {contextCard ? (
        <div className="dashboard-sidebar-context-card" aria-label="Workspace context">
          <label className="dashboard-sidebar-context-card__field">
            <span>Project</span>
            <select
              className="dashboard-input"
              value={contextCard.projectValue}
              onChange={(event) => contextCard.onSelectProject(event.target.value)}
            >
              {contextCard.projectOptions.map((option) => (
                <option key={option.value} value={option.value} disabled={option.disabled}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="dashboard-sidebar-context-card__field">
            <span>Environment</span>
            <select
              className="dashboard-input"
              value={contextCard.environmentValue}
              onChange={(event) => contextCard.onSelectEnvironment(event.target.value)}
            >
              {contextCard.environmentOptions.map((option) => (
                <option key={option.value} value={option.value} disabled={option.disabled}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          {contextCard.environmentValue ? (
            <div className="dashboard-sidebar-context-card__id">
              <code>{contextCard.environmentValue}</code>
              <CopyButton
                text={contextCard.environmentValue}
                ariaLabel="Copy environment id"
                className="dashboard-context-copy"
                size={14}
              />
            </div>
          ) : null}
        </div>
      ) : null}
    </aside>
  );
}

export default DashboardSidebar;
