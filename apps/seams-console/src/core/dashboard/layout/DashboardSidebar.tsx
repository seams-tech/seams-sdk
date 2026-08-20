import React from 'react';
import { dashboardCreateIntentHref } from '../utils/routeCreateIntent';
import { PlusIcon } from '../icons/SidebarIcons';
import SeamsWordmark from '@core/components/SeamsWordmark';
import type {
  DashboardProduct,
  DashboardProductId,
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

export type SidebarProjectGroup = {
  project: TopbarOption;
  environments: TopbarOption[];
};

export type SidebarWorkspaceProps = {
  projectGroups: SidebarProjectGroup[];
  projectValue: string;
  environmentValue: string;
  onSelectEnvironment: (projectValue: string, environmentValue: string) => void;
  organizationOptions: TopbarOption[];
  organizationValue: string;
  onSelectOrganization: (value: string) => void;
};

export type SidebarProductProps = {
  products: DashboardProduct[];
  currentId: DashboardProductId;
  onSelect: (id: DashboardProductId) => void;
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
  product?: SidebarProductProps;
  workspace?: SidebarWorkspaceProps;
  homeProps?: {
    href: string;
    onClick: (event: React.MouseEvent<HTMLAnchorElement>) => void;
  };
};

/* Close an open switcher popup on outside pointerdown or Escape. */
function useDismissablePopup(
  open: boolean,
  setOpen: (value: boolean) => void,
  rootRef: React.RefObject<HTMLDivElement | null>,
): void {
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
  }, [open, rootRef, setOpen]);
}

/* The rail shows the project at rest and slides to the environment on hover,
   so the scope is one glance away without a second permanent line. */
function WorkspaceSwitcherLabel({
  projectLabel,
  environmentLabel,
}: {
  projectLabel: string;
  environmentLabel: string;
}): React.JSX.Element {
  return (
    <>
      <span className="dashboard-workspace-switcher__label" aria-hidden="true">
        <span className="dashboard-workspace-switcher__ticker">
          <span
            className="dashboard-workspace-switcher__ticker-row dashboard-workspace-switcher__ticker-row--project"
            title={projectLabel}
          >
            {projectLabel}
          </span>
          <span
            className="dashboard-workspace-switcher__ticker-row dashboard-workspace-switcher__ticker-row--environment"
            title={environmentLabel}
          >
            {environmentLabel}
          </span>
        </span>
      </span>
      <span className="dashboard-visually-hidden">
        {projectLabel}, {environmentLabel}
      </span>
    </>
  );
}

/* The rail scrolls (overflow-y: auto), which would clip an absolutely
   positioned popover to the rail's width. Fixed positioning escapes that clip
   so the menu can be wider than the rail, reference-app style. The trigger
   lives in the sticky head, so its viewport position is stable while open. */
function useRailMenuPosition(
  open: boolean,
  rootRef: React.RefObject<HTMLDivElement | null>,
): React.CSSProperties | undefined {
  const [style, setStyle] = React.useState<React.CSSProperties | undefined>(undefined);
  React.useLayoutEffect(() => {
    if (!open) {
      setStyle(undefined);
      return;
    }
    const root = rootRef.current;
    if (!root) return;
    const rect = root.getBoundingClientRect();
    const width = Math.max(rect.width, Math.min(320, window.innerWidth - rect.left - 16));
    setStyle({
      position: 'fixed',
      top: rect.bottom + 6,
      left: rect.left,
      right: 'auto',
      width,
    });
  }, [open, rootRef]);
  return style;
}

function RailCaret({ className }: { className: string }): React.JSX.Element {
  return (
    <svg
      className={className}
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
  );
}

/* One avatar row inside a switcher popover: avatar + name (+ description),
   with a trailing check on the active row or a "Soon" pill on unshipped
   products. Disabled rows keep their click as a no-op. */
function RailMenuRow({
  active,
  soon = false,
  disabled = false,
  avatar,
  name,
  description,
  onSelect,
}: {
  active: boolean;
  soon?: boolean;
  disabled?: boolean;
  avatar: React.ReactNode;
  name: string;
  description?: string;
  onSelect: () => void;
}): React.JSX.Element {
  const blocked = soon || disabled;
  return (
    <button
      type="button"
      role="menuitemradio"
      aria-checked={active}
      aria-disabled={blocked || undefined}
      className={`dashboard-rail-menu__item${active ? ' is-active' : ''}${blocked ? ' is-soon' : ''}`}
      onClick={() => {
        if (blocked) return;
        onSelect();
      }}
    >
      {avatar}
      <span className="dashboard-rail-menu__item-text">
        <span className="dashboard-rail-menu__item-name">{name}</span>
        {description ? <span className="dashboard-rail-menu__item-desc">{description}</span> : null}
      </span>
      {soon ? (
        <span className="dashboard-rail-menu__soon">Soon</span>
      ) : active ? (
        <svg
          className="dashboard-rail-menu__check"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.4"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M20 6 9 17l-5-5" />
        </svg>
      ) : null}
    </button>
  );
}

/* The workspace switcher treats a project/environment pair as one scope. */
function SidebarWorkspaceSwitcher({
  projectGroups,
  projectValue,
  environmentValue,
  onSelectEnvironment,
  organizationOptions,
  organizationValue,
  onSelectOrganization,
}: SidebarWorkspaceProps): React.JSX.Element {
  const [open, setOpen] = React.useState(false);
  const rootRef = React.useRef<HTMLDivElement | null>(null);
  useDismissablePopup(open, setOpen, rootRef);
  const menuStyle = useRailMenuPosition(open, rootRef);

  const currentProjectGroup =
    projectGroups.find((group) => group.project.value === projectValue) || projectGroups[0] || null;
  const currentProject = currentProjectGroup?.project || null;
  const currentEnvironment =
    currentProjectGroup?.environments.find((option) => option.value === environmentValue) || null;
  const currentOrganization =
    organizationOptions.find((option) => option.value === organizationValue) ||
    organizationOptions[0] ||
    null;
  /* Projects are the working scope; the organization label is only a fallback
     for accounts that have not created a project yet. */
  const currentLabel = currentProject?.label || currentOrganization?.label || 'Workspace';
  const currentEnvironmentLabel = currentEnvironment?.label || environmentValue || 'No environment';
  const initial = (currentLabel.trim().charAt(0) || 'W').toUpperCase();
  const showOrganizations = organizationOptions.length > 1;
  const showSectionTitles = showOrganizations && projectGroups.length > 0;

  const letterAvatar = (label: string) => (
    <span
      className="dashboard-rail-menu__item-avatar dashboard-rail-menu__item-avatar--letter"
      aria-hidden="true"
    >
      {(label.trim().charAt(0) || 'W').toUpperCase()}
    </span>
  );

  return (
    <div ref={rootRef} className="dashboard-workspace-switcher">
      <button
        type="button"
        className="dashboard-workspace-switcher__trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`${currentLabel}, ${currentEnvironmentLabel}`}
        onClick={() => setOpen((current) => !current)}
      >
        <span className="dashboard-workspace-switcher__avatar" aria-hidden="true">
          {initial}
        </span>
        <WorkspaceSwitcherLabel
          projectLabel={currentLabel}
          environmentLabel={currentEnvironmentLabel}
        />
        <RailCaret className="dashboard-workspace-switcher__caret" />
      </button>
      {open ? (
        <div
          className="dashboard-context-menu dashboard-rail-menu"
          style={menuStyle}
          role="menu"
          aria-label="Workspace"
        >
          {showSectionTitles ? (
            <p className="dashboard-rail-menu__section-title">Projects</p>
          ) : null}
          {projectGroups.map((group) => (
            <div
              key={group.project.value}
              className="dashboard-workspace-menu__project"
              role="group"
              aria-label={group.project.label}
            >
              <div className="dashboard-workspace-menu__project-heading">
                {letterAvatar(group.project.label)}
                <span>{group.project.label}</span>
              </div>
              <div className="dashboard-workspace-menu__environments">
                {group.environments.map((environment) => {
                  const active =
                    group.project.value === currentProject?.value &&
                    environment.value === environmentValue;
                  const disabled = group.project.disabled === true || environment.disabled === true;
                  return (
                    <button
                      key={environment.value}
                      type="button"
                      role="menuitemradio"
                      aria-checked={active}
                      aria-disabled={disabled || undefined}
                      className={`dashboard-workspace-menu__environment${active ? ' is-active' : ''}${disabled ? ' is-disabled' : ''}`}
                      onClick={() => {
                        if (disabled) return;
                        setOpen(false);
                        onSelectEnvironment(group.project.value, environment.value);
                      }}
                    >
                      <span
                        className="dashboard-workspace-menu__environment-dot"
                        aria-hidden="true"
                      />
                      <span>{environment.label}</span>
                      {active ? (
                        <svg
                          className="dashboard-rail-menu__check"
                          width="16"
                          height="16"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2.4"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          aria-hidden="true"
                        >
                          <path d="M20 6 9 17l-5-5" />
                        </svg>
                      ) : null}
                    </button>
                  );
                })}
                {group.environments.length === 0 ? (
                  <p className="dashboard-workspace-menu__empty">No environments</p>
                ) : null}
              </div>
            </div>
          ))}
          {projectGroups.length === 0 && !showOrganizations ? (
            <p className="dashboard-rail-menu__empty">No projects yet</p>
          ) : null}
          {showOrganizations ? (
            <>
              <p className="dashboard-rail-menu__section-title">Organizations</p>
              {organizationOptions.map((option) => (
                <RailMenuRow
                  key={option.value}
                  active={option.value === currentOrganization?.value}
                  disabled={option.disabled === true}
                  avatar={letterAvatar(option.label)}
                  name={option.label}
                  onSelect={() => {
                    setOpen(false);
                    onSelectOrganization(option.value);
                  }}
                />
              ))}
            </>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

/* Product-line switcher pinned at the sidebar top, reference-app style: a
   single-line gradient avatar + product name + up/down chevron, opening a
   menu of products each with a short description. Not-yet-shipped products
   render disabled with a "Soon" pill. */
function SidebarProductSwitcher({
  products,
  currentId,
  onSelect,
}: SidebarProductProps): React.JSX.Element {
  const [open, setOpen] = React.useState(false);
  const rootRef = React.useRef<HTMLDivElement | null>(null);
  useDismissablePopup(open, setOpen, rootRef);
  const menuStyle = useRailMenuPosition(open, rootRef);
  const current = products.find((product) => product.id === currentId) || products[0];

  if (!current) return <></>;

  return (
    <div ref={rootRef} className="dashboard-product-switcher">
      <button
        type="button"
        className="dashboard-product-switcher__trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <span
          className="dashboard-product-switcher__avatar"
          style={{ backgroundImage: `url('${current.gradient}')` }}
          aria-hidden="true"
        />
        <span className="dashboard-product-switcher__label">{current.name}</span>
        <RailCaret className="dashboard-product-switcher__caret" />
      </button>
      {open ? (
        <div
          className="dashboard-context-menu dashboard-rail-menu"
          style={menuStyle}
          role="menu"
          aria-label="Products"
        >
          {products.map((product) => (
            <RailMenuRow
              key={product.id}
              active={product.id === currentId}
              soon={!product.available}
              avatar={
                <span
                  className="dashboard-rail-menu__item-avatar dashboard-rail-menu__item-avatar--image"
                  style={{ backgroundImage: `url('${product.gradient}')` }}
                  aria-hidden="true"
                />
              }
              name={product.name}
              description={product.description}
              onSelect={() => {
                setOpen(false);
                onSelect(product.id);
              }}
            />
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
  product,
  workspace,
  homeProps,
}: DashboardSidebarProps): React.JSX.Element {
  return (
    <aside className="dashboard-sidebar" aria-label="Primary dashboard navigation">
      {/* Pinned head: wordmark + product/org switchers stay fixed at the sidebar
          top (reference-app style) while the nav list scrolls beneath them. */}
      {homeProps || product || workspace ? (
        <div className="dashboard-sidebar__head">
          {homeProps ? (
            <a
              className="dashboard-home-link dashboard-sidebar__brand"
              href={homeProps.href}
              onClick={homeProps.onClick}
              aria-label="Seams home"
            >
              <SeamsWordmark height={24} />
            </a>
          ) : null}
          {product ? <SidebarProductSwitcher {...product} /> : null}
          {workspace ? <SidebarWorkspaceSwitcher {...workspace} /> : null}
        </div>
      ) : null}
      {groups.map((group, groupIndex) => (
        <section className="dashboard-sidebar-group" key={group.key}>
          {/* First section is header-less, reference-app style; the rest get
              static muted labels (no collapse affordance). */}
          {groupIndex > 0 ? <p className="dashboard-sidebar-group__title">{group.label}</p> : null}
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
                  {item.createLabel && !isDisabled ? (
                    <button
                      type="button"
                      className="dashboard-nav-create"
                      aria-label={item.createLabel}
                      title={item.createLabel}
                      onClick={(event) => {
                        event.preventDefault();
                        linkProps(dashboardCreateIntentHref(item.path)).onClick(
                          event as unknown as React.MouseEvent<HTMLAnchorElement>,
                        );
                      }}
                    >
                      <PlusIcon size={14} />
                    </button>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </aside>
  );
}

export default DashboardSidebar;
