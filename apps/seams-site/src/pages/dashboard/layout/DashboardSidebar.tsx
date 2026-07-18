import React from 'react';
import CopyButton from '@/components/CopyButton';
import SeamsWordmark from '@/components/icons/SeamsWordmark';
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

export type SidebarWorkspaceProps = {
  projectOptions: TopbarOption[];
  projectValue: string;
  onSelectProject: (value: string) => void;
  organizationOptions: TopbarOption[];
  organizationValue: string;
  onSelectOrganization: (value: string) => void;
};

export type SidebarProductProps = {
  products: DashboardProduct[];
  currentId: DashboardProductId;
  onSelect: (id: DashboardProductId) => void;
};

export type SidebarContextCardProps = {
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
  product?: SidebarProductProps;
  workspace?: SidebarWorkspaceProps;
  contextCard?: SidebarContextCardProps;
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
        {description ? (
          <span className="dashboard-rail-menu__item-desc">{description}</span>
        ) : null}
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

/* Workspace card below the product switcher, reference-app style: letter
   avatar + the selected project's name (real console records, not a mock),
   opening a menu of projects. An organization section appears only when the
   account can actually switch between organizations. */
function SidebarWorkspaceSwitcher({
  projectOptions,
  projectValue,
  onSelectProject,
  organizationOptions,
  organizationValue,
  onSelectOrganization,
}: SidebarWorkspaceProps): React.JSX.Element {
  const [open, setOpen] = React.useState(false);
  const rootRef = React.useRef<HTMLDivElement | null>(null);
  useDismissablePopup(open, setOpen, rootRef);
  const menuStyle = useRailMenuPosition(open, rootRef);

  const currentProject =
    projectOptions.find((option) => option.value === projectValue) || projectOptions[0] || null;
  const currentOrganization =
    organizationOptions.find((option) => option.value === organizationValue) ||
    organizationOptions[0] ||
    null;
  /* Projects are the working scope; the organization label is only a fallback
     for accounts that have not created a project yet. */
  const currentLabel = currentProject?.label || currentOrganization?.label || 'Workspace';
  const initial = (currentLabel.trim().charAt(0) || 'W').toUpperCase();
  const showOrganizations = organizationOptions.length > 1;
  const showSectionTitles = showOrganizations && projectOptions.length > 0;

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
        onClick={() => setOpen((current) => !current)}
      >
        <span className="dashboard-workspace-switcher__avatar" aria-hidden="true">
          {initial}
        </span>
        <span className="dashboard-workspace-switcher__label">{currentLabel}</span>
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
          {projectOptions.map((option) => (
            <RailMenuRow
              key={option.value}
              active={option.value === currentProject?.value}
              disabled={option.disabled === true}
              avatar={letterAvatar(option.label)}
              name={option.label}
              onSelect={() => {
                setOpen(false);
                onSelectProject(option.value);
              }}
            />
          ))}
          {projectOptions.length === 0 && !showOrganizations ? (
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
  contextCard,
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
              <SeamsWordmark height={24} theme="light" />
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
