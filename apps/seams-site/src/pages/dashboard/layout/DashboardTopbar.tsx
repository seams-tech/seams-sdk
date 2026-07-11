import React from 'react';
import { MoonIcon, SunIcon } from '@seams/sdk/react';
import SeamsLogo from '@/components/icons/SeamsLogo';
import DashboardSidebarToggleIcon from '../icons/DashboardSidebarToggleIcon';
import type { TopbarContextState, TopbarMenuKey, TopbarOption } from '../types';

type HomeLinkProps = {
  href: string;
  onClick: (event: React.MouseEvent<HTMLAnchorElement>) => void;
};

export type TopbarSearchItem = {
  label: string;
  path: string;
  group: string;
};

type DashboardTopbarProps = {
  isSidebarExpanded: boolean;
  onToggleSidebar: () => void;
  homeProps: HomeLinkProps;
  pageTitle: string;
  selectedContext: TopbarContextState;
  onSelectContext: (menu: TopbarMenuKey, value: string) => void;
  dropdownOptions: Record<TopbarMenuKey, TopbarOption[]>;
  focusedMode?: boolean;
  focusedContextValue?: string;
  /* Trigger label for the account menu — the user's identity. */
  accountLabel?: string;
  searchItems?: TopbarSearchItem[];
  onNavigate?: (path: string) => void;
};

function isMetaK(event: KeyboardEvent): boolean {
  return (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k';
}

/* Lightweight ⌘K palette: filters navigation destinations and jumps. */
function TopbarCommandPalette({
  items,
  onNavigate,
  onClose,
}: {
  items: TopbarSearchItem[];
  onNavigate: (path: string) => void;
  onClose: () => void;
}): React.JSX.Element {
  const [query, setQuery] = React.useState('');
  const [activeIndex, setActiveIndex] = React.useState(0);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  const matches = React.useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return items;
    return items.filter((item) =>
      `${item.group} ${item.label}`.toLowerCase().includes(normalized),
    );
  }, [items, query]);

  React.useEffect(() => {
    inputRef.current?.focus();
  }, []);

  React.useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  const commit = React.useCallback(
    (item: TopbarSearchItem | undefined) => {
      if (!item) return;
      onClose();
      onNavigate(item.path);
    },
    [onClose, onNavigate],
  );

  return (
    <div
      className="dashboard-command-palette-backdrop"
      role="presentation"
      onPointerDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="dashboard-command-palette" role="dialog" aria-label="Search everything">
        <input
          ref={inputRef}
          className="dashboard-command-palette__input"
          type="search"
          placeholder="Search pages..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              event.preventDefault();
              onClose();
            } else if (event.key === 'ArrowDown') {
              event.preventDefault();
              setActiveIndex((current) => Math.min(current + 1, matches.length - 1));
            } else if (event.key === 'ArrowUp') {
              event.preventDefault();
              setActiveIndex((current) => Math.max(current - 1, 0));
            } else if (event.key === 'Enter') {
              event.preventDefault();
              commit(matches[activeIndex]);
            }
          }}
        />
        <div className="dashboard-command-palette__list" role="listbox">
          {matches.length === 0 ? (
            <p className="dashboard-command-palette__empty">No matching pages.</p>
          ) : (
            matches.map((item, index) => (
              <button
                key={item.path}
                type="button"
                role="option"
                aria-selected={index === activeIndex}
                className={`dashboard-command-palette__item${index === activeIndex ? ' is-active' : ''}`}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => commit(item)}
              >
                <span>{item.label}</span>
                <span className="dashboard-command-palette__group">{item.group}</span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

export function DashboardTopbar({
  isSidebarExpanded,
  onToggleSidebar,
  homeProps,
  pageTitle,
  selectedContext,
  onSelectContext,
  dropdownOptions,
  focusedMode = false,
  focusedContextValue,
  accountLabel,
  searchItems = [],
  onNavigate,
}: DashboardTopbarProps): React.JSX.Element {
  const topbarRef = React.useRef<HTMLElement | null>(null);
  const [accountMenuOpen, setAccountMenuOpen] = React.useState(false);
  const [paletteOpen, setPaletteOpen] = React.useState(false);
  const organizationLabel =
    focusedContextValue !== undefined
      ? focusedContextValue
      : (dropdownOptions.organization.find((entry) => entry.value === selectedContext.organization)
          ?.label || '');
  const accountName = accountLabel || 'Account';
  const accountInitial = (accountName.trim().charAt(0) || 'A').toUpperCase();
  const searchEnabled = searchItems.length > 0 && Boolean(onNavigate);

  React.useEffect(() => {
    if (!accountMenuOpen) return;
    const onPointerDown = (event: PointerEvent) => {
      const next = event.target;
      if (next instanceof Node && topbarRef.current?.contains(next)) return;
      setAccountMenuOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setAccountMenuOpen(false);
    };
    window.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [accountMenuOpen]);

  React.useEffect(() => {
    if (!searchEnabled) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (isMetaK(event)) {
        event.preventDefault();
        setPaletteOpen((current) => !current);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [searchEnabled]);

  const accountMenu = (
    <div className="dashboard-account-menu">
      <button
        type="button"
        className="dashboard-account-menu__trigger"
        aria-haspopup="menu"
        aria-expanded={accountMenuOpen}
        aria-label={`Account menu for ${accountName}`}
        onClick={() => setAccountMenuOpen((current) => !current)}
      >
        <span className="dashboard-account-menu__avatar" aria-hidden="true">
          {accountInitial}
        </span>
      </button>
      {accountMenuOpen ? (
        <div
          className="dashboard-context-menu dashboard-context-menu--actions dashboard-account-menu__list"
          role="menu"
          aria-label="Account options"
        >
          <p className="dashboard-account-menu__identity">{accountName}</p>
          {dropdownOptions.accountSettings.map((option) => {
            const icon =
              option.icon === 'sun' ? (
                <SunIcon size={18} strokeWidth={2} aria-hidden />
              ) : option.icon === 'moon' ? (
                <MoonIcon size={18} strokeWidth={2} aria-hidden />
              ) : null;
            return (
              <button
                key={option.value}
                type="button"
                className={`dashboard-context-menu__item${option.disabled === true ? ' is-disabled' : ''}`}
                role="menuitem"
                onClick={() => {
                  onSelectContext('accountSettings', option.value);
                  if (option.keepMenuOpen !== true) {
                    setAccountMenuOpen(false);
                  }
                }}
              >
                {icon ? (
                  <span className="dashboard-context-menu__theme-action">
                    <span>{option.label}</span>
                    <span
                      className="navbar-static__theme-toggle dashboard-context-menu__theme-toggle"
                      aria-hidden="true"
                    >
                      {icon}
                    </span>
                  </span>
                ) : (
                  option.label
                )}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );

  if (focusedMode) {
    return (
      <header
        ref={topbarRef}
        className="dashboard-topbar dashboard-topbar--focused"
        aria-label="Workspace context"
      >
        <div className="dashboard-topbar__brand dashboard-topbar__brand--focused">
          <a
            className="navbar-static__brand dashboard-home-link"
            href={homeProps.href}
            onClick={homeProps.onClick}
            aria-label="Seams home"
          >
            <SeamsLogo size={34} />
            <span>Seams</span>
          </a>
        </div>

        <div className="dashboard-topbar__focused-context" role="status" aria-live="polite">
          <span className="dashboard-topbar__focused-value">{organizationLabel}</span>
        </div>

        {accountMenu}
      </header>
    );
  }

  return (
    <header ref={topbarRef} className="dashboard-topbar" aria-label="Workspace context">
      <div className="dashboard-topbar__lead">
        <button
          type="button"
          className="dashboard-sidebar-toggle"
          aria-label={isSidebarExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
          aria-expanded={isSidebarExpanded}
          onClick={onToggleSidebar}
        >
          <DashboardSidebarToggleIcon />
        </button>
        <span className="dashboard-topbar__page-title">{pageTitle}</span>
      </div>

      {searchEnabled ? (
        <button
          type="button"
          className="dashboard-topbar__search"
          onClick={() => setPaletteOpen(true)}
        >
          <span className="dashboard-search-icon" aria-hidden="true" />
          <span className="dashboard-topbar__search-placeholder">Search everything...</span>
          <span className="dashboard-topbar__search-keys" aria-hidden="true">
            <kbd>⌘</kbd>
            <kbd>K</kbd>
          </span>
        </button>
      ) : (
        <span />
      )}

      <div className="dashboard-topbar__utilities">{accountMenu}</div>

      {paletteOpen && searchEnabled && onNavigate ? (
        <TopbarCommandPalette
          items={searchItems}
          onNavigate={onNavigate}
          onClose={() => setPaletteOpen(false)}
        />
      ) : null}
    </header>
  );
}

export default DashboardTopbar;
