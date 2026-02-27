import React from 'react';
import TatchiLogo from '@/components/icons/TatchiLogo';
import type { TopbarContextState, TopbarMenuKey, TopbarOption } from '../types';

type HomeLinkProps = {
  href: string;
  onClick: (event: React.MouseEvent<HTMLAnchorElement>) => void;
};

type DashboardTopbarProps = {
  isSidebarExpanded: boolean;
  onToggleSidebar: () => void;
  homeProps: HomeLinkProps;
  selectedContext: TopbarContextState;
  onSelectContext: (menu: TopbarMenuKey, value: string) => void;
  dropdownOptions: Record<TopbarMenuKey, TopbarOption[]>;
};

export function DashboardTopbar({
  isSidebarExpanded,
  onToggleSidebar,
  homeProps,
  selectedContext,
  onSelectContext,
  dropdownOptions,
}: DashboardTopbarProps): React.JSX.Element {
  const topbarRef = React.useRef<HTMLElement | null>(null);
  const [activeTopbarMenu, setActiveTopbarMenu] = React.useState<TopbarMenuKey | null>(null);

  React.useEffect(() => {
    if (!activeTopbarMenu) return;

    const onPointerDown = (event: PointerEvent) => {
      const next = event.target;
      if (next instanceof Node && topbarRef.current?.contains(next)) return;
      setActiveTopbarMenu(null);
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setActiveTopbarMenu(null);
    };

    window.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [activeTopbarMenu]);

  const renderTopbarDropdown = React.useCallback(
    (
      menu: TopbarMenuKey,
      label: string,
      options: TopbarOption[],
      optionsAreHighlighted: boolean = false,
      compact: boolean = false,
    ): React.JSX.Element => {
      const isOpen = activeTopbarMenu === menu;
      const currentValue = selectedContext[menu];
      const currentLabel =
        options.find((option) => option.value === currentValue)?.label ||
        options[0]?.label ||
        '';
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
            <span className="dashboard-context-card__value">{currentLabel}</span>
            <span
              className={`dashboard-chevron${isOpen ? ' dashboard-chevron--open' : ''}`}
              aria-hidden="true"
            />
          </button>

          {isOpen ? (
            <div
              className={`dashboard-context-menu${optionsAreHighlighted ? ' dashboard-context-menu--highlight' : ''}`}
              role="menu"
              aria-label={`${label} options`}
            >
              {options.map((option) => {
                const isSelected = option.value === currentValue;
                return (
                  <button
                    key={option.value}
                    type="button"
                    className={`dashboard-context-menu__item${isSelected ? ' is-active' : ''}`}
                    role="menuitemradio"
                    aria-checked={isSelected}
                    onClick={() => {
                      onSelectContext(menu, option.value);
                      setActiveTopbarMenu(null);
                    }}
                  >
                    {option.label}
                  </button>
                );
              })}
            </div>
          ) : null}
        </div>
      );
    },
    [activeTopbarMenu, onSelectContext, selectedContext],
  );

  return (
    <header ref={topbarRef} className="dashboard-topbar" aria-label="Workspace context">
      <div className="dashboard-topbar__brand">
        <button
          type="button"
          className="dashboard-sidebar-toggle"
          aria-label={isSidebarExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
          aria-expanded={isSidebarExpanded}
          onClick={onToggleSidebar}
        >
          <span />
          <span />
          <span />
        </button>
        <a
          className="navbar-static__brand dashboard-home-link"
          href={homeProps.href}
          onClick={homeProps.onClick}
          aria-label="Tatchi home"
        >
          <TatchiLogo size={22} strokeWidth={1.2} />
          <span>Tatchi</span>
        </a>
      </div>

      {renderTopbarDropdown('organization', 'Organization', dropdownOptions.organization)}
      {renderTopbarDropdown('project', 'Project', dropdownOptions.project)}
      {renderTopbarDropdown('environment', 'Environment', dropdownOptions.environment, true)}

      <div
        className="dashboard-context-card dashboard-context-card--id"
        role="group"
        aria-label="Environment id"
      >
        <span className="dashboard-context-card__label">Environment ID</span>
        <span className="dashboard-context-card__value">{selectedContext.environment || '—'}</span>
        <button
          type="button"
          className="dashboard-copy-button"
          aria-label="Copy environment id"
          disabled={!selectedContext.environment}
          onClick={() => {
            const value = String(selectedContext.environment || '').trim();
            if (!value) return;
            void window.navigator?.clipboard?.writeText(value);
          }}
        >
          <span aria-hidden="true" />
        </button>
      </div>

      {renderTopbarDropdown(
        'accountSettings',
        'Account and Settings',
        dropdownOptions.accountSettings,
        false,
        true,
      )}
    </header>
  );
}

export default DashboardTopbar;
