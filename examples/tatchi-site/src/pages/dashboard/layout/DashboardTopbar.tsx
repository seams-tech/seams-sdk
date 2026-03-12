import React from 'react';
import { MoonIcon, SunIcon } from '@tatchi-xyz/sdk/react';
import CopyButton from '@/components/CopyButton';
import TatchiLogo from '@/components/icons/TatchiLogo';
import DashboardSidebarToggleIcon from '../icons/DashboardSidebarToggleIcon';
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
  focusedMode?: boolean;
  focusedContextValue?: string;
};

export function DashboardTopbar({
  isSidebarExpanded,
  onToggleSidebar,
  homeProps,
  selectedContext,
  onSelectContext,
  dropdownOptions,
  focusedMode = false,
  focusedContextValue,
}: DashboardTopbarProps): React.JSX.Element {
  const topbarRef = React.useRef<HTMLElement | null>(null);
  const [activeTopbarMenu, setActiveTopbarMenu] = React.useState<TopbarMenuKey | null>(null);
  const environmentId = String(selectedContext.environment || '').trim();
  const organizationLabel =
    focusedContextValue !== undefined
      ? focusedContextValue
      : (dropdownOptions.organization.find((entry) => entry.value === selectedContext.organization)
          ?.label ||
          selectedContext.organization ||
          'Organization');

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
      const isActionMenu = menu === 'accountSettings';
      const currentValue = selectedContext[menu];
      const currentLabel =
        options.find((option) => option.value === currentValue)?.label ||
        options.find((option) => option.disabled !== true)?.label ||
        options[0]?.label ||
        '';
      return (
        <div className={`dashboard-context-dropdown dashboard-context-dropdown--${menu}`}>
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
              className={`dashboard-context-menu${optionsAreHighlighted ? ' dashboard-context-menu--highlight' : ''}${isActionMenu ? ' dashboard-context-menu--actions' : ''}`}
              role="menu"
              aria-label={`${label} options`}
            >
              {options.map((option) => {
                const isSelected = !isActionMenu && option.value === currentValue;
                const isDisabled = option.disabled === true;
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
                    className={`dashboard-context-menu__item${isSelected ? ' is-active' : ''}${isDisabled ? ' is-disabled' : ''}`}
                    role={isActionMenu ? 'menuitem' : 'menuitemradio'}
                    aria-checked={isActionMenu ? undefined : isSelected}
                    onClick={() => {
                      onSelectContext(menu, option.value);
                      if (option.keepMenuOpen !== true) {
                        setActiveTopbarMenu(null);
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
    },
    [activeTopbarMenu, onSelectContext, selectedContext],
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
            aria-label="Tatchi home"
          >
            <TatchiLogo size={22} strokeWidth={1.2} />
            <span>Tatchi</span>
          </a>
        </div>

        <div className="dashboard-topbar__focused-context" role="status" aria-live="polite">
          <span className="dashboard-topbar__focused-label">Onboarding</span>
          <span className="dashboard-topbar__focused-value">{organizationLabel}</span>
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
          <DashboardSidebarToggleIcon />
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
        {environmentId ? (
          <CopyButton
            text={environmentId}
            ariaLabel="Copy environment id"
            className="dashboard-context-copy"
            size={14}
          />
        ) : (
          <span className="dashboard-context-copy-placeholder" aria-hidden="true" />
        )}
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
