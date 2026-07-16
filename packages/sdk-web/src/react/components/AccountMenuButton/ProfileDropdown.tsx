import { Fragment, forwardRef, useMemo } from 'react';
import { MenuItem } from './MenuItem';
import { LockMenuItem } from './LockMenuItem';
import { TransactionSettingsSection } from './TransactionSettingsSection';
import { AccountsSection } from './AccountsSection';
import { LinkedDevicesSection } from './LinkedDevicesSection';
import { ExportKeysSection } from './ExportKeysSection';
import { PROFILE_MENU_ITEM_IDS } from './types';
import type { ProfileDropdownProps } from './types';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import './ProfileDropdown.css';

interface ProfileDropdownWithRefs extends Omit<ProfileDropdownProps, 'menuItemsRef'> {
  menuItemsRef: React.MutableRefObject<(HTMLElement | null)[]>;
  // Transaction settings props
  currentConfirmConfig?: ConfirmationConfig | null;
  onSetUiMode?: (mode: 'none' | 'modal' | 'drawer') => void;
  onToggleShowDetails?: () => void;
  onToggleSkipClick?: () => void;
  onSetDelay?: (delay: number) => void;
  transactionSettingsOpen?: boolean;
}

export const ProfileDropdown = forwardRef<HTMLDivElement, ProfileDropdownWithRefs>(
  (
    {
      isOpen,
      menuItems,
      onLock,
      onClose,
      menuItemsRef,
      toggleColors,
      currentConfirmConfig,
      onSetUiMode,
      onToggleShowDetails,
      onToggleSkipClick,
      onSetDelay,
      transactionSettingsOpen = false,
      accountsRows,
      accountsOpen = false,
      linkedDevicesOpen = false,
      exportKeysOpen = false,
      exportLoadingChain = null,
      exportRestrictionMessage,
      onExportChain,
      walletId,
      nearAccountId,
      theme = 'dark',
      highlightedMenuItemId,
    },
    ref,
  ) => {
    // Only count transaction settings if it's actually rendered (when expanded)
    const hasTransactionSettings =
      transactionSettingsOpen &&
      currentConfirmConfig &&
      onToggleShowDetails &&
      onToggleSkipClick &&
      onSetDelay;

    menuItemsRef.current.length = menuItems.length;

    const highlightedIndex = useMemo(() => {
      if (!highlightedMenuItemId) return -1;
      return menuItems.findIndex(
        (item) => item.id === highlightedMenuItemId || item.label === highlightedMenuItemId,
      );
    }, [highlightedMenuItemId, menuItems]);

    return (
      <div
        ref={ref}
        className={`w3a-profile-dropdown-morphed ${theme}`}
        data-state={isOpen ? 'open' : 'closed'}
      >
        <div className="w3a-profile-dropdown-menu">
          {/* Menu Items */}
          {menuItems.map((item, index) => {
            const refCallback = (el: HTMLElement | null) => {
              if (menuItemsRef.current) {
                menuItemsRef.current[index] = el;
              }
            };
            const isHighlighted = index === highlightedIndex;

            const isAccountsItem = item.id === PROFILE_MENU_ITEM_IDS.ACCOUNTS;
            const isLinkedDevicesItem = item.id === PROFILE_MENU_ITEM_IDS.LINKED_DEVICES;
            const isExportKeysItem = item.id === PROFILE_MENU_ITEM_IDS.EXPORT_KEYS;
            return (
              <Fragment key={item.id ?? index}>
                <MenuItem
                  ref={refCallback}
                  item={item}
                  onClose={onClose}
                  className=""
                  isHighlighted={isHighlighted}
                  // Set CSS variable to calculate stagger delay in CSS stylesheet
                  style={{ ['--stagger-item-n' as any]: index }}
                />
                {/* Expanders ride directly under their toggle items */}
                {isAccountsItem && accountsRows && accountsRows.length > 0 && (
                  <AccountsSection
                    rows={accountsRows}
                    isOpen={accountsOpen}
                    style={{ ['--stagger-item-n' as any]: index }}
                  />
                )}
                {isLinkedDevicesItem && (
                  <LinkedDevicesSection
                    walletId={walletId ?? null}
                    nearAccountId={nearAccountId ?? null}
                    isOpen={linkedDevicesOpen}
                    style={{ ['--stagger-item-n' as any]: index }}
                  />
                )}
                {isExportKeysItem && onExportChain && (
                  <ExportKeysSection
                    isOpen={exportKeysOpen}
                    loadingChain={exportLoadingChain}
                    restrictionMessage={exportRestrictionMessage}
                    onSelectChain={onExportChain}
                    style={{ ['--stagger-item-n' as any]: index }}
                  />
                )}
              </Fragment>
            );
          })}

          {/* Transaction Settings Section - Always render with animation */}
          {currentConfirmConfig &&
            (onSetUiMode || onToggleShowDetails) &&
            onToggleSkipClick &&
            onSetDelay && (
              <TransactionSettingsSection
                currentConfirmConfig={currentConfirmConfig}
                onSetUiMode={onSetUiMode}
                onToggleShowDetails={onToggleShowDetails}
                onToggleSkipClick={onToggleSkipClick}
                onSetDelay={onSetDelay}
                isOpen={transactionSettingsOpen}
                theme={theme}
                // Set CSS variable to calculate stagger delay in CSS stylesheet
                style={{ ['--stagger-item-n' as any]: menuItems.length }}
              />
            )}

          {/* Lock Section */}
          <LockMenuItem
            onLock={onLock}
            className="w3a-lock-menu-item"
            // Set CSS variable to calculate stagger delay in CSS stylesheet
            style={{
              ['--stagger-item-n' as any]: hasTransactionSettings
                ? menuItems.length + 1
                : menuItems.length,
            }}
          />
        </div>
      </div>
    );
  },
);
