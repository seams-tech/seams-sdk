import type { ToggleColorProps } from './Toggle';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { ThemeMode } from '@/core/signingEngine/uiConfirm/ui/confirm-ui-types';
import type { ConfirmationConfig } from '@/core/types/signer-worker';

export interface ProfileDimensions {
  width: number;
  height: number;
}

export interface ProfileAnimationConfig {
  duration: number;
  delay: number;
  ease: string;
}

export const PROFILE_MENU_ITEM_IDS = {
  ACCOUNTS: 'accounts',
  EXPORT_KEYS: 'export-keys',
  RECOVERY_CODES: 'recovery-codes',
  SCAN_LINK_DEVICE: 'scan-link-device',
  LINKED_DEVICES: 'linked-devices',
  TRANSACTION_SETTINGS: 'transaction-settings',
} as const;

/** Which threshold key set an Export Keys row exports. */
export type ExportChain = 'near' | 'evm';

/** One chain row in the expandable Accounts section: links out to the chain's
 * block explorer on the user's account page. */
export interface AccountsSectionRow {
  id: string;
  label: string;
  address: string;
  href: string;
}

export type ProfileSettingsMenuItemId =
  (typeof PROFILE_MENU_ITEM_IDS)[keyof typeof PROFILE_MENU_ITEM_IDS];

export interface MenuItem {
  id?: ProfileSettingsMenuItemId | (string & {});
  icon: React.ReactNode;
  label: string;
  description: string;
  disabled: boolean;
  onClick?: () => void;
  // When true, clicking this item will NOT close the dropdown
  keepOpenOnClick?: boolean;
}

export interface HighlightedProfileMenuItem {
  id: ProfileSettingsMenuItemId | (string & {});
  /**
   * When true (default), focus the highlighted button when the menu opens.
   */
  focus?: boolean;
}

export interface DeviceLinkingScannerParams {
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: LinkDeviceFlowEvent) => void;
  fundingAmount?: string;
}

export interface AccountMenuButtonProps {
  nearAccountId: string;
  nearExplorerBaseUrl?: string;
  username?: string | null;
  hideUsername?: boolean;
  onLock?: () => void;
  // QR Code Scanner parameters
  deviceLinkingScannerParams?: DeviceLinkingScannerParams;
  // styles
  toggleColors?: ToggleColorProps;
  style?: React.CSSProperties;
  className?: string;
  // Optional: where to portal overlays (modals)
  // Defaults to the component's ShadowRoot when present, otherwise document.body
  portalTarget?: HTMLElement | ShadowRoot | null;
  // Programmatic menu control
  isMenuOpen?: boolean;
  onMenuOpenChange?: (open: boolean) => void;
  highlightedMenuItem?: HighlightedProfileMenuItem | null;
}

export type ProfileSettingsButtonProps = AccountMenuButtonProps;

export interface UserAccountButtonProps {
  username: string;
  hideUsername: boolean;
  fullAccountId?: string;
  isOpen: boolean;
  onClick: () => void;
  onMouseEnter?: () => void;
  onMouseLeave?: () => void;
  theme?: ThemeMode;
  // Optional ARIA linkage
  menuId?: string;
  triggerId?: string;
}

export interface ProfileDropdownProps {
  isOpen: boolean;
  menuItems: MenuItem[];
  onLock: () => void;
  onClose: () => void;
  toggleColors?: ToggleColorProps;
  theme?: ThemeMode;
  currentConfirmConfig?: ConfirmationConfig | null;
  onSetUiMode?: (mode: 'none' | 'modal' | 'drawer') => void;
  onToggleShowDetails?: () => void;
  onToggleSkipClick?: () => void;
  onSetDelay?: (delay: number) => void;
  transactionSettingsOpen?: boolean;
  accountsRows?: AccountsSectionRow[];
  accountsOpen?: boolean;
  linkedDevicesOpen?: boolean;
  exportKeysOpen?: boolean;
  exportLoadingChain?: ExportChain | null;
  exportRestrictionMessage?: string | null;
  onExportChain?: (chain: ExportChain) => void;
  walletId?: string | null;
  nearAccountId?: string | null;
  menuItemsRef: React.MutableRefObject<(HTMLElement | null)[]>;
  // Optional ARIA linkage
  menuId?: string;
  triggerId?: string;
  highlightedMenuItemId?: string;
}

export interface MenuItemProps {
  item: MenuItem;
  onClose: () => void;
  className?: string;
  style?: React.CSSProperties;
  isHighlighted?: boolean;
}

export interface LockMenuItemProps {
  onLock: () => void;
  className?: string;
  style?: React.CSSProperties;
}

export interface ProfileRelayerToggleSectionProps {
  toggleColors?: ToggleColorProps;
  className?: string;
  style?: React.CSSProperties;
}

export interface TransactionSettingsSectionProps {
  currentConfirmConfig: ConfirmationConfig;
  onSetUiMode?: (mode: 'none' | 'modal' | 'drawer') => void;
  onToggleShowDetails?: () => void;
  onToggleSkipClick: () => void;
  onSetDelay: (delay: number) => void;
  className?: string;
  style?: React.CSSProperties;
  isOpen?: boolean;
  theme?: ThemeMode;
}

export interface ProfileStateRefs {
  buttonRef: React.RefObject<HTMLDivElement | null>;
  dropdownRef: React.RefObject<HTMLDivElement | null>;
  menuItemsRef: React.MutableRefObject<(HTMLElement | null)[]>;
}

export type { ToggleColorProps };
