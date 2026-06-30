import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { ScanIcon } from './icons/ScanIcon';
import { KeyIcon } from './icons/KeyIcon';
import { LinkIcon } from './icons/LinkIcon';
import { SlidersIcon } from './icons/SlidersIcon';
import { RecoveryCodesIcon } from './icons/RecoveryCodesIcon';
import { SpinnerIcon } from './icons/SpinnerIcon';
import { SunIcon } from './icons/SunIcon';
import { MoonIcon } from './icons/MoonIcon';
import { UserAccountButton } from './UserAccountButton';
import { ProfileDropdown } from './ProfileDropdown';
import { useProfileState } from './hooks/useProfileState';
import { useSeams } from '../../context';
import type { AccountMenuButtonProps, MenuItem } from './types';
import { PROFILE_MENU_ITEM_IDS } from './types';
import { QRCodeScanner } from '../QRCodeScanner';
import { LinkedDevicesModal } from './LinkedDevicesModal';
import { RecoveryCodesModal } from './RecoveryCodesModal';
import { ExportKeyTypeModal } from './ExportKeyTypeModal';
import './Web3AuthProfileButton.css';
import { Theme, useTheme } from '../theme';
import { requirePrimaryChainByFamily } from '@/core/config/chains';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromConfig,
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';

type ExportChain = 'near' | 'evm';

function formatExportKeyErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  const message = String(error || '').trim();
  return message || 'Key export is unavailable for this wallet.';
}

function resolveDefaultPortalTarget(
  explicit: HTMLElement | ShadowRoot | null | undefined,
  buttonRoot: HTMLDivElement | null,
): HTMLElement | ShadowRoot | null {
  if (explicit) return explicit;
  try {
    const root = buttonRoot?.getRootNode?.();
    if (root && typeof ShadowRoot !== 'undefined' && root instanceof ShadowRoot) {
      return root;
    }
  } catch {}
  if (typeof document === 'undefined') return null;
  return document.body;
}

/**
 * Account Menu Button Component
 * Provides user settings, account management, and the refactor-84 device-link scanner shell.
 * **Important:** This component should be used inside a SeamsWeb context.
 * Wrap your app with PasskeyProvider or ensure SeamsWeb is available in context via useSeams.
 *
 * @example
 * ```tsx
 * import { PasskeyProvider } from '@seams/sdk/react';
 * import { AccountMenuButton } from '@seams/sdk/react';
 *
 * function App() {
 *   return (
 *     <PasskeyProvider configs={passkeyConfigs}>
 *       <AccountMenuButton
 *         username="alice"
 *         onLock={() => console.log('Wallet locked')}
 *         deviceLinkingScannerParams={{
 *           onError: (error) => console.error('Error:', error),
 *           onClose: () => console.log('Scanner closed'),
 *           onEvent: (event) => console.log('Event:', event),
 *           fundingAmount: '0.05'
 *         }}
 *       />
 *     </PasskeyProvider>
 *   );
 * }
 * ```
 */
const AccountMenuButtonInner: React.FC<AccountMenuButtonProps> = ({
  nearAccountId: nearAccountIdProp,
  nearExplorerBaseUrl = 'https://nearblocks.io',
  username: usernameProp,
  hideUsername = false,
  onLock: onLock,
  deviceLinkingScannerParams,
  toggleColors,
  style,
  className,
  portalTarget,
  isMenuOpen,
  onMenuOpenChange,
  highlightedMenuItem,
}) => {
  // Get values from context if not provided as props
  const { loginState, seams, lock, themeCapabilities } = useSeams();

  // Use props if provided, otherwise fall back to context
  const accountName =
    usernameProp ||
    nearAccountIdProp?.split('.')?.[0] ||
    loginState.nearAccountId?.split('.')?.[0] ||
    'User';
  const loggedInAccountId = loginState.nearAccountId;
  const nearAccountId = nearAccountIdProp || loggedInAccountId;
  const walletId = loginState.walletId;

  // Local state for modals/expanded sections
  const [showQRScanner, setShowQRScanner] = useState(false);
  const [showLinkedDevices, setShowLinkedDevices] = useState(false);
  const [showRecoveryCodes, setShowRecoveryCodes] = useState(false);
  const [showExportKeyTypeModal, setShowExportKeyTypeModal] = useState(false);
  const [exportLoadingChain, setExportLoadingChain] = useState<ExportChain | null>(null);
  const [exportRestrictionMessage, setExportRestrictionMessage] = useState<string | null>(null);
  const [transactionSettingsOpen, setTransactionSettingsOpen] = useState(false);
  const [currentConfirmConfig, setCurrentConfirmConfig] = useState<any>(null);

  // State management
  const { isOpen, refs, handleToggle, handleClose } = useProfileState({
    open: typeof isMenuOpen === 'boolean' ? isMenuOpen : undefined,
    onOpenChange: onMenuOpenChange,
  });

  // Read current theme from Theme context (falls back to system preference)
  const { theme } = useTheme();
  const canShowRecoveryCodes =
    loginState.isLoggedIn &&
    Boolean(walletId) &&
    loginState.authMethods.some((authMethod) => authMethod.kind === SIGNER_AUTH_METHODS.emailOtp);

  useEffect(() => {
    if (!canShowRecoveryCodes) {
      setShowRecoveryCodes(false);
    }
  }, [canShowRecoveryCodes]);

  // Keep local view state in sync with SDK preferences (mirrors wallet host in iframe mode)
  useEffect(() => {
    if (!seams) return;
    if (!loginState.isLoggedIn || !walletId) {
      setCurrentConfirmConfig(null);
      return;
    }

    let cancelled = false;

    if (walletId) {
      seams.preferences.setCurrentWallet(toWalletId(walletId));
    }
    setCurrentConfirmConfig(seams.preferences.getConfirmationConfig());

    const unsubConfirmConfig = seams.preferences.onConfirmationConfigChange?.((cfg: any) => {
      if (cancelled) return;
      setCurrentConfirmConfig(cfg);
    });

    return () => {
      cancelled = true;
      unsubConfirmConfig?.();
    };
  }, [seams, loginState.isLoggedIn, walletId]);

  // Handlers for transaction settings
  const handleSetUiMode = (mode: 'none' | 'modal' | 'drawer') => {
    // Only patch the field we intend to change to avoid overwriting theme or other values
    seams.preferences.setConfirmationConfig({ uiMode: mode } as any);
  };

  const handleToggleSkipClick = () => {
    if (!currentConfirmConfig) return;
    const newBehavior =
      currentConfirmConfig.behavior === 'requireClick' ? 'skipClick' : 'requireClick';
    seams.preferences.setConfirmBehavior(newBehavior);
  };

  const handleSetDelay = (delay: number) => {
    // Only patch delay; avoid passing a stale theme from local state
    seams.preferences.setConfirmationConfig({ autoProceedDelay: delay } as any);
  };

  const handleToggleTheme = () => {
    if (!themeCapabilities.canSetHostTheme) {
      console.error('theme/setTheme needs to be passed to the SDK');
      return;
    }
    // Determine next theme from current visible theme when possible
    const newTheme =
      theme === 'dark'
        ? 'light'
        : theme === 'light'
          ? 'dark'
          : currentConfirmConfig?.theme === 'dark'
            ? 'light'
            : 'dark';
    seams.setTheme(newTheme);
    // Always show a quick pulse to acknowledge the press
    if (typeof document !== 'undefined' && document.body) {
      document.body.setAttribute('data-w3a-theme-pulse', '1');
      window.setTimeout(() => {
        document.body?.removeAttribute('data-w3a-theme-pulse');
      }, 220);
    }
  };

  const startExportKeyFlow = useCallback(
    async (chain: ExportChain) => {
      if (exportRestrictionMessage) return;
      if (!loginState.isLoggedIn || !walletId) {
        setExportRestrictionMessage('Key export requires an unlocked wallet.');
        return;
      }

      const walletSession = walletSessionRefFromSession({
        walletId,
        walletSessionUserId: walletId,
      });

      setExportLoadingChain(chain);
      setExportRestrictionMessage(null);
      try {
        if (chain === 'near') {
          if (!nearAccountId) {
            throw new Error('NEAR key export requires a NEAR account binding.');
          }
          const nearAccount = nearAccountRefFromAccountId(nearAccountId);
          const resolvedLane = await seams.keys.resolveExactKeyExportLane({
            kind: 'near',
            walletSession,
            nearAccount,
          });
          if (resolvedLane.kind !== 'near') {
            throw new Error('NEAR key export lane resolution returned the wrong signer kind.');
          }
          await seams.keys.exportKeypairWithUI({
            kind: 'near',
            walletSession,
            nearAccount,
            laneIdentity: resolvedLane.laneIdentity,
            options: {
              chain: 'near',
              variant: 'drawer',
            },
          });
        } else {
          const chainTarget = thresholdEcdsaChainTargetFromConfig(
            requirePrimaryChainByFamily(seams.configs.network.chains, 'evm'),
          );
          const resolvedLane = await seams.keys.resolveExactKeyExportLane({
            kind: 'ecdsa',
            walletSession,
            chainTarget,
          });
          if (resolvedLane.kind !== 'ecdsa') {
            throw new Error('ECDSA key export lane resolution returned the wrong signer kind.');
          }
          await seams.keys.exportKeypairWithUI({
            kind: 'ecdsa',
            walletSession,
            chainTarget,
            laneIdentity: resolvedLane.laneIdentity,
            options: {
              variant: 'drawer',
            },
          });
        }
        setShowExportKeyTypeModal(false);
      } catch (error: unknown) {
        const message = formatExportKeyErrorMessage(error);
        setExportRestrictionMessage(message);
        console.error('[AccountMenuButton] Key export failed:', error);
      } finally {
        setExportLoadingChain(null);
      }
    },
    [exportRestrictionMessage, loginState.isLoggedIn, nearAccountId, seams, walletId],
  );

  // Menu items configuration with context-aware handlers
  const MENU_ITEMS: MenuItem[] = useMemo(() => {
    const items: MenuItem[] = [];

    items.push({
      id: PROFILE_MENU_ITEM_IDS.EXPORT_KEYS,
      icon: exportLoadingChain ? <SpinnerIcon /> : <KeyIcon />,
      label: 'Export Keys',
      description: 'Export wallet signing keys',
      disabled: !loginState.isLoggedIn || exportLoadingChain !== null,
      onClick: () => {
        setExportRestrictionMessage(null);
        setShowExportKeyTypeModal(true);
      },
      keepOpenOnClick: true,
    });

    if (canShowRecoveryCodes) {
      items.push({
        id: PROFILE_MENU_ITEM_IDS.RECOVERY_CODES,
        icon: <RecoveryCodesIcon />,
        label: 'Recovery Codes',
        description: 'Email OTP backup codes',
        disabled: false,
        onClick: () => setShowRecoveryCodes(true),
        keepOpenOnClick: true,
      });
    }

    items.push(
      {
        id: PROFILE_MENU_ITEM_IDS.SCAN_LINK_DEVICE,
        icon: <ScanIcon />,
        label: 'Scan and Link Device',
        description: 'Scan QR to link a device',
        disabled: !loginState.isLoggedIn,
        onClick: () => {
          setShowQRScanner(true);
        },
        keepOpenOnClick: true,
      },
      {
        id: PROFILE_MENU_ITEM_IDS.LINKED_DEVICES,
        icon: <LinkIcon />,
        label: 'Linked Devices',
        description: 'View linked devices',
        disabled: !loginState.isLoggedIn,
        onClick: () => setShowLinkedDevices(true),
        keepOpenOnClick: true,
      },
    );

    items.push({
      id: PROFILE_MENU_ITEM_IDS.TOGGLE_THEME,
      icon: theme === 'dark' ? <SunIcon /> : <MoonIcon />,
      label: 'Toggle Theme',
      description: theme === 'dark' ? 'Dark Mode' : 'Light Mode',
      disabled: false,
      onClick: handleToggleTheme,
      keepOpenOnClick: true,
    });

    items.push({
      id: PROFILE_MENU_ITEM_IDS.TRANSACTION_SETTINGS,
      icon: <SlidersIcon />,
      label: 'Transaction Settings',
      description: 'Customize confirmation behavior',
      disabled: !loginState.isLoggedIn,
      onClick: () => setTransactionSettingsOpen((v) => !v),
      keepOpenOnClick: true,
    });
    return items;
  }, [canShowRecoveryCodes, exportLoadingChain, loginState.isLoggedIn, theme, handleToggleTheme]);

  const highlightedMenuItemId = highlightedMenuItem?.id;
  const highlightShouldFocus = highlightedMenuItem?.focus ?? true;
  const highlightedIndex = useMemo(() => {
    if (!highlightedMenuItemId) return -1;
    return MENU_ITEMS.findIndex((item) => item.id === highlightedMenuItemId);
  }, [MENU_ITEMS, highlightedMenuItemId]);

  useEffect(() => {
    if (!isOpen || highlightedIndex < 0 || !highlightShouldFocus) return;
    const el = refs.menuItemsRef.current?.[highlightedIndex];
    if (!el) return;
    const focusItem = () => {
      if (typeof (el as any).focus === 'function') {
        (el as any).focus();
      }
    };
    if (typeof window === 'undefined') {
      focusItem();
      return;
    }
    const frame = window.requestAnimationFrame(focusItem);
    return () => window.cancelAnimationFrame(frame);
  }, [isOpen, highlightedIndex, highlightShouldFocus, refs.menuItemsRef]);

  // Handlers
  const handleLock = () => {
    lock();
    onLock?.();
    handleClose();
  };

  const portalHost = resolveDefaultPortalTarget(portalTarget, refs.buttonRef.current);
  const canPortal = !!portalHost;

  return (
    <div
      ref={refs.buttonRef}
      className={`w3a-profile-button-morphable ${isOpen ? 'open' : 'closed'}${className ? ` ${className}` : ''}`}
      style={style}
      data-state={isOpen ? 'open' : 'closed'}
    >
      <UserAccountButton
        username={accountName}
        hideUsername={hideUsername}
        fullAccountId={nearAccountId || undefined}
        isOpen={isOpen}
        onClick={handleToggle}
        nearExplorerBaseUrl={nearExplorerBaseUrl}
        theme={theme}
      />

      {/* Visible menu structure for actual interaction */}
      <ProfileDropdown
        ref={refs.dropdownRef}
        isOpen={isOpen}
        menuItems={MENU_ITEMS}
        onLock={handleLock}
        onClose={handleClose}
        menuItemsRef={refs.menuItemsRef}
        toggleColors={toggleColors}
        currentConfirmConfig={currentConfirmConfig}
        onSetUiMode={handleSetUiMode}
        onToggleSkipClick={handleToggleSkipClick}
        onSetDelay={handleSetDelay}
        onToggleTheme={handleToggleTheme}
        transactionSettingsOpen={transactionSettingsOpen}
        theme={theme}
        highlightedMenuItemId={highlightedMenuItemId}
      />

      {/* QR Scanner Modal (portaled to nearest root for robustness) */}
      {canPortal &&
        createPortal(
          <QRCodeScanner
            key="profile-qr-scanner"
            isOpen={showQRScanner}
            fundingAmount={deviceLinkingScannerParams?.fundingAmount || '0.05'}
            onError={(error) => {
              deviceLinkingScannerParams?.onError?.(error);
              setShowQRScanner(false);
            }}
            onClose={() => {
              deviceLinkingScannerParams?.onClose?.();
              setShowQRScanner(false);
            }}
            onEvent={(event) => deviceLinkingScannerParams?.onEvent?.(event)}
          />,
          portalHost!,
        )}

      {/* Linked Devices Modal (portaled to nearest root for robustness) */}
      {canPortal &&
        walletId &&
        nearAccountId &&
        createPortal(
          <LinkedDevicesModal
            walletId={walletId}
            nearAccountId={nearAccountId}
            isOpen={showLinkedDevices}
            onClose={() => setShowLinkedDevices(false)}
          />,
          portalHost!,
        )}

      {/* Recovery Codes Modal (portaled to the resolved root so it stays inside shadow-hosted surfaces) */}
      {canPortal &&
        createPortal(
          <RecoveryCodesModal
            walletId={walletId!}
            isOpen={showRecoveryCodes}
            onClose={() => setShowRecoveryCodes(false)}
          />,
          portalHost!,
        )}

      {canPortal &&
        createPortal(
          <ExportKeyTypeModal
            isOpen={showExportKeyTypeModal}
            loadingChain={exportLoadingChain}
            restrictionMessage={exportRestrictionMessage}
            onClose={() => {
              if (exportLoadingChain) return;
              setShowExportKeyTypeModal(false);
            }}
            onSelectChain={startExportKeyFlow}
          />,
          portalHost!,
        )}

    </div>
  );
};

export const AccountMenuButton: React.FC<AccountMenuButtonProps> = (props) => {
  const { theme, tokens } = useTheme();
  const scopedTokens = useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );
  return (
    <Theme theme={theme} tokens={scopedTokens}>
      <AccountMenuButtonInner {...props} />
    </Theme>
  );
};

export const ProfileSettingsButton = AccountMenuButton;
