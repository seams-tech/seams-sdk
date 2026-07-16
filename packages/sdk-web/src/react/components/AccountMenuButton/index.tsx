import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { ScanIcon } from './icons/ScanIcon';
import { KeyIcon } from './icons/KeyIcon';
import { LinkIcon } from './icons/LinkIcon';
import { GlobeIcon } from './icons/GlobeIcon';
import { SlidersIcon } from './icons/SlidersIcon';
import { RecoveryCodesIcon } from './icons/RecoveryCodesIcon';
import { SpinnerIcon } from './icons/SpinnerIcon';
import { UserAccountButton } from './UserAccountButton';
import { ProfileDropdown } from './ProfileDropdown';
import { useProfileState } from './hooks/useProfileState';
import { useSeams } from '../../context';
import type { AccountMenuButtonProps, AccountsSectionRow, MenuItem } from './types';
import { PROFILE_MENU_ITEM_IDS } from './types';
import { QRCodeScanner } from '../QRCodeScanner';
import { RecoveryCodesModal } from './RecoveryCodesModal';
import { ExportKeyTypeModal } from './ExportKeyTypeModal';
import './Web3AuthProfileButton.css';
import { Theme, useTheme } from '../theme';
import { requirePrimaryChainByFamily, resolvePrimaryExplorerUrl } from '@/core/config/chains';
import type { ConfirmationBehavior, ConfirmationConfig } from '@/core/types/signer-worker';
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
  const { loginState, seams, lock } = useSeams();

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
  const [linkedDevicesOpen, setLinkedDevicesOpen] = useState(false);
  const [showRecoveryCodes, setShowRecoveryCodes] = useState(false);
  const [showExportKeyTypeModal, setShowExportKeyTypeModal] = useState(false);
  const [exportLoadingChain, setExportLoadingChain] = useState<ExportChain | null>(null);
  const [exportRestrictionMessage, setExportRestrictionMessage] = useState<string | null>(null);
  const [transactionSettingsOpen, setTransactionSettingsOpen] = useState(false);
  const [accountsOpen, setAccountsOpen] = useState(false);
  const [currentConfirmConfig, setCurrentConfirmConfig] = useState<ConfirmationConfig | null>(null);

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

    const unsubConfirmConfig = seams.preferences.onConfirmationConfigChange?.((cfg) => {
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
    setCurrentConfirmConfig((current) => ({
      ...(current ?? seams.preferences.getConfirmationConfig()),
      uiMode: mode,
    }));
    seams.preferences.setConfirmationConfig({ uiMode: mode });
  };

  const handleToggleSkipClick = () => {
    if (!currentConfirmConfig) return;
    const newBehavior: ConfirmationBehavior =
      currentConfirmConfig.behavior === 'requireClick' ? 'skipClick' : 'requireClick';
    setCurrentConfirmConfig((current) => ({
      ...(current ?? seams.preferences.getConfirmationConfig()),
      behavior: newBehavior,
      autoProceedDelay: newBehavior === 'skipClick' ? 0 : (current?.autoProceedDelay ?? 0),
    }));
    seams.preferences.setConfirmBehavior(newBehavior);
  };

  const handleSetDelay = (delay: number) => {
    setCurrentConfirmConfig((current) => ({
      ...(current ?? seams.preferences.getConfirmationConfig()),
      autoProceedDelay: delay,
    }));
    seams.preferences.setConfirmationConfig({ autoProceedDelay: delay });
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
      setShowExportKeyTypeModal(false);
      try {
        if (chain === 'near') {
          if (!nearAccountId) {
            throw new Error('Ed25519 export requires an active NEAR account.');
          }
          const nearAccount = nearAccountRefFromAccountId(nearAccountId);
          const resolvedLane = await seams.keys.resolveExactKeyExportLane({
            kind: 'ed25519',
            walletSession,
            nearAccount,
          });
          if (resolvedLane.kind !== 'ed25519') {
            throw new Error('Ed25519 export lane resolution returned the wrong curve.');
          }
          await seams.keys.exportKeypairWithUI({
            kind: 'ed25519',
            walletSession,
            nearAccount,
            laneIdentity: resolvedLane.laneIdentity,
            options: { variant: 'drawer' },
          });
          return;
        }
        const chainTarget = thresholdEcdsaChainTargetFromConfig(
          requirePrimaryChainByFamily(seams.configs.network.chains, 'evm'),
        );
        const resolvedLane = await seams.keys.resolveExactKeyExportLane({
          kind: 'ecdsa',
          walletSession,
          chainTarget,
        });
        if (resolvedLane.kind !== 'ecdsa') {
          throw new Error('ECDSA export lane resolution returned the wrong curve.');
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
      } catch (error: unknown) {
        const message = formatExportKeyErrorMessage(error);
        setExportRestrictionMessage(message);
        setShowExportKeyTypeModal(true);
        console.error('[AccountMenuButton] Key export failed:', error);
      } finally {
        setExportLoadingChain(null);
      }
    },
    [exportRestrictionMessage, loginState.isLoggedIn, nearAccountId, seams, walletId],
  );

  // Chain rows for the Accounts expander: one per configured chain with a
  // known account/address and explorer URL, linking to the account page.
  const accountsRows: AccountsSectionRow[] = useMemo(() => {
    const rows: AccountsSectionRow[] = [];
    const chains = seams?.configs.network.chains ?? [];
    const nearExplorer = resolvePrimaryExplorerUrl(chains, 'near') || nearExplorerBaseUrl;
    const tempoExplorer = resolvePrimaryExplorerUrl(chains, 'tempo');
    const evmExplorer = resolvePrimaryExplorerUrl(chains, 'evm');
    const evmAddress = loginState.thresholdEcdsaEthereumAddress;

    if (nearAccountId && nearExplorer) {
      rows.push({
        id: 'near',
        label: 'NEAR',
        address: nearAccountId,
        href: `${nearExplorer}/address/${nearAccountId}`,
      });
    }
    if (evmAddress && tempoExplorer) {
      rows.push({
        id: 'tempo',
        label: 'Tempo',
        address: evmAddress,
        href: `${tempoExplorer}/address/${evmAddress}`,
      });
    }
    if (evmAddress && evmExplorer) {
      rows.push({
        id: 'arc',
        label: 'Arc',
        address: evmAddress,
        href: `${evmExplorer}/address/${evmAddress}`,
      });
    }
    return rows;
  }, [seams, nearAccountId, nearExplorerBaseUrl, loginState.thresholdEcdsaEthereumAddress]);

  // Menu items configuration with context-aware handlers
  const MENU_ITEMS: MenuItem[] = useMemo(() => {
    const items: MenuItem[] = [];

    if (accountsRows.length > 0) {
      items.push({
        id: PROFILE_MENU_ITEM_IDS.ACCOUNTS,
        icon: <GlobeIcon />,
        label: 'Accounts',
        description: 'View accounts on block explorers',
        disabled: !loginState.isLoggedIn,
        onClick: () => setAccountsOpen((v) => !v),
        keepOpenOnClick: true,
      });
    }

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
        onClick: () => setLinkedDevicesOpen((v) => !v),
        keepOpenOnClick: true,
      },
    );

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
  }, [accountsRows.length, canShowRecoveryCodes, exportLoadingChain, loginState.isLoggedIn]);

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
        // identity line under "Settings": the wallet id, not the chain account
        fullAccountId={walletId || nearAccountId || undefined}
        isOpen={isOpen}
        onClick={handleToggle}
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
        transactionSettingsOpen={transactionSettingsOpen}
        accountsRows={accountsRows}
        accountsOpen={accountsOpen}
        linkedDevicesOpen={linkedDevicesOpen}
        walletId={walletId}
        nearAccountId={nearAccountId}
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
