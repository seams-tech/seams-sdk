import type { AppearanceConfig } from '@/core/types/seams';
import type { AuthMenuLoginAccountResolution, AuthMenuRecoveryViewModel } from './auth-menu-domain';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';

declare const appearance: AppearanceConfig;

const recoveryCommon = {
  kind: 'recovery' as const,
  mode: 'login' as const,
  appearance,
  hostname: 'wallet.example.test',
  closeLabel: 'Close',
  heading: 'Recover account',
  subtitle: 'Recover this wallet.',
  ctaLabel: 'Continue',
  showProgress: true,
  enabledExternalProviders: [],
  recoveryCode: '',
  recoveryCodeError: null,
};

const preparing: AuthMenuRecoveryViewModel = {
  ...recoveryCommon,
  stage: 'preparing',
  target: { kind: 'google_email_otp', googleProvider: 'google' } satisfies WalletRecoveryTargetV1,
  status: { kind: 'busy', headline: 'Checking recovery code…' },
};

// @ts-expect-error The code-entry state cannot carry a server-resolved wallet.
const invalidEntryWalletIdentity: AuthMenuRecoveryViewModel = {
  ...recoveryCommon,
  stage: 'enter_code',
  walletId: 'wallet.test',
  status: { kind: 'idle', interaction: 'actionable' },
};

// @ts-expect-error Code entry cannot carry an in-flight status.
const invalidCodeEntry: AuthMenuRecoveryViewModel = {
  ...recoveryCommon,
  stage: 'enter_code',
  status: { kind: 'busy', headline: 'Checking recovery code…' },
};

// @ts-expect-error Finalization retry must stay recoverable until retried.
const invalidFinalization: AuthMenuRecoveryViewModel = {
  ...recoveryCommon,
  stage: 'finalizing',
  status: { kind: 'idle', interaction: 'actionable' },
};

const discoverableLogin: AuthMenuLoginAccountResolution = {
  kind: 'discoverable',
  selectedAccount: null,
  loginTarget: { kind: 'discoverable' },
};

// @ts-expect-error A discoverable login cannot carry a selected wallet.
const invalidDiscoverableLogin: AuthMenuLoginAccountResolution = {
  kind: 'discoverable',
  selectedAccount: {
    walletId: 'wallet.test',
    displayName: 'Wallet',
    authMethod: 'passkey' as const,
  },
  loginTarget: { kind: 'discoverable' },
};

// @ts-expect-error A resolved auth-method branch requires its exact wallet target.
const invalidResolvedLogin: AuthMenuLoginAccountResolution = {
  kind: 'passkey_and_email_otp',
  selectedAccount: {
    walletId: 'wallet.test',
    displayName: 'Wallet',
    authMethod: 'passkey' as const,
  },
  walletId: 'wallet.test',
  loginTarget: { kind: 'discoverable' },
};

void preparing;
void invalidEntryWalletIdentity;
void invalidCodeEntry;
void invalidFinalization;
void discoverableLogin;
void invalidDiscoverableLogin;
void invalidResolvedLogin;
