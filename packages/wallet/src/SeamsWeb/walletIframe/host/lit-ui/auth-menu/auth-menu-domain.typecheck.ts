import type { AppearanceConfig } from '@/core/types/seams';
import type { AuthMenuRecoveryViewModel } from './auth-menu-domain';
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

void preparing;
void invalidEntryWalletIdentity;
void invalidCodeEntry;
void invalidFinalization;
