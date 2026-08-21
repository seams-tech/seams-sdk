import type { AppearanceConfig } from '@/core/types/seams';
import type { AuthMenuRecoveryViewModel } from './auth-menu-domain';

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
  walletId: 'wallet.test',
  recoveryCode: '',
  walletIdError: null,
  recoveryCodeError: null,
};

const preparing: AuthMenuRecoveryViewModel = {
  ...recoveryCommon,
  stage: 'preparing',
  status: { kind: 'busy', headline: 'Checking recovery code…' },
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
void invalidCodeEntry;
void invalidFinalization;
