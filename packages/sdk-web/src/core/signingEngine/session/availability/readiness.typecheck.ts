import { toAccountId } from '@/core/types/accountIds';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletBudgetOwner } from '../budget/budget';
import {
  clearSigningGrant,
  discoverLanesForWallet,
  readWalletScopedLaneClaimsForWallet,
  type SigningGrantReadinessDeps,
  type SigningGrantStatusOverride,
} from './readiness';

declare const walletId: WalletId;
const accountId = toAccountId('owner.testnet');
declare const deps: SigningGrantReadinessDeps;
declare const statusOverrides: Map<string, SigningGrantStatusOverride>;

const validEcdsaOwner: WalletBudgetOwner = {
  curve: 'ecdsa',
  walletId,
};
void validEcdsaOwner;

const validReadinessOverride: SigningGrantStatusOverride = {
  owner: {
    curve: 'ed25519',
    accountId,
  },
  signingGrantId: 'wallet-session-id',
  status: { sessionId: 'wallet-session-id', status: 'active', remainingUses: 1 },
  thresholdSessionIds: new Set(['threshold-session-id']),
  updatedAtMs: 1,
};
void validReadinessOverride;

const invalidReadinessOverrideWithRawAccountId: SigningGrantStatusOverride = {
  owner: {
    curve: 'ed25519',
    // @ts-expect-error readiness owners require normalized AccountId branding.
    accountId: 'owner.testnet',
  },
  signingGrantId: 'wallet-session-id',
  status: { sessionId: 'wallet-session-id', status: 'active', remainingUses: 1 },
  thresholdSessionIds: new Set(['threshold-session-id']),
  updatedAtMs: 1,
};
void invalidReadinessOverrideWithRawAccountId;

const invalidReadinessOverrideWithWalletId: SigningGrantStatusOverride = {
  // @ts-expect-error readiness overrides use owner identity, not mixed walletId.
  walletId,
  signingGrantId: 'wallet-session-id',
  status: { sessionId: 'wallet-session-id', status: 'active', remainingUses: 1 },
  thresholdSessionIds: new Set(['threshold-session-id']),
  updatedAtMs: 1,
};
void invalidReadinessOverrideWithWalletId;

// @ts-expect-error ECDSA owner cannot carry NEAR account identity.
const invalidEcdsaOwnerWithAccountId: WalletBudgetOwner = {
  curve: 'ecdsa',
  walletId,
  accountId,
};
void invalidEcdsaOwnerWithAccountId;

void discoverLanesForWallet(deps, walletId);

void readWalletScopedLaneClaimsForWallet({
  deps,
  walletId,
  statusOverrides,
});

void clearSigningGrant({
  deps,
  statusOverrides,
  walletId,
  signingGrantId: 'wallet-session-id',
});

// @ts-expect-error readiness wallet discovery requires a normalized WalletId.
void discoverLanesForWallet(deps, 'wallet.testnet');

void readWalletScopedLaneClaimsForWallet({
  deps,
  // @ts-expect-error readiness claim reads require a normalized WalletId.
  walletId: 'wallet.testnet',
  statusOverrides,
});

void clearSigningGrant({
  deps,
  statusOverrides,
  // @ts-expect-error readiness clear requires a normalized WalletId.
  walletId: 'wallet.testnet',
  signingGrantId: 'wallet-session-id',
});

export {};
