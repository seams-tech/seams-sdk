import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletSessionStatusOwner } from '../lifecycle/walletSessionStatus';
import { SigningSessionIds } from '../operationState/types';
import {
  clearWalletSession,
  discoverLanesForWallet,
  readWalletScopedLaneClaimsForWallet,
  type WalletSessionReadinessDeps,
  type WalletSessionStatusOverride,
} from './readiness';

declare const walletId: WalletId;
const ed25519WalletId = toWalletId('owner.testnet');
const walletSessionId = SigningSessionIds.walletSession('wallet-session-id');
const quotaId = SigningSessionIds.walletSessionQuota('quota-id');
declare const deps: WalletSessionReadinessDeps;
declare const statusOverrides: Map<string, WalletSessionStatusOverride>;

const validReadinessOverride: WalletSessionStatusOverride = {
  owner: {
    curve: 'ed25519',
    walletId: ed25519WalletId,
  },
  walletSessionId,
  quotaId,
  status: { sessionId: String(walletSessionId), status: 'active', remainingUses: 1 },
  thresholdSessionIds: new Set(['threshold-session-id']),
  updatedAtMs: 1,
};
void validReadinessOverride;

const invalidReadinessOverrideWithRawAccountId: WalletSessionStatusOverride = {
  owner: {
    curve: 'ed25519',
    // @ts-expect-error readiness owners require normalized WalletId branding.
    walletId: 'owner.testnet',
  },
  walletSessionId,
  quotaId,
  status: { sessionId: String(walletSessionId), status: 'active', remainingUses: 1 },
  thresholdSessionIds: new Set(['threshold-session-id']),
  updatedAtMs: 1,
};
void invalidReadinessOverrideWithRawAccountId;

const invalidReadinessOverrideWithWalletId: WalletSessionStatusOverride = {
  // @ts-expect-error readiness overrides use owner identity, not mixed walletId.
  walletId,
  walletSessionId,
  quotaId,
  status: { sessionId: String(walletSessionId), status: 'active', remainingUses: 1 },
  thresholdSessionIds: new Set(['threshold-session-id']),
  updatedAtMs: 1,
};
void invalidReadinessOverrideWithWalletId;

void discoverLanesForWallet(deps, walletId);

void readWalletScopedLaneClaimsForWallet({
  deps,
  walletId,
  statusOverrides,
});

void clearWalletSession({
  deps,
  statusOverrides,
  walletId,
  walletSessionId,
  quotaId,
});

// @ts-expect-error readiness wallet discovery requires a normalized WalletId.
void discoverLanesForWallet(deps, 'wallet.testnet');

void readWalletScopedLaneClaimsForWallet({
  deps,
  // @ts-expect-error readiness claim reads require a normalized WalletId.
  walletId: 'wallet.testnet',
  statusOverrides,
});

void clearWalletSession({
  deps,
  statusOverrides,
  // @ts-expect-error readiness clear requires a normalized WalletId.
  walletId: 'wallet.testnet',
  walletSessionId,
  quotaId,
});

export {};
