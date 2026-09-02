import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '@/core/signingEngine/threshold/ed25519/routerAbNormalSigningState';
import type { ResolvedRouterAbEd25519WalletSessionState } from './routerAbEd25519WalletSessionState';

export type RouterAbEd25519NormalSigningReadyState = {
  kind: 'router_ab_ed25519_normal_signing_ready_state_v1';
  walletSessionId: string;
  quotaId: string;
  thresholdSessionId: string;
  nearAccountId: string;
  relayerUrl: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  signingWorkerId: string;
  signerPublicKey: string;
  signingRootId: string;
  signingRootVersion: string;
  remainingUses: number;
  expiresAtMs: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  credential: RouterAbWalletSessionCredential;
};

function requireNonEmpty(value: unknown, label: string): string {
  const parsed = String(value || '').trim();
  if (!parsed) {
    throw new Error(`Router A/B Ed25519 normal-signing ready state is missing ${label}`);
  }
  return parsed;
}

function requireEqual(actual: string, expected: string, label: string): void {
  if (actual !== expected) {
    throw new Error(`Router A/B Ed25519 normal-signing ready state ${label} mismatch`);
  }
}

function requireFutureEpochMs(value: unknown, label: string): number {
  const parsed = Math.floor(Number(value));
  if (!Number.isFinite(parsed) || parsed <= Date.now()) {
    throw new Error(`Router A/B Ed25519 normal-signing ready state ${label} is expired`);
  }
  return parsed;
}

function requirePositiveInteger(value: unknown, label: string): number {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`Router A/B Ed25519 normal-signing ready state ${label} is exhausted`);
  }
  return parsed;
}

export function requireRouterAbEd25519NormalSigningReadyState(args: {
  state: ResolvedRouterAbEd25519WalletSessionState;
  thresholdSessionId: string;
  nearAccountId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
}): RouterAbEd25519NormalSigningReadyState {
  const state = args.state;
  const signingWalletSession = state.signingWalletSession;

  const thresholdSessionId = requireNonEmpty(args.thresholdSessionId, 'thresholdSessionId');
  const stateThresholdSessionId = requireNonEmpty(state.thresholdSessionId, 'state.thresholdSessionId');
  const laneThresholdSessionId = requireNonEmpty(
    state.signingLane.thresholdSessionId,
    'state.signingLane.thresholdSessionId',
  );
  requireEqual(stateThresholdSessionId, thresholdSessionId, 'thresholdSessionId');
  requireEqual(laneThresholdSessionId, thresholdSessionId, 'lane thresholdSessionId');

  const walletSessionId = requireNonEmpty(state.walletSessionId, 'state.walletSessionId');
  const quotaId = requireNonEmpty(state.quotaId, 'state.quotaId');
  requireEqual(state.signingLane.walletSessionId, walletSessionId, 'lane walletSessionId');
  requireEqual(state.signingLane.quotaId, quotaId, 'lane quotaId');

  const nearAccountId = requireNonEmpty(args.nearAccountId, 'nearAccountId');
  const walletId = requireNonEmpty(
    state.signingLane.identity.signer.account.wallet.walletId,
    'state.signingLane.identity.signer.account.wallet.walletId',
  );
  requireEqual(
    requireNonEmpty(args.thresholdKeyMaterial.nearAccountId, 'thresholdKeyMaterial.nearAccountId'),
    nearAccountId,
    'threshold key accountId',
  );

  const routerAbState = signingWalletSession.routerAbNormalSigning;
  const runtimePolicyScope = signingWalletSession.runtimePolicyScope;
  const walletSessionToken = requireNonEmpty(
    signingWalletSession.auth.walletSessionToken,
    'Wallet Session bearer token',
  );
  const signingRootId = requireNonEmpty(state.signingRootId, 'state.signingRootId');
  const signingRootVersion = requireNonEmpty(
    state.signingRootVersion,
    'state.signingRootVersion',
  );
  requireEqual(
    signingWalletSession.thresholdSessionId,
    thresholdSessionId,
    'Wallet Session thresholdSessionId',
  );
  requireEqual(signingWalletSession.walletSessionId, walletSessionId, 'Wallet Session walletSessionId');
  requireEqual(signingWalletSession.quotaId, quotaId, 'Wallet Session quotaId');
  requireEqual(signingWalletSession.signingRootId, signingRootId, 'signingRootId');
  requireEqual(
    signingWalletSession.signingRootVersion,
    signingRootVersion,
    'signingRootVersion',
  );
  requireEqual(
    state.routerAbNormalSigning.signingWorkerId,
    routerAbState.signingWorkerId,
    'signingWorkerId',
  );
  const expiresAtMs = requireFutureEpochMs(signingWalletSession.expiresAtMs, 'expiresAtMs');
  const remainingUses = requirePositiveInteger(
    signingWalletSession.remainingUses,
    'remainingUses',
  );
  if (state.remainingUses !== remainingUses) {
    throw new Error('Router A/B Ed25519 normal-signing ready state remainingUses mismatch');
  }

  return {
    kind: 'router_ab_ed25519_normal_signing_ready_state_v1',
    walletSessionId,
    quotaId,
    thresholdSessionId,
    nearAccountId,
    relayerUrl: requireNonEmpty(state.relayerUrl, 'relayerUrl'),
    routerAbNormalSigning: routerAbState,
    signingWorkerId: requireNonEmpty(routerAbState.signingWorkerId, 'signingWorkerId'),
    signerPublicKey: requireNonEmpty(args.thresholdKeyMaterial.publicKey, 'signerPublicKey'),
    signingRootId,
    signingRootVersion,
    remainingUses,
    expiresAtMs,
    runtimePolicyScope,
    credential: {
      kind: 'wallet_session_opaque',
      walletSessionToken,
    },
  };
}
