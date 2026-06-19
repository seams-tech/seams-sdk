import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '@/core/signingEngine/threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import { walletSessionJwtFromPersistedEd25519Record } from '@/core/signingEngine/session/walletSessionAuthBoundary';
import type { ResolvedRouterAbEd25519WalletSessionState } from './routerAbEd25519WalletSessionState';
import type { RouterAbEd25519SigningMaterialRef } from '@/core/signingEngine/threshold/ed25519/hssMaterialBinding';

export type RouterAbEd25519NormalSigningReadyState = {
  kind: 'router_ab_ed25519_normal_signing_ready_state_v1';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  nearAccountId: string;
  relayerUrl: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  signingWorkerId: string;
  signerPublicKey: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  signingMaterial: RouterAbEd25519SigningMaterialRef;
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

export function hasRouterAbEd25519SigningAuth(record: ThresholdEd25519SessionRecord): boolean {
  return (
    Boolean(record.routerAbNormalSigning) &&
    Boolean(walletSessionJwtFromPersistedEd25519Record(record))
  );
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

  const walletSigningSessionId = requireNonEmpty(
    state.walletSigningSessionId,
    'state.walletSigningSessionId',
  );
  const laneWalletSigningSessionId = requireNonEmpty(
    state.signingLane.walletSigningSessionId,
    'state.signingLane.walletSigningSessionId',
  );
  requireEqual(laneWalletSigningSessionId, walletSigningSessionId, 'walletSigningSessionId');

  const nearAccountId = requireNonEmpty(args.nearAccountId, 'nearAccountId');
  requireEqual(
    requireNonEmpty(state.signingLane.accountId, 'state.signingLane.accountId'),
    nearAccountId,
    'accountId',
  );
  requireEqual(
    requireNonEmpty(args.thresholdKeyMaterial.nearAccountId, 'thresholdKeyMaterial.nearAccountId'),
    nearAccountId,
    'threshold key accountId',
  );

  const routerAbState = signingWalletSession.routerAbNormalSigning;
  const runtimePolicyScope = signingWalletSession.runtimePolicyScope;
  const walletSessionJwt = requireNonEmpty(signingWalletSession.auth.walletSessionJwt, 'Wallet Session bearer JWT');
  const signingRootId = requireNonEmpty(state.signingRootId, 'state.signingRootId');
  const signingRootVersion = requireNonEmpty(
    state.signingRootVersion,
    'state.signingRootVersion',
  );
  const expiresAtMs = requireFutureEpochMs(signingWalletSession.expiresAtMs, 'expiresAtMs');
  const signingMaterial = signingWalletSession.signingMaterial;
  requireEqual(
    String(state.signingMaterial.materialHandle),
    String(signingMaterial.materialHandle),
    'materialHandle',
  );
  requireEqual(
    state.signingMaterial.bindingDigest,
    signingMaterial.bindingDigest,
    'material bindingDigest',
  );
  requireEqual(
    state.signingMaterial.clientVerifierB64u,
    signingMaterial.clientVerifierB64u,
    'material clientVerifierB64u',
  );

  return {
    kind: 'router_ab_ed25519_normal_signing_ready_state_v1',
    thresholdSessionId,
    walletSigningSessionId,
    nearAccountId,
    relayerUrl: requireNonEmpty(state.relayerUrl, 'relayerUrl'),
    routerAbNormalSigning: routerAbState,
    signingWorkerId: requireNonEmpty(routerAbState.signingWorkerId, 'signingWorkerId'),
    signerPublicKey: requireNonEmpty(args.thresholdKeyMaterial.publicKey, 'signerPublicKey'),
    signingRootId,
    signingRootVersion,
    expiresAtMs,
    signingMaterial,
    runtimePolicyScope,
    credential: {
      kind: 'jwt',
      walletSessionJwt,
    },
  };
}
