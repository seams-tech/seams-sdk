import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import type {
  NearAuthorizedEd25519SigningSessionState,
  NearEd25519YaoOperationMaterialFacts,
  NearResolvedEd25519SigningSessionState,
} from '@/core/signingEngine/interfaces/near';
import {
  walletSessionAuthorizations,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { signingLaneAuthMethod } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import {
  buildRouterAbEd25519SigningWalletSession,
  parseRouterAbEd25519WalletSessionIdentityClaims,
  type RouterAbEd25519SigningWalletSession,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type { ExactEd25519SealedSessionRuntime } from './ed25519SealedSessionRuntime';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';

export type ResolvedRouterAbEd25519WalletSessionState = NearResolvedEd25519SigningSessionState & {
  signingWalletSession: RouterAbEd25519SigningWalletSession;
};

export type AuthorizedRouterAbEd25519WalletSessionState =
  ResolvedRouterAbEd25519WalletSessionState & NearAuthorizedEd25519SigningSessionState;

export type BuildEmailOtpRouterAbEd25519WalletSessionStateInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  providerSubjectId: string;
  signerSlot: number;
  relayerUrl: string;
  signingWalletSession: RouterAbEd25519SigningWalletSession;
};

export type BuildPasskeyRouterAbEd25519WalletSessionStateInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  rpId: ReturnType<typeof toRpId>;
  credentialIdB64u: string;
  relayerUrl: string;
  signingWalletSession: RouterAbEd25519SigningWalletSession;
};

function requireNonEmptyStateValue(value: string, label: string): string {
  const normalized = String(value).trim();
  if (!normalized) throw new Error(`${label} is required for Ed25519 Wallet Session state`);
  return normalized;
}

function requirePositiveStateInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be positive for Ed25519 Wallet Session state`);
  }
  return value;
}

export function buildEmailOtpRouterAbEd25519WalletSessionState(
  input: BuildEmailOtpRouterAbEd25519WalletSessionStateInput,
): ResolvedRouterAbEd25519WalletSessionState {
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(
    requireNonEmptyStateValue(
      input.signingWalletSession.thresholdSessionId,
      'thresholdSessionId',
    ),
  );
  const signingGrantId = requireNonEmptyStateValue(
    input.signingWalletSession.signingGrantId,
    'signingGrantId',
  );
  const walletSessionJwt = requireNonEmptyStateValue(
    input.signingWalletSession.auth.walletSessionJwt,
    'walletSessionJwt',
  );
  const relayerUrl = requireNonEmptyStateValue(input.relayerUrl, 'relayerUrl');
  const providerSubjectId = requireNonEmptyStateValue(
    input.providerSubjectId,
    'providerSubjectId',
  );
  const signerSlot = requirePositiveStateInteger(input.signerSlot, 'signerSlot');
  const remainingUses = requirePositiveStateInteger(
    input.signingWalletSession.remainingUses,
    'remainingUses',
  );
  const walletSessionAuth = {
    kind: 'wallet_session_jwt' as const,
    walletSessionJwt,
  };
  return {
    walletSessionAuth,
    thresholdSessionId,
    signingGrantId,
    signingLane: buildNearTransactionSigningLane({
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      signerSlot,
      auth: {
        kind: 'email_otp',
        providerSubjectId,
      },
      signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
      thresholdSessionId,
      retention: 'session',
      sessionOrigin: 'login',
    }),
    remainingUses,
    signingRootId: input.signingWalletSession.signingRootId,
    signingRootVersion: input.signingWalletSession.signingRootVersion,
    routerAbNormalSigning: input.signingWalletSession.routerAbNormalSigning,
    runtimePolicyScope: input.signingWalletSession.runtimePolicyScope,
    relayerUrl,
    signingWalletSession: input.signingWalletSession,
  };
}

export function buildPasskeyRouterAbEd25519WalletSessionState(
  input: BuildPasskeyRouterAbEd25519WalletSessionStateInput,
): ResolvedRouterAbEd25519WalletSessionState {
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(
    requireNonEmptyStateValue(
      input.signingWalletSession.thresholdSessionId,
      'thresholdSessionId',
    ),
  );
  const signingGrantId = requireNonEmptyStateValue(
    input.signingWalletSession.signingGrantId,
    'signingGrantId',
  );
  const walletSessionJwt = requireNonEmptyStateValue(
    input.signingWalletSession.auth.walletSessionJwt,
    'walletSessionJwt',
  );
  const relayerUrl = requireNonEmptyStateValue(input.relayerUrl, 'relayerUrl');
  const credentialIdB64u = requireNonEmptyStateValue(
    input.credentialIdB64u,
    'credentialIdB64u',
  );
  const signerSlot = requirePositiveStateInteger(input.signerSlot, 'signerSlot');
  return {
    walletSessionAuth: {
      kind: 'wallet_session_jwt',
      walletSessionJwt,
    },
    thresholdSessionId,
    signingGrantId,
    signingLane: buildNearTransactionSigningLane({
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      signerSlot,
      auth: {
        kind: 'passkey',
        rpId: input.rpId,
        credentialIdB64u,
      },
      signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
      thresholdSessionId,
      storageSource: 'login',
    }),
    remainingUses: input.signingWalletSession.remainingUses,
    signingRootId: input.signingWalletSession.signingRootId,
    signingRootVersion: input.signingWalletSession.signingRootVersion,
    routerAbNormalSigning: input.signingWalletSession.routerAbNormalSigning,
    runtimePolicyScope: input.signingWalletSession.runtimePolicyScope,
    relayerUrl,
    signingWalletSession: input.signingWalletSession,
  };
}

export function buildRouterAbEd25519WalletSessionStateFromExactRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  walletSessionJwt: string;
  nowMs: number;
}): ResolvedRouterAbEd25519WalletSessionState {
  const runtime = args.runtime;
  const claims = parseRouterAbEd25519WalletSessionIdentityClaims(args.walletSessionJwt);
  if (
    !claims ||
    claims.walletId !== runtime.walletId ||
    claims.nearAccountId !== runtime.nearAccountId ||
    claims.nearEd25519SigningKeyId !== runtime.nearEd25519SigningKeyId ||
    claims.thresholdSessionId !== runtime.thresholdSessionId
  ) {
    throw new Error('Ed25519 Wallet Session authorization does not match sealed material');
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: runtime.walletId,
    nearAccountId: runtime.nearAccountId,
    nearEd25519SigningKeyId: runtime.nearEd25519SigningKeyId,
    walletSessionId: claims.walletSessionId,
    thresholdSessionId: runtime.thresholdSessionId,
    signingGrantId: claims.signingGrantId,
    remainingUses: runtime.remainingUses,
    expiresAtMs: runtime.expiresAtMs,
    runtimePolicyScope: runtime.runtimePolicyScope,
    signingRootId: runtime.signingRootId,
    signingRootVersion: runtime.signingRootVersion,
    routerAbNormalSigning: runtime.routerAbNormalSigning,
    walletSessionJwt: args.walletSessionJwt,
    nowMs: args.nowMs,
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `Ed25519 Wallet Session runtime is invalid: ${signingWalletSession.reason}`,
    );
  }
  if (runtime.factor.kind === 'passkey' && runtime.auth.kind === 'passkey') {
    return buildPasskeyRouterAbEd25519WalletSessionState({
      walletId: runtime.walletId,
      nearAccountId: runtime.nearAccountId,
      nearEd25519SigningKeyId: runtime.nearEd25519SigningKeyId,
      signerSlot: runtime.signerSlot,
      rpId: runtime.factor.rpId,
      credentialIdB64u: runtime.factor.credentialIdB64u,
      relayerUrl: runtime.relayerUrl,
      signingWalletSession: signingWalletSession.value,
    });
  }
  const signingLane =
    runtime.factor.kind === 'email_otp' && runtime.auth.kind === 'email_otp'
        ? buildNearTransactionSigningLane({
            walletId: runtime.walletId,
            nearAccountId: runtime.nearAccountId,
            nearEd25519SigningKeyId: runtime.nearEd25519SigningKeyId,
            signerSlot: runtime.signerSlot,
            auth: runtime.auth,
            signingGrantId: SigningSessionIds.signingGrant(claims.signingGrantId),
            thresholdSessionId: runtime.thresholdSessionId,
            retention: 'session',
            sessionOrigin: 'login',
          })
        : null;
  if (!signingLane) {
    throw new Error('Ed25519 sealed runtime factor and auth binding disagree');
  }
  return {
    walletSessionAuth: signingWalletSession.value.auth,
    thresholdSessionId: runtime.thresholdSessionId,
    signingGrantId: claims.signingGrantId,
    signingLane,
    remainingUses: runtime.remainingUses,
    signingRootId: runtime.signingRootId,
    signingRootVersion: runtime.signingRootVersion,
    routerAbNormalSigning: runtime.routerAbNormalSigning,
    runtimePolicyScope: runtime.runtimePolicyScope,
    relayerUrl: runtime.relayerUrl,
    signingWalletSession: signingWalletSession.value,
  };
}

export function nearEd25519YaoOperationMaterialFacts(
  state: ResolvedRouterAbEd25519WalletSessionState,
): NearEd25519YaoOperationMaterialFacts {
  return {
    thresholdSessionId: state.thresholdSessionId,
    signer: state.signingLane.identity.signer,
    signingRootId: state.signingRootId,
    signingRootVersion: state.signingRootVersion,
    routerAbNormalSigning: state.routerAbNormalSigning,
    runtimePolicyScope: state.runtimePolicyScope,
    relayerUrl: state.relayerUrl,
  };
}

export function authorizeRouterAbEd25519WalletSessionState(args: {
  state: ResolvedRouterAbEd25519WalletSessionState;
  authorization: ActiveWalletSessionAuthorizationProjection;
  nowMs: number;
}): AuthorizedRouterAbEd25519WalletSessionState | null {
  const state = args.state;
  const authorization = args.authorization;
  const walletId = state.signingLane.identity.signer.account.wallet.walletId;
  if (
    authorization.walletId !== walletId ||
    authorization.authority.walletId !== walletId ||
    authorization.authMethod !== signingLaneAuthMethod(state.signingLane.auth) ||
    authorization.expiresAtMs <= args.nowMs ||
    authorization.expiresAtMs !== state.signingWalletSession.expiresAtMs ||
    authorization.walletSessionJwt !== state.walletSessionAuth.walletSessionJwt
  ) {
    return null;
  }
  return {
    ...state,
    walletSessionId: authorization.walletSessionId,
    walletSessionAuthorization: authorization,
  };
}

export async function resolveActiveAuthorizedRouterAbEd25519WalletSessionState(args: {
  state: ResolvedRouterAbEd25519WalletSessionState;
  nowMs: number;
}): Promise<AuthorizedRouterAbEd25519WalletSessionState | null> {
  const walletId = args.state.signingLane.identity.signer.account.wallet.walletId;
  const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(walletId);
  if (authorizationRead.kind !== 'found') return null;
  return authorizeRouterAbEd25519WalletSessionState({
    state: args.state,
    authorization: authorizationRead.projection,
    nowMs: args.nowMs,
  });
}
