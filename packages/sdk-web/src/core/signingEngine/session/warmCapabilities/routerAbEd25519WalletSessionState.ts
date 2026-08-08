import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import type {
  NearAuthorizedEd25519SigningSessionState,
  NearEd25519YaoOperationMaterialFacts,
  NearResolvedEd25519SigningSessionState,
} from '@/core/signingEngine/interfaces/near';
import {
  walletSessionAuthorizations,
  walletSessionJwtForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { signingLaneAuthMethod } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import {
  buildRouterAbEd25519SigningWalletSession,
  parseRouterAbEd25519WalletSessionIdentityClaims,
  parseWalletSessionAuthorizationIdentityClaims,
  type RouterAbEd25519SigningWalletSession,
  type RouterAbEd25519WalletSessionIdentityClaims,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  ed25519SealedRuntimeAuthorityRef,
  type ExactEd25519SealedSessionRuntime,
} from './ed25519SealedSessionRuntime';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';

export type ResolvedRouterAbEd25519WalletSessionState = NearResolvedEd25519SigningSessionState & {
  signingWalletSession: RouterAbEd25519SigningWalletSession;
  authority: WalletAuthAuthorityRef;
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
  authority: WalletAuthAuthorityRef;
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
  authority: WalletAuthAuthorityRef;
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
    requireNonEmptyStateValue(input.signingWalletSession.thresholdSessionId, 'thresholdSessionId'),
  );
  const walletSessionJwt = requireNonEmptyStateValue(
    input.signingWalletSession.auth.walletSessionJwt,
    'walletSessionJwt',
  );
  const relayerUrl = requireNonEmptyStateValue(input.relayerUrl, 'relayerUrl');
  const providerSubjectId = requireNonEmptyStateValue(input.providerSubjectId, 'providerSubjectId');
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
    walletSessionId: input.signingWalletSession.walletSessionId,
    quotaId: input.signingWalletSession.quotaId,
    thresholdSessionId,
    signingLane: buildNearTransactionSigningLane({
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      signerSlot,
      auth: {
        kind: 'email_otp',
        providerSubjectId,
      },
      walletSessionId: input.signingWalletSession.walletSessionId,
      quotaId: input.signingWalletSession.quotaId,
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
    authority: input.authority,
  };
}

export function buildPasskeyRouterAbEd25519WalletSessionState(
  input: BuildPasskeyRouterAbEd25519WalletSessionStateInput,
): ResolvedRouterAbEd25519WalletSessionState {
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(
    requireNonEmptyStateValue(input.signingWalletSession.thresholdSessionId, 'thresholdSessionId'),
  );
  const walletSessionJwt = requireNonEmptyStateValue(
    input.signingWalletSession.auth.walletSessionJwt,
    'walletSessionJwt',
  );
  const relayerUrl = requireNonEmptyStateValue(input.relayerUrl, 'relayerUrl');
  const credentialIdB64u = requireNonEmptyStateValue(input.credentialIdB64u, 'credentialIdB64u');
  const signerSlot = requirePositiveStateInteger(input.signerSlot, 'signerSlot');
  return {
    walletSessionAuth: {
      kind: 'wallet_session_jwt',
      walletSessionJwt,
    },
    walletSessionId: input.signingWalletSession.walletSessionId,
    quotaId: input.signingWalletSession.quotaId,
    thresholdSessionId,
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
      walletSessionId: input.signingWalletSession.walletSessionId,
      quotaId: input.signingWalletSession.quotaId,
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
    authority: input.authority,
  };
}

type BuildRouterAbEd25519WalletSessionStateFromRuntimeClaimsInput = {
  runtime: ExactEd25519SealedSessionRuntime;
  claims: RouterAbEd25519WalletSessionIdentityClaims;
  walletSessionJwt: string;
  authority: WalletAuthAuthorityRef;
  thresholdSessionId: RouterAbEd25519WalletSessionIdentityClaims['thresholdSessionId'];
  expiresAtMs: number;
  nowMs: number;
};

function buildRouterAbEd25519WalletSessionStateFromRuntimeClaims(
  input: BuildRouterAbEd25519WalletSessionStateFromRuntimeClaimsInput,
): ResolvedRouterAbEd25519WalletSessionState {
  const runtime = input.runtime;
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: runtime.walletId,
    nearAccountId: runtime.nearAccountId,
    nearEd25519SigningKeyId: runtime.nearEd25519SigningKeyId,
    walletSessionId: input.claims.walletSessionId,
    quotaId: input.claims.quotaId,
    thresholdSessionId: input.thresholdSessionId,
    remainingUses: runtime.remainingUses,
    expiresAtMs: input.expiresAtMs,
    runtimePolicyScope: runtime.runtimePolicyScope,
    signingRootId: runtime.signingRootId,
    signingRootVersion: runtime.signingRootVersion,
    routerAbNormalSigning: runtime.routerAbNormalSigning,
    walletSessionJwt: input.walletSessionJwt,
    nowMs: input.nowMs,
  });
  if (!signingWalletSession.ok) {
    throw new Error(`Ed25519 Wallet Session runtime is invalid: ${signingWalletSession.reason}`);
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
      authority: input.authority,
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
          walletSessionId: input.claims.walletSessionId,
          quotaId: input.claims.quotaId,
          thresholdSessionId: input.thresholdSessionId,
          retention: 'session',
          sessionOrigin: 'login',
        })
      : null;
  if (!signingLane) {
    throw new Error('Ed25519 sealed runtime factor and auth binding disagree');
  }
  return {
    walletSessionAuth: signingWalletSession.value.auth,
    walletSessionId: input.claims.walletSessionId,
    quotaId: input.claims.quotaId,
    thresholdSessionId: input.thresholdSessionId,
    signingLane,
    remainingUses: runtime.remainingUses,
    signingRootId: runtime.signingRootId,
    signingRootVersion: runtime.signingRootVersion,
    routerAbNormalSigning: runtime.routerAbNormalSigning,
    runtimePolicyScope: runtime.runtimePolicyScope,
    relayerUrl: runtime.relayerUrl,
    signingWalletSession: signingWalletSession.value,
    authority: input.authority,
  };
}

export function buildRouterAbEd25519WalletSessionStateFromExactRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  walletSessionJwt: string;
  authority: WalletAuthAuthorityRef;
  nowMs: number;
}): ResolvedRouterAbEd25519WalletSessionState {
  const runtime = args.runtime;
  const claims = parseRouterAbEd25519WalletSessionIdentityClaims(args.walletSessionJwt);
  if (
    !claims ||
    claims.walletId !== runtime.walletId ||
    claims.nearAccountId !== runtime.nearAccountId ||
    claims.nearEd25519SigningKeyId !== runtime.nearEd25519SigningKeyId ||
    claims.thresholdSessionId !== runtime.thresholdSessionId ||
    args.authority.walletId !== runtime.walletId
  ) {
    throw new Error('Ed25519 Wallet Session authorization does not match sealed material');
  }
  return buildRouterAbEd25519WalletSessionStateFromRuntimeClaims({
    runtime,
    claims,
    walletSessionJwt: args.walletSessionJwt,
    authority: args.authority,
    thresholdSessionId: runtime.thresholdSessionId,
    expiresAtMs: runtime.expiresAtMs,
    nowMs: args.nowMs,
  });
}

function walletAuthAuthorityRefsMatch(
  left: WalletAuthAuthorityRef,
  right: WalletAuthAuthorityRef,
): boolean {
  return left.walletId === right.walletId && left.authorityDigest === right.authorityDigest;
}

function validateEd25519RuntimeRebindAuthorization(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
  walletSessionJwt: string | null;
  claims: RouterAbEd25519WalletSessionIdentityClaims | null;
  authorizationClaims: ReturnType<typeof parseWalletSessionAuthorizationIdentityClaims>;
  expectedAuthority: WalletAuthAuthorityRef;
  nowMs: number;
}): {
  claims: RouterAbEd25519WalletSessionIdentityClaims;
  walletSessionJwt: string;
  expiresAtMs: number;
} {
  const { runtime, authorization, claims, authorizationClaims, expectedAuthority } = args;
  const expiresAtMs = Math.min(runtime.expiresAtMs, authorization.expiresAtMs);
  if (
    !args.walletSessionJwt ||
    !claims ||
    !authorizationClaims ||
    authorization.walletId !== runtime.walletId ||
    authorization.authMethod !== runtime.auth.kind ||
    !walletAuthAuthorityRefsMatch(authorization.authority, expectedAuthority) ||
    claims.walletId !== runtime.walletId ||
    claims.nearAccountId !== runtime.nearAccountId ||
    claims.nearEd25519SigningKeyId !== runtime.nearEd25519SigningKeyId ||
    authorizationClaims.walletId !== runtime.walletId ||
    authorizationClaims.authorizationId !== authorization.authorizationId ||
    authorizationClaims.walletSessionId !== authorization.walletSessionId ||
    authorizationClaims.quotaId !== authorization.quotaId ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= args.nowMs
  ) {
    throw new Error('Ed25519 Wallet Session authorization does not match sealed material');
  }
  return { claims, walletSessionJwt: args.walletSessionJwt, expiresAtMs };
}

export async function rebindRouterAbEd25519WalletSessionStateFromExactRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
  nowMs: number;
}): Promise<ResolvedRouterAbEd25519WalletSessionState> {
  const walletSessionJwt = walletSessionJwtForCurve(args.authorization, 'ed25519');
  const claims = walletSessionJwt
    ? parseRouterAbEd25519WalletSessionIdentityClaims(walletSessionJwt)
    : null;
  const authorizationClaims = walletSessionJwt
    ? parseWalletSessionAuthorizationIdentityClaims(walletSessionJwt)
    : null;
  const expectedAuthority = await ed25519SealedRuntimeAuthorityRef(args.runtime);
  const validated = validateEd25519RuntimeRebindAuthorization({
    runtime: args.runtime,
    authorization: args.authorization,
    walletSessionJwt,
    claims,
    authorizationClaims,
    expectedAuthority,
    nowMs: args.nowMs,
  });
  return buildRouterAbEd25519WalletSessionStateFromRuntimeClaims({
    runtime: args.runtime,
    claims: validated.claims,
    walletSessionJwt: validated.walletSessionJwt,
    authority: expectedAuthority,
    thresholdSessionId: validated.claims.thresholdSessionId,
    expiresAtMs: validated.expiresAtMs,
    nowMs: args.nowMs,
  });
}

export function nearEd25519YaoOperationMaterialFacts(
  state: NearResolvedEd25519SigningSessionState,
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
  const walletSessionJwt = walletSessionJwtForCurve(authorization, 'ed25519');
  const signer = state.signingLane.identity.signer;
  const claims = walletSessionJwt
    ? parseRouterAbEd25519WalletSessionIdentityClaims(walletSessionJwt)
    : null;
  const effectiveExpiresAtMs = Math.min(
    state.signingWalletSession.expiresAtMs,
    authorization.expiresAtMs,
  );
  if (
    !walletSessionJwt ||
    !claims ||
    authorization.walletId !== walletId ||
    authorization.authority.walletId !== walletId ||
    authorization.authority.authorityDigest !== state.authority.authorityDigest ||
    authorization.authMethod !== signingLaneAuthMethod(state.signingLane.auth) ||
    claims.walletId !== String(walletId) ||
    claims.nearAccountId !== String(signer.account.nearAccountId) ||
    claims.nearEd25519SigningKeyId !== String(signer.nearEd25519SigningKeyId) ||
    claims.thresholdSessionId !== String(state.thresholdSessionId) ||
    claims.walletSessionId !== authorization.walletSessionId ||
    claims.quotaId !== authorization.quotaId ||
    effectiveExpiresAtMs <= args.nowMs ||
    !Number.isSafeInteger(effectiveExpiresAtMs)
  ) {
    return null;
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(signer.account.wallet.walletId),
    nearAccountId: String(signer.account.nearAccountId),
    nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
    walletSessionId: String(authorization.walletSessionId),
    quotaId: String(authorization.quotaId),
    thresholdSessionId: String(state.thresholdSessionId),
    remainingUses: state.remainingUses,
    expiresAtMs: effectiveExpiresAtMs,
    runtimePolicyScope: state.runtimePolicyScope,
    signingRootId: state.signingRootId,
    signingRootVersion: state.signingRootVersion,
    routerAbNormalSigning: state.routerAbNormalSigning,
    walletSessionJwt,
    nowMs: args.nowMs,
  });
  if (!signingWalletSession.ok) return null;
  switch (state.signingLane.auth.kind) {
    case 'passkey': {
      const rebound = buildPasskeyRouterAbEd25519WalletSessionState({
        walletId: signer.account.wallet.walletId,
        nearAccountId: signer.account.nearAccountId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
        signerSlot: signer.signerSlot,
        rpId: state.signingLane.auth.rpId,
        credentialIdB64u: state.signingLane.auth.credentialIdB64u,
        relayerUrl: state.relayerUrl,
        authority: state.authority,
        signingWalletSession: signingWalletSession.value,
      });
      return {
        ...rebound,
        walletSessionAuthorization: authorization,
      };
    }
    case 'email_otp': {
      const rebound = buildEmailOtpRouterAbEd25519WalletSessionState({
        walletId: signer.account.wallet.walletId,
        nearAccountId: signer.account.nearAccountId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
        providerSubjectId: state.signingLane.auth.providerSubjectId,
        signerSlot: signer.signerSlot,
        relayerUrl: state.relayerUrl,
        authority: state.authority,
        signingWalletSession: signingWalletSession.value,
      });
      return {
        ...rebound,
        walletSessionAuthorization: authorization,
      };
    }
    default:
      return assertNeverSigningLaneAuth(state.signingLane.auth);
  }
}

function assertNeverSigningLaneAuth(value: never): never {
  throw new Error(`Unknown Ed25519 signing lane auth: ${String(value)}`);
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
