import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import type {
  NearAuthorizedEd25519SigningSessionState,
  NearEd25519YaoOperationMaterialFacts,
  NearResolvedEd25519SigningSessionState,
} from '@/core/signingEngine/interfaces/near';
import {
  walletSessionAuthorizations,
  type ActiveWalletSessionV1,
  type WalletSessionOperationCredentialV1,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { IndexedDBManager } from '@/core/indexedDB';
import { signingLaneAuthMethod } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import { resolveWalletAuthorityOperation } from '@/core/signingEngine/session/authority';
import {
  buildRouterAbEd25519SigningWalletSession,
  type RouterAbEd25519SigningWalletSession,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  ed25519SealedRuntimeAuthorityRef,
  type ExactEd25519SealedSessionRuntime,
} from './ed25519SealedSessionRuntime';
import type { ExactNearEd25519WalletSessionAuthorization } from '../material/nearEd25519YaoSigningPreparation';
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
  const walletSessionToken = requireNonEmptyStateValue(
    input.signingWalletSession.auth.walletSessionToken,
    'walletSessionToken',
  );
  const relayerUrl = requireNonEmptyStateValue(input.relayerUrl, 'relayerUrl');
  const providerSubjectId = requireNonEmptyStateValue(input.providerSubjectId, 'providerSubjectId');
  const signerSlot = requirePositiveStateInteger(input.signerSlot, 'signerSlot');
  const remainingUses = requirePositiveStateInteger(
    input.signingWalletSession.remainingUses,
    'remainingUses',
  );
  const walletSessionAuth = {
    kind: 'wallet_session_opaque' as const,
    walletSessionToken,
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
  const walletSessionToken = requireNonEmptyStateValue(
    input.signingWalletSession.auth.walletSessionToken,
    'walletSessionToken',
  );
  const relayerUrl = requireNonEmptyStateValue(input.relayerUrl, 'relayerUrl');
  const credentialIdB64u = requireNonEmptyStateValue(input.credentialIdB64u, 'credentialIdB64u');
  const signerSlot = requirePositiveStateInteger(input.signerSlot, 'signerSlot');
  return {
    walletSessionAuth: {
      kind: 'wallet_session_opaque',
      walletSessionToken,
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

export async function rebindRouterAbEd25519WalletSessionStateFromExactRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  authorization: ExactNearEd25519WalletSessionAuthorization;
  nowMs: number;
}): Promise<ResolvedRouterAbEd25519WalletSessionState> {
  const walletSessionToken = args.authorization.operationCredential.token;
  const authorizationId = args.authorization.session.authorizationId;
  const exactAuthority = await ed25519SealedRuntimeAuthorityRef({
    runtime: args.runtime,
    walletAuthMethodId: args.authorization.selectedAuthMethod.walletAuthMethodId,
  });
  const selectedFactorAuthorityRef = await walletAuthAuthorityRef({
    authority: args.authorization.selectedFactorAuthority,
  });
  const expiresAtMs = Math.min(args.runtime.expiresAtMs, args.authorization.status.expiresAtMs);
  if (
    !walletSessionToken ||
    !authorizationId ||
    args.authorization.session.walletId !== args.runtime.walletId ||
    args.authorization.selectedAuthMethod.kind !== args.runtime.auth.kind ||
    exactAuthority.walletId !== args.runtime.walletId ||
    exactAuthority.walletAuthMethodId !==
      args.authorization.selectedAuthMethod.walletAuthMethodId ||
    exactAuthority.walletId !== selectedFactorAuthorityRef.walletId ||
    exactAuthority.walletAuthMethodId !== selectedFactorAuthorityRef.walletAuthMethodId ||
    String(exactAuthority.authorityDigest) !== String(selectedFactorAuthorityRef.authorityDigest) ||
    args.authorization.operationCredential.walletSessionId !==
      args.authorization.status.walletSessionId ||
    expiresAtMs <= args.nowMs
  ) {
    throw new Error('Ed25519 Wallet Session authorization does not match sealed material');
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: args.runtime.walletId,
    nearAccountId: args.runtime.nearAccountId,
    nearEd25519SigningKeyId: args.runtime.nearEd25519SigningKeyId,
    walletSessionId: args.authorization.operationCredential.walletSessionId,
    authorizationId,
    quotaId: args.authorization.session.quotaId,
    thresholdSessionId: args.runtime.thresholdSessionId,
    remainingUses: Math.min(args.runtime.remainingUses, args.authorization.status.remainingUses),
    expiresAtMs,
    runtimePolicyScope: args.runtime.runtimePolicyScope,
    signingRootId: args.runtime.signingRootId,
    signingRootVersion: args.runtime.signingRootVersion,
    routerAbNormalSigning: args.runtime.routerAbNormalSigning,
    walletSessionToken,
    nowMs: args.nowMs,
  });
  if (!signingWalletSession.ok) {
    throw new Error(`Ed25519 Wallet Session runtime is invalid: ${signingWalletSession.reason}`);
  }
  if (args.runtime.factor.kind === 'passkey' && args.runtime.auth.kind === 'passkey') {
    return buildPasskeyRouterAbEd25519WalletSessionState({
      walletId: args.runtime.walletId,
      nearAccountId: args.runtime.nearAccountId,
      nearEd25519SigningKeyId: args.runtime.nearEd25519SigningKeyId,
      signerSlot: args.runtime.signerSlot,
      rpId: args.runtime.factor.rpId,
      credentialIdB64u: args.runtime.factor.credentialIdB64u,
      relayerUrl: args.runtime.relayerUrl,
      authority: exactAuthority,
      signingWalletSession: signingWalletSession.value,
    });
  }
  if (args.runtime.factor.kind === 'email_otp' && args.runtime.auth.kind === 'email_otp') {
    return buildEmailOtpRouterAbEd25519WalletSessionState({
      walletId: args.runtime.walletId,
      nearAccountId: args.runtime.nearAccountId,
      nearEd25519SigningKeyId: args.runtime.nearEd25519SigningKeyId,
      providerSubjectId: args.runtime.auth.providerSubjectId,
      signerSlot: args.runtime.signerSlot,
      relayerUrl: args.runtime.relayerUrl,
      authority: exactAuthority,
      signingWalletSession: signingWalletSession.value,
    });
  }
  throw new Error('Ed25519 sealed runtime factor and auth binding disagree');
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

function hasExactEd25519SigningSubject(args: {
  authorization: ActiveWalletSessionV1;
  materialActivation: MpcMaterialActivationRef;
}): boolean {
  return args.authorization.capabilitySubjects.some(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === 'ed25519' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.materialActivation),
  );
}

function authorizeRouterAbEd25519WalletSessionState(args: {
  state: ResolvedRouterAbEd25519WalletSessionState;
  authorization: ActiveWalletSessionV1;
  operationCredential: WalletSessionOperationCredentialV1;
  materialActivation: MpcMaterialActivationRef;
  nowMs: number;
}): AuthorizedRouterAbEd25519WalletSessionState | null {
  const state = args.state;
  const authorization = args.authorization;
  const walletId = state.signingLane.identity.signer.account.wallet.walletId;
  const walletSessionToken = args.operationCredential.token;
  const signer = state.signingLane.identity.signer;
  const effectiveExpiresAtMs = Math.min(
    state.signingWalletSession.expiresAtMs,
    authorization.expiresAtMs,
  );
  if (
    !walletSessionToken ||
    !hasExactEd25519SigningSubject({
      authorization,
      materialActivation: args.materialActivation,
    }) ||
    authorization.walletId !== walletId ||
    authorization.authMethodId !== state.authority.walletAuthMethodId ||
    args.operationCredential.walletSessionId !== state.walletSessionId ||
    authorization.authorizationId !== state.signingWalletSession.authorizationId ||
    effectiveExpiresAtMs <= args.nowMs ||
    !Number.isSafeInteger(effectiveExpiresAtMs)
  ) {
    return null;
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(signer.account.wallet.walletId),
    nearAccountId: String(signer.account.nearAccountId),
    nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
    walletSessionId: String(state.walletSessionId),
    authorizationId: String(state.signingWalletSession.authorizationId),
    quotaId: String(state.quotaId),
    thresholdSessionId: String(state.thresholdSessionId),
    remainingUses: state.remainingUses,
    expiresAtMs: effectiveExpiresAtMs,
    runtimePolicyScope: state.runtimePolicyScope,
    signingRootId: state.signingRootId,
    signingRootVersion: state.signingRootVersion,
    routerAbNormalSigning: state.routerAbNormalSigning,
    walletSessionToken,
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
        walletSessionOperationCredential: args.operationCredential,
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
        walletSessionOperationCredential: args.operationCredential,
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
  return resolveActiveAuthorizedRouterAbEd25519WalletSessionStateWithResolver(args, {
    resolveSelectedWalletAuthority:
      IndexedDBManager.resolveSelectedWalletAuthority.bind(IndexedDBManager),
    readExactWithOperationCredential:
      walletSessionAuthorizations.readExactWithOperationCredential.bind(
        walletSessionAuthorizations,
      ),
  });
}

export type RouterAbEd25519WalletSessionAuthorizationResolver = {
  readonly resolveSelectedWalletAuthority: typeof IndexedDBManager.resolveSelectedWalletAuthority;
  readonly readExactWithOperationCredential: typeof walletSessionAuthorizations.readExactWithOperationCredential;
};

export async function resolveActiveAuthorizedRouterAbEd25519WalletSessionStateWithResolver(
  args: {
    state: ResolvedRouterAbEd25519WalletSessionState;
    nowMs: number;
  },
  resolver: RouterAbEd25519WalletSessionAuthorizationResolver,
): Promise<AuthorizedRouterAbEd25519WalletSessionState | null> {
  const walletId = args.state.signingLane.identity.signer.account.wallet.walletId;
  let selected: Awaited<ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>>;
  try {
    selected = await resolver.resolveSelectedWalletAuthority(String(walletId));
  } catch {
    return null;
  }
  if (selected.kind !== 'resolved') return null;
  const { selection, authMethod, authority } = selected;
  if (
    selection.lockState !== 'unlocked' ||
    selection.walletId !== walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authMethod.status !== 'active' ||
    authMethod.walletId !== walletId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    authMethod.walletAuthMethodId !== args.state.authority.walletAuthMethodId ||
    authMethod.kind !== signingLaneAuthMethod(args.state.signingLane.auth) ||
    authority.state !== 'active' ||
    authority.walletId !== walletId
  ) {
    return null;
  }
  let operation: Awaited<ReturnType<typeof resolveWalletAuthorityOperation>>;
  try {
    operation = await resolveWalletAuthorityOperation({
      selected: { authMethod, authority },
      operation: { kind: 'near_sign', operation: 'sign', keyFamily: 'ed25519' },
    });
  } catch {
    return null;
  }
  if (
    operation.kind !== 'resolved' ||
    operation.value.walletId !== walletId ||
    operation.value.authorityId !== authority.authorityId ||
    operation.value.authMethodId !== authMethod.walletAuthMethodId
  ) {
    return null;
  }
  let authorizationRead: Awaited<
    ReturnType<typeof walletSessionAuthorizations.readExactWithOperationCredential>
  >;
  try {
    authorizationRead = await resolver.readExactWithOperationCredential({
      walletId,
      authorityId: authority.authorityId,
      authMethodId: authMethod.walletAuthMethodId,
    });
  } catch {
    return null;
  }
  if (authorizationRead.kind !== 'found') return null;
  if (
    authorizationRead.record.walletId !== walletId ||
    authorizationRead.record.authorityId !== authority.authorityId ||
    authorizationRead.record.authMethodId !== authMethod.walletAuthMethodId ||
    authorizationRead.record.authorityDigestB64u !== authority.authorityDigestB64u ||
    authorizationRead.record.authorityRevocationEpoch !== authority.revocationEpoch ||
    authorizationRead.record.expiresAtMs <= args.nowMs
  ) {
    return null;
  }
  return authorizeRouterAbEd25519WalletSessionState({
    state: args.state,
    authorization: authorizationRead.record,
    operationCredential: authorizationRead.operationCredential,
    materialActivation: operation.value.materialActivation,
    nowMs: args.nowMs,
  });
}
