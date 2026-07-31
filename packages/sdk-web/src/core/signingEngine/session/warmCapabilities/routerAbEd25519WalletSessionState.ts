import {
  thresholdEd25519LaneCandidateFromSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type ThresholdEd25519SessionStoreSource,
} from '@/core/signingEngine/session/identity/laneIdentity';
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
  classifyRouterAbEd25519PersistedSigningRecord,
  parseRouterAbEd25519SigningWalletSessionFromRecord,
  type RouterAbEd25519SigningWalletSession,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';

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
  const thresholdSessionId = requireNonEmptyStateValue(
    input.signingWalletSession.thresholdSessionId,
    'thresholdSessionId',
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
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
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

function resolveEd25519PasskeyStorageSource(
  source: ThresholdEd25519SessionStoreSource | undefined,
): Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'> {
  return source && source !== 'email_otp' ? source : 'login';
}

export function resolveRouterAbEd25519WalletSessionStateFromRecord(
  record: ThresholdEd25519SessionRecord | undefined,
): ResolvedRouterAbEd25519WalletSessionState | null {
  if (!record) return null;
  const signingWalletSession = classifyRouterAbEd25519PersistedSigningRecord(record);
  if (signingWalletSession.kind !== 'ready') return null;
  return resolveRouterAbEd25519WalletSessionStateFromParsedSession({
    record,
    signingWalletSession: signingWalletSession.value,
  });
}

export function resolveRouterAbEd25519WalletSessionStateForOperation(args: {
  record: ThresholdEd25519SessionRecord;
  nowMs: number;
}): ResolvedRouterAbEd25519WalletSessionState | null {
  const signingWalletSession = classifyRouterAbEd25519PersistedSigningRecord(
    args.record,
    args.nowMs,
  );
  if (signingWalletSession.kind !== 'ready') return null;
  return resolveRouterAbEd25519WalletSessionStateFromParsedSession({
    record: args.record,
    signingWalletSession: signingWalletSession.value,
  });
}

export function resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(
  record: ThresholdEd25519SessionRecord | undefined,
): ResolvedRouterAbEd25519WalletSessionState | null {
  if (!record) return null;
  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= 1) return null;
  const signingWalletSession = parseRouterAbEd25519SigningWalletSessionFromRecord(
    record,
    Math.min(Date.now(), expiresAtMs - 1),
  );
  if (!signingWalletSession.ok) return null;
  return resolveRouterAbEd25519WalletSessionStateFromParsedSession({
    record,
    signingWalletSession: signingWalletSession.value,
  });
}

function resolveRouterAbEd25519WalletSessionStateFromParsedSession(args: {
  record: ThresholdEd25519SessionRecord;
  signingWalletSession: RouterAbEd25519SigningWalletSession;
}): ResolvedRouterAbEd25519WalletSessionState | null {
  const record = args.record;
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  const signingGrantId = String(record.signingGrantId || '').trim();
  const relayerUrl = String(record.relayerUrl || '').trim();
  if (!thresholdSessionId || !signingGrantId || !relayerUrl) return null;

  const recordCandidate = thresholdEd25519LaneCandidateFromSessionRecord({ record });
  if (!recordCandidate) return null;
  const emailOtpAuthContext = record.source === 'email_otp' ? record.emailOtpAuthContext : null;
  const signingLane =
    record.source === 'email_otp'
      ? recordCandidate.auth.kind === 'email_otp' && emailOtpAuthContext
        ? buildNearTransactionSigningLane({
            walletId: record.walletId,
            nearAccountId: record.nearAccountId,
            nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
            signerSlot: recordCandidate.signerSlot,
            auth: recordCandidate.auth,
            signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
            retention: emailOtpAuthContextRetention(emailOtpAuthContext),
            sessionOrigin:
              emailOtpAuthContextReason(emailOtpAuthContext) === 'login'
                ? 'login'
                : 'per_operation',
          })
        : null
      : recordCandidate.auth.kind === 'passkey'
        ? buildNearTransactionSigningLane({
            walletId: record.walletId,
            nearAccountId: record.nearAccountId,
            nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
            signerSlot: recordCandidate.signerSlot,
            auth: recordCandidate.auth,
            signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
            storageSource: resolveEd25519PasskeyStorageSource(record.source),
          })
        : null;
  if (!signingLane) return null;

  return {
    walletSessionAuth: args.signingWalletSession.auth,
    thresholdSessionId,
    signingGrantId,
    signingLane,
    remainingUses: args.signingWalletSession.remainingUses,
    signingRootId: args.signingWalletSession.signingRootId,
    signingRootVersion: args.signingWalletSession.signingRootVersion,
    routerAbNormalSigning: args.signingWalletSession.routerAbNormalSigning,
    runtimePolicyScope: args.signingWalletSession.runtimePolicyScope,
    relayerUrl,
    signingWalletSession: args.signingWalletSession,
  };
}
