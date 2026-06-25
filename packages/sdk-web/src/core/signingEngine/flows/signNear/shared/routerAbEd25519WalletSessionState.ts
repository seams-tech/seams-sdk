import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  persistStoredThresholdEd25519SessionMaterialHandle,
  thresholdEd25519LaneCandidateFromSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEd25519SessionStoreSource } from '@/core/signingEngine/session/identity/laneIdentity';
import { signingLaneAuthMethod } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import type { UiConfirmSigningSessionPort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { NearResolvedEd25519SigningSessionState } from '@/core/signingEngine/interfaces/near';
import {
  toAuthorizingSigningGrantId,
  type EmailOtpAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  walletSessionAuthFromPersistedEd25519Record,
  walletSessionJwtFromPersistedEd25519Record,
} from '@/core/signingEngine/session/walletSessionAuthBoundary';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
  parseRouterAbEd25519SigningWalletSessionFromRecord,
  type RouterAbEd25519SigningWalletSession,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';

export type ResolvedRouterAbEd25519WalletSessionState = NearResolvedEd25519SigningSessionState & {
  signingWalletSession: RouterAbEd25519SigningWalletSession;
};

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
  if (signingWalletSession.kind !== 'runtime_validated') return null;
  return resolveRouterAbEd25519WalletSessionStateFromParsedSession({
    record,
    signingWalletSession: signingWalletSession.value,
  });
}

export function resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(
  record: ThresholdEd25519SessionRecord | undefined,
): ResolvedRouterAbEd25519WalletSessionState | null {
  if (!record) return null;
  const signingWalletSession = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
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
  if (!thresholdSessionId || !signingGrantId) return null;
  const walletSessionAuth = walletSessionAuthFromPersistedEd25519Record(record);
  if (!walletSessionAuth) return null;
  const recordCandidate = thresholdEd25519LaneCandidateFromSessionRecord({ record });
  if (!recordCandidate) return null;
  const signingLane =
    record.source === 'email_otp'
      ? recordCandidate.auth.kind === 'email_otp'
        ? buildNearTransactionSigningLane({
            walletId: record.walletId,
            nearAccountId: record.nearAccountId,
            nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
            signerSlot: recordCandidate.signerSlot,
            auth: recordCandidate.auth,
            signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
            retention: record.emailOtpAuthContext?.retention || 'session',
            sessionOrigin:
              record.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
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
  const common = {
    thresholdSessionId,
    signingGrantId,
    signingLane,
    remainingUses: Math.max(0, Math.floor(Number(record.remainingUses) || 0)),
    signingMaterial: args.signingWalletSession.signingMaterial,
    signingRootId: args.signingWalletSession.signingRootId,
    signingRootVersion: args.signingWalletSession.signingRootVersion,
    routerAbNormalSigning: args.signingWalletSession.routerAbNormalSigning,
    runtimePolicyScope: args.signingWalletSession.runtimePolicyScope,
    relayerUrl: String(record.relayerUrl || '').trim(),
    persistSigningMaterial: (material: {
      materialHandle: string;
      bindingDigest: string;
      clientVerifyingShareB64u: string;
      sealedWorkerMaterialRef?: string;
      sealedWorkerMaterialB64u?: string;
      materialFormatVersion?: string;
      materialKeyId?: string;
      materialCreatedAtMs?: number;
      signerSlot?: number;
      keyVersion?: string;
    }) => {
      const persisted = Boolean(
        persistStoredThresholdEd25519SessionMaterialHandle({
          thresholdSessionId,
          ed25519WorkerMaterialHandle: material.materialHandle,
          ed25519WorkerMaterialBindingDigest: material.bindingDigest,
          clientVerifyingShareB64u: material.clientVerifyingShareB64u,
          ...(material.sealedWorkerMaterialRef
            ? { sealedWorkerMaterialRef: material.sealedWorkerMaterialRef }
            : {}),
          ...(material.sealedWorkerMaterialB64u
            ? { sealedWorkerMaterialB64u: material.sealedWorkerMaterialB64u }
            : {}),
          ...(material.materialFormatVersion
            ? { materialFormatVersion: material.materialFormatVersion }
            : {}),
          ...(material.materialKeyId ? { materialKeyId: material.materialKeyId } : {}),
          ...(material.materialCreatedAtMs
            ? { materialCreatedAtMs: material.materialCreatedAtMs }
            : {}),
          ...(material.signerSlot ? { signerSlot: material.signerSlot } : {}),
          ...(material.keyVersion ? { keyVersion: material.keyVersion } : {}),
        }),
      );
      if (persisted) {
        markRouterAbEd25519WorkerMaterialRuntimeValidated(
          getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId),
        );
      }
      return persisted;
    },
    signingWalletSession: args.signingWalletSession,
  };
  return {
    ...common,
    walletSessionAuth,
  };
}

export function emailOtpEd25519AuthLaneFromRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): EmailOtpAuthLane | undefined {
  const jwt = walletSessionJwtFromPersistedEd25519Record(record);
  const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
  const signingGrantId = String(record?.signingGrantId || '').trim();
  if (record?.source !== 'email_otp' || !jwt || !thresholdSessionId || !signingGrantId) {
    return undefined;
  }
  return {
    kind: 'signing_session',
    jwt,
    thresholdSessionId,
    authorizingSigningGrantId: toAuthorizingSigningGrantId(signingGrantId),
    curve: 'ed25519',
  };
}

export async function refreshPasskeyEd25519SealedRecordAfterSigningMaterial(args: {
  touchConfirm?: Pick<UiConfirmSigningSessionPort, 'persistSigningSessionSealForThresholdSession'>;
  nearAccountId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdSessionId: string;
  materialHandle: string | undefined;
}): Promise<void> {
  if (signingLaneAuthMethod(args.walletSessionState.signingLane.auth) !== 'passkey') return;
  const persist = args.touchConfirm?.persistSigningSessionSealForThresholdSession;
  if (typeof persist !== 'function') return;
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const signingGrantId = String(args.walletSessionState.signingGrantId || '').trim();
  const relayerUrl = String(args.walletSessionState.relayerUrl || '').trim();
  const materialHandle = String(args.materialHandle || '').trim();
  if (!thresholdSessionId || !signingGrantId || !relayerUrl || !materialHandle) return;
  const signer = args.walletSessionState.signingLane.identity.signer;
  const result = await persist({
        sessionId: thresholdSessionId,
        transport: {
          curve: 'ed25519',
          walletId: String(signer.account.wallet.walletId || '').trim(),
          relayerUrl,
          signingGrantId,
          ...(args.walletSessionState.walletSessionAuth.kind === 'wallet_session_jwt'
            ? { walletSessionJwt: args.walletSessionState.walletSessionAuth.walletSessionJwt }
        : {}),
    },
  }).catch((error: unknown) => {
    console.warn(
      '[SigningEngine][near] failed to refresh passkey Ed25519 sealed restore metadata',
      {
        nearAccountId: args.nearAccountId,
        thresholdSessionId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      },
    );
    return null;
  });
  if (result && !result.ok && result.code !== 'not_enabled') {
    console.warn('[SigningEngine][near] passkey Ed25519 sealed restore metadata refresh failed', {
      nearAccountId: args.nearAccountId,
      thresholdSessionId,
      code: result.code,
      message: result.message,
    });
  }
}
