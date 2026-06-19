import {
  persistStoredThresholdEd25519SessionMaterialHandle,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEd25519SessionStoreSource } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildNearTransactionSigningLane,
} from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import type { UiConfirmSigningSessionPort } from '@/core/signingEngine/uiConfirm/types';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/types';
import type { NearResolvedEd25519SigningSessionState } from '@/core/signingEngine/interfaces/near';
import {
  toAuthorizingSigningGrantId,
  type EmailOtpAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  walletSessionAuthFromPersistedEd25519Record,
  walletSessionJwtFromPersistedEd25519Record,
} from '@/core/signingEngine/session/walletSessionAuthBoundary';
import { SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR } from './signingSessionAuthMode';
import {
  parseRouterAbEd25519SigningWalletSessionFromRecord,
  type RouterAbEd25519SigningWalletSession,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';

export type ResolvedRouterAbEd25519WalletSessionState =
  NearResolvedEd25519SigningSessionState & {
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
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  const signingGrantId = String(record.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) return null;
  const signingWalletSession = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
  if (!signingWalletSession.ok) return null;
  const walletSessionAuth = walletSessionAuthFromPersistedEd25519Record(record);
  if (!walletSessionAuth) return null;
  const signingLane =
    record.source === 'email_otp'
      ? buildNearTransactionSigningLane({
          accountId: record.nearAccountId,
          authMethod: 'email_otp',
          signingGrantId:
            SigningSessionIds.signingGrant(signingGrantId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
          retention: record.emailOtpAuthContext?.retention || 'session',
          sessionOrigin:
            record.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
        })
      : buildNearTransactionSigningLane({
          accountId: record.nearAccountId,
          authMethod: 'passkey',
          signingGrantId:
            SigningSessionIds.signingGrant(signingGrantId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
          storageSource: resolveEd25519PasskeyStorageSource(record.source),
        });
  const common = {
    thresholdSessionId,
    signingGrantId,
    signingLane,
    remainingUses: Math.max(0, Math.floor(Number(record.remainingUses) || 0)),
    signingMaterial: signingWalletSession.value.signingMaterial,
    signingRootId: signingWalletSession.value.signingRootId,
    signingRootVersion: signingWalletSession.value.signingRootVersion,
    routerAbNormalSigning: signingWalletSession.value.routerAbNormalSigning,
    runtimePolicyScope: signingWalletSession.value.runtimePolicyScope,
    relayerUrl: String(record.relayerUrl || '').trim(),
    persistSigningMaterial: (material: {
      materialHandle: string;
      bindingDigest: string;
      clientVerifyingShareB64u: string;
    }) =>
      Boolean(
        persistStoredThresholdEd25519SessionMaterialHandle({
          thresholdSessionId,
          ed25519HssMaterialHandle: material.materialHandle,
          ed25519HssMaterialBindingDigest: material.bindingDigest,
          clientVerifyingShareB64u: material.clientVerifyingShareB64u,
        }),
      ),
    signingWalletSession: signingWalletSession.value,
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
  if (args.walletSessionState.signingLane.authMethod !== 'passkey') return;
  const persist = args.touchConfirm?.persistSigningSessionSealForThresholdSession;
  if (typeof persist !== 'function') return;
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const signingGrantId = String(
    args.walletSessionState.signingGrantId || '',
  ).trim();
  const relayerUrl = String(args.walletSessionState.relayerUrl || '').trim();
  const materialHandle = String(args.materialHandle || '').trim();
  if (!thresholdSessionId || !signingGrantId || !relayerUrl || !materialHandle) return;
  const result = await persist({
    sessionId: thresholdSessionId,
    transport: {
      curve: 'ed25519',
      walletId: String(args.nearAccountId || '').trim(),
      relayerUrl,
      signingGrantId,
      ...(args.walletSessionState.walletSessionAuth.kind === 'wallet_session_jwt'
        ? { walletSessionJwt: args.walletSessionState.walletSessionAuth.walletSessionJwt }
        : {}),
    },
  }).catch((error: unknown) => {
    console.warn('[SigningEngine][near] failed to refresh passkey Ed25519 sealed restore metadata', {
      nearAccountId: args.nearAccountId,
      thresholdSessionId,
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
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

export function requireResolvedRouterAbEd25519WalletSessionState(args: {
  signingSessionCoordinator: WarmSessionCapabilityReader;
  thresholdSessionId: string;
}): ResolvedRouterAbEd25519WalletSessionState {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  const record = args.signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(
    thresholdSessionId,
  );
  if (!record) {
    throw new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  const parsed = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
  if (!parsed.ok) {
    throw new Error(`${SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR}: ${parsed.reason}`);
  }
  const state = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
  if (!state) {
    throw new Error(`${SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR}: unresolved_signable_record`);
  }
  return state;
}
