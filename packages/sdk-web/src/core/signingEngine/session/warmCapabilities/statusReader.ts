import { type AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import {
  type ThresholdEd25519SessionRecord,
  getStoredThresholdEd25519SessionRecordForAccount,
} from '../persistence/records';
import { emailOtpAuthContextRetention } from '../identity/laneIdentity';
import {
  normalizeWarmSessionReadPorts,
  readWarmSessionClaim,
  toWarmSessionClaimFromStatusResult,
  toSigningSessionStatus,
  type WarmSessionReadPortsInput,
} from './readModel';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  parseRouterAbEd25519WalletSessionAuthorityFromRecord,
} from '../routerAbSigningWalletSession';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionPrfClaim,
} from './types';
import type { ExactEd25519SealedSessionRuntime } from './ed25519SealedSessionRuntime';

export const THRESHOLD_SESSION_MISSING_ERROR =
  '[chains] Missing threshold signingSessionId; reconnect threshold session before signing';
export const THRESHOLD_SESSION_EXHAUSTED_ERROR =
  '[chains] threshold signingSession is exhausted; reconnect threshold session before signing';
export const SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR =
  '[chains] signingSession auth is unavailable; reconnect signing session before signing';
export const THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR =
  '[chains] threshold signingSession status is unavailable; retry after refreshing the signer runtime';

export function formatThresholdSigningSessionStatusError(code: string): string {
  return `[chains] threshold signingSession is ${code}; reconnect threshold session before signing`;
}

export function formatThresholdSigningSessionAvailabilityError(code?: string): string {
  const suffix = typeof code === 'string' && code.trim() ? ` (${code.trim()})` : '';
  return `${THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR}${suffix}`;
}

export function requireThresholdSigningSessionId(sessionIdRaw: unknown): string {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
  return sessionId;
}

export function normalizeUsesNeeded(usesNeededRaw: unknown): number {
  const usesNeeded = Math.floor(Number(usesNeededRaw) || 0);
  return usesNeeded > 0 ? usesNeeded : 1;
}

function authMethodForEd25519Record(
  record: ThresholdEd25519SessionRecord | null | undefined,
): SignerAuthMethod | null {
  const source = record?.source;
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case undefined:
      return null;
    case 'login':
    case 'registration':
    case 'add-signer':
    case 'manual-connect':
    case 'bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      return assertNeverEd25519StoreSource(source);
  }
}

function assertNeverEd25519StoreSource(value: never): never {
  throw new Error(`Unsupported signing session store source: ${String(value)}`);
}

export type WarmSessionStatusReaderDeps = {
  touchConfirm?: WarmSessionReadPortsInput;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

export type WarmSigningStatusReader = ThresholdWarmSessionStatusReader & {
  readEd25519WarmSessionClaim: (
    runtime: ExactEd25519SealedSessionRuntime,
  ) => Promise<WarmSessionPrfClaim | null>;
};

export function createWarmSessionStatusReader(
  deps: WarmSessionStatusReaderDeps,
): WarmSigningStatusReader {
  const touchConfirm = normalizeWarmSessionReadPorts(deps.touchConfirm);

  async function readEd25519WarmSessionClaim(
    runtime: ExactEd25519SealedSessionRuntime,
  ): Promise<WarmSessionPrfClaim | null> {
    const sessionId = String(runtime.thresholdSessionId);
    return await readEd25519WarmSessionClaimByMethod({
      authMethod: runtime.factor.kind,
      sessionId,
    });
  }

  async function readEd25519WarmSessionClaimByMethod(args: {
    authMethod: SignerAuthMethod;
    sessionId: string;
  }): Promise<WarmSessionPrfClaim | null> {
    if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
      const status = await deps
        .getEmailOtpWarmSessionStatus(args.sessionId)
        .catch(() => ({
          ok: false as const,
          code: 'worker_error',
          message: 'worker_error',
        }));
      return toWarmSessionClaimFromStatusResult({
        sessionId: args.sessionId,
        status,
      });
    }
    return await readWarmSessionClaim(touchConfirm, args.sessionId);
  }

  function toRecordBackedEd25519StatusIfReady(
    record: ThresholdEd25519SessionRecord,
    thresholdSessionId: string,
  ): SigningSessionStatus | null {
    const persistedState = classifyRouterAbEd25519PersistedSigningRecord(record);
    switch (persistedState.kind) {
      case 'ready':
        break;
      case 'non_signing':
      case 'invalid':
        return null;
      case 'expired':
        return { sessionId: thresholdSessionId, status: 'expired' };
      case 'exhausted':
        return { sessionId: thresholdSessionId, status: 'exhausted' };
    }
    const remainingUses = Math.floor(Number(persistedState.value.remainingUses) || 0);
    const expiresAtMs = Math.floor(Number(persistedState.value.expiresAtMs) || 0);
    const status =
      expiresAtMs > 0 && Date.now() >= expiresAtMs
        ? 'expired'
        : remainingUses <= 0
          ? 'exhausted'
          : 'active';
    return {
      sessionId: thresholdSessionId,
      status,
      authMethod: authMethodForEd25519Record(record),
      ...(record.emailOtpAuthContext
        ? { retention: emailOtpAuthContextRetention(record.emailOtpAuthContext) }
        : {}),
      ...(status === 'active' || status === 'exhausted' ? { remainingUses } : {}),
      ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
    };
  }

  async function getEd25519SigningSessionStatusForRecord(
    record: ThresholdEd25519SessionRecord | null,
  ): Promise<SigningSessionStatus | null> {
    if (!record) return null;
    const thresholdSessionId = String(record.thresholdSessionId).trim();
    if (!thresholdSessionId) return null;
    const walletSessionAuthority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(record);
    if (!walletSessionAuthority.ok) {
      return {
        sessionId: thresholdSessionId,
        status: 'unavailable',
        statusCode: 'auth_missing',
        authMethod: authMethodForEd25519Record(record),
        ...(record.emailOtpAuthContext
          ? { retention: emailOtpAuthContextRetention(record.emailOtpAuthContext) }
          : {}),
      };
    }
    const claim = await readEd25519WarmSessionClaimByMethod({
      authMethod:
        authMethodForEd25519Record(record) ?? SIGNER_AUTH_METHODS.passkey,
      sessionId: thresholdSessionId,
    });
    const status = toSigningSessionStatus({
      sessionId: thresholdSessionId,
      claim,
      authMethod: authMethodForEd25519Record(record),
      retention: record.emailOtpAuthContext
        ? emailOtpAuthContextRetention(record.emailOtpAuthContext)
        : null,
    });
    if (status.status === 'not_found') {
      return toRecordBackedEd25519StatusIfReady(record, thresholdSessionId) || status;
    }
    return status;
  }

  async function getEd25519SigningSessionStatus(
    nearAccountId: AccountId,
  ): Promise<SigningSessionStatus | null> {
    return await getEd25519SigningSessionStatusForRecord(
      getStoredThresholdEd25519SessionRecordForAccount(nearAccountId),
    );
  }

  return {
    getEd25519SigningSessionStatus,
    readEd25519WarmSessionClaim,
  };
}
