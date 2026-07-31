import type { SigningSessionStatus } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import {
  normalizeWarmSessionReadPorts,
  readWarmSessionClaim,
  toWarmSessionClaimFromStatusResult,
  toSigningSessionStatus,
  type WarmSessionReadPortsInput,
} from './readModel';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionPrfClaim,
} from './types';
import type { ExactEd25519SealedSessionRuntime } from './ed25519SealedSessionRuntime';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { parseRouterAbEd25519WalletSessionIdentityClaims } from '../routerAbSigningWalletSession';

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

function ed25519SessionMetadata(runtime: ExactEd25519SealedSessionRuntime): {
  authMethod: SignerAuthMethod;
  retention?: 'session';
} {
  return runtime.factor.kind === SIGNER_AUTH_METHODS.emailOtp
    ? {
        authMethod: SIGNER_AUTH_METHODS.emailOtp,
        retention: 'session',
      }
    : {
        authMethod: SIGNER_AUTH_METHODS.passkey,
      };
}

async function ed25519AuthorizationMatchesRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): Promise<boolean> {
  const runtime = args.runtime;
  const authorization = args.authorization;
  if (
    String(authorization.walletId) !== String(runtime.walletId) ||
    authorization.authMethod !== runtime.factor.kind
  ) {
    return false;
  }
  const claims = parseRouterAbEd25519WalletSessionIdentityClaims(
    authorization.walletSessionJwt,
  );
  if (
    !claims ||
    claims.walletId !== runtime.walletId ||
    claims.nearAccountId !== runtime.nearAccountId ||
    claims.nearEd25519SigningKeyId !== runtime.nearEd25519SigningKeyId ||
    claims.thresholdSessionId !== runtime.thresholdSessionId ||
    claims.signingGrantId !== runtime.signingGrantId
  ) {
    return false;
  }
  try {
    const authority =
      runtime.factor.kind === SIGNER_AUTH_METHODS.passkey
        ? buildPasskeyWalletAuthAuthority({
            walletId: runtime.walletId,
            rpId: runtime.factor.rpId,
            credentialIdB64u: runtime.factor.credentialIdB64u,
          })
        : buildEmailOtpWalletAuthAuthority({
            walletId: runtime.walletId,
            provider: runtime.factor.provider,
            providerUserId: runtime.factor.providerSubjectId,
            emailHashHex: runtime.factor.emailHashHex,
          });
    const expected = await walletAuthAuthorityRef({ authority });
    return expected.authorityDigest === authorization.authority.authorityDigest;
  } catch {
    return false;
  }
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

  async function getEd25519SigningSessionStatus(args: {
    runtime: ExactEd25519SealedSessionRuntime;
    authorization: ActiveWalletSessionAuthorizationProjection | null;
    nowMs: number;
  }): Promise<SigningSessionStatus> {
    const runtime = args.runtime;
    const sessionId = String(runtime.thresholdSessionId);
    const metadata = ed25519SessionMetadata(runtime);
    if (
      !args.authorization ||
      !(await ed25519AuthorizationMatchesRuntime({
        runtime,
        authorization: args.authorization,
      }))
    ) {
      return {
        sessionId,
        status: 'unavailable',
        statusCode: 'auth_missing',
        ...metadata,
      };
    }
    if (args.authorization.expiresAtMs <= args.nowMs || runtime.expiresAtMs <= args.nowMs) {
      return {
        sessionId,
        status: 'expired',
        expiresAtMs: Math.min(
          args.authorization.expiresAtMs,
          runtime.expiresAtMs,
        ),
        ...metadata,
      };
    }
    if (runtime.remainingUses <= 0) {
      return {
        sessionId,
        status: 'exhausted',
        remainingUses: 0,
        expiresAtMs: runtime.expiresAtMs,
        ...metadata,
      };
    }
    const claim = await readEd25519WarmSessionClaim(runtime);
    const status = toSigningSessionStatus({
      sessionId,
      claim,
      authMethod: metadata.authMethod,
      retention: metadata.retention ?? null,
    });
    if (status.status === 'not_found') {
      return {
        sessionId,
        status: 'active',
        remainingUses: runtime.remainingUses,
        expiresAtMs: runtime.expiresAtMs,
        ...metadata,
      };
    }
    return status;
  }

  return {
    getEd25519SigningSessionStatus,
    readEd25519WarmSessionClaim,
  };
}
