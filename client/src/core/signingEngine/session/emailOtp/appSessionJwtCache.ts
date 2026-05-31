import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { walletSessionRefFromSession } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthLane } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { authLaneAppSessionJwt } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  exactSigningLaneIdentityKey,
  type ExactSigningLaneIdentity,
  type ExactSigningLaneIdentityKey,
} from '../identity/exactSigningLaneIdentity';
import type { SigningOperationFingerprint, SigningOperationId } from '../operationState/types';
import {
  decodeJwtPayloadRecord,
  isAppSessionJwt,
  isSessionJwtUnexpired,
} from '@shared/utils/sessionTokens';
import { joinNormalizedUrl } from '@shared/utils/normalize';

export type EmailOtpRefreshIdentity = {
  kind: 'email_otp_refresh_identity';
  walletId: AccountId;
  walletSessionUserId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
};

export type EmailOtpSessionRefreshResult =
  | {
      kind: 'cached_email_otp_session';
      identity: EmailOtpRefreshIdentity;
      appSessionJwt: string;
    }
  | {
      kind: 'refreshed_email_otp_session';
      identity: EmailOtpRefreshIdentity;
      appSessionJwt: string;
    }
  | {
      kind: 'email_otp_refresh_rejected';
      identity: EmailOtpRefreshIdentity;
      reason: 'session_refresh_unauthorized';
      httpStatus: 401 | 403;
      appSessionJwt?: never;
    };

export class EmailOtpAppSessionJwtCache {
  private readonly byAccount = new Map<string, string>();

  constructor(
    private readonly deps: {
      refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
    } = {},
  ) {}

  remember(args: { walletSession: WalletSessionRef; appSessionJwt?: string }): void {
    const jwt = String(args.appSessionJwt || '').trim();
    if (!jwt || !isAppSessionJwt(jwt)) return;
    const accountId = String(args.walletSession.walletId || '').trim();
    if (!accountId) return;
    this.byAccount.set(accountId, jwt);
  }

  async resolve(args: {
    identity: EmailOtpRefreshIdentity;
    relayUrl: string;
  }): Promise<EmailOtpSessionRefreshResult> {
    const cached = this.cachedJwtForIdentity(args.identity);
    if (cached && isSessionJwtUnexpired(cached, { skewMs: 30_000 })) {
      return {
        kind: 'cached_email_otp_session',
        identity: args.identity,
        appSessionJwt: cached,
      };
    }
    const refreshCandidate =
      cached && isAppSessionJwt(cached) && isSessionJwtUnexpired(cached) ? cached : '';
    this.byAccount.delete(String(args.identity.walletId));
    const refreshed = this.deps.refreshAppSessionJwt
      ? {
          kind: 'refreshed_email_otp_session' as const,
          identity: args.identity,
          appSessionJwt: await this.deps.refreshAppSessionJwt({ relayUrl: args.relayUrl }),
        }
      : await refreshEmailOtpAppSessionJwt({
          identity: args.identity,
          relayUrl: args.relayUrl,
          ...(refreshCandidate ? { appSessionJwt: refreshCandidate } : {}),
        });
    if (refreshed.kind === 'refreshed_email_otp_session') {
      this.remember({
        walletSession: walletSessionRefFromSession({
          walletId: args.identity.walletId,
          walletSessionUserId: args.identity.walletSessionUserId,
        }),
        appSessionJwt: refreshed.appSessionJwt,
      });
    }
    return refreshed;
  }

  async resolveJwt(args: { walletSession: WalletSessionRef; relayUrl: string }): Promise<string> {
    const accountId = String(args.walletSession.walletId || '').trim();
    const cached = accountId ? String(this.byAccount.get(accountId) || '').trim() : '';
    if (cached && isAppSessionJwt(cached) && isSessionJwtUnexpired(cached, { skewMs: 30_000 })) {
      return cached;
    }
    const refreshCandidate =
      cached && isAppSessionJwt(cached) && isSessionJwtUnexpired(cached) ? cached : '';
    if (accountId) this.byAccount.delete(accountId);
    const refreshed = this.deps.refreshAppSessionJwt
      ? await this.deps.refreshAppSessionJwt({ relayUrl: args.relayUrl })
      : await refreshEmailOtpAppSessionJwtRaw({
          relayUrl: args.relayUrl,
          ...(refreshCandidate ? { appSessionJwt: refreshCandidate } : {}),
        });
    if (typeof refreshed !== 'string') {
      throw new Error('Email OTP export session refresh requires fresh Email OTP verification');
    }
    if (accountId && refreshed) {
      this.remember({
        walletSession: walletSessionRefFromSession({
          walletId: accountId,
          walletSessionUserId: args.walletSession.walletSessionUserId,
        }),
        appSessionJwt: refreshed,
      });
    }
    return refreshed;
  }

  private cachedJwtForIdentity(identity: EmailOtpRefreshIdentity): string {
    const accountId = String(identity.walletId || '').trim();
    return accountId ? String(this.byAccount.get(accountId) || '').trim() : '';
  }
}

export function appSessionJwtFromEmailOtpAuthLane(authLane?: EmailOtpAuthLane): string {
  return authLaneAppSessionJwt(authLane);
}

export function appSessionSubjectFromEmailOtpAuthLane(authLane?: EmailOtpAuthLane): string {
  const jwt = appSessionJwtFromEmailOtpAuthLane(authLane);
  if (!jwt) return '';
  const payload = decodeJwtPayloadRecord(jwt);
  const sub = typeof payload?.sub === 'string' ? payload.sub.trim() : '';
  return sub || '';
}

export async function refreshEmailOtpAppSessionJwt(args: {
  identity: EmailOtpRefreshIdentity;
  relayUrl: string;
  appSessionJwt?: string;
}): Promise<EmailOtpSessionRefreshResult> {
  const result = await refreshEmailOtpAppSessionJwtRaw({
    relayUrl: args.relayUrl,
    appSessionJwt: args.appSessionJwt,
    identity: args.identity,
  });
  if (typeof result !== 'string') return result;
  return {
    kind: 'refreshed_email_otp_session',
    identity: args.identity,
    appSessionJwt: result,
  };
}

async function refreshEmailOtpAppSessionJwtRaw(args: {
  relayUrl: string;
  appSessionJwt?: string;
  identity?: EmailOtpRefreshIdentity;
}): Promise<
  string | Extract<EmailOtpSessionRefreshResult, { kind: 'email_otp_refresh_rejected' }>
> {
  const relayUrl = String(args.relayUrl || '').trim();
  if (!relayUrl) {
    throw new Error('Missing relayer url for Email OTP export session refresh');
  }
  const appSessionJwt = String(args.appSessionJwt || '').trim();
  const response = await fetch(joinNormalizedUrl(relayUrl, '/session/refresh'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(appSessionJwt ? { Authorization: `Bearer ${appSessionJwt}` } : {}),
    },
    credentials: 'include',
    body: JSON.stringify({ session_kind: 'jwt' }),
  });
  const json = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok || !json || json.ok === false) {
    if (response.status === 401 || response.status === 403) {
      if (!args.identity) {
        throw new Error('Email OTP export session refresh requires fresh Email OTP verification');
      }
      return {
        kind: 'email_otp_refresh_rejected',
        identity: args.identity,
        reason: 'session_refresh_unauthorized',
        httpStatus: response.status,
      };
    }
    const message =
      (typeof json?.message === 'string' && json.message.trim()) ||
      `Email OTP export session refresh failed (HTTP ${response.status})`;
    throw new Error(message);
  }
  const jwt = typeof json.jwt === 'string' ? json.jwt.trim() : '';
  if (!jwt) {
    throw new Error('Email OTP export session refresh did not return a JWT');
  }
  return jwt;
}

export function emailOtpRefreshIdentity(args: {
  walletId: AccountId;
  walletSessionUserId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  laneIdentity: ExactSigningLaneIdentity;
}): EmailOtpRefreshIdentity {
  const laneWalletId =
    args.laneIdentity.curve === 'ecdsa'
      ? String(args.laneIdentity.walletId)
      : String(args.laneIdentity.accountId);
  if (String(args.walletId) !== laneWalletId) {
    throw new Error('[email-otp] refresh identity wallet does not match exact lane identity');
  }
  const walletSessionUserId = String(args.walletSessionUserId || '').trim();
  if (!walletSessionUserId) {
    throw new Error('[email-otp] refresh identity requires walletSessionUserId');
  }
  return {
    kind: 'email_otp_refresh_identity',
    walletId: args.walletId,
    walletSessionUserId,
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
    laneIdentity: args.laneIdentity,
    laneIdentityKey: exactSigningLaneIdentityKey(args.laneIdentity),
  };
}
