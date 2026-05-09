import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthLane } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { authLaneAppSessionJwt } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  decodeJwtPayloadRecord,
  isAppSessionJwt,
  isSessionJwtUnexpired,
} from '@shared/utils/sessionTokens';
import { joinNormalizedUrl } from '@shared/utils/normalize';

export class EmailOtpAppSessionJwtCache {
  private readonly byAccount = new Map<string, string>();

  constructor(
    private readonly deps: {
      refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
    } = {},
  ) {}

  remember(args: { nearAccountId: AccountId | string; appSessionJwt?: string }): void {
    const jwt = String(args.appSessionJwt || '').trim();
    if (!jwt || !isAppSessionJwt(jwt)) return;
    const accountId = String(args.nearAccountId || '').trim();
    if (!accountId) return;
    this.byAccount.set(accountId, jwt);
  }

  async resolve(args: {
    nearAccountId: AccountId | string;
    relayUrl: string;
  }): Promise<string> {
    const accountId = String(args.nearAccountId || '').trim();
    const cached = accountId ? String(this.byAccount.get(accountId) || '').trim() : '';
    if (cached && isAppSessionJwt(cached) && isSessionJwtUnexpired(cached, { skewMs: 30_000 })) {
      return cached;
    }
    const refreshCandidate =
      cached && isAppSessionJwt(cached) && isSessionJwtUnexpired(cached) ? cached : '';
    if (accountId) this.byAccount.delete(accountId);
    const refreshed = this.deps.refreshAppSessionJwt
      ? await this.deps.refreshAppSessionJwt({ relayUrl: args.relayUrl })
      : await refreshEmailOtpAppSessionJwt({
          relayUrl: args.relayUrl,
          ...(refreshCandidate ? { appSessionJwt: refreshCandidate } : {}),
        });
    if (accountId && refreshed) {
      this.remember({ nearAccountId: accountId, appSessionJwt: refreshed });
    }
    return refreshed;
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
  relayUrl: string;
  appSessionJwt?: string;
}): Promise<string> {
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
