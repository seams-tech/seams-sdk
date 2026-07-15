import type { WalletId, WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpAuthLane } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { authLaneAppSessionJwt } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  exactSigningLaneWalletId,
  exactSigningLaneIdentityKey,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
  type ExactSigningLaneIdentity,
  type ExactSigningLaneIdentityKey,
} from '../identity/exactSigningLaneIdentity';
import type { SigningOperationFingerprint, SigningOperationId } from '../operationState/types';
import {
  decodeJwtPayloadRecord,
  isAppSessionJwt,
  isSessionJwtUnexpired,
  requireAppSessionJwt,
} from '@shared/utils/sessionTokens';
import {
  parseAppSessionJwt,
  parseProviderSubject,
  type AppSessionJwt,
  type ProviderSubject,
} from '@shared/utils/domainIds';
import { joinNormalizedUrl } from '@shared/utils/normalize';

type EmailOtpSigningLaneAuth = Extract<
  ExactSigningLaneIdentity['auth'],
  { kind: 'email_otp' }
>;

type ExactEmailOtpSigningLaneIdentity =
  | (Omit<ExactEd25519SigningLaneIdentity, 'auth'> & { auth: EmailOtpSigningLaneAuth })
  | (Omit<ExactEcdsaSigningLaneIdentity, 'auth'> & { auth: EmailOtpSigningLaneAuth });

function isExactEmailOtpSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): identity is ExactEmailOtpSigningLaneIdentity {
  return identity.auth.kind === 'email_otp';
}

export type EmailOtpAppSessionBinding = Readonly<{
  kind: 'email_otp_app_session_binding';
  walletId: WalletId;
  providerSubject: ProviderSubject;
  appSessionJwt: AppSessionJwt;
}>;

export type EmailOtpRefreshIdentity = {
  kind: 'email_otp_refresh_identity';
  walletId: WalletId;
  walletSessionUserId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  laneIdentity: ExactEmailOtpSigningLaneIdentity;
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
  private readonly byWallet = new Map<string, Map<string, EmailOtpAppSessionBinding>>();

  constructor(
    private readonly deps: {
      refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
    } = {},
  ) {}

  remember(binding: EmailOtpAppSessionBinding): void {
    const walletId = String(binding.walletId);
    const providerSubject = String(binding.providerSubject);
    const entries = this.byWallet.get(walletId) ?? new Map<string, EmailOtpAppSessionBinding>();
    entries.set(providerSubject, binding);
    this.byWallet.set(walletId, entries);
  }

  async resolve(args: {
    identity: EmailOtpRefreshIdentity;
    relayUrl: string;
  }): Promise<EmailOtpSessionRefreshResult> {
    const cached = this.cachedBindingForIdentity(args.identity);
    if (cached && isSessionJwtUnexpired(cached.appSessionJwt, { skewMs: 30_000 })) {
      return {
        kind: 'cached_email_otp_session',
        identity: args.identity,
        appSessionJwt: cached.appSessionJwt,
      };
    }
    const refreshCandidate =
      cached &&
      isAppSessionJwt(cached.appSessionJwt) &&
      isSessionJwtUnexpired(cached.appSessionJwt)
        ? cached.appSessionJwt
        : '';
    this.deleteBindingForIdentity(args.identity);
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
      const binding = emailOtpAppSessionBindingFromJwt({
        walletId: args.identity.walletId,
        appSessionJwt: refreshed.appSessionJwt,
      });
      if (binding.providerSubject !== args.identity.laneIdentity.auth.providerSubjectId) {
        throw new Error('Refreshed Email OTP app session belongs to a different provider subject');
      }
      this.remember(binding);
    }
    return refreshed;
  }

  async resolveJwt(args: { walletSession: WalletSessionRef; relayUrl: string }): Promise<string> {
    const walletId = String(args.walletSession.walletId || '').trim();
    const cached = walletId ? this.uniqueBindingForWallet(walletId) : null;
    if (
      cached &&
      isAppSessionJwt(cached.appSessionJwt) &&
      isSessionJwtUnexpired(cached.appSessionJwt, { skewMs: 30_000 })
    ) {
      return cached.appSessionJwt;
    }
    const refreshCandidate =
      cached &&
      isAppSessionJwt(cached.appSessionJwt) &&
      isSessionJwtUnexpired(cached.appSessionJwt)
        ? cached.appSessionJwt
        : '';
    if (walletId) this.byWallet.delete(walletId);
    const refreshed = this.deps.refreshAppSessionJwt
      ? await this.deps.refreshAppSessionJwt({ relayUrl: args.relayUrl })
      : await refreshEmailOtpAppSessionJwtRaw({
          relayUrl: args.relayUrl,
          ...(refreshCandidate ? { appSessionJwt: refreshCandidate } : {}),
        });
    if (typeof refreshed !== 'string') {
      throw new Error('Email OTP export session refresh requires fresh Email OTP verification');
    }
    if (walletId && refreshed) {
      this.remember(
        emailOtpAppSessionBindingFromJwt({
          walletId: args.walletSession.walletId,
          appSessionJwt: refreshed,
        }),
      );
    }
    return refreshed;
  }

  private cachedBindingForIdentity(
    identity: EmailOtpRefreshIdentity,
  ): EmailOtpAppSessionBinding | null {
    const entries = this.byWallet.get(String(identity.walletId));
    return entries?.get(identity.laneIdentity.auth.providerSubjectId) ?? null;
  }

  private deleteBindingForIdentity(identity: EmailOtpRefreshIdentity): void {
    const walletId = String(identity.walletId);
    const entries = this.byWallet.get(walletId);
    if (!entries) return;
    entries.delete(identity.laneIdentity.auth.providerSubjectId);
    if (entries.size === 0) this.byWallet.delete(walletId);
  }

  private uniqueBindingForWallet(walletId: string): EmailOtpAppSessionBinding | null {
    const entries = this.byWallet.get(walletId);
    if (!entries || entries.size === 0) return null;
    if (entries.size !== 1) {
      throw new Error('Email OTP app-session resolution requires one exact provider subject');
    }
    return entries.values().next().value ?? null;
  }
}

export function emailOtpAppSessionBindingFromJwt(args: {
  walletId: WalletId;
  appSessionJwt: string;
}): EmailOtpAppSessionBinding {
  const jwt = requireAppSessionJwt(args.appSessionJwt, 'Email OTP appSessionJwt');
  const parsedJwt = parseAppSessionJwt(jwt);
  if (!parsedJwt.ok) throw new Error(parsedJwt.error.message);
  const payload = decodeJwtPayloadRecord(jwt);
  const parsedSubject = parseProviderSubject(payload?.sub);
  if (!parsedSubject.ok) {
    throw new Error(`Email OTP app-session subject is invalid: ${parsedSubject.error.message}`);
  }
  return {
    kind: 'email_otp_app_session_binding',
    walletId: args.walletId,
    providerSubject: parsedSubject.value,
    appSessionJwt: parsedJwt.value,
  };
}

export function appSessionJwtFromEmailOtpAuthLane(authLane: EmailOtpAuthLane): string {
  return authLaneAppSessionJwt(authLane);
}

export function appSessionSubjectFromEmailOtpAuthLane(authLane: EmailOtpAuthLane): string {
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
  walletId: WalletId;
  walletSessionUserId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  laneIdentity: ExactSigningLaneIdentity;
}): EmailOtpRefreshIdentity {
  const laneWalletId = String(exactSigningLaneWalletId(args.laneIdentity));
  if (String(args.walletId) !== laneWalletId) {
    throw new Error('[email-otp] refresh identity wallet does not match exact lane identity');
  }
  const walletSessionUserId = String(args.walletSessionUserId || '').trim();
  if (!walletSessionUserId) {
    throw new Error('[email-otp] refresh identity requires walletSessionUserId');
  }
  if (!isExactEmailOtpSigningLaneIdentity(args.laneIdentity)) {
    throw new Error('[email-otp] refresh identity requires an Email OTP exact lane');
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
