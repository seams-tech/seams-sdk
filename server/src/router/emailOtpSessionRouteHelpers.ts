import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalRecordString, toOptionalTrimmedString } from '@shared/utils/validation';

export type OidcAccountMode = 'register' | 'login';

export function emailOtpStatusCode(code: string | undefined): number {
  if (code === 'internal') return 500;
  if (code === 'not_configured') return 503;
  if (code === 'not_found') return 404;
  if (code === 'rate_limited') return 429;
  if (code === 'stronger_auth_required') return 403;
  return 400;
}

export function getSessionWalletId(claims: unknown, userId: string): string {
  return toOptionalRecordString(claims, 'walletId') || toOptionalTrimmedString(userId) || '';
}

export function isGoogleOidcEmailOtpSession(claims: unknown): boolean {
  const provider = toOptionalRecordString(claims, 'provider')?.toLowerCase() || '';
  const oidcProvider = toOptionalRecordString(claims, 'oidcProvider')?.toLowerCase() || '';
  const providerSubject = toOptionalRecordString(claims, 'providerSubject')?.toLowerCase() || '';
  return (
    provider === 'oidc' && (oidcProvider === 'google' || providerSubject.startsWith('google:'))
  );
}

export function parseOidcAccountMode(raw: unknown): OidcAccountMode | undefined {
  const value = toOptionalTrimmedString(raw)?.toLowerCase() || '';
  if (value === 'register' || value === 'login') return value;
  return undefined;
}

export function stableEmailOtpSessionBindingClaims(
  claims: Record<string, unknown>,
): Record<string, unknown> {
  const stable: Record<string, unknown> = {};
  for (const key of [
    'kind',
    'sub',
    'appSessionVersion',
    'walletId',
    'orgId',
    'projectId',
    'environmentId',
    'provider',
    'oidcProvider',
    'providerSubject',
    'runtimePolicyScope',
  ]) {
    const value = claims[key];
    if (value !== undefined && value !== null && value !== '') {
      stable[key] = value;
    }
  }
  return stable;
}

export async function hashEmailOtpAppSessionClaims(
  claims: Record<string, unknown>,
): Promise<string> {
  const json = alphabetizeStringify(stableEmailOtpSessionBindingClaims(claims));
  return base64UrlEncode(await sha256BytesUtf8(json));
}

export function emailOtpChallengeResponseBody(result: {
  ok: boolean;
  challenge?: {
    challengeId: string;
    issuedAtMs: number;
    expiresAtMs: number;
    userId: string;
    walletId: string;
    orgId?: string;
    sessionHash: string;
    appSessionVersion: string;
    otpChannel: string;
    action: string;
    operation: string;
  };
  delivery?: unknown;
}): Record<string, unknown> {
  if (!result.ok || !result.challenge) return result as unknown as Record<string, unknown>;
  const challenge = result.challenge;
  return {
    ok: true,
    challenge: {
      challengeId: challenge.challengeId,
      issuedAt: new Date(challenge.issuedAtMs).toISOString(),
      expiresAt: new Date(challenge.expiresAtMs).toISOString(),
      userId: challenge.userId,
      walletId: challenge.walletId,
      ...(challenge.orgId ? { orgId: challenge.orgId } : {}),
      sessionHash: challenge.sessionHash,
      appSessionVersion: challenge.appSessionVersion,
      otpChannel: challenge.otpChannel,
      action: challenge.action,
      operation: challenge.operation,
    },
    delivery: result.delivery,
  };
}
