import { parseAppSessionJwt, type AppSessionJwt } from '@shared/utils/domainIds';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { decodeJwtPayloadRecord, isSessionJwtUnexpired } from '@shared/utils/sessionTokens';

export type HostedWalletSeamsSession = {
  readonly kind: 'active_hosted_wallet_seams_session';
  readonly appSessionJwt: AppSessionJwt;
  readonly expiresAtMs: number;
};

let hostedWalletSeamsSession: HostedWalletSeamsSession | null = null;
const HOSTED_WALLET_REDEMPTION_FIELDS = new Set(['exchangeCode', 'nonce']);
const HOSTED_WALLET_REDEMPTION_RESPONSE_FIELDS = new Set(['ok', 'session', 'jwt']);
const HOSTED_WALLET_SESSION_FIELDS = new Set([
  'kind',
  'userId',
  'tenantId',
  'seamsSessionId',
  'deviceId',
  'audience',
  'expiresAtMs',
]);
const HOSTED_WALLET_AUDIENCE_FIELDS = new Set(['kind', 'appOrigin', 'walletOrigin']);

function recordFromBoundary(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function requiredString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${field} must be a non-empty canonical string`);
  }
  return value;
}

function assertExactFields(
  record: Record<string, unknown>,
  fields: ReadonlySet<string>,
  label: string,
): void {
  for (const key of Object.keys(record)) {
    if (!fields.has(key)) throw new Error(`Unsupported ${label} field: ${key}`);
  }
  for (const field of fields) {
    if (!Object.hasOwn(record, field)) throw new Error(`Missing ${label} field: ${field}`);
  }
}

function compactExchangeValue(record: Record<string, unknown>, field: string): string {
  const value = requiredString(record, field);
  // eslint-disable-next-line no-control-regex
  if (value.length > 512 || /[\s\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${field} must be a compact opaque identifier`);
  }
  return value;
}

function assertHostedWalletRedemptionPayload(record: Record<string, unknown>): void {
  for (const key of Object.keys(record)) {
    if (!HOSTED_WALLET_REDEMPTION_FIELDS.has(key)) {
      throw new Error(`Unsupported hosted-wallet redemption field: ${key}`);
    }
  }
}

export function activeHostedWalletAppSessionJwt(): AppSessionJwt | undefined {
  const active = hostedWalletSeamsSession;
  if (
    !active ||
    active.expiresAtMs <= Date.now() ||
    !isSessionJwtUnexpired(active.appSessionJwt)
  ) {
    hostedWalletSeamsSession = null;
    return undefined;
  }
  return active.appSessionJwt;
}

function parseHostedWalletRedemption(value: unknown): HostedWalletSeamsSession {
  const response = recordFromBoundary(value);
  if (response.ok !== true) {
    const code = requiredString(response, 'code');
    const message = requiredString(response, 'message');
    const error = new Error(message) as Error & { code: string };
    error.code = code;
    throw error;
  }
  assertExactFields(
    response,
    HOSTED_WALLET_REDEMPTION_RESPONSE_FIELDS,
    'hosted-wallet redemption response',
  );
  const session = recordFromBoundary(response.session);
  assertExactFields(session, HOSTED_WALLET_SESSION_FIELDS, 'hosted-wallet session');
  if (session.kind !== 'app_session_v1') {
    throw new Error('hosted-wallet redemption returned the wrong session kind');
  }
  const audience = recordFromBoundary(session.audience);
  assertExactFields(audience, HOSTED_WALLET_AUDIENCE_FIELDS, 'hosted-wallet session audience');
  if (
    audience.kind !== 'hosted_wallet_iframe' ||
    requiredString(audience, 'walletOrigin') !== window.location.origin
  ) {
    throw new Error('hosted-wallet redemption returned the wrong wallet audience');
  }
  requiredString(audience, 'appOrigin');
  const parsedJwt = parseAppSessionJwt(response.jwt);
  if (!parsedJwt.ok || !isSessionJwtUnexpired(parsedJwt.value)) {
    throw new Error('hosted-wallet redemption returned an invalid app session JWT');
  }
  const claims = decodeJwtPayloadRecord(parsedJwt.value);
  const tenantId = requiredString(session, 'tenantId');
  const userId = requiredString(session, 'userId');
  const seamsSessionId = requiredString(session, 'seamsSessionId');
  const deviceId = requiredString(session, 'deviceId');
  if (
    !claims ||
    claims.kind !== 'app_session_v1' ||
    claims.tenantId !== tenantId ||
    claims.sub !== userId ||
    claims.seamsSessionId !== seamsSessionId ||
    claims.deviceId !== deviceId
  ) {
    throw new Error('hosted-wallet session JWT does not match its session projection');
  }
  const claimsAudience = recordFromBoundary(claims.sessionAudience);
  assertExactFields(
    claimsAudience,
    HOSTED_WALLET_AUDIENCE_FIELDS,
    'hosted-wallet session JWT audience',
  );
  if (
    claimsAudience.kind !== audience.kind ||
    claimsAudience.appOrigin !== audience.appOrigin ||
    claimsAudience.walletOrigin !== audience.walletOrigin
  ) {
    throw new Error('hosted-wallet session JWT does not match its session projection');
  }
  const expiresAtMs = Number(session.expiresAtMs);
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('hosted-wallet session projection is expired');
  }
  return {
    kind: 'active_hosted_wallet_seams_session',
    appSessionJwt: parsedJwt.value,
    expiresAtMs,
  };
}

async function readSessionExchangeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function redeemHostedWalletSeamsSession(
  value: unknown,
  relayUrl: string,
): Promise<HostedWalletSeamsSession> {
  const payload = recordFromBoundary(value);
  assertHostedWalletRedemptionPayload(payload);
  const response = await fetch(joinNormalizedUrl(relayUrl, '/session/exchange'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sessionKind: 'jwt',
      exchange: {
        type: 'hosted_wallet_exchange_code_redeem',
        exchange_code: compactExchangeValue(payload, 'exchangeCode'),
        nonce: compactExchangeValue(payload, 'nonce'),
      },
    }),
  });
  const raw = await readSessionExchangeJson(response);
  if (!response.ok) {
    const failure = recordFromBoundary(raw);
    const code = requiredString(failure, 'code');
    const message = requiredString(failure, 'message');
    const error = new Error(message) as Error & { code: string; status: number };
    error.code = code;
    error.status = response.status;
    throw error;
  }
  const session = parseHostedWalletRedemption(raw);
  hostedWalletSeamsSession = session;
  return session;
}
