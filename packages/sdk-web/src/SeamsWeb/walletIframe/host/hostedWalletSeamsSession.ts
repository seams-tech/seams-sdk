import { joinNormalizedUrl, stripTrailingSlashes } from '@shared/utils/normalize';
import {
  requireOpaqueWalletSessionToken,
  type OpaqueWalletSessionToken,
} from '@shared/utils/sessionTokens';

export type HostedWalletSessionCurve = 'ecdsa' | 'ed25519';

/** Normalize curve labels crossing the browser signing API boundary. */
export function hostedWalletSessionCurveFromBoundary(value: unknown): HostedWalletSessionCurve {
  if (value === 'ecdsa' || value === 'ecdsa_secp256k1') return 'ecdsa';
  if (value === 'ed25519') return 'ed25519';
  throw new Error('hosted-wallet exchange curve is invalid');
}

export type HostedWalletSeamsSession = {
  readonly kind: 'active_hosted_wallet_seams_session';
  readonly walletSessionToken: OpaqueWalletSessionToken;
  readonly curve: HostedWalletSessionCurve;
  readonly expiresAtMs: number;
  readonly relayUrl: string;
};

const activeHostedWalletSessions = new Map<HostedWalletSessionCurve, HostedWalletSeamsSession>();

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

function canonicalOrigin(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  const origin = value;
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error(`${label} must be an absolute origin`);
  }
  if (parsed.origin !== origin || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error(`${label} must be a canonical origin`);
  }
  return parsed.origin;
}

export function canonicalRelayUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error('relayUrl must be a non-empty canonical string');
  }
  return stripTrailingSlashes(value);
}

function parseCurve(value: unknown): HostedWalletSessionCurve {
  if (value === 'ecdsa' || value === 'ed25519') return value;
  throw new Error('hosted-wallet exchange curve is invalid');
}

function parseExpiry(value: unknown): number {
  const expiresAtMs = Number(value);
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('hosted-wallet Wallet Session is expired or invalid');
  }
  return expiresAtMs;
}

function parseExchangeFailure(value: unknown, status: number): Error {
  const record = recordFromBoundary(value);
  const code = requiredString(record, 'code');
  const message = requiredString(record, 'message');
  const error = new Error(message) as Error & { code: string; status: number };
  error.code = code;
  error.status = status;
  return error;
}

function parseRedeemedWalletSession(value: unknown): Omit<HostedWalletSeamsSession, 'relayUrl'> {
  const response = recordFromBoundary(value);
  if (response.ok !== true) throw parseExchangeFailure(response, 400);
  assertExactFields(
    response,
    new Set(['ok', 'walletSessionId', 'walletSessionToken', 'curve', 'expiresAtMs']),
    'hosted-wallet session redemption response',
  );
  requiredString(response, 'walletSessionId');
  return {
    kind: 'active_hosted_wallet_seams_session',
    walletSessionToken: requireOpaqueWalletSessionToken(response.walletSessionToken),
    curve: parseCurve(response.curve),
    expiresAtMs: parseExpiry(response.expiresAtMs),
  };
}

function readJson(value: Response): Promise<unknown> {
  return value.json().catch(() => null);
}

export function activeWalletSessionToken(
  curve: HostedWalletSessionCurve,
  expectedRelayUrl?: string,
): OpaqueWalletSessionToken | undefined {
  const active = activeHostedWalletSessions.get(curve);
  if (!active) return undefined;
  if (
    active.expiresAtMs <= Date.now() ||
    (expectedRelayUrl !== undefined && active.relayUrl !== canonicalRelayUrl(expectedRelayUrl))
  ) {
    activeHostedWalletSessions.delete(curve);
    return undefined;
  }
  return active.walletSessionToken;
}

export function clearHostedWalletSessions(): void {
  activeHostedWalletSessions.clear();
}

export async function redeemHostedWalletSeamsSession(
  value: unknown,
  relayUrl: string,
): Promise<HostedWalletSeamsSession> {
  const payload = recordFromBoundary(value);
  assertExactFields(
    payload,
    new Set(['exchangeCode', 'nonce', 'curve', 'appOrigin', 'walletOrigin', 'relayUrl']),
    'hosted-wallet redemption request',
  );
  const requestedRelayUrl = canonicalRelayUrl(relayUrl);
  if (canonicalRelayUrl(payload.relayUrl) !== requestedRelayUrl) {
    throw new Error('Hosted-wallet redemption relayUrl does not match its request boundary');
  }
  const appOrigin = canonicalOrigin(payload.appOrigin, 'appOrigin');
  const walletOrigin = canonicalOrigin(payload.walletOrigin, 'walletOrigin');
  if (walletOrigin !== window.location.origin) {
    throw new Error('Hosted-wallet redemption walletOrigin does not match the wallet host');
  }
  const curve = parseCurve(payload.curve);
  const response = await fetch(
    joinNormalizedUrl(requestedRelayUrl, '/wallet/session/exchange/redeem'),
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        exchangeCode: compactExchangeValue(payload, 'exchangeCode'),
        nonce: compactExchangeValue(payload, 'nonce'),
        curve,
        appOrigin,
        walletOrigin,
      }),
    },
  );
  const raw = await readJson(response);
  if (!response.ok) throw parseExchangeFailure(raw, response.status);
  const redeemed = parseRedeemedWalletSession(raw);
  const session: HostedWalletSeamsSession = { ...redeemed, relayUrl: requestedRelayUrl };
  activeHostedWalletSessions.set(curve, session);
  return session;
}
