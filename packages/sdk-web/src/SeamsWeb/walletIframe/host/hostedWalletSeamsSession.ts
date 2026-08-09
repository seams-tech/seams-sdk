import {
  parseAppSessionJwt,
  parseWalletId,
  type AppSessionJwt,
  type WalletId,
} from '@shared/utils/domainIds';
import { joinNormalizedUrl, stripTrailingSlashes } from '@shared/utils/normalize';
import {
  decodeJwtPayloadRecord,
  getSessionJwtExpiresAtMs,
  isSessionJwtUnexpired,
} from '@shared/utils/sessionTokens';

export type HostedWalletSeamsSession = {
  readonly kind: 'active_hosted_wallet_seams_session';
  readonly appSessionJwt: AppSessionJwt;
  readonly expiresAtMs: number;
  readonly relayUrl: string;
};

export type WalletOriginAppSession = {
  readonly kind: 'active_wallet_origin_app_session';
  readonly appSessionJwt: AppSessionJwt;
  readonly expiresAtMs: number;
  readonly relayUrl: string;
  readonly walletId: WalletId;
  readonly walletOrigin: string;
};

type ActiveWalletAppSessionSource = HostedWalletSeamsSession | WalletOriginAppSession;

let hostedWalletSeamsSession: ActiveWalletAppSessionSource | null = null;
const WALLET_ORIGIN_APP_SESSION_STORAGE_KEY = 'seams:wallet-origin-app-session:v1';
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
const FIRST_PARTY_WEB_AUDIENCE_FIELDS = new Set(['kind', 'origin']);
const PASSKEY_AUTH_SOURCE_FIELDS = new Set(['kind', 'credentialIdB64u']);
const WALLET_ORIGIN_APP_SESSION_FIELDS = new Set([
  'version',
  'walletId',
  'relayUrl',
  'origin',
  'appSessionJwt',
]);

type StoredWalletOriginAppSession = {
  readonly version: 1;
  readonly walletId: string;
  readonly relayUrl: string;
  readonly origin: string;
  readonly appSessionJwt: string;
};

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

function requiredBoundaryString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return value;
}

export function canonicalRelayUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error('relayUrl must be a non-empty canonical string');
  }
  return stripTrailingSlashes(value);
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
  if (typeof record.relayUrl !== 'string') {
    throw new Error('Hosted-wallet redemption requires relayUrl');
  }
  for (const key of Object.keys(record)) {
    if (!HOSTED_WALLET_REDEMPTION_FIELDS.has(key) && key !== 'relayUrl') {
      throw new Error(`Unsupported hosted-wallet redemption field: ${key}`);
    }
  }
}

function activeSessionIsUnexpired(active: ActiveWalletAppSessionSource): boolean {
  return active.expiresAtMs > Date.now() && isSessionJwtUnexpired(active.appSessionJwt);
}

function walletOriginAppSessionStorage(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
}

function clearPersistedWalletOriginAppSession(): void {
  try {
    walletOriginAppSessionStorage()?.removeItem(WALLET_ORIGIN_APP_SESSION_STORAGE_KEY);
  } catch {
    return;
  }
}

function storedWalletOriginAppSessionRecord(
  source: WalletOriginAppSession,
): StoredWalletOriginAppSession {
  return {
    version: 1,
    walletId: String(source.walletId),
    relayUrl: source.relayUrl,
    origin: source.walletOrigin,
    appSessionJwt: source.appSessionJwt,
  };
}

function persistWalletOriginAppSession(source: WalletOriginAppSession): void {
  const storage = walletOriginAppSessionStorage();
  if (!storage) return;
  try {
    storage.setItem(
      WALLET_ORIGIN_APP_SESSION_STORAGE_KEY,
      JSON.stringify(storedWalletOriginAppSessionRecord(source)),
    );
  } catch {
    return;
  }
}

function walletOriginAppSessionFromBoundary(args: {
  appSessionJwt: unknown;
  relayUrl: unknown;
  walletId: unknown;
  walletOrigin: unknown;
}): WalletOriginAppSession {
  const parsedWalletId = parseWalletId(args.walletId);
  if (!parsedWalletId.ok) throw new Error(parsedWalletId.error.message);
  const parsedJwt = parseAppSessionJwt(args.appSessionJwt);
  if (!parsedJwt.ok) throw new Error(parsedJwt.error.message);
  const relayUrl = canonicalRelayUrl(args.relayUrl);
  const walletOrigin = requiredBoundaryString(args.walletOrigin, 'wallet origin');
  const claims = decodeJwtPayloadRecord(parsedJwt.value);
  if (!claims || claims.kind !== 'app_session_v1') {
    throw new Error('wallet-origin passkey session JWT claims are invalid');
  }
  if (claims.sub !== String(parsedWalletId.value)) {
    throw new Error('wallet-origin passkey session JWT subject does not match the wallet');
  }
  if (claims.walletId !== undefined && claims.walletId !== String(parsedWalletId.value)) {
    throw new Error('wallet-origin passkey session JWT walletId does not match the wallet');
  }
  if (claims.provider !== 'passkey') {
    throw new Error('wallet-origin passkey session JWT provider is invalid');
  }
  const authSource = recordFromBoundary(claims.authSource);
  assertExactFields(authSource, PASSKEY_AUTH_SOURCE_FIELDS, 'passkey auth source');
  if (
    authSource.kind !== 'passkey' ||
    typeof authSource.credentialIdB64u !== 'string' ||
    authSource.credentialIdB64u.length === 0
  ) {
    throw new Error('wallet-origin passkey session JWT auth source is invalid');
  }
  const audience = recordFromBoundary(claims.sessionAudience);
  assertExactFields(audience, FIRST_PARTY_WEB_AUDIENCE_FIELDS, 'first-party session audience');
  if (audience.kind !== 'first_party_web' || audience.origin !== walletOrigin) {
    throw new Error('wallet-origin passkey session JWT audience does not match the wallet origin');
  }
  const expiresAtMs = getSessionJwtExpiresAtMs(parsedJwt.value);
  if (
    expiresAtMs === null ||
    !Number.isSafeInteger(expiresAtMs) ||
    !isSessionJwtUnexpired(parsedJwt.value)
  ) {
    throw new Error('wallet-origin passkey session JWT is expired or missing expiry');
  }
  return {
    kind: 'active_wallet_origin_app_session',
    appSessionJwt: parsedJwt.value,
    expiresAtMs,
    relayUrl,
    walletId: parsedWalletId.value,
    walletOrigin,
  };
}

function readPersistedWalletOriginAppSession(): StoredWalletOriginAppSession | null {
  const storage = walletOriginAppSessionStorage();
  if (!storage) return null;
  let raw: string | null;
  try {
    raw = storage.getItem(WALLET_ORIGIN_APP_SESSION_STORAGE_KEY);
  } catch {
    clearPersistedWalletOriginAppSession();
    return null;
  }
  if (!raw) return null;
  try {
    const record = recordFromBoundary(JSON.parse(raw));
    assertExactFields(record, WALLET_ORIGIN_APP_SESSION_FIELDS, 'wallet-origin app session');
    if (record.version !== 1) throw new Error('Unsupported wallet-origin app session version');
    const walletId = requiredString(record, 'walletId');
    const relayUrl = requiredString(record, 'relayUrl');
    if (canonicalRelayUrl(relayUrl) !== relayUrl) {
      throw new Error('wallet-origin app session relayUrl is not normalized');
    }
    const origin = requiredString(record, 'origin');
    const appSessionJwt = requiredString(record, 'appSessionJwt');
    return { version: 1, walletId, relayUrl, origin, appSessionJwt };
  } catch {
    clearPersistedWalletOriginAppSession();
    return null;
  }
}

function restorePersistedWalletOriginAppSession(
  expectedRelayUrl: string | undefined,
  expectedWalletId: string | undefined,
): AppSessionJwt | undefined {
  const stored = readPersistedWalletOriginAppSession();
  if (!stored) return undefined;
  const expectedOrigin = typeof window === 'undefined' ? undefined : window.location.origin;
  if (
    expectedOrigin === undefined ||
    stored.origin !== expectedOrigin ||
    expectedRelayUrl === undefined
  ) {
    clearPersistedWalletOriginAppSession();
    return undefined;
  }
  if (stored.relayUrl !== canonicalRelayUrl(expectedRelayUrl)) {
    clearPersistedWalletOriginAppSession();
    return undefined;
  }
  if (expectedWalletId !== undefined) {
    const expectedWallet = parseWalletId(expectedWalletId);
    if (!expectedWallet.ok || stored.walletId !== String(expectedWallet.value)) {
      clearPersistedWalletOriginAppSession();
      return undefined;
    }
  }
  try {
    const restored = walletOriginAppSessionFromBoundary({
      appSessionJwt: stored.appSessionJwt,
      relayUrl: stored.relayUrl,
      walletId: stored.walletId,
      walletOrigin: stored.origin,
    });
    hostedWalletSeamsSession = restored;
    return restored.appSessionJwt;
  } catch {
    clearPersistedWalletOriginAppSession();
    return undefined;
  }
}

export function activeHostedWalletAppSessionJwt(expectedRelayUrl?: string): AppSessionJwt | undefined {
  const active = hostedWalletSeamsSession;
  if (!active || active.kind !== 'active_hosted_wallet_seams_session') return undefined;
  if (
    !activeSessionIsUnexpired(active) ||
    (expectedRelayUrl !== undefined && active.relayUrl !== canonicalRelayUrl(expectedRelayUrl))
  ) {
    hostedWalletSeamsSession = null;
    return undefined;
  }
  return active.appSessionJwt;
}

export function activeWalletOriginAppSessionJwt(
  expectedRelayUrl?: string,
  expectedWalletId?: string,
): AppSessionJwt | undefined {
  const active = hostedWalletSeamsSession;
  if (!active) return restorePersistedWalletOriginAppSession(expectedRelayUrl, expectedWalletId);
  if (active.kind !== 'active_wallet_origin_app_session') return undefined;
  const expectedOrigin = typeof window === 'undefined' ? undefined : window.location.origin;
  const expectedWallet = expectedWalletId === undefined ? undefined : parseWalletId(expectedWalletId);
  if (
    !activeSessionIsUnexpired(active) ||
    (expectedRelayUrl !== undefined && active.relayUrl !== canonicalRelayUrl(expectedRelayUrl)) ||
    expectedOrigin === undefined ||
    active.walletOrigin !== expectedOrigin ||
    (expectedWallet !== undefined &&
      (!expectedWallet.ok || active.walletId !== expectedWallet.value))
  ) {
    hostedWalletSeamsSession = null;
    clearPersistedWalletOriginAppSession();
    return undefined;
  }
  return active.appSessionJwt;
}

export function activeWalletOrHostedAppSessionJwt(
  expectedRelayUrl?: string,
  expectedWalletId?: string,
): AppSessionJwt | undefined {
  return (
    activeWalletOriginAppSessionJwt(expectedRelayUrl, expectedWalletId) ??
    activeHostedWalletAppSessionJwt(expectedRelayUrl)
  );
}

export function clearWalletOriginAppSession(): void {
  clearPersistedWalletOriginAppSession();
  if (hostedWalletSeamsSession?.kind === 'active_wallet_origin_app_session') {
    hostedWalletSeamsSession = null;
  }
}

export function rememberWalletOriginAppSession(args: {
  appSessionJwt: unknown;
  relayUrl: unknown;
  walletId: unknown;
}): AppSessionJwt {
  const walletOrigin = requiredBoundaryString(
    typeof window === 'undefined' ? undefined : window.location.origin,
    'wallet origin',
  );
  const active = walletOriginAppSessionFromBoundary({
    appSessionJwt: args.appSessionJwt,
    relayUrl: args.relayUrl,
    walletId: args.walletId,
    walletOrigin,
  });
  hostedWalletSeamsSession = active;
  persistWalletOriginAppSession(active);
  return active.appSessionJwt;
}

function parseHostedWalletRedemption(
  value: unknown,
): Omit<HostedWalletSeamsSession, 'relayUrl'> {
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
  const requestedRelayUrl = canonicalRelayUrl(relayUrl);
  if (canonicalRelayUrl(payload.relayUrl) !== requestedRelayUrl) {
    throw new Error('Hosted-wallet redemption relayUrl does not match its request boundary');
  }
  const response = await fetch(joinNormalizedUrl(requestedRelayUrl, '/session/exchange'), {
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
  clearPersistedWalletOriginAppSession();
  const redeemedSession: HostedWalletSeamsSession = {
    ...session,
    relayUrl: requestedRelayUrl,
  };
  hostedWalletSeamsSession = redeemedSession;
  return redeemedSession;
}
