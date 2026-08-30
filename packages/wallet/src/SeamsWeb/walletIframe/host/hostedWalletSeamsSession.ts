import { joinNormalizedUrl, stripTrailingSlashes } from '@shared/utils/normalize';
import {
  parseWalletSessionId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parsePMRedeemHostedWalletSeamsSessionPayload,
  type PMRedeemHostedWalletSeamsSessionPayload,
} from '../shared/messages';

declare const hostedWalletSessionOperationCredentialTokenBrand: unique symbol;

export type HostedWalletSessionOperationCredentialToken = string & {
  readonly [hostedWalletSessionOperationCredentialTokenBrand]: true;
};

export type HostedWalletSessionOperationCredentialV1 = {
  readonly kind: 'opaque_hosted_wallet_session_operation_credential_v1';
  readonly token: HostedWalletSessionOperationCredentialToken;
  readonly walletSessionId: WalletSessionId;
};

export type HostedWalletSeamsSession = {
  readonly kind: 'active_hosted_wallet_seams_session';
  readonly walletSessionId: WalletSessionId;
  readonly operationCredential: HostedWalletSessionOperationCredentialV1;
  readonly expiresAtMs: number;
  readonly relayUrl: string;
  readonly appOrigin: string;
  readonly walletOrigin: string;
};

let activeHostedWalletSession: HostedWalletSeamsSession | null = null;
let adoptedParentOrigin: string | null = null;

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
  if (Object.keys(record).length !== fields.size) {
    throw new Error(`${label} fields are invalid`);
  }
  for (const field of fields) {
    if (!Object.hasOwn(record, field)) throw new Error(`Missing ${label} field: ${field}`);
  }
}

function canonicalOrigin(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} must be a canonical HTTP origin`);
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a canonical HTTP origin`);
  }
  if (
    (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') ||
    parsed.origin !== value ||
    parsed.pathname !== '/' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(`${label} must be a canonical HTTP origin`);
  }
  return parsed.origin;
}

export function canonicalRelayUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error('relayUrl must be a non-empty canonical string');
  }
  return stripTrailingSlashes(value);
}

function parseExpiry(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) <= Date.now()) {
    throw new Error('hosted-wallet Wallet Session is expired or invalid');
  }
  return Number(value);
}

function parseExchangeFailure(value: unknown, status: number): Error {
  const record = recordFromBoundary(value);
  assertExactFields(record, new Set(['ok', 'code', 'message']), 'hosted-wallet exchange failure');
  if (record.ok !== false) throw new Error('hosted-wallet exchange failure is invalid');
  const code = requiredString(record, 'code');
  const message = requiredString(record, 'message');
  const error = new Error(message) as Error & { code: string; status: number };
  error.code = code;
  error.status = status;
  return error;
}

function parseHostedOperationCredentialToken(
  value: unknown,
): HostedWalletSessionOperationCredentialToken {
  if (typeof value !== 'string' || !/^wsh_[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error('hosted-wallet operationCredential.token is invalid');
  }
  return value as HostedWalletSessionOperationCredentialToken;
}

function requireWalletSessionId(value: unknown): WalletSessionId {
  const parsed = parseWalletSessionId(value);
  if (!parsed.ok) throw new Error(`walletSessionId is invalid: ${parsed.error.message}`);
  return parsed.value;
}

function parseHostedOperationCredential(
  value: unknown,
): HostedWalletSessionOperationCredentialV1 {
  const record = recordFromBoundary(value);
  assertExactFields(
    record,
    new Set(['kind', 'token', 'walletSessionId']),
    'hosted-wallet operationCredential',
  );
  if (record.kind !== 'opaque_hosted_wallet_session_operation_credential_v1') {
    throw new Error('hosted-wallet operationCredential.kind is invalid');
  }
  return {
    kind: record.kind,
    token: parseHostedOperationCredentialToken(record.token),
    walletSessionId: requireWalletSessionId(record.walletSessionId),
  };
}

function parseRedeemedWalletSession(value: unknown): {
  readonly walletSessionId: WalletSessionId;
  readonly operationCredential: HostedWalletSessionOperationCredentialV1;
  readonly expiresAtMs: number;
} {
  const response = recordFromBoundary(value);
  if (response.ok !== true) throw parseExchangeFailure(response, 400);
  assertExactFields(
    response,
    new Set(['ok', 'walletSessionId', 'operationCredential', 'expiresAtMs']),
    'hosted-wallet session redemption response',
  );
  const walletSessionId = requireWalletSessionId(response.walletSessionId);
  const operationCredential = parseHostedOperationCredential(response.operationCredential);
  if (operationCredential.walletSessionId !== walletSessionId) {
    throw new Error('hosted-wallet operationCredential does not identify its parent Wallet Session');
  }
  return {
    walletSessionId,
    operationCredential,
    expiresAtMs: parseExpiry(response.expiresAtMs),
  };
}

async function readJson(value: Response): Promise<unknown> {
  try {
    return await value.json();
  } catch {
    return null;
  }
}

export function recordAdoptedWalletIframeParentOrigin(value: unknown): void {
  adoptedParentOrigin = canonicalOrigin(value, 'adopted parent origin');
}

export function activeHostedWalletSessionOperationCredential(
  expectedRelayUrl?: string,
): HostedWalletSessionOperationCredentialV1 | undefined {
  const active = activeHostedWalletSession;
  if (!active) return undefined;
  if (
    active.expiresAtMs <= Date.now() ||
    active.appOrigin !== adoptedParentOrigin ||
    active.walletOrigin !== window.location.origin ||
    (expectedRelayUrl !== undefined && active.relayUrl !== canonicalRelayUrl(expectedRelayUrl))
  ) {
    activeHostedWalletSession = null;
    return undefined;
  }
  return active.operationCredential;
}

export function clearHostedWalletSessions(): void {
  activeHostedWalletSession = null;
  adoptedParentOrigin = null;
}

function redemptionBody(payload: PMRedeemHostedWalletSeamsSessionPayload): string {
  return JSON.stringify({
    exchangeCode: payload.exchangeCode,
    nonce: payload.nonce,
    appOrigin: payload.appOrigin,
    walletOrigin: payload.walletOrigin,
  });
}

export async function redeemHostedWalletSeamsSession(
  value: unknown,
  relayUrl: string,
): Promise<HostedWalletSeamsSession> {
  const payload = parsePMRedeemHostedWalletSeamsSessionPayload(value);
  const requestedRelayUrl = canonicalRelayUrl(relayUrl);
  if (canonicalRelayUrl(payload.relayUrl) !== requestedRelayUrl) {
    throw new Error('Hosted-wallet redemption relayUrl does not match its request boundary');
  }
  if (payload.walletOrigin !== window.location.origin) {
    throw new Error('Hosted-wallet redemption walletOrigin does not match the wallet host');
  }
  if (adoptedParentOrigin === null || payload.appOrigin !== adoptedParentOrigin) {
    throw new Error('Hosted-wallet redemption appOrigin does not match the adopted iframe parent');
  }
  const response = await fetch(
    joinNormalizedUrl(requestedRelayUrl, '/wallet/session/exchange/redeem'),
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: redemptionBody(payload),
    },
  );
  const raw = await readJson(response);
  if (!response.ok) throw parseExchangeFailure(raw, response.status);
  const redeemed = parseRedeemedWalletSession(raw);
  const session: HostedWalletSeamsSession = {
    kind: 'active_hosted_wallet_seams_session',
    walletSessionId: redeemed.walletSessionId,
    operationCredential: redeemed.operationCredential,
    expiresAtMs: redeemed.expiresAtMs,
    relayUrl: requestedRelayUrl,
    appOrigin: payload.appOrigin,
    walletOrigin: payload.walletOrigin,
  };
  activeHostedWalletSession = session;
  return session;
}
