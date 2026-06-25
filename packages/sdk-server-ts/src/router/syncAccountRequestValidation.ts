import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';

export type SyncAccountOptionsRequest = {
  rp_id: string;
  account_id?: string;
  ttl_ms?: number;
};

export type SyncAccountVerifyRequest =
  | {
      challengeId: string;
      webauthn_authentication: Record<string, unknown>;
      expected_origin: string;
      threshold_ed25519?: never;
    }
  | {
      challengeId: string;
      webauthn_authentication: Record<string, unknown>;
      expected_origin: string;
      threshold_ed25519: Record<string, unknown>;
    };

export type SyncAccountRouteErrorBody = {
  ok: false;
  code: 'invalid_body';
  message: string;
};

export type SyncAccountRouteParseResult<T> =
  | { ok: true; request: T }
  | { ok: false; status: 400; body: SyncAccountRouteErrorBody };

const SYNC_ACCOUNT_OPTIONS_KEYS = ['rp_id', 'account_id', 'ttl_ms'] as const;
const SYNC_ACCOUNT_VERIFY_KEYS = [
  'challengeId',
  'webauthn_authentication',
  'threshold_ed25519',
] as const;

function invalidSyncAccountBody(message: string): SyncAccountRouteParseResult<never> {
  return {
    ok: false,
    status: 400,
    body: { ok: false, code: 'invalid_body', message },
  };
}

function unexpectedSyncAccountKey(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
): string | null {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.includes(key)) return key;
  }
  return null;
}

function parseOptionalPositiveInteger(raw: unknown, fieldName: string):
  | { ok: true; value?: number }
  | { ok: false; message: string } {
  if (raw == null) return { ok: true };
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    return { ok: false, message: `${fieldName} must be a positive number` };
  }
  return { ok: true, value: Math.floor(value) };
}

export function parseSyncAccountOptionsRequest(
  raw: unknown,
): SyncAccountRouteParseResult<SyncAccountOptionsRequest> {
  if (!isPlainObject(raw)) {
    return invalidSyncAccountBody('Expected JSON object body');
  }
  const unexpectedKey = unexpectedSyncAccountKey(raw, SYNC_ACCOUNT_OPTIONS_KEYS);
  if (unexpectedKey) {
    return invalidSyncAccountBody(`Unsupported sync-account options field: ${unexpectedKey}`);
  }

  const rpId = toOptionalTrimmedString(raw.rp_id);
  if (!rpId) return invalidSyncAccountBody('rp_id is required');

  const accountId = toOptionalTrimmedString(raw.account_id);
  const parsedTtl = parseOptionalPositiveInteger(raw.ttl_ms, 'ttl_ms');
  if (!parsedTtl.ok) return invalidSyncAccountBody(parsedTtl.message);

  return {
    ok: true,
    request: {
      rp_id: rpId,
      ...(accountId ? { account_id: accountId } : {}),
      ...(parsedTtl.value ? { ttl_ms: parsedTtl.value } : {}),
    },
  };
}

export function parseSyncAccountVerifyRequest(input: {
  body: unknown;
  origin: unknown;
}): SyncAccountRouteParseResult<SyncAccountVerifyRequest> {
  if (!isPlainObject(input.body)) {
    return invalidSyncAccountBody('Expected JSON object body');
  }
  const unexpectedKey = unexpectedSyncAccountKey(input.body, SYNC_ACCOUNT_VERIFY_KEYS);
  if (unexpectedKey) {
    return invalidSyncAccountBody(`Unsupported sync-account verify field: ${unexpectedKey}`);
  }

  const challengeId = toOptionalTrimmedString(input.body.challengeId);
  if (!challengeId) return invalidSyncAccountBody('challengeId is required');

  if (!isPlainObject(input.body.webauthn_authentication)) {
    return invalidSyncAccountBody('webauthn_authentication is required');
  }

  const expectedOrigin = toOptionalTrimmedString(input.origin);
  if (!expectedOrigin) {
    return invalidSyncAccountBody('Origin header is required');
  }

  if (Object.prototype.hasOwnProperty.call(input.body, 'threshold_ed25519')) {
    if (!isPlainObject(input.body.threshold_ed25519)) {
      return invalidSyncAccountBody('threshold_ed25519 must be an object');
    }
    return {
      ok: true,
      request: {
        challengeId,
        webauthn_authentication: input.body.webauthn_authentication,
        expected_origin: expectedOrigin,
        threshold_ed25519: input.body.threshold_ed25519,
      },
    };
  }

  return {
    ok: true,
    request: {
      challengeId,
      webauthn_authentication: input.body.webauthn_authentication,
      expected_origin: expectedOrigin,
    },
  };
}
