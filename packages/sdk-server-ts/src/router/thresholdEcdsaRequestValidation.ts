import { isPlainObject } from '@shared/utils/validation';

export type RouterAbEcdsaHssKeyIdentitiesRequest = {
  sessionKind?: 'jwt' | 'cookie';
  keyTargets: unknown[];
};

export type ThresholdEcdsaRouteErrorBody = {
  ok: false;
  code: 'invalid_body';
  message: string;
};

export type ThresholdEcdsaRouteParseResult<T> =
  | { ok: true; request: T }
  | { ok: false; body: ThresholdEcdsaRouteErrorBody };

const KEY_IDENTITIES_KEYS = ['sessionKind', 'keyTargets'] as const;

function invalidThresholdEcdsaBody(message: string): ThresholdEcdsaRouteParseResult<never> {
  return {
    ok: false,
    body: { ok: false, code: 'invalid_body', message },
  };
}

function unexpectedThresholdEcdsaKey(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
): string | null {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.includes(key)) return key;
  }
  return null;
}

function parseSessionKindField(raw: unknown): 'jwt' | 'cookie' | undefined {
  const value = String(raw ?? '').trim();
  if (!value) return undefined;
  if (value === 'jwt' || value === 'cookie') return value;
  return undefined;
}

function optionalStringField(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim();
  return normalized || undefined;
}

export function parseRouterAbEcdsaHssKeyIdentitiesRequest(
  raw: unknown,
): ThresholdEcdsaRouteParseResult<RouterAbEcdsaHssKeyIdentitiesRequest> {
  if (!isPlainObject(raw)) {
    return invalidThresholdEcdsaBody('Expected JSON object body');
  }
  const unexpectedKey = unexpectedThresholdEcdsaKey(raw, KEY_IDENTITIES_KEYS);
  if (unexpectedKey) {
    return invalidThresholdEcdsaBody(`Unsupported threshold-ecdsa key-identities field: ${unexpectedKey}`);
  }
  const sessionKind = parseSessionKindField(raw.sessionKind);
  const keyTargets = Array.isArray(raw.keyTargets) ? raw.keyTargets : [];
  return {
    ok: true,
    request: {
      ...(sessionKind ? { sessionKind } : {}),
      keyTargets,
    },
  };
}

export function thresholdEcdsaRouteDiagnosticMetadata(
  raw: unknown,
  fields: readonly string[],
): Record<string, string | undefined> {
  if (!isPlainObject(raw)) return {};
  const metadata: Record<string, string | undefined> = {};
  for (const field of fields) {
    metadata[field] = optionalStringField(raw, field);
  }
  return metadata;
}
