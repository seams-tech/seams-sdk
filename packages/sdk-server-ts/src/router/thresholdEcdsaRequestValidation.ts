import { isPlainObject } from '@shared/utils/validation';
import { parseRouterAbEcdsaHssNormalSigningScopeV1 } from '@shared/utils/routerAbEcdsaHss';
import type {
  RouterAbEcdsaHssPoolFillInitRequest,
  RouterAbEcdsaHssPoolFillStepRequest,
} from '../core/types';

export type ThresholdEcdsaRouteErrorBody = {
  ok: false;
  code: 'invalid_body';
  message: string;
};

export type ThresholdEcdsaRouteParseResult<T> =
  | { ok: true; request: T }
  | { ok: false; body: ThresholdEcdsaRouteErrorBody };

const POOL_FILL_INIT_KEYS = [
  'sessionKind',
  'keyHandle',
  'ecdsaThresholdKeyId',
  'count',
  'requestTag',
  'poolFill',
] as const;
const POOL_FILL_STEP_KEYS = [
  'sessionKind',
  'presignSessionId',
  'stage',
  'outgoingMessagesB64u',
  'requestTag',
] as const;
const POOL_FILL_ENVELOPE_KEYS = ['kind', 'scope', 'expiresAtMs'] as const;

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

function rejectNonJwtSessionKind(
  record: Record<string, unknown>,
  message: string,
): ThresholdEcdsaRouteParseResult<never> | null {
  if (record.sessionKind === undefined || record.sessionKind === 'jwt') return null;
  return invalidThresholdEcdsaBody(message);
}

function optionalStringField(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim();
  return normalized || undefined;
}

function isStringValue(value: unknown): value is string {
  return typeof value === 'string';
}

function hasNonStringValue(values: unknown[]): boolean {
  return values.some((value) => !isStringValue(value));
}

export function parseRouterAbEcdsaHssPoolFillInitRouteRequest(
  raw: unknown,
): ThresholdEcdsaRouteParseResult<RouterAbEcdsaHssPoolFillInitRequest> {
  if (!isPlainObject(raw)) {
    return invalidThresholdEcdsaBody('Expected JSON object body');
  }
  const sessionKindError = rejectNonJwtSessionKind(
    raw,
    'Router A/B ECDSA-HSS presignature pool fill requires sessionKind=jwt',
  );
  if (sessionKindError) return sessionKindError;
  const unexpectedKey = unexpectedThresholdEcdsaKey(raw, POOL_FILL_INIT_KEYS);
  if (unexpectedKey) {
    return invalidThresholdEcdsaBody(`Unsupported threshold-ecdsa pool-fill init field: ${unexpectedKey}`);
  }
  if (!isPlainObject(raw.poolFill)) {
    return invalidThresholdEcdsaBody('poolFill is required');
  }
  const unexpectedPoolFillKey = unexpectedThresholdEcdsaKey(raw.poolFill, POOL_FILL_ENVELOPE_KEYS);
  if (unexpectedPoolFillKey) {
    return invalidThresholdEcdsaBody(
      `Unsupported threshold-ecdsa poolFill field: ${unexpectedPoolFillKey}`,
    );
  }
  if (raw.poolFill.kind !== 'router_ab_ecdsa_hss_signing_worker_pool') {
    return invalidThresholdEcdsaBody(
      'poolFill.kind must be router_ab_ecdsa_hss_signing_worker_pool',
    );
  }
  const scope = parseRouterAbEcdsaHssNormalSigningScopeV1(raw.poolFill.scope);
  if (!scope) {
    return invalidThresholdEcdsaBody('poolFill.scope is invalid');
  }
  if (typeof raw.poolFill.expiresAtMs !== 'number' || !Number.isFinite(raw.poolFill.expiresAtMs)) {
    return invalidThresholdEcdsaBody('poolFill.expiresAtMs is required');
  }
  if (raw.count !== undefined && (typeof raw.count !== 'number' || !Number.isFinite(raw.count))) {
    return invalidThresholdEcdsaBody('count must be a number');
  }
  const count = typeof raw.count === 'number' ? raw.count : undefined;
  return {
    ok: true,
    request: {
      ...(optionalStringField(raw, 'keyHandle') ? { keyHandle: optionalStringField(raw, 'keyHandle') } : {}),
      ...(optionalStringField(raw, 'ecdsaThresholdKeyId')
        ? { ecdsaThresholdKeyId: optionalStringField(raw, 'ecdsaThresholdKeyId') }
        : {}),
      ...(count !== undefined ? { count } : {}),
      ...(optionalStringField(raw, 'requestTag') ? { requestTag: optionalStringField(raw, 'requestTag') } : {}),
      poolFill: {
        kind: 'router_ab_ecdsa_hss_signing_worker_pool',
        scope,
        expiresAtMs: raw.poolFill.expiresAtMs,
      },
    },
  };
}

export function parseRouterAbEcdsaHssPoolFillStepRouteRequest(
  raw: unknown,
): ThresholdEcdsaRouteParseResult<RouterAbEcdsaHssPoolFillStepRequest> {
  if (!isPlainObject(raw)) {
    return invalidThresholdEcdsaBody('Expected JSON object body');
  }
  const sessionKindError = rejectNonJwtSessionKind(
    raw,
    'Router A/B ECDSA-HSS presignature pool fill requires sessionKind=jwt',
  );
  if (sessionKindError) return sessionKindError;
  const unexpectedKey = unexpectedThresholdEcdsaKey(raw, POOL_FILL_STEP_KEYS);
  if (unexpectedKey) {
    return invalidThresholdEcdsaBody(`Unsupported threshold-ecdsa pool-fill step field: ${unexpectedKey}`);
  }
  const presignSessionId = optionalStringField(raw, 'presignSessionId');
  if (!presignSessionId) {
    return invalidThresholdEcdsaBody('presignSessionId is required');
  }
  if (raw.stage !== 'triples' && raw.stage !== 'presign') {
    return invalidThresholdEcdsaBody('stage must be triples or presign');
  }
  if (
    raw.outgoingMessagesB64u !== undefined &&
    (!Array.isArray(raw.outgoingMessagesB64u) ||
      hasNonStringValue(raw.outgoingMessagesB64u))
  ) {
    return invalidThresholdEcdsaBody('outgoingMessagesB64u must be an array of strings');
  }
  const outgoingMessagesB64u = Array.isArray(raw.outgoingMessagesB64u)
    ? raw.outgoingMessagesB64u.filter(isStringValue)
    : undefined;
  return {
    ok: true,
    request: {
      presignSessionId,
      stage: raw.stage,
      ...(outgoingMessagesB64u ? { outgoingMessagesB64u } : {}),
      ...(optionalStringField(raw, 'requestTag') ? { requestTag: optionalStringField(raw, 'requestTag') } : {}),
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
