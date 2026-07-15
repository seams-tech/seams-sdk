import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';

export type PrepareEmailRecoveryRequest = {
  account_id: string;
  request_id: string;
  rp_id: string;
  webauthn_registration: Record<string, unknown>;
  threshold_ecdsa_prepare: Record<string, unknown>;
  expected_origin: string;
  signer_slot?: number;
};

export type RespondEmailRecoveryEcdsaRequest = {
  request_id: string;
  clientBootstraps: Array<{
    chainTarget: Record<string, unknown>;
    clientBootstrap: Record<string, unknown>;
  }>;
};

export type EmailRecoveryRouteErrorBody = {
  ok: false;
  code: 'invalid_body';
  message: string;
};

export type EmailRecoveryRouteParseResult<T> =
  | { ok: true; request: T }
  | { ok: false; status: 400; body: EmailRecoveryRouteErrorBody };

const PREPARE_KEYS = [
  'account_id',
  'request_id',
  'signer_slot',
  'threshold_ecdsa_prepare',
  'rp_id',
  'webauthn_registration',
] as const;
const RESPOND_ECDSA_KEYS = ['request_id', 'client_bootstraps'] as const;

function invalidEmailRecoveryBody(message: string): EmailRecoveryRouteParseResult<never> {
  return {
    ok: false,
    status: 400,
    body: { ok: false, code: 'invalid_body', message },
  };
}

function unexpectedEmailRecoveryKey(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
): string | null {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.includes(key)) return key;
  }
  return null;
}

function requireJsonObject(raw: unknown): EmailRecoveryRouteParseResult<Record<string, unknown>> {
  if (!isPlainObject(raw)) {
    return invalidEmailRecoveryBody('Expected JSON object body');
  }
  return { ok: true, request: raw };
}

function requireOnlyAllowedKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  context: string,
): EmailRecoveryRouteParseResult<true> {
  const unexpectedKey = unexpectedEmailRecoveryKey(record, allowedKeys);
  if (unexpectedKey) {
    return invalidEmailRecoveryBody(`Unsupported ${context} field: ${unexpectedKey}`);
  }
  return { ok: true, request: true };
}

function requireTrimmedField(
  record: Record<string, unknown>,
  fieldName: string,
): EmailRecoveryRouteParseResult<string> {
  const value = toOptionalTrimmedString(record[fieldName]);
  if (!value) return invalidEmailRecoveryBody(`${fieldName} is required`);
  return { ok: true, request: value };
}

function parseOptionalPositiveInteger(
  raw: unknown,
  fieldName: string,
): { ok: true; value?: number } | { ok: false; message: string } {
  if (raw == null) return { ok: true };
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    return { ok: false, message: `${fieldName} must be a positive number` };
  }
  return { ok: true, value: Math.floor(value) };
}

function parseOptionalObjectField(
  record: Record<string, unknown>,
  fieldName: string,
): EmailRecoveryRouteParseResult<Record<string, unknown> | undefined> {
  if (!Object.prototype.hasOwnProperty.call(record, fieldName)) {
    return { ok: true, request: undefined };
  }
  const value = record[fieldName];
  if (!isPlainObject(value)) {
    return invalidEmailRecoveryBody(`${fieldName} must be an object`);
  }
  return { ok: true, request: value };
}

function parseRequiredObjectField(
  record: Record<string, unknown>,
  fieldName: string,
): EmailRecoveryRouteParseResult<Record<string, unknown>> {
  const value = record[fieldName];
  if (!isPlainObject(value)) {
    return invalidEmailRecoveryBody(`${fieldName} is required`);
  }
  return { ok: true, request: value };
}

function parseRequiredObjectArrayField(
  record: Record<string, unknown>,
  fieldName: string,
): EmailRecoveryRouteParseResult<Record<string, unknown>[]> {
  const value = record[fieldName];
  if (!Array.isArray(value) || value.length === 0 || !value.every(isPlainObject)) {
    return invalidEmailRecoveryBody(`${fieldName} is required`);
  }
  return { ok: true, request: value };
}

export function parsePrepareEmailRecoveryRequest(input: {
  body: unknown;
  origin: unknown;
}): EmailRecoveryRouteParseResult<PrepareEmailRecoveryRequest> {
  const body = requireJsonObject(input.body);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, PREPARE_KEYS, 'email-recovery prepare');
  if (!keys.ok) return keys;

  const accountId = requireTrimmedField(body.request, 'account_id');
  if (!accountId.ok) return accountId;
  const requestId = requireTrimmedField(body.request, 'request_id');
  if (!requestId.ok) return requestId;
  const rpId = requireTrimmedField(body.request, 'rp_id');
  if (!rpId.ok) return rpId;
  const expectedOrigin = toOptionalTrimmedString(input.origin);
  if (!expectedOrigin) {
    return invalidEmailRecoveryBody('Origin header is required');
  }
  const signerSlot = parseOptionalPositiveInteger(body.request.signer_slot, 'signer_slot');
  if (!signerSlot.ok) return invalidEmailRecoveryBody(signerSlot.message);
  const webauthnRegistration = parseRequiredObjectField(body.request, 'webauthn_registration');
  if (!webauthnRegistration.ok) return webauthnRegistration;
  const thresholdEcdsaPrepare = parseRequiredObjectField(body.request, 'threshold_ecdsa_prepare');
  if (!thresholdEcdsaPrepare.ok) return thresholdEcdsaPrepare;
  const thresholdEd25519 = parseOptionalObjectField(body.request, 'threshold_ed25519');
  if (!thresholdEd25519.ok) return thresholdEd25519;

  return {
    ok: true,
    request: {
      account_id: accountId.request,
      request_id: requestId.request,
      rp_id: rpId.request,
      webauthn_registration: webauthnRegistration.request,
      threshold_ecdsa_prepare: thresholdEcdsaPrepare.request,
      expected_origin: expectedOrigin,
      ...(signerSlot.value ? { signer_slot: signerSlot.value } : {}),
      ...(thresholdEd25519.request ? { threshold_ed25519: thresholdEd25519.request } : {}),
    },
  };
}

export function parseRespondEmailRecoveryEcdsaRequest(
  raw: unknown,
): EmailRecoveryRouteParseResult<RespondEmailRecoveryEcdsaRequest> {
  const body = requireJsonObject(raw);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, RESPOND_ECDSA_KEYS, 'email-recovery ECDSA respond');
  if (!keys.ok) return keys;

  const requestId = requireTrimmedField(body.request, 'request_id');
  if (!requestId.ok) return requestId;
  const clientBootstraps = parseRequiredObjectArrayField(body.request, 'client_bootstraps');
  if (!clientBootstraps.ok) return clientBootstraps;
  const parsedClientBootstraps: RespondEmailRecoveryEcdsaRequest['clientBootstraps'] = [];
  for (const entry of clientBootstraps.request) {
    const chainTarget = parseRequiredObjectField(entry, 'chain_target');
    if (!chainTarget.ok) return chainTarget;
    const clientBootstrap = parseRequiredObjectField(entry, 'client_bootstrap');
    if (!clientBootstrap.ok) return clientBootstrap;
    parsedClientBootstraps.push({
      chainTarget: chainTarget.request,
      clientBootstrap: clientBootstrap.request,
    });
  }

  return {
    ok: true,
    request: {
      request_id: requestId.request,
      clientBootstraps: parsedClientBootstraps,
    },
  };
}
