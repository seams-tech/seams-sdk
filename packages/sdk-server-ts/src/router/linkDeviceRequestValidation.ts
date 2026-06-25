import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';

export type RegisterLinkDeviceSessionRequest = {
  session_id: string;
  device2_public_key: string;
  expires_at_ms?: number;
};

export type ClaimLinkDeviceSessionRequest = {
  session_id: string;
  wallet_id: string;
  account_id: string;
  device2_public_key: string;
  signer_slot?: number;
  add_key_tx_hash?: string;
};

export type PrepareLinkDeviceRequest = {
  wallet_id: string;
  account_id: string;
  rp_id: string;
  webauthn_registration: Record<string, unknown>;
  expected_origin: string;
  session_id?: string;
  signer_slot?: number;
  threshold_ed25519?: Record<string, unknown>;
  threshold_ecdsa_prepare?: Record<string, unknown>;
};

export type RespondLinkDeviceEcdsaRequest = {
  session_id: string;
  client_bootstrap: Record<string, unknown>;
};

export type LinkDeviceRouteErrorBody = {
  ok: false;
  code: 'invalid_body';
  message: string;
};

export type LinkDeviceRouteParseResult<T> =
  | { ok: true; request: T }
  | { ok: false; status: 400; body: LinkDeviceRouteErrorBody };

const REGISTER_SESSION_KEYS = ['session_id', 'device2_public_key', 'expires_at_ms'] as const;
const CLAIM_SESSION_KEYS = [
  'session_id',
  'wallet_id',
  'account_id',
  'device2_public_key',
  'signer_slot',
  'add_key_tx_hash',
] as const;
const PREPARE_KEYS = [
  'wallet_id',
  'account_id',
  'session_id',
  'signer_slot',
  'threshold_ed25519',
  'threshold_ecdsa_prepare',
  'rp_id',
  'webauthn_registration',
] as const;
const RESPOND_ECDSA_KEYS = ['session_id', 'client_bootstrap'] as const;

function invalidLinkDeviceBody(message: string): LinkDeviceRouteParseResult<never> {
  return {
    ok: false,
    status: 400,
    body: { ok: false, code: 'invalid_body', message },
  };
}

function unexpectedLinkDeviceKey(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
): string | null {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.includes(key)) return key;
  }
  return null;
}

function requireJsonObject(raw: unknown): LinkDeviceRouteParseResult<Record<string, unknown>> {
  if (!isPlainObject(raw)) {
    return invalidLinkDeviceBody('Expected JSON object body');
  }
  return { ok: true, request: raw };
}

function requireTrimmedField(
  record: Record<string, unknown>,
  fieldName: string,
): LinkDeviceRouteParseResult<string> {
  const value = toOptionalTrimmedString(record[fieldName]);
  if (!value) return invalidLinkDeviceBody(`${fieldName} is required`);
  return { ok: true, request: value };
}

function parseOptionalTrimmedField(
  record: Record<string, unknown>,
  fieldName: string,
): string | undefined {
  return toOptionalTrimmedString(record[fieldName]) || undefined;
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
): LinkDeviceRouteParseResult<Record<string, unknown> | undefined> {
  if (!Object.prototype.hasOwnProperty.call(record, fieldName)) {
    return { ok: true, request: undefined };
  }
  const value = record[fieldName];
  if (!isPlainObject(value)) {
    return invalidLinkDeviceBody(`${fieldName} must be an object`);
  }
  return { ok: true, request: value };
}

function parseRequiredObjectField(
  record: Record<string, unknown>,
  fieldName: string,
): LinkDeviceRouteParseResult<Record<string, unknown>> {
  const value = record[fieldName];
  if (!isPlainObject(value)) {
    return invalidLinkDeviceBody(`${fieldName} is required`);
  }
  return { ok: true, request: value };
}

function requireOnlyAllowedKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  context: string,
): LinkDeviceRouteParseResult<true> {
  const unexpectedKey = unexpectedLinkDeviceKey(record, allowedKeys);
  if (unexpectedKey) {
    return invalidLinkDeviceBody(`Unsupported ${context} field: ${unexpectedKey}`);
  }
  return { ok: true, request: true };
}

export function parseRegisterLinkDeviceSessionRequest(
  raw: unknown,
): LinkDeviceRouteParseResult<RegisterLinkDeviceSessionRequest> {
  const body = requireJsonObject(raw);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, REGISTER_SESSION_KEYS, 'link-device session');
  if (!keys.ok) return keys;

  const sessionId = requireTrimmedField(body.request, 'session_id');
  if (!sessionId.ok) return sessionId;
  const device2PublicKey = requireTrimmedField(body.request, 'device2_public_key');
  if (!device2PublicKey.ok) return device2PublicKey;
  const expiresAtMs = parseOptionalPositiveInteger(body.request.expires_at_ms, 'expires_at_ms');
  if (!expiresAtMs.ok) return invalidLinkDeviceBody(expiresAtMs.message);

  return {
    ok: true,
    request: {
      session_id: sessionId.request,
      device2_public_key: device2PublicKey.request,
      ...(expiresAtMs.value ? { expires_at_ms: expiresAtMs.value } : {}),
    },
  };
}

export function parseClaimLinkDeviceSessionRequest(
  raw: unknown,
): LinkDeviceRouteParseResult<ClaimLinkDeviceSessionRequest> {
  const body = requireJsonObject(raw);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, CLAIM_SESSION_KEYS, 'link-device claim');
  if (!keys.ok) return keys;

  const sessionId = requireTrimmedField(body.request, 'session_id');
  if (!sessionId.ok) return sessionId;
  const walletId = requireTrimmedField(body.request, 'wallet_id');
  if (!walletId.ok) return walletId;
  const accountId = requireTrimmedField(body.request, 'account_id');
  if (!accountId.ok) return accountId;
  const device2PublicKey = requireTrimmedField(body.request, 'device2_public_key');
  if (!device2PublicKey.ok) return device2PublicKey;
  const signerSlot = parseOptionalPositiveInteger(body.request.signer_slot, 'signer_slot');
  if (!signerSlot.ok) return invalidLinkDeviceBody(signerSlot.message);
  const addKeyTxHash = parseOptionalTrimmedField(body.request, 'add_key_tx_hash');

  return {
    ok: true,
    request: {
      session_id: sessionId.request,
      wallet_id: walletId.request,
      account_id: accountId.request,
      device2_public_key: device2PublicKey.request,
      ...(signerSlot.value ? { signer_slot: signerSlot.value } : {}),
      ...(addKeyTxHash ? { add_key_tx_hash: addKeyTxHash } : {}),
    },
  };
}

export function parsePrepareLinkDeviceRequest(input: {
  body: unknown;
  origin: unknown;
}): LinkDeviceRouteParseResult<PrepareLinkDeviceRequest> {
  const body = requireJsonObject(input.body);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, PREPARE_KEYS, 'link-device prepare');
  if (!keys.ok) return keys;

  const walletId = requireTrimmedField(body.request, 'wallet_id');
  if (!walletId.ok) return walletId;
  const accountId = requireTrimmedField(body.request, 'account_id');
  if (!accountId.ok) return accountId;
  const rpId = requireTrimmedField(body.request, 'rp_id');
  if (!rpId.ok) return rpId;
  const expectedOrigin = toOptionalTrimmedString(input.origin);
  if (!expectedOrigin) {
    return invalidLinkDeviceBody('Origin header is required');
  }
  const signerSlot = parseOptionalPositiveInteger(body.request.signer_slot, 'signer_slot');
  if (!signerSlot.ok) return invalidLinkDeviceBody(signerSlot.message);
  const webauthnRegistration = parseRequiredObjectField(body.request, 'webauthn_registration');
  if (!webauthnRegistration.ok) return webauthnRegistration;
  const thresholdEd25519 = parseOptionalObjectField(body.request, 'threshold_ed25519');
  if (!thresholdEd25519.ok) return thresholdEd25519;
  const thresholdEcdsaPrepare = parseOptionalObjectField(body.request, 'threshold_ecdsa_prepare');
  if (!thresholdEcdsaPrepare.ok) return thresholdEcdsaPrepare;
  const sessionId = parseOptionalTrimmedField(body.request, 'session_id');

  return {
    ok: true,
    request: {
      wallet_id: walletId.request,
      account_id: accountId.request,
      rp_id: rpId.request,
      webauthn_registration: webauthnRegistration.request,
      expected_origin: expectedOrigin,
      ...(sessionId ? { session_id: sessionId } : {}),
      ...(signerSlot.value ? { signer_slot: signerSlot.value } : {}),
      ...(thresholdEd25519.request ? { threshold_ed25519: thresholdEd25519.request } : {}),
      ...(thresholdEcdsaPrepare.request
        ? { threshold_ecdsa_prepare: thresholdEcdsaPrepare.request }
        : {}),
    },
  };
}

export function parseRespondLinkDeviceEcdsaRequest(
  raw: unknown,
): LinkDeviceRouteParseResult<RespondLinkDeviceEcdsaRequest> {
  const body = requireJsonObject(raw);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, RESPOND_ECDSA_KEYS, 'link-device ECDSA respond');
  if (!keys.ok) return keys;

  const sessionId = requireTrimmedField(body.request, 'session_id');
  if (!sessionId.ok) return sessionId;
  const clientBootstrap = parseRequiredObjectField(body.request, 'client_bootstrap');
  if (!clientBootstrap.ok) return clientBootstrap;

  return {
    ok: true,
    request: {
      session_id: sessionId.request,
      client_bootstrap: clientBootstrap.request,
    },
  };
}
