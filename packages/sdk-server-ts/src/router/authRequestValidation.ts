import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';

export type AuthProviderActionRoute =
  | { kind: 'passkey_options' }
  | { kind: 'passkey_verify' }
  | { kind: 'google_options' }
  | { kind: 'google_verify' };

export type PasskeyLoginOptionsRequest = {
  user_id: string;
  rp_id: string;
  ttl_ms?: number;
};

export type PasskeyLoginVerifyRequest = {
  challengeId: string;
  webauthn_authentication: Record<string, unknown>;
  expected_origin: string;
};

export type GoogleLoginVerifyRequest = {
  idToken: string;
};

export type AuthPasskeyStepUpRequest = {
  challengeId: string;
  webauthn_authentication: Record<string, unknown>;
  expected_origin: string;
};

export type AuthLinkIdentityRequest = {
  provider: 'google';
  idToken: string;
  stepUp: AuthPasskeyStepUpRequest;
};

export type AuthUnlinkIdentityRequest = {
  subject: string;
  stepUp: AuthPasskeyStepUpRequest;
  session_kind?: 'jwt' | 'cookie';
};

export type AuthIdentityMutationRequest =
  | {
      kind: 'link';
      source: 'auth.link';
      request: AuthLinkIdentityRequest;
    }
  | {
      kind: 'unlink';
      source: 'auth.unlink';
      request: AuthUnlinkIdentityRequest;
    };

export type AuthRouteErrorBody = {
  ok: false;
  code: 'invalid_body';
  message: string;
};

export type AuthRouteParseResult<T> =
  | { ok: true; request: T }
  | { ok: false; status: 400; body: AuthRouteErrorBody };

const PASSKEY_OPTIONS_KEYS = ['user_id', 'rp_id', 'ttl_ms'] as const;
const PASSKEY_VERIFY_KEYS = ['challengeId', 'webauthn_authentication'] as const;
const GOOGLE_VERIFY_KEYS = ['id_token'] as const;
const AUTH_LINK_KEYS = [
  'provider',
  'id_token',
  'step_up_challenge_id',
  'webauthn_authentication',
] as const;
const AUTH_UNLINK_KEYS = [
  'subject',
  'step_up_challenge_id',
  'webauthn_authentication',
  'session_kind',
] as const;

function invalidAuthBody(message: string): AuthRouteParseResult<never> {
  return {
    ok: false,
    status: 400,
    body: { ok: false, code: 'invalid_body', message },
  };
}

function unexpectedAuthKey(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
): string | null {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.includes(key)) return key;
  }
  return null;
}

function requireJsonObject(raw: unknown): AuthRouteParseResult<Record<string, unknown>> {
  if (!isPlainObject(raw)) {
    return invalidAuthBody('Expected JSON object body');
  }
  return { ok: true, request: raw };
}

function requireOnlyAllowedKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  context: string,
): AuthRouteParseResult<true> {
  const unexpectedKey = unexpectedAuthKey(record, allowedKeys);
  if (unexpectedKey) {
    return invalidAuthBody(`Unsupported ${context} field: ${unexpectedKey}`);
  }
  return { ok: true, request: true };
}

function requireTrimmedField(
  record: Record<string, unknown>,
  fieldName: string,
): AuthRouteParseResult<string> {
  const value = toOptionalTrimmedString(record[fieldName]);
  if (!value) return invalidAuthBody(`${fieldName} is required`);
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

export function parseAuthProviderAction(input: {
  provider: unknown;
  action: unknown;
}): AuthProviderActionRoute | null {
  const provider = toOptionalTrimmedString(input.provider);
  const action = toOptionalTrimmedString(input.action);
  if (provider === 'passkey' && action === 'options') return { kind: 'passkey_options' };
  if (provider === 'passkey' && action === 'verify') return { kind: 'passkey_verify' };
  if (provider === 'google' && action === 'options') return { kind: 'google_options' };
  if (provider === 'google' && action === 'verify') return { kind: 'google_verify' };
  return null;
}

export function parseAuthProviderActionPath(pathname: string): AuthProviderActionRoute | null {
  const parts = String(pathname || '')
    .split('/')
    .filter(Boolean);
  if (parts.length !== 3 || parts[0] !== 'auth') return null;
  return parseAuthProviderAction({ provider: parts[1], action: parts[2] });
}

export function parsePasskeyLoginOptionsRequest(
  raw: unknown,
): AuthRouteParseResult<PasskeyLoginOptionsRequest> {
  const body = requireJsonObject(raw);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, PASSKEY_OPTIONS_KEYS, 'passkey login options');
  if (!keys.ok) return keys;

  const userId = requireTrimmedField(body.request, 'user_id');
  if (!userId.ok) return userId;
  const rpId = requireTrimmedField(body.request, 'rp_id');
  if (!rpId.ok) return rpId;
  const ttlMs = parseOptionalPositiveInteger(body.request.ttl_ms, 'ttl_ms');
  if (!ttlMs.ok) return invalidAuthBody(ttlMs.message);

  return {
    ok: true,
    request: {
      user_id: userId.request,
      rp_id: rpId.request,
      ...(ttlMs.value ? { ttl_ms: ttlMs.value } : {}),
    },
  };
}

export function parsePasskeyLoginVerifyRequest(input: {
  body: unknown;
  origin: unknown;
}): AuthRouteParseResult<PasskeyLoginVerifyRequest> {
  const body = requireJsonObject(input.body);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, PASSKEY_VERIFY_KEYS, 'passkey login verify');
  if (!keys.ok) return keys;

  const challengeId = requireTrimmedField(body.request, 'challengeId');
  if (!challengeId.ok) return challengeId;
  if (!isPlainObject(body.request.webauthn_authentication)) {
    return invalidAuthBody('webauthn_authentication is required');
  }
  const expectedOrigin = toOptionalTrimmedString(input.origin);
  if (!expectedOrigin) {
    return invalidAuthBody('Origin header is required');
  }

  return {
    ok: true,
    request: {
      challengeId: challengeId.request,
      webauthn_authentication: body.request.webauthn_authentication,
      expected_origin: expectedOrigin,
    },
  };
}

export function parseGoogleLoginVerifyRequest(
  raw: unknown,
): AuthRouteParseResult<GoogleLoginVerifyRequest> {
  const body = requireJsonObject(raw);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, GOOGLE_VERIFY_KEYS, 'google login verify');
  if (!keys.ok) return keys;

  const idToken = requireTrimmedField(body.request, 'id_token');
  if (!idToken.ok) return idToken;
  return { ok: true, request: { idToken: idToken.request } };
}

function parsePasskeyStepUpRequest(input: {
  body: Record<string, unknown>;
  origin: unknown;
}): AuthRouteParseResult<AuthPasskeyStepUpRequest> {
  const challengeId = requireTrimmedField(input.body, 'step_up_challenge_id');
  if (!challengeId.ok) return challengeId;
  if (!isPlainObject(input.body.webauthn_authentication)) {
    return invalidAuthBody('webauthn_authentication is required for step-up');
  }
  const expectedOrigin = toOptionalTrimmedString(input.origin);
  if (!expectedOrigin) {
    return invalidAuthBody('Origin header is required');
  }
  return {
    ok: true,
    request: {
      challengeId: challengeId.request,
      webauthn_authentication: input.body.webauthn_authentication,
      expected_origin: expectedOrigin,
    },
  };
}

export function parseAuthLinkIdentityRequest(input: {
  body: unknown;
  origin: unknown;
}): AuthRouteParseResult<AuthLinkIdentityRequest> {
  const body = requireJsonObject(input.body);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, AUTH_LINK_KEYS, 'auth link');
  if (!keys.ok) return keys;

  const provider = requireTrimmedField(body.request, 'provider');
  if (!provider.ok) return provider;
  if (provider.request !== 'google') {
    return invalidAuthBody('provider must be: google');
  }
  const idToken = requireTrimmedField(body.request, 'id_token');
  if (!idToken.ok) return idToken;
  const stepUp = parsePasskeyStepUpRequest({ body: body.request, origin: input.origin });
  if (!stepUp.ok) return stepUp;

  return {
    ok: true,
    request: {
      provider: 'google',
      idToken: idToken.request,
      stepUp: stepUp.request,
    },
  };
}

export function parseAuthUnlinkIdentityRequest(input: {
  body: unknown;
  origin: unknown;
}): AuthRouteParseResult<AuthUnlinkIdentityRequest> {
  const body = requireJsonObject(input.body);
  if (!body.ok) return body;
  const keys = requireOnlyAllowedKeys(body.request, AUTH_UNLINK_KEYS, 'auth unlink');
  if (!keys.ok) return keys;

  const subject = requireTrimmedField(body.request, 'subject');
  if (!subject.ok) return subject;
  const rawSessionKind = toOptionalTrimmedString(body.request.session_kind);
  if (rawSessionKind && rawSessionKind !== 'jwt' && rawSessionKind !== 'cookie') {
    return invalidAuthBody('session_kind must be jwt or cookie');
  }
  const sessionKind =
    rawSessionKind === 'jwt' || rawSessionKind === 'cookie' ? rawSessionKind : undefined;
  const stepUp = parsePasskeyStepUpRequest({ body: body.request, origin: input.origin });
  if (!stepUp.ok) return stepUp;

  return {
    ok: true,
    request: {
      subject: subject.request,
      stepUp: stepUp.request,
      ...(sessionKind ? { session_kind: sessionKind } : {}),
    },
  };
}

export function parseAuthIdentityMutationRequest(input: {
  pathname: unknown;
  body: unknown;
  origin: unknown;
}): AuthRouteParseResult<AuthIdentityMutationRequest> | null {
  const pathname = toOptionalTrimmedString(input.pathname);
  switch (pathname) {
    case '/auth/link': {
      const parsed = parseAuthLinkIdentityRequest({ body: input.body, origin: input.origin });
      if (!parsed.ok) return parsed;
      return {
        ok: true,
        request: {
          kind: 'link',
          source: 'auth.link',
          request: parsed.request,
        },
      };
    }
    case '/auth/unlink': {
      const parsed = parseAuthUnlinkIdentityRequest({ body: input.body, origin: input.origin });
      if (!parsed.ok) return parsed;
      return {
        ok: true,
        request: {
          kind: 'unlink',
          source: 'auth.unlink',
          request: parsed.request,
        },
      };
    }
    default:
      return null;
  }
}
