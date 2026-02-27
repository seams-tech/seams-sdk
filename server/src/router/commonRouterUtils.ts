import type {
  ThresholdEd25519AuthorizeWithSessionRequest,
  ThresholdEcdsaAuthorizeWithSessionRequest,
} from '../core/types';
import {
  parseThresholdEd25519SessionClaims,
  parseThresholdEcdsaSessionClaims,
} from '../core/ThresholdService/validation';
import type { SessionAdapter } from './relay';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';

type PlainObject = Record<string, unknown>;
type AuthorizeErr = { ok: false; code: 'sessions_disabled' | 'unauthorized'; message: string };

function isPlainObject(input: unknown): input is PlainObject {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

export type ThresholdEd25519AuthorizeInputs =
  | {
      ok: true;
      claims: NonNullable<ReturnType<typeof parseThresholdEd25519SessionClaims>>;
      request: ThresholdEd25519AuthorizeWithSessionRequest;
    }
  | AuthorizeErr;

export async function validateThresholdEd25519AuthorizeInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
}): Promise<ThresholdEd25519AuthorizeInputs> {
  const session = input.session;
  if (!session) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const parsed = await session.parse(input.headers);
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Missing or invalid threshold session token',
    };
  }

  const claims = parseThresholdEd25519SessionClaims(parsed.claims);
  if (!claims) {
    return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
  }

  const requestBody = isPlainObject(input.body) ? input.body : {};
  return {
    ok: true,
    claims,
    request: requestBody as unknown as ThresholdEd25519AuthorizeWithSessionRequest,
  };
}

export type ThresholdEcdsaAuthorizeInputs =
  | {
      ok: true;
      claims: NonNullable<ReturnType<typeof parseThresholdEcdsaSessionClaims>>;
      request: ThresholdEcdsaAuthorizeWithSessionRequest;
    }
  | AuthorizeErr;

export type ThresholdEcdsaSessionInputs =
  | {
      ok: true;
      claims: NonNullable<ReturnType<typeof parseThresholdEcdsaSessionClaims>>;
      body: PlainObject;
    }
  | AuthorizeErr;

export async function validateThresholdEcdsaSessionInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
}): Promise<ThresholdEcdsaSessionInputs> {
  const session = input.session;
  if (!session) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const parsed = await session.parse(input.headers);
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Missing or invalid threshold session token',
    };
  }

  const claims = parseThresholdEcdsaSessionClaims(parsed.claims);
  if (!claims) {
    return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
  }

  const body = isPlainObject(input.body) ? input.body : {};
  return { ok: true, claims, body };
}

export async function validateThresholdEcdsaAuthorizeInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
}): Promise<ThresholdEcdsaAuthorizeInputs> {
  const session = input.session;
  if (!session) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const parsed = await session.parse(input.headers);
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Missing or invalid threshold session token',
    };
  }

  const claims = parseThresholdEcdsaSessionClaims(parsed.claims);
  if (!claims) {
    return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
  }

  const requestBody = isPlainObject(input.body) ? input.body : {};
  return {
    ok: true,
    claims,
    request: requestBody as unknown as ThresholdEcdsaAuthorizeWithSessionRequest,
  };
}

type ThresholdSessionJwtKind = 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1';

export type ThresholdSessionJwtSigningResult =
  | {
      ok: true;
      jwt: string;
      sessionId: string;
      thresholdExpiresAtMs: number;
      participantIds: number[];
    }
  | {
      ok: false;
      status: 400 | 500;
      code: 'sessions_disabled' | 'invalid_body' | 'internal';
      message: string;
    };

export async function signThresholdSessionJwt(args: {
  session: SessionAdapter | null | undefined;
  kind: ThresholdSessionJwtKind;
  userId: unknown;
  rpId: unknown;
  relayerKeyId: unknown;
  sessionInfo: {
    sessionKind?: unknown;
    sessionId?: unknown;
    expiresAtMs?: unknown;
    participantIds?: unknown;
  };
  fallbackParticipantIds?: unknown;
  requireJwtErrorMessage: string;
  invalidPayloadErrorMessage: string;
  sessionsDisabledMessage?: string;
}): Promise<ThresholdSessionJwtSigningResult> {
  const session = args.session;
  if (!session) {
    return {
      ok: false,
      status: 500,
      code: 'sessions_disabled',
      message: args.sessionsDisabledMessage || 'Session signing is not configured on this server',
    };
  }

  const sessionKind = String(args.sessionInfo?.sessionKind || '')
    .trim()
    .toLowerCase();
  if (sessionKind && sessionKind !== 'jwt') {
    return {
      ok: false,
      status: 400,
      code: 'invalid_body',
      message: args.requireJwtErrorMessage,
    };
  }

  const userId = String(args.userId || '').trim();
  const rpId = String(args.rpId || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const sessionId = String(args.sessionInfo?.sessionId || '').trim();
  const thresholdExpiresAtMs = Number(args.sessionInfo?.expiresAtMs);
  const participantIds =
    normalizeThresholdEd25519ParticipantIds(args.sessionInfo?.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.fallbackParticipantIds);

  if (
    !userId ||
    !rpId ||
    !relayerKeyId ||
    !sessionId ||
    !Number.isFinite(thresholdExpiresAtMs) ||
    thresholdExpiresAtMs <= 0 ||
    !participantIds ||
    participantIds.length < 2
  ) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = Math.floor(thresholdExpiresAtMs / 1000);
  const jwt = await session.signJwt(userId, {
    kind: args.kind,
    sessionId,
    relayerKeyId,
    rpId,
    participantIds,
    thresholdExpiresAtMs,
    iat: nowSec,
    exp: expSec,
  });
  return {
    ok: true,
    jwt,
    sessionId,
    thresholdExpiresAtMs,
    participantIds,
  };
}
