import type {
  ThresholdEd25519AuthorizeWithSessionRequest,
  ThresholdRuntimePolicyScope,
  ThresholdEcdsaAuthorizeWithSessionRequest,
} from '../core/types';
import {
  parseThresholdEd25519SessionClaims,
  parseThresholdEcdsaSessionClaims,
} from '../core/ThresholdService/validation';
import type { SessionAdapter } from './relay';
import type { RelayPublishableKeyAuthAdapter } from './relay';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import { extractBearerCredential } from './relayApiKeyAuth';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeRuntimePolicyScope,
  normalizeRuntimePolicyScopeFields,
} from '@shared/threshold/signingRootScope';

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

export type ThresholdEd25519SessionTokenInputs =
  | {
      ok: true;
      claims: NonNullable<ReturnType<typeof parseThresholdEd25519SessionClaims>>;
      body: PlainObject;
    }
  | AuthorizeErr;

export async function validateThresholdEd25519SessionTokenInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
}): Promise<ThresholdEd25519SessionTokenInputs> {
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

  const body = isPlainObject(input.body) ? input.body : {};
  return { ok: true, claims, body };
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

type ThresholdSessionAuthTokenKind = 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v2';

export type ThresholdSessionAuthTokenSigningResult =
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

export async function signThresholdSessionAuthToken(args: {
  session: SessionAdapter | null | undefined;
  kind: ThresholdSessionAuthTokenKind;
  userId: unknown;
  rpId: unknown;
  relayerKeyId: unknown;
  sessionInfo: {
    sessionKind?: unknown;
    sessionId?: unknown;
    walletSigningSessionId?: unknown;
    expiresAtMs?: unknown;
    participantIds?: unknown;
    runtimePolicyScope?: unknown;
    keyHandle?: unknown;
  };
  fallbackParticipantIds?: unknown;
  allowedSessionKinds?: Array<'jwt' | 'cookie'>;
  requireJwtErrorMessage: string;
  invalidPayloadErrorMessage: string;
  sessionsDisabledMessage?: string;
}): Promise<ThresholdSessionAuthTokenSigningResult> {
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
  const allowedSessionKinds = Array.isArray(args.allowedSessionKinds)
    ? args.allowedSessionKinds
    : ['jwt'];
  if (sessionKind && !allowedSessionKinds.includes(sessionKind as 'jwt' | 'cookie')) {
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
  const walletSigningSessionId = String(args.sessionInfo?.walletSigningSessionId || '').trim();
  const thresholdExpiresAtMs = Number(args.sessionInfo?.expiresAtMs);
  const participantIds =
    normalizeThresholdEd25519ParticipantIds(args.sessionInfo?.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.fallbackParticipantIds);
  const runtimePolicyScope = (() => {
    const raw = args.sessionInfo?.runtimePolicyScope;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
    try {
      return normalizeRuntimePolicyScope(raw as Record<string, unknown>);
    } catch {
      return undefined;
    }
  })();
  const keyHandle = String(args.sessionInfo?.keyHandle || '').trim();

  if (
    !userId ||
    !rpId ||
    !relayerKeyId ||
    !sessionId ||
    !walletSigningSessionId ||
    !Number.isFinite(thresholdExpiresAtMs) ||
    thresholdExpiresAtMs <= 0 ||
    !participantIds ||
    participantIds.length < 2 ||
    (args.kind === 'threshold_ecdsa_session_v2' && !keyHandle)
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
    walletId: userId,
    sessionId,
    walletSigningSessionId,
    relayerKeyId,
    rpId,
    participantIds,
    thresholdExpiresAtMs,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(args.kind === 'threshold_ecdsa_session_v2'
      ? {
          keyHandle,
          keyScope: 'evm-family',
        }
      : {}),
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

export function stripLegacyThresholdEcdsaIdentityFields<
  TThresholdEcdsa extends Record<string, unknown>,
>(thresholdEcdsa: TThresholdEcdsa): Omit<
  TThresholdEcdsa,
  'ecdsaThresholdKeyId' | 'signingRootId' | 'signingRootVersion'
> {
  const {
    ecdsaThresholdKeyId: _ecdsaThresholdKeyId,
    signingRootId: _signingRootId,
    signingRootVersion: _signingRootVersion,
    ...sanitized
  } = thresholdEcdsa as TThresholdEcdsa & {
    ecdsaThresholdKeyId?: unknown;
    signingRootId?: unknown;
    signingRootVersion?: unknown;
  };
  return sanitized;
}

export type ThresholdRuntimePolicyScopeResolution =
  | { ok: true; scope?: ThresholdRuntimePolicyScope }
  | {
      ok: false;
      status: 401 | 403 | 500;
      code: 'route_auth_not_configured' | 'unauthorized' | 'forbidden';
      message: string;
    };

export async function resolveThresholdRuntimePolicyScope(input: {
  explicitScopeRaw: unknown;
  runtimeEnvironmentIdRaw?: unknown;
  headers: Headers | Record<string, string | string[] | undefined>;
  origin?: string | null;
  publishableKeyAuth?: RelayPublishableKeyAuthAdapter | null;
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
}): Promise<ThresholdRuntimePolicyScopeResolution> {
  if (isPlainObject(input.explicitScopeRaw)) {
    try {
      const scope = await resolveActiveRuntimePolicyScopeFromFields({
        orgProjectEnv: input.orgProjectEnv || null,
        fields: normalizeRuntimePolicyScopeFields(input.explicitScopeRaw),
      });
      return {
        ok: true,
        scope,
      };
    } catch {
      return { ok: true };
    }
  }

  const runtimeEnvironmentId = String(input.runtimeEnvironmentIdRaw || '').trim();
  if (!runtimeEnvironmentId) return { ok: true };

  const publishableKeyAuth = input.publishableKeyAuth || null;
  if (!publishableKeyAuth) {
    return {
      ok: false,
      status: 500,
      code: 'route_auth_not_configured',
      message: 'Runtime scope bootstrap requires publishable key auth on this server',
    };
  }

  const publishableKey = extractBearerCredential(input.headers);
  if (!publishableKey) {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'Managed runtime scope bootstrap requires a publishable key',
    };
  }

  const origin = String(input.origin || '').trim();
  if (!origin) {
    return {
      ok: false,
      status: 403,
      code: 'forbidden',
      message: 'Managed runtime scope bootstrap requires an Origin header',
    };
  }

  const authResult = await publishableKeyAuth.authenticate({
    secret: publishableKey,
    origin,
    environmentId: runtimeEnvironmentId,
  });
  if (!authResult.ok) {
    return {
      ok: false,
      status: authResult.status,
      code: authResult.status === 403 ? 'forbidden' : 'unauthorized',
      message: authResult.message,
    };
  }

  const projectEnvironment = await resolveRuntimeProjectEnvironment({
    orgProjectEnv: input.orgProjectEnv || null,
    orgId: authResult.principal.orgId,
    environmentId: authResult.principal.environmentId,
  });
  if (!projectEnvironment) return { ok: true };

  return {
    ok: true,
    scope: {
      orgId: authResult.principal.orgId,
      projectId: projectEnvironment.projectId,
      envId: projectEnvironment.envId,
      signingRootVersion: projectEnvironment.signingRootVersion,
    },
  };
}

export async function resolveActiveRuntimePolicyScopeFromFields(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
  fields: Omit<ThresholdRuntimePolicyScope, 'signingRootVersion'> & {
    readonly signingRootVersion?: string;
  };
}): Promise<ThresholdRuntimePolicyScope> {
  const resolved = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.orgProjectEnv,
    orgId: input.fields.orgId,
    projectId: input.fields.projectId,
    envId: input.fields.envId,
    fallbackSigningRootVersion: input.fields.signingRootVersion,
  });
  if (resolved) return resolved;
  return normalizeRuntimePolicyScope(input.fields);
}

export async function resolveActiveRuntimePolicyScopeForEnvironment(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
  orgId: string;
  environmentId?: string;
  projectId?: string;
  envId?: string;
  fallbackSigningRootVersion?: string;
}): Promise<ThresholdRuntimePolicyScope | undefined> {
  const orgId = String(input.orgId || '').trim();
  if (!orgId) return undefined;
  const activeEnvironment = await resolveRuntimeProjectEnvironment({
    orgProjectEnv: input.orgProjectEnv,
    orgId,
    environmentId: input.environmentId,
    projectId: input.projectId,
    envId: input.envId,
  });
  if (activeEnvironment) {
    return {
      orgId,
      projectId: activeEnvironment.projectId,
      envId: activeEnvironment.envId,
      signingRootVersion: activeEnvironment.signingRootVersion,
    };
  }
  const projectId = String(input.projectId || '').trim();
  const envId = String(input.envId || '').trim();
  const signingRootVersion = String(input.fallbackSigningRootVersion || '').trim();
  if (projectId && envId && signingRootVersion) {
    return { orgId, projectId, envId, signingRootVersion };
  }
  return undefined;
}

async function resolveRuntimeProjectEnvironment(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
  orgId: string;
  environmentId?: string;
  projectId?: string;
  envId?: string;
}): Promise<{ projectId: string; envId: string; signingRootVersion: string } | undefined> {
  if (!input.orgProjectEnv) return undefined;
  try {
    const environmentId = String(input.environmentId || '').trim();
    const projectIdFilter = String(input.projectId || '').trim();
    const envIdFilter = String(input.envId || '').trim();
    const environments = await input.orgProjectEnv.listEnvironments({
      orgId: input.orgId,
      actorUserId: 'runtime-scope-bootstrap',
      roles: ['system'],
      ...(environmentId ? { environmentId } : {}),
      ...(projectIdFilter ? { projectId: projectIdFilter } : {}),
    });
    const environment = environments.find((entry) => {
      if (environmentId && entry.id !== environmentId) return false;
      if (projectIdFilter && entry.projectId !== projectIdFilter) return false;
      if (envIdFilter && entry.key !== envIdFilter) return false;
      return true;
    });
    const projectId = String(environment?.projectId || '').trim();
    const envId = String(environment?.key || '').trim();
    const signingRootVersion = String(environment?.signingRootVersion || '').trim();
    return projectId && envId && signingRootVersion
      ? { projectId, envId, signingRootVersion }
      : undefined;
  } catch {
    return undefined;
  }
}
