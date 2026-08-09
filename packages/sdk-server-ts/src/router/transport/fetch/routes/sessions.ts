import {
  DEFAULT_SESSION_COOKIE_NAME,
  deriveJwtExpiresAtIso,
  parseSessionKind,
} from '../../../framework/routerApi';
import {
  extractBearerCredential,
  resolveSourceIpFromFetchHeaders,
} from '../../../auth/routerApiKeyAuth';
import { emitRouterApiWebhookEvent } from '../../../framework/routerApiWebhooks';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { headersToRecord, json, readJson } from '../../../framework/http';
import { resolveThresholdRuntimePolicyScope } from '../../../auth/commonRouterUtils';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  handleWalletUnlockChallengeRoute,
  handleWalletUnlockVerifyRoute,
  type WalletUnlockEcdsaCustodySignerV1,
  type WalletUnlockEcdsaSessionContext,
  type WalletUnlockCapabilityContext,
} from '../../../domains/walletUnlock/walletUnlockRouteHandlers';
import { handleStrictEcdsaSessionActivation } from './thresholdEcdsa';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  routerApiEmailOtpRouteService,
  type EmailOtpChallengeDelivery,
} from '../../../framework/authServicePort';
import {
  handleEmailOtpDevCleanupGoogleRegistrationRoute,
  handleEmailOtpDevOtpOutboxRoute,
  handleEmailOtpDeviceRecoveryChallengeRoute,
  handleEmailOtpLoginChallengeRoute,
  handleEmailOtpLoginVerifyAndUnsealRoute,
  handleEmailOtpRecoveryKeyAttemptFailedRoute,
  handleEmailOtpRecoveryKeyConsumeRoute,
  handleEmailOtpRecoveryKeyRotateRoute,
  handleEmailOtpRecoveryKeyStatusRoute,
  handleEmailOtpRecoveryWrappedEscrowsRoute,
  handleEmailOtpSigningSessionChallengeRoute,
  handleEmailOtpLoginVerifyRoute,
  handleEmailOtpSigningSessionVerifyRoute,
  handleEmailOtpRegistrationChallengeRoute,
  handleEmailOtpRegistrationFinalizeRoute,
  handleEmailOtpRegistrationSealRoute,
  handleEmailOtpUnsealRoute,
  handleEmailOtpSigningSessionUnsealRoute,
} from '../../../domains/emailOtp/emailOtpRouteHandlers';
import {
  emailOtpChallengeResponseBody,
  emailOtpStatusCode,
  emailOtpFailureAuditPayload,
  emailOtpAppSessionClaimsForSubject,
  hashEmailOtpAppSessionClaims,
  hashEmailOtpSigningSessionClaims,
} from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import {
  parseSessionExchangeRouteCommand,
  type SessionExchangeRouteCommand,
} from '../../../auth/sessionExchangeRequestValidation';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import {
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
} from '../../../../core/ThresholdService/validation';
import {
  parseGoogleProviderSubject,
  parseVerifiedGoogleEmail,
  parseWalletId,
} from '@shared/utils/domainIds';
import { parseWalletUnlockRequestedCapabilitiesRequest } from '../../../domains/walletUnlock/walletUnlockRequestedCapabilitiesValidation';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { isPlainObject } from '@shared/utils/validation';
import {
  buildActiveAuthorizationSession,
  parseSessionOrigin,
  type ActiveAuthorizationSession,
  type RedeemHostedWalletSeamsSessionExchangeResult,
  type SessionOrigin,
} from '../../../../authorization/domain';
import {
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  parseWalletSessionId,
  type AuthorizationParseResult,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseAppSessionVersion,
  parseProviderSubject,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type DomainIdParseResult,
} from '@shared/utils/domainIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../../../domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';

const HOSTED_WALLET_SESSION_EXCHANGE_TTL_MS = 60_000;

type PasskeySessionCustodyUnlockV1 = {
  readonly kind: 'wallet_custody_passkey_login_v1';
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly storeVersion: string;
  readonly ed25519:
    | { readonly kind: 'absent' }
    | {
        readonly kind: 'active';
        readonly nearAccountId: string;
        readonly nearEd25519SigningKeyId: string;
        readonly signerSlot: number;
        readonly publicKey: string;
        readonly relayerKeyId: string;
        readonly participantIds: readonly [number, number];
        readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
      };
};

type SessionExchangeTimingPhase =
  | 'request_validation'
  | 'webauthn_verification'
  | 'runtime_scope'
  | 'session_version'
  | 'jwt_signing'
  | 'active_session_commit'
  | 'ecdsa_activation'
  | 'strong_auth_commit'
  | 'total';

type SessionExchangeTimings = Partial<Record<SessionExchangeTimingPhase, number>>;

function recordSessionExchangeTiming(
  timings: SessionExchangeTimings,
  phase: SessionExchangeTimingPhase,
  startedAt: number,
): void {
  timings[phase] = Math.max(0, performance.now() - startedAt);
}

function sessionExchangeServerTiming(timings: SessionExchangeTimings): string {
  return Object.entries(timings)
    .map(([phase, durationMs]) => `${phase};dur=${Number(durationMs).toFixed(1)}`)
    .join(', ');
}

async function emitSessionExchangeSucceeded(
  ctx: FetchRouterApiContext,
  input: {
    provider: 'oidc' | 'passkey';
    sessionKind: string;
    appSessionVersion: string;
    userId: string;
    passkeyChallengeId?: string;
  },
): Promise<void> {
  await emitRouterApiWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.routerApiWebhooks,
    eventType: 'session.warm.created',
    userId: input.userId,
    payload: {
      kind: 'app_session_v1',
      provider: input.provider,
      sessionKind: input.sessionKind,
      appSessionVersion: input.appSessionVersion,
    },
  });
  if (input.provider !== 'passkey') return;
  await emitRouterApiWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.routerApiWebhooks,
    eventType: 'wallet.unlocked',
    userId: input.userId,
    eventId: input.passkeyChallengeId,
    payload: {
      unlocked: true,
      method: 'passkey',
      ...(input.passkeyChallengeId ? { challengeId: input.passkeyChallengeId } : {}),
    },
  });
}

async function dispatchSessionExchangeSucceeded(
  ctx: FetchRouterApiContext,
  input: Parameters<typeof emitSessionExchangeSucceeded>[1],
): Promise<void> {
  const emission = emitSessionExchangeSucceeded(ctx, input);
  if (input.provider === 'passkey' && ctx.runtime.kind === 'background') {
    ctx.runtime.waitUntil(emission);
    return;
  }
  await emission;
}

function projectWalletUnlockEcdsaCustodySigner(
  signer: Awaited<
    ReturnType<FetchRouterApiContext['service']['walletRegistration']['listWalletEcdsaCustodyContinuity']>
  >[number],
): WalletUnlockEcdsaCustodySignerV1 {
  return {
    chainTarget: signer.chainTarget,
    walletKey: {
      walletId: signer.walletKey.walletId,
      keyHandle: signer.walletKey.keyHandle,
      ecdsaThresholdKeyId: signer.walletKey.ecdsaThresholdKeyId,
      signingRootId: signer.walletKey.signingRootId,
      signingRootVersion: signer.walletKey.signingRootVersion,
      relayerKeyId: signer.walletKey.relayerKeyId,
      contextBinding32B64u: signer.walletKey.contextBinding32B64u,
      derivationClientSharePublicKey33B64u:
        signer.walletKey.derivationClientSharePublicKey33B64u,
      participantIds: signer.walletKey.participantIds,
      publicCapability: signer.walletKey.publicCapability,
    },
    activationReceipt: signer.activationReceipt,
    runtimePolicyScope: signer.runtimePolicyScope,
  };
}

type WalletUnlockEcdsaAuthoredRequest = {
  readonly request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
  readonly activationReceipt: WalletUnlockEcdsaCustodySignerV1['activationReceipt'];
  readonly continuity: {
    readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
    readonly signers: readonly WalletUnlockEcdsaCustodySignerV1[];
  };
};

async function authorWalletUnlockEcdsaRequest(
  ctx: FetchRouterApiContext,
  walletId: string,
  policy: ReturnType<typeof parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1>,
): Promise<
  | { readonly ok: true; readonly value: WalletUnlockEcdsaAuthoredRequest }
  | { readonly ok: false; readonly status: number; readonly code: string; readonly message: string }
> {
  const signers = await ctx.service.walletRegistration.listWalletEcdsaCustodyContinuity({
    walletId,
  });
  const matching = signers.filter((signer) => signer.walletKey.keyHandle === policy.key_handle);
  const first = matching[0];
  if (!first) {
    return {
      ok: false,
      status: 404,
      code: 'ecdsa_key_not_found',
      message: 'ECDSA key handle is not active for this wallet',
    };
  }
  const requestedScope = normalizeRuntimePolicyScope(policy.session_policy.runtime_policy_scope);
  if (
    matching.some(
      (signer) =>
        alphabetizeStringify(signer.runtimePolicyScope) !== alphabetizeStringify(requestedScope) ||
        alphabetizeStringify(signer.walletKey.publicCapability) !==
          alphabetizeStringify(first.walletKey.publicCapability) ||
        alphabetizeStringify(signer.activationReceipt) !==
          alphabetizeStringify(first.activationReceipt),
    )
  ) {
    return {
      ok: false,
      status: 409,
      code: 'ecdsa_key_continuity_conflict',
      message: 'ECDSA key handle resolves to conflicting active custody records',
    };
  }
  return {
    ok: true,
    value: {
      request: {
        kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
        public_capability: first.walletKey.publicCapability,
        session_policy: policy.session_policy,
      },
      activationReceipt: first.activationReceipt,
      continuity: {
        kind: 'wallet_custody_ecdsa_sync_continuity_v1',
        signers: matching.map(projectWalletUnlockEcdsaCustodySigner),
      },
    },
  };
}

function walletUnlockEcdsaSessionContext(
  ctx: FetchRouterApiContext,
  body: unknown,
): WalletUnlockEcdsaSessionContext {
  if (isPlainObject(body) && body.ecdsaSessionActivation !== undefined) {
    throw new Error('ecdsaSessionActivation is no longer accepted; send ecdsaSessionPolicy');
  }
  if (!isPlainObject(body) || body.ecdsaSessionPolicy === undefined) {
    return { kind: 'no_ecdsa_session' };
  }
  const policy = parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1(
    body.ecdsaSessionPolicy,
  );
  const walletId = String(body.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required with ecdsaSessionPolicy');
  return {
    kind: 'provision_first_ecdsa_session',
    walletId,
    policy,
    provisionWalletSession: async (authorization) => {
      const authored = await authorWalletUnlockEcdsaRequest(ctx, walletId, policy);
      if (!authored.ok) return authored;
      const { request, activationReceipt, continuity } = authored.value;
      let response: Response;
      if (authorization.kind === 'reuse_ed25519_wallet_session') {
        response = await handleStrictEcdsaSessionActivation({
          ctx,
          body: request,
          source: 'verified_ed25519_wallet_session',
          walletSessionJwt: authorization.walletSessionJwt,
        });
      } else {
        let verifiedAuthority: WalletAuthAuthorityRef | undefined;
        if (authorization.verifiedProviderUserId) {
          const resolvedAuthority =
            await ctx.service.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject({
              walletId,
              providerUserId: authorization.verifiedProviderUserId,
            });
          if (!resolvedAuthority.ok) {
            return {
              ok: false,
              status: 403,
              code: resolvedAuthority.code,
              message: resolvedAuthority.message,
            };
          }
          verifiedAuthority = await walletAuthAuthorityRef({
            authority: resolvedAuthority.authority,
          });
        }
        response = await handleStrictEcdsaSessionActivation({
          ctx,
          body: request,
          source: 'verified_wallet_unlock',
          verifiedAuthority,
        });
      }
      const responseBody: unknown = await response.json();
      if (!response.ok) {
        const failure = isPlainObject(responseBody) ? responseBody : {};
        return {
          ok: false,
          status: response.status,
          code: String(failure.code || 'ecdsa_session_activation_failed'),
          message: String(failure.message || 'ECDSA Wallet Session activation failed'),
        };
      }
      return {
        ok: true,
        activation: parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(responseBody),
        activationReceipt,
        continuity,
      };
    },
  };
}

async function emitSessionExchangeFailed(
  ctx: FetchRouterApiContext,
  input: {
    code: string;
    message: string;
    status: number;
    exchangeType?: string;
    sessionKind?: string;
    userId?: string;
  },
): Promise<void> {
  await emitRouterApiWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.routerApiWebhooks,
    eventType: 'session.exchange.failed',
    userId: input.userId,
    payload: {
      code: input.code,
      message: input.message,
      status: input.status,
      exchangeType: input.exchangeType || 'unknown',
      sessionKind: input.sessionKind || 'jwt',
    },
  });
}

async function emitEmailOtpWebhookEvent(
  ctx: FetchRouterApiContext,
  input: {
    eventType: string;
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId?: string;
    eventId?: string;
    payload?: Record<string, unknown>;
  },
): Promise<void> {
  await emitRouterApiWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.routerApiWebhooks,
    eventType: input.eventType,
    claims: input.claims || undefined,
    userId: input.userId,
    ...(input.eventId ? { eventId: input.eventId } : {}),
    payload: {
      ...(input.walletId ? { walletId: input.walletId } : {}),
      ...(input.payload || {}),
    },
  });
}

async function emitEmailOtpWebhookDescriptor(
  ctx: FetchRouterApiContext,
  input: {
    descriptor: { eventType: string; eventId?: string; payload: Record<string, unknown> };
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId?: string;
  },
): Promise<void> {
  await emitEmailOtpWebhookEvent(ctx, {
    eventType: input.descriptor.eventType,
    claims: input.claims,
    userId: input.userId,
    walletId: input.walletId,
    ...(input.descriptor.eventId ? { eventId: input.descriptor.eventId } : {}),
    payload: input.descriptor.payload,
  });
}

function hasBearerSessionSignal(ctx: FetchRouterApiContext): boolean {
  const authorization = String(ctx.request.headers.get('authorization') || '').trim();
  return authorization.toLowerCase().startsWith('bearer ');
}

function hasCookieSessionSignal(ctx: FetchRouterApiContext): boolean {
  const cookie = String(ctx.request.headers.get('cookie') || '').trim();
  if (!cookie) return false;
  const cookieName = String(ctx.opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
  for (const part of cookie.split(';')) {
    const chunk = String(part || '').trim();
    if (!chunk) continue;
    const equalsIndex = chunk.indexOf('=');
    const name = (equalsIndex >= 0 ? chunk.slice(0, equalsIndex) : chunk).trim();
    if (name === cookieName) return true;
  }
  return false;
}

type ValidAppSessionValidation = {
  ok: true;
  claims: any;
  userId: string;
  appSessionVersion: string;
};

type InvalidAppSessionValidation = {
  ok: false;
  response: Response;
  code: string;
  message: string;
  claims?: any;
  userId?: string;
  appSessionVersion?: string;
  hadBearerSessionSignal?: boolean;
  hadCookieSessionSignal?: boolean;
};

type AppSessionValidation = ValidAppSessionValidation | InvalidAppSessionValidation;

function sessionStateFailureResponse(validated: InvalidAppSessionValidation): Response {
  const code = String(validated.code || 'unauthorized').trim() || 'unauthorized';
  const message = String(validated.message || 'No valid session').trim() || 'No valid session';
  return json(
    {
      authenticated: false,
      code,
      message,
    },
    { status: code === 'internal' ? 500 : 200 },
  );
}

async function readAndValidateAppSession(
  ctx: FetchRouterApiContext,
): Promise<AppSessionValidation> {
  const session = ctx.opts.session;
  if (!session) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured',
      response: json(
        { authenticated: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
        { status: 501 },
      ),
    };
  }

  const parsed = await session.parse(headersToRecord(ctx.request.headers));
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'No valid session',
      hadBearerSessionSignal: hasBearerSessionSignal(ctx),
      hadCookieSessionSignal: hasCookieSessionSignal(ctx),
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'No valid session' },
        { status: 401 },
      ),
    };
  }

  const claims: any = (parsed as any).claims || {};
  const kindRaw = (claims as any).kind;
  const kind = typeof kindRaw === 'string' ? kindRaw.trim() : '';
  if (kind !== 'app_session_v1') {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'No valid app session',
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'No valid app session' },
        { status: 401 },
      ),
    };
  }
  const userId = String((claims as any).sub || '').trim();
  const appSessionVersion =
    typeof (claims as any).appSessionVersion === 'string'
      ? String((claims as any).appSessionVersion).trim()
      : '';
  if (!userId || !appSessionVersion) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Invalid app session',
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'Invalid app session' },
        { status: 401 },
      ),
    };
  }
  const validated = await ctx.service.sessionVersions.validateAppSessionVersion({
    userId,
    appSessionVersion,
  });
  if (!validated.ok) {
    return {
      ok: false,
      code: validated.code,
      message: validated.message,
      claims,
      userId,
      appSessionVersion,
      response: json(
        { authenticated: false, code: validated.code, message: validated.message },
        { status: validated.code === 'internal' ? 500 : 401 },
      ),
    };
  }
  return { ok: true, claims, userId, appSessionVersion };
}

async function readWalletUnlockSourceSession(ctx: FetchRouterApiContext): Promise<
  | {
      readonly ok: true;
      readonly sessionId: ActiveAuthorizationSession['sessionId'];
      readonly principalId: ActiveAuthorizationSession['principalId'];
      readonly walletId: string;
    }
  | { readonly ok: false; readonly response: Response }
> {
  const session = ctx.opts.session;
  if (!session) {
    return {
      ok: false,
      response: json(
        { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
        { status: 501 },
      ),
    };
  }
  try {
    const parsed = await session.parse(headersToRecord(ctx.request.headers));
    if (!parsed.ok) throw new Error('No valid authorization session');
    const ed25519WalletSession = parseRouterAbEd25519WalletSessionClaims(parsed.claims);
    if (ed25519WalletSession) {
      const sessionId = ed25519WalletSession.sid;
      if (!sessionId) throw new Error('Wallet Session app-session binding is missing');
      const principalSubject =
        ed25519WalletSession.authority.factor.kind === 'email_otp'
          ? ed25519WalletSession.authority.factor.providerUserId
          : ed25519WalletSession.authority.walletId;
      const principalId = requiredAuthorizationValue(parsePrincipalId(principalSubject));
      const activeSession = await ctx.service.authorizationSessions.readActiveSession({
        tenantId: ctx.service.authorizationSessions.tenantId,
        sessionId,
        nowMs: Date.now(),
      });
      if (!activeSession || activeSession.principalId !== principalId) {
        throw new Error('Wallet Session authorization is unavailable');
      }
      return {
        ok: true,
        sessionId,
        principalId,
        walletId: ed25519WalletSession.walletId,
      };
    }
    const validated = await readAndValidateAppSession(ctx);
    if (!validated.ok) return { ok: false, response: validated.response };
    const claims = validated.claims as Record<string, unknown>;
    const sourceIds = sourceSessionClaimIds(claims);
    const walletId = String(claims.walletId || '').trim();
    if (!walletId) throw new Error('App session wallet identity is missing');
    const activeSession = await ctx.service.authorizationSessions.readActiveSession({
      tenantId: ctx.service.authorizationSessions.tenantId,
      sessionId: sourceIds.sessionId,
      nowMs: Date.now(),
    });
    if (!activeSession || activeSession.principalId !== sourceIds.principalId) {
      throw new Error('App session authorization is unavailable');
    }
    return {
      ok: true,
      sessionId: sourceIds.sessionId,
      principalId: sourceIds.principalId,
      walletId,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: error instanceof Error ? error.message : 'App session is invalid',
        },
        { status: 401 },
      ),
    };
  }
}

async function hashAppSessionClaims(claims: Record<string, unknown>): Promise<string> {
  return hashEmailOtpAppSessionClaims(claims);
}

async function readAndValidateEmailOtpSigningSession(ctx: FetchRouterApiContext): Promise<
  | {
      ok: true;
      claims: Record<string, unknown>;
      userId: string;
      appSessionVersion: string;
      sessionHash: string;
      thresholdSessionId: string;
    }
  | { ok: false; response: Response }
> {
  const session = ctx.opts.session;
  if (!session) {
    return {
      ok: false,
      response: json(
        { authenticated: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
        { status: 501 },
      ),
    };
  }
  let parsed: Awaited<ReturnType<typeof session.parse>>;
  try {
    parsed = await session.parse(headersToRecord(ctx.request.headers));
  } catch {
    return {
      ok: false,
      response: json(
        {
          authenticated: false,
          code: 'wallet_session_unavailable',
          message: 'Wallet Session status is unavailable',
        },
        { status: 503 },
      ),
    };
  }
  if (!parsed.ok) {
    return {
      ok: false,
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'No valid Wallet Session' },
        { status: 401 },
      ),
    };
  }
  const claims = parsed.claims;
  const walletSession =
    parseRouterAbEcdsaDerivationWalletSessionClaims(claims) ||
    parseRouterAbEd25519WalletSessionClaims(claims);
  if (!walletSession) {
    return {
      ok: false,
      response: json(
        {
          authenticated: false,
          code: 'wallet_session_claims_invalid',
          message: 'Wallet Session claims are invalid',
        },
        { status: 401 },
      ),
    };
  }
  if (walletSession.thresholdExpiresAtMs <= Date.now()) {
    return {
      ok: false,
      response: json(
        {
          authenticated: false,
          code: 'wallet_session_expired',
          message: 'Wallet Session expired',
        },
        { status: 401 },
      ),
    };
  }
  return {
    ok: true,
    claims,
    userId: walletSession.walletId,
    appSessionVersion: `signing-session:${walletSession.kind}:${walletSession.walletSessionId}:${walletSession.quotaId}:${walletSession.thresholdSessionId}`,
    sessionHash: await hashEmailOtpSigningSessionClaims(claims),
    thresholdSessionId: walletSession.thresholdSessionId,
  };
}

async function maybeEmitWarmExpiredFromValidationFailure(input: {
  ctx: FetchRouterApiContext;
  validated:
    | { ok: true; claims: any; userId: string; appSessionVersion: string }
    | {
        ok: false;
        response: Response;
        code?: string;
        message?: string;
        claims?: any;
        userId?: string;
        appSessionVersion?: string;
        hadBearerSessionSignal?: boolean;
        hadCookieSessionSignal?: boolean;
      };
  source: string;
  sessionKind?: string;
}): Promise<void> {
  if (input.validated.ok) return;
  const code = String(input.validated.code || '').trim();
  const shouldEmit =
    code === 'invalid_session_version' ||
    (code === 'unauthorized' &&
      (Boolean(input.validated.hadBearerSessionSignal) ||
        Boolean(input.validated.hadCookieSessionSignal)));
  if (!shouldEmit) return;
  await emitRouterApiWebhookEvent({
    logger: input.ctx.logger,
    webhooks: input.ctx.opts.routerApiWebhooks,
    eventType: 'session.warm.expired',
    claims: input.validated.claims,
    userId: input.validated.userId,
    payload: {
      expired: true,
      source: input.source,
      reason: String(input.validated.message || 'Session expired'),
      sessionKind: input.sessionKind || 'jwt',
      code,
      ...(input.validated.appSessionVersion
        ? { appSessionVersion: input.validated.appSessionVersion }
        : {}),
    },
  });
}

export async function handleSessionState(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== ctx.mePath && ctx.pathname !== '/session/state') return null;

  try {
    const validated = await readAndValidateAppSession(ctx);
    if (!validated.ok) {
      await maybeEmitWarmExpiredFromValidationFailure({
        ctx,
        validated,
        source: 'session.state',
      });
      return sessionStateFailureResponse(validated);
    }
    return json({ authenticated: true, claims: validated.claims }, { status: 200 });
  } catch (e: any) {
    return json(
      { authenticated: false, code: 'internal', message: e?.message || 'Internal error' },
      { status: 500 },
    );
  }
}

function requiredAuthorizationValue<T>(
  parsed: AuthorizationParseResult<T> | DomainIdParseResult<T>,
): T {
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function sourceSessionClaimIds(claims: Record<string, unknown>): {
  readonly sessionId: ActiveAuthorizationSession['sessionId'];
  readonly principalId: ActiveAuthorizationSession['principalId'];
} {
  return {
    sessionId: requiredAuthorizationValue(parseSeamsSessionId(claims.seamsSessionId)),
    principalId: requiredAuthorizationValue(parsePrincipalId(claims.sub)),
  };
}

async function handleHostedWalletExchangeCodeIssue(
  ctx: FetchRouterApiContext,
  command: Extract<SessionExchangeRouteCommand, { kind: 'hosted_wallet_exchange_code' }>,
): Promise<Response> {
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) return validated.response;
  const claims = validated.claims as Record<string, unknown>;
  let sourceIds: ReturnType<typeof sourceSessionClaimIds>;
  let appOrigin: SessionOrigin;
  let walletOrigin: SessionOrigin;
  try {
    sourceIds = sourceSessionClaimIds(claims);
    appOrigin = parseSessionOrigin(ctx.request.headers.get('origin'));
    walletOrigin = command.walletOrigin;
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_session_exchange_context',
        message: error instanceof Error ? error.message : 'Invalid session exchange context',
      },
      { status: 400 },
    );
  }
  try {
    const issuedAtMs = Date.now();
    const delivery = await ctx.service.authorizationSessions.mintHostedWalletSeamsSessionExchange({
      tenantId: ctx.service.authorizationSessions.tenantId,
      principalId: sourceIds.principalId,
      sourceSessionId: sourceIds.sessionId,
      appOrigin,
      walletOrigin,
      issuedAtMs,
      expiresAtMs: issuedAtMs + HOSTED_WALLET_SESSION_EXCHANGE_TTL_MS,
    });
    return json({ ok: true, delivery }, { status: 200 });
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'source_session_unavailable',
        message: error instanceof Error ? error.message : 'Source session is unavailable',
      },
      { status: 401 },
    );
  }
}

function hostedWalletRedeemStatus(
  result: Exclude<RedeemHostedWalletSeamsSessionExchangeResult, { kind: 'redeemed' }>,
): number {
  switch (result.kind) {
    case 'invalid_code':
    case 'nonce_mismatch':
      return 401;
    case 'wallet_origin_mismatch':
      return 403;
    case 'already_consumed':
      return 409;
    case 'expired':
    case 'source_session_unavailable':
      return 410;
  }
}

async function handleHostedWalletExchangeCodeRedeem(
  ctx: FetchRouterApiContext,
  command: Extract<SessionExchangeRouteCommand, { kind: 'hosted_wallet_exchange_code_redeem' }>,
): Promise<Response> {
  const session = ctx.opts.session;
  if (!session) {
    return json(
      { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
      { status: 501 },
    );
  }
  let walletOrigin: SessionOrigin;
  try {
    walletOrigin = parseSessionOrigin(ctx.request.headers.get('origin'));
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_session_exchange_context',
        message: error instanceof Error ? error.message : 'Invalid wallet origin',
      },
      { status: 400 },
    );
  }
  const result = await ctx.service.authorizationSessions.redeemHostedWalletSeamsSessionExchange({
    exchangeCode: command.exchangeCode,
    nonce: command.nonce,
    walletOrigin,
    redeemedAtMs: Date.now(),
  });
  if (result.kind !== 'redeemed') {
    return json(
      {
        ok: false,
        code: result.kind,
        message: 'Hosted-wallet Seams session exchange could not be redeemed',
      },
      { status: hostedWalletRedeemStatus(result) },
    );
  }
  const target = result.session;
  const claims = {
    kind: 'app_session_v1',
    appSessionVersion: target.appSessionVersion,
    tenantId: target.tenantId,
    seamsSessionId: target.sessionId,
    deviceId: target.deviceId,
    authSource: target.authSource,
    sessionAudience: target.audience,
  };
  const jwt = await session.signJwt(target.principalId, claims);
  return json(
    {
      ok: true,
      session: {
        kind: 'app_session_v1',
        userId: target.principalId,
        tenantId: target.tenantId,
        seamsSessionId: target.sessionId,
        deviceId: target.deviceId,
        audience: target.audience,
        expiresAtMs: target.lifecycle.expiresAtMs,
      },
      jwt,
    },
    { status: 200 },
  );
}

export async function handleSessionExchange(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/session/exchange') return null;

  const exchangeStartedAt = performance.now();
  const timings: SessionExchangeTimings = {};
  try {
    const validationStartedAt = performance.now();
    const body = await readJson(ctx.request);
    const parsedExchange = parseSessionExchangeRouteCommand(body);
    recordSessionExchangeTiming(timings, 'request_validation', validationStartedAt);
    if (!parsedExchange.ok) {
      await emitSessionExchangeFailed(ctx, {
        status: 400,
        code: parsedExchange.body.code,
        message: parsedExchange.body.message,
        exchangeType: parsedExchange.exchangeType,
        sessionKind: parsedExchange.sessionKind,
      });
      return json(parsedExchange.body, { status: 400 });
    }
    const command = parsedExchange.command;
    const sessionKind = command.sessionKind;
    const exchangeType = command.kind;

    const session = ctx.opts.session;
    if (!session) {
      await emitSessionExchangeFailed(ctx, {
        status: 501,
        code: 'sessions_disabled',
        message: 'Sessions are not configured',
        exchangeType,
        sessionKind,
      });
      return json(
        { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
        { status: 501 },
      );
    }

    if (command.kind === 'hosted_wallet_exchange_code') {
      return await handleHostedWalletExchangeCodeIssue(ctx, command);
    }
    if (command.kind === 'hosted_wallet_exchange_code_redeem') {
      return await handleHostedWalletExchangeCodeRedeem(ctx, command);
    }

    let userId = '';
    let provider: 'oidc' | 'passkey' = 'oidc';
    let providerSubject: string | undefined;
    let oidcIssuer: string | undefined;
    let oidcSub: string | undefined;
    let oidcAud: string[] | undefined;
    let oidcEmail: string | undefined;
    let oidcEmailVerified: boolean | undefined;
    let oidcHostedDomain: string | undefined;
    let oidcName: string | undefined;
    let oidcGivenName: string | undefined;
    let oidcFamilyName: string | undefined;
    let oidcProvider: string | undefined;
    let oidcAccountMode: 'register' | 'login' | undefined;
    let oidcRestartRegistrationOffer = false;
    let passkeyChallengeId: string | undefined;
    let passkeyCredentialIdB64u: string | undefined;
    let passkeyAuthorityRef: WalletAuthAuthorityRef | undefined;
    let passkeyCustodyUnlock: PasskeySessionCustodyUnlockV1 | undefined;
    let emailOtpAuthorityRef: WalletAuthAuthorityRef | undefined;
    let walletId: string | undefined;
    let googleEmailOtpResolution:
      | {
          mode: 'existing_wallet' | 'register_started';
          registrationAttemptId?: string;
          expiresAtMs?: number;
          offer?: {
            offerId: string;
            selectedCandidateId: string;
            candidates: readonly { candidateId: string; walletId: string }[];
          };
          loginChallenge?:
            | {
                delivery: 'sent' | 'reused';
                deliveryDetails: EmailOtpChallengeDelivery;
                challengeId: string;
                emailHint?: string;
                expiresAtMs: number;
              }
            | {
                delivery: 'rate_limited';
                retryAfterMs?: number;
                resetAtMs?: number;
              };
        }
      | undefined;
    let runtimePolicyScope: RuntimePolicyScope | undefined;
    let appSessionVersion = '';
    let isGoogleEmailOtpExchange = false;

    const resolveRuntimePolicyScopeForExchange = async (
      failureUserId?: string,
    ): Promise<{ ok: true; scope?: RuntimePolicyScope } | { ok: false; response: Response }> => {
      const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
        explicitScopeRaw: undefined,
        projectEnvironmentIdRaw: command.projectEnvironmentId,
        headers: ctx.request.headers,
        origin: ctx.request.headers.get('origin'),
        publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
        orgProjectEnv: ctx.opts.orgProjectEnv || null,
      });
      if (!runtimePolicyScopeResolution.ok) {
        await emitSessionExchangeFailed(ctx, {
          status: runtimePolicyScopeResolution.status,
          code: runtimePolicyScopeResolution.code,
          message: runtimePolicyScopeResolution.message,
          exchangeType,
          sessionKind,
          userId: failureUserId,
        });
        return {
          ok: false,
          response: json(
            {
              ok: false,
              code: runtimePolicyScopeResolution.code,
              message: runtimePolicyScopeResolution.message,
            },
            { status: runtimePolicyScopeResolution.status },
          ),
        };
      }
      return { ok: true, scope: runtimePolicyScopeResolution.scope };
    };

    const requireRuntimePolicyScopeForOidcWallet = async (): Promise<
      { ok: true } | { ok: false; response: Response }
    > => {
      if (!runtimePolicyScope) {
        const resolution = await resolveRuntimePolicyScopeForExchange(userId);
        if (!resolution.ok) return resolution;
        runtimePolicyScope = resolution.scope;
      }
      if (runtimePolicyScope) return { ok: true };
      await emitSessionExchangeFailed(ctx, {
        status: 400,
        code: 'invalid_body',
        message: 'session/exchange OIDC wallet derivation requires projectEnvironmentId',
        exchangeType,
        sessionKind,
        userId,
      });
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'session/exchange OIDC wallet derivation requires projectEnvironmentId',
          },
          { status: 400 },
        ),
      };
    };

    if (command.kind === 'oidc_jwt') {
      oidcProvider = command.provider;
      oidcAccountMode = command.accountMode;
      oidcRestartRegistrationOffer = command.restartRegistrationOffer;
      isGoogleEmailOtpExchange = oidcProvider === 'google' && Boolean(oidcAccountMode);
      const verified =
        oidcProvider === 'google'
          ? await ctx.service.identity.verifyGoogleLogin({ idToken: command.token })
          : await ctx.service.identity.verifyOidcJwtExchange({ token: command.token });
      if (!verified.ok) {
        const code = verified.code || 'not_verified';
        const status =
          code === 'internal'
            ? 500
            : code === 'not_configured' || code === 'unsupported'
              ? 501
              : code === 'invalid_body'
                ? 400
                : 401;
        await emitSessionExchangeFailed(ctx, {
          status,
          code,
          message: verified.message || 'OIDC exchange failed',
          exchangeType,
          sessionKind,
        });
        return json(
          { ok: false, code, message: verified.message || 'OIDC exchange failed' },
          { status },
        );
      }
      userId = String(verified.userId || '').trim();
      provider = 'oidc';
      providerSubject = verified.providerSubject;
      oidcIssuer =
        oidcProvider === 'google' ? 'https://accounts.google.com' : (verified as any).iss;
      oidcSub = verified.sub;
      oidcAud = Array.isArray((verified as any).aud) ? (verified as any).aud : undefined;
      oidcEmail =
        typeof verified.email === 'string' && verified.email.trim()
          ? verified.email.trim().toLowerCase()
          : undefined;
      if (oidcProvider === 'google') {
        oidcEmailVerified = 'emailVerified' in verified && verified.emailVerified === true;
        oidcHostedDomain =
          'hostedDomain' in verified &&
          typeof verified.hostedDomain === 'string' &&
          verified.hostedDomain.trim()
            ? verified.hostedDomain.trim().toLowerCase()
            : undefined;
      }
      oidcName =
        typeof (verified as any).name === 'string' && (verified as any).name.trim()
          ? (verified as any).name.trim()
          : undefined;
      oidcGivenName =
        typeof (verified as any).given_name === 'string' && (verified as any).given_name.trim()
          ? (verified as any).given_name.trim()
          : undefined;
      oidcFamilyName =
        typeof (verified as any).family_name === 'string' && (verified as any).family_name.trim()
          ? (verified as any).family_name.trim()
          : undefined;
      if (
        isGoogleEmailOtpExchange &&
        oidcAccountMode === 'register' &&
        (!oidcEmail || oidcEmailVerified !== true)
      ) {
        await emitSessionExchangeFailed(ctx, {
          status: 400,
          code: 'invalid_claims',
          message: 'Google id_token must include verified email for Email OTP registration',
          exchangeType,
          sessionKind,
          userId,
        });
        return json(
          {
            ok: false,
            code: 'invalid_claims',
            message: 'Google id_token must include verified email for Email OTP registration',
          },
          { status: 400 },
        );
      }
      if (isGoogleEmailOtpExchange && oidcAccountMode === 'register') {
        const googleProviderSubject = parseGoogleProviderSubject(providerSubject);
        const verifiedGoogleEmail = parseVerifiedGoogleEmail(oidcEmail);
        if (!googleProviderSubject.ok || !verifiedGoogleEmail.ok) {
          let message = 'Invalid Google registration claims';
          if (!googleProviderSubject.ok) {
            message = googleProviderSubject.error.message;
          } else if (!verifiedGoogleEmail.ok) {
            message = verifiedGoogleEmail.error.message;
          }
          await emitSessionExchangeFailed(ctx, {
            status: 400,
            code: 'invalid_claims',
            message,
            exchangeType,
            sessionKind,
            userId,
          });
          return json({ ok: false, code: 'invalid_claims', message }, { status: 400 });
        }
        providerSubject = googleProviderSubject.value;
        oidcEmail = verifiedGoogleEmail.value;
      }
      try {
        if (isGoogleEmailOtpExchange) {
          const scoped = await requireRuntimePolicyScopeForOidcWallet();
          if (!scoped.ok) return scoped.response;
          if (oidcAccountMode === 'register') {
            const appVersion = await ctx.service.sessionVersions.getOrCreateAppSessionVersion({
              userId,
            });
            if (!appVersion.ok) {
              await emitSessionExchangeFailed(ctx, {
                status: appVersion.code === 'internal' ? 500 : 400,
                code: appVersion.code,
                message: appVersion.message,
                exchangeType,
                sessionKind,
                userId,
              });
              return json(
                { ok: false, code: appVersion.code, message: appVersion.message },
                { status: appVersion.code === 'internal' ? 500 : 400 },
              );
            }
            appSessionVersion = appVersion.appSessionVersion;
          }
          if (oidcAccountMode === 'register') {
            const rateLimit =
              await ctx.service.identity.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
                providerSubject,
                email: oidcEmail,
                accountMode: oidcAccountMode,
                restartRegistrationOffer: oidcRestartRegistrationOffer,
                runtimePolicyScope,
                appSessionUserId: userId,
                clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
              });
            if (!rateLimit.ok) {
              const status = emailOtpStatusCode(rateLimit.code);
              await emitSessionExchangeFailed(ctx, {
                status,
                code: rateLimit.code,
                message: rateLimit.message,
                exchangeType,
                sessionKind,
                userId,
              });
              return json(rateLimit, { status });
            }
          }
          const resolution = await ctx.service.identity.resolveGoogleEmailOtpSession({
            providerSubject,
            sub: oidcSub,
            email: oidcEmail,
            accountMode: oidcAccountMode,
            restartRegistrationOffer: oidcRestartRegistrationOffer,
            ...(appSessionVersion ? { appSessionVersion } : {}),
            runtimePolicyScope,
          });
          if (!resolution.ok) {
            const status = resolution.code === 'wallet_id_collision' ? 409 : 409;
            await emitSessionExchangeFailed(ctx, {
              status,
              code: resolution.code,
              message: resolution.message,
              exchangeType,
              sessionKind,
              userId,
            });
            return json(resolution, { status });
          }
          walletId = resolution.walletId;
          googleEmailOtpResolution = {
            mode: resolution.mode,
            ...(resolution.mode === 'register_started'
              ? {
                  registrationAttemptId: resolution.registrationAttemptId,
                  expiresAtMs: resolution.expiresAtMs,
                  offer: resolution.offer,
                }
              : {}),
          };
        } else if (oidcProvider !== 'google') {
          const scoped = await requireRuntimePolicyScopeForOidcWallet();
          if (!scoped.ok) return scoped.response;
          walletId = await ctx.service.identity.resolveOidcWalletId({
            providerSubject,
            sub: oidcSub,
            email: oidcEmail,
            accountMode: oidcAccountMode,
            runtimePolicyScope,
          });
        }
      } catch (e: any) {
        const code = typeof e?.code === 'string' && e.code ? e.code : 'internal';
        const status =
          code === 'not_found'
            ? 404
            : code === 'invalid_body'
              ? 400
              : code === 'already_linked' || code === 'stale_identity_mapping'
                ? 409
                : 500;
        const message = e?.message || 'Failed to resolve OIDC wallet id';
        await emitSessionExchangeFailed(ctx, {
          status,
          code,
          message,
          exchangeType,
          sessionKind,
          userId,
        });
        return json({ ok: false, code, message }, { status });
      }
      if (isGoogleEmailOtpExchange && oidcAccountMode === 'login') {
        const enrollment = await ctx.service.emailOtp.readEmailOtpEnrollment({
          walletId,
          orgId: runtimePolicyScope?.orgId,
        });
        if (!enrollment.ok) {
          const status = emailOtpStatusCode(enrollment.code);
          await emitSessionExchangeFailed(ctx, {
            status,
            code: enrollment.code,
            message: enrollment.message,
            exchangeType,
            sessionKind,
            userId,
          });
          return json(enrollment, { status });
        }
      }
    } else {
      const challengeId = command.challengeId;
      const webauthnAuthentication = command.webauthnAuthentication;
      const expectedOrigin = (() => {
        if (command.expectedOrigin) return command.expectedOrigin;
        const headerOrigin = String(ctx.request.headers.get('origin') || '').trim();
        return headerOrigin || undefined;
      })();
      const webauthnStartedAt = performance.now();
      const verified = await ctx.service.webAuthn.verifyWebAuthnLogin({
        challengeId,
        webauthn_authentication: webauthnAuthentication,
        expected_origin: expectedOrigin,
      });
      recordSessionExchangeTiming(timings, 'webauthn_verification', webauthnStartedAt);
      if (!verified.ok || !verified.verified || !verified.userId) {
        const code = verified.code || 'not_verified';
        const status = code === 'internal' ? 500 : code === 'invalid_body' ? 400 : 401;
        await emitSessionExchangeFailed(ctx, {
          status,
          code,
          message: verified.message || 'Passkey assertion exchange failed',
          exchangeType,
          sessionKind,
        });
        return json(
          { ok: false, code, message: verified.message || 'Passkey assertion exchange failed' },
          { status },
        );
      }
      userId = String(verified.userId || '').trim();
      walletId = userId;
      provider = 'passkey';
      passkeyChallengeId = challengeId;
      passkeyCredentialIdB64u = verified.credentialIdB64u;
      passkeyAuthorityRef = await walletAuthAuthorityRef({
        authority: buildPasskeyWalletAuthAuthority({
          walletId: userId,
          rpId: verified.rpId,
          credentialIdB64u: passkeyCredentialIdB64u,
        }),
      });
      const custodyRpId = parseWebAuthnRpId(verified.rpId);
      const custodyCredentialId = parseWebAuthnCredentialIdB64u(verified.credentialIdB64u);
      if (!custodyRpId.ok || !custodyCredentialId.ok) {
        throw new Error('Verified passkey custody identity is invalid');
      }
      const custodyEnvelope = await ctx.service.passkeyCustody.readVerifiedFactorCustody({
        walletId: walletIdFromString(verified.userId),
        factor: {
          kind: 'passkey',
          rpId: custodyRpId.value,
          credentialIdB64u: custodyCredentialId.value,
        },
      });
      if (custodyEnvelope.kind !== 'active') {
        throw new Error('Verified passkey has no unique active wallet custody envelope');
      }
      let ed25519: PasskeySessionCustodyUnlockV1['ed25519'] = { kind: 'absent' };
      if (verified.ed25519.kind === 'active') {
        const yaoRuntime = ctx.opts.routerAbEd25519YaoProduct;
        if (!yaoRuntime) {
          throw new Error('Ed25519 Yao product is not configured');
        }
        const capability = await yaoRuntime.resolveActiveCapability({
          kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
          walletId: userId,
          nearEd25519SigningKeyId: verified.ed25519.nearEd25519SigningKeyId,
          signerSlot: verified.ed25519.signerSlot,
          signingWorkerId: verified.ed25519.relayerKeyId,
          participantIds: verified.ed25519.participantIds,
        });
        if (!capability.ok) {
          throw new Error(capability.message);
        }
        ed25519 = {
          kind: 'active',
          nearAccountId: verified.ed25519.nearAccountId,
          nearEd25519SigningKeyId: verified.ed25519.nearEd25519SigningKeyId,
          signerSlot: verified.ed25519.signerSlot,
          publicKey: verified.ed25519.publicKey,
          relayerKeyId: verified.ed25519.relayerKeyId,
          participantIds: verified.ed25519.participantIds,
          capability: capability.capability,
        };
      }
      passkeyCustodyUnlock = {
        kind: 'wallet_custody_passkey_login_v1',
        envelope: custodyEnvelope.envelope,
        storeVersion: custodyEnvelope.storeVersion,
        ed25519,
      };
    }

    if (!userId) {
      await emitSessionExchangeFailed(ctx, {
        status: 500,
        code: 'internal',
        message: 'Exchange did not resolve userId',
        exchangeType,
        sessionKind,
      });
      return json(
        { ok: false, code: 'internal', message: 'Exchange did not resolve userId' },
        { status: 500 },
      );
    }

    if (!runtimePolicyScope) {
      const runtimeScopeStartedAt = performance.now();
      const resolution = await resolveRuntimePolicyScopeForExchange(userId);
      recordSessionExchangeTiming(timings, 'runtime_scope', runtimeScopeStartedAt);
      if (!resolution.ok) return resolution.response;
      runtimePolicyScope = resolution.scope;
    }

    if (!appSessionVersion) {
      const sessionVersionStartedAt = performance.now();
      const appVersion = await ctx.service.sessionVersions.getOrCreateAppSessionVersion({ userId });
      recordSessionExchangeTiming(timings, 'session_version', sessionVersionStartedAt);
      if (!appVersion.ok) {
        await emitSessionExchangeFailed(ctx, {
          status: appVersion.code === 'internal' ? 500 : 400,
          code: appVersion.code,
          message: appVersion.message,
          exchangeType,
          sessionKind,
          userId,
        });
        return json(
          { ok: false, code: appVersion.code, message: appVersion.message },
          { status: appVersion.code === 'internal' ? 500 : 400 },
        );
      }
      appSessionVersion = appVersion.appSessionVersion;
    }

    if (googleEmailOtpResolution?.mode === 'existing_wallet') {
      if (!walletId || !providerSubject) {
        throw new Error('Google Email OTP exchange did not resolve its wallet authority');
      }
      const resolvedAuthority =
        await ctx.service.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject({
          walletId,
          providerUserId: providerSubject,
        });
      if (!resolvedAuthority.ok) {
        const status =
          resolvedAuthority.code === 'unauthorized'
            ? 401
            : resolvedAuthority.code === 'invalid_body'
              ? 400
              : 500;
        await emitSessionExchangeFailed(ctx, {
          status,
          code: resolvedAuthority.code,
          message: resolvedAuthority.message,
          exchangeType,
          sessionKind,
          userId,
        });
        return json(
          {
            ok: false,
            code: resolvedAuthority.code,
            message: resolvedAuthority.message,
          },
          { status },
        );
      }
      emailOtpAuthorityRef = await walletAuthAuthorityRef({
        authority: resolvedAuthority.authority,
      });
    }

    let principalId: ActiveAuthorizationSession['principalId'];
    let seamsSessionId: ActiveAuthorizationSession['sessionId'];
    let deviceId: ActiveAuthorizationSession['deviceId'];
    let normalizedAppSessionVersion: ActiveAuthorizationSession['appSessionVersion'];
    let sessionOrigin: SessionOrigin;
    let authSource: ActiveAuthorizationSession['authSource'];
    try {
      principalId = requiredAuthorizationValue(parsePrincipalId(userId));
      seamsSessionId = requiredAuthorizationValue(
        parseSeamsSessionId(`ses_${secureRandomBase64Url(24, 'Seams Sessions')}`),
      );
      deviceId = requiredAuthorizationValue(
        parseDeviceId(`dev_${secureRandomBase64Url(18, 'session devices')}`),
      );
      normalizedAppSessionVersion = requiredAuthorizationValue(
        parseAppSessionVersion(appSessionVersion),
      );
      sessionOrigin = parseSessionOrigin(ctx.request.headers.get('origin'));
      authSource =
        provider === 'passkey'
          ? {
              kind: 'passkey',
              credentialIdB64u: requiredAuthorizationValue(
                parseWebAuthnCredentialIdB64u(passkeyCredentialIdB64u),
              ),
            }
          : {
              kind: 'oidc_provider',
              providerId: oidcProvider === 'google' ? 'google_oidc' : 'oidc',
              providerSubject: requiredAuthorizationValue(parseProviderSubject(providerSubject)),
            };
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Invalid authorization session context';
      await emitSessionExchangeFailed(ctx, {
        status: 400,
        code: 'invalid_session_exchange_context',
        message,
        exchangeType,
        sessionKind,
        userId,
      });
      return json(
        { ok: false, code: 'invalid_session_exchange_context', message },
        { status: 400 },
      );
    }

    const sessionClaims: Record<string, unknown> = {
      kind: 'app_session_v1',
      appSessionVersion,
      tenantId: ctx.service.authorizationSessions.tenantId,
      seamsSessionId,
      deviceId,
      authSource,
      sessionAudience: {
        kind: 'first_party_web',
        origin: sessionOrigin,
      },
      provider,
      ...(walletId ? { walletId } : {}),
      ...(googleEmailOtpResolution?.registrationAttemptId
        ? { googleEmailOtpRegistrationAttemptId: googleEmailOtpResolution.registrationAttemptId }
        : {}),
      ...(googleEmailOtpResolution?.mode
        ? { googleEmailOtpResolutionMode: googleEmailOtpResolution.mode }
        : {}),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(oidcProvider ? { oidcProvider } : {}),
      ...(providerSubject ? { providerSubject } : {}),
      ...(oidcIssuer ? { oidcIssuer } : {}),
      ...(oidcSub ? { oidcSub } : {}),
      ...(oidcAud?.length ? { oidcAud } : {}),
      ...(oidcEmail ? { email: oidcEmail } : {}),
      ...(typeof oidcEmailVerified === 'boolean' ? { oidcEmailVerified } : {}),
      ...(oidcHostedDomain ? { oidcHostedDomain } : {}),
      ...(oidcName ? { name: oidcName } : {}),
      ...(oidcGivenName ? { given_name: oidcGivenName } : {}),
      ...(oidcFamilyName ? { family_name: oidcFamilyName } : {}),
    };
    if (passkeyAuthorityRef) {
      sessionClaims.walletAuthAuthorityRef = passkeyAuthorityRef;
    }
    if (emailOtpAuthorityRef) {
      sessionClaims.walletAuthAuthorityRef = emailOtpAuthorityRef;
    }
    const jwtSigningStartedAt = performance.now();
    const jwt = await session.signJwt(userId, sessionClaims);
    recordSessionExchangeTiming(timings, 'jwt_signing', jwtSigningStartedAt);
    const sessionExpiresAt = deriveJwtExpiresAtIso(jwt);
    const sessionExpiresAtMs = sessionExpiresAt ? Date.parse(sessionExpiresAt) : Number.NaN;
    if (!Number.isSafeInteger(sessionExpiresAtMs)) {
      throw new Error('signed app session did not contain a valid expiry');
    }
    const activeSessionCommitStartedAt = performance.now();
    await ctx.service.authorizationSessions.recordActiveSession(
      buildActiveAuthorizationSession({
        tenantId: ctx.service.authorizationSessions.tenantId,
        principalId,
        sessionId: seamsSessionId,
        authSource,
        deviceId,
        audience: {
          kind: 'first_party_web',
          origin: sessionOrigin,
        },
        appSessionVersion: normalizedAppSessionVersion,
        assurance: 'session',
        createdAtMs: Date.now(),
        lifecycle: {
          kind: 'active',
          expiresAtMs: sessionExpiresAtMs,
        },
      }),
    );
    recordSessionExchangeTiming(timings, 'active_session_commit', activeSessionCommitStartedAt);
    let ecdsaSession: RouterAbEcdsaPostRegistrationSessionActivationResponseV1 | undefined;
    let ecdsaActivationReceipt: WalletUnlockEcdsaCustodySignerV1['activationReceipt'] | undefined;
    let ecdsaCustody: WalletUnlockEcdsaAuthoredRequest['continuity'] | undefined;
    if (
      command.kind === 'passkey_assertion' &&
      command.ecdsaActivation.kind === 'activate_first_ecdsa_wallet_session'
    ) {
      if (!passkeyAuthorityRef) {
        throw new Error('verified passkey exchange did not resolve an authority');
      }
      if (command.walletId !== userId) {
        return json(
          {
            ok: false,
            code: 'scope_mismatch',
            message: 'Passkey ECDSA policy wallet does not match the verified passkey wallet',
          },
          { status: 403 },
        );
      }
      const authored = await authorWalletUnlockEcdsaRequest(
        ctx,
        userId,
        command.ecdsaActivation.policy,
      );
      if (!authored.ok) {
        await emitSessionExchangeFailed(ctx, {
          status: authored.status,
          code: authored.code,
          message: authored.message,
          exchangeType,
          sessionKind,
          userId,
        });
        return json(
          { ok: false, code: authored.code, message: authored.message },
          { status: authored.status },
        );
      }
      const ecdsaActivationStartedAt = performance.now();
      const activationResponse = await handleStrictEcdsaSessionActivation({
        ctx,
        body: authored.value.request,
        source: 'verified_passkey_session_exchange',
        authorization: {
          walletId: userId,
          principalId,
          authorizationSessionId: seamsSessionId,
          authority: passkeyAuthorityRef,
        },
      });
      recordSessionExchangeTiming(timings, 'ecdsa_activation', ecdsaActivationStartedAt);
      const activationBody: unknown = await activationResponse.json();
      if (!activationResponse.ok) {
        const failure = isPlainObject(activationBody) ? activationBody : {};
        await emitSessionExchangeFailed(ctx, {
          status: activationResponse.status,
          code: String(failure.code || 'ecdsa_session_activation_failed'),
          message: String(failure.message || 'ECDSA Wallet Session activation failed'),
          exchangeType,
          sessionKind,
          userId,
        });
        return json(activationBody, { status: activationResponse.status });
      }
      ecdsaSession = parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(activationBody);
      ecdsaActivationReceipt = authored.value.activationReceipt;
      ecdsaCustody = authored.value.continuity;
    }
    if (provider === 'passkey') {
      const strongAuthCommitStartedAt = performance.now();
      await ctx.service.emailOtp.markEmailOtpStrongAuthSatisfied({ walletId: userId });
      recordSessionExchangeTiming(timings, 'strong_auth_commit', strongAuthCommitStartedAt);
    }
    if (
      isGoogleEmailOtpExchange &&
      oidcAccountMode === 'login' &&
      googleEmailOtpResolution?.mode === 'existing_wallet' &&
      walletId &&
      providerSubject &&
      runtimePolicyScope?.orgId
    ) {
      const challengeResult = await ctx.service.emailOtp.createEmailOtpChallenge({
        userId: providerSubject,
        walletId,
        orgId: runtimePolicyScope.orgId,
        email: oidcEmail,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash: await hashEmailOtpAppSessionClaims(
          emailOtpAppSessionClaimsForSubject({
            userId,
            claims: sessionClaims,
          }),
        ),
        appSessionVersion,
        reuseActiveChallenge: true,
        clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
        requestOrigin: ctx.request.headers.get('origin'),
      });
      if (challengeResult.ok) {
        googleEmailOtpResolution.loginChallenge = {
          delivery: challengeResult.delivery.status,
          deliveryDetails: challengeResult.delivery,
          challengeId: challengeResult.challenge.challengeId,
          ...(challengeResult.delivery.emailHint
            ? { emailHint: challengeResult.delivery.emailHint }
            : {}),
          expiresAtMs: challengeResult.challenge.expiresAtMs,
        };
      } else if (challengeResult.code === 'rate_limited') {
        googleEmailOtpResolution.loginChallenge = {
          delivery: 'rate_limited',
          ...(typeof (challengeResult as { retryAfterMs?: unknown }).retryAfterMs === 'number'
            ? { retryAfterMs: Number((challengeResult as { retryAfterMs?: unknown }).retryAfterMs) }
            : {}),
          ...(typeof (challengeResult as { resetAtMs?: unknown }).resetAtMs === 'number'
            ? { resetAtMs: Number((challengeResult as { resetAtMs?: unknown }).resetAtMs) }
            : {}),
        };
      } else {
        const status = emailOtpStatusCode(challengeResult.code);
        return json(emailOtpChallengeResponseBody(challengeResult), { status });
      }
    }
    const responseBody = {
      ok: true,
      ...(ecdsaSession ? { ecdsaSession } : {}),
      ...(ecdsaActivationReceipt ? { ecdsaActivationReceipt } : {}),
      ...(ecdsaCustody ? { ecdsaCustody } : {}),
      ...(passkeyCustodyUnlock ? { walletCustody: passkeyCustodyUnlock } : {}),
      session: {
        kind: 'app_session_v1',
        userId,
        tenantId: ctx.service.authorizationSessions.tenantId,
        seamsSessionId,
        deviceId,
        authSource,
        audience: {
          kind: 'first_party_web',
          origin: sessionOrigin,
        },
        ...(walletId ? { walletId } : {}),
        ...(googleEmailOtpResolution
          ? {
              googleEmailOtpResolution: {
                mode: googleEmailOtpResolution.mode,
                ...(googleEmailOtpResolution.registrationAttemptId
                  ? { registrationAttemptId: googleEmailOtpResolution.registrationAttemptId }
                  : {}),
                ...(googleEmailOtpResolution.expiresAtMs
                  ? {
                      expiresAt: new Date(googleEmailOtpResolution.expiresAtMs).toISOString(),
                      expiresAtMs: googleEmailOtpResolution.expiresAtMs,
                    }
                  : {}),
                ...(googleEmailOtpResolution.offer
                  ? { offer: googleEmailOtpResolution.offer }
                  : {}),
                ...(googleEmailOtpResolution.loginChallenge
                  ? {
                      loginChallenge:
                        googleEmailOtpResolution.loginChallenge.delivery === 'sent' ||
                        googleEmailOtpResolution.loginChallenge.delivery === 'reused'
                          ? {
                              delivery: googleEmailOtpResolution.loginChallenge.delivery,
                              deliveryDetails:
                                googleEmailOtpResolution.loginChallenge.deliveryDetails,
                              challengeId: googleEmailOtpResolution.loginChallenge.challengeId,
                              ...(googleEmailOtpResolution.loginChallenge.emailHint
                                ? { emailHint: googleEmailOtpResolution.loginChallenge.emailHint }
                                : {}),
                              expiresAt: new Date(
                                googleEmailOtpResolution.loginChallenge.expiresAtMs,
                              ).toISOString(),
                              expiresAtMs: googleEmailOtpResolution.loginChallenge.expiresAtMs,
                            }
                          : googleEmailOtpResolution.loginChallenge,
                    }
                  : {}),
              },
            }
          : {}),
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(sessionExpiresAt ? { expiresAt: sessionExpiresAt } : {}),
        ...(oidcEmail ? { email: oidcEmail } : {}),
        ...(oidcName ? { name: oidcName } : {}),
      },
    };
    await dispatchSessionExchangeSucceeded(ctx, {
      provider,
      sessionKind,
      appSessionVersion,
      userId,
      ...(passkeyChallengeId ? { passkeyChallengeId } : {}),
    });
    recordSessionExchangeTiming(timings, 'total', exchangeStartedAt);
    ctx.logger.debug('[router-api][session-exchange] timing', {
      provider,
      sessionKind,
      seamsSessionId,
      timings,
    });
    const serverTiming = sessionExchangeServerTiming(timings);
    if (sessionKind === 'cookie') {
      return json(responseBody, {
        status: 200,
        headers: {
          'Set-Cookie': session.buildSetCookie(jwt),
          'Server-Timing': serverTiming,
        },
      });
    }
    return json(
      { ...responseBody, jwt },
      { status: 200, headers: { 'Server-Timing': serverTiming } },
    );
  } catch (error: unknown) {
    await emitSessionExchangeFailed(ctx, {
      status: 500,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    });
    return json(
      {
        ok: false,
        code: 'internal',
        message: error instanceof Error ? error.message : 'Internal error',
      },
      { status: 500 },
    );
  }
}

export async function handleSessionRevoke(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/session/revoke') return null;

  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'session.revoke',
    });
    return validated.response;
  }

  const rotated = await ctx.service.sessionVersions.rotateAppSessionVersion({
    userId: validated.userId,
  });
  if (!rotated.ok) {
    return json(
      { ok: false, code: rotated.code, message: rotated.message },
      { status: rotated.code === 'internal' ? 500 : 400 },
    );
  }

  const session = ctx.opts.session;
  await emitRouterApiWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.routerApiWebhooks,
    eventType: 'session.revoked',
    claims: validated.claims,
    userId: validated.userId,
    payload: {
      revoked: true,
      appSessionVersion: validated.appSessionVersion,
    },
  });
  return json(
    { ok: true, revoked: true, userId: validated.userId },
    {
      status: 200,
      ...(session ? { headers: { 'Set-Cookie': session.buildClearCookie() } } : {}),
    },
  );
}

export async function handleSessionRefresh(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/session/refresh') return null;

  const body = await readJson(ctx.request);
  const sessionKind = parseSessionKind(body);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'session.refresh',
      sessionKind,
    });
    const payload = await validated.response
      .clone()
      .json()
      .catch(() => ({}));
    return json(
      {
        code: String((payload as any)?.code || 'unauthorized'),
        message: String((payload as any)?.message || 'No valid app session'),
      },
      { status: validated.response.status },
    );
  }
  const session = ctx.opts.session;
  if (!session) {
    return json(
      { code: 'sessions_disabled', message: 'Sessions are not configured' },
      { status: 501 },
    );
  }
  const out = await session.refresh(Object.fromEntries(ctx.request.headers.entries()));
  if (!out.ok || !out.jwt) {
    if ((out.code || 'not_eligible') === 'unauthorized') {
      await emitRouterApiWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.routerApiWebhooks,
        eventType: 'session.warm.expired',
        claims: validated.claims,
        userId: validated.userId,
        payload: {
          expired: true,
          source: 'session.refresh',
          reason: out.message || 'Refresh not eligible',
          sessionKind,
        },
      });
    }
    return json(
      { code: out.code || 'not_eligible', message: out.message || 'Refresh not eligible' },
      { status: out.code === 'unauthorized' ? 401 : 400 },
    );
  }
  await emitRouterApiWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.routerApiWebhooks,
    eventType: 'session.warm.refreshed',
    claims: validated.claims,
    userId: validated.userId,
    payload: {
      refreshed: true,
      sessionKind,
    },
  });
  const res = json(sessionKind === 'cookie' ? { ok: true } : { ok: true, jwt: out.jwt }, {
    status: 200,
  });
  if (sessionKind === 'cookie' && out.jwt) {
    try {
      res.headers.set('Set-Cookie', session.buildSetCookie(out.jwt));
    } catch {}
  }
  return res;
}

function parseReusableWalletSessionStatusBody(body: unknown): {
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
} | null {
  if (!isPlainObject(body)) return null;
  const fields = Object.keys(body);
  if (
    fields.length !== 2 ||
    !fields.every((field) => field === 'walletSessionId' || field === 'quotaId')
  ) {
    return null;
  }
  const walletSessionId = parseWalletSessionId(body.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(body.quotaId);
  if (!walletSessionId.ok || !quotaId.ok) return null;
  return {
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
  };
}

type WalletSessionStatusAuthorization = {
  readonly walletId: string;
  readonly principalId: PrincipalId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

function walletSessionStatusClaimsInvalidResponse(): {
  readonly ok: false;
  readonly response: Response;
} {
  return {
    ok: false,
    response: json(
      {
        authenticated: false,
        code: 'wallet_session_claims_invalid',
        message: 'Wallet Session claims are invalid',
      },
      { status: 401 },
    ),
  };
}

async function readAndValidateWalletSessionStatusAuthorization(
  ctx: FetchRouterApiContext,
): Promise<
  | { readonly ok: true; readonly authorization: WalletSessionStatusAuthorization }
  | { readonly ok: false; readonly response: Response }
> {
  const session = ctx.opts.session;
  if (!session) {
    return {
      ok: false,
      response: json(
        { authenticated: false, code: 'sessions_disabled', message: 'Sessions are not configured' },
        { status: 501 },
      ),
    };
  }

  const bearerToken = extractBearerCredential(ctx.request.headers);
  if (!bearerToken) {
    return {
      ok: false,
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'No valid Wallet Session' },
        { status: 401 },
      ),
    };
  }

  let parsed: Awaited<ReturnType<typeof session.parse>>;
  try {
    parsed = await session.parse({ authorization: `Bearer ${bearerToken}` });
  } catch {
    return {
      ok: false,
      response: json(
        {
          authenticated: false,
          code: 'wallet_session_unavailable',
          message: 'Wallet Session status is unavailable',
        },
        { status: 503 },
      ),
    };
  }
  if (!parsed.ok) {
    return {
      ok: false,
      response: json(
        { authenticated: false, code: 'unauthorized', message: 'No valid Wallet Session' },
        { status: 401 },
      ),
    };
  }

  const walletSession =
    parseRouterAbEcdsaDerivationWalletSessionClaims(parsed.claims) ||
    parseRouterAbEd25519WalletSessionClaims(parsed.claims);
  if (!walletSession) {
    return {
      ok: false,
      response: json(
        {
          authenticated: false,
          code: 'wallet_session_claims_invalid',
          message: 'Wallet Session claims are invalid',
        },
        { status: 401 },
      ),
    };
  }
  if (walletSession.thresholdExpiresAtMs <= Date.now()) {
    return {
      ok: false,
      response: json(
        {
          authenticated: false,
          code: 'wallet_session_expired',
          message: 'Wallet Session expired',
        },
        { status: 401 },
      ),
    };
  }

  let principalId: PrincipalId;
  if ('authorizationSessionId' in walletSession) {
    // ECDSA `sub` identifies the wallet key. Reusable grants are owned by the
    // authorization-session principal, which may be a provider subject.
    const authorizationSession = await ctx.service.authorizationSessions.readActiveSession({
      tenantId: ctx.service.authorizationSessions.tenantId,
      sessionId: walletSession.authorizationSessionId,
      nowMs: Date.now(),
    });
    if (!authorizationSession) return walletSessionStatusClaimsInvalidResponse();
    principalId = authorizationSession.principalId;
  } else {
    const authorityPrincipalSubject =
      walletSession.authority.factor.kind === 'email_otp'
        ? walletSession.authority.factor.providerUserId
        : walletSession.authority.walletId;
    const authorityPrincipal = parsePrincipalId(authorityPrincipalSubject);
    if (!authorityPrincipal.ok) return walletSessionStatusClaimsInvalidResponse();
    if (walletSession.sid) {
      const authorizationSession = await ctx.service.authorizationSessions.readActiveSession({
        tenantId: ctx.service.authorizationSessions.tenantId,
        sessionId: walletSession.sid,
        nowMs: Date.now(),
      });
      if (!authorizationSession || authorizationSession.principalId !== authorityPrincipal.value) {
        return walletSessionStatusClaimsInvalidResponse();
      }
    }
    principalId = authorityPrincipal.value;
  }
  return {
    ok: true,
    authorization: {
      walletId: walletSession.walletId,
      principalId,
      walletSessionId: walletSession.walletSessionId,
      quotaId: walletSession.quotaId,
    },
  };
}

export async function handleReusableWalletSessionStatus(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/session/status') return null;
  const body = parseReusableWalletSessionStatusBody(await readJson(ctx.request));
  if (!body) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: 'Wallet Session status requires exact walletSessionId and quotaId',
      },
      { status: 400 },
    );
  }
  const validated = await readAndValidateWalletSessionStatusAuthorization(ctx);
  if (!validated.ok) return validated.response;
  if (
    validated.authorization.walletSessionId !== body.walletSessionId ||
    validated.authorization.quotaId !== body.quotaId
  ) {
    return json(
      {
        ok: false,
        code: 'wallet_session_scope_mismatch',
        message: 'Wallet Session status does not match the verified Wallet Session',
      },
      { status: 403 },
    );
  }
  const nowMs = Date.now();
  const result = await ctx.service.authorizationSessions.readReusableWalletSessionStatus({
    tenantId: ctx.service.authorizationSessions.tenantId,
    principalId: validated.authorization.principalId,
    walletSessionId: body.walletSessionId,
    quotaId: body.quotaId,
    nowMs,
  });
  switch (result.kind) {
    case 'active':
    case 'exhausted':
      return json(
        {
          ok: true,
          status: result.kind,
          walletSessionId: result.walletSessionId,
          quotaId: result.quotaId,
          remainingUses: result.remainingUses,
          expiresAtMs: result.expiresAtMs,
        },
        { status: 200 },
      );
    case 'expired':
      return json(
        {
          ok: true,
          status: result.kind,
          walletSessionId: result.walletSessionId,
          quotaId: result.quotaId,
          expiresAtMs: result.expiresAtMs,
        },
        { status: 200 },
      );
    case 'superseded':
    case 'missing':
    case 'invalid':
      return json(
        {
          ok: true,
          status: result.kind,
          walletSessionId: result.walletSessionId,
          quotaId: result.quotaId,
        },
        { status: 200 },
      );
  }
  result satisfies never;
  return json(
    { ok: false, code: 'internal', message: 'Invalid Wallet Session status' },
    { status: 500 },
  );
}

export async function handleWalletUnlockChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/challenge') return null;
  const body = await readJson(ctx.request);
  const response = await handleWalletUnlockChallengeRoute({
    body,
    service: ctx.service.walletUnlock,
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletUnlockVerify(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/verify') return null;
  const body = await readJson(ctx.request);
  let ecdsaSession: WalletUnlockEcdsaSessionContext;
  try {
    ecdsaSession = walletUnlockEcdsaSessionContext(ctx, body);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message:
          error instanceof Error ? error.message : 'ECDSA Wallet Session activation is invalid',
      },
      { status: 400 },
    );
  }
  const parsedRequestedCapabilities = parseWalletUnlockRequestedCapabilitiesRequest(body);
  if (!parsedRequestedCapabilities.ok) {
    return json(parsedRequestedCapabilities.body, { status: parsedRequestedCapabilities.status });
  }
  const unlockSourceSession = parsedRequestedCapabilities.request
    ? await readWalletUnlockSourceSession(ctx)
    : null;
  if (unlockSourceSession && !unlockSourceSession.ok) return unlockSourceSession.response;
  const capabilityContext: WalletUnlockCapabilityContext = parsedRequestedCapabilities.request
    ? {
        kind: 'email_otp',
        request: parsedRequestedCapabilities.request,
        provisionWalletSession: async (request) => {
          if (
            !unlockSourceSession ||
            request.walletId !== unlockSourceSession.walletId ||
            request.verifiedProviderUserId !== unlockSourceSession.principalId
          ) {
            return {
              ok: false,
              code: 'scope_mismatch',
              message: 'Verified wallet unlock does not match the active app session',
            };
          }
          return await ctx.service.walletRegistration.provisionEd25519YaoWalletSession({
            ...request,
            seamsSessionId: unlockSourceSession.sessionId,
          });
        },
      }
    : { kind: 'passkey_unlock' };
  const response = await handleWalletUnlockVerifyRoute({
    body,
    origin: String(ctx.request.headers.get('origin') || '').trim() || undefined,
    service: ctx.service.walletUnlock,
    resolveEmailOtpCustody: async ({
      walletId,
      enrollmentId,
      enrollmentSealKeyVersion,
    }) =>
      await ctx.service.passkeyCustody.readVerifiedFactorCustody({
        walletId: walletIdFromString(walletId),
        factor: {
          kind: 'email_otp',
          enrollmentId,
          enrollmentSealKeyVersion,
        },
      }),
    capabilityContext,
    ecdsaSession,
    emitRouterApiWebhook: async (event) => {
      await emitRouterApiWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.routerApiWebhooks,
        eventType: event.eventType,
        userId: event.userId,
        eventId: event.eventId,
        payload: event.payload,
      });
    },
    emitEmailOtpWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRegistrationChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/challenge')
    return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.challenge',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRegistrationChallengeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    requestOrigin: ctx.request.headers.get('origin'),
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRegistrationFinalize(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/finalize')
    return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.finalize',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRegistrationFinalizeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRegistrationSeal(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/seal') return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.registration.seal',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRegistrationSealRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpLoginChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/login/challenge') return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.login.challenge',
    });
    return validated.response;
  }
  const response = await handleEmailOtpLoginChallengeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    requestOrigin: ctx.request.headers.get('origin'),
    service: routerApiEmailOtpRouteService(ctx.service),
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpSigningSessionChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/signing-session/challenge') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateEmailOtpSigningSession(ctx);
  if (!validated.ok) return validated.response;
  const response = await handleEmailOtpSigningSessionChallengeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    sessionHash: validated.sessionHash,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    requestOrigin: ctx.request.headers.get('origin'),
    service: routerApiEmailOtpRouteService(ctx.service),
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpDeviceRecoveryChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-challenge') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_challenge',
    });
    return validated.response;
  }
  const response = await handleEmailOtpDeviceRecoveryChallengeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    requestOrigin: ctx.request.headers.get('origin'),
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

/** Starts the recovery-only Email OTP path on a device with no app session. */
export async function handleWalletEmailOtpRecoveryBootstrapChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-bootstrap/challenge') {
    return null;
  }
  const body = await readJson(ctx.request);
  const record = isPlainObject(body) ? body : {};
  const walletId = typeof record.walletId === 'string' ? record.walletId.trim() : '';
  const orgId = typeof record.orgId === 'string' ? record.orgId.trim() : '';
  if (!walletId || !orgId) {
    return json(
      { ok: false, code: 'recovery_unavailable', message: 'wallet recovery is unavailable' },
      { status: 404 },
    );
  }
  const result = await ctx.service.emailOtp.createEmailOtpWalletRecoveryBootstrapChallenge({
    walletId,
    orgId,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    requestOrigin: ctx.request.headers.get('origin'),
  });
  if (!result.ok) {
    return json(
      { ok: false, code: 'recovery_unavailable', message: 'wallet recovery is unavailable' },
      { status: 404 },
    );
  }
  return json(
    {
      ok: true,
      challengeId: result.challengeId,
      otpChannel: result.otpChannel,
      expiresAtMs: result.expiresAtMs,
      emailHint: result.emailHint,
    },
    { status: 200 },
  );
}

/** Verifies the recovery-only challenge and returns a one-purpose grant. */
export async function handleWalletEmailOtpRecoveryBootstrapVerify(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-bootstrap/verify') {
    return null;
  }
  const body = await readJson(ctx.request);
  const record = isPlainObject(body) ? body : {};
  const walletId = typeof record.walletId === 'string' ? record.walletId.trim() : '';
  const orgId = typeof record.orgId === 'string' ? record.orgId.trim() : '';
  const challengeId = typeof record.challengeId === 'string' ? record.challengeId.trim() : '';
  const otpCode = typeof record.otpCode === 'string' ? record.otpCode.trim() : '';
  if (!walletId || !orgId || !challengeId || !otpCode) {
    return json(
      { ok: false, code: 'challenge_expired_or_invalid', message: 'Email OTP challenge expired or invalid' },
      { status: 401 },
    );
  }
  const result = await ctx.service.emailOtp.verifyEmailOtpWalletRecoveryBootstrap({
    walletId,
    orgId,
    challengeId,
    otpCode,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
  });
  if (!result.ok) {
    return json(
      { ok: false, code: result.code, message: result.message },
      { status: result.code === 'invalid_body' ? 400 : 401 },
    );
  }
  const replaceableCredentials = await listWalletRecoveryBootstrapCredentialChoices(
    ctx,
    result.walletId,
  );
  if (!replaceableCredentials) {
    return json(
      { ok: false, code: 'recovery_unavailable', message: 'wallet recovery is unavailable' },
      { status: 503 },
    );
  }
  return json(
    {
      ok: true,
      walletId: result.walletId,
      challengeId: result.challengeId,
      recoveryBootstrapGrant: result.recoveryBootstrapGrant,
      recoveryBootstrapGrantExpiresAtMs: result.recoveryBootstrapGrantExpiresAtMs,
      replaceableCredentials,
    },
    { status: 200 },
  );
}

async function listWalletRecoveryBootstrapCredentialChoices(
  ctx: FetchRouterApiContext,
  walletId: string,
): Promise<readonly { readonly credentialIdB64u: string; readonly label?: string }[] | null> {
  const parsedWalletId = parseWalletId(walletId);
  if (!parsedWalletId.ok) return null;
  try {
    const credentials = await ctx.service.passkeyCustody.listWalletCredentials({
      walletId: parsedWalletId.value,
    });
    return credentials.flatMap((credential) => {
      if (
        credential.index.factor.kind !== 'passkey' ||
        credential.index.lifecycle.kind !== 'active'
      ) {
        return [];
      }
      return [
        {
          credentialIdB64u: credential.index.factor.credentialIdB64u,
          ...(credential.index.deviceLabel ?? credential.activity.label
            ? { label: credential.index.deviceLabel ?? credential.activity.label }
            : {}),
        },
      ];
    });
  } catch {
    return null;
  }
}

export async function handleWalletEmailOtpLoginVerify(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/login/verify') return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.login.verify',
    });
    return validated.response;
  }
  const response = await handleEmailOtpLoginVerifyRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpLoginVerifyAndUnseal(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/login/verify-and-unseal') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.login.verify_and_unseal',
    });
    return validated.response;
  }
  const response = await handleEmailOtpLoginVerifyAndUnsealRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpSigningSessionVerify(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/signing-session/verify') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateEmailOtpSigningSession(ctx);
  if (!validated.ok) return validated.response;
  const response = await handleEmailOtpSigningSessionVerifyRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    sessionHash: validated.sessionHash,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
    opts: ctx.opts,
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRecoveryWrappedEscrows(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-wrapped-escrows') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_wrapped_escrows',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRecoveryWrappedEscrowsRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRecoveryKeyConsume(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-key/consume') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_key.consume',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRecoveryKeyConsumeRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRecoveryKeyStatus(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-key/status') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_key.status',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRecoveryKeyStatusRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRecoveryKeyRotate(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-key/rotate') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_key.rotate',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRecoveryKeyRotateRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRecoveryKeyAttemptFailed(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/recovery-key/attempt-failed') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.recovery_key.attempt_failed',
    });
    return validated.response;
  }
  const response = await handleEmailOtpRecoveryKeyAttemptFailedRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpUnseal(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/unseal') return null;
  const body = await readJson(ctx.request);
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.unseal',
    });
    return validated.response;
  }
  const response = await handleEmailOtpUnsealRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpSigningSessionUnseal(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/signing-session/unseal') {
    return null;
  }
  const body = await readJson(ctx.request);
  const validated = await readAndValidateEmailOtpSigningSession(ctx);
  if (!validated.ok) return validated.response;
  const response = await handleEmailOtpSigningSessionUnsealRoute({
    body,
    claims: validated.claims,
    userId: validated.userId,
    appSessionVersion: validated.appSessionVersion,
    sessionHash: validated.sessionHash,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    service: routerApiEmailOtpRouteService(ctx.service),
    emitWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        claims: event.claims,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpDevCleanupGoogleRegistration(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (
    ctx.method !== 'POST' ||
    ctx.pathname !== '/wallet/email-otp/dev/cleanup-google-registration'
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  const response = await handleEmailOtpDevCleanupGoogleRegistrationRoute({
    body,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpDevOtpOutbox(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'GET' || ctx.pathname !== '/wallet/email-otp/dev/otp-outbox') return null;
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.email_otp.dev_outbox',
    });
    return validated.response;
  }

  const response = await handleEmailOtpDevOtpOutboxRoute({
    challengeId: String(ctx.url.searchParams.get('challengeId') || ''),
    walletId: String(ctx.url.searchParams.get('walletId') || ''),
    claims: validated.claims,
    userId: validated.userId,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletState(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'GET' || ctx.pathname !== '/wallet/state') return null;
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.state',
    });
    const payload = await validated.response
      .clone()
      .json()
      .catch(() => ({}));
    return json(
      {
        ok: false,
        locked: true,
        code: String((payload as any)?.code || 'unauthorized'),
        message: String((payload as any)?.message || 'No valid app session'),
      },
      { status: validated.response.status },
    );
  }
  return json({ ok: true, locked: false, userId: validated.userId }, { status: 200 });
}

export async function handleWalletLock(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/lock') return null;
  const validated = await readAndValidateAppSession(ctx);
  if (!validated.ok) {
    await maybeEmitWarmExpiredFromValidationFailure({
      ctx,
      validated,
      source: 'wallet.lock',
    });
    const payload = await validated.response
      .clone()
      .json()
      .catch(() => ({}));
    return json(
      {
        ok: false,
        locked: true,
        code: String((payload as any)?.code || 'unauthorized'),
        message: String((payload as any)?.message || 'No valid app session'),
      },
      { status: validated.response.status },
    );
  }

  const rotated = await ctx.service.sessionVersions.rotateAppSessionVersion({
    userId: validated.userId,
  });
  if (!rotated.ok) {
    return json(
      { ok: false, locked: true, code: rotated.code, message: rotated.message },
      { status: rotated.code === 'internal' ? 500 : 400 },
    );
  }

  const session = ctx.opts.session;
  await emitRouterApiWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.routerApiWebhooks,
    eventType: 'wallet.locked',
    claims: validated.claims,
    userId: validated.userId,
    payload: {
      locked: true,
      appSessionVersion: validated.appSessionVersion,
    },
  });
  return json(
    { ok: true, locked: true, userId: validated.userId },
    {
      status: 200,
      ...(session ? { headers: { 'Set-Cookie': session.buildClearCookie() } } : {}),
    },
  );
}
