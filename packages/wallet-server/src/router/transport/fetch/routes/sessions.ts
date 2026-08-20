import {
  extractBearerCredential,
  resolveSourceIpFromFetchHeaders,
} from '../../../auth/routerApiKeyAuth';
import { emitRouterApiWebhookEvent } from '../../../framework/routerApiWebhooks';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  handleWalletUnlockChallengeRoute,
  handleWalletUnlockVerifyRoute,
  type WalletUnlockEcdsaCustodySignerV1,
  type WalletUnlockEcdsaSessionContext,
  type WalletUnlockCapabilityContext,
} from '../../../domains/walletUnlock/walletUnlockRouteHandlers';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../../../domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import { handleStrictEcdsaSessionActivation } from './thresholdEcdsa';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { routerApiEmailOtpRouteService } from '../../../framework/authServicePort';
import {
  handleEmailOtpDevCleanupGoogleRegistrationRoute,
  handleEmailOtpDevOutboxRoute,
  handleEmailOtpRegistrationSealRoute,
  sealEmailOtpFactorSecretForWorker,
} from '../../../domains/emailOtp/emailOtpRouteHandlers';
import { parseOrgId, parseProviderSubject, parseWalletId } from '@shared/utils/domainIds';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  type WalletEmailOtpOperation,
} from '@shared/utils/emailOtpDomain';
import { parseWalletUnlockRequestedCapabilitiesRequest } from '../../../domains/walletUnlock/walletUnlockRequestedCapabilitiesValidation';
import { parseWalletEmailOtpLoginOperation } from '../../../domains/emailOtp/emailOtpRequestValidation';
import {
  emailOtpStatusCode,
  hashEmailOtpOperationBinding,
} from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import { authorizeEmailOtpExportPolicy } from '../../../domains/emailOtp/emailOtpExportPolicy';
import { isPlainObject } from '@shared/utils/validation';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type AuthorizationParseResult,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWebAuthnCredentialIdB64u, parseWebAuthnRpId } from '@shared/utils/domainIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseSessionOrigin,
  type SessionOrigin,
} from '../../../../authorization/domain';
import type { OpaqueWalletSessionCurve } from '../../../../authorization/service';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

const HOSTED_WALLET_EXCHANGE_TTL_MS = 5 * 60 * 1000;

function parseHostedWalletExchangeCurve(value: unknown): OpaqueWalletSessionCurve {
  if (value === 'ecdsa' || value === 'ed25519') return value;
  throw new Error('hosted-wallet exchange curve is invalid');
}

function parseExactHostedWalletExchangeBody(
  value: unknown,
  fields: readonly string[],
): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error('hosted-wallet exchange body is invalid');
  const allowed = new Set(fields);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`Unsupported hosted-wallet exchange field: ${key}`);
  }
  for (const field of fields) {
    if (!Object.hasOwn(value, field))
      throw new Error(`Missing hosted-wallet exchange field: ${field}`);
  }
  return value;
}

function requiredExchangeOrigin(record: Record<string, unknown>, field: string): SessionOrigin {
  return parseSessionOrigin(record[field]);
}

function requestOrigin(request: Request): SessionOrigin {
  return parseSessionOrigin(request.headers.get('origin'));
}

function hostedWalletExchangeFailure(result: { readonly kind: string }): {
  readonly status: number;
  readonly code: string;
  readonly message: string;
} {
  switch (result.kind) {
    case 'expired':
      return {
        status: 410,
        code: 'exchange_expired',
        message: 'Hosted-wallet exchange is expired',
      };
    case 'already_consumed':
      return {
        status: 409,
        code: 'exchange_already_consumed',
        message: 'Hosted-wallet exchange was already redeemed',
      };
    case 'nonce_mismatch':
    case 'app_origin_mismatch':
    case 'invalid_code':
      return {
        status: 401,
        code: 'exchange_invalid',
        message: 'Hosted-wallet exchange is invalid',
      };
    default:
      return {
        status: 503,
        code: 'wallet_session_unavailable',
        message: 'Wallet Session is unavailable',
      };
  }
}

export async function handleHostedWalletSessionExchangeIssue(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/session/exchange/issue') return null;
  let record: Record<string, unknown>;
  try {
    record = parseExactHostedWalletExchangeBody(await readJson(ctx.request), [
      'curve',
      'appOrigin',
      'walletOrigin',
    ]);
  } catch (error) {
    return json({ ok: false, code: 'invalid_body', message: String(error) }, { status: 400 });
  }
  let curve: OpaqueWalletSessionCurve;
  let appOrigin: SessionOrigin;
  let walletOrigin: SessionOrigin;
  try {
    curve = parseHostedWalletExchangeCurve(record.curve);
    appOrigin = requiredExchangeOrigin(record, 'appOrigin');
    walletOrigin = requiredExchangeOrigin(record, 'walletOrigin');
    if (requestOrigin(ctx.request) !== appOrigin)
      throw new Error('request Origin does not match appOrigin');
  } catch (error) {
    return json({ ok: false, code: 'origin_mismatch', message: String(error) }, { status: 403 });
  }
  const token = extractBearerCredential(ctx.request.headers);
  if (!token)
    return json(
      { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
      { status: 401 },
    );
  let resolved: Awaited<
    ReturnType<
      FetchRouterApiContext['service']['authorizationSessions']['resolveOpaqueWalletSessionToken']
    >
  >;
  try {
    resolved = await ctx.service.authorizationSessions.resolveOpaqueWalletSessionToken({
      tenantId: ctx.service.authorizationSessions.tenantId,
      token,
      curve,
      nowMs: Date.now(),
    });
  } catch {
    return json(
      { ok: false, code: 'wallet_session_unavailable', message: 'Wallet Session is unavailable' },
      { status: 503 },
    );
  }
  if (!resolved)
    return json(
      { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
      { status: 401 },
    );
  let delivery: Awaited<
    ReturnType<
      FetchRouterApiContext['service']['authorizationSessions']['mintHostedWalletSeamsSessionExchange']
    >
  >;
  try {
    const issuedAtMs = Date.now();
    delivery = await ctx.service.authorizationSessions.mintHostedWalletSeamsSessionExchange({
      tenantId: ctx.service.authorizationSessions.tenantId,
      walletSessionId: resolved.authorization.walletSessionId,
      appOrigin,
      walletOrigin,
      curve: resolved.curve,
      binding: resolved.binding,
      issuedAtMs,
      expiresAtMs: issuedAtMs + HOSTED_WALLET_EXCHANGE_TTL_MS,
    });
  } catch {
    return json(
      { ok: false, code: 'wallet_session_unavailable', message: 'Wallet Session is unavailable' },
      { status: 503 },
    );
  }
  return json(
    {
      ok: true,
      delivery: {
        exchangeCode: delivery.exchangeCode,
        nonce: delivery.nonce,
        appOrigin: delivery.appOrigin,
        walletOrigin: delivery.walletOrigin,
        expiresAtMs: delivery.expiresAtMs,
      },
    },
    { status: 200 },
  );
}

export async function handleHostedWalletSessionExchangeRedeem(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/session/exchange/redeem') return null;
  let record: Record<string, unknown>;
  try {
    record = parseExactHostedWalletExchangeBody(await readJson(ctx.request), [
      'exchangeCode',
      'nonce',
      'curve',
      'appOrigin',
      'walletOrigin',
    ]);
  } catch (error) {
    return json({ ok: false, code: 'invalid_body', message: String(error) }, { status: 400 });
  }
  let exchangeCode: ReturnType<typeof parseHostedWalletSeamsSessionExchangeCode>;
  let nonce: ReturnType<typeof parseHostedWalletSeamsSessionExchangeNonce>;
  let appOrigin: SessionOrigin;
  let walletOrigin: SessionOrigin;
  let curve: OpaqueWalletSessionCurve;
  try {
    exchangeCode = parseHostedWalletSeamsSessionExchangeCode(record.exchangeCode);
    nonce = parseHostedWalletSeamsSessionExchangeNonce(record.nonce);
    curve = parseHostedWalletExchangeCurve(record.curve);
    appOrigin = requiredExchangeOrigin(record, 'appOrigin');
    walletOrigin = requiredExchangeOrigin(record, 'walletOrigin');
    if (requestOrigin(ctx.request) !== walletOrigin) {
      throw new Error('request Origin does not match walletOrigin');
    }
  } catch (error) {
    return json({ ok: false, code: 'origin_mismatch', message: String(error) }, { status: 403 });
  }
  const result = await ctx.service.authorizationSessions.redeemHostedWalletSeamsSessionExchange({
    exchangeCode,
    nonce,
    appOrigin,
    walletOrigin,
    curve,
    redeemedAtMs: Date.now(),
  });
  if (result.kind !== 'redeemed') {
    const failure = hostedWalletExchangeFailure(result);
    return json(
      { ok: false, code: failure.code, message: failure.message },
      { status: failure.status },
    );
  }
  return json(
    {
      ok: true,
      walletSessionId: result.walletSessionId,
      walletSessionToken: result.walletSessionToken,
      curve: result.curve,
      expiresAtMs: result.expiresAtMs,
    },
    { status: 200 },
  );
}

function requiredAuthorizationValue<T>(result: AuthorizationParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function projectWalletUnlockEcdsaCustodySigner(
  signer: Awaited<
    ReturnType<
      FetchRouterApiContext['service']['walletRegistration']['listWalletEcdsaCustodyContinuity']
    >
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
      derivationClientSharePublicKey33B64u: signer.walletKey.derivationClientSharePublicKey33B64u,
      participantIds: signer.walletKey.participantIds,
      publicCapability: signer.walletKey.publicCapability,
    },
    activationReceipt: signer.activationReceipt,
    runtimePolicyScope: signer.runtimePolicyScope,
  };
}

export type WalletUnlockEcdsaAuthoredRequest = {
  readonly request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
  readonly activationReceipt: WalletUnlockEcdsaCustodySignerV1['activationReceipt'];
  readonly continuity: {
    readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
    readonly signers: readonly WalletUnlockEcdsaCustodySignerV1[];
  };
};

export async function authorWalletUnlockEcdsaRequest(
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
          walletSessionToken: authorization.walletSessionToken,
          proof: authorization.proof,
        });
      } else {
        response = await handleStrictEcdsaSessionActivation({
          ctx,
          body: request,
          source: 'verified_wallet_unlock',
          proof: authorization.proof,
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

function walletSessionStatusInvalidResponse(body: {
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
}): {
  readonly ok: false;
  readonly response: Response;
} {
  return {
    ok: false,
    response: json(
      {
        ok: true,
        status: 'invalid',
        walletSessionId: body.walletSessionId,
        quotaId: body.quotaId,
      },
      { status: 200 },
    ),
  };
}

async function readAndValidateWalletSessionStatusAuthorization(
  ctx: FetchRouterApiContext,
  body: {
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
  },
): Promise<
  | { readonly ok: true; readonly authorization: WalletSessionStatusAuthorization }
  | { readonly ok: false; readonly response: Response }
> {
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

  const nowMs = Date.now();
  const ecdsa = await ctx.service.authorizationSessions.resolveOpaqueWalletSessionToken({
    tenantId: ctx.service.authorizationSessions.tenantId,
    token: bearerToken,
    curve: 'ecdsa',
    nowMs,
  });
  const walletSession =
    ecdsa ??
    (await ctx.service.authorizationSessions.resolveOpaqueWalletSessionToken({
      tenantId: ctx.service.authorizationSessions.tenantId,
      token: bearerToken,
      curve: 'ed25519',
      nowMs,
    }));
  if (!walletSession) return walletSessionStatusInvalidResponse(body);
  return {
    ok: true,
    authorization: {
      walletId: walletSession.authorization.walletId,
      principalId: walletSession.authorization.principalId,
      walletSessionId: walletSession.authorization.walletSessionId,
      quotaId: walletSession.authorization.quotaId,
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
  const validated = await readAndValidateWalletSessionStatusAuthorization(ctx, body);
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

export async function handleWalletEmailOtpChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/challenge') return null;
  const origin = ctx.request.headers.get('origin');
  let requestOrigin: SessionOrigin;
  let body: Record<string, unknown>;
  try {
    requestOrigin = parseSessionOrigin(origin);
    const raw = await readJson(ctx.request);
    if (!isPlainObject(raw)) throw new Error('Expected JSON object body');
    const keys = Object.keys(raw).sort();
    if (keys.length !== 3 || keys.join(',') !== 'operation,otpChannel,walletId') {
      throw new Error('Email OTP challenge body must contain walletId, otpChannel, and operation');
    }
    body = raw;
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : 'Email OTP challenge request is invalid',
      },
      { status: 400 },
    );
  }
  const parsedWalletId = parseWalletId(body.walletId);
  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedWalletId.ok || !parsedOperation.ok || body.otpChannel !== EMAIL_OTP_CHANNEL) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: !parsedWalletId.ok
          ? parsedWalletId.error.message
          : !parsedOperation.ok
            ? parsedOperation.message
            : 'otpChannel must be email_otp',
      },
      { status: 400 },
    );
  }
  const walletId = parsedWalletId.value;
  const orgId = ctx.service.authorizedOperations.tenantId;
  const enrollment = await ctx.service.emailOtp.readActiveEmailOtpEnrollment({ walletId, orgId });
  if (!enrollment.ok) {
    return json(enrollment, { status: emailOtpStatusCode(enrollment.code) });
  }
  const authority =
    await ctx.service.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject({
      walletId,
      providerUserId: enrollment.enrollment.providerUserId,
    });
  if (!authority.ok) return json(authority, { status: 403 });
  const ownerProofBindingDigest = await hashEmailOtpOperationBinding({
    walletId,
    providerUserId: enrollment.enrollment.providerUserId,
    orgId,
    operation: parsedOperation.operation,
    requestOrigin,
    audience: requestOrigin,
    authorityRef: await walletAuthAuthorityRef({ authority: authority.authority }),
  });
  if (parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
    const policy = await authorizeEmailOtpExportPolicy(ctx.opts, {
      operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      phase: 'challenge',
      userId: enrollment.enrollment.providerUserId,
      walletId,
      orgId,
      ownerProofBindingDigest,
      sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    if (!policy.ok) {
      return json({ ok: false, code: policy.code, message: policy.message }, { status: 403 });
    }
  }
  const result = await ctx.service.emailOtp.createEmailOtpChallenge({
    userId: enrollment.enrollment.providerUserId,
    walletId,
    orgId,
    email: enrollment.enrollment.verifiedEmail,
    otpChannel: EMAIL_OTP_CHANNEL,
    ownerProofBindingDigest,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    requestOrigin,
    operation: parsedOperation.operation,
    reuseActiveChallenge: true,
  });
  return json(result, { status: result.ok ? 200 : emailOtpStatusCode(result.code) });
}

type WalletEmailOtpFactorReleaseRequest = {
  readonly walletId: unknown;
  readonly workerEphemeralPublicKey65B64u: unknown;
} & (
  | { readonly kind: 'verified_grant'; readonly loginGrant: unknown }
  | { readonly kind: 'wallet_session' }
  | {
      readonly kind: 'email_otp';
      readonly challengeId: unknown;
      readonly otpCode: unknown;
      readonly operation: WalletEmailOtpOperation;
    }
);

function parseWalletEmailOtpFactorReleaseRequest(
  value: unknown,
): WalletEmailOtpFactorReleaseRequest {
  if (!isPlainObject(value)) throw new Error('Expected JSON object body');
  const kind = value.kind;
  const expectedFields =
    kind === 'verified_grant'
      ? ['kind', 'loginGrant', 'walletId', 'workerEphemeralPublicKey65B64u']
      : kind === 'wallet_session'
        ? ['kind', 'walletId', 'workerEphemeralPublicKey65B64u']
        : kind === 'email_otp'
          ? [
              'challengeId',
              'kind',
              'operation',
              'otpCode',
              'walletId',
              'workerEphemeralPublicKey65B64u',
            ]
          : null;
  if (!expectedFields || Object.keys(value).sort().join(',') !== expectedFields.join(',')) {
    throw new Error('Email OTP factor release body has invalid fields');
  }
  if (kind === 'verified_grant') {
    return {
      kind,
      walletId: value.walletId,
      loginGrant: value.loginGrant,
      workerEphemeralPublicKey65B64u: value.workerEphemeralPublicKey65B64u,
    };
  }
  if (kind === 'wallet_session') {
    return {
      kind,
      walletId: value.walletId,
      workerEphemeralPublicKey65B64u: value.workerEphemeralPublicKey65B64u,
    };
  }
  const operation = parseWalletEmailOtpLoginOperation(value.operation);
  if (!operation.ok) throw new Error(operation.message);
  return {
    kind: 'email_otp',
    walletId: value.walletId,
    challengeId: value.challengeId,
    otpCode: value.otpCode,
    operation: operation.operation,
    workerEphemeralPublicKey65B64u: value.workerEphemeralPublicKey65B64u,
  };
}

export async function handleWalletEmailOtpFactorRelease(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/factor-release') return null;
  let body: WalletEmailOtpFactorReleaseRequest;
  try {
    body = parseWalletEmailOtpFactorReleaseRequest(await readJson(ctx.request));
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message:
          error instanceof Error ? error.message : 'Email OTP factor release request is invalid',
      },
      { status: 400 },
    );
  }
  const walletId = parseWalletId(body.walletId);
  const orgId = parseOrgId(ctx.service.authorizedOperations.tenantId);
  const workerEphemeralPublicKey65B64u =
    typeof body.workerEphemeralPublicKey65B64u === 'string'
      ? body.workerEphemeralPublicKey65B64u.trim()
      : '';
  if (!walletId.ok || !orgId.ok || !workerEphemeralPublicKey65B64u) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Email OTP factor release request is invalid' },
      { status: 400 },
    );
  }
  const enrollment = await ctx.service.emailOtp.readActiveEmailOtpEnrollment({
    walletId: walletId.value,
    orgId: orgId.value,
  });
  if (!enrollment.ok) {
    return json(enrollment, { status: emailOtpStatusCode(enrollment.code) });
  }
  const providerSubject = parseProviderSubject(enrollment.enrollment.providerUserId);
  if (!providerSubject.ok) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'Email OTP enrollment identity is invalid' },
      { status: 403 },
    );
  }
  let factorReleaseChallengeId: string;
  if (body.kind === 'wallet_session') {
    const token = extractBearerCredential(ctx.request.headers);
    const resolved = token
      ? await ctx.service.authorizationSessions.resolveOpaqueWalletSessionToken({
          tenantId: ctx.service.authorizationSessions.tenantId,
          token,
          curve: 'ed25519',
          nowMs: Date.now(),
        })
      : null;
    if (
      !resolved ||
      resolved.binding.curve !== 'ed25519' ||
      resolved.authorization.walletId !== walletId.value ||
      resolved.binding.authority.factor.kind !== 'email_otp' ||
      resolved.binding.authority.factor.providerUserId !== enrollment.enrollment.providerUserId
    ) {
      return json(
        { ok: false, code: 'unauthorized', message: 'No valid Email OTP Wallet Session' },
        { status: 401 },
      );
    }
    factorReleaseChallengeId = `wallet-session:${resolved.authorization.walletSessionId}`;
  } else {
    let loginGrant: string;
    if (body.kind === 'verified_grant') {
      loginGrant = typeof body.loginGrant === 'string' ? body.loginGrant.trim() : '';
    } else {
      const challengeId = typeof body.challengeId === 'string' ? body.challengeId.trim() : '';
      const otpCode = typeof body.otpCode === 'string' ? body.otpCode.trim() : '';
      if (!challengeId || !otpCode) {
        return json(
          { ok: false, code: 'invalid_body', message: 'Email OTP verification is invalid' },
          { status: 400 },
        );
      }
      const origin = requestOrigin(ctx.request);
      const authority =
        await ctx.service.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject({
          walletId: walletId.value,
          providerUserId: enrollment.enrollment.providerUserId,
        });
      if (!authority.ok) return json(authority, { status: 403 });
      const ownerProofBindingDigest = await hashEmailOtpOperationBinding({
        walletId: walletId.value,
        providerUserId: enrollment.enrollment.providerUserId,
        orgId: orgId.value,
        operation: body.operation,
        requestOrigin: origin,
        audience: origin,
        authorityRef: await walletAuthAuthorityRef({ authority: authority.authority }),
      });
      const verified = await ctx.service.emailOtp.verifyEmailOtpChallenge({
        userId: enrollment.enrollment.providerUserId,
        walletId: String(walletId.value),
        orgId: orgId.value,
        challengeId,
        otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        ownerProofBindingDigest,
        operation: body.operation,
      });
      if (!verified.ok) return json(verified, { status: emailOtpStatusCode(verified.code) });
      loginGrant = verified.loginGrant;
    }
    if (!loginGrant) {
      return json(
        { ok: false, code: 'invalid_body', message: 'Email OTP factor release grant is required' },
        { status: 400 },
      );
    }
    const consumed = await ctx.service.emailOtp.consumeEmailOtpGrant({
      subject: {
        kind: 'provider_identity',
        orgId: orgId.value,
        providerSubject: providerSubject.value,
        walletId: walletId.value,
      },
      loginGrant,
      otpChannel: EMAIL_OTP_CHANNEL,
      clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    if (!consumed.ok) {
      return json(consumed, { status: emailOtpStatusCode(consumed.code) });
    }
    factorReleaseChallengeId = consumed.challengeId;
  }
  const unsealed = await ctx.service.emailOtp.removeEmailOtpServerSeal({
    wrappedCiphertext: enrollment.enrollment.serverSealedFactorCiphertextB64u,
  });
  if (!unsealed.ok) {
    return json(unsealed, { status: emailOtpStatusCode(unsealed.code) });
  }
  if (unsealed.enrollmentSealKeyVersion !== enrollment.enrollment.enrollmentSealKeyVersion) {
    return json(
      {
        ok: false,
        code: 'scope_mismatch',
        message: 'Email OTP factor release seal key version changed',
      },
      { status: 409 },
    );
  }
  const sealed = await sealEmailOtpFactorSecretForWorker({
    factorSecret32B64u: unsealed.ciphertext,
    workerEphemeralPublicKey65B64u,
    walletId: String(walletId.value),
    enrollmentId: enrollment.enrollment.enrollmentId,
    enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
    challengeId: factorReleaseChallengeId,
  });
  if (!sealed.ok) {
    return json(sealed, { status: emailOtpStatusCode(sealed.code) });
  }
  return json(
    {
      ok: true,
      kind: 'email_otp_factor_release_v1',
      challengeId: factorReleaseChallengeId,
      enrollmentId: enrollment.enrollment.enrollmentId,
      enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
      serverEphemeralPublicKey65B64u: sealed.serverEphemeralPublicKey65B64u,
      nonce12B64u: sealed.nonce12B64u,
      ciphertextB64u: sealed.ciphertextB64u,
    },
    { status: 200 },
  );
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
  const capabilityContext: WalletUnlockCapabilityContext = parsedRequestedCapabilities.request
    ? {
        kind: 'email_otp',
        request: parsedRequestedCapabilities.request,
        provisionWalletSession: async (request, proof) =>
          await ctx.service.walletRegistration.provisionEd25519YaoWalletSession({
            ...request,
            proof,
          }),
      }
    : {
        kind: 'passkey_unlock',
        provisionWalletSession: async (request) =>
          await ctx.service.walletRegistration.provisionEd25519YaoWalletSession(request),
      };
  const response = await handleWalletUnlockVerifyRoute({
    body,
    origin: String(ctx.request.headers.get('origin') || '').trim() || undefined,
    service: ctx.service.walletUnlock,
    resolveEmailOtpCustody: async ({ walletId, enrollmentId, enrollmentSealKeyVersion }) =>
      await ctx.service.passkeyCustody.readVerifiedFactorCustody({
        walletId: walletIdFromString(walletId),
        factor: {
          kind: 'email_otp',
          enrollmentId,
          enrollmentSealKeyVersion,
        },
      }),
    resolvePasskeyCustody: async ({ walletId, rpId, credentialIdB64u, ed25519 }) => {
      const parsedRpId = parseWebAuthnRpId(rpId);
      const parsedCredentialId = parseWebAuthnCredentialIdB64u(credentialIdB64u);
      if (!parsedRpId.ok || !parsedCredentialId.ok) {
        throw new Error('Verified passkey custody identity is invalid');
      }
      const custody = await ctx.service.passkeyCustody.readVerifiedFactorCustody({
        walletId: walletIdFromString(walletId),
        factor: {
          kind: 'passkey',
          rpId: parsedRpId.value,
          credentialIdB64u: parsedCredentialId.value,
        },
      });
      let capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1 | null = null;
      if (custody.kind !== 'active') return { custody, capability };
      if (ed25519.kind === 'active') {
        const yaoRuntime = ctx.opts.routerAbEd25519YaoProduct;
        if (!yaoRuntime) throw new Error('Ed25519 Yao product is not configured');
        const resolved = await yaoRuntime.resolveActiveCapability({
          kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
          walletId,
          nearEd25519SigningKeyId: ed25519.nearEd25519SigningKeyId,
          signerSlot: ed25519.signerSlot,
          signingWorkerId: ed25519.relayerKeyId,
          participantIds: ed25519.participantIds,
        });
        if (!resolved.ok) throw new Error(resolved.message);
        capability = resolved.capability;
      }
      return { custody, capability };
    },
    capabilityContext,
    ecdsaSession,
    tenantId: ctx.service.authorizationSessions.tenantId,
    buildVerifiedOwnerProof: ctx.service.authorizedOperations.buildVerifiedOwnerProof,
    resolveEmailOtpAuthority:
      ctx.service.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject,
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

export async function handleWalletEmailOtpRegistrationSeal(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/seal') {
    return null;
  }
  const response = await handleEmailOtpRegistrationSealRoute({
    body: await readJson(ctx.request),
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpDevOutbox(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/dev/otp-outbox') {
    return null;
  }
  const response = await handleEmailOtpDevOutboxRoute({
    body: await readJson(ctx.request),
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}
