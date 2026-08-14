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
import { handleStrictEcdsaSessionActivation } from './thresholdEcdsa';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { routerApiEmailOtpRouteService } from '../../../framework/authServicePort';
import { handleEmailOtpDevCleanupGoogleRegistrationRoute } from '../../../domains/emailOtp/emailOtpRouteHandlers';
import { parseWalletId } from '@shared/utils/domainIds';
import { parseWalletUnlockRequestedCapabilitiesRequest } from '../../../domains/walletUnlock/walletUnlockRequestedCapabilitiesValidation';
import { isPlainObject } from '@shared/utils/validation';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type AuthorizationParseResult,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';

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
  if (!walletSession) return walletSessionStatusClaimsInvalidResponse();
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
    : { kind: 'passkey_unlock' };
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
    capabilityContext,
    ecdsaSession,
    tenantId: ctx.service.authorizationSessions.tenantId,
    buildVerifiedOwnerProof: ctx.service.authorizedOperations.buildVerifiedOwnerProof,
    resolveEmailOtpAuthority: ctx.service.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject,
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
      {
        ok: false,
        code: 'challenge_expired_or_invalid',
        message: 'Email OTP challenge expired or invalid',
      },
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
        credential.index.lifecycle.state !== 'active'
      ) {
        return [];
      }
      return [
        {
          credentialIdB64u: credential.index.factor.credentialIdB64u,
          ...((credential.index.deviceLabel ?? credential.activity.label)
            ? { label: credential.index.deviceLabel ?? credential.activity.label }
            : {}),
        },
      ];
    });
  } catch {
    return null;
  }
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
