import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  type RouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
} from '../../../core/ThresholdService/validation';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind } from '../../routerApi';
import {
  signRouterAbEcdsaDerivationWalletSessionJwt,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../commonRouterUtils';
import {
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  parseRouterAbEcdsaDerivationRecoveryRequestV1,
  ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH,
  ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationExplicitExportRequestV1,
  type RouterAbEcdsaDerivationRecoveryRequestV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  handleRouterAbEcdsaDerivationNormalSigningRouteCore,
  ROUTER_AB_ECDSA_DERIVATION_PRIVATE_SIGNING_PATHS,
  type RouterAbEcdsaDerivationPrivateSigningPath,
} from '../../routerAbPrivateSigningWorker';
import {
  parseRouterAbEcdsaDerivationPoolFillInitRouteRequest,
  parseRouterAbEcdsaDerivationPoolFillStepRouteRequest,
} from '../../thresholdEcdsaRequestValidation';
import type {
  RouterAbEcdsaStrictPostRegistrationPort,
  RouterAbEcdsaStrictPostRegistrationResult,
  RouterAbEcdsaStrictExportAuthority,
  RouterAbEcdsaStrictRegistrationAuthority,
} from '../../routerAbEcdsaStrictRegistration';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  walletSessionFailure,
  walletSessionFailureStatus,
  walletSessionParseFailure,
  type WalletSessionBoundaryFailure,
} from '../../walletSessionFailure';

const NOT_IMPLEMENTED = {
  ok: false,
  code: 'not_implemented',
  message: 'threshold-ecdsa is not implemented',
} as const;

async function handleRouterAbEcdsaDerivationNormalSigningRoute(input: {
  ctx: CloudflareRouterApiContext;
  body: Record<string, unknown>;
  privatePath: RouterAbEcdsaDerivationPrivateSigningPath;
  phase: 'prepare' | 'finalize';
}): Promise<Response> {
  const result = await handleRouterAbEcdsaDerivationNormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    runtime: input.ctx.service.thresholdRuntime.getRouterAbNormalSigningRuntime(),
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    privatePath: input.privatePath,
    phase: input.phase,
  });
  return json(result.body, { status: result.status });
}

type PresignTrafficClass = 'foreground' | 'background';

type PresignPriorityTicket = {
  release: () => void;
};

class PresignPriorityGate {
  private foregroundInFlight = 0;
  private backgroundInFlight = 0;
  private readonly backgroundQueue: Array<{
    resolve: (ticket: PresignPriorityTicket) => void;
  }> = [];

  async acquire(trafficClass: PresignTrafficClass): Promise<PresignPriorityTicket> {
    if (trafficClass === 'foreground') {
      this.foregroundInFlight += 1;
      return this.createTicket('foreground');
    }
    if (this.canRunBackgroundNow()) {
      this.backgroundInFlight += 1;
      return this.createTicket('background');
    }
    return await new Promise((resolve) => {
      this.backgroundQueue.push({ resolve });
    });
  }

  private createTicket(trafficClass: PresignTrafficClass): PresignPriorityTicket {
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        if (trafficClass === 'foreground') {
          this.foregroundInFlight = Math.max(0, this.foregroundInFlight - 1);
        } else {
          this.backgroundInFlight = Math.max(0, this.backgroundInFlight - 1);
        }
        this.drainBackgroundQueue();
      },
    };
  }

  private canRunBackgroundNow(): boolean {
    return this.foregroundInFlight === 0 && this.backgroundInFlight === 0;
  }

  private drainBackgroundQueue(): void {
    if (!this.canRunBackgroundNow()) return;
    const next = this.backgroundQueue.shift();
    if (!next) return;
    this.backgroundInFlight += 1;
    next.resolve(this.createTicket('background'));
  }
}

function parsePresignRequestTag(body: unknown): string | undefined {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined;
  const tag = String((body as { requestTag?: unknown }).requestTag || '').trim();
  return tag || undefined;
}

function resolvePresignTrafficClass(requestTag: string | undefined): PresignTrafficClass {
  return requestTag === 'background_presign_pool_refill' ? 'background' : 'foreground';
}

const presignPriorityGate = new PresignPriorityGate();

type StrictEcdsaPostRegistrationRequest =
  | {
      readonly kind: 'export';
      readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
    }
  | {
      readonly kind: 'recovery';
      readonly request: RouterAbEcdsaDerivationRecoveryRequestV1;
    }
  | {
      readonly kind: 'refresh';
      readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
    };

type StrictEcdsaPostRegistrationAuthorization =
  | {
      readonly ok: true;
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      readonly ecdsaClaims: RouterAbEcdsaDerivationWalletSessionClaims | null;
    }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure;

type StrictEcdsaAuthorizationClaims = {
  readonly appSessionClaims: NonNullable<ReturnType<typeof parseAppSessionClaims>> | null;
  readonly ecdsaClaims: RouterAbEcdsaDerivationWalletSessionClaims | null;
  readonly ed25519Claims: NonNullable<
    ReturnType<typeof parseRouterAbEd25519WalletSessionClaims>
  > | null;
  readonly expiresAtMs: number;
};

type StrictEcdsaAuthorizationClaimsResult =
  | { readonly ok: true; readonly claims: StrictEcdsaAuthorizationClaims }
  | WalletSessionBoundaryFailure;

function strictEcdsaAuthorizationFailureStatus(
  failure: Extract<StrictEcdsaPostRegistrationAuthorization, { readonly ok: false }>,
): number {
  switch (failure.code) {
    case 'unauthorized':
      return 401;
    case 'identity_mismatch':
      return 403;
    default:
      return walletSessionFailureStatus(failure.code);
  }
}

async function parseStrictEcdsaAuthorizationSession(
  ctx: CloudflareRouterApiContext,
): Promise<
  { readonly ok: true; readonly claims: Record<string, unknown> } | WalletSessionBoundaryFailure
> {
  const session = ctx.opts.session;
  if (!session) return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  try {
    const parsed = await session.parse(Object.fromEntries(ctx.request.headers.entries()));
    if (!parsed.ok) return walletSessionParseFailure(parsed.reason);
    return { ok: true, claims: parsed.claims };
  } catch {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  }
}

async function resolveStrictEcdsaAuthorizationClaims(input: {
  readonly ctx: CloudflareRouterApiContext;
  readonly rawClaims: Record<string, unknown>;
}): Promise<StrictEcdsaAuthorizationClaimsResult> {
  const appSessionClaims = parseAppSessionClaims(input.rawClaims);
  const ecdsaClaims = parseRouterAbEcdsaDerivationWalletSessionClaims(input.rawClaims);
  const ed25519Claims = parseRouterAbEd25519WalletSessionClaims(input.rawClaims);
  if (!appSessionClaims && !ecdsaClaims && !ed25519Claims) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
  }
  if (appSessionClaims) {
    try {
      const version = await input.ctx.service.sessionVersions.validateAppSessionVersion({
        userId: appSessionClaims.sub,
        appSessionVersion: appSessionClaims.appSessionVersion,
      });
      if (!version.ok) {
        return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
      }
    } catch {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
    }
  }
  const expSeconds = appSessionClaims?.exp ?? ecdsaClaims?.exp ?? ed25519Claims?.exp;
  if (expSeconds === undefined || !Number.isSafeInteger(expSeconds) || expSeconds <= 0) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
  }
  const expiresAtMs = expSeconds * 1000;
  if (!Number.isSafeInteger(expiresAtMs)) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
  }
  if (expiresAtMs <= Date.now()) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.expired);
  }
  return {
    ok: true,
    claims: {
      appSessionClaims,
      ecdsaClaims,
      ed25519Claims,
      expiresAtMs,
    },
  };
}

function parseStrictEcdsaPostRegistrationRequest(
  pathname: string,
  body: unknown,
): StrictEcdsaPostRegistrationRequest {
  switch (pathname) {
    case ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH:
      return {
        kind: 'export',
        request: parseRouterAbEcdsaDerivationExplicitExportRequestV1(body),
      };
    case ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH:
      return {
        kind: 'recovery',
        request: parseRouterAbEcdsaDerivationRecoveryRequestV1(body),
      };
    case ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH:
      return {
        kind: 'refresh',
        request: parseRouterAbEcdsaDerivationActivationRefreshRequestV1(body),
      };
    default:
      throw new Error('Strict ECDSA post-registration path is invalid');
  }
}

function strictEcdsaPostRegistrationRequestAuthority(
  input: StrictEcdsaPostRegistrationRequest,
): RouterAbEcdsaStrictRegistrationAuthority {
  return {
    subjectId: input.request.client_id,
    sessionId: input.request.lifecycle.session_id,
    accountId: input.request.lifecycle.account_id,
    expiresAtMs: input.request.expires_at_ms,
  };
}

type StrictEcdsaRequestExpiryValidation =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'unauthorized' }
  | { readonly ok: false; readonly code: typeof WALLET_SESSION_FAILURE_CODES.scopeMismatch };

function validateStrictEcdsaPostRegistrationRequestExpiry(input: {
  readonly requestExpiresAtMs: number;
  readonly sessionExpiresAtMs: number;
}): StrictEcdsaRequestExpiryValidation {
  const nowMs = Date.now();
  if (input.requestExpiresAtMs <= nowMs || input.requestExpiresAtMs > nowMs + 10 * 60_000) {
    return { ok: false, code: 'unauthorized' };
  }
  if (input.requestExpiresAtMs > input.sessionExpiresAtMs) {
    return { ok: false, code: WALLET_SESSION_FAILURE_CODES.scopeMismatch };
  }
  return { ok: true };
}

async function authorizeStrictEcdsaPostRegistrationRequest(input: {
  readonly ctx: CloudflareRouterApiContext;
  readonly request: StrictEcdsaPostRegistrationRequest;
}): Promise<StrictEcdsaPostRegistrationAuthorization> {
  const authority = strictEcdsaPostRegistrationRequestAuthority(input.request);
  if (
    authority.subjectId !== authority.accountId ||
    input.request.request.signer_set.signer_set_id !==
      input.request.request.lifecycle.signer_set_id ||
    input.request.request.signer_set.selected_server.server_id !==
      input.request.request.lifecycle.selected_server_id
  ) {
    return {
      ok: false,
      code: 'identity_mismatch',
      message: 'Strict ECDSA request identity does not match its lifecycle',
    };
  }
  const parsedSession = await parseStrictEcdsaAuthorizationSession(input.ctx);
  if (!parsedSession.ok) {
    return parsedSession;
  }
  const resolvedClaims = await resolveStrictEcdsaAuthorizationClaims({
    ctx: input.ctx,
    rawClaims: parsedSession.claims,
  });
  if (!resolvedClaims.ok) return resolvedClaims;
  const { appSessionClaims, ecdsaClaims, ed25519Claims, expiresAtMs } = resolvedClaims.claims;
  const expiry = validateStrictEcdsaPostRegistrationRequestExpiry({
    requestExpiresAtMs: authority.expiresAtMs,
    sessionExpiresAtMs: expiresAtMs,
  });
  if (!expiry.ok && expiry.code === WALLET_SESSION_FAILURE_CODES.scopeMismatch) {
    return walletSessionFailure(expiry.code);
  }
  if (!expiry.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Strict ECDSA request expiry is invalid',
    };
  }
  if (
    ecdsaClaims?.walletId === authority.accountId ||
    ed25519Claims?.walletId === authority.accountId
  ) {
    return { ok: true, authority, ecdsaClaims };
  }
  const appSessionWalletId = resolveAppSessionWalletIdForWalletScope(
    appSessionClaims,
    authority.accountId,
  );
  if (appSessionWalletId === authority.accountId) {
    return { ok: true, authority, ecdsaClaims: null };
  }
  const providerUserId = resolveAppSessionProviderUserIdForWalletScope(
    appSessionClaims,
    authority.accountId,
  );
  if (providerUserId) {
    try {
      const enrollment = await input.ctx.service.emailOtp.readActiveEmailOtpEnrollment({
        walletId: authority.accountId,
        orgId: appSessionClaims?.runtimePolicyScope?.orgId,
        providerUserId,
      });
      if (enrollment.ok && enrollment.enrollment.providerUserId === providerUserId) {
        return { ok: true, authority, ecdsaClaims: null };
      }
    } catch {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
    }
  }
  return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
}

async function handleStrictEcdsaPostRegistrationRoute(input: {
  readonly ctx: CloudflareRouterApiContext;
  readonly body: unknown;
  readonly pathname: string;
  readonly port: RouterAbEcdsaStrictPostRegistrationPort | null | undefined;
}): Promise<Response> {
  if (!input.port) {
    return json(
      {
        ok: false,
        code: 'not_configured',
        message: 'Strict Router A/B ECDSA post-registration port is not configured',
      },
      { status: 503 },
    );
  }
  let parsed: StrictEcdsaPostRegistrationRequest;
  try {
    parsed = parseStrictEcdsaPostRegistrationRequest(input.pathname, input.body);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message:
          error instanceof Error
            ? error.message
            : 'Strict ECDSA post-registration request is invalid',
      },
      { status: 400 },
    );
  }
  const authorized = await authorizeStrictEcdsaPostRegistrationRequest({
    ctx: input.ctx,
    request: parsed,
  });
  if (!authorized.ok) {
    return json(authorized, {
      status: strictEcdsaAuthorizationFailureStatus(authorized),
    });
  }
  switch (parsed.kind) {
    case 'export': {
      const exportAuthority = strictEcdsaExportAuthority({
        request: parsed.request,
        authorization: authorized,
      });
      if (!exportAuthority) {
        const failure = walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
        return json(failure, { status: walletSessionFailureStatus(failure.code) });
      }
      const result = await input.port.explicitExport({
        request: parsed.request,
        authority: exportAuthority,
      });
      if (!result.ok) return strictPostRegistrationFailureResponse(result);
      return json(result.value, { status: 200 });
    }
    case 'recovery': {
      const result = await input.port.recover({
        request: parsed.request,
        authority: authorized.authority,
      });
      if (!result.ok) return strictPostRegistrationFailureResponse(result);
      const recorded = await input.ctx.service.walletRegistration.recordEcdsaPostRegistrationProof({
        operation: 'recovery',
        request: parsed.request,
        response: result.value,
      });
      if (!recorded.ok) {
        return json(recorded, { status: recorded.code === 'internal' ? 500 : 400 });
      }
      return json(result.value, { status: 200 });
    }
    case 'refresh': {
      const result = await input.port.refresh({
        request: parsed.request,
        authority: authorized.authority,
      });
      if (!result.ok) return strictPostRegistrationFailureResponse(result);
      const recorded = await input.ctx.service.walletRegistration.recordEcdsaPostRegistrationProof({
        operation: 'refresh',
        request: parsed.request,
        response: result.value,
      });
      if (!recorded.ok) {
        return json(recorded, { status: recorded.code === 'internal' ? 500 : 400 });
      }
      return json(result.value, { status: 200 });
    }
  }
}

function strictEcdsaExportAuthority(input: {
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly authorization: Extract<StrictEcdsaPostRegistrationAuthorization, { readonly ok: true }>;
}): RouterAbEcdsaStrictExportAuthority | null {
  const claims = input.authorization.ecdsaClaims;
  if (
    !claims ||
    claims.walletId !== input.request.lifecycle.account_id ||
    claims.thresholdSessionId !== input.request.lifecycle.session_id ||
    claims.evmFamilySigningKeySlotId !==
      claims.routerAbEcdsaDerivationNormalSigning.scope.wallet_key_id
  ) {
    return null;
  }
  const scope = claims.routerAbEcdsaDerivationNormalSigning.scope;
  if (
    scope.wallet_id !== input.request.lifecycle.account_id ||
    scope.context.application_binding_digest_b64u !==
      input.request.context.application_binding_digest_b64u ||
    scope.public_identity.context_binding_b64u !==
      input.request.public_identity.context_binding_b64u ||
    scope.public_identity.threshold_public_key33_b64u !==
      input.request.public_identity.threshold_public_key33_b64u ||
    scope.signing_worker.server_id !== input.request.lifecycle.selected_server_id ||
    scope.activation_epoch !== input.request.lifecycle.root_share_epoch
  ) {
    return null;
  }
  return {
    subjectId: input.authorization.authority.subjectId,
    sessionId: input.authorization.authority.sessionId,
    accountId: input.authorization.authority.accountId,
    expiresAtMs: input.authorization.authority.expiresAtMs,
    keyHandle: claims.keyHandle,
    signingGrantId: claims.signingGrantId,
    normalSigningScope: scope,
  };
}

function strictPostRegistrationFailureResponse(
  result: Extract<RouterAbEcdsaStrictPostRegistrationResult, { readonly ok: false }>,
): Response {
  return json(
    {
      ok: false,
      code: result.code,
      message: result.message,
    },
    { status: result.retryable ? 502 : 400 },
  );
}

async function authorizeStrictEcdsaSessionActivation(input: {
  readonly ctx: CloudflareRouterApiContext;
  readonly walletId: string;
}): Promise<
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure
> {
  const parsedSession = await parseStrictEcdsaAuthorizationSession(input.ctx);
  if (!parsedSession.ok) return parsedSession;
  const resolvedClaims = await resolveStrictEcdsaAuthorizationClaims({
    ctx: input.ctx,
    rawClaims: parsedSession.claims,
  });
  if (!resolvedClaims.ok) return resolvedClaims;
  const { appSessionClaims, ecdsaClaims, ed25519Claims } = resolvedClaims.claims;
  if (ecdsaClaims?.walletId === input.walletId || ed25519Claims?.walletId === input.walletId) {
    return { ok: true };
  }
  if (
    resolveAppSessionWalletIdForWalletScope(appSessionClaims, input.walletId) === input.walletId
  ) {
    return { ok: true };
  }
  const providerUserId = resolveAppSessionProviderUserIdForWalletScope(
    appSessionClaims,
    input.walletId,
  );
  if (providerUserId) {
    try {
      const enrollment = await input.ctx.service.emailOtp.readActiveEmailOtpEnrollment({
        walletId: input.walletId,
        orgId: appSessionClaims?.runtimePolicyScope?.orgId,
        providerUserId,
      });
      if (enrollment.ok && enrollment.enrollment.providerUserId === providerUserId) {
        return { ok: true };
      }
    } catch {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
    }
  }
  return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
}

async function handleStrictEcdsaSessionActivation(input: {
  readonly ctx: CloudflareRouterApiContext;
  readonly body: unknown;
}): Promise<Response> {
  let request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
  try {
    request = parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1(input.body);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message:
          error instanceof Error
            ? error.message
            : 'ECDSA post-registration session activation is invalid',
      },
      { status: 400 },
    );
  }
  const authorized = await authorizeStrictEcdsaSessionActivation({
    ctx: input.ctx,
    walletId: request.public_capability.client_id,
  });
  if (!authorized.ok) {
    return json(authorized, {
      status: strictEcdsaAuthorizationFailureStatus(authorized),
    });
  }
  const activated =
    await input.ctx.service.walletRegistration.activateEcdsaPostRegistrationSession(request);
  if (!activated.ok) {
    return json(activated, {
      status: activated.code === 'not_found' ? 404 : activated.code === 'internal' ? 500 : 400,
    });
  }
  const walletKey = activated.walletKey;
  const normalSigning = activated.normalSigning;
  const signed = await signRouterAbEcdsaDerivationWalletSessionJwt({
    session: input.ctx.opts.session,
    userId: walletKey.walletId,
    evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
    relayerKeyId: walletKey.relayerKeyId,
    sessionInfo: {
      sessionKind: 'jwt',
      thresholdSessionId: activated.session.thresholdSessionId,
      signingGrantId: activated.session.signingGrantId,
      expiresAtMs: activated.session.expiresAtMs,
      participantIds: walletKey.participantIds,
      runtimePolicyScope: request.session_policy.runtime_policy_scope,
      keyHandle: walletKey.keyHandle,
      stableKeyContext: {
        walletId: walletKey.walletId,
        evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
        keyScope: walletKey.keyScope,
        ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
        signingRootId: walletKey.signingRootId,
        signingRootVersion: walletKey.signingRootVersion,
        applicationBindingDigestB64u: normalSigning.scope.context.application_binding_digest_b64u,
        contextBinding32B64u: normalSigning.scope.public_identity.context_binding_b64u,
      },
      publicIdentity: {
        derivationClientSharePublicKey33B64u:
          normalSigning.scope.public_identity.derivation_client_share_public_key33_b64u,
        relayerPublicKey33B64u: normalSigning.scope.public_identity.server_public_key33_b64u,
        groupPublicKey33B64u: normalSigning.scope.public_identity.threshold_public_key33_b64u,
        ethereumAddress: walletKey.thresholdOwnerAddress,
      },
      activationEpoch: normalSigning.scope.activation_epoch,
      signingWorkerId: normalSigning.scope.signing_worker.server_id,
      routerAbEcdsaDerivationNormalSigning: normalSigning,
    },
    fallbackParticipantIds: walletKey.participantIds,
    requireJwtErrorMessage:
      'Router A/B ECDSA post-registration Wallet Session must use jwt sessionKind',
    invalidPayloadErrorMessage: 'invalid Router A/B ECDSA post-registration Wallet Session payload',
  });
  if (!signed.ok) {
    return json(
      {
        ok: false,
        code: signed.code,
        message: signed.message,
      },
      { status: signed.status },
    );
  }
  return json(
    {
      kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
      public_capability: request.public_capability,
      session: {
        threshold_session_id: activated.session.thresholdSessionId,
        signing_grant_id: activated.session.signingGrantId,
        expires_at_ms: activated.session.expiresAtMs,
        remaining_uses: activated.session.remainingUses,
        wallet_session_jwt: signed.jwt,
      },
      normal_signing: normalSigning,
    },
    { status: 200 },
  );
}

export async function handleThresholdEcdsa(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH) {
    const runtime = ctx.service.thresholdRuntime.getRouterAbEcdsaPresignRuntime();
    if (!runtime) {
      const body = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B ECDSA presign runtime is not configured on this server',
        configured: false,
      };
      return json(body, { status: thresholdEcdsaStatusCode(body) });
    }
    const health = runtime.healthz();
    if (health.ok) return json({ ok: true, configured: true }, { status: 200 });
    const body = { ...NOT_IMPLEMENTED, configured: true };
    return json(body, { status: thresholdEcdsaStatusCode(body) });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request);
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH) {
    return handleStrictEcdsaSessionActivation({
      ctx,
      body: bodyUnknown,
    });
  }
  if (
    pathname === ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH ||
    pathname === ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH ||
    pathname === ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH
  ) {
    return handleStrictEcdsaPostRegistrationRoute({
      ctx,
      body: bodyUnknown,
      pathname,
      port: ctx.opts.routerAbEcdsaStrictPostRegistration,
    });
  }
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH) {
    return handleRouterAbEcdsaDerivationNormalSigningRoute({
      ctx,
      body,
      privatePath: ROUTER_AB_ECDSA_DERIVATION_PRIVATE_SIGNING_PATHS.prepare,
      phase: 'prepare',
    });
  }

  if (pathname === ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH) {
    return handleRouterAbEcdsaDerivationNormalSigningRoute({
      ctx,
      body,
      privatePath: ROUTER_AB_ECDSA_DERIVATION_PRIVATE_SIGNING_PATHS.finalize,
      phase: 'finalize',
    });
  }

  if (pathname === ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH) {
    const runtime = ctx.service.thresholdRuntime.getRouterAbEcdsaPresignRuntime();
    if (!runtime) {
      const failure = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B ECDSA presign runtime is not configured on this server',
      };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const parsedBody = parseRouterAbEcdsaDerivationPoolFillInitRouteRequest(body);
    const requestTag = parsedBody.ok ? parsedBody.request.requestTag : undefined;
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    try {
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEcdsaStatusCode(parsedBody.body) });
      }
      const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
        body: parsedBody.request,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
      const result = await runtime.initializePoolFill({
        claims: validated.claims,
        request: parsedBody.request,
      });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH) {
    const runtime = ctx.service.thresholdRuntime.getRouterAbEcdsaPresignRuntime();
    if (!runtime) {
      const failure = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B ECDSA presign runtime is not configured on this server',
      };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const parsedBody = parseRouterAbEcdsaDerivationPoolFillStepRouteRequest(body);
    const requestTag = parsedBody.ok ? parsedBody.request.requestTag : undefined;
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    try {
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEcdsaStatusCode(parsedBody.body) });
      }
      const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
        body: parsedBody.request,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
      const result = await runtime.advancePoolFill({
        claims: validated.claims,
        request: parsedBody.request,
      });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  return null;
}
