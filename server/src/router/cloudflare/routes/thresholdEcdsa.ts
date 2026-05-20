import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import type {
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaHssFinalizeRequest,
  ThresholdEcdsaHssPrepareRequest,
  ThresholdEcdsaHssRespondRequest,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignInitRequest,
} from '../../../core/types';
import {
  parseAppSessionClaims,
  parseRegistrationContinuationClaims,
  parseThresholdEcdsaSessionClaims,
  parseThresholdEd25519SessionClaims,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
} from '../../../core/ThresholdService/validation';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  resolveThresholdRuntimePolicyScope,
  signThresholdSessionAuthToken,
  validateThresholdEcdsaAuthorizeInputs,
  validateThresholdEcdsaSessionInputs,
  validateThresholdEd25519SessionTokenInputs,
} from '../../commonRouterUtils';
import { validateRuntimeSnapshotExpectation } from '../../runtimeSnapshotConsumer';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';

type EcdsaRuntimePolicyScope = NonNullable<
  ThresholdEcdsaHssPrepareRequest['sessionPolicy']
>['runtimePolicyScope'];

const NOT_IMPLEMENTED = {
  ok: false,
  code: 'not_implemented',
  message: 'threshold-ecdsa is not implemented',
} as const;

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

function normalizeEcdsaRuntimePolicyScope(raw: unknown): EcdsaRuntimePolicyScope | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const scope = raw as {
    orgId?: unknown;
    envId?: unknown;
    projectId?: unknown;
    signingRootVersion?: unknown;
  };
  const orgId = String(scope.orgId || '').trim();
  const envId = String(scope.envId || '').trim();
  const projectId = String(scope.projectId || '').trim();
  const signingRootVersion = String(scope.signingRootVersion || '').trim();
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return {
    orgId,
    projectId,
    envId,
    signingRootVersion,
  };
}

function resolveEcdsaRuntimePolicyScopeFromClaims(input: {
  appSessionClaims: ReturnType<typeof parseAppSessionClaims>;
  ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims>;
  ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims>;
  registrationContinuationClaims: ReturnType<typeof parseRegistrationContinuationClaims>;
}): EcdsaRuntimePolicyScope | undefined {
  return (
    normalizeEcdsaRuntimePolicyScope(input.registrationContinuationClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ed25519SessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.appSessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ecdsaSessionClaims?.runtimePolicyScope)
  );
}

function applyEcdsaRuntimePolicyScope(
  body: ThresholdEcdsaHssPrepareRequest,
  runtimePolicyScope: EcdsaRuntimePolicyScope | undefined,
): ThresholdEcdsaHssPrepareRequest {
  if (!runtimePolicyScope) return body;
  switch (body.operation) {
    case 'registration_bootstrap':
    case 'email_otp_bootstrap':
    case 'session_bootstrap':
      return {
        ...body,
        sessionPolicy: {
          ...body.sessionPolicy,
          runtimePolicyScope,
        },
      };
    case 'explicit_key_export':
      return body;
  }
}

function attachEcdsaPrepareRouteClaims(input: {
  body: ThresholdEcdsaHssPrepareRequest;
  appSessionClaims: ReturnType<typeof parseAppSessionClaims>;
  ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims>;
  ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims>;
  registrationContinuationClaims: ReturnType<typeof parseRegistrationContinuationClaims>;
  emailOtpEnrollmentClaims: ThresholdEcdsaHssPrepareRequest['emailOtpEnrollmentClaims'] | undefined;
}): ThresholdEcdsaHssPrepareRequest {
  const shared = {
    appSessionClaims: input.appSessionClaims || undefined,
    ed25519SessionClaims: input.ed25519SessionClaims || undefined,
    ecdsaSessionClaims: input.ecdsaSessionClaims || undefined,
  };
  switch (input.body.operation) {
    case 'registration_bootstrap':
      return {
        ...input.body,
        ...shared,
        registrationContinuationClaims: input.registrationContinuationClaims || undefined,
      };
    case 'email_otp_bootstrap':
      return {
        ...input.body,
        ...shared,
        emailOtpEnrollmentClaims: input.emailOtpEnrollmentClaims,
      };
    case 'session_bootstrap':
      return {
        ...input.body,
        ...shared,
        registrationContinuationClaims: input.registrationContinuationClaims || undefined,
      };
    case 'explicit_key_export':
      return {
        ...input.body,
        ...shared,
        ecdsaSessionClaims: input.ecdsaSessionClaims || input.body.ecdsaSessionClaims,
      };
  }
}

async function resolveEmailOtpEnrollmentClaimsForThresholdEcdsa(
  ctx: CloudflareRelayContext,
  body: ThresholdEcdsaHssPrepareRequest,
  runtimePolicyScope: EcdsaRuntimePolicyScope | undefined,
  appSessionClaims: ReturnType<typeof parseAppSessionClaims>,
  ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims>,
  ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims>,
): Promise<ThresholdEcdsaHssPrepareRequest['emailOtpEnrollmentClaims'] | undefined> {
  if (body.operation !== 'email_otp_bootstrap') return undefined;
  const sessionClaims = appSessionClaims || ed25519SessionClaims || ecdsaSessionClaims;
  if (!sessionClaims) return undefined;
  const walletSessionUserId = String(body.walletSessionUserId || '').trim();
  if (!walletSessionUserId) {
    return undefined;
  }
  const appSessionWalletId = resolveAppSessionWalletIdForWalletScope(
    appSessionClaims,
    walletSessionUserId,
  );
  const appSessionProviderUserId = resolveAppSessionProviderUserIdForWalletScope(
    appSessionClaims,
    walletSessionUserId,
  );
  if (appSessionClaims) {
    if (appSessionWalletId && appSessionWalletId !== walletSessionUserId) return undefined;
    if (!appSessionWalletId && !appSessionProviderUserId) return undefined;
  } else if (String(sessionClaims.walletId || '').trim() !== walletSessionUserId) {
    return undefined;
  }
  const sessionOrgId =
    appSessionClaims?.runtimePolicyScope?.orgId ||
    ed25519SessionClaims?.runtimePolicyScope?.orgId ||
    ecdsaSessionClaims?.runtimePolicyScope?.orgId ||
    runtimePolicyScope?.orgId;
  const enrollment = await ctx.service.readActiveEmailOtpEnrollment({
    walletId: walletSessionUserId,
    orgId: String(sessionOrgId || '').trim() || undefined,
    providerUserId: appSessionProviderUserId,
  });
  if (!enrollment.ok) return undefined;
  const verifier = String(
    enrollment.enrollment.thresholdEcdsaClientVerifyingShareB64u || '',
  ).trim();
  // App-session subjects can be provider-scoped or wallet-scoped depending on
  // the issuing unlock path.
  if (
    (appSessionProviderUserId &&
      enrollment.enrollment.providerUserId !== appSessionProviderUserId) ||
    !verifier
  ) {
    return undefined;
  }
  return {
    walletId: enrollment.enrollment.walletId,
    userId: enrollment.enrollment.providerUserId,
    otpChannel: EMAIL_OTP_CHANNEL,
    thresholdEcdsaClientVerifyingShareB64u: verifier,
  };
}

const presignPriorityGate = new PresignPriorityGate();

export async function handleThresholdEcdsa(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === '/threshold-ecdsa/healthz') {
    const resolved = resolveThresholdScheme(
      ctx.opts.threshold,
      THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      {
        notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
      },
    );
    if (!resolved.ok) {
      const resBody = { ...resolved, configured: false };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    const scheme = resolved.scheme;

    const health = await scheme.healthz();
    if (health.ok) return json({ ok: true, configured: true }, { status: 200 });
    const body = { ...(health.code ? health : NOT_IMPLEMENTED), configured: true };
    return json(body, { status: thresholdEcdsaStatusCode(body) });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== '/threshold-ecdsa/key-identities' &&
    pathname !== '/threshold-ecdsa/hss/prepare' &&
    pathname !== '/threshold-ecdsa/hss/respond' &&
    pathname !== '/threshold-ecdsa/hss/finalize' &&
    pathname !== '/threshold-ecdsa/authorize' &&
    pathname !== '/threshold-ecdsa/presign/init' &&
    pathname !== '/threshold-ecdsa/presign/step' &&
    pathname !== '/threshold-ecdsa/sign/init' &&
    pathname !== '/threshold-ecdsa/sign/finalize' &&
    pathname !== '/threshold-ecdsa/internal/cosign/init' &&
    pathname !== '/threshold-ecdsa/internal/cosign/finalize'
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  const resolved = resolveThresholdScheme(
    ctx.opts.threshold,
    THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    {
      notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
    },
  );
  if (!resolved.ok) {
    return json(resolved, { status: thresholdEcdsaStatusCode(resolved) });
  }
  const scheme = resolved.scheme;

  if (pathname === '/threshold-ecdsa/key-identities') {
    const validated = await validateThresholdEd25519SessionTokenInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    if (!validated.ok) {
      return json(validated, { status: thresholdEcdsaStatusCode(validated) });
    }
    if (validated.claims.thresholdExpiresAtMs <= Date.now()) {
      const result = {
        ok: false,
        code: 'unauthorized' as const,
        message: 'Threshold Ed25519 session is expired',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const bodyRecord =
      body && typeof body === 'object' && !Array.isArray(body)
        ? (body as Record<string, unknown>)
        : {};
    const keyInventory = await ctx.service.listThresholdEcdsaKeyIdentityTargetsForUser({
      userId: validated.claims.walletId,
      rpId: validated.claims.rpId,
      keyTargets: Array.isArray(bodyRecord.keyTargets) ? bodyRecord.keyTargets : [],
    });
    ctx.logger.info('[threshold-ecdsa][key-identities][diagnostic]', {
      walletId: validated.claims.walletId,
      ...keyInventory.diagnostics,
    });
    return json(
      {
        ok: true,
        ecdsaKeyIdentityTargets: keyInventory.records,
        diagnostics: keyInventory.diagnostics,
      },
      { status: 200 },
    );
  }

  if (pathname === '/threshold-ecdsa/hss/prepare') {
    if (!scheme.hss) {
      const resBody = {
        ok: false,
        code: 'not_implemented',
        message: 'threshold-ecdsa hss prepare is not implemented on this server',
      };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    const reqBody = (body || {}) as ThresholdEcdsaHssPrepareRequest;
    const session = ctx.opts.session;
    let appSessionClaims: ReturnType<typeof parseAppSessionClaims> = null;
    let ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims> = null;
    let ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims> = null;
    let registrationContinuationClaims: ReturnType<typeof parseRegistrationContinuationClaims> =
      null;
    if (session) {
      const parsedSession = await session.parse(Object.fromEntries(ctx.request.headers.entries()));
      if (parsedSession.ok) {
        appSessionClaims = parseAppSessionClaims(parsedSession.claims);
        if (appSessionClaims) {
          const validated = await ctx.service.validateAppSessionVersion({
            userId: appSessionClaims.sub,
            appSessionVersion: appSessionClaims.appSessionVersion,
          });
          if (!validated.ok) {
            appSessionClaims = null;
          }
        }
        ed25519SessionClaims = parseThresholdEd25519SessionClaims(parsedSession.claims);
        ecdsaSessionClaims = parseThresholdEcdsaSessionClaims(parsedSession.claims);
        registrationContinuationClaims = parseRegistrationContinuationClaims(parsedSession.claims);
      }
    }
    const inheritedRuntimePolicyScope = resolveEcdsaRuntimePolicyScopeFromClaims({
      appSessionClaims,
      ed25519SessionClaims,
      ecdsaSessionClaims,
      registrationContinuationClaims,
    });
    const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
      explicitScopeRaw: inheritedRuntimePolicyScope ?? reqBody.sessionPolicy?.runtimePolicyScope,
      runtimeEnvironmentIdRaw: (reqBody as { runtimeEnvironmentId?: unknown }).runtimeEnvironmentId,
      headers: ctx.request.headers,
      origin: ctx.request.headers.get('origin'),
      publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
      orgProjectEnv: ctx.opts.orgProjectEnv || null,
    });
    if (!runtimePolicyScopeResolution.ok) {
      return json(
        {
          ok: false,
          code: runtimePolicyScopeResolution.code,
          message: runtimePolicyScopeResolution.message,
        },
        { status: runtimePolicyScopeResolution.status },
      );
    }
    const runtimePolicyScope = runtimePolicyScopeResolution.scope;
    const scopedBody = applyEcdsaRuntimePolicyScope(reqBody, runtimePolicyScope);
    const emailOtpEnrollmentClaims = await resolveEmailOtpEnrollmentClaimsForThresholdEcdsa(
      ctx,
      scopedBody,
      runtimePolicyScope,
      appSessionClaims,
      ed25519SessionClaims,
      ecdsaSessionClaims,
    );
    const request = attachEcdsaPrepareRouteClaims({
      body: scopedBody,
      appSessionClaims,
      emailOtpEnrollmentClaims,
      ed25519SessionClaims,
      ecdsaSessionClaims,
      registrationContinuationClaims,
    });
    const result = await scheme.hss.prepare(request);
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }

  if (pathname === '/threshold-ecdsa/hss/respond') {
    if (!scheme.hss) {
      const resBody = {
        ok: false,
        code: 'not_implemented',
        message: 'threshold-ecdsa hss respond is not implemented on this server',
      };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    const reqBody = (body || {}) as ThresholdEcdsaHssRespondRequest;
    const result = await scheme.hss.respond(reqBody);
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }

  if (pathname === '/threshold-ecdsa/hss/finalize') {
    if (!scheme.hss) {
      const resBody = {
        ok: false,
        code: 'not_implemented',
        message: 'threshold-ecdsa hss finalize is not implemented on this server',
      };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    const reqBody = (body || {}) as ThresholdEcdsaHssFinalizeRequest;
    const result = await scheme.hss.finalize(reqBody);
    if (!result.ok) {
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    if (!result.sessionId || !result.sessionAuthTokenUserId || !result.sessionAuthTokenRpId) {
      return json(result, { status: 200 });
    }
    const signed = await signThresholdSessionAuthToken({
      session: ctx.opts.session,
      kind: 'threshold_ecdsa_session_v1',
      userId: result.sessionAuthTokenUserId,
      rpId: result.sessionAuthTokenRpId,
      relayerKeyId: result.relayerKeyId,
      allowedSessionKinds: ['jwt', 'cookie'],
      sessionInfo: {
        sessionKind: result.sessionKind,
        sessionId: result.sessionId,
        walletSigningSessionId: result.walletSigningSessionId,
        expiresAtMs: result.expiresAtMs,
        participantIds: result.participantIds,
        subjectId: result.subjectId,
        chainTarget: result.chainTarget,
        keyHandle: result.keyHandle,
        ...(result.runtimePolicyScope
          ? { runtimePolicyScope: result.runtimePolicyScope }
          : {}),
      },
      fallbackParticipantIds: result.participantIds,
      requireJwtErrorMessage: 'threshold-ecdsa hss finalize requires sessionKind "jwt" or "cookie"',
      invalidPayloadErrorMessage: 'threshold-ecdsa hss finalize returned invalid session payload',
      sessionsDisabledMessage: 'Sessions are not configured on this server',
    });
    if (!signed.ok) {
      const resBody = {
        ok: false,
        code: signed.code,
        message: signed.message,
      };
      return json(resBody, { status: signed.status });
    }
    const {
      sessionAuthTokenUserId: _sessionAuthTokenUserId,
      sessionAuthTokenRpId: _sessionAuthTokenRpId,
      jwt: _rawJwt,
      ...rest
    } = result;
    const response = json(
      result.sessionKind === 'cookie' ? { ...rest, jwt: undefined } : { ...rest, jwt: signed.jwt },
      { status: thresholdEcdsaStatusCode(result) },
    );
    if (result.sessionKind === 'cookie') {
      response.headers.set('Set-Cookie', ctx.opts.session!.buildSetCookie(signed.jwt));
    }
    return response;
  }

  if (pathname === '/threshold-ecdsa/authorize') {
    const validated = await validateThresholdEcdsaAuthorizeInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
    const runtimeSnapshotValidation = await validateRuntimeSnapshotExpectation({
      runtimeSnapshots: ctx.opts.runtimeSnapshots,
      scope: validated.claims.runtimePolicyScope,
      expectationRaw: (validated.request as unknown as Record<string, unknown>).runtimeSnapshot,
    });
    if (!runtimeSnapshotValidation.ok) {
      return json(runtimeSnapshotValidation, {
        status: thresholdEcdsaStatusCode(runtimeSnapshotValidation),
      });
    }
    const result = await scheme.authorize({ claims: validated.claims, request: validated.request });
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }
  if (pathname === '/threshold-ecdsa/presign/init') {
    const reqBody = (body || {}) as ThresholdEcdsaPresignInitRequest;
    const requestTag = parsePresignRequestTag(reqBody);
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    const validated = await validateThresholdEcdsaSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    try {
      if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
      const result = await scheme.presign.init({ claims: validated.claims, request: reqBody });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  if (pathname === '/threshold-ecdsa/presign/step') {
    const reqBody = (body || {}) as ThresholdEcdsaPresignStepRequest;
    const requestTag = parsePresignRequestTag(reqBody);
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    const validated = await validateThresholdEcdsaSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    try {
      if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
      const result = await scheme.presign.step({ claims: validated.claims, request: reqBody });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  if (pathname === '/threshold-ecdsa/sign/init') {
    const reqBody = (body || {}) as ThresholdEcdsaSignInitRequest;
    const result = await scheme.protocol.signInit(reqBody);
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }
  if (pathname === '/threshold-ecdsa/sign/finalize') {
    const reqBody = (body || {}) as ThresholdEcdsaSignFinalizeRequest;
    const result = await scheme.protocol.signFinalize(reqBody);
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }
  if (pathname === '/threshold-ecdsa/internal/cosign/init') {
    const cosignInit = scheme.protocol.internalCosignInit;
    if (!cosignInit) {
      const resBody = {
        ok: false,
        code: 'not_found',
        message: 'threshold-ecdsa cosigner endpoints are not enabled on this server',
      };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    const reqBody = (body || {}) as ThresholdEcdsaCosignInitRequest;
    const result = await cosignInit(reqBody);
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }
  if (pathname === '/threshold-ecdsa/internal/cosign/finalize') {
    const cosignFinalize = scheme.protocol.internalCosignFinalize;
    if (!cosignFinalize) {
      const resBody = {
        ok: false,
        code: 'not_found',
        message: 'threshold-ecdsa cosigner endpoints are not enabled on this server',
      };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    const reqBody = (body || {}) as ThresholdEcdsaCosignFinalizeRequest;
    const result = await cosignFinalize(reqBody);
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }

  return null;
}
