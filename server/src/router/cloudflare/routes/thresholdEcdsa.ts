import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import type {
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignInitRequest,
} from '../../../core/types';
import {
  parseAppSessionClaims,
  parseEcdsaHssClientBootstrapRequest,
  parseEcdsaHssExportShareRequest,
  parseThresholdEcdsaSessionClaims,
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
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u,
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { verifySecp256k1RecoverableSignatureAgainstPublicKey33 } from '../../../core/ThresholdService/ethSignerWasm';

type EcdsaRuntimePolicyScope = RuntimePolicyScope;
type ThresholdEcdsaSessionClaims = NonNullable<ReturnType<typeof parseThresholdEcdsaSessionClaims>>;

const NOT_IMPLEMENTED = {
  ok: false,
  code: 'not_implemented',
  message: 'threshold-ecdsa is not implemented',
} as const;

function validateEcdsaHssSessionIdentity(input: {
  claims: ThresholdEcdsaSessionClaims;
  walletSessionUserId: string;
  rpId: string;
  subjectId: string;
  relayerKeyId: string;
}): { ok: true } | { ok: false; code: string; message: string } {
  if (input.claims.thresholdExpiresAtMs <= Date.now()) {
    return { ok: false, code: 'unauthorized', message: 'Threshold ECDSA session is expired' };
  }
  if (input.walletSessionUserId !== input.claims.walletId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletSessionUserId mismatch' };
  }
  if (input.rpId !== input.claims.rpId) {
    return { ok: false, code: 'identity_mismatch', message: 'rpId mismatch' };
  }
  if (input.subjectId !== input.claims.subjectId) {
    return { ok: false, code: 'identity_mismatch', message: 'subjectId mismatch' };
  }
  if (input.relayerKeyId !== input.claims.relayerKeyId) {
    return { ok: false, code: 'relayer_key_mismatch', message: 'relayerKeyId mismatch' };
  }
  return { ok: true };
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
  ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims>;
}): EcdsaRuntimePolicyScope | undefined {
  return (
    normalizeEcdsaRuntimePolicyScope(input.appSessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ecdsaSessionClaims?.runtimePolicyScope)
  );
}

async function authorizeEcdsaHssRoleLocalBootstrap(input: {
  ctx: CloudflareRelayContext;
  request: NonNullable<ReturnType<typeof parseEcdsaHssClientBootstrapRequest>>;
}): Promise<
  | { ok: true; runtimePolicyScope?: EcdsaRuntimePolicyScope }
  | { ok: false; code: string; message: string }
> {
  const { ctx, request } = input;
  const expectedRelayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletSessionUserId: request.walletSessionUserId,
    rpId: request.rpId,
  });
  if (request.relayerKeyId !== expectedRelayerKeyId) {
    return { ok: false, code: 'relayer_key_mismatch', message: 'relayerKeyId mismatch' };
  }
  const expectedThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletSessionUserId: request.walletSessionUserId,
    rpId: request.rpId,
    subjectId: request.subjectId,
    signingRootId: request.signingRootId,
    signingRootVersion: request.signingRootVersion,
  });
  if (request.ecdsaThresholdKeyId !== expectedThresholdKeyId) {
    return {
      ok: false,
      code: 'ecdsa_key_mismatch',
      message: 'ecdsaThresholdKeyId mismatch',
    };
  }
  const proof = request.clientRootProof;
  const passkeyAuthorization = request.passkeyBootstrapAuthorization;
  if (passkeyAuthorization) {
    const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
      explicitScopeRaw: passkeyAuthorization.runtimePolicyScope,
      runtimeEnvironmentIdRaw: passkeyAuthorization.runtimeEnvironmentId,
      headers: ctx.request.headers,
      origin: ctx.request.headers.get('origin'),
      publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
      orgProjectEnv: ctx.opts.orgProjectEnv || null,
    });
    if (!runtimePolicyScopeResolution.ok) {
      return {
        ok: false,
        code: runtimePolicyScopeResolution.code,
        message: runtimePolicyScopeResolution.message,
      };
    }
    const runtimePolicyScope = runtimePolicyScopeResolution.scope;
    if (!runtimePolicyScope) {
      return { ok: false, code: 'unauthorized', message: 'Missing runtime policy scope' };
    }
    const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
    if (
      request.signingRootId !== signingRootScope.signingRootId ||
      request.signingRootVersion !==
        (signingRootScope.signingRootVersion || runtimePolicyScope.signingRootVersion)
    ) {
      return { ok: false, code: 'identity_mismatch', message: 'signing root mismatch' };
    }
    const expectedChallenge =
      await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
        walletSessionUserId: request.walletSessionUserId,
        rpId: request.rpId,
        subjectId: request.subjectId,
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        signingRootId: request.signingRootId,
        signingRootVersion: request.signingRootVersion,
        keyScope: request.keyScope,
        relayerKeyId: request.relayerKeyId,
        requestId: request.requestId,
        sessionId: request.sessionId,
        walletSigningSessionId: request.walletSigningSessionId,
        ttlMs: request.ttlMs,
        remainingUses: request.remainingUses,
        participantIds: request.participantIds,
      });
    const verified = await ctx.service.verifyWebAuthnAuthenticationLite({
      nearAccountId: request.walletSessionUserId,
      rpId: request.rpId,
      expectedChallenge,
      webauthn_authentication: passkeyAuthorization.webauthn_authentication,
    });
    if (!verified.success || !verified.verified) {
      return {
        ok: false,
        code: verified.code || 'unauthorized',
        message: verified.message || 'Invalid passkey bootstrap authorization',
      };
    }
    return { ok: true, runtimePolicyScope };
  }
  const session = ctx.opts.session;
  if (!proof) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'First bootstrap requires client root proof',
    };
  }
  const expectedDigest32B64u =
    await computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u(request);
  if (proof.digest32B64u !== expectedDigest32B64u) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Invalid client root proof digest',
    };
  }
  if (!session) {
    return { ok: false, code: 'unauthorized', message: 'Session transport is not configured' };
  }
  const parsedSession = await session.parse(Object.fromEntries(ctx.request.headers.entries()));
  if (!parsedSession.ok) {
    return { ok: false, code: 'unauthorized', message: 'Missing bootstrap authorization session' };
  }
  let appSessionClaims = parseAppSessionClaims(parsedSession.claims);
  if (appSessionClaims) {
    const validated = await ctx.service.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!validated.ok) appSessionClaims = null;
  }
  const ecdsaSessionClaims = parseThresholdEcdsaSessionClaims(parsedSession.claims);
  const sessionClaims = appSessionClaims || ecdsaSessionClaims;
  if (!sessionClaims) {
    return { ok: false, code: 'unauthorized', message: 'Invalid bootstrap authorization session' };
  }
  const appSessionWalletId = resolveAppSessionWalletIdForWalletScope(
    appSessionClaims,
    request.walletSessionUserId,
  );
  const appSessionProviderUserId = resolveAppSessionProviderUserIdForWalletScope(
    appSessionClaims,
    request.walletSessionUserId,
  );
  if (appSessionClaims) {
    if (appSessionWalletId && appSessionWalletId !== request.walletSessionUserId) {
      return { ok: false, code: 'identity_mismatch', message: 'walletSessionUserId mismatch' };
    }
    if (!appSessionWalletId && !appSessionProviderUserId) {
      return { ok: false, code: 'identity_mismatch', message: 'walletSessionUserId mismatch' };
    }
  } else if (String(sessionClaims.walletId || '').trim() !== request.walletSessionUserId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletSessionUserId mismatch' };
  }
  const runtimePolicyScope = resolveEcdsaRuntimePolicyScopeFromClaims({
    appSessionClaims,
    ecdsaSessionClaims,
  });
  if (!proof) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'First bootstrap requires client root proof',
    };
  }
  const enrollment = await ctx.service.readActiveEmailOtpEnrollment({
    walletId: request.walletSessionUserId,
    orgId: String(runtimePolicyScope?.orgId || '').trim() || undefined,
    providerUserId: appSessionProviderUserId,
  });
  if (!enrollment.ok) {
    return { ok: false, code: 'unauthorized', message: 'Missing active Email OTP enrollment' };
  }
  const verifier = String(
    enrollment.enrollment.thresholdEcdsaClientVerifyingShareB64u || '',
  ).trim();
  if (
    !verifier ||
    (appSessionProviderUserId && enrollment.enrollment.providerUserId !== appSessionProviderUserId)
  ) {
    return { ok: false, code: 'unauthorized', message: 'Invalid Email OTP enrollment' };
  }
  try {
    const recovered33 = await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
      base64UrlDecode(proof.digest32B64u),
      base64UrlDecode(proof.signature65B64u),
      base64UrlDecode(verifier),
    );
    if (base64UrlEncode(recovered33) !== verifier) {
      return { ok: false, code: 'unauthorized', message: 'Invalid client root proof' };
    }
  } catch {
    return { ok: false, code: 'unauthorized', message: 'Invalid client root proof' };
  }
  return { ok: true, ...(runtimePolicyScope ? { runtimePolicyScope } : {}) };
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
    pathname !== '/threshold-ecdsa/hss/bootstrap' &&
    pathname !== '/threshold-ecdsa/hss/export/share' &&
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

  if (pathname === '/threshold-ecdsa/hss/bootstrap') {
    const parsed = parseEcdsaHssClientBootstrapRequest(body);
    if (!parsed) {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid ECDSA HSS bootstrap body',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const validated = await validateThresholdEcdsaSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    let runtimePolicyScope: EcdsaRuntimePolicyScope | undefined;
    if (validated.ok) {
      runtimePolicyScope = validated.claims.runtimePolicyScope;
      const identity = validateEcdsaHssSessionIdentity({
        claims: validated.claims,
        walletSessionUserId: parsed.walletSessionUserId,
        rpId: parsed.rpId,
        subjectId: parsed.subjectId,
        relayerKeyId: parsed.relayerKeyId,
      });
      if (!identity.ok) {
        return json(identity, { status: thresholdEcdsaStatusCode(identity) });
      }
    } else {
      const firstBootstrap = await authorizeEcdsaHssRoleLocalBootstrap({
        ctx,
        request: parsed,
      });
      if (!firstBootstrap.ok) {
        return json(firstBootstrap, { status: thresholdEcdsaStatusCode(firstBootstrap) });
      }
      runtimePolicyScope = firstBootstrap.runtimePolicyScope;
    }
    const result = await ctx.service.ecdsaHssRoleLocalBootstrap(parsed);
    if (!result.ok || parsed.sessionKind === 'cookie') {
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const signed = await signThresholdSessionAuthToken({
      session: ctx.opts.session,
      kind: 'threshold_ecdsa_session_v1',
      userId: parsed.walletSessionUserId,
      rpId: parsed.rpId,
      relayerKeyId: parsed.relayerKeyId,
      sessionInfo: {
        sessionKind: 'jwt',
        sessionId: result.value.sessionId,
        walletSigningSessionId: result.value.walletSigningSessionId,
        expiresAtMs: result.value.expiresAtMs,
        participantIds: result.value.participantIds,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        subjectId: parsed.subjectId,
        keyHandle: result.value.keyHandle,
      },
      fallbackParticipantIds: result.value.participantIds,
      requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
      invalidPayloadErrorMessage: 'invalid thresholdEcdsa HSS bootstrap session payload for jwt signing',
    });
    if (!signed.ok) {
      const failure = { ok: false, code: signed.code, message: signed.message };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const signedResult = {
      ...result,
      value: {
        ...result.value,
        jwt: signed.jwt,
      },
    };
    return json(signedResult, { status: thresholdEcdsaStatusCode(signedResult) });
  }

  if (pathname === '/threshold-ecdsa/hss/export/share') {
    const parsed = parseEcdsaHssExportShareRequest(body);
    if (!parsed) {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid ECDSA HSS export-share body',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const validated = await validateThresholdEcdsaSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    if (!validated.ok) {
      return json(validated, { status: thresholdEcdsaStatusCode(validated) });
    }
    const identity = validateEcdsaHssSessionIdentity({
      claims: validated.claims,
      walletSessionUserId: parsed.walletSessionUserId,
      rpId: parsed.rpId,
      subjectId: parsed.subjectId,
      relayerKeyId: parsed.relayerKeyId,
    });
    if (!identity.ok) {
      return json(identity, { status: thresholdEcdsaStatusCode(identity) });
    }
    const result = await ctx.service.ecdsaHssRoleLocalExportShare({
      request: parsed,
      keyHandle: validated.claims.keyHandle,
      claims: validated.claims,
    });
    return json(result, { status: thresholdEcdsaStatusCode(result) });
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
