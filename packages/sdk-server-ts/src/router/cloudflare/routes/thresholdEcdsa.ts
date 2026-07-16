import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  parseAppSessionClaims,
  parseEcdsaDerivationClientBootstrapRequest,
  parseEcdsaDerivationExportShareRequest,
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
} from '../../../core/ThresholdService/validation';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind } from '../../routerApi';
import {
  buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap,
  resolveThresholdRuntimePolicyScope,
  signRouterAbEcdsaDerivationWalletSessionJwt,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../commonRouterUtils';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  computeEcdsaDerivationRoleLocalFirstBootstrapRootProofDigest32B64u,
  computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaDerivationRoleLocalRelayerKeyId,
  computeEcdsaDerivationRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  ROUTER_AB_ECDSA_DERIVATION_BOOTSTRAP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH,
  ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { verifySecp256k1RecoverableSignatureAgainstPublicKey33 } from '../../../core/ThresholdService/evmCryptoWasm';
import { normalizeCorsOrigin } from '../../../core/SessionService';
import {
  handleRouterAbEcdsaDerivationNormalSigningRouteCore,
  ROUTER_AB_ECDSA_DERIVATION_PRIVATE_SIGNING_PATHS,
  type RouterAbEcdsaDerivationPrivateSigningPath,
} from '../../routerAbPrivateSigningWorker';
import type { VerifiedEcdsaWalletSessionAuth } from '../../verifiedWalletSessionAuth';
import {
  parseRouterAbEcdsaDerivationPoolFillInitRouteRequest,
  parseRouterAbEcdsaDerivationPoolFillStepRouteRequest,
} from '../../thresholdEcdsaRequestValidation';
import { handleRouterAbEcdsaDerivationRefreshRoute } from '../../routerAbEcdsaDerivationRefreshPort';

type EcdsaRuntimePolicyScope = RuntimePolicyScope;
type ThresholdEd25519SessionClaims = NonNullable<
  ReturnType<typeof parseRouterAbEd25519WalletSessionClaims>
>;

const NOT_IMPLEMENTED = {
  ok: false,
  code: 'not_implemented',
  message: 'threshold-ecdsa is not implemented',
} as const;

function publicEcdsaDerivationBootstrapValue<T extends { thresholdSessionId: string }>(value: T): T {
  return value;
}

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

function validateEcdsaDerivationSessionIdentity(input: {
  walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  relayerKeyId: string;
}): { ok: true } | { ok: false; code: string; message: string } {
  if (input.walletSessionAuth.expiresAtMs <= Date.now()) {
    return { ok: false, code: 'unauthorized', message: 'Threshold ECDSA session is expired' };
  }
  if (input.walletId !== input.walletSessionAuth.userId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletId mismatch' };
  }
  if (input.evmFamilySigningKeySlotId !== input.walletSessionAuth.evmFamilySigningKeySlotId) {
    return { ok: false, code: 'identity_mismatch', message: 'evmFamilySigningKeySlotId mismatch' };
  }

  if (input.relayerKeyId !== input.walletSessionAuth.relayerKeyId) {
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
  ecdsaSessionClaims: ReturnType<typeof parseRouterAbEcdsaDerivationWalletSessionClaims>;
  ed25519SessionClaims: ReturnType<typeof parseRouterAbEd25519WalletSessionClaims>;
}): EcdsaRuntimePolicyScope | undefined {
  return (
    normalizeEcdsaRuntimePolicyScope(input.appSessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ecdsaSessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ed25519SessionClaims?.runtimePolicyScope)
  );
}

function validateEd25519SessionBridgeForEcdsaDerivationBootstrap(input: {
  claims: ThresholdEd25519SessionClaims;
  walletId: string;
}): { ok: true } | { ok: false; code: string; message: string } {
  if (input.claims.thresholdExpiresAtMs <= Date.now()) {
    return { ok: false, code: 'unauthorized', message: 'Threshold Ed25519 session is expired' };
  }
  if (input.claims.walletId !== input.walletId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletId mismatch' };
  }
  return { ok: true };
}

async function authorizeEcdsaDerivationRoleLocalBootstrap(input: {
  ctx: CloudflareRouterApiContext;
  request: NonNullable<ReturnType<typeof parseEcdsaDerivationClientBootstrapRequest>>;
}): Promise<
  | { ok: true; runtimePolicyScope?: EcdsaRuntimePolicyScope }
  | { ok: false; code: string; message: string }
> {
  const { ctx, request } = input;
  const expectedRelayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
    walletId: request.walletId,
    evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
  });
  if (request.relayerKeyId !== expectedRelayerKeyId) {
    return { ok: false, code: 'relayer_key_mismatch', message: 'relayerKeyId mismatch' };
  }
  const expectedThresholdKeyId = await computeEcdsaDerivationRoleLocalThresholdKeyId({
    walletId: request.walletId,
    evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
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
    const expectedOrigin = normalizeCorsOrigin(ctx.request.headers.get('origin') || undefined);
    if (!expectedOrigin) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Origin header is required and must be a valid exact origin',
      };
    }
    const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
      explicitScopeRaw: passkeyAuthorization.runtimePolicyScope,
      projectEnvironmentIdRaw: passkeyAuthorization.projectEnvironmentId,
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
    const rpId = parseWebAuthnRpId(passkeyAuthorization.rpId);
    if (!rpId.ok) {
      return { ok: false, code: 'invalid_body', message: rpId.error.message };
    }
    const expectedChallenge = await computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32B64u({
      walletId: request.walletId,
      evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
      rpId: rpId.value,
      ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
      signingRootId: request.signingRootId,
      signingRootVersion: request.signingRootVersion,
      keyScope: request.keyScope,
      relayerKeyId: request.relayerKeyId,
      requestId: request.requestId,
      sessionId: request.sessionId,
      signingGrantId: request.signingGrantId,
      ttlMs: request.ttlMs,
      remainingUses: request.remainingUses,
      participantIds: request.participantIds,
    });
    const verified = await ctx.service.webAuthn.verifyWebAuthnAuthenticationLite({
      userId: request.walletId,
      rpId: rpId.value,
      expectedChallenge,
      expected_origin: expectedOrigin,
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
    await computeEcdsaDerivationRoleLocalFirstBootstrapRootProofDigest32B64u(request);
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
    const validated = await ctx.service.sessionVersions.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!validated.ok) appSessionClaims = null;
  }
  const ecdsaSessionClaims = parseRouterAbEcdsaDerivationWalletSessionClaims(parsedSession.claims);
  const ed25519SessionClaims = parseRouterAbEd25519WalletSessionClaims(parsedSession.claims);
  const sessionClaims = appSessionClaims || ecdsaSessionClaims || ed25519SessionClaims;
  if (!sessionClaims) {
    return { ok: false, code: 'unauthorized', message: 'Invalid bootstrap authorization session' };
  }
  const appSessionWalletId = resolveAppSessionWalletIdForWalletScope(
    appSessionClaims,
    request.walletId,
  );
  const appSessionProviderUserId = resolveAppSessionProviderUserIdForWalletScope(
    appSessionClaims,
    request.walletId,
  );
  if (appSessionClaims) {
    if (appSessionWalletId && appSessionWalletId !== request.walletId) {
      return { ok: false, code: 'identity_mismatch', message: 'walletId mismatch' };
    }
    if (!appSessionWalletId && !appSessionProviderUserId) {
      return { ok: false, code: 'identity_mismatch', message: 'walletId mismatch' };
    }
  } else if (ed25519SessionClaims) {
    const identity = validateEd25519SessionBridgeForEcdsaDerivationBootstrap({
      claims: ed25519SessionClaims,
      walletId: request.walletId,
    });
    if (!identity.ok) return identity;
  } else if (String(sessionClaims.walletId || '').trim() !== request.walletId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletId mismatch' };
  }
  const runtimePolicyScope = resolveEcdsaRuntimePolicyScopeFromClaims({
    appSessionClaims,
    ecdsaSessionClaims,
    ed25519SessionClaims,
  });
  if (!proof) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'First bootstrap requires client root proof',
    };
  }
  if (ed25519SessionClaims) {
    const verified =
      await ctx.service.thresholdRuntime.verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey({
        ...request,
        clientRootProof: proof,
      });
    if (!verified.ok) return verified;
    return { ok: true, ...(runtimePolicyScope ? { runtimePolicyScope } : {}) };
  }
  const enrollment = await ctx.service.emailOtp.readActiveEmailOtpEnrollment({
    walletId: request.walletId,
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
    proof.clientRootPublicKey33B64u !== verifier ||
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
    pathname !== ROUTER_AB_ECDSA_DERIVATION_BOOTSTRAP_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request);
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH) {
    return handleRouterAbEcdsaDerivationRefreshRoute({
      body: bodyUnknown,
      authorizationHeader: ctx.request.headers.get('authorization'),
      port: ctx.opts.routerAbEcdsaDerivationRefresh,
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

  if (pathname === ROUTER_AB_ECDSA_DERIVATION_BOOTSTRAP_PATH) {
    if (parseSessionKind(body) === 'cookie') {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B ECDSA derivation bootstrap requires sessionKind=jwt',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const parsed = parseEcdsaDerivationClientBootstrapRequest(body);
    if (!parsed) {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid ECDSA DERIVATION bootstrap body',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    let runtimePolicyScope: EcdsaRuntimePolicyScope | undefined;
    if (validated.ok) {
      runtimePolicyScope = validated.claims.runtimePolicyScope;
      const identity = validateEcdsaDerivationSessionIdentity({
        walletSessionAuth: validated.walletSessionAuth,
        walletId: parsed.walletId,
        evmFamilySigningKeySlotId: parsed.evmFamilySigningKeySlotId,
        relayerKeyId: parsed.relayerKeyId,
      });
      if (!identity.ok) {
        return json(identity, { status: thresholdEcdsaStatusCode(identity) });
      }
    } else {
      const firstBootstrap = await authorizeEcdsaDerivationRoleLocalBootstrap({
        ctx,
        request: parsed,
      });
      if (!firstBootstrap.ok) {
        return json(firstBootstrap, { status: thresholdEcdsaStatusCode(firstBootstrap) });
      }
      runtimePolicyScope = firstBootstrap.runtimePolicyScope;
    }
    const result = await ctx.service.thresholdRuntime.ecdsaDerivationRoleLocalBootstrap(parsed);
    if (!result.ok) {
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const normalSigningRuntime = ctx.service.thresholdRuntime.getRouterAbNormalSigningRuntime();
    if (!normalSigningRuntime) {
      const failure = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B normal signing is not configured on this server',
      };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const signingWorkerId = normalSigningRuntime.getSigningWorkerId();
    const routerAbEcdsaDerivationNormalSigning = buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap({
      bootstrap: result.value,
      routerAbPublicKeyset: ctx.opts.routerAbPublicKeyset,
      signingWorkerId,
    });
    if (!routerAbEcdsaDerivationNormalSigning.ok) {
      return json(routerAbEcdsaDerivationNormalSigning, {
        status: thresholdEcdsaStatusCode(routerAbEcdsaDerivationNormalSigning),
      });
    }
    const signed = await signRouterAbEcdsaDerivationWalletSessionJwt({
      session: ctx.opts.session,
      userId: parsed.walletId,
      evmFamilySigningKeySlotId: parsed.evmFamilySigningKeySlotId,
      relayerKeyId: parsed.relayerKeyId,
      sessionInfo: {
        sessionKind: 'jwt',
        thresholdSessionId: result.value.thresholdSessionId,
        signingGrantId: result.value.signingGrantId,
        expiresAtMs: result.value.expiresAtMs,
        participantIds: result.value.participantIds,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        keyHandle: result.value.keyHandle,
        stableKeyContext: {
          walletId: parsed.walletId,
          evmFamilySigningKeySlotId: parsed.evmFamilySigningKeySlotId,
          keyScope: 'evm-family',
          ecdsaThresholdKeyId: parsed.ecdsaThresholdKeyId,
          signingRootId: parsed.signingRootId,
          signingRootVersion: parsed.signingRootVersion,
          applicationBindingDigestB64u: result.value.applicationBindingDigestB64u,
          contextBinding32B64u: parsed.contextBinding32B64u,
        },
        publicIdentity: result.value.publicIdentity,
        activationEpoch: result.value.thresholdSessionId,
        signingWorkerId,
        routerAbEcdsaDerivationNormalSigning: routerAbEcdsaDerivationNormalSigning.state,
      },
      fallbackParticipantIds: result.value.participantIds,
      requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
      invalidPayloadErrorMessage:
        'invalid thresholdECDSA derivation bootstrap session payload for jwt signing',
    });
    if (!signed.ok) {
      const failure = { ok: false, code: signed.code, message: signed.message };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const signedResult = {
      ...result,
      value: {
        ...publicEcdsaDerivationBootstrapValue(result.value),
        jwt: signed.jwt,
      },
    };
    return json(signedResult, { status: thresholdEcdsaStatusCode(signedResult) });
  }

  if (pathname === ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH) {
    if (parseSessionKind(body) === 'cookie') {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B ECDSA derivation export-share requires sessionKind=jwt',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const parsed = parseEcdsaDerivationExportShareRequest(body);
    if (!parsed) {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid ECDSA DERIVATION export-share body',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    if (!validated.ok) {
      return json(validated, { status: thresholdEcdsaStatusCode(validated) });
    }
    const identity = validateEcdsaDerivationSessionIdentity({
      walletSessionAuth: validated.walletSessionAuth,
      walletId: parsed.walletId,
      evmFamilySigningKeySlotId: parsed.evmFamilySigningKeySlotId,
      relayerKeyId: parsed.relayerKeyId,
    });
    if (!identity.ok) {
      return json(identity, { status: thresholdEcdsaStatusCode(identity) });
    }
    const result = await ctx.service.thresholdRuntime.ecdsaDerivationRoleLocalExportShare({
      request: parsed,
      keyHandle: validated.walletSessionAuth.keyHandle,
      claims: validated.claims,
    });
    return json(result, { status: thresholdEcdsaStatusCode(result) });
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
