import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  parseAppSessionClaims,
  parseEcdsaHssClientBootstrapRequest,
  parseEcdsaHssExportShareRequest,
  parseRouterAbEcdsaHssWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
} from '../../../core/ThresholdService/validation';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  buildRouterAbEcdsaHssNormalSigningStateForBootstrap,
  resolveThresholdRuntimePolicyScope,
  signRouterAbEcdsaHssWalletSessionJwt,
  validateRouterAbEcdsaHssWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../commonRouterUtils';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u,
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH,
  ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH,
  ROUTER_AB_ECDSA_HSS_HEALTH_PATH,
  ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PATH,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
} from '@shared/utils/routerAbEcdsaHss';
import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { verifySecp256k1RecoverableSignatureAgainstPublicKey33 } from '../../../core/ThresholdService/ethSignerWasm';
import { normalizeCorsOrigin } from '../../../core/SessionService';
import {
  handleRouterAbEcdsaHssNormalSigningRouteCore,
  ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS,
  type RouterAbEcdsaHssPrivateSigningPath,
} from '../../routerAbPrivateSigningWorker';
import type { VerifiedEcdsaWalletSessionAuth } from '../../verifiedWalletSessionAuth';
import {
  parseRouterAbEcdsaHssKeyIdentitiesRequest,
  parseRouterAbEcdsaHssPoolFillInitRouteRequest,
  parseRouterAbEcdsaHssPoolFillStepRouteRequest,
} from '../../thresholdEcdsaRequestValidation';

type EcdsaRuntimePolicyScope = RuntimePolicyScope;
type ThresholdEd25519SessionClaims = NonNullable<
  ReturnType<typeof parseRouterAbEd25519WalletSessionClaims>
>;

const NOT_IMPLEMENTED = {
  ok: false,
  code: 'not_implemented',
  message: 'threshold-ecdsa is not implemented',
} as const;

function publicEcdsaHssBootstrapValue<T extends { thresholdSessionId: string }>(value: T): T {
  return value;
}

async function handleRouterAbEcdsaHssNormalSigningRoute(input: {
  ctx: CloudflareRelayContext;
  body: Record<string, unknown>;
  privatePath: RouterAbEcdsaHssPrivateSigningPath;
  phase: 'prepare' | 'finalize';
}): Promise<Response> {
  const result = await handleRouterAbEcdsaHssNormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    getThreshold: () => input.ctx.service.getThresholdSigningService(),
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    privatePath: input.privatePath,
    phase: input.phase,
  });
  return json(result.body, { status: result.status });
}

function validateEcdsaHssSessionIdentity(input: {
  walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
  walletId: string;
  walletKeyId: string;
  relayerKeyId: string;
}): { ok: true } | { ok: false; code: string; message: string } {
  if (input.walletSessionAuth.expiresAtMs <= Date.now()) {
    return { ok: false, code: 'unauthorized', message: 'Threshold ECDSA session is expired' };
  }
  if (input.walletId !== input.walletSessionAuth.userId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletId mismatch' };
  }
  if (input.walletKeyId !== input.walletSessionAuth.walletKeyId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletKeyId mismatch' };
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
  ecdsaSessionClaims: ReturnType<typeof parseRouterAbEcdsaHssWalletSessionClaims>;
  ed25519SessionClaims: ReturnType<typeof parseRouterAbEd25519WalletSessionClaims>;
}): EcdsaRuntimePolicyScope | undefined {
  return (
    normalizeEcdsaRuntimePolicyScope(input.appSessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ecdsaSessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ed25519SessionClaims?.runtimePolicyScope)
  );
}

function validateEd25519SessionBridgeForEcdsaHssBootstrap(input: {
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

async function authorizeEcdsaHssRoleLocalBootstrap(input: {
  ctx: CloudflareRelayContext;
  request: NonNullable<ReturnType<typeof parseEcdsaHssClientBootstrapRequest>>;
}): Promise<
  | { ok: true; runtimePolicyScope?: EcdsaRuntimePolicyScope }
  | { ok: false; code: string; message: string }
> {
  const { ctx, request } = input;
  const expectedRelayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletId: request.walletId,
    walletKeyId: request.walletKeyId,
  });
  if (request.relayerKeyId !== expectedRelayerKeyId) {
    return { ok: false, code: 'relayer_key_mismatch', message: 'relayerKeyId mismatch' };
  }
  const expectedThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletId: request.walletId,
    walletKeyId: request.walletKeyId,
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
    const rpId = parseWebAuthnRpId(passkeyAuthorization.rpId);
    if (!rpId.ok) {
      return { ok: false, code: 'invalid_body', message: rpId.error.message };
    }
    const expectedChallenge = await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
      walletId: request.walletId,
      walletKeyId: request.walletKeyId,
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
    const verified = await ctx.service.verifyWebAuthnAuthenticationLite({
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
  const ecdsaSessionClaims = parseRouterAbEcdsaHssWalletSessionClaims(parsedSession.claims);
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
    const identity = validateEd25519SessionBridgeForEcdsaHssBootstrap({
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
    const verified = await ctx.service.verifyEcdsaHssRoleLocalClientRootProofForExistingKey({
      ...request,
      clientRootProof: proof,
    });
    if (!verified.ok) return verified;
    return { ok: true, ...(runtimePolicyScope ? { runtimePolicyScope } : {}) };
  }
  const enrollment = await ctx.service.readActiveEmailOtpEnrollment({
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

export async function handleThresholdEcdsa(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ECDSA_HSS_HEALTH_PATH) {
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
    pathname !== ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH &&
    pathname !== ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH &&
    pathname !== ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH &&
    pathname !== ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PATH &&
    pathname !== ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH &&
    pathname !== ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request);
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};
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

  if (pathname === ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH) {
    return handleRouterAbEcdsaHssNormalSigningRoute({
      ctx,
      body,
      privatePath: ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.prepare,
      phase: 'prepare',
    });
  }

  if (pathname === ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PATH) {
    return handleRouterAbEcdsaHssNormalSigningRoute({
      ctx,
      body,
      privatePath: ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.finalize,
      phase: 'finalize',
    });
  }

  if (pathname === ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH) {
    const parsed = parseRouterAbEcdsaHssKeyIdentitiesRequest(body);
    if (!parsed.ok) {
      return json(parsed.body, { status: thresholdEcdsaStatusCode(parsed.body) });
    }
    if (parsed.request.sessionKind === 'cookie') {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B ECDSA-HSS key identities requires sessionKind=jwt',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    if (!validated.ok) {
      return json(validated, { status: thresholdEcdsaStatusCode(validated) });
    }
    if (validated.walletSessionAuth.expiresAtMs <= Date.now()) {
      const result = {
        ok: false,
        code: 'unauthorized' as const,
        message: 'Threshold Ed25519 session is expired',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const keyInventory = await ctx.service.listThresholdEcdsaKeyIdentityTargetsForUser({
      userId: validated.walletSessionAuth.userId,
      rpId: validated.walletSessionAuth.rpId,
      keyTargets: parsed.request.keyTargets,
    });
    ctx.logger.info('[threshold-ecdsa][key-identities][diagnostic]', {
      walletId: validated.walletSessionAuth.userId,
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

  if (pathname === ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH) {
    if (parseSessionKind(body) === 'cookie') {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B ECDSA-HSS bootstrap requires sessionKind=jwt',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const parsed = parseEcdsaHssClientBootstrapRequest(body);
    if (!parsed) {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid ECDSA HSS bootstrap body',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const validated = await validateRouterAbEcdsaHssWalletSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    let runtimePolicyScope: EcdsaRuntimePolicyScope | undefined;
    if (validated.ok) {
      runtimePolicyScope = validated.claims.runtimePolicyScope;
      const identity = validateEcdsaHssSessionIdentity({
        walletSessionAuth: validated.walletSessionAuth,
        walletId: parsed.walletId,
        walletKeyId: parsed.walletKeyId,
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
    if (!result.ok) {
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const threshold = ctx.service.getThresholdSigningService();
    if (!threshold) {
      const failure = {
        ok: false,
        code: 'not_configured',
        message: 'Threshold signing is not configured on this server',
      };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const routerAbEcdsaHssNormalSigning = buildRouterAbEcdsaHssNormalSigningStateForBootstrap({
      bootstrap: result.value,
      routerAbPublicKeyset: ctx.opts.routerAbPublicKeyset,
      signingWorkerId: threshold.getRouterAbNormalSigningWorkerId(),
    });
    if (!routerAbEcdsaHssNormalSigning.ok) {
      return json(routerAbEcdsaHssNormalSigning, {
        status: thresholdEcdsaStatusCode(routerAbEcdsaHssNormalSigning),
      });
    }
    const signed = await signRouterAbEcdsaHssWalletSessionJwt({
      session: ctx.opts.session,
      userId: parsed.walletId,
      walletKeyId: parsed.walletKeyId,
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
            walletKeyId: parsed.walletKeyId,
            keyScope: 'evm-family',
            ecdsaThresholdKeyId: parsed.ecdsaThresholdKeyId,
            signingRootId: parsed.signingRootId,
            signingRootVersion: parsed.signingRootVersion,
            applicationBindingDigestB64u: result.value.applicationBindingDigestB64u,
            contextBinding32B64u: parsed.contextBinding32B64u,
          },
        publicIdentity: result.value.publicIdentity,
        activationEpoch: result.value.thresholdSessionId,
        signingWorkerId: threshold.getRouterAbNormalSigningWorkerId(),
        routerAbEcdsaHssNormalSigning: routerAbEcdsaHssNormalSigning.state,
      },
      fallbackParticipantIds: result.value.participantIds,
      requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
      invalidPayloadErrorMessage:
        'invalid thresholdEcdsa HSS bootstrap session payload for jwt signing',
    });
    if (!signed.ok) {
      const failure = { ok: false, code: signed.code, message: signed.message };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const signedResult = {
      ...result,
      value: {
        ...publicEcdsaHssBootstrapValue(result.value),
        jwt: signed.jwt,
      },
    };
    return json(signedResult, { status: thresholdEcdsaStatusCode(signedResult) });
  }

  if (pathname === ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH) {
    if (parseSessionKind(body) === 'cookie') {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B ECDSA-HSS export-share requires sessionKind=jwt',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const parsed = parseEcdsaHssExportShareRequest(body);
    if (!parsed) {
      const result = {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid ECDSA HSS export-share body',
      };
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    }
    const validated = await validateRouterAbEcdsaHssWalletSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    if (!validated.ok) {
      return json(validated, { status: thresholdEcdsaStatusCode(validated) });
    }
    const identity = validateEcdsaHssSessionIdentity({
      walletSessionAuth: validated.walletSessionAuth,
      walletId: parsed.walletId,
      walletKeyId: parsed.walletKeyId,
      relayerKeyId: parsed.relayerKeyId,
    });
    if (!identity.ok) {
      return json(identity, { status: thresholdEcdsaStatusCode(identity) });
    }
    const result = await ctx.service.ecdsaHssRoleLocalExportShare({
      request: parsed,
      keyHandle: validated.walletSessionAuth.keyHandle,
      claims: validated.claims,
    });
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }

  if (pathname === ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH) {
    const parsedBody = parseRouterAbEcdsaHssPoolFillInitRouteRequest(body);
    const requestTag = parsedBody.ok ? parsedBody.request.requestTag : undefined;
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    try {
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEcdsaStatusCode(parsedBody.body) });
      }
      const validated = await validateRouterAbEcdsaHssWalletSessionInputs({
        body: parsedBody.request,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
      const result = await scheme.poolFill.init({
        claims: validated.claims,
        request: parsedBody.request,
      });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  if (pathname === ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH) {
    const parsedBody = parseRouterAbEcdsaHssPoolFillStepRouteRequest(body);
    const requestTag = parsedBody.ok ? parsedBody.request.requestTag : undefined;
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    try {
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEcdsaStatusCode(parsedBody.body) });
      }
      const validated = await validateRouterAbEcdsaHssWalletSessionInputs({
        body: parsedBody.request,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
      const result = await scheme.poolFill.step({
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
