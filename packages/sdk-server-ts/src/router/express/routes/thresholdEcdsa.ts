import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import type {
  RouterAbEcdsaHssPoolFillInitRequest,
  RouterAbEcdsaHssPoolFillStepRequest,
} from '../../../core/types';
import {
  parseAppSessionClaims,
  parseEcdsaHssClientBootstrapRequest,
  parseEcdsaHssExportShareRequest,
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
  signWalletSessionJwt,
  validateThresholdEcdsaSessionInputs,
  validateThresholdEd25519SessionTokenInputs,
} from '../../commonRouterUtils';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u,
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH_V1,
  ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH_V1,
  ROUTER_AB_ECDSA_HSS_HEALTH_PATH_V1,
  ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1,
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH_V1,
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH_V1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { verifySecp256k1RecoverableSignatureAgainstPublicKey33 } from '../../../core/ThresholdService/ethSignerWasm';
import { normalizeCorsOrigin } from '../../../core/SessionService';

type EcdsaRuntimePolicyScope = RuntimePolicyScope;
type ThresholdEcdsaSessionClaims = NonNullable<ReturnType<typeof parseThresholdEcdsaSessionClaims>>;
type ThresholdEd25519SessionClaims = NonNullable<
  ReturnType<typeof parseThresholdEd25519SessionClaims>
>;

const NOT_IMPLEMENTED = {
  ok: false,
  code: 'not_implemented',
  message: 'threshold-ecdsa is not implemented',
} as const;

function validateEcdsaHssSessionIdentity(input: {
  claims: ThresholdEcdsaSessionClaims;
  walletId: string;
  rpId: string;
  relayerKeyId: string;
}): { ok: true } | { ok: false; code: string; message: string } {
  if (input.claims.thresholdExpiresAtMs <= Date.now()) {
    return { ok: false, code: 'unauthorized', message: 'Threshold ECDSA session is expired' };
  }
  if (input.walletId !== input.claims.walletId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletId mismatch' };
  }
  if (input.rpId !== input.claims.rpId) {
    return { ok: false, code: 'identity_mismatch', message: 'rpId mismatch' };
  }

  if (input.relayerKeyId !== input.claims.relayerKeyId) {
    return { ok: false, code: 'relayer_key_mismatch', message: 'relayerKeyId mismatch' };
  }
  return { ok: true };
}

type PresignTrafficClass = 'foreground' | 'background';

type PresignPriorityTicket = {
  waitedMs: number;
  queuedDepth: number;
  release: () => void;
};

const ROUTER_AB_ECDSA_HSS_POOL_FILL_FORWARD_HOP_HEADER =
  'x-router-ab-ecdsa-hss-pool-fill-forward-hop';
const ROUTER_AB_ECDSA_HSS_POOL_FILL_FORWARDED_BY_HEADER =
  'x-router-ab-ecdsa-hss-pool-fill-forwarded-by';

class PresignPriorityGate {
  private foregroundInFlight = 0;
  private backgroundInFlight = 0;
  private readonly backgroundQueue: Array<{
    enqueuedAtMs: number;
    queuedDepth: number;
    resolve: (ticket: PresignPriorityTicket) => void;
  }> = [];

  async acquire(trafficClass: PresignTrafficClass): Promise<PresignPriorityTicket> {
    if (trafficClass === 'foreground') {
      this.foregroundInFlight += 1;
      return this.createTicket('foreground', 0, 0);
    }
    if (this.canRunBackgroundNow()) {
      this.backgroundInFlight += 1;
      return this.createTicket('background', 0, 0);
    }
    const enqueuedAtMs = Date.now();
    const queuedDepth = this.backgroundQueue.length + 1;
    return await new Promise((resolve) => {
      this.backgroundQueue.push({ enqueuedAtMs, queuedDepth, resolve });
    });
  }

  private createTicket(
    trafficClass: PresignTrafficClass,
    waitedMs: number,
    queuedDepth: number,
  ): PresignPriorityTicket {
    let released = false;
    return {
      waitedMs,
      queuedDepth,
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
    const waitedMs = Math.max(0, Date.now() - next.enqueuedAtMs);
    next.resolve(this.createTicket('background', waitedMs, next.queuedDepth));
  }
}

function errMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e)
    return String((e as { message?: unknown }).message || 'Internal error');
  return String(e || 'Internal error');
}

function parsePresignRequestTag(body: unknown): string | undefined {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined;
  const tag = String((body as { requestTag?: unknown }).requestTag || '').trim();
  return tag || undefined;
}

function resolvePresignLogLabel(requestTag: string | undefined): string | undefined {
  if (requestTag === 'background_presign_pool_refill') {
    return 'background presign pool refill';
  }
  return undefined;
}

function resolvePresignTrafficClass(requestTag: string | undefined): PresignTrafficClass {
  return requestTag === 'background_presign_pool_refill' ? 'background' : 'foreground';
}

function toOptionalHeaderString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const trimmed = String(entry || '').trim();
      if (trimmed) return trimmed;
    }
    return undefined;
  }
  const trimmed = String(value || '').trim();
  return trimmed || undefined;
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
  ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims>;
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
  rpId: string;
}): { ok: true } | { ok: false; code: string; message: string } {
  if (input.claims.thresholdExpiresAtMs <= Date.now()) {
    return { ok: false, code: 'unauthorized', message: 'Threshold Ed25519 session is expired' };
  }
  if (input.claims.walletId !== input.walletId) {
    return { ok: false, code: 'identity_mismatch', message: 'walletId mismatch' };
  }
  if (input.claims.rpId !== input.rpId) {
    return { ok: false, code: 'identity_mismatch', message: 'rpId mismatch' };
  }
  return { ok: true };
}

async function authorizeEcdsaHssRoleLocalBootstrap(input: {
  ctx: ExpressRelayContext;
  headers: Request['headers'];
  request: NonNullable<ReturnType<typeof parseEcdsaHssClientBootstrapRequest>>;
}): Promise<
  | { ok: true; runtimePolicyScope?: EcdsaRuntimePolicyScope }
  | { ok: false; code: string; message: string }
> {
  const { ctx, headers, request } = input;
  const expectedRelayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletId: request.walletId,
    rpId: request.rpId,
  });
  if (request.relayerKeyId !== expectedRelayerKeyId) {
    return { ok: false, code: 'relayer_key_mismatch', message: 'relayerKeyId mismatch' };
  }
  const expectedThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletId: request.walletId,
    rpId: request.rpId,
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
    const expectedOrigin = normalizeCorsOrigin(
      Array.isArray(headers?.origin) ? headers.origin[0] : headers?.origin,
    );
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
      headers: headers || {},
      origin: Array.isArray(headers?.origin) ? headers.origin[0] : headers?.origin,
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
    const expectedChallenge = await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
      walletId: request.walletId,
      rpId: request.rpId,
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
      nearAccountId: request.walletId,
      rpId: request.rpId,
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
  const parsedSession = await session.parse(headers || {});
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
  const ed25519SessionClaims = parseThresholdEd25519SessionClaims(parsedSession.claims);
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
      rpId: request.rpId,
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

function parseForwardHop(value: string | undefined): number {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n) || n < 0) return 0;
  return n;
}

const presignPriorityGate = new PresignPriorityGate();

async function handle<T extends { ok: boolean; code?: string; message?: string }>(
  ctx: ExpressRelayContext,
  req: Request,
  res: Response,
  route: string,
  requestMeta: Record<string, unknown>,
  fn: () => Promise<T>,
): Promise<void> {
  const startedAtMs = Date.now();
  try {
    ctx.logger.info('[threshold-ecdsa] request', {
      route,
      method: req.method,
      ...(requestMeta || {}),
    });
    const result = await fn();
    const status = thresholdEcdsaStatusCode(result);
    ctx.logger.info('[threshold-ecdsa] response', {
      route,
      status,
      ok: result.ok,
      durationMs: Math.max(0, Date.now() - startedAtMs),
      ...(result.code ? { code: result.code } : {}),
    });
    res.status(status).json(result);
  } catch (e: unknown) {
    ctx.logger.error('[threshold-ecdsa] error', {
      route,
      message: errMessage(e),
      durationMs: Math.max(0, Date.now() - startedAtMs),
      ...(requestMeta || {}),
    });
    res.status(500).json({ ok: false, code: 'internal', message: errMessage(e) });
  }
}

export function registerThresholdEcdsaRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  ctx.logger.info('[threshold-ecdsa] routes', { enabled: Boolean(ctx.opts.threshold) });

  router.get(ROUTER_AB_ECDSA_HSS_HEALTH_PATH_V1, async (req: Request, res: Response) => {
    await handle(ctx, req, res, ROUTER_AB_ECDSA_HSS_HEALTH_PATH_V1, {}, async () => {
      const resolved = resolveThresholdScheme(
        ctx.opts.threshold,
        THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        {
          notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
        },
      );
      if (!resolved.ok)
        return { ok: false, configured: false, code: resolved.code, message: resolved.message };
      const scheme = resolved.scheme;
      const health = await scheme.healthz();
      if (health.ok) return { ok: true, configured: true };
      return { ...(health.code ? health : NOT_IMPLEMENTED), configured: true };
    });
  });

  router.post(ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1, async (req: Request, res: Response) => {
    await handle(ctx, req, res, ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1, {}, async () => {
      const validated = await validateThresholdEd25519SessionTokenInputs({
        body: req.body || {},
        headers: req.headers || {},
        session: ctx.opts.session,
      });
      if (!validated.ok) return validated;
      if (validated.claims.thresholdExpiresAtMs <= Date.now()) {
        return {
          ok: false,
          code: 'unauthorized' as const,
          message: 'Threshold Ed25519 session is expired',
        };
      }
      const bodyRecord =
        req.body && typeof req.body === 'object' && !Array.isArray(req.body)
          ? (req.body as Record<string, unknown>)
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
      return {
        ok: true,
        ecdsaKeyIdentityTargets: keyInventory.records,
        diagnostics: keyInventory.diagnostics,
      };
    });
  });

  router.post(ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH_V1, async (req: Request, res: Response) => {
    const body = req.body || {};
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH_V1,
      {
        walletId:
          typeof (body as { walletId?: unknown }).walletId === 'string'
            ? (body as { walletId: string }).walletId
            : undefined,
        rpId:
          typeof (body as { rpId?: unknown }).rpId === 'string'
            ? (body as { rpId: string }).rpId
            : undefined,
        ecdsaThresholdKeyId:
          typeof (body as { ecdsaThresholdKeyId?: unknown }).ecdsaThresholdKeyId === 'string'
            ? (body as { ecdsaThresholdKeyId: string }).ecdsaThresholdKeyId
            : undefined,
        relayerKeyId:
          typeof (body as { relayerKeyId?: unknown }).relayerKeyId === 'string'
            ? (body as { relayerKeyId: string }).relayerKeyId
            : undefined,
        requestId:
          typeof (body as { requestId?: unknown }).requestId === 'string'
            ? (body as { requestId: string }).requestId
            : undefined,
      },
      async () => {
        const parsed = parseEcdsaHssClientBootstrapRequest(body);
        if (!parsed) {
          return { ok: false, code: 'invalid_body', message: 'Invalid ECDSA HSS bootstrap body' };
        }
        const validated = await validateThresholdEcdsaSessionInputs({
          body,
          headers: req.headers || {},
          session: ctx.opts.session,
        });
        let runtimePolicyScope: EcdsaRuntimePolicyScope | undefined;
        if (validated.ok) {
          runtimePolicyScope = validated.claims.runtimePolicyScope;
          const identity = validateEcdsaHssSessionIdentity({
            claims: validated.claims,
            walletId: parsed.walletId,
            rpId: parsed.rpId,
            relayerKeyId: parsed.relayerKeyId,
          });
          if (!identity.ok) return identity;
        } else {
          const firstBootstrap = await authorizeEcdsaHssRoleLocalBootstrap({
            ctx,
            headers: req.headers || {},
            request: parsed,
          });
          if (!firstBootstrap.ok) return firstBootstrap;
          runtimePolicyScope = firstBootstrap.runtimePolicyScope;
        }
        const bootstrap = await ctx.service.ecdsaHssRoleLocalBootstrap(parsed);
        if (!bootstrap.ok || parsed.sessionKind === 'cookie') return bootstrap;
        const signed = await signWalletSessionJwt({
          session: ctx.opts.session,
          kind: 'threshold_ecdsa_session_v2',
          userId: parsed.walletId,
          rpId: parsed.rpId,
          relayerKeyId: parsed.relayerKeyId,
          sessionInfo: {
            sessionKind: 'jwt',
            sessionId: bootstrap.value.sessionId,
            walletSigningSessionId: bootstrap.value.walletSigningSessionId,
            expiresAtMs: bootstrap.value.expiresAtMs,
            participantIds: bootstrap.value.participantIds,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            keyHandle: bootstrap.value.keyHandle,
          },
          fallbackParticipantIds: bootstrap.value.participantIds,
          requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
          invalidPayloadErrorMessage:
            'invalid thresholdEcdsa HSS bootstrap session payload for jwt signing',
        });
        if (!signed.ok) {
          return { ok: false, code: signed.code, message: signed.message };
        }
        return {
          ...bootstrap,
          value: {
            ...bootstrap.value,
            jwt: signed.jwt,
          },
        };
      },
    );
  });

  router.post(ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH_V1, async (req: Request, res: Response) => {
    const body = req.body || {};
    await handle(
      ctx,
      req,
      res,
      ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH_V1,
      {
        walletId:
          typeof (body as { walletId?: unknown }).walletId === 'string'
            ? (body as { walletId: string }).walletId
            : undefined,
        rpId:
          typeof (body as { rpId?: unknown }).rpId === 'string'
            ? (body as { rpId: string }).rpId
            : undefined,
        ecdsaThresholdKeyId:
          typeof (body as { ecdsaThresholdKeyId?: unknown }).ecdsaThresholdKeyId === 'string'
            ? (body as { ecdsaThresholdKeyId: string }).ecdsaThresholdKeyId
            : undefined,
        relayerKeyId:
          typeof (body as { relayerKeyId?: unknown }).relayerKeyId === 'string'
            ? (body as { relayerKeyId: string }).relayerKeyId
            : undefined,
        clientDeviceId:
          typeof (body as { clientDeviceId?: unknown }).clientDeviceId === 'string'
            ? (body as { clientDeviceId: string }).clientDeviceId
            : undefined,
      },
      async () => {
        const parsed = parseEcdsaHssExportShareRequest(body);
        if (!parsed) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Invalid ECDSA HSS export-share body',
          };
        }
        const validated = await validateThresholdEcdsaSessionInputs({
          body,
          headers: req.headers || {},
          session: ctx.opts.session,
        });
        if (!validated.ok) return validated;
        const identity = validateEcdsaHssSessionIdentity({
          claims: validated.claims,
          walletId: parsed.walletId,
          rpId: parsed.rpId,
          relayerKeyId: parsed.relayerKeyId,
        });
        if (!identity.ok) return identity;
        return await ctx.service.ecdsaHssRoleLocalExportShare({
          request: parsed,
          keyHandle: validated.claims.keyHandle,
          claims: validated.claims,
        });
      },
    );
  });

  async function handleRouterAbEcdsaHssPoolFillInitRoute(
    routePath: string,
    req: Request,
    res: Response,
  ): Promise<void> {
    const body = (req.body || {}) as RouterAbEcdsaHssPoolFillInitRequest;
    const requestTag = parsePresignRequestTag(body);
    const label = resolvePresignLogLabel(requestTag);
    const trafficClass = resolvePresignTrafficClass(requestTag);
    const gateTicket = await presignPriorityGate.acquire(trafficClass);
    try {
      await handle(
        ctx,
        req,
        res,
        routePath,
        {
          keyHandle: typeof body.keyHandle === 'string' ? body.keyHandle : undefined,
          ecdsaThresholdKeyId:
            typeof body.ecdsaThresholdKeyId === 'string' ? body.ecdsaThresholdKeyId : undefined,
          count: typeof (body as any).count === 'number' ? (body as any).count : undefined,
          ...(requestTag ? { requestTag } : {}),
          ...(label ? { label } : {}),
          presignTrafficClass: trafficClass,
          gateWaitMs: gateTicket.waitedMs,
          gateQueuedDepth: gateTicket.queuedDepth,
        },
        async () => {
          const resolved = resolveThresholdScheme(
            ctx.opts.threshold,
            THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
            {
              notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
            },
          );
          if (!resolved.ok) return resolved;
          const scheme = resolved.scheme;

          const validated = await validateThresholdEcdsaSessionInputs({
            body: req.body,
            headers: req.headers || {},
            session: ctx.opts.session,
          });
          if (!validated.ok) return validated;

          return scheme.poolFill.init({ claims: validated.claims, request: body });
        },
      );
    } finally {
      gateTicket.release();
    }
  }

  async function handleRouterAbEcdsaHssPoolFillStepRoute(
    routePath: string,
    req: Request,
    res: Response,
  ): Promise<void> {
    const body = (req.body || {}) as RouterAbEcdsaHssPoolFillStepRequest;
    const requestTag = parsePresignRequestTag(body);
    const label = resolvePresignLogLabel(requestTag);
    const trafficClass = resolvePresignTrafficClass(requestTag);
    const gateTicket = await presignPriorityGate.acquire(trafficClass);
    try {
      await handle(
        ctx,
        req,
        res,
        routePath,
        {
          presignSessionId:
            typeof body.presignSessionId === 'string' ? body.presignSessionId : undefined,
          stage: typeof (body as any).stage === 'string' ? (body as any).stage : undefined,
          outgoingMessagesB64u_len: Array.isArray((body as any).outgoingMessagesB64u)
            ? (body as any).outgoingMessagesB64u.length
            : undefined,
          ...(requestTag ? { requestTag } : {}),
          ...(label ? { label } : {}),
          presignTrafficClass: trafficClass,
          gateWaitMs: gateTicket.waitedMs,
          gateQueuedDepth: gateTicket.queuedDepth,
        },
        async () => {
          const resolved = resolveThresholdScheme(
            ctx.opts.threshold,
            THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
            {
              notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
            },
          );
          if (!resolved.ok) return resolved;
          const scheme = resolved.scheme;

          const validated = await validateThresholdEcdsaSessionInputs({
            body: req.body,
            headers: req.headers || {},
            session: ctx.opts.session,
          });
          if (!validated.ok) return validated;

          const headers = req.headers || {};
          const authorizationHeader = toOptionalHeaderString(headers.authorization);
          const cookieHeader = toOptionalHeaderString(headers.cookie);
          const forwardedHop = parseForwardHop(
            toOptionalHeaderString(headers[ROUTER_AB_ECDSA_HSS_POOL_FILL_FORWARD_HOP_HEADER]),
          );
          const forwardedByInstanceId = toOptionalHeaderString(
            headers[ROUTER_AB_ECDSA_HSS_POOL_FILL_FORWARDED_BY_HEADER],
          );
          return scheme.poolFill.step({
            claims: validated.claims,
            request: body,
            transport: {
              ...(authorizationHeader ? { authorizationHeader } : {}),
              ...(cookieHeader ? { cookieHeader } : {}),
              ...(forwardedHop > 0 ? { forwardedHop } : {}),
              ...(forwardedByInstanceId ? { forwardedByInstanceId } : {}),
            },
          });
        },
      );
    } finally {
      gateTicket.release();
    }
  }

  router.post(
    ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH_V1,
    async (req: Request, res: Response) => {
      await handleRouterAbEcdsaHssPoolFillInitRoute(
        ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH_V1,
        req,
        res,
      );
    },
  );

  router.post(
    ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH_V1,
    async (req: Request, res: Response) => {
      await handleRouterAbEcdsaHssPoolFillStepRoute(
        ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH_V1,
        req,
        res,
      );
    },
  );
}
