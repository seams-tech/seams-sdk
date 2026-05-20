import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
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
  parseThresholdEd25519SessionClaims,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
} from '../../../core/ThresholdService/validation';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  resolveThresholdRuntimePolicyScope,
  validateThresholdEcdsaAuthorizeInputs,
  validateThresholdEcdsaSessionInputs,
  validateThresholdEd25519SessionTokenInputs,
} from '../../commonRouterUtils';
import { validateRuntimeSnapshotExpectation } from '../../runtimeSnapshotConsumer';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u,
  computeEcdsaHssRoleLocalPasskeyFirstBootstrapAuthDigest32B64u,
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
  waitedMs: number;
  queuedDepth: number;
  release: () => void;
};

const PRESIGN_FORWARD_HOP_HEADER = 'x-threshold-ecdsa-presign-forward-hop';
const PRESIGN_FORWARDED_BY_HEADER = 'x-threshold-ecdsa-presign-forwarded-by';

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
  ed25519SessionClaims: ReturnType<typeof parseThresholdEd25519SessionClaims>;
  ecdsaSessionClaims: ReturnType<typeof parseThresholdEcdsaSessionClaims>;
}): EcdsaRuntimePolicyScope | undefined {
  return (
    normalizeEcdsaRuntimePolicyScope(input.ed25519SessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.appSessionClaims?.runtimePolicyScope) ||
    normalizeEcdsaRuntimePolicyScope(input.ecdsaSessionClaims?.runtimePolicyScope)
  );
}

async function authorizeEcdsaHssRoleLocalFirstBootstrap(input: {
  ctx: ExpressRelayContext;
  headers: Request['headers'];
  request: NonNullable<ReturnType<typeof parseEcdsaHssClientBootstrapRequest>>;
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  const { ctx, headers, request } = input;
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
  const passkeyAuthorization = request.passkeyFirstBootstrapAuthorization;
  if (passkeyAuthorization) {
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
    const expectedChallenge =
      await computeEcdsaHssRoleLocalPasskeyFirstBootstrapAuthDigest32B64u({
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
    return { ok: true };
  }
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
  const session = ctx.opts.session;
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
  const ed25519SessionClaims = parseThresholdEd25519SessionClaims(parsedSession.claims);
  const ecdsaSessionClaims = parseThresholdEcdsaSessionClaims(parsedSession.claims);
  const sessionClaims = appSessionClaims || ed25519SessionClaims || ecdsaSessionClaims;
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
    ed25519SessionClaims,
    ecdsaSessionClaims,
  });
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
  return { ok: true };
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

  router.get('/threshold-ecdsa/healthz', async (req: Request, res: Response) => {
    await handle(ctx, req, res, '/threshold-ecdsa/healthz', {}, async () => {
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

  router.post('/threshold-ecdsa/key-identities', async (req: Request, res: Response) => {
    await handle(ctx, req, res, '/threshold-ecdsa/key-identities', {}, async () => {
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

  router.post('/threshold-ecdsa/hss/bootstrap', async (req: Request, res: Response) => {
    const body = req.body || {};
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/hss/bootstrap',
      {
        walletSessionUserId:
          typeof (body as { walletSessionUserId?: unknown }).walletSessionUserId === 'string'
            ? (body as { walletSessionUserId: string }).walletSessionUserId
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
        if (validated.ok) {
          const identity = validateEcdsaHssSessionIdentity({
            claims: validated.claims,
            walletSessionUserId: parsed.walletSessionUserId,
            rpId: parsed.rpId,
            subjectId: parsed.subjectId,
            relayerKeyId: parsed.relayerKeyId,
          });
          if (!identity.ok) return identity;
        } else {
          const firstBootstrap = await authorizeEcdsaHssRoleLocalFirstBootstrap({
            ctx,
            headers: req.headers || {},
            request: parsed,
          });
          if (!firstBootstrap.ok) return firstBootstrap;
        }
        return await ctx.service.ecdsaHssRoleLocalBootstrap(parsed);
      },
    );
  });

  router.post('/threshold-ecdsa/hss/export/share', async (req: Request, res: Response) => {
    const body = req.body || {};
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/hss/export/share',
      {
        walletSessionUserId:
          typeof (body as { walletSessionUserId?: unknown }).walletSessionUserId === 'string'
            ? (body as { walletSessionUserId: string }).walletSessionUserId
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
          walletSessionUserId: parsed.walletSessionUserId,
          rpId: parsed.rpId,
          subjectId: parsed.subjectId,
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

  router.post('/threshold-ecdsa/authorize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaAuthorizeWithSessionRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/authorize',
      {
        keyHandle: typeof body.keyHandle === 'string' ? body.keyHandle : undefined,
        ecdsaThresholdKeyId:
          typeof body.ecdsaThresholdKeyId === 'string' ? body.ecdsaThresholdKeyId : undefined,
        purpose: typeof body.purpose === 'string' ? body.purpose : undefined,
        signing_digest_32_len: Array.isArray(body.signing_digest_32)
          ? body.signing_digest_32.length
          : undefined,
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

        const validated = await validateThresholdEcdsaAuthorizeInputs({
          body: req.body,
          headers: req.headers || {},
          session: ctx.opts.session,
        });
        if (!validated.ok) return validated;
        const runtimeSnapshotValidation = await validateRuntimeSnapshotExpectation({
          runtimeSnapshots: ctx.opts.runtimeSnapshots,
          scope: validated.claims.runtimePolicyScope,
          expectationRaw: (validated.request as unknown as Record<string, unknown>).runtimeSnapshot,
        });
        if (!runtimeSnapshotValidation.ok) return runtimeSnapshotValidation;

        return scheme.authorize({ claims: validated.claims, request: validated.request });
      },
    );
  });

  router.post('/threshold-ecdsa/presign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaPresignInitRequest;
    const requestTag = parsePresignRequestTag(body);
    const label = resolvePresignLogLabel(requestTag);
    const trafficClass = resolvePresignTrafficClass(requestTag);
    const gateTicket = await presignPriorityGate.acquire(trafficClass);
    try {
      await handle(
        ctx,
        req,
        res,
        '/threshold-ecdsa/presign/init',
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

          return scheme.presign.init({ claims: validated.claims, request: body });
        },
      );
    } finally {
      gateTicket.release();
    }
  });

  router.post('/threshold-ecdsa/presign/step', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaPresignStepRequest;
    const requestTag = parsePresignRequestTag(body);
    const label = resolvePresignLogLabel(requestTag);
    const trafficClass = resolvePresignTrafficClass(requestTag);
    const gateTicket = await presignPriorityGate.acquire(trafficClass);
    try {
      await handle(
        ctx,
        req,
        res,
        '/threshold-ecdsa/presign/step',
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
            toOptionalHeaderString(headers[PRESIGN_FORWARD_HOP_HEADER]),
          );
          const forwardedByInstanceId = toOptionalHeaderString(
            headers[PRESIGN_FORWARDED_BY_HEADER],
          );
          return scheme.presign.step({
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
  });

  router.post('/threshold-ecdsa/sign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaSignInitRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/sign/init',
      {
        mpcSessionId: typeof body.mpcSessionId === 'string' ? body.mpcSessionId : undefined,
        relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
        signingDigestB64u_len:
          typeof body.signingDigestB64u === 'string' ? body.signingDigestB64u.length : undefined,
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
        return resolved.scheme.protocol.signInit(body);
      },
    );
  });

  router.post('/threshold-ecdsa/sign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaSignFinalizeRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/sign/finalize',
      {
        signingSessionId:
          typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
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
        return resolved.scheme.protocol.signFinalize(body);
      },
    );
  });

  router.post('/threshold-ecdsa/internal/cosign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaCosignInitRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/internal/cosign/init',
      {
        coordinatorGrant_len:
          typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
        signingSessionId:
          typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
        cosignerShareB64u_len:
          typeof body.cosignerShareB64u === 'string' ? body.cosignerShareB64u.length : undefined,
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
        const cosignInit = resolved.scheme.protocol.internalCosignInit;
        if (!cosignInit) {
          return {
            ok: false,
            code: 'not_found',
            message: 'threshold-ecdsa cosigner endpoints are not enabled on this server',
          };
        }
        return cosignInit(body);
      },
    );
  });

  router.post('/threshold-ecdsa/internal/cosign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEcdsaCosignFinalizeRequest;
    await handle(
      ctx,
      req,
      res,
      '/threshold-ecdsa/internal/cosign/finalize',
      {
        coordinatorGrant_len:
          typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
        signingSessionId:
          typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
        groupPublicKey_len:
          typeof body.groupPublicKey === 'string' ? body.groupPublicKey.length : undefined,
        cosignerIds_len: Array.isArray(body.cosignerIds) ? body.cosignerIds.length : undefined,
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
        const cosignFinalize = resolved.scheme.protocol.internalCosignFinalize;
        if (!cosignFinalize) {
          return {
            ok: false,
            code: 'not_found',
            message: 'threshold-ecdsa cosigner endpoints are not enabled on this server',
          };
        }
        return cosignFinalize(body);
      },
    );
  });
}
