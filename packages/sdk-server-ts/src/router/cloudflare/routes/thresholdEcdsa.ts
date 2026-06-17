import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
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
  ctx: CloudflareRelayContext;
  request: NonNullable<ReturnType<typeof parseEcdsaHssClientBootstrapRequest>>;
}): Promise<
  | { ok: true; runtimePolicyScope?: EcdsaRuntimePolicyScope }
  | { ok: false; code: string; message: string }
> {
  const { ctx, request } = input;
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

const presignPriorityGate = new PresignPriorityGate();

export async function handleThresholdEcdsa(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ECDSA_HSS_HEALTH_PATH_V1) {
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
    pathname !== ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1 &&
    pathname !== ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH_V1 &&
    pathname !== ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH_V1 &&
    pathname !== ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH_V1 &&
    pathname !== ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH_V1
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

  if (pathname === ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1) {
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

  if (pathname === ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH_V1) {
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
        walletId: parsed.walletId,
        rpId: parsed.rpId,
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
    const signed = await signWalletSessionJwt({
      session: ctx.opts.session,
      kind: 'threshold_ecdsa_session_v2',
      userId: parsed.walletId,
      rpId: parsed.rpId,
      relayerKeyId: parsed.relayerKeyId,
      sessionInfo: {
        sessionKind: 'jwt',
        sessionId: result.value.sessionId,
        walletSigningSessionId: result.value.walletSigningSessionId,
        expiresAtMs: result.value.expiresAtMs,
        participantIds: result.value.participantIds,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        keyHandle: result.value.keyHandle,
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
        ...result.value,
        jwt: signed.jwt,
      },
    };
    return json(signedResult, { status: thresholdEcdsaStatusCode(signedResult) });
  }

  if (pathname === ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH_V1) {
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
      walletId: parsed.walletId,
      rpId: parsed.rpId,
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

  if (pathname === ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH_V1) {
    const reqBody = (body || {}) as RouterAbEcdsaHssPoolFillInitRequest;
    const requestTag = parsePresignRequestTag(reqBody);
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    const validated = await validateThresholdEcdsaSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    try {
      if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
      const result = await scheme.poolFill.init({ claims: validated.claims, request: reqBody });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  if (pathname === ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH_V1) {
    const reqBody = (body || {}) as RouterAbEcdsaHssPoolFillStepRequest;
    const requestTag = parsePresignRequestTag(reqBody);
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    const validated = await validateThresholdEcdsaSessionInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    try {
      if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
      const result = await scheme.poolFill.step({ claims: validated.claims, request: reqBody });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  return null;
}
