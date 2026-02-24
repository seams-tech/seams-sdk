import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import type {
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaBootstrapRequest,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignInitRequest,
} from '../../../core/types';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import { validateThresholdEcdsaAuthorizeInputs, validateThresholdEcdsaSessionInputs } from '../../commonRouterUtils';

const NOT_IMPLEMENTED = { ok: false, code: 'not_implemented', message: 'threshold-ecdsa is not implemented' } as const;

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

export async function handleThresholdEcdsa(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === '/threshold-ecdsa/healthz') {
    const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
      notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
    });
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
    pathname !== '/threshold-ecdsa/bootstrap'
    && pathname !== '/threshold-ecdsa/authorize'
    && pathname !== '/threshold-ecdsa/presign/init'
    && pathname !== '/threshold-ecdsa/presign/step'
    && pathname !== '/threshold-ecdsa/sign/init'
    && pathname !== '/threshold-ecdsa/sign/finalize'
    && pathname !== '/threshold-ecdsa/internal/cosign/init'
    && pathname !== '/threshold-ecdsa/internal/cosign/finalize'
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID, {
    notFoundMessage: 'threshold-ecdsa scheme is not enabled on this server',
  });
  if (!resolved.ok) {
    return json(resolved, { status: thresholdEcdsaStatusCode(resolved) });
  }
  const scheme = resolved.scheme;

  if (pathname === '/threshold-ecdsa/bootstrap') {
    const session = ctx.opts.session;
    if (!session) {
      const resBody = { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured on this server' };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    if (!scheme.bootstrap) {
      const resBody = { ok: false, code: 'not_implemented', message: 'threshold-ecdsa bootstrap is not implemented on this server' };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }

    const reqBody = (body || {}) as ThresholdEcdsaBootstrapRequest;
    const result = await scheme.bootstrap(reqBody);
    if (!result.ok) return json(result, { status: thresholdEcdsaStatusCode(result) });

    const sessionId = String(result.sessionId || '').trim();
    if (!sessionId) {
      return json({ ok: false, code: 'internal', message: 'threshold bootstrap missing sessionId' }, { status: 500 });
    }
    const userId = String(reqBody.userId || reqBody.sessionPolicy?.userId || '').trim();
    const rpId = String(reqBody.rpId || reqBody.sessionPolicy?.rpId || '').trim();
    const relayerKeyId = String(result.relayerKeyId || '').trim();
    const thresholdExpiresAtMs = Number(result.expiresAtMs);
    if (!userId) return json({ ok: false, code: 'internal', message: 'threshold bootstrap missing userId' }, { status: 500 });
    if (!rpId) return json({ ok: false, code: 'internal', message: 'threshold bootstrap missing rpId' }, { status: 500 });
    if (!relayerKeyId) return json({ ok: false, code: 'internal', message: 'threshold bootstrap missing relayerKeyId' }, { status: 500 });
    if (!Number.isFinite(thresholdExpiresAtMs) || thresholdExpiresAtMs <= 0) {
      return json({ ok: false, code: 'internal', message: 'threshold bootstrap missing expiresAtMs' }, { status: 500 });
    }

    const participantIds = Array.isArray(result.participantIds) ? result.participantIds : undefined;
    const nowSec = Math.floor(Date.now() / 1000);
    const expSec = Math.floor(thresholdExpiresAtMs / 1000);
    const token = await session.signJwt(userId, {
      kind: 'threshold_ecdsa_session_v1',
      sessionId,
      relayerKeyId,
      rpId,
      ...(participantIds ? { participantIds } : {}),
      thresholdExpiresAtMs,
      iat: nowSec,
      exp: expSec,
    });

    const sessionKind = parseSessionKind(reqBody);
    if (sessionKind === 'cookie') {
      const headers = { 'Set-Cookie': session.buildSetCookie(token) };
      const { jwt: _omit, ...rest } = result;
      return json({ ...rest, ok: true }, { status: 200, headers });
    }

    return json({ ...result, jwt: token }, { status: 200 });
  }
  if (pathname === '/threshold-ecdsa/authorize') {
    const validated = await validateThresholdEcdsaAuthorizeInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    if (!validated.ok) return json(validated, { status: thresholdEcdsaStatusCode(validated) });
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
      const resBody = { ok: false, code: 'not_found', message: 'threshold-ecdsa cosigner endpoints are not enabled on this server' };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    const reqBody = (body || {}) as ThresholdEcdsaCosignInitRequest;
    const result = await cosignInit(reqBody);
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }
  if (pathname === '/threshold-ecdsa/internal/cosign/finalize') {
    const cosignFinalize = scheme.protocol.internalCosignFinalize;
    if (!cosignFinalize) {
      const resBody = { ok: false, code: 'not_found', message: 'threshold-ecdsa cosigner endpoints are not enabled on this server' };
      return json(resBody, { status: thresholdEcdsaStatusCode(resBody) });
    }
    const reqBody = (body || {}) as ThresholdEcdsaCosignFinalizeRequest;
    const result = await cosignFinalize(reqBody);
    return json(result, { status: thresholdEcdsaStatusCode(result) });
  }

  return null;
}
