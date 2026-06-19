import type {
  RouterAbEd25519SigningWorkerPrivateMaterial,
  RouterAbSigningWorkerPrivateHttpConfig,
} from '../core/ThresholdService/ThresholdSigningService';
import { postRouterAbInternalServiceJson } from '../core/ThresholdService/routerAb/internalServiceHttp';
import type {
  RouterAbEcdsaHssWalletSessionClaims,
  RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import { validateRouterAbEd25519WalletSessionTokenInputs } from './commonRouterUtils';
import type { SessionAdapter } from './relay';
import {
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  parseRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
  parseRouterAbEcdsaHssEvmDigestSigningRequestV1,
  routerAbEcdsaHssActiveStateSessionId,
  routerAbEcdsaHssEvmDigestSigningFinalizeRequestDigestV1,
  routerAbEcdsaHssEvmDigestSigningRequestDigestV1,
  sameRouterAbEcdsaHssNormalSigningScopeV1,
  type RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaHssNormalSigningScopeV1,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaHss';
import { base64UrlDecode } from '@shared/utils/encoders';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';

const PRIVATE_ED25519_SIGNING_PREPARE_PATH_V1 = '/router-ab/v1/signing-worker/sign/prepare';
const PRIVATE_ED25519_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1 =
  '/router-ab/v1/signing-worker/sign/presign-pool/prepare';
const PRIVATE_ED25519_SIGNING_PRESIGN_POOL_FINALIZE_PATH_V1 =
  '/router-ab/v1/signing-worker/sign/presign-pool';
const PRIVATE_ED25519_SIGNING_FINALIZE_PATH_V1 = '/router-ab/v1/signing-worker/sign';
const PRIVATE_ECDSA_HSS_SIGNING_PREPARE_PATH_V1 =
  '/router-ab/v1/signing-worker/ecdsa-hss/sign/prepare';
const PRIVATE_ECDSA_HSS_SIGNING_FINALIZE_PATH_V1 = '/router-ab/v1/signing-worker/ecdsa-hss/sign';

export type RouterAbEd25519PrivateSigningPath =
  | typeof PRIVATE_ED25519_SIGNING_PREPARE_PATH_V1
  | typeof PRIVATE_ED25519_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1
  | typeof PRIVATE_ED25519_SIGNING_PRESIGN_POOL_FINALIZE_PATH_V1
  | typeof PRIVATE_ED25519_SIGNING_FINALIZE_PATH_V1;

export const ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS = {
  prepare: PRIVATE_ED25519_SIGNING_PREPARE_PATH_V1,
  presignPoolPrepare: PRIVATE_ED25519_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1,
  presignPoolFinalize: PRIVATE_ED25519_SIGNING_PRESIGN_POOL_FINALIZE_PATH_V1,
  finalize: PRIVATE_ED25519_SIGNING_FINALIZE_PATH_V1,
} as const;

export type RouterAbEcdsaHssPrivateSigningPath =
  | typeof PRIVATE_ECDSA_HSS_SIGNING_PREPARE_PATH_V1
  | typeof PRIVATE_ECDSA_HSS_SIGNING_FINALIZE_PATH_V1;

export const ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS = {
  prepare: PRIVATE_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
  finalize: PRIVATE_ECDSA_HSS_SIGNING_FINALIZE_PATH_V1,
} as const;

export type RouterAbSigningWorkerJsonResult =
  | { ok: true; body: unknown }
  | {
      ok: false;
      status: number;
      body: { ok: false; code: string; message: string };
    };
type RouterAbSigningWorkerJsonError = Extract<RouterAbSigningWorkerJsonResult, { ok: false }>;

export type RouterAbEd25519NormalSigningRoutePhase =
  | 'prepare'
  | 'presign-pool-prepare'
  | 'finalize';

export type RouterAbJsonRouteResult = {
  status: number;
  body: unknown;
};

type RouterAbEd25519NormalSigningThresholdService = {
  getRouterAbSigningWorkerPrivateHttpConfig(): RouterAbSigningWorkerPrivateHttpConfig | null;
  resolveRouterAbEd25519SigningWorkerPrivateMaterial(input: {
    claims: RouterAbEd25519WalletSessionClaims;
  }): Promise<
    | { ok: true; material: RouterAbEd25519SigningWorkerPrivateMaterial }
    | { ok: false; status: number; code: string; message: string }
  >;
  reserveRouterAbNormalSigningPrepareReplay(input: {
    curve: 'ed25519';
    phase: 'prepare' | 'presign-pool-prepare';
    sessionId: string;
    requestId: string;
    expiresAtMs: number;
  }): Promise<
    | { ok: true }
    | { ok: false; status: number; code: string; message: string }
  >;
};

export type RouterAbNormalSigningRouteAdmission =
  | {
      ok: true;
      sessionId: string;
      requestId: string;
      expiresAtMs: number;
    }
  | {
      ok: false;
      error: RouterAbSigningWorkerJsonError;
    };

export type RouterAbNormalSigningAdmissionFailureCode =
  | 'project_policy_rejected'
  | 'quota_saturated'
  | 'abuse_rejected'
  | 'rate_limited'
  | 'unauthorized'
  | 'invalid_body'
  | 'not_configured'
  | 'internal';

export type RouterAbNormalSigningAdmissionFailure = {
  ok: false;
  status: 400 | 401 | 403 | 408 | 409 | 429 | 500 | 503;
  code: RouterAbNormalSigningAdmissionFailureCode;
  message: string;
};

export type RouterAbNormalSigningAdmissionResult =
  | { ok: true }
  | RouterAbNormalSigningAdmissionFailure;

export type RouterAbNormalSigningAdmissionInput =
  | {
      curve: 'ed25519';
      phase: 'prepare' | 'presign-pool-prepare' | 'finalize';
      walletId: string;
      rpId: string;
      sessionId: string;
      walletSigningSessionId: string;
      requestId: string;
      expiresAtMs: number;
      signingWorkerId: string;
      runtimePolicyScope: RuntimePolicyScope;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'prepare' | 'finalize';
      walletId: string;
      rpId: string;
      sessionId: string;
      walletSigningSessionId: string;
      requestId: string;
      expiresAtMs: number;
      signingWorkerId: string;
      keyHandle: string;
      runtimePolicyScope: RuntimePolicyScope;
    };

export interface RouterAbNormalSigningAdmissionAdapter {
  evaluate(input: RouterAbNormalSigningAdmissionInput): Promise<RouterAbNormalSigningAdmissionResult>;
}

type AcceptedRouteAdmission = Extract<RouterAbNormalSigningRouteAdmission, { ok: true }>;

export type RouterAbNormalSigningAdmissionEvaluationInput =
  | {
      adapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
      curve: 'ed25519';
      phase: 'prepare' | 'presign-pool-prepare' | 'finalize';
      claims: RouterAbEd25519WalletSessionClaims;
      admission: AcceptedRouteAdmission;
    }
  | {
      adapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
      curve: 'ecdsa-hss';
      phase: 'prepare' | 'finalize';
      claims: RouterAbEcdsaHssWalletSessionClaims;
      admission: AcceptedRouteAdmission;
    };

export async function evaluateRouterAbNormalSigningAdmission(
  input: RouterAbNormalSigningAdmissionEvaluationInput,
): Promise<RouterAbNormalSigningAdmissionResult> {
  if (!input.adapter) return { ok: true };

  if (input.curve === 'ed25519') {
    return await input.adapter.evaluate({
      curve: 'ed25519',
      phase: input.phase,
      walletId: input.claims.walletId,
      rpId: input.claims.rpId,
      sessionId: input.admission.sessionId,
      walletSigningSessionId: input.claims.walletSigningSessionId,
      requestId: input.admission.requestId,
      expiresAtMs: input.admission.expiresAtMs,
      signingWorkerId: input.claims.routerAbNormalSigning.signingWorkerId,
      runtimePolicyScope: input.claims.runtimePolicyScope,
    });
  }

  if (!input.claims.runtimePolicyScope) {
    return {
      ok: false,
      status: 403,
      code: 'project_policy_rejected',
      message: 'Router A/B ECDSA-HSS normal-signing runtime policy scope is required',
    };
  }

  return await input.adapter.evaluate({
    curve: 'ecdsa-hss',
    phase: input.phase,
    walletId: input.claims.walletId,
    rpId: input.claims.rpId,
    sessionId: input.admission.sessionId,
    walletSigningSessionId: input.claims.walletSigningSessionId,
    requestId: input.admission.requestId,
    expiresAtMs: input.admission.expiresAtMs,
    signingWorkerId: input.claims.routerAbEcdsaHssNormalSigning.scope.signing_worker.server_id,
    keyHandle: input.claims.keyHandle,
    runtimePolicyScope: input.claims.runtimePolicyScope,
  });
}

export type RouterAbEd25519PrivateSigningWorkerBody = {
  kind: 'router_ab_ed25519_signing_worker_private_request_v1';
  request: Record<string, unknown>;
  server_material: RouterAbEd25519SigningWorkerPrivateMaterial;
};

type RouterAbEcdsaHssTrustedAdmissionV1 = {
  account_id: string;
  session_id: string;
  request_digest: RouterAbPublicDigest32V1Wire;
  signing_digest: RouterAbPublicDigest32V1Wire;
  admitted_at_ms: number;
  expires_at_ms: number;
};

type RouterAbEcdsaHssPrivatePrepareSigningWorkerBody = {
  request: RouterAbEcdsaHssEvmDigestSigningRequestV1Wire;
  trusted_admission: RouterAbEcdsaHssTrustedAdmissionV1;
};

type RouterAbEcdsaHssPrivateFinalizeSigningWorkerBody = {
  request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1Wire;
  trusted_admission: RouterAbEcdsaHssTrustedAdmissionV1;
};

export type RouterAbEcdsaHssPrivateSigningWorkerBody =
  | RouterAbEcdsaHssPrivatePrepareSigningWorkerBody
  | RouterAbEcdsaHssPrivateFinalizeSigningWorkerBody;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function routerAbSigningError(
  status: number,
  code: string,
  message: string,
): RouterAbSigningWorkerJsonError {
  return { ok: false, status, body: { ok: false, code, message } };
}

function privateSigningWorkerUrl(
  config: RouterAbSigningWorkerPrivateHttpConfig,
  path: RouterAbEd25519PrivateSigningPath | RouterAbEcdsaHssPrivateSigningPath,
): string {
  const base = config.signingWorkerBaseUrl.trim().replace(/\/+$/, '');
  if (!base) throw new Error('Router A/B SigningWorker base URL is required');
  return `${base}${path}`;
}

export function buildRouterAbEd25519PrivateSigningWorkerBody(input: {
  body: Record<string, unknown>;
  material: RouterAbEd25519SigningWorkerPrivateMaterial;
}): RouterAbEd25519PrivateSigningWorkerBody {
  return {
    kind: 'router_ab_ed25519_signing_worker_private_request_v1',
    request: input.body,
    server_material: input.material,
  };
}

function digest32FromB64u(value: string): RouterAbPublicDigest32V1Wire {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 32) {
    throw new Error('Router A/B digest must be 32 bytes');
  }
  return { bytes: Array.from(bytes) };
}

function ecdsaHssTrustedAdmission(input: {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  requestDigest: RouterAbPublicDigest32V1Wire;
  signingDigestB64u: string;
  expiresAtMs: number;
}): RouterAbEcdsaHssTrustedAdmissionV1 {
  return {
    account_id: input.scope.context.wallet_id,
    session_id: routerAbEcdsaHssActiveStateSessionId({
      kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
      scope: input.scope,
    }),
    request_digest: input.requestDigest,
    signing_digest: digest32FromB64u(input.signingDigestB64u),
    admitted_at_ms: Math.max(1, Math.floor(Date.now())),
    expires_at_ms: input.expiresAtMs,
  };
}

export async function buildRouterAbEcdsaHssPrivateSigningWorkerBody(input: {
  phase: 'prepare' | 'finalize';
  body: Record<string, unknown>;
}): Promise<RouterAbEcdsaHssPrivateSigningWorkerBody> {
  if (input.phase === 'prepare') {
    const request = parseRouterAbEcdsaHssEvmDigestSigningRequestV1(input.body);
    const requestDigest = await routerAbEcdsaHssEvmDigestSigningRequestDigestV1(request);
    return {
      request,
      trusted_admission: ecdsaHssTrustedAdmission({
        scope: request.scope,
        requestDigest,
        signingDigestB64u: request.signing_digest_b64u,
        expiresAtMs: request.expires_at_ms,
      }),
    };
  }
  const request = parseRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1(input.body);
  const requestDigest = await routerAbEcdsaHssEvmDigestSigningFinalizeRequestDigestV1(request);
  return {
    request,
    trusted_admission: ecdsaHssTrustedAdmission({
      scope: request.scope,
      requestDigest,
      signingDigestB64u: request.signing_digest_b64u,
      expiresAtMs: request.expires_at_ms,
    }),
  };
}

export function resolveRouterAbEd25519PrivateSigningPath(input: {
  defaultPath: RouterAbEd25519PrivateSigningPath;
  body: Record<string, unknown>;
}): RouterAbEd25519PrivateSigningPath {
  if (
    input.defaultPath === ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize &&
    isPlainObject(input.body.pool_binding)
  ) {
    return ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.presignPoolFinalize;
  }
  return input.defaultPath;
}

export async function handleRouterAbEd25519NormalSigningRouteCore(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  getThreshold: () => RouterAbEd25519NormalSigningThresholdService | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  privatePath: RouterAbEd25519PrivateSigningPath;
  phase: RouterAbEd25519NormalSigningRoutePhase;
}): Promise<RouterAbJsonRouteResult> {
  const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: input.rawBody,
    headers: input.headers,
    session: input.session,
  });
  if (!validated.ok) {
    return {
      status: validated.code === 'sessions_disabled' ? 501 : 401,
      body: { ok: false, code: validated.code, message: validated.message },
    };
  }

  const admission = validateRouterAbEd25519NormalSigningRequestScope({
    claims: validated.claims,
    body: input.body,
  });
  if (!admission.ok) {
    return { status: admission.error.status, body: admission.error.body };
  }

  const threshold = input.getThreshold();
  if (!threshold) {
    return {
      status: 501,
      body: {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B Threshold service is not configured',
      },
    };
  }

  const admissionDecision = await evaluateRouterAbNormalSigningAdmission({
    adapter: input.admissionAdapter,
    curve: 'ed25519',
    phase: input.phase,
    claims: validated.claims,
    admission,
  });
  if (!admissionDecision.ok) {
    return {
      status: admissionDecision.status,
      body: {
        ok: false,
        code: admissionDecision.code,
        message: admissionDecision.message,
      },
    };
  }

  const signingWorker = threshold.getRouterAbSigningWorkerPrivateHttpConfig();
  if (!signingWorker) {
    return {
      status: 501,
      body: {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B SigningWorker private HTTP target is not configured',
      },
    };
  }

  const material = await threshold.resolveRouterAbEd25519SigningWorkerPrivateMaterial({
    claims: validated.claims,
  });
  if (!material.ok) {
    return {
      status: material.status,
      body: { ok: false, code: material.code, message: material.message },
    };
  }

  if (input.phase === 'prepare' || input.phase === 'presign-pool-prepare') {
    const replay = await threshold.reserveRouterAbNormalSigningPrepareReplay({
      curve: 'ed25519',
      phase: input.phase,
      sessionId: admission.sessionId,
      requestId: admission.requestId,
      expiresAtMs: admission.expiresAtMs,
    });
    if (!replay.ok) {
      return {
        status: replay.status,
        body: { ok: false, code: replay.code, message: replay.message },
      };
    }
  }

  const forwarded = await postRouterAbSigningWorkerJson({
    config: signingWorker,
    path: resolveRouterAbEd25519PrivateSigningPath({
      defaultPath: input.privatePath,
      body: input.body,
    }),
    body: buildRouterAbEd25519PrivateSigningWorkerBody({
      body: input.body,
      material: material.material,
    }),
  });
  if (!forwarded.ok) {
    return { status: forwarded.status, body: forwarded.body };
  }
  return { status: 200, body: forwarded.body };
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || 'unknown error',
  );
}

export function validateRouterAbEd25519NormalSigningRequestScope(input: {
  claims: RouterAbEd25519WalletSessionClaims;
  body: Record<string, unknown>;
}): RouterAbNormalSigningRouteAdmission {
  const scope = isPlainObject(input.body.scope) ? input.body.scope : null;
  const requestId = nonEmptyString(scope?.request_id);
  const accountId = nonEmptyString(scope?.account_id);
  const sessionId = nonEmptyString(scope?.session_id);
  const signingWorkerId = nonEmptyString(scope?.signing_worker_id);
  if (!requestId || !accountId || !sessionId || !signingWorkerId) {
    return {
      ok: false,
      error: routerAbSigningError(
        400,
        'invalid_body',
        'Router A/B Ed25519 normal-signing scope is required',
      ),
    };
  }
  if (accountId !== input.claims.walletId || sessionId !== input.claims.sessionId) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B Ed25519 normal-signing scope does not match Wallet Session claims',
      ),
    };
  }
  if (signingWorkerId !== input.claims.routerAbNormalSigning.signingWorkerId) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B Ed25519 normal-signing worker does not match Wallet Session claims',
      ),
    };
  }

  const expiresAtMs = Number(input.body.expires_at_ms);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    return {
      ok: false,
      error: routerAbSigningError(
        400,
        'invalid_body',
        'Router A/B Ed25519 normal-signing expires_at_ms is required',
      ),
    };
  }
  if (expiresAtMs <= Date.now()) {
    return {
      ok: false,
      error: routerAbSigningError(
        408,
        'expired_request',
        'Router A/B Ed25519 normal-signing request is expired',
      ),
    };
  }
  if (expiresAtMs > input.claims.thresholdExpiresAtMs) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B Ed25519 normal-signing expiry exceeds Wallet Session expiry',
      ),
    };
  }
  return {
    ok: true,
    sessionId,
    requestId,
    expiresAtMs,
  };
}

export function validateRouterAbEcdsaHssNormalSigningPrepareRequest(input: {
  claims: RouterAbEcdsaHssWalletSessionClaims;
  body: Record<string, unknown>;
}): RouterAbNormalSigningRouteAdmission {
  const normalSigning = input.claims.routerAbEcdsaHssNormalSigning;
  if (!normalSigning) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA-HSS normal-signing state is required',
      ),
    };
  }
  let request: ReturnType<typeof parseRouterAbEcdsaHssEvmDigestSigningRequestV1>;
  try {
    request = parseRouterAbEcdsaHssEvmDigestSigningRequestV1(input.body);
  } catch (error) {
    return {
      ok: false,
      error: routerAbSigningError(400, 'invalid_body', errorMessage(error)),
    };
  }
  if (!sameRouterAbEcdsaHssNormalSigningScopeV1(request.scope, normalSigning.scope)) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA-HSS normal-signing scope does not match Wallet Session claims',
      ),
    };
  }
  if (request.expires_at_ms <= Date.now()) {
    return {
      ok: false,
      error: routerAbSigningError(
        408,
        'expired_request',
        'Router A/B ECDSA-HSS normal-signing request is expired',
      ),
    };
  }
  if (request.expires_at_ms > input.claims.thresholdExpiresAtMs) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA-HSS normal-signing expiry exceeds Wallet Session expiry',
      ),
    };
  }
  return {
    ok: true,
    sessionId: input.claims.sessionId,
    requestId: request.request_id,
    expiresAtMs: request.expires_at_ms,
  };
}

export function validateRouterAbEcdsaHssNormalSigningFinalizeRequest(input: {
  claims: RouterAbEcdsaHssWalletSessionClaims;
  body: Record<string, unknown>;
}): RouterAbNormalSigningRouteAdmission {
  const normalSigning = input.claims.routerAbEcdsaHssNormalSigning;
  if (!normalSigning) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA-HSS normal-signing state is required',
      ),
    };
  }
  let request: ReturnType<typeof parseRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1>;
  try {
    request = parseRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1(input.body);
  } catch (error) {
    return {
      ok: false,
      error: routerAbSigningError(400, 'invalid_body', errorMessage(error)),
    };
  }
  if (!sameRouterAbEcdsaHssNormalSigningScopeV1(request.scope, normalSigning.scope)) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA-HSS normal-signing scope does not match Wallet Session claims',
      ),
    };
  }
  if (request.expires_at_ms <= Date.now()) {
    return {
      ok: false,
      error: routerAbSigningError(
        408,
        'expired_request',
        'Router A/B ECDSA-HSS normal-signing request is expired',
      ),
    };
  }
  if (request.expires_at_ms > input.claims.thresholdExpiresAtMs) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA-HSS normal-signing expiry exceeds Wallet Session expiry',
      ),
    };
  }
  return {
    ok: true,
    sessionId: input.claims.sessionId,
    requestId: request.request_id,
    expiresAtMs: request.expires_at_ms,
  };
}

export async function postRouterAbSigningWorkerJson(input: {
  config: RouterAbSigningWorkerPrivateHttpConfig;
  path: RouterAbEd25519PrivateSigningPath | RouterAbEcdsaHssPrivateSigningPath;
  body: unknown;
  fetchImpl?: typeof fetch;
}): Promise<RouterAbSigningWorkerJsonResult> {
  const fetchImpl = input.fetchImpl || fetch;
  if (typeof fetchImpl !== 'function') {
    return routerAbSigningError(500, 'internal', 'fetch is not available in this runtime');
  }

  const url = privateSigningWorkerUrl(input.config, input.path);
  const response = await postRouterAbInternalServiceJson({
    url,
    body: input.body,
    authToken: input.config.auth.token,
    fetchImpl,
  });
  if (!response.ok && response.code === 'network_error') {
    return routerAbSigningError(
      502,
      'signing_worker_unreachable',
      `Router A/B SigningWorker request failed: ${response.message}`,
    );
  }

  if (!response.ok && response.code === 'http_error') {
    return routerAbSigningError(
      response.status || 502,
      'signing_worker_error',
      response.bodyText || `Router A/B SigningWorker returned HTTP ${response.status}`,
    );
  }

  if (!response.ok) {
    return routerAbSigningError(
      502,
      'invalid_signing_worker_response',
      `Router A/B SigningWorker returned invalid JSON: ${response.message}`,
    );
  }

  return { ok: true, body: response.json };
}
