import type {
  RouterAbEd25519SigningWorkerPrivateMaterial,
  RouterAbSigningWorkerPrivateHttpConfig,
} from '../core/ThresholdService/ThresholdSigningService';
import { ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1 } from '../core/ThresholdService/routerAb/ecdsaHssPresignBridge';
import type {
  RouterAbEcdsaHssWalletSessionClaims,
  RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import {
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  parseRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
  parseRouterAbEcdsaHssEvmDigestSigningRequestV1,
  routerAbEcdsaHssActiveStateSessionId,
  routerAbEcdsaHssEvmDigestSigningFinalizeRequestDigestV1,
  routerAbEcdsaHssEvmDigestSigningRequestDigestV1,
  type RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaHssNormalSigningScopeV1,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaHss';
import { base64UrlDecode } from '@shared/utils/encoders';

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

function sameEcdsaHssNormalSigningScope(
  left: RouterAbEcdsaHssNormalSigningScopeV1,
  right: RouterAbEcdsaHssNormalSigningScopeV1,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function internalServiceAuthToken(config: RouterAbSigningWorkerPrivateHttpConfig): string {
  const token = config.auth.token.trim();
  if (!token) throw new Error('Router A/B internal service-auth token is required');
  if (!/^[\x20-\x7e]+$/.test(token)) {
    throw new Error('Router A/B internal service-auth token must be printable ASCII');
  }
  return token;
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
}): RouterAbSigningWorkerJsonError | null {
  const scope = isPlainObject(input.body.scope) ? input.body.scope : null;
  const accountId = nonEmptyString(scope?.account_id);
  const sessionId = nonEmptyString(scope?.session_id);
  const signingWorkerId = nonEmptyString(scope?.signing_worker_id);
  if (!accountId || !sessionId || !signingWorkerId) {
    return routerAbSigningError(
      400,
      'invalid_body',
      'Router A/B Ed25519 normal-signing scope is required',
    );
  }
  if (accountId !== input.claims.walletId || sessionId !== input.claims.sessionId) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B Ed25519 normal-signing scope does not match Wallet Session claims',
    );
  }
  if (signingWorkerId !== input.claims.routerAbNormalSigning.signingWorkerId) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B Ed25519 normal-signing worker does not match Wallet Session claims',
    );
  }

  const expiresAtMs = Number(input.body.expires_at_ms);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    return routerAbSigningError(
      400,
      'invalid_body',
      'Router A/B Ed25519 normal-signing expires_at_ms is required',
    );
  }
  if (expiresAtMs > input.claims.thresholdExpiresAtMs) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B Ed25519 normal-signing expiry exceeds Wallet Session expiry',
    );
  }
  return null;
}

export function validateRouterAbEcdsaHssNormalSigningPrepareRequest(input: {
  claims: RouterAbEcdsaHssWalletSessionClaims;
  body: Record<string, unknown>;
}): RouterAbSigningWorkerJsonError | null {
  const normalSigning = input.claims.routerAbEcdsaHssNormalSigning;
  if (!normalSigning) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B ECDSA-HSS normal-signing state is required',
    );
  }
  let request: ReturnType<typeof parseRouterAbEcdsaHssEvmDigestSigningRequestV1>;
  try {
    request = parseRouterAbEcdsaHssEvmDigestSigningRequestV1(input.body);
  } catch (error) {
    return routerAbSigningError(400, 'invalid_body', errorMessage(error));
  }
  if (!sameEcdsaHssNormalSigningScope(request.scope, normalSigning.scope)) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B ECDSA-HSS normal-signing scope does not match Wallet Session claims',
    );
  }
  if (request.expires_at_ms > input.claims.thresholdExpiresAtMs) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B ECDSA-HSS normal-signing expiry exceeds Wallet Session expiry',
    );
  }
  return null;
}

export function validateRouterAbEcdsaHssNormalSigningFinalizeRequest(input: {
  claims: RouterAbEcdsaHssWalletSessionClaims;
  body: Record<string, unknown>;
}): RouterAbSigningWorkerJsonError | null {
  const normalSigning = input.claims.routerAbEcdsaHssNormalSigning;
  if (!normalSigning) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B ECDSA-HSS normal-signing state is required',
    );
  }
  let request: ReturnType<typeof parseRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1>;
  try {
    request = parseRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1(input.body);
  } catch (error) {
    return routerAbSigningError(400, 'invalid_body', errorMessage(error));
  }
  if (!sameEcdsaHssNormalSigningScope(request.scope, normalSigning.scope)) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B ECDSA-HSS normal-signing scope does not match Wallet Session claims',
    );
  }
  if (request.expires_at_ms > input.claims.thresholdExpiresAtMs) {
    return routerAbSigningError(
      403,
      'forbidden',
      'Router A/B ECDSA-HSS normal-signing expiry exceeds Wallet Session expiry',
    );
  }
  return null;
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
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        [ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1]: internalServiceAuthToken(input.config),
      },
      body: JSON.stringify(input.body),
    });
  } catch (error) {
    return routerAbSigningError(
      502,
      'signing_worker_unreachable',
      `Router A/B SigningWorker request failed: ${errorMessage(error)}`,
    );
  }

  const text = await response.text().catch(() => '');
  if (!response.ok) {
    return routerAbSigningError(
      response.status || 502,
      'signing_worker_error',
      text || `Router A/B SigningWorker returned HTTP ${response.status}`,
    );
  }

  try {
    return { ok: true, body: text ? JSON.parse(text) : {} };
  } catch (error) {
    return routerAbSigningError(
      502,
      'invalid_signing_worker_response',
      `Router A/B SigningWorker returned invalid JSON: ${errorMessage(error)}`,
    );
  }
}
