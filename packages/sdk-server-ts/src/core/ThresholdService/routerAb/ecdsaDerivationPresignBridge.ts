import {
  buildCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1,
  parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptForRequestV1,
  parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1,
  parseRouterAbEcdsaDerivationNormalSigningScopeV1,
  type CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire,
  type CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire,
  type RouterAbEcdsaDerivationServerPresignatureShareV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { postRouterAbInternalServiceJson } from './internalServiceHttp';
export { ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1 } from './internalServiceHttp';

export const CLOUDFLARE_SIGNING_WORKER_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH =
  '/router-ab/signing-worker/ecdsa-derivation/presignature-pool/put' as const;
export const CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_INIT_PATH =
  '/router-ab/signing-worker/ecdsa-derivation/presignature-session/init' as const;
export const CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_STEP_PATH =
  '/router-ab/signing-worker/ecdsa-derivation/presignature-session/step' as const;

export type RouterAbEcdsaDerivationPresignaturePoolFillInput = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  presignature: RouterAbEcdsaDerivationServerPresignatureShareV1;
  expiresAtMs: number;
};

export function buildRouterAbEcdsaDerivationPresignaturePoolPutRequest(
  input: RouterAbEcdsaDerivationPresignaturePoolFillInput,
): CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire {
  return parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1(
    buildCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1({
      scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(input.scope),
      presignature: input.presignature,
      expiresAtMs: input.expiresAtMs,
    }),
  );
}

export type RouterAbEcdsaDerivationPresignaturePoolFillAuth = {
  kind: 'internal_service_auth_secret';
  secret: string;
};

export type RouterAbEcdsaDerivationPresignaturePoolFillHttpInput = {
  signingWorkerBaseUrl: string;
  request: CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire;
  auth: RouterAbEcdsaDerivationPresignaturePoolFillAuth;
  fetchImpl: typeof fetch;
};

export type RouterAbEcdsaDerivationPresignaturePoolFillHttpResult =
  | {
      ok: true;
      status: number;
      receipt: CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire & {
        stored: true;
      };
    }
  | {
      ok: false;
      code: 'already_exists';
      message: string;
      status: number;
      receipt: CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire & {
        stored: false;
      };
    }
  | {
      ok: false;
      code: 'http_error';
      message: string;
      status: number;
      bodyText: string;
    }
  | {
      ok: false;
      code: 'invalid_response';
      message: string;
      status: number;
      bodyText: string;
    }
  | {
      ok: false;
      code: 'network_error';
      message: string;
    };

function privatePoolFillUrl(signingWorkerBaseUrl: string): string {
  const base = signingWorkerBaseUrl.trim().replace(/\/+$/, '');
  if (!base) throw new Error('signingWorkerBaseUrl is required');
  return `${base}${CLOUDFLARE_SIGNING_WORKER_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH}`;
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

export type RouterAbEcdsaPresignSessionProgress =
  | {
      kind: 'continue';
      presignSessionId: string;
      stage: 'triples' | 'triples_done' | 'presign';
      event: 'none' | 'triples_done';
      outgoingMessagesB64u: string[];
    }
  | {
      kind: 'complete';
      presignSessionId: string;
      serverPresignatureId: string;
      serverBigR33B64u: string;
    };

export type RouterAbEcdsaPresignSessionHttpResult =
  | { ok: true; value: RouterAbEcdsaPresignSessionProgress }
  | { ok: false; code: 'network_error' | 'http_error' | 'invalid_response'; message: string };

function parseStrictPresignProgress(input: unknown): RouterAbEcdsaPresignSessionProgress {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('SigningWorker ECDSA presign response must be an object');
  }
  const record = input as Record<string, unknown>;
  const kind = String(record.kind || '');
  const presignSessionId = String(record.presign_session_id || '').trim();
  if (!presignSessionId) {
    throw new Error('SigningWorker ECDSA presign response is missing presign_session_id');
  }
  if (kind === 'complete') {
    const serverPresignatureId = String(record.server_presignature_id || '').trim();
    const serverBigR33B64u = String(record.server_big_r33_b64u || '').trim();
    if (!serverPresignatureId || !serverBigR33B64u) {
      throw new Error('SigningWorker ECDSA presign completion is missing public material');
    }
    return {
      kind,
      presignSessionId,
      serverPresignatureId,
      serverBigR33B64u,
    };
  }
  if (kind !== 'continue') {
    throw new Error('SigningWorker ECDSA presign response kind is invalid');
  }
  const stage = String(record.stage || '');
  if (stage !== 'triples' && stage !== 'triples_done' && stage !== 'presign') {
    throw new Error('SigningWorker ECDSA presign response stage is invalid');
  }
  const event = String(record.event || '');
  if (event !== 'none' && event !== 'triples_done') {
    throw new Error('SigningWorker ECDSA presign response event is invalid');
  }
  if (!Array.isArray(record.outgoing_messages_b64u)) {
    throw new Error('SigningWorker ECDSA presign response messages must be an array');
  }
  const outgoingMessagesB64u = record.outgoing_messages_b64u.map((value) => {
    const message = String(value || '').trim();
    if (!message) throw new Error('SigningWorker ECDSA presign response contains an empty message');
    return message;
  });
  return { kind, presignSessionId, stage, event, outgoingMessagesB64u };
}

async function postStrictPresignSession(input: {
  signingWorkerBaseUrl: string;
  path: string;
  body: unknown;
  auth: RouterAbEcdsaDerivationPresignaturePoolFillAuth;
  fetchImpl: typeof fetch;
}): Promise<RouterAbEcdsaPresignSessionHttpResult> {
  const base = input.signingWorkerBaseUrl.trim().replace(/\/+$/, '');
  if (!base)
    return { ok: false, code: 'invalid_response', message: 'signingWorkerBaseUrl is required' };
  const response = await postRouterAbInternalServiceJson({
    url: `${base}${input.path}`,
    body: input.body,
    authSecret: input.auth.secret,
    fetchImpl: input.fetchImpl,
  });
  if (!response.ok) {
    return {
      ok: false,
      code: response.code,
      message:
        response.code === 'network_error'
          ? response.message
          : response.bodyText || 'SigningWorker ECDSA presign request failed',
    };
  }
  try {
    return { ok: true, value: parseStrictPresignProgress(response.json) };
  } catch (error: unknown) {
    return { ok: false, code: 'invalid_response', message: errorMessage(error) };
  }
}

export async function startRouterAbEcdsaPresignSession(input: {
  signingWorkerBaseUrl: string;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  presignSessionId: string;
  expiresAtMs: number;
  auth: RouterAbEcdsaDerivationPresignaturePoolFillAuth;
  fetchImpl: typeof fetch;
}): Promise<RouterAbEcdsaPresignSessionHttpResult> {
  return postStrictPresignSession({
    signingWorkerBaseUrl: input.signingWorkerBaseUrl,
    path: CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_INIT_PATH,
    body: {
      scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(input.scope),
      presign_session_id: input.presignSessionId,
      expires_at_ms: input.expiresAtMs,
    },
    auth: input.auth,
    fetchImpl: input.fetchImpl,
  });
}

export async function stepRouterAbEcdsaPresignSession(input: {
  signingWorkerBaseUrl: string;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  presignSessionId: string;
  requestedStage: 'triples' | 'presign';
  outgoingMessagesB64u: string[];
  expiresAtMs: number;
  auth: RouterAbEcdsaDerivationPresignaturePoolFillAuth;
  fetchImpl: typeof fetch;
}): Promise<RouterAbEcdsaPresignSessionHttpResult> {
  return postStrictPresignSession({
    signingWorkerBaseUrl: input.signingWorkerBaseUrl,
    path: CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_STEP_PATH,
    body: {
      scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(input.scope),
      presign_session_id: input.presignSessionId,
      requested_stage: input.requestedStage,
      outgoing_messages_b64u: input.outgoingMessagesB64u,
      expires_at_ms: input.expiresAtMs,
    },
    auth: input.auth,
    fetchImpl: input.fetchImpl,
  });
}

export async function putRouterAbEcdsaDerivationPresignaturePoolFill(
  input: RouterAbEcdsaDerivationPresignaturePoolFillHttpInput,
): Promise<RouterAbEcdsaDerivationPresignaturePoolFillHttpResult> {
  const request = parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1(
    input.request,
  );
  const url = privatePoolFillUrl(input.signingWorkerBaseUrl);
  const response = await postRouterAbInternalServiceJson({
    url,
    body: request,
    authSecret: input.auth.secret,
    fetchImpl: input.fetchImpl,
  });
  if (!response.ok && response.code === 'network_error') {
    return {
      ok: false,
      code: 'network_error',
      message: `pool-fill request to ${url} failed: ${response.message}`,
    };
  }

  if (!response.ok && response.code === 'http_error') {
    return {
      ok: false,
      code: 'http_error',
      message: response.bodyText || `pool-fill request failed with HTTP ${response.status}`,
      status: response.status,
      bodyText: response.bodyText,
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'pool-fill response body is not valid JSON',
      status: response.status,
      bodyText: response.bodyText,
    };
  }

  let receipt: CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire;
  try {
    receipt = parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptForRequestV1(
      request,
      response.json,
    );
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_response',
      message: errorMessage(error),
      status: response.status,
      bodyText: response.bodyText,
    };
  }

  if (!receipt.stored) {
    return {
      ok: false,
      code: 'already_exists',
      message: 'Router A/B ECDSA derivation presignature already exists in the SigningWorker pool',
      status: response.status,
      receipt: { ...receipt, stored: false },
    };
  }

  return {
    ok: true,
    status: response.status,
    receipt: { ...receipt, stored: true },
  };
}
