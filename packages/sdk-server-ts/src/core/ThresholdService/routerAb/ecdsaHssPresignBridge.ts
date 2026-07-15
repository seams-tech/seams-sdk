import {
  buildCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1,
  parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptForRequestV1,
  parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1,
  parseRouterAbEcdsaHssNormalSigningScopeV1,
  type CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire,
  type CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire,
  type RouterAbEcdsaHssServerPresignatureShareV1,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import { postRouterAbInternalServiceJson } from './internalServiceHttp';
export { ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1 } from './internalServiceHttp';

export const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH =
  '/router-ab/signing-worker/ecdsa-hss/presignature-pool/put' as const;

export type RouterAbEcdsaHssPresignaturePoolFillInput = {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  presignature: RouterAbEcdsaHssServerPresignatureShareV1;
  expiresAtMs: number;
};

export function buildRouterAbEcdsaHssPresignaturePoolPutRequest(
  input: RouterAbEcdsaHssPresignaturePoolFillInput,
): CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire {
  return parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1(
    buildCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1({
      scope: parseRouterAbEcdsaHssNormalSigningScopeV1(input.scope),
      presignature: input.presignature,
      expiresAtMs: input.expiresAtMs,
    }),
  );
}

export type RouterAbEcdsaHssPresignaturePoolFillAuth = {
  kind: 'internal_service_auth_secret';
  secret: string;
};

export type RouterAbEcdsaHssPresignaturePoolFillHttpInput = {
  signingWorkerBaseUrl: string;
  request: CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire;
  auth: RouterAbEcdsaHssPresignaturePoolFillAuth;
  fetchImpl: typeof fetch;
};

export type RouterAbEcdsaHssPresignaturePoolFillHttpResult =
  | {
      ok: true;
      status: number;
      receipt: CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire & {
        stored: true;
      };
    }
  | {
      ok: false;
      code: 'already_exists';
      message: string;
      status: number;
      receipt: CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire & {
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
  return `${base}${CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH}`;
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

export async function putRouterAbEcdsaHssPresignaturePoolFill(
  input: RouterAbEcdsaHssPresignaturePoolFillHttpInput,
): Promise<RouterAbEcdsaHssPresignaturePoolFillHttpResult> {
  const request = parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1(input.request);
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

  let receipt: CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire;
  try {
    receipt = parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptForRequestV1(
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
      message: 'Router A/B ECDSA-HSS presignature already exists in the SigningWorker pool',
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
