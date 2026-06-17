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

export const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1 =
  '/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put' as const;

export const ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1 = 'x-router-ab-internal-service-auth';

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
  kind: 'internal_service_auth_token';
  token: string;
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
  return `${base}${CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1}`;
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

function normalizeInternalServiceAuthToken(input: string): string {
  const token = input.trim();
  if (!token) throw new Error('Router A/B internal service-auth token is required');
  if (!/^[\x20-\x7e]+$/.test(token)) {
    throw new Error('Router A/B internal service-auth token must be printable ASCII');
  }
  return token;
}

export async function putRouterAbEcdsaHssPresignaturePoolFill(
  input: RouterAbEcdsaHssPresignaturePoolFillHttpInput,
): Promise<RouterAbEcdsaHssPresignaturePoolFillHttpResult> {
  const request = parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1(input.request);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    [ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1]: normalizeInternalServiceAuthToken(
      input.auth.token,
    ),
  };

  let response: Response;
  try {
    response = await input.fetchImpl(privatePoolFillUrl(input.signingWorkerBaseUrl), {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
    });
  } catch (error: unknown) {
    return { ok: false, code: 'network_error', message: errorMessage(error) };
  }

  const bodyText = await response.text();
  if (!response.ok) {
    return {
      ok: false,
      code: 'http_error',
      message: bodyText || `pool-fill request failed with HTTP ${response.status}`,
      status: response.status,
      bodyText,
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(bodyText);
  } catch {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'pool-fill response body is not valid JSON',
      status: response.status,
      bodyText,
    };
  }

  let receipt: CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire;
  try {
    receipt = parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptForRequestV1(
      request,
      json,
    );
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_response',
      message: errorMessage(error),
      status: response.status,
      bodyText,
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
