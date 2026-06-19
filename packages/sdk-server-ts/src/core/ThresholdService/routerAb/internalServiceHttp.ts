export const ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1 = 'x-router-ab-internal-service-auth';

export type RouterAbInternalServiceJsonResult =
  | { ok: true; status: number; bodyText: string; json: unknown }
  | { ok: false; code: 'network_error'; message: string }
  | { ok: false; code: 'http_error'; status: number; bodyText: string }
  | { ok: false; code: 'invalid_response'; status: number; bodyText: string; message: string };

export function normalizeRouterAbInternalServiceAuthToken(input: string): string {
  const token = input.trim();
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
      : error || '',
  );
}

export async function postRouterAbInternalServiceJson(input: {
  url: string;
  body: unknown;
  authToken: string;
  fetchImpl: typeof fetch;
}): Promise<RouterAbInternalServiceJsonResult> {
  let response: Response;
  try {
    response = await input.fetchImpl(input.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        [ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1]: normalizeRouterAbInternalServiceAuthToken(
          input.authToken,
        ),
      },
      body: JSON.stringify(input.body),
    });
  } catch (error: unknown) {
    return { ok: false, code: 'network_error', message: errorMessage(error) };
  }

  const bodyText = await response.text().catch(() => '');
  if (!response.ok) {
    return { ok: false, code: 'http_error', status: response.status, bodyText };
  }

  try {
    return {
      ok: true,
      status: response.status,
      bodyText,
      json: bodyText ? JSON.parse(bodyText) : {},
    };
  } catch {
    return {
      ok: false,
      code: 'invalid_response',
      status: response.status,
      bodyText,
      message: 'response body is not valid JSON',
    };
  }
}
