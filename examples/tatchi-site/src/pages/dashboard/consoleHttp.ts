import { FRONTEND_CONFIG } from '@/config';
import { readDashboardActorUserId } from './dashboardActorIdentity';

export function resolveConsoleBaseUrl(): string {
  const base = String(FRONTEND_CONFIG.consoleBaseUrl || FRONTEND_CONFIG.relayerUrl || '').trim();
  return base.replace(/\/+$/, '');
}

export function requireConsoleBaseUrl(): string {
  const base = resolveConsoleBaseUrl();
  if (!base) {
    throw new Error(
      'Console API base URL is not configured (set VITE_CONSOLE_BASE_URL or VITE_RELAYER_URL).',
    );
  }
  return base;
}

export function buildConsoleAcceptHeaders(): HeadersInit {
  const authHeaders = buildConsoleAuthHeaders();
  return {
    Accept: 'application/json',
    ...authHeaders,
  };
}

export function buildConsoleJsonHeaders(): HeadersInit {
  const authHeaders = buildConsoleAuthHeaders();
  return {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    ...authHeaders,
  };
}

export async function parseConsoleJson(response: Response): Promise<any> {
  return response.json().catch(() => null);
}

export function consoleErrorMessage(response: Response, body: any, fallbackPrefix: string): string {
  const apiMessage = String(body?.message || '').trim();
  return apiMessage || `${fallbackPrefix} (${response.status})`;
}

function normalizeUrl(input: string): URL | null {
  try {
    return new URL(String(input || '').trim());
  } catch {
    return null;
  }
}

function isLikelyNetworkFetchFailure(error: unknown): boolean {
  if (error instanceof TypeError) return true;
  const message = String((error as Error | undefined)?.message || '')
    .trim()
    .toLowerCase();
  if (!message) return false;
  return (
    message.includes('failed to fetch') ||
    message.includes('networkerror') ||
    message.includes('load failed') ||
    message.includes('fetch failed') ||
    message.includes('err_failed')
  );
}

export function normalizeConsoleFetchError(input: {
  error: unknown;
  baseUrl: string;
  path: string;
  operation: string;
}): Error {
  const { error, baseUrl, path, operation } = input;
  if (!isLikelyNetworkFetchFailure(error)) {
    return error instanceof Error ? error : new Error(String(error));
  }

  const base = String(baseUrl || '').trim().replace(/\/+$/, '');
  const requestPath = String(path || '').trim();
  const endpoint =
    base && requestPath
      ? `${base}${requestPath.startsWith('/') ? requestPath : `/${requestPath}`}`
      : requestPath || base || 'unknown endpoint';
  const currentOrigin =
    typeof window !== 'undefined' ? String(window.location.origin || '').trim() : '';

  const endpointUrl = normalizeUrl(endpoint);
  const mixedContentBlocked =
    typeof window !== 'undefined' &&
    window.location.protocol === 'https:' &&
    endpointUrl?.protocol === 'http:';

  const hints: string[] = [];
  if (currentOrigin) hints.push(`dashboard origin: ${currentOrigin}`);
  if (endpointUrl?.origin) hints.push(`console origin: ${endpointUrl.origin}`);
  if (mixedContentBlocked) {
    hints.push(
      'mixed-content blocked: HTTPS dashboard cannot call an HTTP Console API origin',
    );
  }
  hints.push(
    'verify relay/console server is running and CORS allows the dashboard origin',
  );

  return new Error(
    `${operation} failed. Unable to reach Console API endpoint ${endpoint}. ${hints.join('; ')}.`,
  );
}

function buildConsoleAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  const auth = FRONTEND_CONFIG.consoleAuth;
  const actorUserId = readDashboardActorUserId();
  if (auth.bearerToken) {
    headers.Authorization = `Bearer ${auth.bearerToken}`;
  }
  if (auth.orgId) headers['x-console-org-id'] = auth.orgId;
  if (actorUserId) {
    headers['x-console-user-id'] = actorUserId;
  } else if (auth.userId) {
    headers['x-console-user-id'] = auth.userId;
  }
  if (auth.roles) headers['x-console-roles'] = auth.roles;
  if (auth.projectId) headers['x-console-project-id'] = auth.projectId;
  if (auth.environmentId) headers['x-console-environment-id'] = auth.environmentId;
  return headers;
}
