import { FRONTEND_CONFIG } from '@/config';

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
  return {
    Accept: 'application/json',
  };
}

export function buildConsoleJsonHeaders(): HeadersInit {
  return {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };
}

export async function parseConsoleJson(response: Response): Promise<any> {
  return response.json().catch(() => null);
}

export function consoleErrorMessage(response: Response, body: any, fallbackPrefix: string): string {
  const apiMessage = String(body?.message || '').trim();
  return apiMessage || `${fallbackPrefix} (${response.status})`;
}

