export type GithubOAuthOptions =
  | { configured: false }
  | { configured: true; clientId: string; callbackUrl: string };

export type GithubOAuthCallback =
  | { kind: 'none' }
  | { kind: 'error'; message: string }
  | { kind: 'code'; code: string };

const GITHUB_OAUTH_STATE_KEY = 'seams.dashboard.github.oauth.state';

function normalizeRelayBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

async function parseOptionalJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function randomState(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function clearGithubCallbackQuery(): void {
  const url = new URL(window.location.href);
  url.searchParams.delete('code');
  url.searchParams.delete('state');
  url.searchParams.delete('error');
  url.searchParams.delete('error_description');
  window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`);
}

export async function fetchGithubOAuthOptions(relayerBaseUrl: string): Promise<GithubOAuthOptions> {
  const baseUrl = normalizeRelayBaseUrl(relayerBaseUrl);
  if (!baseUrl) return { configured: false };
  const response = await fetch(`${baseUrl}/auth/github/options`, {
    method: 'POST',
    credentials: 'include',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  const body = await parseOptionalJson(response);
  if (!response.ok || !body || typeof body !== 'object') return { configured: false };
  const record = body as Record<string, unknown>;
  const clientId = String(record.clientId || '').trim();
  const callbackUrl = String(record.callbackUrl || '').trim();
  if (record.ok !== true || record.configured !== true || !clientId || !callbackUrl) {
    return { configured: false };
  }
  return { configured: true, clientId, callbackUrl };
}

export function beginGithubOAuth(options: Extract<GithubOAuthOptions, { configured: true }>): void {
  const state = randomState();
  sessionStorage.setItem(GITHUB_OAUTH_STATE_KEY, state);
  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', options.clientId);
  authorizeUrl.searchParams.set('redirect_uri', options.callbackUrl);
  authorizeUrl.searchParams.set('scope', 'read:user user:email');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('prompt', 'select_account');
  window.location.assign(authorizeUrl.toString());
}

export function consumeGithubOAuthCallback(): GithubOAuthCallback {
  const params = new URLSearchParams(window.location.search);
  const code = String(params.get('code') || '').trim();
  const returnedState = String(params.get('state') || '').trim();
  const oauthError = String(params.get('error_description') || params.get('error') || '').trim();
  if (!code && !oauthError) return { kind: 'none' };
  const expectedState = String(sessionStorage.getItem(GITHUB_OAUTH_STATE_KEY) || '').trim();
  sessionStorage.removeItem(GITHUB_OAUTH_STATE_KEY);
  clearGithubCallbackQuery();
  if (oauthError) return { kind: 'error', message: `GitHub sign-in failed: ${oauthError}` };
  if (!expectedState || !returnedState || expectedState !== returnedState) {
    return { kind: 'error', message: 'GitHub sign-in state did not match. Please try again.' };
  }
  return { kind: 'code', code };
}
