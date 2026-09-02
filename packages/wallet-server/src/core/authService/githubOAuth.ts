import { errorMessage } from '@shared/utils/errors';
import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import type { IdentityStore } from '../IdentityStore';
import type { GithubOAuthConfig } from '../types';

const GITHUB_API_VERSION = '2022-11-28';

export type GithubOAuthPublicConfig =
  | { configured: false }
  | { configured: true; clientId: string; callbackUrl: string };

export type GithubOAuthCodeFacadeResult =
  | {
      ok: true;
      verified: true;
      userId: string;
      providerSubject: string;
      iss: 'https://github.com';
      aud: string[];
      sub: string;
      email?: string;
      name?: string;
    }
  | {
      ok: false;
      verified: false;
      code: string;
      message: string;
    };

type GithubUser = {
  id: string;
  login: string;
  name: string;
  email: string;
};

type GithubEmail = {
  email: string;
  primary: boolean;
  verified: boolean;
};

function failure(code: string, message: string): GithubOAuthCodeFacadeResult {
  return { ok: false, verified: false, code, message };
}

function githubHeaders(accessToken: string): HeadersInit {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': 'seams-sdk-auth',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
  };
}

async function parseJson(response: Response): Promise<unknown> {
  return await response.json().catch(() => null);
}

function parseGithubUser(raw: unknown): GithubUser | null {
  if (!isPlainObject(raw)) return null;
  const idRaw = raw.id;
  const id =
    typeof idRaw === 'number' && Number.isSafeInteger(idRaw) && idRaw > 0 ? String(idRaw) : '';
  const login = toOptionalTrimmedString(raw.login) || '';
  if (!id || !login) return null;
  return {
    id,
    login,
    name: toOptionalTrimmedString(raw.name) || login,
    email: (toOptionalTrimmedString(raw.email) || '').toLowerCase(),
  };
}

function parseGithubEmails(raw: unknown): GithubEmail[] {
  if (!Array.isArray(raw)) return [];
  const emails: GithubEmail[] = [];
  for (const item of raw) {
    if (!isPlainObject(item)) continue;
    const email = (toOptionalTrimmedString(item.email) || '').toLowerCase();
    if (!email || item.verified !== true) continue;
    emails.push({ email, verified: true, primary: item.primary === true });
  }
  return emails;
}

function selectGithubEmail(user: GithubUser, emails: readonly GithubEmail[]): string {
  return emails.find((email) => email.primary)?.email || emails[0]?.email || user.email;
}

async function exchangeGithubCode(input: {
  config: GithubOAuthConfig;
  code: string;
  fetchImpl: typeof fetch;
}): Promise<string | null> {
  const response = await input.fetchImpl('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: input.config.clientId,
      client_secret: input.config.clientSecret,
      code: input.code,
      redirect_uri: input.config.callbackUrl,
    }).toString(),
  });
  const body = await parseJson(response);
  if (!response.ok || !isPlainObject(body)) return null;
  return toOptionalTrimmedString(body.access_token) || null;
}

async function fetchGithubIdentity(input: {
  accessToken: string;
  fetchImpl: typeof fetch;
}): Promise<{ user: GithubUser; email: string } | null> {
  const headers = githubHeaders(input.accessToken);
  const [userResponse, emailsResponse] = await Promise.all([
    input.fetchImpl('https://api.github.com/user', { headers }),
    input.fetchImpl('https://api.github.com/user/emails', { headers }),
  ]);
  const user = parseGithubUser(await parseJson(userResponse));
  if (!userResponse.ok || !user) return null;
  const emails = emailsResponse.ok ? parseGithubEmails(await parseJson(emailsResponse)) : [];
  return { user, email: selectGithubEmail(user, emails) };
}

async function resolveGithubUserId(input: {
  identityStore: IdentityStore;
  providerSubject: string;
}): Promise<string> {
  const linked = await input.identityStore.getUserIdBySubject(input.providerSubject);
  const userId = linked || input.providerSubject;
  await input.identityStore.linkSubjectToUserId({
    userId,
    subject: input.providerSubject,
    allowMoveIfSoleIdentity: false,
  });
  return userId;
}

export function githubOAuthPublicConfig(
  config: GithubOAuthConfig | undefined,
): GithubOAuthPublicConfig {
  if (!config) return { configured: false };
  return { configured: true, clientId: config.clientId, callbackUrl: config.callbackUrl };
}

export async function verifyGithubOAuthCodeWithIdentityStore(input: {
  request: { code?: unknown };
  config: GithubOAuthConfig | undefined;
  identityStore: IdentityStore;
  fetchImpl?: typeof fetch;
}): Promise<GithubOAuthCodeFacadeResult> {
  try {
    if (!input.config) return failure('not_configured', 'GitHub OAuth is not configured');
    const code = toOptionalTrimmedString(input.request.code);
    if (!code) return failure('invalid_body', 'exchange.code is required');
    const fetchImpl = input.fetchImpl || fetch;
    const accessToken = await exchangeGithubCode({
      config: input.config,
      code,
      fetchImpl,
    });
    if (!accessToken) return failure('invalid_grant', 'GitHub authorization code exchange failed');
    const identity = await fetchGithubIdentity({ accessToken, fetchImpl });
    if (!identity) return failure('invalid_identity', 'GitHub user lookup failed');
    const providerSubject = `github:${identity.user.id}`;
    const userId = await resolveGithubUserId({
      identityStore: input.identityStore,
      providerSubject,
    });
    return {
      ok: true,
      verified: true,
      userId,
      providerSubject,
      iss: 'https://github.com',
      aud: [input.config.clientId],
      sub: identity.user.id,
      ...(identity.email ? { email: identity.email } : {}),
      name: identity.user.name,
    };
  } catch (error: unknown) {
    return failure('internal', errorMessage(error) || 'GitHub OAuth verification failed');
  }
}
