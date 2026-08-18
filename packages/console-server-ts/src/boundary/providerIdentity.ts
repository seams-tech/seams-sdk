import { base64UrlDecode } from './encoding';

// Console-owned Google/GitHub provider verification for /console/auth/*.
// Unlike the Wallet server's verifier there is no identity-link store here:
// the Console user id is deterministically `google:<sub>` / `github:<id>`,
// and no correlation with Wallet identities is required or performed.

export type ConsoleGithubOAuthConfig = {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly callbackUrl: string;
};

export type ConsoleProviderVerificationFailure = {
  readonly ok: false;
  readonly verified: false;
  readonly code: string;
  readonly message: string;
};

export type ConsoleGoogleLoginResult =
  | {
      readonly ok: true;
      readonly verified: true;
      readonly userId: string;
      readonly providerSubject: string;
      readonly sub: string;
      readonly email?: string;
      readonly name?: string;
      readonly emailVerified?: boolean;
      readonly hostedDomain?: string;
    }
  | ConsoleProviderVerificationFailure;

export type ConsoleGithubLoginResult =
  | {
      readonly ok: true;
      readonly verified: true;
      readonly userId: string;
      readonly providerSubject: string;
      readonly sub: string;
      readonly email?: string;
      readonly name?: string;
    }
  | ConsoleProviderVerificationFailure;

export interface ConsoleProviderIdentity {
  verifyGoogleLogin(input: { idToken: string }): Promise<ConsoleGoogleLoginResult>;
  verifyGithubOAuthCode(input: { code: string }): Promise<ConsoleGithubLoginResult>;
}

function toOptionalTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function toRecordValue(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}

function failure(code: string, message: string): ConsoleProviderVerificationFailure {
  return { ok: false, verified: false, code, message };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

type ParsedRs256Jwt = {
  readonly headerB64u: string;
  readonly payloadB64u: string;
  readonly signatureB64u: string;
  readonly payload: Record<string, unknown>;
  readonly kid: string;
};

function parseJwtSegmentJson(input: string | undefined): Record<string, unknown> | null {
  if (!input) return null;
  try {
    const decoded = base64UrlDecode(input);
    const parsed: unknown = JSON.parse(new TextDecoder().decode(decoded));
    return toRecordValue(parsed);
  } catch {
    return null;
  }
}

function parseRs256Jwt(
  token: string,
): { readonly ok: true; readonly jwt: ParsedRs256Jwt } | ConsoleProviderVerificationFailure {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return failure('invalid_body', 'id_token must be a JWT (3 segments)');
  }
  const [headerB64u = '', payloadB64u = '', signatureB64u = ''] = parts;
  const header = parseJwtSegmentJson(headerB64u);
  if (!header) return failure('invalid_body', 'Invalid id_token header encoding');
  const payload = parseJwtSegmentJson(payloadB64u);
  if (!payload) return failure('invalid_body', 'Invalid id_token payload encoding');
  const kid = toOptionalTrimmedString(header.kid);
  if (!kid) return failure('invalid_body', 'id_token header.kid is required');
  if (toOptionalTrimmedString(header.alg) !== 'RS256') {
    return failure('invalid_body', 'id_token header.alg must be RS256');
  }
  return { ok: true, jwt: { headerB64u, payloadB64u, signatureB64u, payload, kid } };
}

function parseJwtAud(input: unknown): string[] {
  if (Array.isArray(input)) {
    return input.map((item) => toOptionalTrimmedString(item)).filter((v): v is string => Boolean(v));
  }
  const value = toOptionalTrimmedString(input);
  return value ? [value] : [];
}

function parseBooleanJwtClaim(input: unknown): boolean | undefined {
  if (typeof input === 'boolean') return input;
  const value = toOptionalTrimmedString(input)?.toLowerCase();
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

function parseCacheControlMaxAgeSec(input: unknown): number | null {
  const header = toOptionalTrimmedString(input);
  if (!header) return null;
  for (const part of header.split(',')) {
    const segment = part.trim().toLowerCase();
    if (!segment.startsWith('max-age=')) continue;
    const value = Number(segment.slice('max-age='.length));
    if (Number.isFinite(value) && value > 0) return Math.floor(value);
  }
  return null;
}

function googleRs256JwkFromRaw(
  input: unknown,
): { readonly kid: string; readonly jwk: JsonWebKey } | null {
  const record = toRecordValue(input);
  if (!record) return null;
  const kid = toOptionalTrimmedString(record.kid);
  const kty = toOptionalTrimmedString(record.kty);
  const use = toOptionalTrimmedString(record.use);
  const alg = toOptionalTrimmedString(record.alg);
  const n = toOptionalTrimmedString(record.n);
  const e = toOptionalTrimmedString(record.e);
  if (!kid || kty !== 'RSA' || use !== 'sig' || alg !== 'RS256' || !n || !e) return null;
  return { kid, jwk: { kty: 'RSA', use: 'sig', alg: 'RS256', n, e } };
}

type JwksCacheEntry = {
  readonly keysByKid: Map<string, JsonWebKey>;
  readonly expiresAtMs: number;
};

class ConsoleGoogleJwksCache {
  private cache: JwksCacheEntry | null = null;
  private fetchPromise: Promise<JwksCacheEntry> | null = null;

  async getGoogleJwks(): Promise<JwksCacheEntry> {
    const nowMs = Date.now();
    if (this.cache && nowMs < this.cache.expiresAtMs) return this.cache;
    if (this.fetchPromise) return await this.fetchPromise;
    this.fetchPromise = this.fetchGoogleJwks(nowMs);
    try {
      return await this.fetchPromise;
    } finally {
      this.fetchPromise = null;
    }
  }

  private async fetchGoogleJwks(nowMs: number): Promise<JwksCacheEntry> {
    if (typeof fetch !== 'function') throw new Error('fetch is unavailable in this runtime');
    const response = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    const text = await response.text();
    if (!response.ok) {
      throw new Error(
        `Google OIDC certs fetch failed (HTTP ${response.status}): ${text.slice(0, 200)}`,
      );
    }
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      throw new Error('Google OIDC certs returned non-JSON response');
    }
    const record = toRecordValue(parsed);
    const rawKeys = record ? record.keys : null;
    const keysByKid = new Map<string, JsonWebKey>();
    for (const rawKey of Array.isArray(rawKeys) ? rawKeys : []) {
      const key = googleRs256JwkFromRaw(rawKey);
      if (key) keysByKid.set(key.kid, key.jwk);
    }
    if (keysByKid.size === 0) throw new Error('Google OIDC certs returned no usable RSA keys');
    const maxAgeSec = parseCacheControlMaxAgeSec(response.headers.get('cache-control')) || 60 * 60;
    const value = { keysByKid, expiresAtMs: nowMs + maxAgeSec * 1_000 };
    this.cache = value;
    return value;
  }
}

function validateGoogleIdTokenClaims(input: {
  readonly payload: Record<string, unknown>;
  readonly clientId: string;
}):
  | {
      readonly ok: true;
      readonly sub: string;
      readonly email?: string;
      readonly name?: string;
      readonly emailVerified?: boolean;
      readonly hostedDomain?: string;
    }
  | ConsoleProviderVerificationFailure {
  const payload = input.payload;
  const iss = toOptionalTrimmedString(payload.iss);
  if (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') {
    return failure('invalid_issuer', 'Invalid Google id_token issuer');
  }
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp <= 0) return failure('invalid_claims', 'Invalid Google id_token exp');
  if (nowSec >= exp) return failure('expired', 'Google id_token is expired');
  if (payload.nbf !== undefined) {
    const nbf = Number(payload.nbf);
    if (!Number.isFinite(nbf)) return failure('invalid_claims', 'Invalid Google id_token nbf');
    if (nowSec < nbf) return failure('not_yet_valid', 'Google id_token is not yet valid');
  }
  const aud = parseJwtAud(payload.aud);
  if (aud.length === 0) return failure('invalid_claims', 'Missing Google id_token aud');
  if (!aud.includes(input.clientId)) {
    return failure('invalid_audience', 'Google id_token audience mismatch');
  }
  const sub = toOptionalTrimmedString(payload.sub);
  if (!sub) return failure('invalid_claims', 'Missing Google id_token sub');
  const email = toOptionalTrimmedString(payload.email);
  const name = toOptionalTrimmedString(payload.name);
  const emailVerified = parseBooleanJwtClaim(payload.email_verified);
  const hostedDomain = toOptionalTrimmedString(payload.hd);
  return {
    ok: true,
    sub,
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(typeof emailVerified === 'boolean' ? { emailVerified } : {}),
    ...(hostedDomain ? { hostedDomain } : {}),
  };
}

const GITHUB_API_VERSION = '2022-11-28';

function githubHeaders(accessToken: string): HeadersInit {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': 'seams-console-auth',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
  };
}

async function parseJson(response: Response): Promise<unknown> {
  return await response.json().catch(() => null);
}

async function exchangeGithubCode(input: {
  readonly config: ConsoleGithubOAuthConfig;
  readonly code: string;
  readonly fetchImpl: typeof fetch;
}): Promise<string | null> {
  const response = await input.fetchImpl('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: input.config.clientId,
      client_secret: input.config.clientSecret,
      code: input.code,
      redirect_uri: input.config.callbackUrl,
    }),
  });
  const body = toRecordValue(await parseJson(response));
  if (!response.ok || !body) return null;
  return toOptionalTrimmedString(body.access_token) || null;
}

async function fetchGithubIdentity(input: {
  readonly accessToken: string;
  readonly fetchImpl: typeof fetch;
}): Promise<{ readonly id: string; readonly name: string; readonly email?: string } | null> {
  const [userResponse, emailsResponse] = await Promise.all([
    input.fetchImpl('https://api.github.com/user', { headers: githubHeaders(input.accessToken) }),
    input.fetchImpl('https://api.github.com/user/emails', {
      headers: githubHeaders(input.accessToken),
    }),
  ]);
  const user = toRecordValue(await parseJson(userResponse));
  if (!userResponse.ok || !user) return null;
  const id = toOptionalTrimmedString(String(user.id ?? ''));
  if (!id) return null;
  const login = toOptionalTrimmedString(user.login) || '';
  const name = toOptionalTrimmedString(user.name) || login || id;
  let email = toOptionalTrimmedString(user.email);
  if (emailsResponse.ok) {
    const emails = await parseJson(emailsResponse);
    if (Array.isArray(emails)) {
      let primaryVerified: string | undefined;
      let anyVerified: string | undefined;
      for (const entry of emails) {
        const record = toRecordValue(entry);
        if (!record) continue;
        const address = toOptionalTrimmedString(record.email);
        if (!address || record.verified !== true) continue;
        if (record.primary === true && !primaryVerified) primaryVerified = address;
        if (!anyVerified) anyVerified = address;
      }
      email = primaryVerified || anyVerified || email;
    }
  }
  return { id, name, ...(email ? { email } : {}) };
}

export function createConsoleProviderIdentity(options: {
  readonly googleOidcClientId?: string;
  readonly githubOAuth?: ConsoleGithubOAuthConfig;
  readonly fetchImpl?: typeof fetch;
}): ConsoleProviderIdentity {
  const jwksCache = new ConsoleGoogleJwksCache();
  return {
    async verifyGoogleLogin(input: { idToken: string }): Promise<ConsoleGoogleLoginResult> {
      try {
        const clientId = toOptionalTrimmedString(options.googleOidcClientId);
        if (!clientId) {
          return failure('not_configured', 'Google OIDC is not configured on this Worker');
        }
        const idToken = toOptionalTrimmedString(input.idToken);
        if (!idToken) return failure('invalid_body', 'id_token is required');
        const subtle = globalThis.crypto?.subtle;
        if (!subtle) {
          return failure('unsupported', 'WebCrypto (crypto.subtle) is unavailable in this runtime');
        }
        const parsed = parseRs256Jwt(idToken);
        if (!parsed.ok) return parsed;
        const jwks = await jwksCache.getGoogleJwks();
        const jwk = jwks.keysByKid.get(parsed.jwt.kid);
        if (!jwk) return failure('unknown_kid', 'Unknown Google key id (kid)');

        let signatureBytes: Uint8Array;
        try {
          signatureBytes = base64UrlDecode(parsed.jwt.signatureB64u);
        } catch {
          return failure('invalid_body', 'Invalid id_token signature encoding');
        }
        const dataBytes = new TextEncoder().encode(
          `${parsed.jwt.headerB64u}.${parsed.jwt.payloadB64u}`,
        );
        const key = await subtle.importKey(
          'jwk',
          jwk,
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          false,
          ['verify'],
        );
        const verified = await subtle.verify(
          { name: 'RSASSA-PKCS1-v1_5' },
          key,
          toArrayBufferCopy(signatureBytes),
          toArrayBufferCopy(dataBytes),
        );
        if (!verified) return failure('invalid_signature', 'Invalid Google id_token signature');

        const claims = validateGoogleIdTokenClaims({ payload: parsed.jwt.payload, clientId });
        if (!claims.ok) return claims;
        const providerSubject = `google:${claims.sub}`;
        return {
          ok: true,
          verified: true,
          userId: providerSubject,
          providerSubject,
          sub: claims.sub,
          ...(claims.email ? { email: claims.email } : {}),
          ...(claims.name ? { name: claims.name } : {}),
          ...(typeof claims.emailVerified === 'boolean'
            ? { emailVerified: claims.emailVerified }
            : {}),
          ...(claims.hostedDomain ? { hostedDomain: claims.hostedDomain } : {}),
        };
      } catch (error: unknown) {
        return failure('internal', errorMessage(error) || 'Google OIDC verification failed');
      }
    },

    async verifyGithubOAuthCode(input: { code: string }): Promise<ConsoleGithubLoginResult> {
      try {
        if (!options.githubOAuth) return failure('not_configured', 'GitHub OAuth is not configured');
        const code = toOptionalTrimmedString(input.code);
        if (!code) return failure('invalid_body', 'exchange.code is required');
        const fetchImpl = options.fetchImpl || fetch;
        const accessToken = await exchangeGithubCode({ config: options.githubOAuth, code, fetchImpl });
        if (!accessToken) return failure('invalid_grant', 'GitHub authorization code exchange failed');
        const identity = await fetchGithubIdentity({ accessToken, fetchImpl });
        if (!identity) return failure('invalid_identity', 'GitHub user lookup failed');
        const providerSubject = `github:${identity.id}`;
        return {
          ok: true,
          verified: true,
          userId: providerSubject,
          providerSubject,
          sub: identity.id,
          ...(identity.email ? { email: identity.email } : {}),
          name: identity.name,
        };
      } catch (error: unknown) {
        return failure('internal', errorMessage(error) || 'GitHub OAuth verification failed');
      }
    },
  };
}
