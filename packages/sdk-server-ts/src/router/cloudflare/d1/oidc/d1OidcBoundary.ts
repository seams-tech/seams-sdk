import { base64UrlDecode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  toArrayBufferCopy,
  toRecordValue,
} from './d1RouterApiAuthBoundary';

export type CloudflareD1OidcExchangeIssuerConfig = {
  readonly issuer: string;
  readonly audiences: readonly string[];
  readonly jwksUrl: string;
  readonly subjectPrefix?: string;
};

export type CloudflareD1OidcExchangeConfig = {
  readonly issuers: readonly CloudflareD1OidcExchangeIssuerConfig[];
  readonly clockSkewSec?: number | string;
};

export type NormalizedCloudflareD1OidcExchangeConfig = {
  readonly issuers: readonly CloudflareD1OidcExchangeIssuerConfig[];
  readonly clockSkewSec: number;
};

export type JsonWebKeyCache = {
  readonly keysByKid: Map<string, JsonWebKey>;
  readonly expiresAtMs: number;
};

export type JwtVerificationFailure = {
  readonly ok: false;
  readonly verified: false;
  readonly code: string;
  readonly message: string;
};

export type ParsedRs256Jwt = {
  readonly headerB64u: string;
  readonly payloadB64u: string;
  readonly signatureB64u: string;
  readonly payload: Record<string, unknown>;
  readonly kid: string;
};

export type ParsedRs256JwtResult =
  | { readonly ok: true; readonly jwt: ParsedRs256Jwt }
  | JwtVerificationFailure;

export type GoogleIdTokenClaims = {
  readonly ok: true;
  readonly sub: string;
  readonly email?: string;
  readonly name?: string;
  readonly givenName?: string;
  readonly familyName?: string;
  readonly emailVerified?: boolean;
  readonly hostedDomain?: string;
};

export type GoogleIdTokenClaimValidationResult = GoogleIdTokenClaims | JwtVerificationFailure;

export type OidcJwtExchangeUnverifiedClaims = {
  readonly ok: true;
  readonly issuerConfig: CloudflareD1OidcExchangeIssuerConfig;
  readonly iss: string;
  readonly aud: string[];
  readonly sub: string;
  readonly providerSubject: string;
  readonly email?: string;
  readonly name?: string;
  readonly givenName?: string;
  readonly familyName?: string;
};

export type OidcJwtExchangeUnverifiedClaimResult =
  | OidcJwtExchangeUnverifiedClaims
  | JwtVerificationFailure;

export type OidcJwtExchangeTemporalClaimValidationResult =
  | { readonly ok: true }
  | JwtVerificationFailure;

export function normalizedOidcIssuer(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) return '';
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

export function normalizeOidcExchangeConfig(input: {
  readonly oidcExchange?: CloudflareD1OidcExchangeConfig;
}): NormalizedCloudflareD1OidcExchangeConfig | undefined {
  const raw = input.oidcExchange;
  if (!raw || !Array.isArray(raw.issuers)) return undefined;
  const issuers: CloudflareD1OidcExchangeIssuerConfig[] = [];
  for (const issuer of raw.issuers) {
    const normalized = normalizeOidcExchangeIssuerConfig(issuer);
    if (normalized) issuers.push(normalized);
  }
  if (issuers.length === 0) return undefined;
  return {
    issuers,
    clockSkewSec: normalizeOidcExchangeClockSkewSec(raw.clockSkewSec),
  };
}

export function oidcIssuerConfigForTokenIssuer(input: {
  readonly issuers: readonly CloudflareD1OidcExchangeIssuerConfig[];
  readonly issuer: string;
}): CloudflareD1OidcExchangeIssuerConfig | null {
  for (const candidate of input.issuers) {
    if (normalizedOidcIssuer(candidate.issuer) === input.issuer) return candidate;
  }
  return null;
}

export function parseJwtAud(input: unknown): string[] {
  const values: string[] = [];
  if (Array.isArray(input)) {
    for (const item of input) {
      const value = toOptionalTrimmedString(item);
      if (value) values.push(value);
    }
    return values;
  }
  const value = toOptionalTrimmedString(input);
  return value ? [value] : [];
}

export function parseCacheControlMaxAgeSec(input: unknown): number | null {
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

export function parseGoogleJwks(input: unknown): Map<string, JsonWebKey> | null {
  const record = toRecordValue(input);
  if (!record) return null;
  const rawKeys = record.keys;
  if (!Array.isArray(rawKeys)) return null;
  const keysByKid = new Map<string, JsonWebKey>();
  for (const rawKey of rawKeys) {
    const key = googleRs256JwkFromRaw(rawKey);
    if (key) keysByKid.set(key.kid, key.jwk);
  }
  return keysByKid.size > 0 ? keysByKid : null;
}

export function parseOidcJwks(input: unknown): Map<string, JsonWebKey> | null {
  const record = toRecordValue(input);
  if (!record) return null;
  const rawKeys = record.keys;
  if (!Array.isArray(rawKeys)) return null;
  const keysByKid = new Map<string, JsonWebKey>();
  for (const rawKey of rawKeys) {
    const key = oidcRs256JwkFromRaw(rawKey);
    if (key) keysByKid.set(key.kid, key.jwk);
  }
  return keysByKid.size > 0 ? keysByKid : null;
}

export class CloudflareD1OidcJwksCache {
  private googleJwksCache: JsonWebKeyCache | null = null;
  private googleJwksFetchPromise: Promise<JsonWebKeyCache> | null = null;
  private readonly oidcJwksCacheByUrl = new Map<string, JsonWebKeyCache>();
  private readonly oidcJwksFetchPromiseByUrl = new Map<string, Promise<JsonWebKeyCache>>();

  async getGoogleJwks(): Promise<JsonWebKeyCache> {
    const nowMs = Date.now();
    if (this.googleJwksCache && nowMs < this.googleJwksCache.expiresAtMs) {
      return this.googleJwksCache;
    }
    if (this.googleJwksFetchPromise) return await this.googleJwksFetchPromise;
    this.googleJwksFetchPromise = this.fetchGoogleJwks(nowMs);
    try {
      return await this.googleJwksFetchPromise;
    } finally {
      this.googleJwksFetchPromise = null;
    }
  }

  async getOidcJwksByUrl(jwksUrl: string): Promise<JsonWebKeyCache> {
    const url = toOptionalTrimmedString(jwksUrl);
    if (!url) throw new Error('Missing OIDC JWKS URL');
    const nowMs = Date.now();
    const cached = this.oidcJwksCacheByUrl.get(url);
    if (cached && nowMs < cached.expiresAtMs) return cached;
    const inflight = this.oidcJwksFetchPromiseByUrl.get(url);
    if (inflight) return await inflight;
    const promise = this.fetchOidcJwks(url, nowMs);
    this.oidcJwksFetchPromiseByUrl.set(url, promise);
    try {
      return await promise;
    } finally {
      this.oidcJwksFetchPromiseByUrl.delete(url);
    }
  }

  private async fetchGoogleJwks(nowMs: number): Promise<JsonWebKeyCache> {
    if (typeof fetch !== 'function') {
      throw new Error('fetch is unavailable in this runtime');
    }
    const response = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    const text = await response.text();
    if (!response.ok) {
      throw new Error(
        `Google OIDC certs fetch failed (HTTP ${response.status}): ${text.slice(0, 200)}`,
      );
    }
    const parsed = parseJwksResponseText({
      text,
      nonJsonMessage: 'Google OIDC certs returned non-JSON response',
    });
    const keysByKid = parseGoogleJwks(parsed);
    if (!keysByKid) throw new Error('Google OIDC certs returned no usable RSA keys');
    const maxAgeSec = parseCacheControlMaxAgeSec(response.headers.get('cache-control')) || 60 * 60;
    const value = { keysByKid, expiresAtMs: nowMs + maxAgeSec * 1_000 };
    this.googleJwksCache = value;
    return value;
  }

  private async fetchOidcJwks(url: string, nowMs: number): Promise<JsonWebKeyCache> {
    if (typeof fetch !== 'function') {
      throw new Error('fetch is unavailable in this runtime');
    }
    const response = await fetch(url);
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`OIDC JWKS fetch failed (HTTP ${response.status}): ${text.slice(0, 200)}`);
    }
    const parsed = parseJwksResponseText({
      text,
      nonJsonMessage: 'OIDC JWKS returned non-JSON response',
    });
    const keysByKid = parseOidcJwks(parsed);
    if (!keysByKid) throw new Error('OIDC JWKS returned no usable RSA keys');
    const maxAgeSec = parseCacheControlMaxAgeSec(response.headers.get('cache-control')) || 60 * 60;
    const value = { keysByKid, expiresAtMs: nowMs + maxAgeSec * 1_000 };
    this.oidcJwksCacheByUrl.set(url, value);
    return value;
  }
}

export function parseRs256JwtForVerification(input: {
  readonly token: string;
  readonly tokenLabel: string;
}): ParsedRs256JwtResult {
  const parts = input.token.split('.');
  if (parts.length !== 3) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `${input.tokenLabel} must be a JWT (3 segments)`,
    };
  }
  const headerB64u = parts[0] || '';
  const payloadB64u = parts[1] || '';
  const signatureB64u = parts[2] || '';
  const header = parseJwtSegmentJson(headerB64u);
  if (!header) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `Invalid ${input.tokenLabel} header encoding`,
    };
  }
  const payload = parseJwtSegmentJson(payloadB64u);
  if (!payload) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `Invalid ${input.tokenLabel} payload encoding`,
    };
  }

  const kid = toOptionalTrimmedString(header.kid);
  const alg = toOptionalTrimmedString(header.alg);
  if (!kid) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `${input.tokenLabel} header.kid is required`,
    };
  }
  if (alg !== 'RS256') {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `${input.tokenLabel} header.alg must be RS256`,
    };
  }

  return {
    ok: true,
    jwt: {
      headerB64u,
      payloadB64u,
      signatureB64u,
      payload,
      kid,
    },
  };
}

export async function verifyRs256JwtSignature(input: {
  readonly subtle: SubtleCrypto;
  readonly jwt: ParsedRs256Jwt;
  readonly jwk: JsonWebKey;
  readonly tokenLabel: string;
  readonly invalidSignatureMessage: string;
}): Promise<{ readonly ok: true } | JwtVerificationFailure> {
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(input.jwt.signatureB64u);
  } catch {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `Invalid ${input.tokenLabel} signature encoding`,
    };
  }
  const dataBytes = new TextEncoder().encode(`${input.jwt.headerB64u}.${input.jwt.payloadB64u}`);
  const key = await input.subtle.importKey(
    'jwk',
    input.jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const verified = await input.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    toArrayBufferCopy(signatureBytes),
    toArrayBufferCopy(dataBytes),
  );
  if (!verified) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_signature',
      message: input.invalidSignatureMessage,
    };
  }
  return { ok: true };
}

export function parseBooleanJwtClaim(input: unknown): boolean | undefined {
  if (typeof input === 'boolean') return input;
  const value = toOptionalTrimmedString(input)?.toLowerCase();
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

export function parseOidcJwtExchangeUnverifiedClaims(input: {
  readonly payload: Record<string, unknown>;
  readonly oidcExchange: NormalizedCloudflareD1OidcExchangeConfig;
}): OidcJwtExchangeUnverifiedClaimResult {
  const payload = input.payload;
  const iss = normalizedOidcIssuer(payload.iss);
  if (!iss) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_claims',
      message: 'Missing exchange.token iss',
    };
  }
  const issuerConfig = oidcIssuerConfigForTokenIssuer({
    issuers: input.oidcExchange.issuers,
    issuer: iss,
  });
  if (!issuerConfig) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_issuer',
      message: 'exchange.token issuer is not allowed',
    };
  }

  const aud = parseJwtAud(payload.aud);
  if (aud.length === 0) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_claims',
      message: 'Missing exchange.token aud',
    };
  }
  if (
    !oidcJwtExchangeAudienceAllowed({
      tokenAudiences: aud,
      allowedAudiences: issuerConfig.audiences,
    })
  ) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_audience',
      message: 'exchange.token audience mismatch',
    };
  }

  const sub = toOptionalTrimmedString(payload.sub);
  if (!sub) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_claims',
      message: 'Missing exchange.token sub',
    };
  }

  const providerSubject = `${issuerConfig.subjectPrefix || `oidc:${iss}:`}${sub}`;
  const email = toOptionalTrimmedString(payload.email);
  const name = toOptionalTrimmedString(payload.name);
  const givenName = toOptionalTrimmedString(payload.given_name);
  const familyName = toOptionalTrimmedString(payload.family_name);
  return {
    ok: true,
    issuerConfig,
    iss,
    aud,
    sub,
    providerSubject,
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(givenName ? { givenName } : {}),
    ...(familyName ? { familyName } : {}),
  };
}

export function validateOidcJwtExchangeTemporalClaims(input: {
  readonly payload: Record<string, unknown>;
  readonly clockSkewSec: number;
}): OidcJwtExchangeTemporalClaimValidationResult {
  const payload = input.payload;
  const nowSec = Math.floor(Date.now() / 1_000);
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp <= 0) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_claims',
      message: 'Invalid exchange.token exp',
    };
  }
  if (nowSec > exp + input.clockSkewSec) {
    return {
      ok: false,
      verified: false,
      code: 'expired',
      message: 'exchange.token is expired',
    };
  }
  if (payload.nbf !== undefined) {
    const nbf = Number(payload.nbf);
    if (!Number.isFinite(nbf)) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Invalid exchange.token nbf',
      };
    }
    if (nowSec + input.clockSkewSec < nbf) {
      return {
        ok: false,
        verified: false,
        code: 'not_yet_valid',
        message: 'exchange.token is not yet valid',
      };
    }
  }
  if (payload.iat !== undefined) {
    const iat = Number(payload.iat);
    if (!Number.isFinite(iat)) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Invalid exchange.token iat',
      };
    }
    if (iat > nowSec + input.clockSkewSec) {
      return {
        ok: false,
        verified: false,
        code: 'not_yet_valid',
        message: 'exchange.token issued-at is in the future',
      };
    }
  }
  return { ok: true };
}

export function validateGoogleIdTokenClaims(input: {
  readonly payload: Record<string, unknown>;
  readonly clientId: string;
}): GoogleIdTokenClaimValidationResult {
  const payload = input.payload;
  const iss = toOptionalTrimmedString(payload.iss);
  if (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') {
    return {
      ok: false,
      verified: false,
      code: 'invalid_issuer',
      message: 'Invalid Google id_token issuer',
    };
  }
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp <= 0) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_claims',
      message: 'Invalid Google id_token exp',
    };
  }
  if (nowSec >= exp) {
    return {
      ok: false,
      verified: false,
      code: 'expired',
      message: 'Google id_token is expired',
    };
  }
  if (payload.nbf !== undefined) {
    const nbf = Number(payload.nbf);
    if (!Number.isFinite(nbf)) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Invalid Google id_token nbf',
      };
    }
    if (nowSec < nbf) {
      return {
        ok: false,
        verified: false,
        code: 'not_yet_valid',
        message: 'Google id_token is not yet valid',
      };
    }
  }

  const aud = parseJwtAud(payload.aud);
  if (aud.length === 0) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_claims',
      message: 'Missing Google id_token aud',
    };
  }
  if (!aud.includes(input.clientId)) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_audience',
      message: 'Google id_token audience mismatch',
    };
  }

  const sub = toOptionalTrimmedString(payload.sub);
  if (!sub) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_claims',
      message: 'Missing Google id_token sub',
    };
  }
  const email = toOptionalTrimmedString(payload.email);
  const name = toOptionalTrimmedString(payload.name);
  const givenName = toOptionalTrimmedString(payload.given_name);
  const familyName = toOptionalTrimmedString(payload.family_name);
  const emailVerified = parseBooleanJwtClaim(payload.email_verified);
  const hostedDomain = toOptionalTrimmedString(payload.hd);
  return {
    ok: true,
    sub,
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(givenName ? { givenName } : {}),
    ...(familyName ? { familyName } : {}),
    ...(typeof emailVerified === 'boolean' ? { emailVerified } : {}),
    ...(hostedDomain ? { hostedDomain } : {}),
  };
}

function oidcJwtExchangeAudienceAllowed(input: {
  readonly tokenAudiences: readonly string[];
  readonly allowedAudiences: readonly string[];
}): boolean {
  for (const audience of input.tokenAudiences) {
    if (input.allowedAudiences.includes(audience)) return true;
  }
  return false;
}

function parseJwksResponseText(input: {
  readonly text: string;
  readonly nonJsonMessage: string;
}): unknown {
  try {
    return input.text ? JSON.parse(input.text) : null;
  } catch {
    throw new Error(input.nonJsonMessage);
  }
}

function normalizeOidcExchangeIssuerConfig(
  input: unknown,
): CloudflareD1OidcExchangeIssuerConfig | null {
  const record = toRecordValue(input);
  if (!record) return null;
  const issuer = normalizedOidcIssuer(record.issuer);
  const jwksUrl = toOptionalTrimmedString(record.jwksUrl);
  const audiences = normalizeOidcExchangeAudiences(record.audiences);
  const subjectPrefix = toOptionalTrimmedString(record.subjectPrefix);
  if (!issuer || !jwksUrl || audiences.length === 0) return null;
  return {
    issuer,
    jwksUrl,
    audiences,
    ...(subjectPrefix ? { subjectPrefix } : {}),
  };
}

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

function normalizeOidcExchangeAudiences(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  const audiences: string[] = [];
  for (const item of input) {
    const value = toOptionalTrimmedString(item);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    audiences.push(value);
  }
  return audiences;
}

function normalizeOidcExchangeClockSkewSec(input: unknown): number {
  if (input == null || input === '') return 60;
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value)) return 60;
  return Math.max(0, Math.floor(value));
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
  return {
    kid,
    jwk: {
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      n,
      e,
    },
  };
}

function oidcRs256JwkFromRaw(
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
  if (!kid || kty !== 'RSA' || !n || !e) return null;
  if (use && use !== 'sig') return null;
  if (alg && alg !== 'RS256') return null;
  return {
    kid,
    jwk: {
      kty: 'RSA',
      ...(use ? { use } : {}),
      alg: 'RS256',
      n,
      e,
    },
  };
}
