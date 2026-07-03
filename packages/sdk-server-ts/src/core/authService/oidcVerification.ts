import { base64UrlDecode } from '@shared/utils/encoders';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { GoogleOidcConfig, OidcExchangeConfig, OidcExchangeIssuerConfig } from '../types';
import type { IdentityStore } from '../IdentityStore';
import { toArrayBufferCopy } from './portableCrypto';
import {
  normalizeOidcIssuer,
  parseCacheControlMaxAgeSec,
  parseJwtAud,
  parseJwtSegmentJson,
} from './webauthnOidcHelpers';
import { isObject } from './record';

export type JwksCacheValue = {
  keysByKid: Map<string, JsonWebKey>;
  expiresAtMs: number;
};

export type GoogleJwksState = {
  cache: JwksCacheValue | null;
  fetchPromise: Promise<JwksCacheValue> | null;
};

export type OidcJwksState = {
  cacheByUrl: Map<string, JwksCacheValue>;
  fetchPromiseByUrl: Map<string, Promise<JwksCacheValue>>;
};

export type OidcJwtExchangeVerificationResult =
  | {
      ok: true;
      verified: true;
      providerSubject: string;
      iss: string;
      aud: string[];
      sub: string;
      email?: string;
      name?: string;
      given_name?: string;
      family_name?: string;
    }
  | {
      ok: false;
      verified: false;
      code: string;
      message: string;
    };

export type GoogleLoginVerificationResult =
  | {
      ok: true;
      verified: true;
      providerSubject: string;
      sub: string;
      email?: string;
      name?: string;
      given_name?: string;
      family_name?: string;
      emailVerified?: boolean;
      hostedDomain?: string;
    }
  | {
      ok: false;
      verified: false;
      code: string;
      message: string;
    };

export type OidcJwtExchangeFacadeResult =
  | {
      ok: true;
      verified: true;
      userId: string;
      providerSubject: string;
      iss: string;
      aud: string[];
      sub: string;
      email?: string;
      name?: string;
      given_name?: string;
      family_name?: string;
    }
  | {
      ok: false;
      verified: false;
      code: string;
      message: string;
    };

export type GoogleLoginFacadeResult =
  | {
      ok: true;
      verified: true;
      userId: string;
      providerSubject: string;
      sub: string;
      email?: string;
      name?: string;
      given_name?: string;
      family_name?: string;
      emailVerified?: boolean;
      hostedDomain?: string;
    }
  | {
      ok: false;
      verified: false;
      code: string;
      message: string;
    };

type OidcJwtExchangeVerificationSuccess = Extract<
  OidcJwtExchangeVerificationResult,
  { ok: true }
>;

type GoogleLoginVerificationSuccess = Extract<GoogleLoginVerificationResult, { ok: true }>;

type OidcJwtExchangeFacadeSuccess = Extract<OidcJwtExchangeFacadeResult, { ok: true }>;

type GoogleLoginFacadeSuccess = Extract<GoogleLoginFacadeResult, { ok: true }>;

type JwtParts = {
  headerB64u: string;
  payloadB64u: string;
  signatureB64u: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
};

export function createGoogleJwksState(): GoogleJwksState {
  return { cache: null, fetchPromise: null };
}

export function createOidcJwksState(): OidcJwksState {
  return { cacheByUrl: new Map(), fetchPromiseByUrl: new Map() };
}

function jwtError(code: string, message: string): {
  ok: false;
  verified: false;
  code: string;
  message: string;
} {
  return { ok: false, verified: false, code, message };
}

function requireWebCrypto(): boolean {
  return typeof crypto !== 'undefined' && Boolean(crypto.subtle);
}

function parseJwtParts(input: {
  token: string;
  tokenName: string;
}):
  | { ok: true; value: JwtParts }
  | { ok: false; verified: false; code: string; message: string } {
  const parts = input.token.split('.');
  if (parts.length !== 3) {
    return jwtError('invalid_body', `${input.tokenName} must be a JWT (3 segments)`);
  }
  const [headerB64u, payloadB64u, signatureB64u] = parts;
  const header = parseJwtSegmentJson(headerB64u);
  if (!header) {
    return jwtError('invalid_body', `Invalid ${input.tokenName} header encoding`);
  }
  const payload = parseJwtSegmentJson(payloadB64u);
  if (!payload) {
    return jwtError('invalid_body', `Invalid ${input.tokenName} payload encoding`);
  }
  return { ok: true, value: { headerB64u, payloadB64u, signatureB64u, header, payload } };
}

function jwkFromRaw(rawKey: unknown, mode: 'google' | 'generic'): { kid: string; jwk: JsonWebKey } | null {
  if (!isObject(rawKey)) return null;
  const kid = toOptionalTrimmedString(rawKey.kid);
  const kty = toOptionalTrimmedString(rawKey.kty);
  const use = toOptionalTrimmedString(rawKey.use);
  const alg = toOptionalTrimmedString(rawKey.alg);
  const n = toOptionalTrimmedString(rawKey.n);
  const e = toOptionalTrimmedString(rawKey.e);
  if (!kid || kty !== 'RSA' || !n || !e) return null;
  if (mode === 'google' && (use !== 'sig' || alg !== 'RS256')) return null;
  if (mode === 'generic' && use && use !== 'sig') return null;
  if (mode === 'generic' && alg && alg !== 'RS256') return null;
  return { kid, jwk: rawKey as unknown as JsonWebKey };
}

async function fetchJwks(input: {
  url: string;
  mode: 'google' | 'generic';
  failureLabel: string;
  missingKeysLabel: string;
  invalidJsonLabel: string;
  invalidShapeLabel: string;
  noUsableKeysLabel: string;
}): Promise<JwksCacheValue> {
  const now = Date.now();
  const resp = await fetch(input.url);
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`${input.failureLabel} (HTTP ${resp.status}): ${text.slice(0, 200)}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(input.invalidJsonLabel);
  }
  if (!isObject(json)) {
    throw new Error(input.invalidShapeLabel);
  }
  const keysRaw = json.keys;
  if (!Array.isArray(keysRaw)) {
    throw new Error(input.missingKeysLabel);
  }
  const keysByKid = new Map<string, JsonWebKey>();
  for (const rawKey of keysRaw) {
    const key = jwkFromRaw(rawKey, input.mode);
    if (key) keysByKid.set(key.kid, key.jwk);
  }
  if (!keysByKid.size) {
    throw new Error(input.noUsableKeysLabel);
  }

  const maxAgeSec = parseCacheControlMaxAgeSec(resp.headers.get('cache-control')) || 60 * 60;
  return { keysByKid, expiresAtMs: now + maxAgeSec * 1000 };
}

export async function getGoogleJwks(state: GoogleJwksState): Promise<JwksCacheValue> {
  const now = Date.now();
  if (state.cache && now < state.cache.expiresAtMs) return state.cache;
  if (state.fetchPromise) return state.fetchPromise;

  state.fetchPromise = fetchJwks({
    url: 'https://www.googleapis.com/oauth2/v3/certs',
    mode: 'google',
    failureLabel: 'Google OIDC certs fetch failed',
    missingKeysLabel: 'Google OIDC certs missing "keys" array',
    invalidJsonLabel: 'Google OIDC certs returned non-JSON response',
    invalidShapeLabel: 'Google OIDC certs returned invalid JSON shape',
    noUsableKeysLabel: 'Google OIDC certs returned no usable RSA keys',
  });
  try {
    state.cache = await state.fetchPromise;
    return state.cache;
  } finally {
    state.fetchPromise = null;
  }
}

export async function getOidcJwksByUrl(input: {
  state: OidcJwksState;
  jwksUrl: string;
}): Promise<JwksCacheValue> {
  const url = String(input.jwksUrl || '').trim();
  if (!url) throw new Error('Missing OIDC JWKS URL');

  const now = Date.now();
  const cached = input.state.cacheByUrl.get(url) || null;
  if (cached && now < cached.expiresAtMs) return cached;

  const inflight = input.state.fetchPromiseByUrl.get(url) || null;
  if (inflight) return inflight;

  const fetchPromise = fetchJwks({
    url,
    mode: 'generic',
    failureLabel: 'OIDC JWKS fetch failed',
    missingKeysLabel: 'OIDC JWKS missing "keys" array',
    invalidJsonLabel: 'OIDC JWKS returned non-JSON response',
    invalidShapeLabel: 'OIDC JWKS returned invalid JSON shape',
    noUsableKeysLabel: 'OIDC JWKS returned no usable RSA keys',
  });
  input.state.fetchPromiseByUrl.set(url, fetchPromise);
  try {
    const value = await fetchPromise;
    input.state.cacheByUrl.set(url, value);
    return value;
  } finally {
    input.state.fetchPromiseByUrl.delete(url);
  }
}

async function verifyJwtSignature(input: {
  jwk: JsonWebKey;
  parts: JwtParts;
  tokenName: string;
}): Promise<{ ok: true } | { ok: false; verified: false; code: string; message: string }> {
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(input.parts.signatureB64u);
  } catch {
    return jwtError('invalid_body', `Invalid ${input.tokenName} signature encoding`);
  }

  const dataBytes = new TextEncoder().encode(`${input.parts.headerB64u}.${input.parts.payloadB64u}`);
  const key = await crypto.subtle.importKey(
    'jwk',
    input.jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const verified = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    toArrayBufferCopy(signatureBytes),
    toArrayBufferCopy(dataBytes),
  );
  if (!verified) {
    return jwtError('invalid_signature', `Invalid ${input.tokenName} signature`);
  }
  return { ok: true };
}

function findOidcIssuerConfig(
  issuers: readonly OidcExchangeIssuerConfig[],
  iss: string,
): OidcExchangeIssuerConfig | null {
  for (const candidate of issuers) {
    if (normalizeOidcIssuer(candidate.issuer) === iss) return candidate;
  }
  return null;
}

function clockSkewSeconds(config: OidcExchangeConfig): number {
  const clockSkewInput = Number(config.clockSkewSec);
  return Number.isFinite(clockSkewInput) ? Math.max(0, Math.floor(clockSkewInput)) : 60;
}

function verifyTimeClaims(input: {
  payload: Record<string, unknown>;
  tokenName: string;
  clockSkewSec: number;
}): { ok: true } | { ok: false; verified: false; code: string; message: string } {
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = Number(input.payload.exp);
  if (!Number.isFinite(exp) || exp <= 0) {
    return jwtError('invalid_claims', `Invalid ${input.tokenName} exp`);
  }
  if (nowSec > exp + input.clockSkewSec) {
    return jwtError('expired', `${input.tokenName} is expired`);
  }
  const nbfRaw = input.payload.nbf;
  if (nbfRaw !== undefined) {
    const nbf = Number(nbfRaw);
    if (!Number.isFinite(nbf)) return jwtError('invalid_claims', `Invalid ${input.tokenName} nbf`);
    if (nowSec + input.clockSkewSec < nbf) {
      return jwtError('not_yet_valid', `${input.tokenName} is not yet valid`);
    }
  }
  const iatRaw = input.payload.iat;
  if (iatRaw !== undefined) {
    const iat = Number(iatRaw);
    if (!Number.isFinite(iat)) return jwtError('invalid_claims', `Invalid ${input.tokenName} iat`);
    if (iat > nowSec + input.clockSkewSec) {
      return jwtError('not_yet_valid', `${input.tokenName} issued-at is in the future`);
    }
  }
  return { ok: true };
}

function verifyGoogleTimeClaims(
  payload: Record<string, unknown>,
): { ok: true } | { ok: false; verified: false; code: string; message: string } {
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp <= 0) {
    return jwtError('invalid_claims', 'Invalid Google id_token exp');
  }
  if (nowSec >= exp) return jwtError('expired', 'Google id_token is expired');
  const nbfRaw = payload.nbf;
  if (nbfRaw !== undefined) {
    const nbf = Number(nbfRaw);
    if (!Number.isFinite(nbf)) return jwtError('invalid_claims', 'Invalid Google id_token nbf');
    if (nowSec < nbf) return jwtError('not_yet_valid', 'Google id_token is not yet valid');
  }
  return { ok: true };
}

function buildOidcJwtExchangeVerificationSuccess(input: {
  providerSubject: string;
  iss: string;
  aud: string[];
  sub: string;
  email: string;
  name: string;
  givenName: string;
  familyName: string;
}): OidcJwtExchangeVerificationSuccess {
  const result: OidcJwtExchangeVerificationSuccess = {
    ok: true,
    verified: true,
    providerSubject: input.providerSubject,
    iss: input.iss,
    aud: input.aud,
    sub: input.sub,
  };
  if (input.email) result.email = input.email;
  if (input.name) result.name = input.name;
  if (input.givenName) result.given_name = input.givenName;
  if (input.familyName) result.family_name = input.familyName;
  return result;
}

function parseGoogleEmailVerified(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.trim().toLowerCase() === 'true';
  return null;
}

function buildGoogleLoginVerificationSuccess(input: {
  providerSubject: string;
  sub: string;
  email: string;
  name: string;
  givenName: string;
  familyName: string;
  emailVerified: boolean | null;
  hostedDomain: string;
}): GoogleLoginVerificationSuccess {
  const result: GoogleLoginVerificationSuccess = {
    ok: true,
    verified: true,
    providerSubject: input.providerSubject,
    sub: input.sub,
  };
  if (input.email) result.email = input.email;
  if (input.name) result.name = input.name;
  if (input.givenName) result.given_name = input.givenName;
  if (input.familyName) result.family_name = input.familyName;
  if (input.emailVerified !== null) result.emailVerified = input.emailVerified;
  if (input.hostedDomain) result.hostedDomain = input.hostedDomain;
  return result;
}

async function resolveLinkedProviderUserId(input: {
  identityStore: IdentityStore;
  providerSubject: string;
}): Promise<string> {
  let userId = input.providerSubject;
  try {
    const linked = await input.identityStore.getUserIdBySubject(input.providerSubject);
    if (linked) userId = linked;
    await input.identityStore.linkSubjectToUserId({
      userId,
      subject: input.providerSubject,
      allowMoveIfSoleIdentity: false,
    });
  } catch {}
  return userId;
}

function buildOidcJwtExchangeFacadeSuccess(input: {
  verified: OidcJwtExchangeVerificationSuccess;
  userId: string;
}): OidcJwtExchangeFacadeSuccess {
  const result: OidcJwtExchangeFacadeSuccess = {
    ok: true,
    verified: true,
    userId: input.userId,
    providerSubject: input.verified.providerSubject,
    iss: input.verified.iss,
    aud: input.verified.aud,
    sub: input.verified.sub,
  };
  if (input.verified.email) result.email = input.verified.email;
  if (input.verified.name) result.name = input.verified.name;
  if (input.verified.given_name) result.given_name = input.verified.given_name;
  if (input.verified.family_name) result.family_name = input.verified.family_name;
  return result;
}

function buildGoogleLoginFacadeSuccess(input: {
  verified: GoogleLoginVerificationSuccess;
  userId: string;
}): GoogleLoginFacadeSuccess {
  const result: GoogleLoginFacadeSuccess = {
    ok: true,
    verified: true,
    userId: input.userId,
    providerSubject: input.verified.providerSubject,
    sub: input.verified.sub,
  };
  if (input.verified.email) result.email = input.verified.email;
  if (input.verified.name) result.name = input.verified.name;
  if (input.verified.given_name) result.given_name = input.verified.given_name;
  if (input.verified.family_name) result.family_name = input.verified.family_name;
  if (typeof input.verified.emailVerified === 'boolean') {
    result.emailVerified = input.verified.emailVerified;
  }
  if (input.verified.hostedDomain) result.hostedDomain = input.verified.hostedDomain;
  return result;
}

export async function verifyOidcJwtExchangeToken(input: {
  request: { token?: unknown };
  config?: OidcExchangeConfig;
  jwksState: OidcJwksState;
}): Promise<OidcJwtExchangeVerificationResult> {
  const config = input.config || null;
  const issuers = Array.isArray(config?.issuers) ? config.issuers : [];
  if (!config || !issuers.length) {
    return jwtError('not_configured', 'OIDC exchange is not configured on this server');
  }
  const token = toOptionalTrimmedString(input.request.token);
  if (!token) return jwtError('invalid_body', 'exchange.token is required');
  if (!requireWebCrypto()) {
    return jwtError('unsupported', 'WebCrypto (crypto.subtle) is unavailable in this runtime');
  }

  const parts = parseJwtParts({ token, tokenName: 'exchange.token' });
  if (!parts.ok) return parts;
  const kid = toOptionalTrimmedString(parts.value.header.kid);
  const alg = toOptionalTrimmedString(parts.value.header.alg);
  if (!kid) return jwtError('invalid_body', 'exchange.token header.kid is required');
  if (alg !== 'RS256') {
    return jwtError('invalid_body', 'exchange.token header.alg must be RS256');
  }

  const iss = normalizeOidcIssuer(toOptionalTrimmedString(parts.value.payload.iss) || '');
  if (!iss) return jwtError('invalid_claims', 'Missing exchange.token iss');
  const issuerConfig = findOidcIssuerConfig(issuers, iss);
  if (!issuerConfig) {
    return jwtError('invalid_issuer', 'exchange.token issuer is not allowed');
  }

  const aud = parseJwtAud(parts.value.payload.aud);
  if (!aud.length) return jwtError('invalid_claims', 'Missing exchange.token aud');
  const allowedAud = new Set(issuerConfig.audiences || []);
  if (!aud.some((value) => allowedAud.has(value))) {
    return jwtError('invalid_audience', 'exchange.token audience mismatch');
  }

  const sub = toOptionalTrimmedString(parts.value.payload.sub);
  if (!sub) return jwtError('invalid_claims', 'Missing exchange.token sub');

  const jwks = await getOidcJwksByUrl({ state: input.jwksState, jwksUrl: issuerConfig.jwksUrl });
  const jwk = jwks.keysByKid.get(kid);
  if (!jwk) return jwtError('unknown_kid', 'Unknown OIDC key id (kid)');
  const signature = await verifyJwtSignature({
    jwk,
    parts: parts.value,
    tokenName: 'exchange.token',
  });
  if (!signature.ok) return signature;

  const time = verifyTimeClaims({
    payload: parts.value.payload,
    tokenName: 'exchange.token',
    clockSkewSec: clockSkewSeconds(config),
  });
  if (!time.ok) return time;

  const subjectPrefix = toOptionalTrimmedString(issuerConfig.subjectPrefix) || `oidc:${iss}:`;
  const providerSubject = `${subjectPrefix}${sub}`;
  const email = toOptionalTrimmedString(parts.value.payload.email);
  const name = toOptionalTrimmedString(parts.value.payload.name);
  const givenName = toOptionalTrimmedString(parts.value.payload.given_name);
  const familyName = toOptionalTrimmedString(parts.value.payload.family_name);
  return buildOidcJwtExchangeVerificationSuccess({
    providerSubject,
    iss,
    aud,
    sub,
    email,
    name,
    givenName,
    familyName,
  });
}

export async function verifyOidcJwtExchangeWithIdentityStore(input: {
  request: { token?: unknown };
  config?: OidcExchangeConfig;
  jwksState: OidcJwksState;
  identityStore: IdentityStore;
}): Promise<OidcJwtExchangeFacadeResult> {
  try {
    const verified = await verifyOidcJwtExchangeToken({
      request: input.request,
      config: input.config,
      jwksState: input.jwksState,
    });
    if (!verified.ok) return verified;
    const userId = await resolveLinkedProviderUserId({
      identityStore: input.identityStore,
      providerSubject: verified.providerSubject,
    });
    return buildOidcJwtExchangeFacadeSuccess({ verified, userId });
  } catch (e: unknown) {
    return {
      ok: false,
      verified: false,
      code: 'internal',
      message: errorMessage(e) || 'OIDC exchange verification failed',
    };
  }
}

export async function verifyGoogleIdToken(input: {
  request: { idToken?: unknown; id_token?: unknown };
  config?: GoogleOidcConfig;
  jwksState: GoogleJwksState;
}): Promise<GoogleLoginVerificationResult> {
  if (!input.config?.clientIds?.length) {
    return jwtError('not_configured', 'Google OIDC is not configured on this server');
  }
  const idToken = toOptionalTrimmedString(input.request.idToken ?? input.request.id_token);
  if (!idToken) return jwtError('invalid_body', 'id_token is required');
  if (!requireWebCrypto()) {
    return jwtError('unsupported', 'WebCrypto (crypto.subtle) is unavailable in this runtime');
  }

  const parts = parseJwtParts({ token: idToken, tokenName: 'id_token' });
  if (!parts.ok) return parts;
  const kid = toOptionalTrimmedString(parts.value.header.kid);
  const alg = toOptionalTrimmedString(parts.value.header.alg);
  if (!kid) return jwtError('invalid_body', 'id_token header.kid is required');
  if (alg !== 'RS256') return jwtError('invalid_body', 'id_token header.alg must be RS256');

  const jwks = await getGoogleJwks(input.jwksState);
  const jwk = jwks.keysByKid.get(kid);
  if (!jwk) return jwtError('unknown_kid', 'Unknown Google key id (kid)');
  const signature = await verifyJwtSignature({
    jwk,
    parts: parts.value,
    tokenName: 'Google id_token',
  });
  if (!signature.ok) return signature;

  const iss = toOptionalTrimmedString(parts.value.payload.iss);
  if (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') {
    return jwtError('invalid_issuer', 'Invalid Google id_token issuer');
  }

  const time = verifyGoogleTimeClaims(parts.value.payload);
  if (!time.ok) return time;

  const aud = parseJwtAud(parts.value.payload.aud);
  if (!aud.length) return jwtError('invalid_claims', 'Missing Google id_token aud');
  const allowedAudSet = new Set(input.config.clientIds);
  if (!aud.some((value) => allowedAudSet.has(value))) {
    return jwtError('invalid_audience', 'Google id_token audience mismatch');
  }

  const sub = toOptionalTrimmedString(parts.value.payload.sub);
  if (!sub) return jwtError('invalid_claims', 'Missing Google id_token sub');

  const hostedDomain = toOptionalTrimmedString(parts.value.payload.hd);
  if (input.config.hostedDomains?.length) {
    const allowHd = new Set(input.config.hostedDomains.map((d) => d.toLowerCase()));
    if (!hostedDomain || !allowHd.has(hostedDomain.toLowerCase())) {
      return jwtError('invalid_hosted_domain', 'Google hosted domain is not allowed');
    }
  }

  const email = toOptionalTrimmedString(parts.value.payload.email);
  const name = toOptionalTrimmedString(parts.value.payload.name);
  const givenName = toOptionalTrimmedString(parts.value.payload.given_name);
  const familyName = toOptionalTrimmedString(parts.value.payload.family_name);
  const emailVerified = parseGoogleEmailVerified(parts.value.payload.email_verified);

  return buildGoogleLoginVerificationSuccess({
    providerSubject: `google:${sub}`,
    sub,
    email,
    name,
    givenName,
    familyName,
    emailVerified,
    hostedDomain,
  });
}

export async function verifyGoogleLoginWithIdentityStore(input: {
  request: { idToken?: unknown; id_token?: unknown };
  config?: GoogleOidcConfig;
  jwksState: GoogleJwksState;
  identityStore: IdentityStore;
}): Promise<GoogleLoginFacadeResult> {
  try {
    const verified = await verifyGoogleIdToken({
      request: input.request,
      config: input.config,
      jwksState: input.jwksState,
    });
    if (!verified.ok) return verified;
    const userId = await resolveLinkedProviderUserId({
      identityStore: input.identityStore,
      providerSubject: verified.providerSubject,
    });
    return buildGoogleLoginFacadeSuccess({ verified, userId });
  } catch (e: unknown) {
    return {
      ok: false,
      verified: false,
      code: 'internal',
      message: errorMessage(e) || 'Google OIDC verification failed',
    };
  }
}
