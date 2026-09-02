import { base64UrlDecode, base64UrlEncode } from '@seams/wallet-server/cloud-host';
import { ConsoleSessionService } from '@seams-internal/console-server/boundary/session';
import type {
  ActiveOrganizationAuthorization,
  ConsoleOrganizationAccessService,
} from '@seams-internal/console-server/teamRbac/index';
import type { ConsoleAuthAdapter, ConsoleAuthAdapterResult, HeaderRecord } from '@seams-internal/console-server/router/consoleAuth';
import type { SessionAdapter } from '@seams/wallet-server/cloud-host';

export type CloudflareD1StagingSessionEnv = Readonly<Record<string, unknown>>;

export interface HmacSessionAdapterOptions {
  readonly secret: string;
  readonly cookieName?: string;
  readonly issuer?: string;
  readonly audience?: string;
  readonly ttlSeconds?: number;
}

export interface HmacSessionEnvOptions {
  readonly env: CloudflareD1StagingSessionEnv;
  readonly secretName: string;
  readonly cookieName?: string;
  readonly issuer?: string;
  readonly audience?: string;
  readonly ttlSeconds?: number;
}

export interface Ed25519SessionAdapterOptions {
  readonly privateJwk: JsonWebKey & {
    readonly kty: 'OKP';
    readonly crv: 'Ed25519';
    readonly x: string;
    readonly d: string;
  };
  readonly keyId: string;
  readonly cookieName?: string;
  readonly issuer: string;
  readonly audience: string;
  readonly ttlSeconds?: number;
}

export interface ConsoleSessionAuthAdapterOptions {
  readonly session: SessionAdapter;
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly defaultOrgId?: string;
  readonly defaultProjectId?: string;
  readonly defaultEnvironmentId?: string;
  readonly platformSupportEmails?: string;
}

type HmacVerificationResult =
  | { readonly valid: true; readonly payload: Record<string, unknown> }
  | { readonly valid: false };

type ParsedJwt =
  | {
      readonly ok: true;
      readonly headerB64u: string;
      readonly payloadB64u: string;
      readonly signatureB64u: string;
      readonly header: Record<string, unknown>;
      readonly payload: Record<string, unknown>;
    }
  | { readonly ok: false };

class HmacSessionJwtAdapter {
  private readonly secretBytes: Uint8Array;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly ttlSeconds: number;

  constructor(options: HmacSessionAdapterOptions) {
    this.secretBytes = encodeRequiredSecret(options.secret);
    this.issuer = normalizeString(options.issuer);
    this.audience = normalizeString(options.audience);
    this.ttlSeconds = normalizeTtlSeconds(options.ttlSeconds);
  }

  async signToken(input: {
    readonly header: Record<string, unknown>;
    readonly payload: Record<string, unknown>;
  }): Promise<string> {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const timeClaims = sessionJwtTimeClaims(input.payload, nowSeconds, this.ttlSeconds);
    const headerB64u = encodeJsonSegment({
      ...input.header,
      typ: 'JWT',
      alg: 'HS256',
    });
    const payloadB64u = encodeJsonSegment({
      ...input.payload,
      ...timeClaims,
      ...(this.issuer ? { iss: this.issuer } : {}),
      ...(this.audience ? { aud: this.audience } : {}),
    });
    const signingInput = `${headerB64u}.${payloadB64u}`;
    const signature = await this.signUtf8(signingInput);
    return `${signingInput}.${base64UrlEncode(signature)}`;
  }

  async verifyToken(
    token: string,
  ): Promise<{ readonly valid: boolean; readonly payload?: unknown }> {
    const verified = await this.verify(token);
    if (!verified.valid) return { valid: false };
    return { valid: true, payload: verified.payload };
  }

  private async verify(token: string): Promise<HmacVerificationResult> {
    const parsed = parseJwt(token);
    if (!parsed.ok) return { valid: false };
    if (normalizeString(parsed.header.alg) !== 'HS256') return { valid: false };
    if (!this.payloadMatchesConfiguredAudience(parsed.payload)) return { valid: false };
    if (!this.payloadMatchesConfiguredIssuer(parsed.payload)) return { valid: false };
    let signature: Uint8Array;
    try {
      signature = base64UrlDecode(parsed.signatureB64u);
    } catch {
      return { valid: false };
    }
    const signingInput = `${parsed.headerB64u}.${parsed.payloadB64u}`;
    const expected = await this.signUtf8(signingInput);
    if (!constantTimeEqual(signature, expected)) return { valid: false };
    return { valid: true, payload: parsed.payload };
  }

  private payloadMatchesConfiguredIssuer(payload: Record<string, unknown>): boolean {
    if (!this.issuer) return true;
    return normalizeString(payload.iss) === this.issuer;
  }

  private payloadMatchesConfiguredAudience(payload: Record<string, unknown>): boolean {
    if (!this.audience) return true;
    const aud = payload.aud;
    if (typeof aud === 'string') return aud === this.audience;
    if (!Array.isArray(aud)) return false;
    for (const item of aud) {
      if (item === this.audience) return true;
    }
    return false;
  }

  private async signUtf8(value: string): Promise<Uint8Array> {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) throw new Error('WebCrypto crypto.subtle is required for staging sessions');
    const key = await subtle.importKey(
      'raw',
      toArrayBufferCopy(this.secretBytes),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const signature = await subtle.sign('HMAC', key, new TextEncoder().encode(value));
    return new Uint8Array(signature);
  }
}

class Ed25519SessionJwtAdapter {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly keyId: string;
  private readonly ttlSeconds: number;
  private readonly signingKey: Promise<CryptoKey>;
  private readonly verifyingKey: Promise<CryptoKey>;

  constructor(private readonly options: Ed25519SessionAdapterOptions) {
    this.issuer = requireNormalizedString(options.issuer, 'Ed25519 session issuer');
    this.audience = requireNormalizedString(options.audience, 'Ed25519 session audience');
    this.keyId = requireNormalizedString(options.keyId, 'Ed25519 session key id');
    this.ttlSeconds = normalizeTtlSeconds(options.ttlSeconds);
    this.signingKey = this.importSigningKey();
    this.verifyingKey = this.importVerifyingKey();
  }

  async signToken(input: {
    readonly header: Record<string, unknown>;
    readonly payload: Record<string, unknown>;
  }): Promise<string> {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const timeClaims = sessionJwtTimeClaims(input.payload, nowSeconds, this.ttlSeconds);
    const headerB64u = encodeJsonSegment({
      ...input.header,
      typ: 'JWT',
      alg: 'EdDSA',
      kid: this.keyId,
    });
    const payloadB64u = encodeJsonSegment({
      ...input.payload,
      ...routerWalletSessionScopeClaims(input.payload),
      ...timeClaims,
      iss: this.issuer,
      aud: this.audience,
    });
    const signingInput = `${headerB64u}.${payloadB64u}`;
    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' },
      await this.signingKey,
      new TextEncoder().encode(signingInput),
    );
    return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
  }

  async verifyToken(
    token: string,
  ): Promise<{ readonly valid: boolean; readonly payload?: unknown }> {
    const parsed = parseJwt(token);
    if (!parsed.ok) return { valid: false };
    if (
      normalizeString(parsed.header.alg) !== 'EdDSA' ||
      normalizeString(parsed.header.kid) !== this.keyId ||
      !payloadMatchesIssuer(parsed.payload, this.issuer) ||
      !payloadMatchesAudience(parsed.payload, this.audience)
    ) {
      return { valid: false };
    }
    let signature: Uint8Array;
    try {
      signature = base64UrlDecode(parsed.signatureB64u);
    } catch {
      return { valid: false };
    }
    const valid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      await this.verifyingKey,
      toArrayBufferCopy(signature),
      new TextEncoder().encode(`${parsed.headerB64u}.${parsed.payloadB64u}`),
    );
    return valid ? { valid: true, payload: parsed.payload } : { valid: false };
  }

  private async importSigningKey(): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
      'jwk',
      this.options.privateJwk,
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
  }

  private async importVerifyingKey(): Promise<CryptoKey> {
    const { crv, kty, x } = this.options.privateJwk;
    return await crypto.subtle.importKey(
      'jwk',
      { alg: 'EdDSA', crv, kty, use: 'sig', x },
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
  }
}

function requireNormalizedString(value: unknown, label: string): string {
  const normalized = normalizeString(value);
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function payloadMatchesIssuer(payload: Record<string, unknown>, issuer: string): boolean {
  return normalizeString(payload.iss) === issuer;
}

function payloadMatchesAudience(payload: Record<string, unknown>, audience: string): boolean {
  const value = payload.aud;
  if (typeof value === 'string') return value === audience;
  return Array.isArray(value) && value.includes(audience);
}

function routerWalletSessionScopeClaims(payload: Record<string, unknown>): Record<string, unknown> {
  const kind = normalizeString(payload.kind);
  if (
    kind !== 'router_ab_ed25519_wallet_session_v1' &&
    kind !== 'router_ab_ecdsa_derivation_wallet_session_v1'
  ) {
    return {};
  }
  if (payload.authorizationKind === 'linked_device_wallet_session') return {};
  const scope =
    payload.runtimePolicyScope &&
    typeof payload.runtimePolicyScope === 'object' &&
    !Array.isArray(payload.runtimePolicyScope)
      ? (payload.runtimePolicyScope as Record<string, unknown>)
      : null;
  const orgId = requireNormalizedString(scope?.orgId, 'Wallet Session org id');
  const projectId = requireNormalizedString(scope?.projectId, 'Wallet Session project id');
  const environment = requireNormalizedString(scope?.envId, 'Wallet Session environment');
  const accountId = requireNormalizedString(
    payload.walletId ?? payload.sub,
    'Wallet Session account id',
  );
  const claims = {
    org_id: orgId,
    project_id: projectId,
    environment,
    account_id: accountId,
  };
  if (payload.sid === undefined) return claims;
  return {
    ...claims,
    sid: requireNormalizedString(payload.sid, 'Wallet Session Seams session id'),
  };
}

function sessionJwtTimeClaims(
  payload: Record<string, unknown>,
  nowSeconds: number,
  ttlSeconds: number,
): { readonly iat: number; readonly exp: number } {
  if (!isRouterWalletSessionPayload(payload)) {
    return { iat: nowSeconds, exp: nowSeconds + ttlSeconds };
  }
  const iat = Number(payload.iat);
  const exp = Number(payload.exp);
  if (
    !Number.isSafeInteger(iat) ||
    iat < 0 ||
    iat > nowSeconds ||
    !Number.isSafeInteger(exp) ||
    exp <= nowSeconds ||
    exp > nowSeconds + ttlSeconds
  ) {
    throw new Error('Wallet Session JWT lifetime exceeds the session signing policy');
  }
  return { iat, exp };
}

function isRouterWalletSessionPayload(payload: Record<string, unknown>): boolean {
  return (
    payload.kind === 'router_ab_ed25519_wallet_session_v1' ||
    payload.kind === 'router_ab_ecdsa_derivation_wallet_session_v1'
  );
}

class CrossSiteSessionCookieAdapter {
  private readonly cookieName: string;
  private readonly ttlSeconds: number;

  constructor(cookieName: string, ttlSeconds: number) {
    this.cookieName = cookieName;
    this.ttlSeconds = ttlSeconds;
  }

  buildSetHeader(token: string): string {
    const expires = new Date(Date.now() + this.ttlSeconds * 1000).toUTCString();
    return [
      `${this.cookieName}=${token}`,
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=None',
      `Max-Age=${this.ttlSeconds}`,
      `Expires=${expires}`,
    ].join('; ');
  }

  buildClearHeader(): string {
    return [
      `${this.cookieName}=`,
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=None',
      'Max-Age=0',
      'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    ].join('; ');
  }
}

class ConsoleSessionAuthAdapter implements ConsoleAuthAdapter {
  private readonly session: SessionAdapter;
  private readonly organizationAccess: ConsoleOrganizationAccessService;
  private readonly defaultOrgId: string;
  private readonly defaultProjectId: string;
  private readonly defaultEnvironmentId: string;
  private readonly platformSupportEmails: readonly string[];

  constructor(options: ConsoleSessionAuthAdapterOptions) {
    this.session = options.session;
    this.organizationAccess = options.organizationAccess;
    this.defaultOrgId = normalizeString(options.defaultOrgId);
    this.defaultProjectId = normalizeString(options.defaultProjectId);
    this.defaultEnvironmentId = normalizeString(options.defaultEnvironmentId);
    this.platformSupportEmails = normalizeEmailList(options.platformSupportEmails);
  }

  async authenticate(headers: HeaderRecord): Promise<ConsoleAuthAdapterResult> {
    const parsed = await this.session.parse(headers);
    if (!parsed.ok) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Missing or invalid console session',
        status: 401,
      };
    }

    const claims = parsed.claims;
    if (normalizeString(claims.kind) !== 'console_session_v1') {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Invalid console session kind',
        status: 401,
      };
    }

    const userId = normalizeString(claims.sub);
    const orgId = normalizeString(claims.orgId) || this.defaultOrgId;
    if (!userId || !orgId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Console session requires sub and orgId',
        status: 401,
      };
    }

    const authorization = await this.organizationAccess.lookupAuthorization({ orgId, userId });
    if (!authorization || authorization.kind === 'denied') {
      return {
        ok: false,
        code: 'forbidden',
        message: 'No active organization membership',
        status: 403,
      };
    }

    const claimedProjectId = normalizeString(claims.projectId) || this.defaultProjectId;
    const projectId =
      authorization.role === 'MEMBER'
        ? resolveMemberProjectId(authorization, claimedProjectId)
        : claimedProjectId;
    const claimedEnvironmentId = normalizeString(claims.environmentId) || this.defaultEnvironmentId;
    const environmentId =
      authorization.role === 'MEMBER' && projectId !== claimedProjectId ? '' : claimedEnvironmentId;
    const email = normalizeString(claims.email).toLowerCase();
    const identity = {
      userId,
      orgId,
      platformSupport: this.platformSupportEmails.includes(email),
      ...(projectId ? { projectId } : {}),
      ...(environmentId ? { environmentId } : {}),
      ...(email ? { email } : {}),
      ...(normalizeString(claims.name) ? { name: normalizeString(claims.name) } : {}),
      ...(normalizeString(claims.provider) ? { provider: normalizeString(claims.provider) } : {}),
    };
    switch (authorization.role) {
      case 'OWNER':
        return {
          ok: true,
          claims: {
            ...identity,
            membershipId: authorization.membershipId,
            authorizationVersion: authorization.authorizationVersion,
            role: 'OWNER',
            adminPermissions: [...authorization.adminPermissions],
            projectAccess: { kind: 'all' },
          },
        };
      case 'ADMIN':
        return {
          ok: true,
          claims: {
            ...identity,
            membershipId: authorization.membershipId,
            authorizationVersion: authorization.authorizationVersion,
            role: 'ADMIN',
            adminPermissions: [...authorization.adminPermissions],
            projectAccess: { kind: 'all' },
          },
        };
      case 'MEMBER':
        return {
          ok: true,
          claims: {
            ...identity,
            membershipId: authorization.membershipId,
            authorizationVersion: authorization.authorizationVersion,
            role: 'MEMBER',
            adminPermissions: [],
            projectAccess: {
              kind: 'assigned',
              assignments: authorization.projectAccess.assignments.map((assignment) => ({
                projectId: assignment.projectId,
                accessLevel: assignment.accessLevel,
              })),
            },
          },
        };
    }
  }
}

export function createHmacSessionAdapter(options: HmacSessionAdapterOptions): SessionAdapter {
  const jwt = new HmacSessionJwtAdapter(options);
  const cookieName = normalizeString(options.cookieName) || 'seams-jwt';
  const cookie = new CrossSiteSessionCookieAdapter(
    cookieName,
    normalizeTtlSeconds(options.ttlSeconds),
  );
  return new ConsoleSessionService({
    jwt: {
      signToken: jwt.signToken.bind(jwt),
      verifyToken: jwt.verifyToken.bind(jwt),
    },
    cookie: {
      name: cookieName,
      buildSetHeader: cookie.buildSetHeader.bind(cookie),
      buildClearHeader: cookie.buildClearHeader.bind(cookie),
    },
  });
}

export function createEd25519SessionAdapter(options: Ed25519SessionAdapterOptions): SessionAdapter {
  const jwt = new Ed25519SessionJwtAdapter(options);
  const cookieName = normalizeString(options.cookieName) || 'seams-jwt';
  const cookie = new CrossSiteSessionCookieAdapter(
    cookieName,
    normalizeTtlSeconds(options.ttlSeconds),
  );
  return new ConsoleSessionService({
    jwt: {
      signToken: jwt.signToken.bind(jwt),
      verifyToken: jwt.verifyToken.bind(jwt),
    },
    cookie: {
      name: cookieName,
      buildSetHeader: cookie.buildSetHeader.bind(cookie),
      buildClearHeader: cookie.buildClearHeader.bind(cookie),
    },
  });
}

export function createHmacSessionAdapterFromEnv(options: HmacSessionEnvOptions): SessionAdapter {
  return createHmacSessionAdapter({
    secret: requireEnvString(options.env, options.secretName),
    cookieName: options.cookieName,
    issuer: options.issuer,
    audience: options.audience,
    ttlSeconds: options.ttlSeconds,
  });
}

export function createConsoleSessionAuthAdapter(
  options: ConsoleSessionAuthAdapterOptions,
): ConsoleAuthAdapter {
  return new ConsoleSessionAuthAdapter(options);
}

export function requireEnvString(env: Readonly<Record<string, unknown>>, name: string): string {
  const value = normalizeString(env[name]);
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function readEnvString(env: Readonly<Record<string, unknown>>, name: string): string {
  return normalizeString(env[name]);
}

export function readCsvList(input: unknown): string[] {
  const values: string[] = [];
  const seen = new Set<string>();
  for (const raw of normalizeString(input).split(',')) {
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    values.push(value);
    seen.add(value);
  }
  return values;
}

function encodeRequiredSecret(secret: string): Uint8Array {
  const value = normalizeString(secret);
  if (value.length < 32) {
    throw new Error('staging session HMAC secret must be at least 32 characters');
  }
  return new TextEncoder().encode(value);
}

function normalizeTtlSeconds(input: number | undefined): number {
  const ttl = Number(input || 24 * 60 * 60);
  if (!Number.isSafeInteger(ttl) || ttl < 60 || ttl > 30 * 24 * 60 * 60) {
    throw new Error('staging session ttlSeconds must be between 60 seconds and 30 days');
  }
  return ttl;
}

function encodeJsonSegment(input: Record<string, unknown>): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(input)));
}

function parseJwt(token: string): ParsedJwt {
  const parts = normalizeString(token).split('.');
  if (parts.length !== 3) return { ok: false };
  const header = parseJsonSegment(parts[0] || '');
  const payload = parseJsonSegment(parts[1] || '');
  if (!header || !payload) return { ok: false };
  return {
    ok: true,
    headerB64u: parts[0] || '',
    payloadB64u: parts[1] || '',
    signatureB64u: parts[2] || '',
    header,
    payload,
  };
}

function parseJsonSegment(input: string): Record<string, unknown> | null {
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(input);
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(decoded));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    diff |= (left[index] || 0) ^ (right[index] || 0);
  }
  return diff === 0;
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

function resolveMemberProjectId(
  authorization: Extract<ActiveOrganizationAuthorization, { readonly role: 'MEMBER' }>,
  requestedProjectId: string,
): string {
  if (
    requestedProjectId &&
    authorization.projectAccess.assignments.some(
      (assignment) => assignment.projectId === requestedProjectId,
    )
  ) {
    return requestedProjectId;
  }
  return authorization.projectAccess.assignments[0]?.projectId ?? '';
}

function normalizeEmailList(input: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of readCsvList(input)) {
    const email = raw.toLowerCase();
    if (!email.includes('@') || seen.has(email)) continue;
    out.push(email);
    seen.add(email);
  }
  return out;
}

function normalizeString(input: unknown): string {
  return String(input || '').trim();
}
