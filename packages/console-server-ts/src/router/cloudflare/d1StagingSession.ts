import { base64UrlDecode, base64UrlEncode } from '@seams-internal/shared-ts/utils/encoders';
import { SessionService } from '@seams/sdk-server/internal/core/SessionService';
import type {
  CloudflareSecretsStoreSecretBinding,
  SigningRootEncodedKekMaterialEncoding,
  SigningRootKekProvider,
} from '@seams/sdk-server/internal/core/ThresholdService/signingRootKekProvider';
import type { ConsoleTeamRbacService } from '@seams-internal/console-server/teamRbac/service';
import type { ConsoleAuthAdapter, ConsoleAuthAdapterResult, HeaderRecord } from '@seams/sdk-server/internal/router/consoleAuth';
import type { SessionAdapter } from '@seams/sdk-server/internal/router/routerApi';

export interface CloudflareD1StagingSecretEnv extends Readonly<Record<string, unknown>> {
  readonly SIGNING_ROOT_KEK_PROVIDER?: string;
  readonly SIGNING_ROOT_KEK_ENCODING?: string;
  readonly SIGNING_ROOT_KEK_IDS?: string;
}

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

export interface ConsoleSessionAuthAdapterOptions {
  readonly session: SessionAdapter;
  readonly teamRbac: ConsoleTeamRbacService;
  readonly defaultOrgId?: string;
  readonly defaultProjectId?: string;
  readonly defaultEnvironmentId?: string;
  readonly platformAdminEmails?: string;
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
    const headerB64u = encodeJsonSegment({
      ...input.header,
      typ: 'JWT',
      alg: 'HS256',
    });
    const payloadB64u = encodeJsonSegment({
      ...input.payload,
      iat: nowSeconds,
      exp: nowSeconds + this.ttlSeconds,
      ...(this.issuer ? { iss: this.issuer } : {}),
      ...(this.audience ? { aud: this.audience } : {}),
    });
    const signingInput = `${headerB64u}.${payloadB64u}`;
    const signature = await this.signUtf8(signingInput);
    return `${signingInput}.${base64UrlEncode(signature)}`;
  }

  async verifyToken(token: string): Promise<{ readonly valid: boolean; readonly payload?: unknown }> {
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
  private readonly teamRbac: ConsoleTeamRbacService;
  private readonly defaultOrgId: string;
  private readonly defaultProjectId: string;
  private readonly defaultEnvironmentId: string;
  private readonly platformAdminEmails: readonly string[];

  constructor(options: ConsoleSessionAuthAdapterOptions) {
    this.session = options.session;
    this.teamRbac = options.teamRbac;
    this.defaultOrgId = normalizeString(options.defaultOrgId);
    this.defaultProjectId = normalizeString(options.defaultProjectId);
    this.defaultEnvironmentId = normalizeString(options.defaultEnvironmentId);
    this.platformAdminEmails = normalizeEmailList(options.platformAdminEmails);
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

    const roles = await this.resolveRoles({ claims, orgId, userId });
    if (roles.length === 0) {
      return {
        ok: false,
        code: 'forbidden',
        message: 'No console roles assigned',
        status: 403,
      };
    }

    return {
      ok: true,
      claims: {
        userId,
        orgId,
        roles,
        ...(normalizeString(claims.projectId) || this.defaultProjectId
          ? { projectId: normalizeString(claims.projectId) || this.defaultProjectId }
          : {}),
        ...(normalizeString(claims.environmentId) || this.defaultEnvironmentId
          ? { environmentId: normalizeString(claims.environmentId) || this.defaultEnvironmentId }
          : {}),
        ...(normalizeString(claims.email) ? { email: normalizeString(claims.email) } : {}),
        ...(normalizeString(claims.name) ? { name: normalizeString(claims.name) } : {}),
      },
    };
  }

  private async resolveRoles(input: {
    readonly claims: Record<string, unknown>;
    readonly orgId: string;
    readonly userId: string;
  }): Promise<string[]> {
    const memberRoles = await loadActiveConsoleMemberRoles({
      teamRbac: this.teamRbac,
      orgId: input.orgId,
      userId: input.userId,
    });
    const adminRoles = this.platformAdminEmails.includes(normalizeString(input.claims.email))
      ? ['platform_admin']
      : [];
    return mergeRoleLists(memberRoles, adminRoles);
  }
}

export function createHmacSessionAdapter(options: HmacSessionAdapterOptions): SessionAdapter {
  const jwt = new HmacSessionJwtAdapter(options);
  const cookieName = normalizeString(options.cookieName) || 'seams-jwt';
  const cookie = new CrossSiteSessionCookieAdapter(
    cookieName,
    normalizeTtlSeconds(options.ttlSeconds),
  );
  return new SessionService({
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

export function createCloudflareSecretsStoreKekProviderFromEnv(
  env: CloudflareD1StagingSecretEnv,
): SigningRootKekProvider {
  const provider = requireEnvString(env, 'SIGNING_ROOT_KEK_PROVIDER');
  if (provider !== 'cloudflare_secrets_store') {
    throw new Error('SIGNING_ROOT_KEK_PROVIDER must be cloudflare_secrets_store');
  }
  const encoding = parseKekEncoding(requireEnvString(env, 'SIGNING_ROOT_KEK_ENCODING'));
  const secretsByKekId: Record<string, CloudflareSecretsStoreSecretBinding> = {};
  for (const kekId of readCsvList(env.SIGNING_ROOT_KEK_IDS)) {
    const bindingName = secretBindingNameForKekId(kekId);
    const binding = readSecretStoreBinding(env, bindingName);
    secretsByKekId[kekId] = binding;
  }
  if (Object.keys(secretsByKekId).length === 0) {
    throw new Error('SIGNING_ROOT_KEK_IDS must list at least one signer KEK id');
  }
  return {
    kind: 'cloudflare_secrets_store',
    secretsByKekId,
    encoding,
  };
}

export function requireEnvString(
  env: Readonly<Record<string, unknown>>,
  name: string,
): string {
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

export function secretBindingNameForKekId(kekId: string): string {
  const normalized = normalizeString(kekId).toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  if (!normalized) throw new Error('signing-root KEK id is required');
  return normalized;
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

async function loadActiveConsoleMemberRoles(input: {
  readonly teamRbac: ConsoleTeamRbacService;
  readonly orgId: string;
  readonly userId: string;
}): Promise<string[]> {
  if (!input.teamRbac.listOrganizationMembers) return [];
  const members = await input.teamRbac.listOrganizationMembers(input.orgId, {
    status: 'ACTIVE',
  });
  for (const member of members) {
    if (member.userId !== input.userId) continue;
    return normalizeRoleList(member.roles.map(readRoleAssignmentRole));
  }
  return [];
}

function readRoleAssignmentRole(input: { readonly role: unknown }): string {
  return normalizeString(input.role);
}

function normalizeRoleList(input: unknown): string[] {
  const rawValues = Array.isArray(input) ? input : normalizeString(input).split(',');
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of rawValues) {
    const role = normalizeString(raw).toLowerCase();
    if (!role || seen.has(role)) continue;
    out.push(role);
    seen.add(role);
  }
  return out;
}

function mergeRoleLists(...lists: readonly string[][]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const list of lists) {
    for (const role of list) {
      const normalized = normalizeString(role).toLowerCase();
      if (!normalized || seen.has(normalized)) continue;
      out.push(normalized);
      seen.add(normalized);
    }
  }
  return out;
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

function parseKekEncoding(input: string): SigningRootEncodedKekMaterialEncoding {
  switch (input) {
    case 'base64url':
    case 'base64':
    case 'hex':
      return input;
    default:
      throw new Error('SIGNING_ROOT_KEK_ENCODING must be base64url, base64, or hex');
  }
}

function readSecretStoreBinding(
  env: Readonly<Record<string, unknown>>,
  bindingName: string,
): CloudflareSecretsStoreSecretBinding {
  const binding = env[bindingName];
  if (!isSecretStoreBinding(binding)) {
    throw new Error(`Cloudflare Secrets Store binding ${bindingName} is required`);
  }
  return binding;
}

function isSecretStoreBinding(input: unknown): input is CloudflareSecretsStoreSecretBinding {
  if (!input || typeof input !== 'object') return false;
  const candidate = input as { readonly get?: unknown };
  return typeof candidate.get === 'function';
}

function normalizeString(input: unknown): string {
  return String(input || '').trim();
}
