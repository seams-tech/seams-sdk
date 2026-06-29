import type { NormalizedLogger } from './logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdStoreConfigInput,
} from './types';
import {
  THRESHOLD_DO_OBJECT_NAME_DEFAULT,
  THRESHOLD_PREFIX_DEFAULT,
} from './defaultConfigsServer';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetdelJson,
  redisSetJson,
} from './ThresholdService/kv';
import {
  formatD1ExecStatement,
  parseD1JsonColumn,
  resolveD1DatabaseFromConfig,
} from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';

export type WebAuthnLoginChallengeRecord = {
  version: 'webauthn_login_challenge_v1';
  challengeId: string;
  userId: string;
  rpId: string;
  challengeB64u: string;
  createdAtMs: number;
  expiresAtMs: number;
};

export interface WebAuthnLoginChallengeStore {
  put(record: WebAuthnLoginChallengeRecord): Promise<void>;
  consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null>;
  del(challengeId: string): Promise<void>;
}

export interface D1WebAuthnLoginChallengeStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1WebAuthnLoginChallengeStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

type NormalizedD1WebAuthnLoginChallengeStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
  readonly now: () => Date;
};

type D1WebAuthnLoginChallengeScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1WebAuthnChallengeRow = {
  readonly record_json?: unknown;
};

const WEBAUTHN_LOGIN_CHALLENGE_KIND = 'login';

export const WEBAUTHN_LOGIN_CHALLENGE_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS webauthn_challenges (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      challenge_id TEXT NOT NULL,
      challenge_kind TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
      CHECK (length(challenge_id) > 0),
      CHECK (challenge_kind IN ('login', 'sync')),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (expires_at_ms > created_at_ms)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS webauthn_challenges_expiry_idx
      ON webauthn_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_kind,
        expires_at_ms
      )
  `,
] as const);

export async function ensureWebAuthnLoginChallengeStoreD1Schema(
  options: D1WebAuthnLoginChallengeStoreSchemaOptions,
): Promise<void> {
  for (const statement of WEBAUTHN_LOGIN_CHALLENGE_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

function toWebAuthnLoginChallengePrefix(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.WEBAUTHN_LOGIN_CHALLENGE_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');

  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}webauthn:login_challenge:`;
}

function parseWebAuthnLoginChallengeRecord(raw: unknown): WebAuthnLoginChallengeRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const challengeId = toOptionalTrimmedString(raw.challengeId);
  const userId = toOptionalTrimmedString(raw.userId);
  const rpId = toOptionalTrimmedString(raw.rpId);
  const challengeB64u = toOptionalTrimmedString(raw.challengeB64u);
  const createdAtMs =
    typeof raw.createdAtMs === 'number' ? raw.createdAtMs : Number(raw.createdAtMs);
  const expiresAtMs =
    typeof raw.expiresAtMs === 'number' ? raw.expiresAtMs : Number(raw.expiresAtMs);
  if (version !== 'webauthn_login_challenge_v1') return null;
  if (!challengeId || !userId || !rpId || !challengeB64u) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  return {
    version: 'webauthn_login_challenge_v1',
    challengeId,
    userId,
    rpId,
    challengeB64u,
    createdAtMs: Math.floor(createdAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
  };
}

function defaultNow(): Date {
  return new Date();
}

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) throw new Error(`${field} is required for D1 WebAuthn login challenge store`);
  return normalized;
}

function normalizeD1WebAuthnLoginChallengeStoreOptions(
  input: D1WebAuthnLoginChallengeStoreOptions,
): NormalizedD1WebAuthnLoginChallengeStoreOptions {
  return {
    database: input.database,
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.orgId, 'orgId'),
    projectId: requireD1ScopeString(input.projectId, 'projectId'),
    envId: requireD1ScopeString(input.envId, 'envId'),
    ensureSchema: input.ensureSchema !== false,
    now: input.now || defaultNow,
  };
}

function d1ScopeFromConfig(input: {
  readonly config: Record<string, unknown>;
  readonly namespace: string;
}): Omit<D1WebAuthnLoginChallengeStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

class InMemoryWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly map = new Map<string, WebAuthnLoginChallengeRecord>();
  private readonly prefix: string;

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  private key(challengeId: string): string {
    return `${this.prefix}${challengeId}`;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    this.map.set(this.key(parsed.challengeId), parsed);
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const key = this.key(id);
    const rec = this.map.get(key) || null;
    this.map.delete(key);
    if (!rec) return null;
    if (Date.now() > rec.expiresAtMs) return null;
    return rec;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    this.map.delete(this.key(id));
  }
}

export class D1WebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1WebAuthnLoginChallengeScope;
  private readonly ensureSchemaOnUse: boolean;
  private readonly now: () => Date;
  private schemaReady = false;

  constructor(input: D1WebAuthnLoginChallengeStoreOptions) {
    const normalized = normalizeD1WebAuthnLoginChallengeStoreOptions(input);
    this.database = normalized.database;
    this.scope = {
      namespace: normalized.namespace,
      orgId: normalized.orgId,
      projectId: normalized.projectId,
      envId: normalized.envId,
    };
    this.ensureSchemaOnUse = normalized.ensureSchema;
    this.now = normalized.now;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.schemaReady) return;
    await ensureWebAuthnLoginChallengeStoreD1Schema({ database: this.database });
    this.schemaReady = true;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    await this.database
      .prepare(
        `INSERT INTO webauthn_challenges (
          namespace,
          org_id,
          project_id,
          env_id,
          challenge_id,
          challenge_kind,
          record_json,
          created_at_ms,
          expires_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, challenge_id)
        DO UPDATE SET
          challenge_kind = EXCLUDED.challenge_kind,
          record_json = EXCLUDED.record_json,
          created_at_ms = EXCLUDED.created_at_ms,
          expires_at_ms = EXCLUDED.expires_at_ms`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        parsed.challengeId,
        WEBAUTHN_LOGIN_CHALLENGE_KIND,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.expiresAtMs,
      )
      .run();
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const row = await this.database
      .prepare(
        `DELETE FROM webauthn_challenges
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND challenge_id = ?
            AND challenge_kind = ?
            AND expires_at_ms > ?
          RETURNING record_json`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        id,
        WEBAUTHN_LOGIN_CHALLENGE_KIND,
        this.now().getTime(),
      )
      .first<D1WebAuthnChallengeRow>();
    return parseWebAuthnLoginChallengeRecord(parseD1JsonColumn(row?.record_json));
  }

  async del(challengeId: string): Promise<void> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    await this.database
      .prepare(
        `DELETE FROM webauthn_challenges
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND challenge_id = ?
            AND challenge_kind = ?`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        id,
        WEBAUTHN_LOGIN_CHALLENGE_KIND,
      )
      .run();
  }
}

class UpstashRedisRestWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly client: UpstashRedisRestClient;
  private readonly prefix: string;

  constructor(input: { url: string; token: string; prefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.prefix = input.prefix;
  }

  private key(challengeId: string): string {
    return `${this.prefix}${challengeId}`;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    await this.client.setJson(this.key(parsed.challengeId), parsed, ttlMs);
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const raw = await this.client.getdelJson(this.key(id));
    const parsed = parseWebAuthnLoginChallengeRecord(raw);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    await this.client.del(this.key(id));
  }
}

class RedisTcpWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly client: RedisTcpClient;
  private readonly prefix: string;

  constructor(input: { redisUrl: string; prefix: string }) {
    this.client = new RedisTcpClient(input.redisUrl);
    this.prefix = input.prefix;
  }

  private key(challengeId: string): string {
    return `${this.prefix}${challengeId}`;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    await redisSetJson(this.client, this.key(parsed.challengeId), parsed, ttlMs);
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const raw = await redisGetdelJson(this.client, this.key(id));
    const parsed = parseWebAuthnLoginChallengeRecord(raw);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    await redisDel(this.client, this.key(id));
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

type DoRequest =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'del'; key: string }
  | { op: 'getdel'; key: string };

function isDurableObjectNamespaceLike(v: unknown): v is CloudflareDurableObjectNamespaceLike {
  return (
    Boolean(v) &&
    typeof v === 'object' &&
    !Array.isArray(v) &&
    typeof (v as CloudflareDurableObjectNamespaceLike).idFromName === 'function' &&
    typeof (v as CloudflareDurableObjectNamespaceLike).get === 'function'
  );
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const direct = (config as { namespace?: unknown }).namespace;
  if (isDurableObjectNamespaceLike(direct)) return direct;

  const alt = (config as { durableObjectNamespace?: unknown }).durableObjectNamespace;
  if (isDurableObjectNamespaceLike(alt)) return alt;

  const envStyle = (config as { THRESHOLD_DO_NAMESPACE?: unknown })
    .THRESHOLD_DO_NAMESPACE;
  if (isDurableObjectNamespaceLike(envStyle)) return envStyle;

  return null;
}

function resolveDoStub(input: {
  namespace: CloudflareDurableObjectNamespaceLike;
  objectName: string;
}): DurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id) as unknown as DurableObjectStubLike;
}

async function callDo<T>(stub: DurableObjectStubLike, req: DoRequest): Promise<DoResp<T>> {
  const resp = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(req),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`WebAuthn DO store HTTP ${resp.status}: ${text}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`WebAuthn DO store returned non-JSON response: ${text.slice(0, 200)}`);
  }
  if (!isObject(json)) {
    throw new Error('WebAuthn DO store returned invalid JSON shape');
  }
  const ok = (json as { ok?: unknown }).ok;
  if (ok === true) return json as DoOk<T>;
  const code = toOptionalTrimmedString((json as { code?: unknown }).code);
  const message = toOptionalTrimmedString((json as { message?: unknown }).message);
  return { ok: false, code: code || 'internal', message: message || 'WebAuthn DO store error' };
}

class CloudflareDurableObjectWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly stub: DurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.prefix = input.prefix;
  }

  private key(challengeId: string): string {
    return `${this.prefix}${challengeId}`;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key(parsed.challengeId),
      value: parsed,
      ttlMs,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'getdel', key: this.key(id) });
    if (!resp.ok) return null;
    const parsed = parseWebAuthnLoginChallengeRecord(resp.value);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    const resp = await callDo<void>(this.stub, { op: 'del', key: this.key(id) });
    if (!resp.ok) throw new Error(resp.message);
  }
}

export function createWebAuthnLoginChallengeStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WebAuthnLoginChallengeStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const prefix = toWebAuthnLoginChallengePrefix(config);

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error(
        '[webauthn] D1 login challenge store selected but no D1 database was provided',
      );
    }
    input.logger.info('[webauthn] Using D1 login challenge store');
    return new D1WebAuthnLoginChallengeStore({
      database,
      ...d1ScopeFromConfig({ config, namespace: prefix }),
    });
  }
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error(
        'cloudflare-do webauthn store selected but no Durable Object namespace was provided (expected config.namespace)',
      );
    }
    const objectName =
      toOptionalTrimmedString((config as { objectName?: unknown }).objectName) ||
      toOptionalTrimmedString((config as { name?: unknown }).name) ||
      THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger.info(
      '[webauthn] Using Cloudflare Durable Object store for login challenge persistence',
    );
    return new CloudflareDurableObjectWebAuthnLoginChallengeStore({
      namespace,
      objectName,
      prefix,
    });
  }

  if (kind === 'in-memory') {
    input.logger.info('[webauthn] Using in-memory login challenge store (non-persistent)');
    return new InMemoryWebAuthnLoginChallengeStore(prefix);
  }

  if (kind === 'upstash-redis-rest') {
    const url =
      toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token =
      toOptionalTrimmedString(config.token) ||
      toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token) {
      throw new Error(
        'Upstash webauthn login challenge store enabled but url/token are not both set',
      );
    }
    input.logger.info('[webauthn] Using Upstash REST login challenge store');
    return new UpstashRedisRestWebAuthnLoginChallengeStore({ url, token, prefix });
  }

  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      input.logger.warn(
        '[webauthn] redis-tcp login challenge store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryWebAuthnLoginChallengeStore(prefix);
    }
    const redisUrl =
      toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) {
      throw new Error('redis-tcp webauthn login challenge store enabled but redisUrl is not set');
    }
    input.logger.info('[webauthn] Using redis-tcp login challenge store');
    return new RedisTcpWebAuthnLoginChallengeStore({ redisUrl, prefix });
  }

  if (kind) throw new Error(`[webauthn] Unknown login challenge store kind: ${kind}`);

  // Env-shaped config: prefer Redis/Upstash for one-time challenges.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash webauthn login challenge store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[webauthn] Using Upstash REST login challenge store');
    return new UpstashRedisRestWebAuthnLoginChallengeStore({
      url: upstashUrl,
      token: upstashToken,
      prefix,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      input.logger.warn(
        '[webauthn] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryWebAuthnLoginChallengeStore(prefix);
    }
    input.logger.info('[webauthn] Using redis-tcp login challenge store');
    return new RedisTcpWebAuthnLoginChallengeStore({ redisUrl, prefix });
  }

  input.logger.info('[webauthn] Using in-memory login challenge store (non-persistent)');
  return new InMemoryWebAuthnLoginChallengeStore(prefix);
}
