import type { NormalizedLogger } from './logger';
import type {
  ThresholdEd25519BootstrapSession,
  ThresholdRuntimePolicyScope,
  ThresholdStoreConfigInput,
  WalletRegistrationEcdsaPreparePayload,
} from './types';
import { THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetJson,
  redisSetJson,
} from './ThresholdService/kv';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type EmailRecoveryPreparedThresholdEd25519Record = {
  relayerKeyId: string;
  publicKey: string;
  keyVersion: string;
  recoveryExportCapable: true;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  participantIds?: number[];
  session?: ThresholdEd25519BootstrapSession;
};

export type EmailRecoveryResolvedWalletBinding = {
  walletId: string;
  nearAccountId: string;
  ed25519KeyScopeId: string;
  rpId: string;
  signerSlot: number;
};

export type EmailRecoveryPreparationRecord = {
  version: 'email_recovery_preparation_v1';
  requestId: string;
  accountId: string;
  walletBinding: EmailRecoveryResolvedWalletBinding;
  rpId: string;
  signerSlot: number;
  credentialIdB64u: string;
  credentialPublicKeyB64u: string;
  counter: number;
  createdAtMs: number;
  expiresAtMs: number;
  thresholdEd25519: EmailRecoveryPreparedThresholdEd25519Record;
  ecdsa: WalletRegistrationEcdsaPreparePayload;
  existingRuntimePolicyScope?: ThresholdRuntimePolicyScope;
};

export interface EmailRecoveryPreparationStore {
  get(requestId: string): Promise<EmailRecoveryPreparationRecord | null>;
  put(record: EmailRecoveryPreparationRecord): Promise<void>;
  del(requestId: string): Promise<void>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

function toEmailRecoveryPreparationPrefix(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.EMAIL_RECOVERY_PREPARATION_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');

  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}email_recovery_preparation:`;
}

function parsePositiveInteger(value: unknown): number | undefined {
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isSafeInteger(n) && n > 0 ? Math.floor(n) : undefined;
}

function parseNonNegativeInteger(value: unknown): number | undefined {
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isSafeInteger(n) && n >= 0 ? Math.floor(n) : undefined;
}

function parseParticipantIds(raw: unknown): number[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const participantIds = raw
    .map((participantId) => Number(participantId))
    .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0)
    .map((participantId) => Math.floor(participantId));
  return participantIds.length === raw.length && participantIds.length > 0
    ? participantIds
    : undefined;
}

function parseThresholdEd25519Session(raw: unknown): ThresholdEd25519BootstrapSession | undefined {
  if (!isObject(raw)) return undefined;
  const sessionKind = toOptionalTrimmedString(raw.sessionKind);
  const walletId = toOptionalTrimmedString(raw.walletId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const ed25519KeyScopeId = toOptionalTrimmedString(raw.ed25519KeyScopeId);
  const thresholdSessionId = toOptionalTrimmedString(raw.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(raw.signingGrantId);
  const expiresAtMs = parsePositiveInteger(raw.expiresAtMs);
  if (
    (sessionKind !== 'jwt' && sessionKind !== 'cookie') ||
    !walletId ||
    !nearAccountId ||
    !ed25519KeyScopeId ||
    !thresholdSessionId ||
    !signingGrantId ||
    !expiresAtMs
  ) {
    return undefined;
  }
  const expiresAt = toOptionalTrimmedString(raw.expiresAt);
  const participantIds = parseParticipantIds(raw.participantIds);
  const remainingUses = parseNonNegativeInteger(raw.remainingUses);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
  const jwt = toOptionalTrimmedString(raw.jwt);
  return {
    sessionKind,
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
    thresholdSessionId,
    signingGrantId,
    expiresAtMs,
    ...(expiresAt ? { expiresAt } : {}),
    ...(participantIds ? { participantIds } : {}),
    ...(remainingUses !== undefined ? { remainingUses } : {}),
    ...(isObject(raw.runtimePolicyScope)
      ? { runtimePolicyScope: raw.runtimePolicyScope as ThresholdRuntimePolicyScope }
      : {}),
    ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
    ...(jwt ? { jwt } : {}),
  };
}

function parseEmailRecoveryResolvedWalletBinding(
  raw: unknown,
): EmailRecoveryResolvedWalletBinding | null {
  if (!isObject(raw)) return null;
  const walletId = toOptionalTrimmedString(raw.walletId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const ed25519KeyScopeId = toOptionalTrimmedString(raw.ed25519KeyScopeId);
  const rpId = toOptionalTrimmedString(raw.rpId);
  const signerSlot = parsePositiveInteger(raw.signerSlot);
  if (!walletId || !nearAccountId || !ed25519KeyScopeId || !rpId || !signerSlot) return null;
  return {
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
    rpId,
    signerSlot,
  };
}

function parsePreparedThresholdEd25519(
  raw: unknown,
): EmailRecoveryPreparedThresholdEd25519Record | null {
  if (!isObject(raw)) return null;
  const relayerKeyId = toOptionalTrimmedString(raw.relayerKeyId);
  const publicKey = toOptionalTrimmedString(raw.publicKey);
  const keyVersion = toOptionalTrimmedString(raw.keyVersion);
  const recoveryExportCapable = raw.recoveryExportCapable === true;
  if (!relayerKeyId || !publicKey || !keyVersion || !recoveryExportCapable) return null;
  const clientParticipantId = parsePositiveInteger(raw.clientParticipantId);
  const relayerParticipantId = parsePositiveInteger(raw.relayerParticipantId);
  const participantIds = parseParticipantIds(raw.participantIds);
  const session = parseThresholdEd25519Session(raw.session);
  return {
    relayerKeyId,
    publicKey,
    keyVersion,
    recoveryExportCapable: true,
    ...(clientParticipantId ? { clientParticipantId } : {}),
    ...(relayerParticipantId ? { relayerParticipantId } : {}),
    ...(participantIds ? { participantIds } : {}),
    ...(session ? { session } : {}),
  };
}

function parseEcdsaPreparePayload(raw: unknown): WalletRegistrationEcdsaPreparePayload | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalTrimmedString(raw.kind);
  const chainTargets = Array.isArray(raw.chainTargets) ? raw.chainTargets : [];
  const prepare = isObject(raw.prepare) ? raw.prepare : null;
  if (kind !== 'evm_family_ecdsa_keygen' || chainTargets.length === 0 || !prepare) return null;
  const participantIds = parseParticipantIds(prepare.participantIds);
  const ttlMs = parseNonNegativeInteger(prepare.ttlMs);
  const remainingUses = parseNonNegativeInteger(prepare.remainingUses);
  const required = {
    formatVersion: toOptionalTrimmedString(prepare.formatVersion),
    walletId: toOptionalTrimmedString(prepare.walletId),
    rpId: toOptionalTrimmedString(prepare.rpId),
    ecdsaThresholdKeyId: toOptionalTrimmedString(prepare.ecdsaThresholdKeyId),
    signingRootId: toOptionalTrimmedString(prepare.signingRootId),
    signingRootVersion: toOptionalTrimmedString(prepare.signingRootVersion),
    keyScope: toOptionalTrimmedString(prepare.keyScope),
    relayerKeyId: toOptionalTrimmedString(prepare.relayerKeyId),
    requestId: toOptionalTrimmedString(prepare.requestId),
    thresholdSessionId: toOptionalTrimmedString(prepare.thresholdSessionId),
    signingGrantId: toOptionalTrimmedString(prepare.signingGrantId),
  };
  if (
    required.formatVersion !== 'ecdsa-hss-role-local' ||
    required.keyScope !== 'evm-family' ||
    !required.walletId ||
    !required.rpId ||
    !required.ecdsaThresholdKeyId ||
    !required.signingRootId ||
    !required.signingRootVersion ||
    !required.relayerKeyId ||
    !required.requestId ||
    !required.thresholdSessionId ||
    !required.signingGrantId ||
    ttlMs === undefined ||
    remainingUses === undefined ||
    !participantIds
  ) {
    return null;
  }
  return {
    kind: 'evm_family_ecdsa_keygen',
    chainTargets: chainTargets as WalletRegistrationEcdsaPreparePayload['chainTargets'],
    prepare: {
      formatVersion: 'ecdsa-hss-role-local',
      walletId: required.walletId,
      rpId: required.rpId,
      ecdsaThresholdKeyId: required.ecdsaThresholdKeyId,
      signingRootId: required.signingRootId,
      signingRootVersion: required.signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId: required.relayerKeyId,
      requestId: required.requestId,
      thresholdSessionId: required.thresholdSessionId,
      signingGrantId: required.signingGrantId,
      ttlMs,
      remainingUses,
      participantIds,
      ...(isObject(prepare.runtimePolicyScope)
        ? {
            runtimePolicyScope:
              prepare.runtimePolicyScope as WalletRegistrationEcdsaPreparePayload['prepare']['runtimePolicyScope'],
          }
        : {}),
    },
  };
}

function parseEmailRecoveryPreparationRecord(raw: unknown): EmailRecoveryPreparationRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const requestId = toOptionalTrimmedString(raw.requestId);
  const accountId = toOptionalTrimmedString(raw.accountId);
  const walletBinding = parseEmailRecoveryResolvedWalletBinding(raw.walletBinding);
  const rpId = toOptionalTrimmedString(raw.rpId);
  const signerSlot = parsePositiveInteger(raw.signerSlot);
  const credentialIdB64u = toOptionalTrimmedString(raw.credentialIdB64u);
  const credentialPublicKeyB64u = toOptionalTrimmedString(raw.credentialPublicKeyB64u);
  const counter = parseNonNegativeInteger(raw.counter);
  const createdAtMs = parsePositiveInteger(raw.createdAtMs);
  const expiresAtMs = parsePositiveInteger(raw.expiresAtMs);
  const thresholdEd25519 = parsePreparedThresholdEd25519(raw.thresholdEd25519);
  const ecdsa = parseEcdsaPreparePayload(raw.ecdsa);
  if (
    version !== 'email_recovery_preparation_v1' ||
    !requestId ||
    !accountId ||
    !walletBinding ||
    !rpId ||
    !signerSlot ||
    !credentialIdB64u ||
    !credentialPublicKeyB64u ||
    counter === undefined ||
    !createdAtMs ||
    !expiresAtMs ||
    !thresholdEd25519 ||
    !ecdsa
  ) {
    return null;
  }
  return {
    version: 'email_recovery_preparation_v1',
    requestId,
    accountId,
    walletBinding,
    rpId,
    signerSlot,
    credentialIdB64u,
    credentialPublicKeyB64u,
    counter,
    createdAtMs,
    expiresAtMs,
    thresholdEd25519,
    ecdsa,
    ...(isObject(raw.existingRuntimePolicyScope)
      ? {
          existingRuntimePolicyScope: raw.existingRuntimePolicyScope as ThresholdRuntimePolicyScope,
        }
      : {}),
  };
}

class InMemoryEmailRecoveryPreparationStore implements EmailRecoveryPreparationStore {
  private readonly namespace: string;
  private readonly map = new Map<string, EmailRecoveryPreparationRecord>();

  constructor(input: { namespace: string }) {
    this.namespace = input.namespace;
  }

  private key(requestId: string): string {
    return `${this.namespace}${requestId}`;
  }

  async get(requestId: string): Promise<EmailRecoveryPreparationRecord | null> {
    const id = toOptionalTrimmedString(requestId);
    if (!id) return null;
    const parsed = parseEmailRecoveryPreparationRecord(this.map.get(this.key(id)));
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) {
      this.map.delete(this.key(id));
      return null;
    }
    return parsed;
  }

  async put(record: EmailRecoveryPreparationRecord): Promise<void> {
    const parsed = parseEmailRecoveryPreparationRecord(record);
    if (!parsed) throw new Error('Invalid email recovery preparation record');
    this.map.set(this.key(parsed.requestId), parsed);
  }

  async del(requestId: string): Promise<void> {
    const id = toOptionalTrimmedString(requestId);
    if (!id) return;
    this.map.delete(this.key(id));
  }
}

class PostgresEmailRecoveryPreparationStore implements EmailRecoveryPreparationStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(requestId: string): Promise<EmailRecoveryPreparationRecord | null> {
    const id = toOptionalTrimmedString(requestId);
    if (!id) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM email_recovery_preparations
        WHERE namespace = $1 AND request_id = $2 AND expires_at_ms > $3
      `,
      [this.namespace, id, nowMs],
    );
    return parseEmailRecoveryPreparationRecord(rows[0]?.record_json);
  }

  async put(record: EmailRecoveryPreparationRecord): Promise<void> {
    const parsed = parseEmailRecoveryPreparationRecord(record);
    if (!parsed) throw new Error('Invalid email recovery preparation record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_recovery_preparations (namespace, request_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (namespace, request_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, parsed.requestId, parsed, parsed.expiresAtMs],
    );
  }

  async del(requestId: string): Promise<void> {
    const id = toOptionalTrimmedString(requestId);
    if (!id) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM email_recovery_preparations WHERE namespace = $1 AND request_id = $2',
      [this.namespace, id],
    );
  }
}

class UpstashRedisRestEmailRecoveryPreparationStore implements EmailRecoveryPreparationStore {
  private readonly client: UpstashRedisRestClient;
  private readonly prefix: string;

  constructor(input: { url: string; token: string; prefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.prefix = input.prefix;
  }

  private key(requestId: string): string {
    return `${this.prefix}${requestId}`;
  }

  async get(requestId: string): Promise<EmailRecoveryPreparationRecord | null> {
    const id = toOptionalTrimmedString(requestId);
    if (!id) return null;
    const raw = await this.client.getJson(this.key(id));
    const parsed = parseEmailRecoveryPreparationRecord(raw);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) {
      await this.del(id);
      return null;
    }
    return parsed;
  }

  async put(record: EmailRecoveryPreparationRecord): Promise<void> {
    const parsed = parseEmailRecoveryPreparationRecord(record);
    if (!parsed) throw new Error('Invalid email recovery preparation record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    await this.client.setJson(this.key(parsed.requestId), parsed, ttlMs);
  }

  async del(requestId: string): Promise<void> {
    const id = toOptionalTrimmedString(requestId);
    if (!id) return;
    await this.client.del(this.key(id));
  }
}

class RedisTcpEmailRecoveryPreparationStore implements EmailRecoveryPreparationStore {
  private readonly client: RedisTcpClient;
  private readonly prefix: string;

  constructor(input: { redisUrl: string; prefix: string }) {
    this.client = new RedisTcpClient(input.redisUrl);
    this.prefix = input.prefix;
  }

  private key(requestId: string): string {
    return `${this.prefix}${requestId}`;
  }

  async get(requestId: string): Promise<EmailRecoveryPreparationRecord | null> {
    const id = toOptionalTrimmedString(requestId);
    if (!id) return null;
    const raw = await redisGetJson(this.client, this.key(id));
    const parsed = parseEmailRecoveryPreparationRecord(raw);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) {
      await this.del(id);
      return null;
    }
    return parsed;
  }

  async put(record: EmailRecoveryPreparationRecord): Promise<void> {
    const parsed = parseEmailRecoveryPreparationRecord(record);
    if (!parsed) throw new Error('Invalid email recovery preparation record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    await redisSetJson(this.client, this.key(parsed.requestId), parsed, ttlMs);
  }

  async del(requestId: string): Promise<void> {
    const id = toOptionalTrimmedString(requestId);
    if (!id) return;
    await redisDel(this.client, this.key(id));
  }
}

export function createEmailRecoveryPreparationStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): EmailRecoveryPreparationStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const namespace = toEmailRecoveryPreparationPrefix(config);
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const kind = toOptionalTrimmedString(config.kind);

  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[email-recovery] In-memory preparation store is not supported in this runtime; configure Upstash/Redis',
      );
    }
    input.logger.info('[email-recovery] Using in-memory preparation store (non-persistent)');
    return new InMemoryEmailRecoveryPreparationStore({ namespace });
  }
  if (kind === 'upstash-redis-rest') {
    const url =
      toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token =
      toOptionalTrimmedString(config.token) ||
      toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token) {
      throw new Error(
        '[email-recovery] upstash-redis-rest preparation store enabled but url/token are not both set',
      );
    }
    input.logger.info('[email-recovery] Using Upstash REST preparation store');
    return new UpstashRedisRestEmailRecoveryPreparationStore({ url, token, prefix: namespace });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[email-recovery] redis-tcp preparation store is not supported in this runtime; configure Upstash/Redis REST',
        );
      }
      input.logger.warn(
        '[email-recovery] redis-tcp preparation store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEmailRecoveryPreparationStore({ namespace });
    }
    const redisUrl =
      toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl)
      throw new Error(
        '[email-recovery] redis-tcp preparation store enabled but REDIS_URL is not set',
      );
    input.logger.info('[email-recovery] Using redis-tcp preparation store');
    return new RedisTcpEmailRecoveryPreparationStore({ redisUrl, prefix: namespace });
  }
  if (kind === 'postgres') {
    if (!input.isNode)
      throw new Error(
        '[email-recovery] postgres preparation store is not supported in this runtime',
      );
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error(
        '[email-recovery] postgres preparation store enabled but POSTGRES_URL is not set',
      );
    input.logger.info('[email-recovery] Using Postgres preparation store');
    return new PostgresEmailRecoveryPreparationStore({ postgresUrl, namespace });
  }

  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        '[email-recovery] Upstash preparation store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[email-recovery] Using Upstash REST preparation store');
    return new UpstashRedisRestEmailRecoveryPreparationStore({
      url: upstashUrl,
      token: upstashToken,
      prefix: namespace,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[email-recovery] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST',
        );
      }
      input.logger.warn(
        '[email-recovery] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEmailRecoveryPreparationStore({ namespace });
    }
    input.logger.info('[email-recovery] Using redis-tcp preparation store');
    return new RedisTcpEmailRecoveryPreparationStore({ redisUrl, prefix: namespace });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode)
      throw new Error(
        '[email-recovery] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    input.logger.info('[email-recovery] Using Postgres preparation store');
    return new PostgresEmailRecoveryPreparationStore({ postgresUrl, namespace });
  }

  if (requirePersistent) {
    throw new Error(
      '[email-recovery] Email recovery preparations require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN',
    );
  }

  input.logger.info('[email-recovery] Using in-memory preparation store (non-persistent)');
  return new InMemoryEmailRecoveryPreparationStore({ namespace });
}
