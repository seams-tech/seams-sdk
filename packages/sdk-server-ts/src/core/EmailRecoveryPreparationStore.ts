import type { NormalizedLogger } from './logger';
import type {
  ThresholdEd25519AuthorityScope,
  ThresholdEd25519BootstrapSession,
  ThresholdRuntimePolicyScope,
  ThresholdStoreConfigInput
} from './types';
import type {
  WalletRegistrationEcdsaPreparePayload
} from './registrationContracts';
import { THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { parseThresholdEd25519AuthorityScope } from './ThresholdService/validation';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetJson,
  redisSetJson,
} from './ThresholdService/kv';
import {
  formatD1ExecStatement,
  parseD1JsonColumn,
  resolveD1DatabaseFromConfig,
} from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';

export type EmailRecoveryPreparedThresholdEd25519Record = {
  relayerKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
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
  nearEd25519SigningKeyId: string;
  rpId: string;
  credentialIdB64u: string;
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

export interface D1EmailRecoveryPreparationStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1EmailRecoveryPreparationStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

type NormalizedD1EmailRecoveryPreparationStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
  readonly now: () => Date;
};

type D1EmailRecoveryPreparationScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1EmailRecoveryPreparationRow = {
  readonly record_json?: unknown;
};

export const EMAIL_RECOVERY_PREPARATION_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS email_recovery_preparations (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      request_id TEXT NOT NULL,
      account_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      rp_id TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, request_id),
      CHECK (length(namespace) > 0),
      CHECK (length(org_id) > 0),
      CHECK (length(project_id) > 0),
      CHECK (length(env_id) > 0),
      CHECK (length(request_id) > 0),
      CHECK (length(account_id) > 0),
      CHECK (length(wallet_id) > 0),
      CHECK (length(rp_id) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (expires_at_ms > created_at_ms),
      CHECK (
        COALESCE(json_extract(record_json, '$.version') = 'email_recovery_preparation_v1', 0)
      ),
      CHECK (COALESCE(json_extract(record_json, '$.requestId') = request_id, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.accountId') = account_id, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.rpId') = rp_id, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.walletBinding.walletId') = wallet_id, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_recovery_preparations_expires_idx
      ON email_recovery_preparations (
        namespace,
        org_id,
        project_id,
        env_id,
        expires_at_ms
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_recovery_preparations_account_idx
      ON email_recovery_preparations (
        namespace,
        org_id,
        project_id,
        env_id,
        account_id,
        created_at_ms
      )
  `,
] as const);

export async function ensureEmailRecoveryPreparationStoreD1Schema(
  options: D1EmailRecoveryPreparationStoreSchemaOptions,
): Promise<void> {
  for (const statement of EMAIL_RECOVERY_PREPARATION_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function defaultNow(): Date {
  return new Date();
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
  const nearEd25519SigningKeyId = toOptionalTrimmedString(raw.nearEd25519SigningKeyId);
  const authorityScope = parseThresholdEd25519AuthorityScope(raw.authorityScope);
  const thresholdSessionId = toOptionalTrimmedString(raw.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(raw.signingGrantId);
  const expiresAtMs = parsePositiveInteger(raw.expiresAtMs);
  if (
    (sessionKind !== 'jwt' && sessionKind !== 'cookie') ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !authorityScope ||
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
    nearEd25519SigningKeyId,
    authorityScope,
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
  const nearEd25519SigningKeyId = toOptionalTrimmedString(raw.nearEd25519SigningKeyId);
  const rpId = toOptionalTrimmedString(raw.rpId);
  const credentialIdB64u = toOptionalTrimmedString(raw.credentialIdB64u);
  const signerSlot = parsePositiveInteger(raw.signerSlot);
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !rpId ||
    !credentialIdB64u ||
    !signerSlot
  ) {
    return null;
  }
  return {
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId,
    credentialIdB64u,
    signerSlot,
  };
}

function parsePreparedThresholdEd25519(
  raw: unknown,
): EmailRecoveryPreparedThresholdEd25519Record | null {
  if (!isObject(raw)) return null;
  const relayerKeyId = toOptionalTrimmedString(raw.relayerKeyId);
  const authorityScope = parseThresholdEd25519AuthorityScope(raw.authorityScope);
  const publicKey = toOptionalTrimmedString(raw.publicKey);
  const keyVersion = toOptionalTrimmedString(raw.keyVersion);
  const recoveryExportCapable = raw.recoveryExportCapable === true;
  if (!relayerKeyId || !authorityScope || !publicKey || !keyVersion || !recoveryExportCapable)
    return null;
  const clientParticipantId = parsePositiveInteger(raw.clientParticipantId);
  const relayerParticipantId = parsePositiveInteger(raw.relayerParticipantId);
  const participantIds = parseParticipantIds(raw.participantIds);
  const session = parseThresholdEd25519Session(raw.session);
  return {
    relayerKeyId,
    authorityScope,
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
    evmFamilySigningKeySlotId: toOptionalTrimmedString(prepare.evmFamilySigningKeySlotId),
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
    !required.evmFamilySigningKeySlotId ||
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
      evmFamilySigningKeySlotId: required.evmFamilySigningKeySlotId,
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

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) {
    throw new Error(`${field} is required for D1 email recovery preparation store`);
  }
  return normalized;
}

function normalizeD1EmailRecoveryPreparationStoreOptions(
  input: D1EmailRecoveryPreparationStoreOptions,
): NormalizedD1EmailRecoveryPreparationStoreOptions {
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
}): Omit<D1EmailRecoveryPreparationStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
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

export class D1EmailRecoveryPreparationStore implements EmailRecoveryPreparationStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1EmailRecoveryPreparationScope;
  private readonly ensureSchemaOnUse: boolean;
  private readonly now: () => Date;
  private schemaReady = false;

  constructor(input: D1EmailRecoveryPreparationStoreOptions) {
    const normalized = normalizeD1EmailRecoveryPreparationStoreOptions(input);
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
    await ensureEmailRecoveryPreparationStoreD1Schema({ database: this.database });
    this.schemaReady = true;
  }

  private bindScope(statement: string, values: readonly unknown[] = []) {
    return this.database
      .prepare(statement)
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        ...values,
      );
  }

  async get(requestId: string): Promise<EmailRecoveryPreparationRecord | null> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(requestId);
    if (!id) return null;
    const row = await this.bindScope(
      `SELECT record_json
         FROM email_recovery_preparations
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND request_id = ?
          AND expires_at_ms > ?
        LIMIT 1`,
      [id, this.now().getTime()],
    ).first<D1EmailRecoveryPreparationRow>();
    return parseEmailRecoveryPreparationRecord(parseD1JsonColumn(row?.record_json));
  }

  async put(record: EmailRecoveryPreparationRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseEmailRecoveryPreparationRecord(record);
    if (!parsed) throw new Error('Invalid email recovery preparation record');
    await this.bindScope(
      `INSERT INTO email_recovery_preparations (
        namespace,
        org_id,
        project_id,
        env_id,
        request_id,
        account_id,
        wallet_id,
        rp_id,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, request_id)
      DO UPDATE SET
        account_id = EXCLUDED.account_id,
        wallet_id = EXCLUDED.wallet_id,
        rp_id = EXCLUDED.rp_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        parsed.requestId,
        parsed.accountId,
        parsed.walletBinding.walletId,
        parsed.rpId,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.expiresAtMs,
      ],
    ).run();
  }

  async del(requestId: string): Promise<void> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(requestId);
    if (!id) return;
    await this.bindScope(
      `DELETE FROM email_recovery_preparations
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND request_id = ?`,
      [id],
    ).run();
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

  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error(
        '[email-recovery] D1 preparation store selected but no D1 database was provided',
      );
    }
    input.logger.info('[email-recovery] Using D1 preparation store');
    return new D1EmailRecoveryPreparationStore({
      database,
      ...d1ScopeFromConfig({ config, namespace }),
    });
  }

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
  if (kind) throw new Error(`[email-recovery] Unknown preparation store kind: ${kind}`);

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

  if (requirePersistent) {
    throw new Error(
      '[email-recovery] Email recovery preparations require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN',
    );
  }

  input.logger.info('[email-recovery] Using in-memory preparation store (non-persistent)');
  return new InMemoryEmailRecoveryPreparationStore({ namespace });
}
