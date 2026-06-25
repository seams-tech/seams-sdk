import type { NormalizedLogger } from '../../logger';
import type { RouterAbEcdsaHssNormalSigningScopeV1 } from '@shared/utils/routerAbEcdsaHss';
import type {
  ThresholdEcdsaSigningRootMetadata,
  ThresholdStoreConfigInput,
} from '../../types';
import { RedisTcpClient, UpstashRedisRestClient, redisGetdelJson, redisSetJson } from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  getPostgresPool,
  getPostgresUrlFromConfig,
  parsePostgresRow,
} from '../../../storage/postgres';
import {
  parseCurrentRouterAbEcdsaHssPoolFillSessionRecord,
  parseCurrentRouterAbEcdsaHssPoolFillSessionRow,
  parseCurrentRouterAbEcdsaHssServerPresignatureRecord,
} from '../postgresRecords';
import {
  isObject,
  parseRouterAbEcdsaHssPoolFillSessionRecord,
  parseRouterAbEcdsaHssServerPresignatureShareRecord,
  toThresholdEcdsaPresignPrefix,
  toThresholdEcdsaPrefixFromBase,
} from '../validation';
import { createCloudflareDurableObjectThresholdEcdsaStores } from './CloudflareDurableObjectStore';
import { secureRandomIdFragment } from '../secureRandomId';

export type RouterAbEcdsaHssServerPresignatureShareRecord = {
  relayerKeyId: string;
  presignatureId: string;
  bigRB64u: string;
  /** Base64url-encoded scalar share for k^{-1}. */
  kShareB64u: string;
  /** Base64url-encoded scalar share for x*k^{-1}. */
  sigmaShareB64u: string;
  createdAtMs: number;
};

export type RouterAbEcdsaHssPoolFillSessionStage = 'triples' | 'triples_done' | 'presign' | 'done';

export type RouterAbEcdsaHssPoolFillSessionDestination =
  | {
      kind: 'local_threshold_ecdsa_presignature_pool';
      routerAbEcdsaHss?: never;
    }
  | {
      kind: 'router_ab_ecdsa_hss_signing_worker_pool';
      routerAbEcdsaHss: {
        scope: RouterAbEcdsaHssNormalSigningScopeV1;
        expiresAtMs: number;
      };
    };

export type RouterAbEcdsaHssPoolFillSessionRecord = {
  expiresAtMs: number;
  walletId: string;
  walletKeyId: string;
  relayerKeyId: string;
  presignPoolKey: string;
  poolFill: RouterAbEcdsaHssPoolFillSessionDestination;
  ownerInstanceId?: string;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  stage: RouterAbEcdsaHssPoolFillSessionStage;
  version: number;
  createdAtMs: number;
  updatedAtMs: number;
} & ThresholdEcdsaSigningRootMetadata;

export type RouterAbEcdsaHssPoolFillSessionCasResult =
  | { ok: true; record: RouterAbEcdsaHssPoolFillSessionRecord }
  | { ok: false; code: 'not_found' | 'expired' | 'version_mismatch' };

export interface RouterAbEcdsaHssPoolFillSessionStore {
  createSession(
    id: string,
    record: RouterAbEcdsaHssPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }>;
  getSession(id: string): Promise<RouterAbEcdsaHssPoolFillSessionRecord | null>;
  advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaHssPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaHssPoolFillSessionCasResult>;
  deleteSession(id: string): Promise<void>;
}

export interface RouterAbEcdsaHssPresignaturePool {
  reserve(relayerKeyId: string): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null>;
  reserveById(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null>;
  consume(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null>;
  discard(relayerKeyId: string, presignatureId: string): Promise<void>;
  put(record: RouterAbEcdsaHssServerPresignatureShareRecord): Promise<void>;
}

export class InMemoryRouterAbEcdsaHssPoolFillSessionStore implements RouterAbEcdsaHssPoolFillSessionStore {
  private readonly map = new Map<
    string,
    { value: RouterAbEcdsaHssPoolFillSessionRecord; expiresAtMs: number }
  >();

  async createSession(
    id: string,
    record: RouterAbEcdsaHssPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');

    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');

    const existing = this.map.get(key);
    const nowMs = Date.now();
    if (existing && existing.expiresAtMs > nowMs) {
      return { ok: false, code: 'exists' };
    }

    const expiresAtMs = nowMs + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: parsed, expiresAtMs });
    return { ok: true };
  }

  async getSession(id: string): Promise<RouterAbEcdsaHssPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return entry.value;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaHssPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaHssPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const entry = this.map.get(key);
    if (!entry) return { ok: false, code: 'not_found' };

    const nowMs = Date.now();
    if (nowMs > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'expired' };
    }

    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1) {
      return { ok: false, code: 'version_mismatch' };
    }
    if (entry.value.version !== expectedVersion) {
      return { ok: false, code: 'version_mismatch' };
    }

    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');
    const expiresAtMs = nowMs + Math.max(0, Number(input.ttlMs) || 0);
    this.map.set(key, { value: parsed, expiresAtMs });
    return { ok: true, record: parsed };
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    this.map.delete(key);
  }
}

export class InMemoryRouterAbEcdsaHssPresignaturePool implements RouterAbEcdsaHssPresignaturePool {
  private readonly availableByKey = new Map<
    string,
    RouterAbEcdsaHssServerPresignatureShareRecord[]
  >();
  private readonly reservedByKey = new Map<
    string,
    Map<string, { value: RouterAbEcdsaHssServerPresignatureShareRecord; expiresAtMs: number }>
  >();
  private readonly reservationTtlMs: number;

  constructor(input?: { reservationTtlMs?: number }) {
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input?.reservationTtlMs) || 120_000));
  }

  private gc(relayerKeyId: string): void {
    const reserved = this.reservedByKey.get(relayerKeyId);
    if (!reserved) return;
    const now = Date.now();
    for (const [id, entry] of reserved.entries()) {
      if (now > entry.expiresAtMs) reserved.delete(id);
    }
    if (reserved.size === 0) this.reservedByKey.delete(relayerKeyId);
  }

  async put(record: RouterAbEcdsaHssServerPresignatureShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const presignatureId = toOptionalTrimmedString(record.presignatureId);
    if (!relayerKeyId || !presignatureId) throw new Error('Missing relayerKeyId/presignatureId');

    const list = this.availableByKey.get(relayerKeyId) || [];
    list.push(record);
    this.availableByKey.set(relayerKeyId, list);
  }

  async reserve(
    relayerKeyId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    this.gc(key);
    const list = this.availableByKey.get(key);
    if (!list || list.length === 0) return null;
    const record = list.shift()!;
    this.availableByKey.set(key, list);

    let reserved = this.reservedByKey.get(key);
    if (!reserved) {
      reserved = new Map();
      this.reservedByKey.set(key, reserved);
    }
    reserved.set(record.presignatureId, {
      value: record,
      expiresAtMs: Date.now() + this.reservationTtlMs,
    });
    return record;
  }

  async reserveById(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    this.gc(key);
    const list = this.availableByKey.get(key);
    if (!list || list.length === 0) return null;
    const idx = list.findIndex((entry) => entry.presignatureId === id);
    if (idx < 0) return null;
    const [record] = list.splice(idx, 1);
    if (!record) return null;
    this.availableByKey.set(key, list);

    let reserved = this.reservedByKey.get(key);
    if (!reserved) {
      reserved = new Map();
      this.reservedByKey.set(key, reserved);
    }
    reserved.set(record.presignatureId, {
      value: record,
      expiresAtMs: Date.now() + this.reservationTtlMs,
    });
    return record;
  }

  async consume(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    this.gc(key);
    const reserved = this.reservedByKey.get(key);
    if (!reserved) return null;
    const entry = reserved.get(id) || null;
    reserved.delete(id);
    if (reserved.size === 0) this.reservedByKey.delete(key);
    return entry?.value || null;
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return;
    this.gc(key);
    const reserved = this.reservedByKey.get(key);
    reserved?.delete(id);
    if (reserved && reserved.size === 0) this.reservedByKey.delete(key);
  }
}

class UpstashRedisRestRouterAbEcdsaHssPoolFillSessionStore implements RouterAbEcdsaHssPoolFillSessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async createSession(
    id: string,
    record: RouterAbEcdsaHssPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_SESSION_CREATE_LUA,
        [this.key(key)],
        [JSON.stringify(parsed), String(toRedisMilliseconds(ttlMs)), String(Date.now())],
      );
      if (raw === 'ok') return { ok: true };
      if (raw === 'exists') return { ok: false, code: 'exists' };
      throw new Error(`[threshold-ecdsa] Unexpected Upstash CAS-create result: ${String(raw)}`);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || '',
      );
      if (isEvalUnsupportedError(msg)) {
        throw new Error(
          '[threshold-ecdsa] Upstash EVAL is required for atomic presign-session CAS; ensure scripting is enabled',
        );
      }
      throw e;
    }
  }

  async getSession(id: string): Promise<RouterAbEcdsaHssPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const record = parseRouterAbEcdsaHssPoolFillSessionRecordFromRaw(await this.client.getJson(this.key(key)));
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) {
      await this.client.del(this.key(key));
      return null;
    }
    return record;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaHssPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaHssPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1)
      return { ok: false, code: 'version_mismatch' };
    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_SESSION_CAS_LUA,
        [this.key(key)],
        [
          String(expectedVersion),
          JSON.stringify(parsed),
          String(toRedisMilliseconds(input.ttlMs)),
          String(Date.now()),
        ],
      );
      return parsePresignSessionCasLuaResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || '',
      );
      if (isEvalUnsupportedError(msg)) {
        throw new Error(
          '[threshold-ecdsa] Upstash EVAL is required for atomic presign-session CAS; ensure scripting is enabled',
        );
      }
      throw e;
    }
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    await this.client.del(this.key(key));
  }
}

class RedisTcpRouterAbEcdsaHssPoolFillSessionStore implements RouterAbEcdsaHssPoolFillSessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp presign session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async createSession(
    id: string,
    record: RouterAbEcdsaHssPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_SESSION_CREATE_LUA,
      '1',
      this.key(key),
      JSON.stringify(parsed),
      String(toRedisMilliseconds(ttlMs)),
      String(Date.now()),
    ]);
    if (evalResp.type === 'bulk' || evalResp.type === 'simple') {
      const raw = evalResp.value;
      if (raw === 'ok') return { ok: true };
      if (raw === 'exists') return { ok: false, code: 'exists' };
      throw new Error(`[threshold-ecdsa] Unexpected redis CAS-create result: ${String(raw)}`);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error(
          '[threshold-ecdsa] Redis EVAL is required for atomic presign-session CAS; enable scripting permissions',
        );
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(
      `[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`,
    );
  }

  async getSession(id: string): Promise<RouterAbEcdsaHssPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const raw = await this.client.send(['GET', this.key(key)]);
    if (raw.type === 'error') throw new Error(`Redis GET error: ${raw.value}`);
    if (raw.type !== 'bulk' || raw.value === null) return null;
    const record = parseRouterAbEcdsaHssPoolFillSessionRecordFromRaw(raw.value);
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) {
      await this.deleteSession(key);
      return null;
    }
    return record;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaHssPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaHssPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1)
      return { ok: false, code: 'version_mismatch' };
    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_SESSION_CAS_LUA,
      '1',
      this.key(key),
      String(expectedVersion),
      JSON.stringify(parsed),
      String(toRedisMilliseconds(input.ttlMs)),
      String(Date.now()),
    ]);
    if (evalResp.type === 'bulk' || evalResp.type === 'simple') {
      return parsePresignSessionCasLuaResult(evalResp.value);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error(
          '[threshold-ecdsa] Redis EVAL is required for atomic presign-session CAS; enable scripting permissions',
        );
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(
      `[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`,
    );
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    const resp = await this.client.send(['DEL', this.key(key)]);
    if (resp.type === 'error') throw new Error(`Redis DEL error: ${resp.value}`);
  }
}

class PostgresRouterAbEcdsaHssPoolFillSessionStore implements RouterAbEcdsaHssPoolFillSessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  private async deleteMalformedSession(id: string): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM threshold_ecdsa_presign_sessions
        WHERE namespace = $1 AND presign_session_id = $2
      `,
      [this.namespace, id],
    );
  }

  async createSession(
    id: string,
    record: RouterAbEcdsaHssPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseCurrentRouterAbEcdsaHssPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');
    const ttl = Math.max(0, Number(ttlMs) || 0);
    const nowMs = Date.now();
    const expiresAtMs = nowMs + ttl;
    const storedRecord = {
      ...parsed,
      expiresAtMs,
      updatedAtMs: nowMs,
    } satisfies RouterAbEcdsaHssPoolFillSessionRecord;
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        INSERT INTO threshold_ecdsa_presign_sessions (
          namespace,
          presign_session_id,
          record_json,
          stage,
          version,
          expires_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (namespace, presign_session_id) DO NOTHING
        RETURNING presign_session_id
      `,
      [
        this.namespace,
        key,
        storedRecord,
        storedRecord.stage,
        storedRecord.version,
        expiresAtMs,
        storedRecord.updatedAtMs,
      ],
    );
    if (Array.isArray(result.rows) && result.rows.length > 0) {
      return { ok: true };
    }
    return { ok: false, code: 'exists' };
  }

  async getSession(id: string): Promise<RouterAbEcdsaHssPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const nowMs = Date.now();
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms
        FROM threshold_ecdsa_presign_sessions
        WHERE namespace = $1 AND presign_session_id = $2
      `,
      [this.namespace, key],
    );
    const parsedRow = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentRouterAbEcdsaHssPoolFillSessionRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        }),
    });
    if (parsedRow.kind === 'missing') {
      return null;
    }
    if (parsedRow.kind === 'malformed') {
      await this.deleteMalformedSession(key);
      return null;
    }
    if (parsedRow.value.expiresAtMs <= nowMs) return null;
    return parsedRow.value.record;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: RouterAbEcdsaHssPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaHssPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1) {
      return { ok: false, code: 'version_mismatch' };
    }
    const parsed = parseCurrentRouterAbEcdsaHssPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');

    const ttl = Math.max(0, Number(input.ttlMs) || 0);
    const nowMs = Date.now();
    const expiresAtMs = nowMs + ttl;
    const storedRecord = {
      ...parsed,
      expiresAtMs,
      updatedAtMs: nowMs,
    } satisfies RouterAbEcdsaHssPoolFillSessionRecord;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        UPDATE threshold_ecdsa_presign_sessions
        SET
          record_json = $4,
          stage = $5,
          version = $6,
          expires_at_ms = $7,
          updated_at_ms = $8
        WHERE namespace = $1
          AND presign_session_id = $2
          AND version = $3
          AND expires_at_ms > $8
        RETURNING record_json, expires_at_ms
      `,
      [
        this.namespace,
        key,
        expectedVersion,
        storedRecord,
        storedRecord.stage,
        storedRecord.version,
        expiresAtMs,
        nowMs,
      ],
    );
    const row = rows[0] as { record_json?: unknown; expires_at_ms?: unknown } | undefined;
    if (row) {
      const updated = parseCurrentRouterAbEcdsaHssPoolFillSessionRow({
        recordJson: row.record_json,
        expiresAtMs: row.expires_at_ms,
      });
      if (!updated) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record after CAS');
      return { ok: true, record: updated.record };
    }

    const existing = await pool.query(
      `
        SELECT version, expires_at_ms
        FROM threshold_ecdsa_presign_sessions
        WHERE namespace = $1 AND presign_session_id = $2
      `,
      [this.namespace, key],
    );
    const existingRow = existing.rows[0] as
      | { version?: unknown; expires_at_ms?: unknown }
      | undefined;
    if (!existingRow) return { ok: false, code: 'not_found' };
    const existingExpiresAtMs =
      typeof existingRow.expires_at_ms === 'number'
        ? existingRow.expires_at_ms
        : Number(existingRow.expires_at_ms);
    if (!Number.isFinite(existingExpiresAtMs) || existingExpiresAtMs <= nowMs) {
      return { ok: false, code: 'expired' };
    }
    return { ok: false, code: 'version_mismatch' };
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM threshold_ecdsa_presign_sessions
        WHERE namespace = $1 AND presign_session_id = $2
      `,
      [this.namespace, key],
    );
  }
}

function parseJson(raw: string): unknown | null {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

const ECDSA_PRESIGN_RESERVE_LUA = `
local listKey = KEYS[1]
local reservedKeyPrefix = KEYS[2]
local ttlSeconds = tonumber(ARGV[1]) or 120
local maxAttempts = tonumber(ARGV[2]) or 8

for _ = 1, maxAttempts do
  local item = redis.call('LPOP', listKey)
  if not item then
    return nil
  end
  local ok, decoded = pcall(cjson.decode, item)
  if ok and type(decoded) == 'table' then
    local presignatureId = decoded['presignatureId']
    if type(presignatureId) == 'string' and presignatureId ~= '' then
      redis.call('SET', reservedKeyPrefix .. presignatureId, item, 'EX', ttlSeconds)
      return item
    end
  end
end

return nil
`.trim();

const ECDSA_PRESIGN_RESERVE_BY_ID_LUA = `
local listKey = KEYS[1]
local reservedKey = KEYS[2]
local requestedId = ARGV[1]
local ttlSeconds = tonumber(ARGV[2]) or 120
local marker = ARGV[3]

if type(requestedId) ~= 'string' or requestedId == '' then
  return nil
end
if type(marker) ~= 'string' or marker == '' then
  marker = '__seams_threshold_ecdsa_presign_deleted__'
end

local len = redis.call('LLEN', listKey)
for i = 0, len - 1 do
  local item = redis.call('LINDEX', listKey, i)
  if item then
    local ok, decoded = pcall(cjson.decode, item)
    if ok and type(decoded) == 'table' then
      local presignatureId = decoded['presignatureId']
      if presignatureId == requestedId then
        redis.call('LSET', listKey, i, marker)
        redis.call('LREM', listKey, 1, marker)
        redis.call('SET', reservedKey, item, 'EX', ttlSeconds)
        return item
      end
    end
  end
end

return nil
`.trim();

const ECDSA_PRESIGN_SESSION_CREATE_LUA = `
local key = KEYS[1]
local value = ARGV[1]
local ttlMs = tonumber(ARGV[2]) or 0
local nowMs = tonumber(ARGV[3]) or 0

local existing = redis.call('GET', key)
if existing then
  local ok, decoded = pcall(cjson.decode, existing)
  if ok and type(decoded) == 'table' then
    local expiresAtMs = tonumber(decoded['expiresAtMs']) or 0
    if expiresAtMs > nowMs then
      return 'exists'
    end
  else
    return 'exists'
  end
end

if ttlMs > 0 then
  redis.call('SET', key, value, 'PX', ttlMs)
else
  redis.call('SET', key, value)
end
return 'ok'
`.trim();

const ECDSA_PRESIGN_SESSION_CAS_LUA = `
local key = KEYS[1]
local expectedVersion = tonumber(ARGV[1]) or -1
local nextValue = ARGV[2]
local ttlMs = tonumber(ARGV[3]) or 0
local nowMs = tonumber(ARGV[4]) or 0

local raw = redis.call('GET', key)
if not raw then
  return '__err__:not_found'
end

local ok, decoded = pcall(cjson.decode, raw)
if (not ok) or type(decoded) ~= 'table' then
  return '__err__:not_found'
end

local expiresAtMs = tonumber(decoded['expiresAtMs']) or 0
if expiresAtMs <= nowMs then
  redis.call('DEL', key)
  return '__err__:expired'
end

local version = tonumber(decoded['version']) or -1
if version ~= expectedVersion then
  return '__err__:version_mismatch'
end

if ttlMs > 0 then
  redis.call('SET', key, nextValue, 'PX', ttlMs)
else
  redis.call('SET', key, nextValue)
end

return nextValue
`.trim();

function toRedisSeconds(ms: number): number {
  return Math.max(1, Math.ceil(Math.max(0, Number(ms) || 0) / 1000));
}

function toRedisMilliseconds(ms: number): number {
  return Math.max(1, Math.ceil(Math.max(0, Number(ms) || 0)));
}

function parsePresignatureRecordFromRaw(
  raw: unknown,
): RouterAbEcdsaHssServerPresignatureShareRecord | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'string') {
    return parseRouterAbEcdsaHssServerPresignatureShareRecord(
      parseJson(raw),
    ) as RouterAbEcdsaHssServerPresignatureShareRecord | null;
  }
  return parseRouterAbEcdsaHssServerPresignatureShareRecord(
    raw,
  ) as RouterAbEcdsaHssServerPresignatureShareRecord | null;
}

function parseRouterAbEcdsaHssPoolFillSessionRecordFromRaw(raw: unknown): RouterAbEcdsaHssPoolFillSessionRecord | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'string') {
    return parseRouterAbEcdsaHssPoolFillSessionRecord(
      parseJson(raw),
    ) as RouterAbEcdsaHssPoolFillSessionRecord | null;
  }
  return parseRouterAbEcdsaHssPoolFillSessionRecord(raw) as RouterAbEcdsaHssPoolFillSessionRecord | null;
}

function parsePresignSessionCasLuaResult(raw: unknown): RouterAbEcdsaHssPoolFillSessionCasResult {
  if (typeof raw === 'string' && raw.startsWith('__err__:')) {
    const codeRaw = raw.slice('__err__:'.length).trim();
    const code =
      codeRaw === 'expired'
        ? 'expired'
        : codeRaw === 'version_mismatch'
          ? 'version_mismatch'
          : 'not_found';
    return { ok: false, code };
  }
  const record = parseRouterAbEcdsaHssPoolFillSessionRecordFromRaw(raw);
  if (!record) return { ok: false, code: 'not_found' };
  return { ok: true, record };
}

function isEvalUnsupportedError(message: string): boolean {
  const m = String(message || '').toLowerCase();
  if (!m) return false;
  return (
    m.includes('unknown command') ||
    m.includes('err unknown command') ||
    m.includes('noperm') ||
    m.includes('command is not allowed')
  );
}

class UpstashRedisRestRouterAbEcdsaHssPresignaturePool implements RouterAbEcdsaHssPresignaturePool {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;
  private readonly reservationTtlMs: number;

  constructor(input: { url: string; token: string; keyPrefix: string; reservationTtlMs?: number }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.keyPrefix = input.keyPrefix;
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input.reservationTtlMs) || 120_000));
  }

  private availKey(relayerKeyId: string): string {
    return `${this.keyPrefix}avail:${relayerKeyId}`;
  }

  private reservedKey(relayerKeyId: string, presignatureId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:${presignatureId}`;
  }

  private reservedKeyPrefix(relayerKeyId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:`;
  }

  async put(record: RouterAbEcdsaHssServerPresignatureShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const presignatureId = toOptionalTrimmedString(record.presignatureId);
    if (!relayerKeyId || !presignatureId) throw new Error('Missing relayerKeyId/presignatureId');
    await this.client.rpush(this.availKey(relayerKeyId), JSON.stringify(record));
  }

  async reserve(
    relayerKeyId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    const ttlSeconds = String(toRedisSeconds(this.reservationTtlMs));
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_RESERVE_LUA,
        [this.availKey(key), this.reservedKeyPrefix(key)],
        [ttlSeconds, '8'],
      );
      return parsePresignatureRecordFromRaw(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || '',
      );
      if (isEvalUnsupportedError(msg)) {
        throw new Error(
          '[threshold-ecdsa] Upstash EVAL is required for atomic presignature reserve; ensure scripting is enabled',
        );
      }
      throw e;
    }
  }

  async reserveById(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const ttlSeconds = String(toRedisSeconds(this.reservationTtlMs));
    const marker = `__seams_threshold_ecdsa_presign_deleted__:${Date.now()}:${secureRandomIdFragment()}`;
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_RESERVE_BY_ID_LUA,
        [this.availKey(key), this.reservedKey(key, id)],
        [id, ttlSeconds, marker],
      );
      return parsePresignatureRecordFromRaw(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || '',
      );
      if (isEvalUnsupportedError(msg)) {
        throw new Error(
          '[threshold-ecdsa] Upstash EVAL is required for atomic presignature reserve-by-id; ensure scripting is enabled',
        );
      }
      throw e;
    }
  }

  async consume(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const raw = await this.client.getdelJson(this.reservedKey(key, id));
    return parseRouterAbEcdsaHssServerPresignatureShareRecord(
      raw,
    ) as RouterAbEcdsaHssServerPresignatureShareRecord | null;
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return;
    await this.client.del(this.reservedKey(key, id));
  }
}

async function redisRpushRaw(client: RedisTcpClient, key: string, value: string): Promise<void> {
  const resp = await client.send(['RPUSH', key, value]);
  if (resp.type === 'error') throw new Error(`Redis RPUSH error: ${resp.value}`);
}

class RedisTcpRouterAbEcdsaHssPresignaturePool implements RouterAbEcdsaHssPresignaturePool {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;
  private readonly reservationTtlMs: number;

  constructor(input: { redisUrl: string; keyPrefix: string; reservationTtlMs?: number }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp presignature pool missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = input.keyPrefix;
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input.reservationTtlMs) || 120_000));
  }

  private availKey(relayerKeyId: string): string {
    return `${this.keyPrefix}avail:${relayerKeyId}`;
  }

  private reservedKey(relayerKeyId: string, presignatureId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:${presignatureId}`;
  }

  private reservedKeyPrefix(relayerKeyId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:`;
  }

  async put(record: RouterAbEcdsaHssServerPresignatureShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const presignatureId = toOptionalTrimmedString(record.presignatureId);
    if (!relayerKeyId || !presignatureId) throw new Error('Missing relayerKeyId/presignatureId');
    await redisRpushRaw(this.client, this.availKey(relayerKeyId), JSON.stringify(record));
  }

  async reserve(
    relayerKeyId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    const ttlSeconds = String(toRedisSeconds(this.reservationTtlMs));
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_RESERVE_LUA,
      '2',
      this.availKey(key),
      this.reservedKeyPrefix(key),
      ttlSeconds,
      '8',
    ]);
    if (evalResp.type === 'bulk') {
      return parsePresignatureRecordFromRaw(evalResp.value);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error(
          '[threshold-ecdsa] Redis EVAL is required for atomic presignature reserve; enable scripting permissions',
        );
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(
      `[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`,
    );
  }

  async reserveById(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const ttlSeconds = String(toRedisSeconds(this.reservationTtlMs));
    const marker = `__seams_threshold_ecdsa_presign_deleted__:${Date.now()}:${secureRandomIdFragment()}`;
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_RESERVE_BY_ID_LUA,
      '2',
      this.availKey(key),
      this.reservedKey(key, id),
      id,
      ttlSeconds,
      marker,
    ]);
    if (evalResp.type === 'bulk') {
      return parsePresignatureRecordFromRaw(evalResp.value);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error(
          '[threshold-ecdsa] Redis EVAL is required for atomic presignature reserve-by-id; enable scripting permissions',
        );
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(
      `[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`,
    );
  }

  async consume(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const raw = await redisGetdelJson(this.client, this.reservedKey(key, id));
    return parseRouterAbEcdsaHssServerPresignatureShareRecord(
      raw,
    ) as RouterAbEcdsaHssServerPresignatureShareRecord | null;
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return;
    const resp = await this.client.send(['DEL', this.reservedKey(key, id)]);
    if (resp.type === 'error') throw new Error(`Redis DEL error: ${resp.value}`);
  }
}

class PostgresRouterAbEcdsaHssPresignaturePool implements RouterAbEcdsaHssPresignaturePool {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;
  private readonly reservationTtlMs: number;

  constructor(input: { postgresUrl: string; namespace: string; reservationTtlMs?: number }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input.reservationTtlMs) || 120_000));
  }

  private async deleteMalformedPresignature(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM threshold_ecdsa_presignatures
        WHERE namespace = $1 AND relayer_key_id = $2 AND presignature_id = $3
      `,
      [this.namespace, relayerKeyId, presignatureId],
    );
  }

  async put(record: RouterAbEcdsaHssServerPresignatureShareRecord): Promise<void> {
    const parsed = parseCurrentRouterAbEcdsaHssServerPresignatureRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presignature record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO threshold_ecdsa_presignatures (
          namespace,
          relayer_key_id,
          presignature_id,
          state,
          record_json,
          created_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, relayer_key_id, presignature_id) DO NOTHING
      `,
      [
        this.namespace,
        parsed.relayerKeyId,
        parsed.presignatureId,
        'available',
        parsed,
        parsed.createdAtMs,
      ],
    );
  }

  async reserve(
    relayerKeyId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const relayer = toOptionalTrimmedString(relayerKeyId);
    if (!relayer) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const reserveExpiresAtMs = nowMs + this.reservationTtlMs;
    const { rows } = await pool.query(
      `
        WITH expired AS (
          DELETE FROM threshold_ecdsa_presignatures
          WHERE namespace = $1 AND relayer_key_id = $2 AND state = 'reserved' AND reserve_expires_at_ms < $3
        ),
        picked AS (
          SELECT presignature_id
          FROM threshold_ecdsa_presignatures
          WHERE namespace = $1 AND relayer_key_id = $2 AND state = 'available'
          ORDER BY created_at_ms ASC
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        UPDATE threshold_ecdsa_presignatures p
        SET state = 'reserved', reserved_at_ms = $3, reserve_expires_at_ms = $4
        FROM picked
        WHERE p.namespace = $1 AND p.relayer_key_id = $2 AND p.presignature_id = picked.presignature_id
        RETURNING p.record_json, p.presignature_id
      `,
      [this.namespace, relayer, nowMs, reserveExpiresAtMs],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) => parseCurrentRouterAbEcdsaHssServerPresignatureRecord(row.record_json),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      const presignatureId = toOptionalTrimmedString(
        (rows[0] as { presignature_id?: unknown } | undefined)?.presignature_id,
      );
      if (presignatureId) {
        await this.deleteMalformedPresignature(relayer, presignatureId);
      }
      return null;
    }
    return parsed.value;
  }

  async reserveById(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const relayer = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!relayer || !id) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const reserveExpiresAtMs = nowMs + this.reservationTtlMs;
    const { rows } = await pool.query(
      `
        WITH expired AS (
          DELETE FROM threshold_ecdsa_presignatures
          WHERE namespace = $1 AND relayer_key_id = $2 AND state = 'reserved' AND reserve_expires_at_ms < $4
        ),
        picked AS (
          SELECT presignature_id
          FROM threshold_ecdsa_presignatures
          WHERE namespace = $1 AND relayer_key_id = $2 AND state = 'available' AND presignature_id = $3
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        UPDATE threshold_ecdsa_presignatures p
        SET state = 'reserved', reserved_at_ms = $4, reserve_expires_at_ms = $5
        FROM picked
        WHERE p.namespace = $1 AND p.relayer_key_id = $2 AND p.presignature_id = picked.presignature_id
        RETURNING p.record_json, p.presignature_id
      `,
      [this.namespace, relayer, id, nowMs, reserveExpiresAtMs],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) => parseCurrentRouterAbEcdsaHssServerPresignatureRecord(row.record_json),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      const presignatureId = toOptionalTrimmedString(
        (rows[0] as { presignature_id?: unknown } | undefined)?.presignature_id,
      );
      if (presignatureId) {
        await this.deleteMalformedPresignature(relayer, presignatureId);
      }
      return null;
    }
    return parsed.value;
  }

  async consume(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const relayer = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!relayer || !id) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        DELETE FROM threshold_ecdsa_presignatures
        WHERE namespace = $1 AND relayer_key_id = $2 AND presignature_id = $3 AND state = 'reserved'
        RETURNING record_json, reserve_expires_at_ms
      `,
      [this.namespace, relayer, id],
    );
    const row = rows[0] as { record_json?: unknown; reserve_expires_at_ms?: unknown } | undefined;
    const reserveExpiresAtMs =
      typeof row?.reserve_expires_at_ms === 'number'
        ? row.reserve_expires_at_ms
        : Number(row?.reserve_expires_at_ms);
    if (Number.isFinite(reserveExpiresAtMs) && reserveExpiresAtMs < nowMs) return null;
    return parseCurrentRouterAbEcdsaHssServerPresignatureRecord(row?.record_json);
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const relayer = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!relayer || !id) return;
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM threshold_ecdsa_presignatures
        WHERE namespace = $1 AND relayer_key_id = $2 AND presignature_id = $3 AND state = 'reserved'
      `,
      [this.namespace, relayer, id],
    );
  }
}

export function createThresholdEcdsaSigningStores(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): {
  presignaturePool: RouterAbEcdsaHssPresignaturePool;
  poolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
} {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) {
    return {
      presignaturePool: doStores.presignaturePool,
      poolFillSessionStore: doStores.poolFillSessionStore,
    };
  }

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const presignPrefix = toThresholdEcdsaPresignPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_PRESIGN_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'presign'),
  );

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ecdsa] In-memory presign stores are not supported in this runtime; configure Redis/Postgres or Durable Objects',
      );
    }
    return {
      presignaturePool: new InMemoryRouterAbEcdsaHssPresignaturePool(),
      poolFillSessionStore: new InMemoryRouterAbEcdsaHssPoolFillSessionStore(),
    };
  }

  if (kind === 'upstash-redis-rest') {
    const url =
      toOptionalTrimmedString(config.url) ||
      toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token =
      toOptionalTrimmedString(config.token) ||
      toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token)
      throw new Error(
        '[threshold-ecdsa] upstash-redis-rest selected but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not set',
      );
    return {
      presignaturePool: new UpstashRedisRestRouterAbEcdsaHssPresignaturePool({
        url,
        token,
        keyPrefix: presignPrefix,
      }),
      poolFillSessionStore: new UpstashRedisRestRouterAbEcdsaHssPoolFillSessionStore({
        url,
        token,
        keyPrefix: presignPrefix,
      }),
    };
  }

  if (kind === 'redis-tcp') {
    const redisUrl =
      toOptionalTrimmedString(config.redisUrl) ||
      toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) throw new Error('[threshold-ecdsa] redis-tcp selected but REDIS_URL is not set');
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] redis-tcp presign stores are not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] redis-tcp is not supported in this runtime; falling back to in-memory',
      );
      return {
        presignaturePool: new InMemoryRouterAbEcdsaHssPresignaturePool(),
        poolFillSessionStore: new InMemoryRouterAbEcdsaHssPoolFillSessionStore(),
      };
    }
    return {
      presignaturePool: new RedisTcpRouterAbEcdsaHssPresignaturePool({
        redisUrl,
        keyPrefix: presignPrefix,
      }),
      poolFillSessionStore: new RedisTcpRouterAbEcdsaHssPoolFillSessionStore({
        redisUrl,
        keyPrefix: presignPrefix,
      }),
    };
  }

  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ecdsa] postgres presign stores are not supported in this runtime',
      );
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error('[threshold-ecdsa] postgres selected but POSTGRES_URL is not set');
    input.logger.warn(
      '[threshold-ecdsa] Using Postgres for presign hot path; for lower presign p95/p99, prefer Upstash/Redis (set UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN or REDIS_URL)',
    );
    return {
      presignaturePool: new PostgresRouterAbEcdsaHssPresignaturePool({
        postgresUrl,
        namespace: presignPrefix,
      }),
      poolFillSessionStore: new PostgresRouterAbEcdsaHssPoolFillSessionStore({
        postgresUrl,
        namespace: presignPrefix,
      }),
    };
  }

  // Env-shaped config: prefer Redis/Upstash for presign pools because records churn heavily.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        '[threshold-ecdsa] Upstash selected but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[threshold-ecdsa] Using Upstash REST for presign pool');
    return {
      presignaturePool: new UpstashRedisRestRouterAbEcdsaHssPresignaturePool({
        url: upstashUrl,
        token: upstashToken,
        keyPrefix: presignPrefix,
      }),
      poolFillSessionStore: new UpstashRedisRestRouterAbEcdsaHssPoolFillSessionStore({
        url: upstashUrl,
        token: upstashToken,
        keyPrefix: presignPrefix,
      }),
    };
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return {
        presignaturePool: new InMemoryRouterAbEcdsaHssPresignaturePool(),
        poolFillSessionStore: new InMemoryRouterAbEcdsaHssPoolFillSessionStore(),
      };
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp for presign pool');
    return {
      presignaturePool: new RedisTcpRouterAbEcdsaHssPresignaturePool({
        redisUrl,
        keyPrefix: presignPrefix,
      }),
      poolFillSessionStore: new RedisTcpRouterAbEcdsaHssPoolFillSessionStore({
        redisUrl,
        keyPrefix: presignPrefix,
      }),
    };
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ecdsa] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[threshold-ecdsa] Using Postgres for presign pool');
    input.logger.warn(
      '[threshold-ecdsa] Postgres hot-path selected for threshold-ecdsa presign; for lower tail latency, prefer Upstash/Redis for these stores',
    );
    return {
      presignaturePool: new PostgresRouterAbEcdsaHssPresignaturePool({
        postgresUrl,
        namespace: presignPrefix,
      }),
      poolFillSessionStore: new PostgresRouterAbEcdsaHssPoolFillSessionStore({
        postgresUrl,
        namespace: presignPrefix,
      }),
    };
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ecdsa] Presign stores require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }

  input.logger.info(
    '[threshold-ecdsa] Using in-memory presign pool (non-persistent)',
  );
  return {
    presignaturePool: new InMemoryRouterAbEcdsaHssPresignaturePool(),
    poolFillSessionStore: new InMemoryRouterAbEcdsaHssPoolFillSessionStore(),
  };
}
