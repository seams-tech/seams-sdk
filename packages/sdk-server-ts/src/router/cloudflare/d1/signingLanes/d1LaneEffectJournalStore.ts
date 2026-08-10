import type { D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import type {
  LaneEffectJournalStore,
  LaneEffectMutation,
  LaneEffectMutationResult,
  LaneEffectRecordV1,
} from '../../../../core/signingLanes/LaneEffectJournalStore';
import {
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseLaneShareEpoch,
  parseSigningLaneId,
  parseWalletId,
  parseWalletKeyId,
} from '@shared/utils/domainIds';
import {
  assertD1Success,
  firstBatchResult,
  LANE_CAS_GUARD_SQL,
  requireD1LaneStoreOptions,
  scopeValues,
  type CloudflareD1LaneStoreOptions,
} from './d1LaneRecords';

const EFFECT_TABLE = 'lane_effect_journal';

type EffectRow = {
  readonly effect_id?: unknown;
  readonly enrollment_id?: unknown;
  readonly operation_id?: unknown;
  readonly wallet_id?: unknown;
  readonly wallet_key_id?: unknown;
  readonly lane_id?: unknown;
  readonly lane_share_epoch?: unknown;
  readonly effect_kind?: unknown;
  readonly request_digest_b64u?: unknown;
  readonly status?: unknown;
  readonly response_digest_b64u?: unknown;
  readonly recorded_at_ms?: unknown;
  readonly confirmed_at_ms?: unknown;
  readonly version?: unknown;
  readonly command_digest_b64u?: unknown;
};

export type CloudflareD1LaneEffectJournalStoreOptions = CloudflareD1LaneStoreOptions;

export class CloudflareD1LaneEffectJournalStore implements LaneEffectJournalStore {
  private readonly database: CloudflareD1LaneStoreOptions['database'];
  private readonly scope: CloudflareD1LaneStoreOptions['scope'];
  private readonly now: () => number;

  constructor(options: CloudflareD1LaneEffectJournalStoreOptions) {
    const normalized = requireD1LaneStoreOptions(options);
    this.database = normalized.database;
    this.scope = normalized.scope;
    this.now = normalized.now;
  }

  async getEffect(input: { readonly effectId: string }): Promise<{
    readonly version: number;
    readonly commandDigestB64u: string;
    readonly record: LaneEffectRecordV1;
  } | null> {
    const row = await this.database
      .prepare(
        `SELECT effect_id, enrollment_id, operation_id, wallet_id, wallet_key_id, lane_id, lane_share_epoch, effect_kind, request_digest_b64u, status, response_digest_b64u, recorded_at_ms, confirmed_at_ms, version, command_digest_b64u FROM ${EFFECT_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND effect_id = ?5`,
      )
      .bind(...scopeValues(this.scope), input.effectId)
      .first<EffectRow>();
    return row ? parseEffectRow(row) : null;
  }

  async recordEffect(input: LaneEffectMutation): Promise<LaneEffectMutationResult> {
    const record = input.record;
    if (record.status !== 'recorded')
      throw new Error('lane effect admission requires a recorded effect');
    const existing = await this.getEffect({ effectId: record.effectId });
    if (existing) {
      if (
        sameEffect(existing.record, record) &&
        existing.commandDigestB64u === input.commandDigestB64u
      ) {
        return {
          outcome: 'replayed',
          version: existing.version,
          commandDigestB64u: existing.commandDigestB64u,
          record: existing.record,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: null,
        actualVersion: existing.version,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: existing.commandDigestB64u,
      };
    }
    const statements: D1PreparedStatementLike[] = [
      this.database
        .prepare(
          `INSERT INTO ${EFFECT_TABLE} (namespace, org_id, project_id, env_id, effect_id, enrollment_id, operation_id, wallet_id, wallet_key_id, lane_id, lane_share_epoch, effect_kind, request_digest_b64u, status, response_digest_b64u, recorded_at_ms, confirmed_at_ms, version, command_digest_b64u) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'recorded', NULL, ?14, NULL, 1, ?15)`,
        )
        .bind(
          ...scopeValues(this.scope),
          record.effectId,
          String(record.enrollmentId),
          String(record.operationId),
          String(record.walletId),
          String(record.walletKeyId),
          String(record.laneId),
          String(record.laneShareEpoch),
          record.effectKind,
          record.requestDigestB64u,
          record.recordedAtMs,
          input.commandDigestB64u,
        ),
      this.database.prepare(LANE_CAS_GUARD_SQL),
    ];
    try {
      const results = await this.database.batch(statements);
      assertD1Success(firstBatchResult(results, 0), 'lane effect admission');
      return { outcome: 'applied', version: 1, commandDigestB64u: input.commandDigestB64u, record };
    } catch (error: unknown) {
      const raced = await this.getEffect({ effectId: record.effectId });
      if (
        raced &&
        sameEffect(raced.record, record) &&
        raced.commandDigestB64u === input.commandDigestB64u
      )
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: raced.commandDigestB64u,
          record: raced.record,
        };
      if (raced)
        return {
          outcome: 'conflict',
          expectedVersion: null,
          actualVersion: raced.version,
          requestedCommandDigestB64u: input.commandDigestB64u,
          storedCommandDigestB64u: raced.commandDigestB64u,
        };
      throw error;
    }
  }

  async confirmEffect(input: {
    readonly effectId: string;
    readonly expectedVersion: number;
    readonly commandDigestB64u: string;
    readonly responseDigestB64u: string;
    readonly confirmedAtMs: number;
  }): Promise<LaneEffectMutationResult> {
    const existing = await this.getEffect({ effectId: input.effectId });
    if (!existing)
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: '',
      };
    if (
      existing.record.status === 'confirmed' &&
      existing.record.responseDigestB64u === input.responseDigestB64u &&
      existing.commandDigestB64u === input.commandDigestB64u
    )
      return {
        outcome: 'replayed',
        version: existing.version,
        commandDigestB64u: existing.commandDigestB64u,
        record: existing.record,
      };
    const values = scopeValues(this.scope);
    const statements: D1PreparedStatementLike[] = [
      this.database
        .prepare(
          `UPDATE ${EFFECT_TABLE} SET status = 'confirmed', response_digest_b64u = ?5, confirmed_at_ms = ?6, version = version + 1, command_digest_b64u = ?7 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND effect_id = ?8 AND version = ?9 AND status = 'recorded'`,
        )
        .bind(
          ...values,
          input.responseDigestB64u,
          input.confirmedAtMs,
          input.commandDigestB64u,
          input.effectId,
          input.expectedVersion,
        ),
      this.database.prepare(LANE_CAS_GUARD_SQL),
    ];
    try {
      const results = await this.database.batch(statements);
      assertD1Success(firstBatchResult(results, 0), 'lane effect confirmation');
    } catch {
      const raced = await this.getEffect({ effectId: input.effectId });
      if (
        raced &&
        raced.record.status === 'confirmed' &&
        raced.record.responseDigestB64u === input.responseDigestB64u &&
        raced.commandDigestB64u === input.commandDigestB64u
      )
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: raced.commandDigestB64u,
          record: raced.record,
        };
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: raced?.version ?? 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: raced?.commandDigestB64u ?? '',
      };
    }
    const updated = await this.getEffect({ effectId: input.effectId });
    if (!updated) throw new Error('lane effect disappeared after confirmation');
    return {
      outcome: 'applied',
      version: updated.version,
      commandDigestB64u: updated.commandDigestB64u,
      record: updated.record,
    };
  }
}

function parseEffectRow(row: EffectRow): {
  readonly version: number;
  readonly commandDigestB64u: string;
  readonly record: LaneEffectRecordV1;
} {
  const required = (value: unknown, label: string): string => {
    if (typeof value !== 'string' || !value) throw new Error(`${label} is invalid`);
    return value;
  };
  const status = required(row.status, 'effect status');
  if (status !== 'recorded' && status !== 'confirmed') throw new Error('effect status is invalid');
  const effectKindValue = required(row.effect_kind, 'effect kind');
  if (
    effectKindValue !== 'activate_server_material' &&
    effectKindValue !== 'retire_server_material' &&
    effectKindValue !== 'invalidate_holder_material'
  )
    throw new Error('effect kind is invalid');
  const effectKind: LaneEffectRecordV1['effectKind'] = effectKindValue;
  const version = Number(row.version);
  if (!Number.isSafeInteger(version) || version < 1) throw new Error('effect version is invalid');
  const recordedAtMs = Number(row.recorded_at_ms);
  if (!Number.isSafeInteger(recordedAtMs) || recordedAtMs < 0)
    throw new Error('effect recorded time is invalid');
  const responseDigest =
    row.response_digest_b64u === null || row.response_digest_b64u === undefined
      ? undefined
      : required(row.response_digest_b64u, 'effect response digest');
  const confirmedAt =
    row.confirmed_at_ms === null || row.confirmed_at_ms === undefined
      ? undefined
      : Number(row.confirmed_at_ms);
  const base = {
    kind: 'lane_effect_record_v1' as const,
    effectId: required(row.effect_id, 'effect id'),
    enrollmentId: parsedId(parseLaneEnrollmentId, row.enrollment_id, 'enrollment id'),
    operationId: parsedId(parseLaneOperationId, row.operation_id, 'operation id'),
    walletId: parsedId(parseWalletId, row.wallet_id, 'wallet id'),
    walletKeyId: parsedId(parseWalletKeyId, row.wallet_key_id, 'wallet key id'),
    laneId: parsedId(parseSigningLaneId, row.lane_id, 'lane id'),
    laneShareEpoch: parsedId(parseLaneShareEpoch, row.lane_share_epoch, 'lane share epoch'),
    effectKind,
    requestDigestB64u: required(row.request_digest_b64u, 'effect request digest'),
    recordedAtMs,
  };
  const record: LaneEffectRecordV1 =
    status === 'recorded'
      ? { ...base, status: 'recorded' }
      : responseDigest !== undefined &&
          confirmedAt !== undefined &&
          Number.isSafeInteger(confirmedAt) &&
          confirmedAt >= recordedAtMs
        ? {
            ...base,
            status: 'confirmed',
            responseDigestB64u: responseDigest,
            confirmedAtMs: confirmedAt,
          }
        : (() => {
            throw new Error('confirmed lane effect is missing response or confirmation time');
          })();
  return {
    version,
    commandDigestB64u: required(row.command_digest_b64u, 'effect command digest'),
    record,
  };
}

function parsedId<T>(
  parser: (
    raw: unknown,
  ) =>
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  raw: unknown,
  label: string,
): T {
  const result = parser(raw);
  if (!result.ok) throw new Error(`${label} is invalid: ${result.error.message}`);
  return result.value;
}

function sameEffect(left: LaneEffectRecordV1, right: LaneEffectRecordV1): boolean {
  if (
    left.kind !== right.kind ||
    left.effectId !== right.effectId ||
    left.enrollmentId !== right.enrollmentId ||
    left.operationId !== right.operationId ||
    left.walletId !== right.walletId ||
    left.walletKeyId !== right.walletKeyId ||
    left.laneId !== right.laneId ||
    left.laneShareEpoch !== right.laneShareEpoch ||
    left.effectKind !== right.effectKind ||
    left.requestDigestB64u !== right.requestDigestB64u ||
    left.recordedAtMs !== right.recordedAtMs ||
    left.status !== right.status
  ) {
    return false;
  }
  if (left.status === 'recorded' && right.status === 'recorded') return true;
  if (left.status !== 'confirmed' || right.status !== 'confirmed') return false;
  return (
    left.responseDigestB64u === right.responseDigestB64u &&
    left.confirmedAtMs === right.confirmedAtMs
  );
}
