import {
  parseAggregateLaneActivationReceiptV1,
  parseAggregateLaneRevocationReceiptV1,
  parseLaneEnrollmentLifecycleV1,
  parseLaneEnrollmentManifestV1,
  parseLaneHolderDeliveryReceiptV1,
  parseLaneProductEpochRecordV1,
  parseLaneProtocolCommitReceiptV1,
  parseLaneProtocolJobV1,
  parseLaneProtocolLifecycleV1,
  parseLaneServerActivationReceiptV1,
} from '@shared/signing-lanes/rotationParsers';
import type {
  AggregateLaneActivationReceiptV1,
  AggregateLaneRevocationReceiptV1,
  LaneEnrollmentLifecycleV1,
  LaneEnrollmentManifestV1,
  LaneHolderDeliveryReceiptV1,
  LaneProductEpochRecordV1,
  LaneProtocolCommitReceiptV1,
  LaneProtocolRecordV1,
  LaneServerActivationReceiptV1,
  RevokeLaneEnrollmentV1,
} from '@shared/signing-lanes';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import type { D1DatabaseLike, D1ResultLike } from '../../../../storage/tenantRoute';
import { isD1DatabaseLike, parseD1JsonColumn } from '../../../../storage/d1Sql';

export type CloudflareD1LaneScopeV1 = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

export type CloudflareD1LaneStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly scope: CloudflareD1LaneScopeV1;
  readonly now?: () => number;
};

export type LaneEnrollmentRow = {
  readonly enrollment_id?: unknown;
  readonly wallet_id?: unknown;
  readonly manifest_digest_b64u?: unknown;
  readonly manifest_json?: unknown;
  readonly lifecycle_json?: unknown;
  readonly version?: unknown;
  readonly command_digest_b64u?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

export type LaneProtocolRow = {
  readonly operation_id?: unknown;
  readonly enrollment_id?: unknown;
  readonly wallet_id?: unknown;
  readonly wallet_key_id?: unknown;
  readonly source_lane_id?: unknown;
  readonly source_lane_share_epoch?: unknown;
  readonly source_revocation_epoch?: unknown;
  readonly target_lane_id?: unknown;
  readonly target_lane_share_epoch?: unknown;
  readonly target_material_activation_id?: unknown;
  readonly job_json?: unknown;
  readonly lifecycle_json?: unknown;
  readonly version?: unknown;
  readonly command_digest_b64u?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

export type LaneProductEpochRow = {
  readonly product_json?: unknown;
  readonly version?: unknown;
  readonly command_digest_b64u?: unknown;
};

export type LaneReceiptRow = {
  readonly receipt_id?: unknown;
  readonly receipt_kind?: unknown;
  readonly receipt_digest_b64u?: unknown;
  readonly receipt_json?: unknown;
  readonly created_at_ms?: unknown;
};

export function requireD1LaneStoreOptions(input: CloudflareD1LaneStoreOptions): {
  readonly database: D1DatabaseLike;
  readonly scope: CloudflareD1LaneScopeV1;
  readonly now: () => number;
} {
  if (!isD1DatabaseLike(input.database)) throw new Error('R102 lane D1 database is required');
  return {
    database: input.database,
    scope: normalizeScope(input.scope),
    now: input.now ?? Date.now,
  };
}

export function normalizeScope(scope: CloudflareD1LaneScopeV1): CloudflareD1LaneScopeV1 {
  const namespace = requiredScopeString(scope.namespace, 'namespace');
  const orgId = requiredScopeString(scope.orgId, 'orgId');
  const projectId = requiredScopeString(scope.projectId, 'projectId');
  const envId = requiredScopeString(scope.envId, 'envId');
  return { namespace, orgId, projectId, envId };
}

function requiredScopeString(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`R102 lane ${label} is required`);
  if (/[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error(`R102 lane ${label} contains control characters`);
  }
  return normalized;
}

export function parseVersion(value: unknown, label: string): number {
  const version = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(version) || version < 1) throw new Error(`${label} is invalid`);
  return version;
}

export function parseTimestamp(value: unknown, label: string): number {
  const timestamp = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error(`${label} is invalid`);
  return timestamp;
}

export function parseRequiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is invalid`);
  return value;
}

export function parseJsonRecord(value: unknown, label: string): Record<string, unknown> {
  const parsed = parseD1JsonColumn(value);
  if (!isJsonRecord(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return parsed;
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Compare parsed JSON records without relying on insertion order. */
export function equalLaneRecords(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (left === null || right === null || typeof left !== typeof right) return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    for (let index = 0; index < left.length; index += 1) {
      if (!equalLaneRecords(left[index], right[index])) return false;
    }
    return true;
  }
  if (isJsonRecord(left) && isJsonRecord(right)) {
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    if (leftKeys.length !== rightKeys.length) return false;
    for (let index = 0; index < leftKeys.length; index += 1) {
      const key = leftKeys[index];
      if (key !== rightKeys[index] || !equalLaneRecords(left[key], right[key])) return false;
    }
    return true;
  }
  return false;
}

export function parseEnrollmentRow(row: LaneEnrollmentRow): {
  readonly enrollmentId: string;
  readonly walletId: string;
  readonly manifestDigestB64u: string;
  readonly manifest: LaneEnrollmentManifestV1;
  readonly lifecycle: LaneEnrollmentLifecycleV1;
  readonly version: number;
  readonly commandDigestB64u: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
} {
  return {
    enrollmentId: parseRequiredString(row.enrollment_id, 'enrollment_id'),
    walletId: parseRequiredString(row.wallet_id, 'wallet_id'),
    manifestDigestB64u: parseRequiredString(row.manifest_digest_b64u, 'manifest_digest_b64u'),
    manifest: parseLaneEnrollmentManifestV1(row.manifest_json, 'lane enrollment manifest'),
    lifecycle: parseLaneEnrollmentLifecycleV1(row.lifecycle_json, 'lane enrollment lifecycle'),
    version: parseVersion(row.version, 'enrollment version'),
    commandDigestB64u: parseRequiredString(row.command_digest_b64u, 'command_digest_b64u'),
    createdAtMs: parseTimestamp(row.created_at_ms, 'enrollment created_at_ms'),
    updatedAtMs: parseTimestamp(row.updated_at_ms, 'enrollment updated_at_ms'),
  };
}

export function parseProtocolRow(row: LaneProtocolRow): {
  readonly operationId: string;
  readonly enrollmentId: string;
  readonly walletId: string;
  readonly walletKeyId: string;
  readonly sourceLaneId: string;
  readonly sourceLaneShareEpoch: string;
  readonly sourceRevocationEpoch: number;
  readonly targetLaneId: string;
  readonly targetLaneShareEpoch: string;
  readonly targetMaterialActivationId: string;
  readonly record: LaneProtocolRecordV1;
  readonly version: number;
  readonly commandDigestB64u: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
} {
  const job = parseLaneProtocolJobV1(row.job_json, 'lane protocol job');
  const lifecycle = parseLaneProtocolLifecycleV1(row.lifecycle_json, 'lane protocol lifecycle');
  return {
    operationId: parseRequiredString(row.operation_id, 'operation_id'),
    enrollmentId: parseRequiredString(row.enrollment_id, 'enrollment_id'),
    walletId: parseRequiredString(row.wallet_id, 'wallet_id'),
    walletKeyId: parseRequiredString(row.wallet_key_id, 'wallet_key_id'),
    sourceLaneId: parseRequiredString(row.source_lane_id, 'source_lane_id'),
    sourceLaneShareEpoch: parseRequiredString(
      row.source_lane_share_epoch,
      'source_lane_share_epoch',
    ),
    sourceRevocationEpoch: parseTimestamp(row.source_revocation_epoch, 'source_revocation_epoch'),
    targetLaneId: parseRequiredString(row.target_lane_id, 'target_lane_id'),
    targetLaneShareEpoch: parseRequiredString(
      row.target_lane_share_epoch,
      'target_lane_share_epoch',
    ),
    targetMaterialActivationId: parseRequiredString(
      row.target_material_activation_id,
      'target_material_activation_id',
    ),
    record: { job, lifecycle },
    version: parseVersion(row.version, 'protocol version'),
    commandDigestB64u: parseRequiredString(row.command_digest_b64u, 'command_digest_b64u'),
    createdAtMs: parseTimestamp(row.created_at_ms, 'protocol created_at_ms'),
    updatedAtMs: parseTimestamp(row.updated_at_ms, 'protocol updated_at_ms'),
  };
}

export function parseProductEpochRow(row: LaneProductEpochRow): LaneProductEpochRecordV1 {
  return parseLaneProductEpochRecordV1(row.product_json, 'lane product epoch');
}

export function parseReceiptRow(row: LaneReceiptRow): {
  readonly receiptId: string;
  readonly receiptKind: string;
  readonly receiptDigestB64u: string;
  readonly value:
    | LaneProtocolCommitReceiptV1
    | LaneHolderDeliveryReceiptV1
    | LaneServerActivationReceiptV1
    | AggregateLaneActivationReceiptV1
    | AggregateLaneRevocationReceiptV1;
} {
  const receiptKind = parseRequiredString(row.receipt_kind, 'receipt_kind');
  const raw = row.receipt_json;
  const value = (() => {
    switch (receiptKind) {
      case 'lane_protocol_commit':
        return parseLaneProtocolCommitReceiptV1(raw);
      case 'lane_holder_delivery':
        return parseLaneHolderDeliveryReceiptV1(raw);
      case 'lane_server_activation':
        return parseLaneServerActivationReceiptV1(raw);
      case 'aggregate_activation':
        return parseAggregateLaneActivationReceiptV1(raw);
      case 'aggregate_revocation':
        return parseAggregateLaneRevocationReceiptV1(raw);
      default:
        throw new Error(`unknown R102 receipt kind ${receiptKind}`);
    }
  })();
  return {
    receiptId: parseRequiredString(row.receipt_id, 'receipt_id'),
    receiptKind,
    receiptDigestB64u: parseRequiredString(row.receipt_digest_b64u, 'receipt_digest_b64u'),
    value,
  };
}

export async function digestLaneEnrollmentRevocationCommand(
  input: RevokeLaneEnrollmentV1,
): Promise<string> {
  const encoded = [
    'seams/rotatable-signing-lanes/revoke-enrollment/v1',
    String(input.enrollmentId),
    String(input.walletId),
    input.manifestDigestB64u,
    input.reason,
    String(input.requestedAtMs),
  ].join('\u0000');
  return base64UrlEncode(await sha256BytesUtf8(encoded));
}

export function scopeValues(scope: CloudflareD1LaneScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

export function firstBatchResult(results: readonly unknown[], index: number): D1ResultLike {
  const result = results[index];
  if (!result || typeof result !== 'object')
    throw new Error(`R102 lane D1 batch result ${index} is invalid`);
  return result as D1ResultLike;
}

export const LANE_CAS_GUARD_SQL =
  'INSERT INTO lane_cas_guard (guard_id) SELECT 1 WHERE changes() = 0';

export function assertD1Success(result: D1ResultLike, label: string): void {
  if (result.success === false) throw new Error(`${label} failed`);
}
