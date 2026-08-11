import { alphabetizeStringify } from '@shared/utils/digests';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '@shared/device-linking/digests';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import { d1ChangedRows } from '../../../../storage/d1Sql';
import {
  parseD1LinkedDeviceSessionTranscriptRowV1,
  parseD1LinkedDeviceSessionRowV1,
  type D1LinkedDeviceSessionRowV1,
} from './d1LinkedDeviceSessionRecords';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceSessionState,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionMutationResultV1,
  type LinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionStoreV1,
  type LinkedDeviceMutationResultWithReceiptV1,
  type LinkedDeviceRecoveryContinuationV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type { LinkDeviceSessionId } from '@shared/signing-lanes/ids';

export type D1LinkedDeviceSessionScopeV1 = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

export type D1LinkedDeviceSessionStoreOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly now?: () => number;
};

const SESSION_TABLE = 'linked_device_sessions';
const TRANSCRIPT_TABLE = 'linked_device_session_transcripts';

export class D1LinkedDeviceSessionStoreV1 implements LinkedDeviceSessionStoreV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly now: () => number;

  constructor(options: D1LinkedDeviceSessionStoreOptionsV1) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
    this.now = options.now ?? Date.now;
  }

  async createUnclaimedSessionV1(
    record: LinkedDeviceSessionRecordV1,
  ): Promise<LinkedDeviceSessionMutationResultV1> {
    const normalized = parseLinkedDeviceSessionRecordV1(record);
    if (normalized.state.state !== 'displaying_qr' || normalized.revision !== 1) {
      return { outcome: 'invalid_state', state: normalized.state.state, record: normalized };
    }
    let insertFailed = false;
    let insertError: unknown;
    try {
      const result = await this.database
        .prepare(
          `INSERT INTO ${SESSION_TABLE} (
             namespace, org_id, project_id, env_id, link_session_id,
             link_public_key_b64u, device_public_key_b64u, state, record_json,
             revision, expires_at_ms, claim_expires_at_ms, claim_digest_b64u,
             approval_digest_b64u, created_at_ms, updated_at_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(...scopeValues(this.scope), ...sessionColumnValues(normalized))
        .run();
      if (d1ChangedRows(result) === 1) return { outcome: 'applied', record: normalized };
    } catch (error: unknown) {
      insertFailed = true;
      insertError = error;
    }
    const existing = await this.getSessionV1(normalized.linkSessionId);
    if (!existing) {
      if (insertFailed) throw insertError;
      throw new Error('linked-device session insert did not persist');
    }
    if (sameQrPayload(existing, normalized)) return { outcome: 'replayed', record: existing };
    return {
      outcome: 'conflict',
      expectedRevision: 1,
      actualRevision: existing.revision,
      record: existing,
    };
  }

  async getSessionV1(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<LinkedDeviceSessionRecordV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT link_session_id, link_public_key_b64u, device_public_key_b64u,
                state, record_json, revision, expires_at_ms, claim_expires_at_ms,
                claim_digest_b64u, approval_digest_b64u, created_at_ms, updated_at_ms
           FROM ${SESSION_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), String(linkSessionId))
      .first<D1LinkedDeviceSessionRowV1>();
    if (!row) return null;
    const parsed = parseD1LinkedDeviceSessionRowV1(row);
    await this.verifyImmutableTranscripts(parsed.record);
    return parsed.record;
  }

  async claimSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly claim: LinkedDeviceSessionClaimV1;
    readonly claimDigestB64u: string;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return conflictResult(input.expectedRevision, null);
    if (sameClaim(current, input.claimDigestB64u, input.claim))
      return { outcome: 'replayed', record: current };
    if (current.state.state !== 'displaying_qr') return invalidStateResult(current);
    if (input.nowMs >= current.qrPayload.expiresAtMs)
      return { outcome: 'expired', record: current };
    return this.applyTranscriptCas({
      kind: 'claim',
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      digestB64u: input.claimDigestB64u,
      transcript: input.claim,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
    });
  }

  async recordOwnerApprovalV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly approval: LinkedDeviceApprovalV1;
    readonly approvalDigestB64u: string;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return conflictResult(input.expectedRevision, null);
    if (sameApproval(current, input.approvalDigestB64u, input.approval))
      return { outcome: 'replayed', record: current };
    if (current.state.state !== 'claimed_by_owner') return invalidStateResult(current);
    if (input.nowMs >= current.state.claimExpiresAtMs)
      return { outcome: 'expired', record: current };
    return this.applyTranscriptCas({
      kind: 'approval',
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      digestB64u: input.approvalDigestB64u,
      transcript: input.approval,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
    });
  }

  async markCommittedCompletionRequiredV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly transcriptSetDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: ['provisioning', 'awaiting_aggregate_receipt'],
      replay: (current) =>
        current.state.state === 'committed_completion_required' &&
        current.state.transcriptSetDigestB64u === input.transcriptSetDigestB64u,
    });
  }

  async bindRecoveryContinuationV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly continuation: LinkedDeviceRecoveryContinuationV1;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: ['committed_completion_required'],
      replay: (current) => {
        const recovery = current.recovery;
        return (
          current.state.state === 'committed_completion_required' &&
          recovery?.kind === 'bound' &&
          alphabetizeStringify(recovery.continuation) === alphabetizeStringify(input.continuation)
        );
      },
    });
  }

  async recordTargetCredentialV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly keyManifestDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: ['awaiting_target_passkey'],
      replay: (current) =>
        current.state.state === 'provisioning' &&
        current.state.keyManifestDigestB64u === input.keyManifestDigestB64u,
    });
  }

  async recordAggregateActivationV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceMutationResultWithReceiptV1> {
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: ['awaiting_aggregate_receipt'],
      replay: (current) =>
        current.state.state === 'active' &&
        Boolean(current.aggregateReceipt) &&
        alphabetizeStringify(current.aggregateReceipt) === alphabetizeStringify(input.receipt),
    });
  }

  async cancelSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: ['displaying_qr', 'claimed_by_owner', 'awaiting_target_passkey'],
      replay: (current) =>
        (current.state.state === 'cancelled_unclaimed' ||
          current.state.state === 'cancelled_claimed_precommit') &&
        current.state.cancelledAtMs === cancelledAtMs(input.nextRecord.state),
    });
  }

  async expireSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return conflictResult(input.expectedRevision, null);
    if (current.state.state === 'expired_unclaimed' || current.state.state === 'expired_claimed')
      return { outcome: 'replayed', record: current };
    if (!isExpirableState(current.state)) return invalidStateResult(current);
    if (input.nowMs < expiryMs(current))
      return { outcome: 'invalid_state', state: current.state.state, record: current };
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: [
        'displaying_qr',
        'claimed_by_owner',
        'awaiting_target_passkey',
        'provisioning',
        'awaiting_aggregate_receipt',
      ],
      replay: (record) => record.state.state === input.nextRecord.state.state,
    });
  }

  private async applyTranscriptCas(input: {
    readonly kind: 'claim' | 'approval';
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly digestB64u: string;
    readonly transcript: unknown;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const update = this.updateStatement(input);
    const transcriptInsert = this.database
      .prepare(
        `INSERT INTO ${TRANSCRIPT_TABLE} (
           namespace, org_id, project_id, env_id, link_session_id,
           transcript_kind, digest_b64u, transcript_json, created_at_ms
         ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE changes() = 1`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(input.linkSessionId),
        input.kind,
        input.digestB64u,
        JSON.stringify(input.transcript),
        input.nowMs,
      );
    let batchFailed = false;
    let batchError: unknown;
    try {
      await this.database.batch([update, transcriptInsert]);
    } catch (error: unknown) {
      batchFailed = true;
      batchError = error;
    }
    if (batchFailed) {
      const raced = await this.getSessionV1(input.linkSessionId);
      if (!raced) throw batchError;
      if (input.kind === 'claim' && sameClaim(raced, input.digestB64u, input.transcript))
        return { outcome: 'replayed', record: raced };
      if (input.kind === 'approval' && sameApproval(raced, input.digestB64u, input.transcript))
        return { outcome: 'replayed', record: raced };
      return conflictResult(input.expectedRevision, raced);
    }
    const persisted = await this.getSessionV1(input.linkSessionId);
    if (!persisted) throw new Error('linked-device session disappeared after CAS');
    if (
      persisted.revision === input.nextRecord.revision &&
      alphabetizeStringify(persisted) === alphabetizeStringify(input.nextRecord)
    )
      return { outcome: 'applied', record: persisted };
    return resolveMutationRace(input.expectedRevision, persisted);
  }

  private async applyStateCas(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
    readonly expectedStates: readonly LinkedDeviceSessionState['state'][];
    readonly replay: (current: LinkedDeviceSessionRecordV1) => boolean;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return conflictResult(input.expectedRevision, null);
    if (input.replay(current)) return { outcome: 'replayed', record: current };
    if (!input.expectedStates.includes(current.state.state)) return invalidStateResult(current);
    await this.updateStatement({
      kind: 'state',
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
    }).run();
    const persisted = await this.getSessionV1(input.linkSessionId);
    if (!persisted) throw new Error('linked-device session disappeared after state CAS');
    if (
      persisted.revision === input.nextRecord.revision &&
      alphabetizeStringify(persisted) === alphabetizeStringify(input.nextRecord)
    )
      return { outcome: 'applied', record: persisted };
    return resolveMutationRace(input.expectedRevision, persisted);
  }

  private updateStatement(input: {
    readonly kind: 'claim' | 'approval' | 'state';
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): D1PreparedStatementLike {
    const record = input.nextRecord;
    return this.database
      .prepare(
        `UPDATE ${SESSION_TABLE}
            SET state = ?, record_json = ?, revision = ?, expires_at_ms = ?,
                claim_expires_at_ms = ?, claim_digest_b64u = ?,
                approval_digest_b64u = ?, updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND revision = ?`,
      )
      .bind(
        record.state.state,
        JSON.stringify(record),
        record.revision,
        record.qrPayload.expiresAtMs,
        record.claimTranscript?.value.claimExpiresAtMs ?? null,
        record.claimTranscript?.digestB64u ?? null,
        record.approvalTranscript?.digestB64u ?? null,
        input.nowMs,
        ...scopeValues(this.scope),
        String(input.linkSessionId),
        input.expectedRevision,
      );
  }

  private async verifyImmutableTranscripts(record: LinkedDeviceSessionRecordV1): Promise<void> {
    const rows = await this.database
      .prepare(
        `SELECT transcript_kind, digest_b64u, transcript_json, created_at_ms
           FROM ${TRANSCRIPT_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?
          ORDER BY transcript_kind ASC`,
      )
      .bind(...scopeValues(this.scope), String(record.linkSessionId))
      .all<{
        transcript_kind?: unknown;
        digest_b64u?: unknown;
        transcript_json?: unknown;
        created_at_ms?: unknown;
      }>();
    const expected = new Map<string, { readonly digestB64u: string; readonly json: string }>();
    if (record.claimTranscript) {
      const digest = await computeLinkedDeviceSessionClaimDigestV1(record.claimTranscript.value);
      if (digest !== record.claimTranscript.digestB64u)
        throw new Error('claim transcript digest is invalid');
      expected.set('claim', {
        digestB64u: record.claimTranscript.digestB64u,
        json: alphabetizeStringify(record.claimTranscript.value),
      });
    }
    if (record.approvalTranscript) {
      const digest = await computeLinkedDeviceApprovalDigestV1(record.approvalTranscript.value);
      if (digest !== record.approvalTranscript.digestB64u)
        throw new Error('approval transcript digest is invalid');
      expected.set('approval', {
        digestB64u: record.approvalTranscript.digestB64u,
        json: alphabetizeStringify(record.approvalTranscript.value),
      });
    }
    const actual = new Map<string, { readonly digestB64u: string; readonly json: string }>();
    for (const row of rows.results || []) {
      const parsed = parseD1LinkedDeviceSessionTranscriptRowV1(row);
      const kind = parsed.kind;
      const digest = parsed.digestB64u;
      const json = alphabetizeStringify(parsed.transcriptJson);
      if (actual.has(kind)) throw new Error('duplicate linked-device transcript');
      actual.set(kind, { digestB64u: digest, json });
    }
    if (actual.size !== expected.size)
      throw new Error('linked-device transcript ledger is incomplete');
    for (const [kind, value] of expected) {
      const persisted = actual.get(kind);
      if (!persisted || persisted.digestB64u !== value.digestB64u || persisted.json !== value.json)
        throw new Error('linked-device transcript ledger is immutable and mismatched');
    }
  }
}

function normalizeScope(scope: D1LinkedDeviceSessionScopeV1): D1LinkedDeviceSessionScopeV1 {
  return {
    namespace: requiredScope(scope.namespace, 'namespace'),
    orgId: requiredScope(scope.orgId, 'orgId'),
    projectId: requiredScope(scope.projectId, 'projectId'),
    envId: requiredScope(scope.envId, 'envId'),
  };
}

function requiredScope(value: string, field: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  )
    throw new Error(`${field} is invalid`);
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function sessionColumnValues(record: LinkedDeviceSessionRecordV1): readonly unknown[] {
  return [
    record.linkSessionId,
    record.qrPayload.linkPublicKeyB64u,
    record.qrPayload.devicePublicKeyB64u,
    record.state.state,
    JSON.stringify(record),
    record.revision,
    record.qrPayload.expiresAtMs,
    record.claimTranscript?.value.claimExpiresAtMs ?? null,
    record.claimTranscript?.digestB64u ?? null,
    record.approvalTranscript?.digestB64u ?? null,
    record.createdAtMs,
    record.updatedAtMs,
  ];
}

function sameQrPayload(
  left: LinkedDeviceSessionRecordV1,
  right: LinkedDeviceSessionRecordV1,
): boolean {
  return alphabetizeStringify(left.qrPayload) === alphabetizeStringify(right.qrPayload);
}

function sameClaim(record: LinkedDeviceSessionRecordV1, digest: string, value: unknown): boolean {
  return Boolean(
    record.claimTranscript &&
    record.claimTranscript.digestB64u === digest &&
    alphabetizeStringify(record.claimTranscript.value) === alphabetizeStringify(value),
  );
}

function sameApproval(
  record: LinkedDeviceSessionRecordV1,
  digest: string,
  value: unknown,
): boolean {
  return Boolean(
    record.approvalTranscript &&
    record.approvalTranscript.digestB64u === digest &&
    alphabetizeStringify(record.approvalTranscript.value) === alphabetizeStringify(value),
  );
}

function resolveMutationRace(
  expectedRevision: number,
  record: LinkedDeviceSessionRecordV1,
): LinkedDeviceSessionMutationResultV1 {
  if (record.revision === expectedRevision) return invalidStateResult(record);
  return conflictResult(expectedRevision, record);
}

function conflictResult(
  expectedRevision: number,
  record: LinkedDeviceSessionRecordV1 | null,
): LinkedDeviceSessionMutationResultV1 {
  return {
    outcome: 'conflict',
    expectedRevision,
    actualRevision: record?.revision ?? null,
    record,
  };
}

function invalidStateResult(
  record: LinkedDeviceSessionRecordV1,
): LinkedDeviceSessionMutationResultV1 {
  return { outcome: 'invalid_state', state: record.state.state, record };
}

function cancelledAtMs(state: LinkedDeviceSessionState): number | null {
  return state.state === 'cancelled_unclaimed' || state.state === 'cancelled_claimed_precommit'
    ? state.cancelledAtMs
    : null;
}

function isExpirableState(state: LinkedDeviceSessionState): boolean {
  switch (state.state) {
    case 'displaying_qr':
    case 'claimed_by_owner':
    case 'awaiting_target_passkey':
    case 'provisioning':
    case 'awaiting_aggregate_receipt':
      return true;
    case 'active':
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
    case 'committed_completion_required':
      return false;
    default:
      return assertNeverSessionState(state);
  }
}

function expiryMs(record: LinkedDeviceSessionRecordV1): number {
  switch (record.state.state) {
    case 'displaying_qr':
      return record.state.expiresAtMs;
    case 'claimed_by_owner':
      return record.state.claimExpiresAtMs;
    case 'awaiting_target_passkey':
      return record.state.credentialDeadlineMs;
    case 'provisioning':
    case 'awaiting_aggregate_receipt':
      return record.qrPayload.expiresAtMs;
    default:
      return Number.POSITIVE_INFINITY;
  }
}

function assertNeverSessionState(value: never): never {
  throw new Error(`unsupported linked-device state: ${String(value)}`);
}
