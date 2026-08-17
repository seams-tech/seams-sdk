import { alphabetizeStringify } from '@shared/utils/digests';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '@shared/device-linking/digests';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import { d1ChangedRows, queryD1All, type D1Row } from '../../../../storage/d1Sql';
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
  buildCommittedCompletionRequiredLinkedDeviceSessionRecordV1,
  parseLinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionMutationResultV1,
  type LinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionListCursorV1,
  type LinkedDeviceSessionListPageV1,
  type LinkedDeviceSessionStoreV1,
  type LinkedDeviceMutationResultWithReceiptV1,
  type LinkedDeviceRecoveryContinuationV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { hasControlCharacter, type WalletId } from '@shared/utils/domainIds';

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
const SOURCE_HANDOFF_TABLE = 'linked_device_source_handoffs';

/**
 * Turns a lost session CAS into a failed batch.
 *
 * A D1 batch does not roll back on an `UPDATE` that matches nothing — zero rows
 * changed is a successful statement. When the session CAS is riding in another
 * service's batch, that silence is the bug: the batch would commit its own
 * writes against a session that had already moved on. Following the update with
 * an insert that only runs on `changes() = 0`, into a table whose single row
 * already exists, converts the miss into a constraint violation that takes the
 * batch down.
 */
const SESSION_CAS_GUARD_SQL = `INSERT INTO linked_device_session_cas_guard (guard_id)
SELECT 1
 WHERE changes() = 0`;

type CommittedSourceHandoffRowV1 = {
  readonly deliveries_digest_b64u?: unknown;
};

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

  async listSessionsForWalletV1(input: {
    readonly walletId: WalletId;
    readonly limit: number;
    readonly cursor: LinkedDeviceSessionListCursorV1 | null;
  }): Promise<LinkedDeviceSessionListPageV1> {
    if (!Number.isSafeInteger(input.limit) || input.limit < 1) {
      throw new Error('linked-device session list limit is invalid');
    }
    const cursorClause = input.cursor
      ? `
          AND (
            updated_at_ms < ?6
            OR (updated_at_ms = ?6 AND link_session_id > ?7)
          )`
      : '';
    const limitParameter = input.cursor ? '?8' : '?6';
    const rows = await queryD1All(
      this.database,
      `SELECT link_session_id, link_public_key_b64u, device_public_key_b64u,
              state, record_json, revision, expires_at_ms, claim_expires_at_ms,
              claim_digest_b64u, approval_digest_b64u, created_at_ms, updated_at_ms
         FROM ${SESSION_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND json_extract(record_json, '$.approvalTranscript.value.walletId') = ?5
          ${cursorClause}
        ORDER BY updated_at_ms DESC, link_session_id ASC
        LIMIT ${limitParameter}`,
      [
        ...scopeValues(this.scope),
        String(input.walletId),
        ...(input.cursor ? [input.cursor.updatedAtMs, String(input.cursor.linkSessionId)] : []),
        input.limit + 1,
      ],
    );
    if (rows.length === 0) return { records: [], nextCursor: null };
    const sessionIds = rows.map((row) => requiredSessionId(row.link_session_id));
    const transcripts = await queryD1All(
      this.database,
      `SELECT transcript.link_session_id, transcript.transcript_kind,
              transcript.digest_b64u, transcript.transcript_json, transcript.created_at_ms
         FROM ${TRANSCRIPT_TABLE} AS transcript
         JOIN ${SESSION_TABLE} AS session
           ON session.namespace = transcript.namespace
          AND session.org_id = transcript.org_id
          AND session.project_id = transcript.project_id
          AND session.env_id = transcript.env_id
          AND session.link_session_id = transcript.link_session_id
        WHERE transcript.namespace = ?1 AND transcript.org_id = ?2
          AND transcript.project_id = ?3 AND transcript.env_id = ?4
          AND transcript.link_session_id IN (${sessionIds
            .map((_, index) => `?${index + 5}`)
            .join(', ')})
        ORDER BY transcript.link_session_id ASC, transcript.transcript_kind ASC`,
      [...scopeValues(this.scope), ...sessionIds],
    );
    const transcriptBySession = new Map<string, D1Row[]>();
    for (const row of transcripts) {
      const sessionId = requiredSessionId(row.link_session_id);
      const existing = transcriptBySession.get(sessionId);
      if (existing) existing.push(row);
      else transcriptBySession.set(sessionId, [row]);
    }
    const records: LinkedDeviceSessionRecordV1[] = [];
    for (const row of rows) {
      const parsed = parseD1LinkedDeviceSessionRowV1(row);
      await this.verifyImmutableTranscriptsForRows(
        parsed.record,
        transcriptBySession.get(String(parsed.record.linkSessionId)) ?? [],
      );
      records.push(parsed.record);
    }
    const boundary = rows.length > input.limit ? rows[input.limit - 1] : undefined;
    return {
      records: records.slice(0, input.limit),
      nextCursor: boundary
        ? {
            updatedAtMs: requiredTimestamp(boundary.updated_at_ms, 'updated_at_ms'),
            linkSessionId: requiredLinkSessionId(boundary.link_session_id),
          }
        : null,
    };
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
      expectedStates: ['provisioning'],
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

  /**
   * The session CAS as statements, for a caller that must commit it with its
   * own writes or not at all.
   *
   * Device 2's owner finalize is the only caller. Its credential write is
   * irreversible, so the session advance cannot be a second round trip that a
   * cancel or an expiry could win in between — the two go into one batch, and
   * the guard makes a lost CAS fail the batch rather than pass unnoticed.
   *
   * Preconditions are the caller's to check against the record it read; these
   * statements only enforce the one thing a reader cannot: that the session has
   * not moved since it was read.
   */
  buildTargetCredentialCasStatementsV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): readonly D1PreparedStatementLike[] {
    return [
      this.updateStatement({
        kind: 'state',
        linkSessionId: input.linkSessionId,
        expectedRevision: input.expectedRevision,
        nextRecord: input.nextRecord,
        nowMs: input.nowMs,
      }),
      this.database.prepare(SESSION_CAS_GUARD_SQL),
    ];
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
      expectedStates: ['committed_completion_required'],
      replay: (current) =>
        current.state.state === 'active' &&
        Boolean(current.aggregateReceipt) &&
        alphabetizeStringify(current.aggregateReceipt) === alphabetizeStringify(input.receipt),
    });
  }

  async reconcileCommittedProvisioningOutputV1(input: {
    readonly record: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionRecordV1> {
    const record = parseLinkedDeviceSessionRecordV1(input.record);
    if (
      record.state.state !== 'provisioning' &&
      record.state.state !== 'committed_completion_required'
    ) {
      return record;
    }
    const row = await this.database
      .prepare(
        `SELECT deliveries_digest_b64u
           FROM ${SOURCE_HANDOFF_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?
            AND deliveries_json IS NOT NULL AND deliveries_digest_b64u IS NOT NULL
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), String(record.linkSessionId))
      .first<CommittedSourceHandoffRowV1>();
    if (!row) return record;
    const transcriptSetDigestB64u = parseDigestB64u(row.deliveries_digest_b64u);
    if (record.state.state === 'committed_completion_required') {
      if (record.state.transcriptSetDigestB64u !== transcriptSetDigestB64u) {
        throw new Error('committed linked-device output digest changed');
      }
      return record;
    }
    const nextRecord = buildCommittedCompletionRequiredLinkedDeviceSessionRecordV1({
      record,
      transcriptSetDigestB64u,
      committedAtMs: input.nowMs,
    });
    const result = await this.markCommittedCompletionRequiredV1({
      linkSessionId: record.linkSessionId,
      expectedRevision: record.revision,
      transcriptSetDigestB64u,
      nextRecord,
      nowMs: input.nowMs,
    });
    if (result.outcome === 'applied' || result.outcome === 'replayed') return result.record;
    if (
      result.outcome === 'conflict' &&
      result.record?.state.state === 'committed_completion_required' &&
      result.record.state.transcriptSetDigestB64u === transcriptSetDigestB64u &&
      result.record.state.keyManifestDigestB64u === record.state.keyManifestDigestB64u
    ) {
      return result.record;
    }
    throw new Error('linked-device committed output could not advance its parent session');
  }

  async cancelSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return conflictResult(input.expectedRevision, null);
    const reconciled = await this.reconcileCommittedProvisioningOutputV1({
      record: current,
      nowMs: input.nowMs,
    });
    if (reconciled.state.state === 'committed_completion_required') {
      return invalidStateResult(reconciled);
    }
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
      ],
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
    const stored = await this.getSessionV1(input.linkSessionId);
    if (!stored) return conflictResult(input.expectedRevision, null);
    const current = await this.reconcileCommittedProvisioningOutputV1({
      record: stored,
      nowMs: input.nowMs,
    });
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
    await this.verifyImmutableTranscriptsForRows(record, rows.results ?? []);
  }

  private async verifyImmutableTranscriptsForRows(
    record: LinkedDeviceSessionRecordV1,
    rows: readonly {
      readonly transcript_kind?: unknown;
      readonly digest_b64u?: unknown;
      readonly transcript_json?: unknown;
      readonly created_at_ms?: unknown;
    }[],
  ): Promise<void> {
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
    for (const row of rows) {
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
    hasControlCharacter(value)
  )
    throw new Error(`${field} is invalid`);
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function requiredSessionId(raw: unknown): string {
  const parsed = parseLinkDeviceSessionId(raw);
  if (!parsed.ok) throw new Error('linked-device session id is invalid');
  return String(parsed.value);
}

function requiredLinkSessionId(raw: unknown): LinkDeviceSessionId {
  const parsed = parseLinkDeviceSessionId(raw);
  if (!parsed.ok) throw new Error('linked-device session id is invalid');
  return parsed.value;
}

function requiredTimestamp(raw: unknown, field: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) < 0) {
    throw new Error(`${field} is invalid`);
  }
  return Number(raw);
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
      return record.qrPayload.expiresAtMs;
    default:
      return Number.POSITIVE_INFINITY;
  }
}

function assertNeverSessionState(value: never): never {
  throw new Error(`unsupported linked-device state: ${String(value)}`);
}
