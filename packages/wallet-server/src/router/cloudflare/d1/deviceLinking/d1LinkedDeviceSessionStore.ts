import { alphabetizeStringify } from '@shared/utils/digests';
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
  LinkSessionStateV1,
  LinkedDeviceApprovalV1,
  LinkedDeviceSessionClaimV1,
} from '@shared/device-linking/contracts';
import { assertNeverLinkSessionStateV1 } from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionListCursorV1,
  type LinkedDeviceSessionListPageV1,
  type LinkedDeviceSessionMutationResultV1,
  type LinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionStoreV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { hasControlCharacter } from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletAuthorityId, WalletId } from '@shared/utils/domainIds';

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
const SESSION_CAS_GUARD_SQL = `INSERT INTO linked_device_session_cas_guard (guard_id)
SELECT 1 WHERE changes() = 0`;

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
      return invalidStateResult(normalized);
    }
    let insertError: unknown;
    try {
      const result = await this.database
        .prepare(
          `INSERT INTO ${SESSION_TABLE} (
             namespace, org_id, project_id, env_id, link_session_id,
             link_public_key_b64u, device_public_key_b64u, state, record_json,
             revision, expires_at_ms, claim_expires_at_ms, claim_digest_b64u,
             approval_digest_b64u, authority_id, package_set_digest_b64u,
             created_at_ms, updated_at_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(...scopeValues(this.scope), ...sessionColumnValues(normalized))
        .run();
      if (d1ChangedRows(result) === 1) return { outcome: 'applied', record: normalized };
    } catch (error: unknown) {
      insertError = error;
    }
    const existing = await this.getSessionV1(normalized.linkSessionId);
    if (!existing) {
      if (insertError) throw insertError;
      throw new Error('linked-device session insert did not persist');
    }
    if (sameQrPayload(existing, normalized)) return { outcome: 'replayed', record: existing };
    return conflictResult(1, existing);
  }

  async getSessionV1(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<LinkedDeviceSessionRecordV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT link_session_id, link_public_key_b64u, device_public_key_b64u,
                state, record_json, revision, expires_at_ms, claim_expires_at_ms,
                claim_digest_b64u, approval_digest_b64u, authority_id,
                package_set_digest_b64u, created_at_ms, updated_at_ms
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
      ? ` AND (updated_at_ms < ?6 OR (updated_at_ms = ?6 AND link_session_id > ?7))`
      : '';
    const limitParameter = input.cursor ? '?8' : '?6';
    const rows = await queryD1All(
      this.database,
      `SELECT link_session_id, link_public_key_b64u, device_public_key_b64u,
              state, record_json, revision, expires_at_ms, claim_expires_at_ms,
              claim_digest_b64u, approval_digest_b64u, authority_id,
              package_set_digest_b64u, created_at_ms, updated_at_ms
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
          AND transcript.link_session_id IN (${sessionIds.map((_, index) => `?${index + 5}`).join(', ')})
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
    readonly claimDigestB64u: DigestB64u;
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
      nextStates: ['claimed'],
      current,
    });
  }

  async recordOwnerApprovalV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly approval: LinkedDeviceApprovalV1;
    readonly approvalDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return conflictResult(input.expectedRevision, null);
    if (sameApproval(current, input.approvalDigestB64u, input.approval))
      return { outcome: 'replayed', record: current };
    if (current.state.state !== 'claimed') return invalidStateResult(current);
    if (!current.claimTranscript || input.nowMs >= current.claimTranscript.value.claimExpiresAtMs)
      return { outcome: 'expired', record: current };
    return this.applyTranscriptCas({
      kind: 'approval',
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      digestB64u: input.approvalDigestB64u,
      transcript: input.approval,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      nextStates: ['awaiting_target_factor'],
      current,
    });
  }

  async recordTargetCredentialV1(input: {
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
      expectedStates: ['awaiting_target_factor'],
      nextStates: ['provisioning'],
      replay: isProvisioningRecord,
    });
  }

  async recordEmailOtpChallengeStateV1(input: {
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
      expectedStates: ['awaiting_target_factor'],
      nextStates: ['awaiting_target_factor'],
      replay: sameEmailOtpChallenge,
    });
  }

  buildTargetCredentialCasStatementsV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): readonly D1PreparedStatementLike[] {
    const nextRecord = normalizeMutationRecordV1(input);
    if (nextRecord.revision !== input.expectedRevision + 1) {
      throw new Error('linked-device mutation revision is invalid');
    }
    return [this.updateStatement(input), this.database.prepare(SESSION_CAS_GUARD_SQL)];
  }

  /**
   * Builds the session half of the pending-authority transaction. The caller
   * supplies the already validated next record; the CAS guard keeps the
   * authority and session writes in one D1 batch.
   */
  buildAuthorityPendingLocalInstallCasStatementsV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): readonly D1PreparedStatementLike[] {
    const nextRecord = normalizeMutationRecordV1(input);
    if (
      nextRecord.revision !== input.expectedRevision + 1 ||
      nextRecord.state.state !== 'authority_pending_local_install'
    ) {
      throw new Error('linked-device pending-authority session CAS input is invalid');
    }
    return [this.updateStatement(input), this.database.prepare(SESSION_CAS_GUARD_SQL)];
  }

  /** Builds the session half of the pending-to-active authority transaction. */
  buildAuthorityActivationCasStatementsV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): readonly D1PreparedStatementLike[] {
    const nextRecord = normalizeMutationRecordV1(input);
    if (nextRecord.revision !== input.expectedRevision + 1 || nextRecord.state.state !== 'active') {
      throw new Error('linked-device active-authority session CAS input is invalid');
    }
    return [this.updateStatement(input), this.database.prepare(SESSION_CAS_GUARD_SQL)];
  }

  async markAuthorityPendingLocalInstallV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly authorityId: WalletAuthorityId;
    readonly packageSetDigestB64u: DigestB64u;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: ['provisioning'],
      nextStates: ['authority_pending_local_install'],
      replay: (record) =>
        record.state.state === 'authority_pending_local_install' &&
        record.state.authorityId === input.authorityId &&
        record.state.packageSetDigestB64u === input.packageSetDigestB64u,
    });
  }

  async activateSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly authorityId: WalletAuthorityId;
    readonly packageSetDigestB64u: DigestB64u;
    readonly activatedAtMs: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return conflictResult(input.expectedRevision, null);
    if (
      current.state.state === 'active' &&
      current.state.authorityId === input.authorityId &&
      current.packageSetDigestB64u === input.packageSetDigestB64u
    ) {
      return { outcome: 'replayed', record: current };
    }
    if (current.state.state !== 'authority_pending_local_install')
      return invalidStateResult(current);
    if (
      current.state.authorityId !== input.authorityId ||
      current.state.packageSetDigestB64u !== input.packageSetDigestB64u
    ) {
      return integrityResult(
        current,
        current.state.authorityId !== input.authorityId
          ? 'authority_id_mismatch'
          : 'package_set_digest_mismatch',
      );
    }
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: ['authority_pending_local_install'],
      nextStates: ['active'],
      replay: isActiveRecord,
    });
  }

  async failBeforeCommitV1(input: {
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
      expectedStates: ['displaying_qr', 'claimed', 'awaiting_target_factor', 'provisioning'],
      nextStates: ['failed_before_commit'],
      replay: isFailedRecord,
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
      expectedStates: ['displaying_qr', 'claimed', 'awaiting_target_factor', 'provisioning'],
      nextStates: ['cancelled'],
      replay: isCancelledRecord,
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
    if (current.state.state === 'expired') return { outcome: 'replayed', record: current };
    if (!isExpirableState(current.state)) return invalidStateResult(current);
    if (input.nowMs < expiryMs(current)) return invalidStateResult(current);
    return this.applyStateCas({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord: input.nextRecord,
      nowMs: input.nowMs,
      expectedStates: ['displaying_qr', 'claimed', 'awaiting_target_factor', 'provisioning'],
      nextStates: ['expired'],
      replay: isExpiredRecord,
    });
  }

  async deleteActiveSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly authorityId: WalletAuthorityId;
    readonly packageSetDigestB64u: DigestB64u;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return { outcome: 'deleted', record: null };
    if (current.state.state !== 'active') return invalidStateResult(current);
    if (current.state.authorityId !== input.authorityId) {
      return integrityResult(current, 'authority_id_mismatch');
    }
    if (current.packageSetDigestB64u !== input.packageSetDigestB64u) {
      return integrityResult(current, 'package_set_digest_mismatch');
    }
    if (current.revision !== input.expectedRevision) {
      return conflictResult(input.expectedRevision, current);
    }
    await this.database.batch([
      this.database
        .prepare(
          `DELETE FROM ${TRANSCRIPT_TABLE}
             WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
               AND link_session_id = ?`,
        )
        .bind(...scopeValues(this.scope), String(input.linkSessionId)),
      this.database
        .prepare(
          `DELETE FROM ${SESSION_TABLE}
             WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
               AND link_session_id = ? AND revision = ?`,
        )
        .bind(...scopeValues(this.scope), String(input.linkSessionId), input.expectedRevision),
      this.database.prepare(SESSION_CAS_GUARD_SQL),
    ]);
    const persisted = await this.getSessionV1(input.linkSessionId);
    return persisted
      ? resolveMutationRace(input.expectedRevision, persisted)
      : { outcome: 'deleted', record: null };
  }

  private async applyTranscriptCas(input: {
    readonly kind: 'claim' | 'approval';
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly digestB64u: DigestB64u;
    readonly transcript: LinkedDeviceSessionClaimV1 | LinkedDeviceApprovalV1;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
    readonly nextStates: readonly LinkSessionStateV1['state'][];
    readonly current: LinkedDeviceSessionRecordV1;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const nextRecord = normalizeMutationRecordV1(input);
    if (nextRecord.revision !== input.current.revision + 1) {
      throw new Error('linked-device mutation revision is invalid');
    }
    if (!input.nextStates.includes(nextRecord.state.state)) {
      throw new Error('linked-device transcript transition is invalid');
    }
    const transcript =
      input.kind === 'claim' ? nextRecord.claimTranscript : nextRecord.approvalTranscript;
    if (
      !transcript ||
      transcript.digestB64u !== input.digestB64u ||
      alphabetizeStringify(transcript.value) !== alphabetizeStringify(input.transcript)
    ) {
      throw new Error('linked-device transcript does not match the next record');
    }
    const update = this.updateStatement({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord,
      nowMs: input.nowMs,
    });
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
        JSON.stringify(transcript.value),
        input.nowMs,
      );
    try {
      await this.database.batch([
        update,
        transcriptInsert,
        this.database.prepare(SESSION_CAS_GUARD_SQL),
      ]);
    } catch {
      const raced = await this.getSessionV1(input.linkSessionId);
      if (!raced) throw new Error('linked-device session disappeared after transcript CAS');
      if (
        input.kind === 'claim'
          ? sameClaim(raced, input.digestB64u, input.transcript)
          : sameApproval(raced, input.digestB64u, input.transcript)
      ) {
        return { outcome: 'replayed', record: raced };
      }
      return conflictResult(input.expectedRevision, raced);
    }
    const persisted = await this.getSessionV1(input.linkSessionId);
    if (!persisted) throw new Error('linked-device session disappeared after CAS');
    return persisted.revision === nextRecord.revision &&
      alphabetizeStringify(persisted) === alphabetizeStringify(nextRecord)
      ? { outcome: 'applied', record: persisted }
      : resolveMutationRace(input.expectedRevision, persisted);
  }

  private async applyStateCas(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
    readonly expectedStates: readonly LinkSessionStateV1['state'][];
    readonly nextStates: readonly LinkSessionStateV1['state'][];
    readonly replay: (
      record: LinkedDeviceSessionRecordV1,
      nextRecord: LinkedDeviceSessionRecordV1,
    ) => boolean;
  }): Promise<LinkedDeviceSessionMutationResultV1> {
    const current = await this.getSessionV1(input.linkSessionId);
    if (!current) return conflictResult(input.expectedRevision, null);
    const nextRecord = normalizeMutationRecordV1(input);
    if (nextRecord.revision !== current.revision + 1) {
      throw new Error('linked-device mutation revision is invalid');
    }
    if (!input.nextStates.includes(nextRecord.state.state)) {
      throw new Error('linked-device state transition is invalid');
    }
    if (input.replay(current, nextRecord)) return { outcome: 'replayed', record: current };
    if (!input.expectedStates.includes(current.state.state)) return invalidStateResult(current);
    await this.updateStatement({
      linkSessionId: input.linkSessionId,
      expectedRevision: input.expectedRevision,
      nextRecord,
      nowMs: input.nowMs,
    }).run();
    const persisted = await this.getSessionV1(input.linkSessionId);
    if (!persisted) throw new Error('linked-device session disappeared after state CAS');
    return persisted.revision === nextRecord.revision &&
      alphabetizeStringify(persisted) === alphabetizeStringify(nextRecord)
      ? { outcome: 'applied', record: persisted }
      : resolveMutationRace(input.expectedRevision, persisted);
  }

  private updateStatement(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nextRecord: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): D1PreparedStatementLike {
    const record = normalizeMutationRecordV1(input);
    return this.database
      .prepare(
        `UPDATE ${SESSION_TABLE}
            SET state = ?, record_json = ?, revision = ?, expires_at_ms = ?,
                claim_expires_at_ms = ?, claim_digest_b64u = ?,
                approval_digest_b64u = ?, authority_id = ?,
                package_set_digest_b64u = ?, updated_at_ms = ?
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
        record.authorityId ? String(record.authorityId) : null,
        record.packageSetDigestB64u ?? null,
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
    const expected = new Map<string, { readonly digestB64u: DigestB64u; readonly json: string }>();
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
    const actual = new Map<string, { readonly digestB64u: DigestB64u; readonly json: string }>();
    for (const row of rows) {
      const parsed = parseD1LinkedDeviceSessionTranscriptRowV1(row);
      if (actual.has(parsed.kind)) throw new Error('duplicate linked-device transcript');
      actual.set(parsed.kind, {
        digestB64u: parsed.digestB64u,
        json: alphabetizeStringify(parsed.transcriptJson),
      });
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
  if (!Number.isSafeInteger(raw) || Number(raw) < 0) throw new Error(`${field} is invalid`);
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
    record.authorityId ? String(record.authorityId) : null,
    record.packageSetDigestB64u ?? null,
    record.createdAtMs,
    record.updatedAtMs,
  ];
}

function normalizeMutationRecordV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly nextRecord: unknown;
  readonly nowMs: number;
}): LinkedDeviceSessionRecordV1 {
  const record = parseLinkedDeviceSessionRecordV1(input.nextRecord);
  if (String(record.linkSessionId) !== String(input.linkSessionId)) {
    throw new Error('linked-device mutation session id does not match');
  }
  if (!Number.isSafeInteger(record.revision) || record.revision < 1) {
    throw new Error('linked-device mutation revision is invalid');
  }
  if (record.updatedAtMs !== input.nowMs) {
    throw new Error('linked-device mutation timestamp is invalid');
  }
  return record;
}

function sameQrPayload(
  left: LinkedDeviceSessionRecordV1,
  right: LinkedDeviceSessionRecordV1,
): boolean {
  return alphabetizeStringify(left.qrPayload) === alphabetizeStringify(right.qrPayload);
}

function sameClaim(
  record: LinkedDeviceSessionRecordV1,
  digest: DigestB64u,
  value: unknown,
): boolean {
  return Boolean(
    record.claimTranscript &&
    record.claimTranscript.digestB64u === digest &&
    alphabetizeStringify(record.claimTranscript.value) === alphabetizeStringify(value),
  );
}

function sameApproval(
  record: LinkedDeviceSessionRecordV1,
  digest: DigestB64u,
  value: unknown,
): boolean {
  return Boolean(
    record.approvalTranscript &&
    record.approvalTranscript.digestB64u === digest &&
    alphabetizeStringify(record.approvalTranscript.value) === alphabetizeStringify(value),
  );
}

function isProvisioningRecord(
  record: LinkedDeviceSessionRecordV1,
  nextRecord: LinkedDeviceSessionRecordV1,
): boolean {
  return (
    record.state.state === 'provisioning' &&
    alphabetizeStringify(record) === alphabetizeStringify(nextRecord)
  );
}

function sameEmailOtpChallenge(
  record: LinkedDeviceSessionRecordV1,
  nextRecord: LinkedDeviceSessionRecordV1,
): boolean {
  return (
    record.state.state === 'awaiting_target_factor' &&
    nextRecord.state.state === 'awaiting_target_factor' &&
    alphabetizeStringify(record.emailOtpChallenge) ===
      alphabetizeStringify(nextRecord.emailOtpChallenge)
  );
}

function isActiveRecord(record: LinkedDeviceSessionRecordV1): boolean {
  return record.state.state === 'active';
}

function isFailedRecord(record: LinkedDeviceSessionRecordV1): boolean {
  return record.state.state === 'failed_before_commit';
}

function isCancelledRecord(record: LinkedDeviceSessionRecordV1): boolean {
  return record.state.state === 'cancelled';
}

function isExpiredRecord(record: LinkedDeviceSessionRecordV1): boolean {
  return record.state.state === 'expired';
}

function isExpirableState(state: LinkSessionStateV1): boolean {
  switch (state.state) {
    case 'displaying_qr':
    case 'claimed':
    case 'awaiting_target_factor':
    case 'provisioning':
      return true;
    case 'authority_pending_local_install':
    case 'active':
    case 'failed_before_commit':
    case 'cancelled':
    case 'expired':
      return false;
    default:
      return assertNeverLinkSessionStateV1(state);
  }
}

function expiryMs(record: LinkedDeviceSessionRecordV1): number {
  switch (record.state.state) {
    case 'displaying_qr':
      return record.qrPayload.expiresAtMs;
    case 'claimed':
      return record.claimTranscript?.value.claimExpiresAtMs ?? record.qrPayload.expiresAtMs;
    case 'awaiting_target_factor':
    case 'provisioning':
      return record.approvalTranscript?.value.expiresAtMs ?? record.qrPayload.expiresAtMs;
    case 'authority_pending_local_install':
    case 'active':
    case 'failed_before_commit':
    case 'cancelled':
    case 'expired':
      return Number.POSITIVE_INFINITY;
    default:
      return assertNeverLinkSessionStateV1(record.state);
  }
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

function integrityResult(
  record: LinkedDeviceSessionRecordV1,
  reason: 'authority_id_mismatch' | 'package_set_digest_mismatch',
): LinkedDeviceSessionMutationResultV1 {
  return { outcome: 'integrity_error', reason, record };
}
