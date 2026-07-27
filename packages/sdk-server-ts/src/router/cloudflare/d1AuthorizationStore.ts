import {
  parseAuthorizationAuditEventId,
  parseCapabilityGrantId,
  parseCapabilityGrantUseId,
  parseCapabilityId,
  parseCapabilityOperationRef,
  parseCapabilityOperationResultStorageRef,
  parseDeviceId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  type AuthorizationParseResult,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  ActiveAuthorizationSession,
  ActiveCapabilityGrant,
  ActiveWalletSessionQuota,
  AuthorizationAuditEvent,
  CapabilityGrantUse,
  CapabilityOperationClaim,
  CapabilityOperationResultRef,
  ClaimCapabilityOperationResult,
  CompleteCapabilityOperationResult,
  CompletedCapabilityOperationResult,
  MpcWalletSigningQuotaId,
  VerifiedGrantEvidenceSet,
  WalletSessionId,
} from '../../authorization/domain';
import {
  parseCapabilityOperationFingerprintDigest,
  type CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import type { AuthorizationStore } from '../../authorization/service';
import { d1ChangedRows, type D1Row } from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';

export type D1AuthorizationStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
};

type GrantClassificationRow = {
  readonly principal_id?: unknown;
  readonly capability_id?: unknown;
  readonly capability_kind?: unknown;
  readonly operation_kind?: unknown;
  readonly evidence_set_digest?: unknown;
  readonly lane_digest?: unknown;
  readonly intent_digest?: unknown;
  readonly display_digest?: unknown;
  readonly authority_kind?: unknown;
  readonly wallet_session_id?: unknown;
  readonly quota_id?: unknown;
  readonly remaining_uses?: unknown;
  readonly lifecycle_kind?: unknown;
  readonly expires_at_ms?: unknown;
};

type QuotaClassificationRow = {
  readonly wallet_session_id?: unknown;
  readonly principal_id?: unknown;
  readonly remaining_uses?: unknown;
  readonly lifecycle_kind?: unknown;
  readonly expires_at_ms?: unknown;
};

export class CloudflareD1AuthorizationStore implements AuthorizationStore {
  private readonly database: D1DatabaseLike;
  private readonly namespace: string;

  constructor(options: D1AuthorizationStoreOptions) {
    this.database = options.database;
    this.namespace = requireOpaqueString(options.namespace, 'namespace');
  }

  async putActiveSession(session: ActiveAuthorizationSession): Promise<void> {
    const result = await this.database
      .prepare(
        `INSERT INTO authorization_sessions (
          namespace,
          tenant_id,
          session_id,
          principal_id,
          device_id,
          assurance,
          lifecycle_kind,
          created_at_ms,
          expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
      )
      .bind(
        this.namespace,
        session.tenantId,
        session.sessionId,
        session.principalId,
        session.deviceId,
        session.assurance,
        requirePositiveInteger(session.createdAtMs, 'session.createdAtMs'),
        requirePositiveInteger(session.expiresAtMs, 'session.expiresAtMs'),
      )
      .run();
    requireOneChangedRow(result, 'active authorization session');
  }

  async putVerifiedEvidenceSet(evidenceSet: VerifiedGrantEvidenceSet): Promise<void> {
    const result = await this.database
      .prepare(
        `INSERT INTO verified_grant_evidence_sets (
          namespace,
          tenant_id,
          evidence_set_id,
          principal_id,
          session_id,
          device_id,
          evidence_set_digest,
          evidence_json,
          capability_kind,
          operation_kind,
          lane_digest,
          intent_digest,
          display_digest,
          assurance,
          expires_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          FROM authorization_sessions AS session
         WHERE session.namespace = ?
           AND session.tenant_id = ?
           AND session.session_id = ?
           AND session.principal_id = ?
           AND session.device_id = ?
           AND session.assurance = ?
           AND session.lifecycle_kind = 'active'
           AND session.expires_at_ms >= ?`,
      )
      .bind(
        this.namespace,
        evidenceSet.tenantId,
        evidenceSet.evidenceSetId,
        evidenceSet.principalId,
        evidenceSet.sessionId,
        evidenceSet.deviceId,
        evidenceSet.evidenceSetDigest,
        JSON.stringify(evidenceSet.evidence),
        evidenceSet.operation.capabilityKind,
        evidenceSet.operation.operationKind,
        evidenceSet.laneDigest,
        evidenceSet.intentDigest,
        evidenceSet.displayDigest,
        evidenceSet.assurance,
        requirePositiveInteger(evidenceSet.expiresAtMs, 'evidenceSet.expiresAtMs'),
        this.namespace,
        evidenceSet.tenantId,
        evidenceSet.sessionId,
        evidenceSet.principalId,
        evidenceSet.deviceId,
        evidenceSet.assurance,
        evidenceSet.expiresAtMs,
      )
      .run();
    requireOneChangedRow(result, 'verified grant evidence set');
  }

  async putActiveGrant(grant: ActiveCapabilityGrant): Promise<void> {
    const authority = grantAuthorityColumns(grant);
    const result = await this.database
      .prepare(
        `INSERT INTO capability_grants (
          namespace,
          tenant_id,
          grant_id,
          principal_id,
          binding_id,
          evidence_set_id,
          evidence_set_digest,
          capability_id,
          capability_kind,
          operation_kind,
          lane_digest,
          intent_digest,
          display_digest,
          authority_kind,
          wallet_session_id,
          quota_id,
          remaining_uses,
          lifecycle_kind,
          created_at_ms,
          expires_at_ms,
          consumed_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL
          FROM verified_grant_evidence_sets AS evidence
         WHERE evidence.namespace = ?
           AND evidence.tenant_id = ?
           AND evidence.evidence_set_id = ?
           AND evidence.principal_id = ?
           AND evidence.evidence_set_digest = ?
           AND evidence.capability_kind = ?
           AND evidence.operation_kind = ?
           AND evidence.lane_digest = ?
           AND evidence.intent_digest = ?
           AND evidence.display_digest = ?
           AND evidence.expires_at_ms >= ?`,
      )
      .bind(
        this.namespace,
        grant.tenantId,
        grant.grantId,
        grant.principalId,
        grant.bindingId,
        grant.evidenceSetId,
        grant.evidenceSetDigest,
        grant.capabilityId,
        grant.operation.capabilityKind,
        grant.operation.operationKind,
        grant.laneDigest,
        grant.intentDigest,
        grant.displayDigest,
        authority.kind,
        authority.walletSessionId,
        authority.quotaId,
        requirePositiveInteger(grant.remainingUses, 'grant.remainingUses'),
        requirePositiveInteger(grant.createdAtMs, 'grant.createdAtMs'),
        requirePositiveInteger(grant.expiresAtMs, 'grant.expiresAtMs'),
        this.namespace,
        grant.tenantId,
        grant.evidenceSetId,
        grant.principalId,
        grant.evidenceSetDigest,
        grant.operation.capabilityKind,
        grant.operation.operationKind,
        grant.laneDigest,
        grant.intentDigest,
        grant.displayDigest,
        grant.expiresAtMs,
      )
      .run();
    requireOneChangedRow(result, 'active capability grant');
  }

  async putActiveWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void> {
    const result = await this.database
      .prepare(
        `INSERT INTO authorization_wallet_session_quotas (
          namespace,
          tenant_id,
          quota_id,
          wallet_session_id,
          principal_id,
          remaining_uses,
          lifecycle_kind,
          expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .bind(
        this.namespace,
        quota.tenantId,
        quota.quotaId,
        quota.walletSessionId,
        quota.principalId,
        requirePositiveInteger(quota.remainingUses, 'quota.remainingUses'),
        requirePositiveInteger(quota.expiresAtMs, 'quota.expiresAtMs'),
      )
      .run();
    requireOneChangedRow(result, 'active Wallet Session quota');
  }

  async claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult> {
    const existing = await this.readUseByFingerprint(
      claim.tenantId,
      claim.operationFingerprintDigest,
    );
    if (existing) return replayResult(existing, claim);

    const authorization = claimAuthorizationColumns(claim);
    try {
      const result = await this.database
        .prepare(
          `INSERT INTO capability_grant_uses (
            namespace,
            tenant_id,
            use_id,
            audit_event_id,
            grant_id,
            principal_id,
            capability_id,
            capability_kind,
            operation_kind,
            operation_id,
            operation_fingerprint_digest,
            evidence_set_digest,
            lane_digest,
            intent_digest,
            display_digest,
            authorization_kind,
            wallet_session_id,
            quota_id,
            quota_kind,
            lifecycle_kind,
            result_kind,
            result_digest,
            result_storage_ref,
            claimed_at_ms,
            completed_at_ms
          ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            'claimed', 'pending', NULL, NULL, ?, NULL
          )`,
        )
        .bind(
          this.namespace,
          claim.tenantId,
          claim.useId,
          claim.auditEventId,
          claim.grantId,
          claim.operation.principalId,
          claim.operation.capabilityId,
          claim.operation.operation.capabilityKind,
          claim.operation.operation.operationKind,
          claim.operation.operationId,
          claim.operationFingerprintDigest,
          claim.evidenceSetDigest,
          claim.operation.digests.laneDigest,
          claim.operation.digests.intentDigest,
          claim.operation.digests.displayDigest,
          authorization.kind,
          authorization.walletSessionId,
          authorization.quotaId,
          claim.quota.kind,
          requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
        )
        .run();
      requireOneChangedRow(result, 'capability operation claim');
    } catch {
      const raced = await this.readUseByFingerprint(
        claim.tenantId,
        claim.operationFingerprintDigest,
      );
      if (raced) return replayResult(raced, claim);
      return await this.classifyRejectedClaim(claim);
    }

    const use = await this.readUseByFingerprint(claim.tenantId, claim.operationFingerprintDigest);
    if (!use || use.kind !== 'claimed') {
      throw new Error('committed capability operation claim could not be read back');
    }
    return { kind: 'claimed', use };
  }

  async completeOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult> {
    const current = await this.readUseByFingerprint(
      input.claim.tenantId,
      input.claim.operationFingerprintDigest,
    );
    if (!current) return { kind: 'claim_missing' };
    if (current.useId !== input.claim.useId || current.grantId !== input.claim.grantId) {
      return { kind: 'claim_mismatch' };
    }
    if (current.kind === 'completed') return { kind: 'already_completed', use: current };

    const update = await this.database
      .prepare(
        `UPDATE capability_grant_uses
            SET lifecycle_kind = 'completed',
                result_kind = ?,
                result_digest = ?,
                result_storage_ref = ?,
                completed_at_ms = ?
          WHERE namespace = ?
            AND tenant_id = ?
            AND use_id = ?
            AND grant_id = ?
            AND operation_fingerprint_digest = ?
            AND lifecycle_kind = 'claimed'`,
      )
      .bind(
        input.result,
        input.resultRef.resultDigest,
        input.resultRef.resultStorageRef,
        requirePositiveInteger(input.completedAtMs, 'completedAtMs'),
        this.namespace,
        input.claim.tenantId,
        input.claim.useId,
        input.claim.grantId,
        input.claim.operationFingerprintDigest,
      )
      .run();
    if (d1ChangedRows(update) !== 1) {
      const raced = await this.readUseByFingerprint(
        input.claim.tenantId,
        input.claim.operationFingerprintDigest,
      );
      if (raced?.kind === 'completed') return { kind: 'already_completed', use: raced };
      return raced ? { kind: 'claim_mismatch' } : { kind: 'claim_missing' };
    }
    const completed = await this.readUseByFingerprint(
      input.claim.tenantId,
      input.claim.operationFingerprintDigest,
    );
    if (!completed || completed.kind !== 'completed') {
      throw new Error('completed capability operation could not be read back');
    }
    return { kind: 'completed', use: completed };
  }

  async readAuditEvent(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly eventId: CapabilityOperationClaim['auditEventId'];
  }): Promise<AuthorizationAuditEvent | null> {
    const row = await this.database
      .prepare(
        `SELECT *
           FROM authorization_audit_events
          WHERE namespace = ?
            AND tenant_id = ?
            AND event_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.eventId)
      .first<D1Row>();
    return row ? parseAuditEventRow(row) : null;
  }

  private async readUseByFingerprint(
    tenantId: CapabilityOperationClaim['tenantId'],
    fingerprint: CapabilityOperationFingerprintDigest,
  ): Promise<CapabilityGrantUse | null> {
    const row = await this.database
      .prepare(
        `SELECT *
           FROM capability_grant_uses
          WHERE namespace = ?
            AND tenant_id = ?
            AND operation_fingerprint_digest = ?
          LIMIT 1`,
      )
      .bind(this.namespace, tenantId, fingerprint)
      .first<D1Row>();
    return row ? parseCapabilityGrantUseRow(row) : null;
  }

  private async classifyRejectedClaim(
    claim: CapabilityOperationClaim,
  ): Promise<ClaimCapabilityOperationResult> {
    const grant = await this.database
      .prepare(
        `SELECT *
           FROM capability_grants
          WHERE namespace = ?
            AND tenant_id = ?
            AND grant_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, claim.tenantId, claim.grantId)
      .first<GrantClassificationRow>();
    if (!grant || !grantMatchesClaim(grant, claim)) return { kind: 'grant_mismatch' };
    if (integerColumn(grant.expires_at_ms, 'grant.expires_at_ms') <= claim.claimedAtMs) {
      return { kind: 'grant_expired' };
    }
    if (
      grant.lifecycle_kind !== 'active' ||
      integerColumn(grant.remaining_uses, 'grant.remaining_uses') <= 0
    ) {
      return { kind: 'grant_exhausted' };
    }
    if (claim.quota.kind === 'quota_neutral') {
      throw new Error('authorization claim failed despite an eligible quota-neutral grant');
    }

    const quota = await this.database
      .prepare(
        `SELECT *
           FROM authorization_wallet_session_quotas
          WHERE namespace = ?
            AND tenant_id = ?
            AND quota_id = ?
          LIMIT 1`,
      )
      .bind(
        this.namespace,
        claim.tenantId,
        claim.authorization.kind === 'reusable_wallet_session' ? claim.authorization.quotaId : '',
      )
      .first<QuotaClassificationRow>();
    if (!quota || !quotaMatchesClaim(quota, claim)) return { kind: 'wallet_session_mismatch' };
    if (integerColumn(quota.expires_at_ms, 'quota.expires_at_ms') <= claim.claimedAtMs) {
      return { kind: 'wallet_session_expired' };
    }
    if (
      quota.lifecycle_kind !== 'active' ||
      integerColumn(quota.remaining_uses, 'quota.remaining_uses') <= 0
    ) {
      return { kind: 'wallet_session_quota_exhausted' };
    }
    throw new Error('authorization claim failed despite eligible grant and Wallet Session quota');
  }
}

function grantAuthorityColumns(grant: ActiveCapabilityGrant): {
  readonly kind: ActiveCapabilityGrant['authority']['kind'];
  readonly walletSessionId: WalletSessionId | null;
  readonly quotaId: MpcWalletSigningQuotaId | null;
} {
  switch (grant.authority.kind) {
    case 'reusable_wallet_session':
      return {
        kind: grant.authority.kind,
        walletSessionId: grant.authority.walletSessionId,
        quotaId: grant.authority.quotaId,
      };
    case 'operation_step_up':
      return {
        kind: grant.authority.kind,
        walletSessionId: null,
        quotaId: null,
      };
  }
}

function claimAuthorizationColumns(claim: CapabilityOperationClaim): {
  readonly kind: CapabilityOperationClaim['authorization']['kind'];
  readonly walletSessionId: WalletSessionId | null;
  readonly quotaId: MpcWalletSigningQuotaId | null;
} {
  switch (claim.authorization.kind) {
    case 'reusable_wallet_session':
      return {
        kind: claim.authorization.kind,
        walletSessionId: claim.authorization.walletSessionId,
        quotaId: claim.authorization.quotaId,
      };
    case 'operation_step_up':
      return {
        kind: claim.authorization.kind,
        walletSessionId: null,
        quotaId: null,
      };
  }
}

function replayResult(
  use: CapabilityGrantUse,
  claim: CapabilityOperationClaim,
): ClaimCapabilityOperationResult {
  if (
    use.principalId !== claim.operation.principalId ||
    use.capabilityId !== claim.operation.capabilityId ||
    use.operation.capabilityKind !== claim.operation.operation.capabilityKind ||
    use.operation.operationKind !== claim.operation.operation.operationKind ||
    use.evidenceSetDigest !== claim.evidenceSetDigest
  ) {
    return { kind: 'grant_mismatch' };
  }
  switch (use.kind) {
    case 'claimed':
      return { kind: 'operation_in_progress', use };
    case 'completed':
      return { kind: 'replayed', use };
  }
}

function grantMatchesClaim(row: GrantClassificationRow, claim: CapabilityOperationClaim): boolean {
  const authorization = claimAuthorizationColumns(claim);
  return (
    row.principal_id === claim.operation.principalId &&
    row.capability_id === claim.operation.capabilityId &&
    row.capability_kind === claim.operation.operation.capabilityKind &&
    row.operation_kind === claim.operation.operation.operationKind &&
    row.evidence_set_digest === claim.evidenceSetDigest &&
    row.lane_digest === claim.operation.digests.laneDigest &&
    row.intent_digest === claim.operation.digests.intentDigest &&
    row.display_digest === claim.operation.digests.displayDigest &&
    row.authority_kind === authorization.kind &&
    nullableString(row.wallet_session_id) === authorization.walletSessionId &&
    nullableString(row.quota_id) === authorization.quotaId
  );
}

function quotaMatchesClaim(row: QuotaClassificationRow, claim: CapabilityOperationClaim): boolean {
  if (claim.authorization.kind !== 'reusable_wallet_session') return false;
  return (
    row.wallet_session_id === claim.authorization.walletSessionId &&
    row.principal_id === claim.operation.principalId
  );
}

function parseCapabilityGrantUseRow(row: D1Row): CapabilityGrantUse {
  const base = {
    tenantId: requireParsed(row.tenant_id, parseTenantId, 'use.tenantId'),
    useId: requireParsed(row.use_id, parseCapabilityGrantUseId, 'use.useId'),
    grantId: requireParsed(row.grant_id, parseCapabilityGrantId, 'use.grantId'),
    principalId: requireParsed(row.principal_id, parsePrincipalId, 'use.principalId'),
    capabilityId: requireParsed(row.capability_id, parseCapabilityId, 'use.capabilityId'),
    operation: requireParsed(
      {
        capabilityKind: row.capability_kind,
        operationKind: row.operation_kind,
      },
      parseCapabilityOperationRef,
      'use.operation',
    ),
    operationFingerprintDigest: parseOperationFingerprint(row.operation_fingerprint_digest),
    evidenceSetDigest: parseDigestB64u(row.evidence_set_digest),
    claimedAtMs: integerColumn(row.claimed_at_ms, 'use.claimedAtMs'),
  };
  if (row.lifecycle_kind === 'claimed' && row.result_kind === 'pending') {
    return {
      kind: 'claimed',
      tenantId: base.tenantId,
      useId: base.useId,
      grantId: base.grantId,
      principalId: base.principalId,
      capabilityId: base.capabilityId,
      operation: base.operation,
      operationFingerprintDigest: base.operationFingerprintDigest,
      evidenceSetDigest: base.evidenceSetDigest,
      claimedAtMs: base.claimedAtMs,
    };
  }
  if (row.lifecycle_kind !== 'completed' || !isCompletedResult(row.result_kind)) {
    throw new Error('capability grant use row has an invalid lifecycle');
  }
  return {
    kind: 'completed',
    tenantId: base.tenantId,
    useId: base.useId,
    grantId: base.grantId,
    principalId: base.principalId,
    capabilityId: base.capabilityId,
    operation: base.operation,
    operationFingerprintDigest: base.operationFingerprintDigest,
    evidenceSetDigest: base.evidenceSetDigest,
    claimedAtMs: base.claimedAtMs,
    result: row.result_kind,
    resultRef: {
      resultDigest: parseDigestB64u(row.result_digest),
      resultStorageRef: requireParsed(
        row.result_storage_ref,
        parseCapabilityOperationResultStorageRef,
        'use.resultStorageRef',
      ),
    },
    completedAtMs: integerColumn(row.completed_at_ms, 'use.completedAtMs'),
  };
}

function parseAuditEventRow(row: D1Row): AuthorizationAuditEvent {
  if (!isAuditResult(row.result_kind)) {
    throw new Error('authorization audit row has an invalid result');
  }
  return {
    kind: 'authorization_audit_event',
    tenantId: requireParsed(row.tenant_id, parseTenantId, 'audit.tenantId'),
    eventId: requireParsed(row.event_id, parseAuthorizationAuditEventId, 'audit.eventId'),
    principalId: requireParsed(row.principal_id, parsePrincipalId, 'audit.principalId'),
    sessionId: requireParsed(row.session_id, parseSeamsSessionId, 'audit.sessionId'),
    deviceId: requireParsed(row.device_id, parseDeviceId, 'audit.deviceId'),
    grantId: requireParsed(row.grant_id, parseCapabilityGrantId, 'audit.grantId'),
    useId: requireParsed(row.use_id, parseCapabilityGrantUseId, 'audit.useId'),
    capabilityId: requireParsed(row.capability_id, parseCapabilityId, 'audit.capabilityId'),
    operation: requireParsed(
      {
        capabilityKind: row.capability_kind,
        operationKind: row.operation_kind,
      },
      parseCapabilityOperationRef,
      'audit.operation',
    ),
    operationFingerprintDigest: parseOperationFingerprint(row.operation_fingerprint_digest),
    evidenceSetDigest: parseDigestB64u(row.evidence_set_digest),
    result: row.result_kind,
    createdAtMs: integerColumn(row.created_at_ms, 'audit.createdAtMs'),
  };
}

function requireParsed<T>(
  value: unknown,
  parser: (raw: unknown) => AuthorizationParseResult<T>,
  label: string,
): T {
  const parsed = parser(value);
  if (!parsed.ok) throw new Error(`${label}: ${parsed.error.message}`);
  return parsed.value;
}

function parseOperationFingerprint(value: unknown): CapabilityOperationFingerprintDigest {
  return parseCapabilityOperationFingerprintDigest(value);
}

function isCompletedResult(value: unknown): value is CompletedCapabilityOperationResult {
  return (
    value === 'succeeded' ||
    value === 'failed_before_side_effect' ||
    value === 'failed_after_side_effect'
  );
}

function isAuditResult(value: unknown): value is AuthorizationAuditEvent['result'] {
  return value === 'claimed' || isCompletedResult(value);
}

function nullableString(value: unknown): string | null {
  return value == null ? null : requireOpaqueString(value, 'nullable identifier');
}

function integerColumn(value: unknown, label: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${label} must be a safe integer`);
  return parsed;
}

function requirePositiveInteger(value: unknown, label: string): number {
  const parsed = integerColumn(value, label);
  if (parsed <= 0) throw new Error(`${label} must be positive`);
  return parsed;
}

function requireOpaqueString<T extends string = string>(value: unknown, label: string): T {
  if (
    typeof value !== 'string' ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > 512 ||
    /[\s\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${label} must be a compact opaque identifier`);
  }
  return value as T;
}

function requireOneChangedRow(
  result: { readonly meta?: { readonly changes?: number } },
  label: string,
): void {
  if (d1ChangedRows({ success: true, meta: result.meta }) !== 1) {
    throw new Error(`${label} was not persisted`);
  }
}
