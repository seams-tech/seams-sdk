import {
  CAPABILITY_KINDS,
  parseAuthorizationAuditEventId,
  parseCapabilityGrantId,
  parseCapabilityGrantUseId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationRef,
  parseCapabilityOperationResultStorageRef,
  parseDeviceId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseSeamsSessionId,
  parseTenantId,
  type AuthorizationParseResult,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  ActiveAuthorizationSession,
  ActiveCapabilityGrant,
  WalletSessionAuthorization,
  ActiveWalletSessionQuota,
  AuthorizationAuditEvent,
  CapabilityGrantUse,
  CapabilityOperationClaim,
  CapabilityOperationCompletionClaimRef,
  CapabilityOperationResultRef,
  ClaimCapabilityOperationResult,
  CompleteCapabilityOperationResult,
  CompletedCapabilityOperationResult,
  IssuedHostedWalletSeamsSessionExchange,
  MpcWalletSigningQuotaId,
  RedeemHostedWalletSeamsSessionExchangeInput,
  RedeemHostedWalletSeamsSessionExchangeResult,
  ReusableWalletSessionStatus,
  VerifiedGrantEvidenceSet,
  WalletSessionId,
} from '../../authorization/domain';
import {
  buildActiveAuthorizationSession,
  buildWalletSessionAuthorization,
  buildActiveWalletSessionQuota,
  parseMpcWalletSigningQuotaId,
  parseSessionOrigin,
  parseWalletSessionId,
} from '../../authorization/domain';
import {
  parseCapabilityOperationFingerprintDigest,
  type CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import type {
  AuthorizationAuditPort,
  AuthorizationClaimPort,
  AuthorizationEvidencePort,
  CapabilityGrantClaimSource,
  AuthorizationGrantPort,
  AuthorizationSessionPort,
  EcdsaAtomicAuthorizationResult,
  EcdsaMaterialActivationScope,
} from '../../authorization/service';
import { d1ChangedRows, type D1Row } from '../../storage/d1Sql';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../storage/tenantRoute';
import {
  parseAppSessionVersion,
  parseProviderSubject,
  parseWebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';

export type D1AuthorizationStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
};

const ECDSA_SIGNER_MATCH = `
  EXISTS (
    SELECT 1
      FROM wallet_signers AS signer
     WHERE signer.namespace = ?
       AND signer.org_id = ?
       AND signer.project_id = ?
       AND signer.env_id = ?
       AND signer.wallet_id = ?
       AND signer.signer_family = 'ecdsa'
       AND json_extract(signer.record_json, '$.walletKey.publicCapability.material_activation.material_owner') = signer.wallet_id
       AND json_extract(signer.record_json, '$.walletKey.keyHandle') = ?
       AND json_extract(signer.record_json, '$.walletKey.publicCapability.material_activation.kind') = ?
       AND json_extract(signer.record_json, '$.walletKey.publicCapability.material_activation.activation_id') = ?
       AND json_extract(signer.record_json, '$.walletKey.publicCapability.material_activation.capability') = ?
       AND json_extract(signer.record_json, '$.walletKey.publicCapability.material_activation.material_owner') = ?
       AND json_extract(signer.record_json, '$.walletKey.publicCapability.material_activation.key_binding') = ?
       AND json_extract(signer.record_json, '$.walletKey.publicCapability.material_activation.lifecycle_binding') = ?
       AND json_extract(signer.record_json, '$.walletKey.publicCapability.material_activation.signing_worker') = ?
  )`;

function ecdsaSignerMatchBindings(
  namespace: string,
  material: EcdsaMaterialActivationScope,
): readonly unknown[] {
  const activation = material.materialActivation;
  return [
    namespace,
    material.runtimePolicyScope.orgId,
    material.runtimePolicyScope.projectId,
    material.runtimePolicyScope.envId,
    material.walletId,
    material.keyHandle,
    activation.kind,
    activation.activation_id,
    activation.capability,
    activation.material_owner,
    activation.key_binding,
    activation.lifecycle_binding,
    activation.signing_worker,
  ];
}

type AtomicD1Result = {
  readonly success: boolean;
  readonly meta?: { readonly changes?: number };
  readonly results?: readonly Record<string, unknown>[];
};

function isD1ConstraintFailure(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /(?:SQLITE_CONSTRAINT|constraint failed|constraint violation)/i.test(message);
}

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

type HostedWalletExchangeRow = {
  readonly tenant_id?: unknown;
  readonly source_session_id?: unknown;
  readonly code_hash?: unknown;
  readonly nonce_digest?: unknown;
  readonly app_origin?: unknown;
  readonly wallet_origin?: unknown;
  readonly lifecycle_kind?: unknown;
  readonly expires_at_ms?: unknown;
};

export class CloudflareD1AuthorizationStore
  implements
    AuthorizationSessionPort,
    AuthorizationEvidencePort,
    AuthorizationGrantPort,
    AuthorizationClaimPort,
    AuthorizationAuditPort
{
  private readonly database: D1DatabaseLike;
  private readonly namespace: string;

  constructor(options: D1AuthorizationStoreOptions) {
    this.database = options.database;
    this.namespace = requireOpaqueString(options.namespace, 'namespace');
  }

  private async readEcdsaMaterialMatch(
    material: EcdsaMaterialActivationScope,
  ): Promise<boolean> {
    const row = await this.database
      .prepare(`SELECT 1 AS matched WHERE ${ECDSA_SIGNER_MATCH}`)
      .bind(...ecdsaSignerMatchBindings(this.namespace, material))
      .first<D1Row>();
    return row !== null;
  }

  private ecdsaAtomicGuard(input: {
    readonly tenantId: TenantId;
    readonly checkId: string;
    readonly exactMatchSql: string;
    readonly bindings: readonly unknown[];
  }): readonly [D1PreparedStatementLike, D1PreparedStatementLike] {
    const assertExact = this.database
      .prepare(
        `INSERT INTO ecdsa_authorization_atomic_guards (
          namespace, tenant_id, check_id, matched
        ) VALUES (?, ?, ?, (SELECT 1 WHERE ${input.exactMatchSql}))`,
      )
      .bind(this.namespace, input.tenantId, input.checkId, ...input.bindings);
    const clear = this.database
      .prepare(
        `DELETE FROM ecdsa_authorization_atomic_guards
          WHERE namespace = ? AND tenant_id = ? AND check_id = ?`,
      )
      .bind(this.namespace, input.tenantId, input.checkId);
    return [assertExact, clear];
  }

  private async readExactEcdsaEvidence(
    evidenceSet: VerifiedGrantEvidenceSet,
  ): Promise<boolean> {
    const row = await this.database
      .prepare(
        `SELECT 1 AS matched
           FROM verified_grant_evidence_sets
          WHERE namespace = ? AND tenant_id = ? AND evidence_set_id = ?
            AND principal_id = ? AND session_id = ? AND device_id = ?
            AND evidence_set_digest = ? AND evidence_json = ?
            AND capability_kind = ? AND operation_kind = ?
            AND lane_digest = ? AND intent_digest = ? AND display_digest = ?
            AND assurance = ? AND expires_at_ms = ?`,
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
      )
      .first<D1Row>();
    return row !== null;
  }

  private async readExactEcdsaGrant(grant: ActiveCapabilityGrant): Promise<boolean> {
    const authority = grantAuthorityColumns(grant);
    const row = await this.database
      .prepare(
        `SELECT 1 AS matched
           FROM capability_grants
          WHERE namespace = ? AND tenant_id = ? AND grant_id = ?
            AND principal_id = ? AND binding_id = ? AND evidence_set_id = ?
            AND evidence_set_digest = ? AND capability_id = ? AND operation_id = ?
            AND capability_kind = ? AND operation_kind = ?
            AND lane_digest = ? AND intent_digest = ? AND display_digest = ?
            AND authority_kind = ? AND COALESCE(wallet_session_id, '') = COALESCE(?, '')
            AND COALESCE(quota_id, '') = COALESCE(?, '')
            AND remaining_uses = ? AND lifecycle_kind = 'active'
            AND created_at_ms = ? AND expires_at_ms = ? AND consumed_at_ms IS NULL`,
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
        grant.operationId,
        grant.operation.capabilityKind,
        grant.operation.operationKind,
        grant.laneDigest,
        grant.intentDigest,
        grant.displayDigest,
        authority.kind,
        authority.walletSessionId ?? null,
        authority.quotaId ?? null,
        requirePositiveInteger(grant.remainingUses, 'grant.remainingUses'),
        requirePositiveInteger(grant.createdAtMs, 'grant.createdAtMs'),
        requirePositiveInteger(grant.expiresAtMs, 'grant.expiresAtMs'),
      )
      .first<D1Row>();
    return row !== null;
  }

  async putActiveSession(session: ActiveAuthorizationSession): Promise<void> {
    const result = await this.database
      .prepare(
        `INSERT INTO authorization_sessions (
          namespace,
          tenant_id,
          session_id,
          principal_id,
          auth_source_kind,
          auth_source_json,
          device_id,
          audience_kind,
          audience_json,
          app_session_version,
          assurance,
          lifecycle_kind,
          created_at_ms,
          expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
      )
      .bind(
        this.namespace,
        session.tenantId,
        session.sessionId,
        session.principalId,
        session.authSource.kind,
        JSON.stringify(authSourcePayload(session.authSource)),
        session.deviceId,
        session.audience.kind,
        JSON.stringify(audiencePayload(session.audience)),
        session.appSessionVersion,
        session.assurance,
        requirePositiveInteger(session.createdAtMs, 'session.createdAtMs'),
        requirePositiveInteger(session.lifecycle.expiresAtMs, 'session.lifecycle.expiresAtMs'),
      )
      .run();
    requireOneChangedRow(result, 'active authorization session');
  }

  async readActiveSession(input: {
    readonly tenantId: ActiveAuthorizationSession['tenantId'];
    readonly sessionId: ActiveAuthorizationSession['sessionId'];
    readonly nowMs: number;
  }): Promise<ActiveAuthorizationSession | null> {
    const row = await this.database
      .prepare(
        `SELECT *
           FROM authorization_sessions
          WHERE namespace = ?
            AND tenant_id = ?
            AND session_id = ?
            AND lifecycle_kind = 'active'
            AND expires_at_ms > ?
          LIMIT 1`,
      )
      .bind(
        this.namespace,
        input.tenantId,
        input.sessionId,
        requirePositiveInteger(input.nowMs, 'session read time'),
      )
      .first<D1Row>();
    return row ? parseAuthorizationSessionRow(row) : null;
  }

  async readReusableWalletSessionStatus(input: {
    readonly tenantId: ReusableWalletSessionStatus['tenantId'];
    readonly principalId: ReusableWalletSessionStatus['principalId'];
    readonly walletSessionId: ReusableWalletSessionStatus['walletSessionId'];
    readonly quotaId: ReusableWalletSessionStatus['quotaId'];
    readonly nowMs: number;
  }): Promise<ReusableWalletSessionStatus> {
    const identity = {
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
    } as const;
    const row = await this.database
      .prepare(
        `SELECT
           wallet_session.principal_id AS session_principal_id,
           wallet_session.quota_id AS session_quota_id,
           wallet_session.lifecycle_kind AS session_lifecycle_kind,
           wallet_session.expires_at_ms AS session_expires_at_ms,
           quota.wallet_session_id AS quota_wallet_session_id,
           quota.principal_id AS quota_principal_id,
           quota.remaining_uses AS quota_remaining_uses,
           quota.lifecycle_kind AS quota_lifecycle_kind,
           quota.expires_at_ms AS quota_expires_at_ms
         FROM reusable_wallet_sessions AS wallet_session
         LEFT JOIN authorization_wallet_session_quotas AS quota
           ON quota.namespace = wallet_session.namespace
          AND quota.tenant_id = wallet_session.tenant_id
          AND quota.quota_id = wallet_session.quota_id
        WHERE wallet_session.namespace = ?
          AND wallet_session.tenant_id = ?
          AND wallet_session.wallet_session_id = ?
        LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.walletSessionId)
      .first<D1Row>();
    if (!row) return { kind: 'missing', ...identity };
    if (
      row.session_principal_id !== input.principalId ||
      row.session_quota_id !== input.quotaId ||
      row.quota_wallet_session_id !== input.walletSessionId ||
      row.quota_principal_id !== input.principalId
    ) {
      return { kind: 'invalid', ...identity };
    }
    const sessionLifecycle = String(row.session_lifecycle_kind || '');
    const quotaLifecycle = String(row.quota_lifecycle_kind || '');
    const sessionExpiresAtMs = Number(row.session_expires_at_ms);
    const quotaExpiresAtMs = Number(row.quota_expires_at_ms);
    const remainingUses = Number(row.quota_remaining_uses);
    if (
      !Number.isSafeInteger(sessionExpiresAtMs) ||
      sessionExpiresAtMs <= 0 ||
      !Number.isSafeInteger(quotaExpiresAtMs) ||
      quotaExpiresAtMs !== sessionExpiresAtMs ||
      !Number.isSafeInteger(remainingUses) ||
      remainingUses < 0 ||
      (sessionLifecycle !== 'active' && sessionLifecycle !== 'superseded') ||
      (quotaLifecycle !== 'active' && quotaLifecycle !== 'exhausted')
    ) {
      return { kind: 'invalid', ...identity };
    }
    if (sessionLifecycle === 'superseded') {
      if (quotaLifecycle !== 'exhausted' || remainingUses !== 0) {
        return { kind: 'invalid', ...identity };
      }
      return { kind: 'superseded', ...identity };
    }
    if (sessionExpiresAtMs <= requirePositiveInteger(input.nowMs, 'Wallet Session status time')) {
      return { kind: 'expired', ...identity, expiresAtMs: sessionExpiresAtMs };
    }
    if (quotaLifecycle === 'exhausted' && remainingUses === 0) {
      return {
        kind: 'exhausted',
        ...identity,
        remainingUses: 0,
        expiresAtMs: sessionExpiresAtMs,
      };
    }
    if (quotaLifecycle !== 'active' || remainingUses === 0) {
      return { kind: 'invalid', ...identity };
    }
    return {
      kind: 'active',
      ...identity,
      remainingUses,
      expiresAtMs: sessionExpiresAtMs,
    };
  }

  async putIssuedHostedWalletSeamsSessionExchange(
    exchange: IssuedHostedWalletSeamsSessionExchange,
  ): Promise<void> {
    const result = await this.database
      .prepare(
        `INSERT INTO hosted_wallet_session_exchange_codes (
          namespace,
          tenant_id,
          exchange_code_id,
          source_session_id,
          code_hash,
          nonce_digest,
          app_origin,
          wallet_origin,
          lifecycle_kind,
          issued_at_ms,
          expires_at_ms,
          target_session_id,
          consumed_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, 'issued', ?, ?, NULL, NULL
          FROM authorization_sessions AS source
         WHERE source.namespace = ?
           AND source.tenant_id = ?
           AND source.session_id = ?
           AND source.audience_kind = 'first_party_web'
           AND json_extract(source.audience_json, '$.origin') = ?
           AND source.lifecycle_kind = 'active'
           AND source.expires_at_ms > ?`,
      )
      .bind(
        this.namespace,
        exchange.tenantId,
        exchange.exchangeCodeId,
        exchange.sourceSessionId,
        exchange.codeHash,
        exchange.nonceDigest,
        exchange.appOrigin,
        exchange.walletOrigin,
        requirePositiveInteger(exchange.issuedAtMs, 'exchange.issuedAtMs'),
        requirePositiveInteger(exchange.expiresAtMs, 'exchange.expiresAtMs'),
        this.namespace,
        exchange.tenantId,
        exchange.sourceSessionId,
        exchange.appOrigin,
        exchange.issuedAtMs,
      )
      .run();
    requireOneChangedRow(result, 'hosted-wallet Seams session exchange code');
  }

  async redeemHostedWalletSeamsSessionExchange(
    input: RedeemHostedWalletSeamsSessionExchangeInput,
  ): Promise<RedeemHostedWalletSeamsSessionExchangeResult> {
    const current = await this.readHostedWalletExchange(input.codeHash);
    const rejected = classifyHostedWalletExchange(current, input);
    if (rejected) return rejected;
    try {
      const update = await this.database
        .prepare(
          `UPDATE hosted_wallet_session_exchange_codes
              SET lifecycle_kind = 'consumed',
                  target_session_id = ?,
                  consumed_at_ms = ?
            WHERE namespace = ?
              AND code_hash = ?
              AND nonce_digest = ?
              AND wallet_origin = ?
              AND lifecycle_kind = 'issued'
              AND expires_at_ms > ?`,
        )
        .bind(
          input.targetSessionId,
          requirePositiveInteger(input.redeemedAtMs, 'exchange.redeemedAtMs'),
          this.namespace,
          input.codeHash,
          input.nonceDigest,
          input.walletOrigin,
          input.redeemedAtMs,
        )
        .run();
      if (d1ChangedRows(update) !== 1) {
        return (
          classifyHostedWalletExchange(
            await this.readHostedWalletExchange(input.codeHash),
            input,
          ) ?? { kind: 'source_session_unavailable' }
        );
      }
    } catch {
      return { kind: 'source_session_unavailable' };
    }
    if (!current) throw new Error('hosted-wallet Seams session exchange disappeared');
    const session = await this.readActiveSession({
      tenantId: requireParsed(current.tenant_id, parseTenantId, 'exchange.tenantId'),
      sessionId: input.targetSessionId,
      nowMs: input.redeemedAtMs,
    });
    if (!session) {
      throw new Error('redeemed hosted-wallet Seams session could not be read back');
    }
    return { kind: 'redeemed', session };
  }

  async putVerifiedEvidenceSet(evidenceSet: VerifiedGrantEvidenceSet): Promise<void> {
    const result = await this.database
      .prepare(
        `INSERT OR IGNORE INTO verified_grant_evidence_sets (
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
        evidenceSet.expiresAtMs,
      )
      .run();
    if (d1ChangedRows(result) > 1) {
      throw new Error('verified grant evidence set changed more than one row');
    }
  }

  async putActiveGrant(grant: ActiveCapabilityGrant): Promise<void> {
    const authority = grantAuthorityColumns(grant);
    const result = await this.database
      .prepare(
        `INSERT OR IGNORE INTO capability_grants (
          namespace,
          tenant_id,
          grant_id,
          principal_id,
          binding_id,
          evidence_set_id,
          evidence_set_digest,
          capability_id,
          operation_id,
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
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL
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
           AND evidence.expires_at_ms >= ?
           AND (
             ? = 'operation_step_up'
             OR EXISTS (
               SELECT 1
                 FROM reusable_wallet_sessions AS wallet_session
                WHERE wallet_session.namespace = ?
                  AND wallet_session.tenant_id = ?
                  AND wallet_session.wallet_session_id = ?
                  AND wallet_session.principal_id = ?
                  AND wallet_session.quota_id = ?
                  AND wallet_session.lifecycle_kind = 'active'
                  AND wallet_session.expires_at_ms >= ?
             )
           )`,
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
        grant.operationId,
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
        authority.kind,
        this.namespace,
        grant.tenantId,
        authority.walletSessionId,
        grant.principalId,
        authority.quotaId,
        grant.expiresAtMs,
      )
      .run();
    if (d1ChangedRows(result) > 1) {
      throw new Error('active capability grant changed more than one row');
    }
  }

  async putEcdsaEvidenceAndGrant(input: {
    readonly evidenceSet: VerifiedGrantEvidenceSet;
    readonly grant: ActiveCapabilityGrant;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<EcdsaAtomicAuthorizationResult> {
    if (
      input.material.runtimePolicyScope.orgId !== input.evidenceSet.tenantId ||
      input.material.runtimePolicyScope.orgId !== input.grant.tenantId ||
      input.evidenceSet.tenantId !== input.grant.tenantId ||
      input.grant.operation.capabilityKind !== CAPABILITY_KINDS.evmEcdsaMpcSigning ||
      input.material.materialActivation.capability !== input.grant.capabilityId
    ) {
      return { kind: 'material_mismatch' };
    }
    const authority = grantAuthorityColumns(input.grant);
    const signerBindings = ecdsaSignerMatchBindings(this.namespace, input.material);
    const signerCheck = this.database
      .prepare(`SELECT 1 AS matched WHERE ${ECDSA_SIGNER_MATCH}`)
      .bind(...signerBindings);
    const evidenceStatement = this.database
      .prepare(
        `INSERT INTO verified_grant_evidence_sets (
          namespace, tenant_id, evidence_set_id, principal_id, session_id, device_id,
          evidence_set_digest, evidence_json, capability_kind, operation_kind,
          lane_digest, intent_digest, display_digest, assurance, expires_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          FROM authorization_sessions AS session
         WHERE session.namespace = ? AND session.tenant_id = ?
           AND session.session_id = ? AND session.principal_id = ?
           AND session.device_id = ? AND session.lifecycle_kind = 'active'
           AND session.expires_at_ms >= ? AND ${ECDSA_SIGNER_MATCH}`,
      )
      .bind(
        this.namespace,
        input.evidenceSet.tenantId,
        input.evidenceSet.evidenceSetId,
        input.evidenceSet.principalId,
        input.evidenceSet.sessionId,
        input.evidenceSet.deviceId,
        input.evidenceSet.evidenceSetDigest,
        JSON.stringify(input.evidenceSet.evidence),
        input.evidenceSet.operation.capabilityKind,
        input.evidenceSet.operation.operationKind,
        input.evidenceSet.laneDigest,
        input.evidenceSet.intentDigest,
        input.evidenceSet.displayDigest,
        input.evidenceSet.assurance,
        requirePositiveInteger(input.evidenceSet.expiresAtMs, 'evidenceSet.expiresAtMs'),
        this.namespace,
        input.evidenceSet.tenantId,
        input.evidenceSet.sessionId,
        input.evidenceSet.principalId,
        input.evidenceSet.deviceId,
        input.evidenceSet.expiresAtMs,
        ...signerBindings,
      );
    const evidenceCheck = this.database
      .prepare(
        `SELECT 1 AS matched
           FROM verified_grant_evidence_sets
          WHERE namespace = ? AND tenant_id = ? AND evidence_set_id = ?
            AND principal_id = ? AND session_id = ? AND device_id = ?
            AND evidence_set_digest = ? AND evidence_json = ?
            AND capability_kind = ? AND operation_kind = ?
            AND lane_digest = ? AND intent_digest = ? AND display_digest = ?
            AND assurance = ? AND expires_at_ms = ?`,
      )
      .bind(
        this.namespace,
        input.evidenceSet.tenantId,
        input.evidenceSet.evidenceSetId,
        input.evidenceSet.principalId,
        input.evidenceSet.sessionId,
        input.evidenceSet.deviceId,
        input.evidenceSet.evidenceSetDigest,
        JSON.stringify(input.evidenceSet.evidence),
        input.evidenceSet.operation.capabilityKind,
        input.evidenceSet.operation.operationKind,
        input.evidenceSet.laneDigest,
        input.evidenceSet.intentDigest,
        input.evidenceSet.displayDigest,
        input.evidenceSet.assurance,
        requirePositiveInteger(input.evidenceSet.expiresAtMs, 'evidenceSet.expiresAtMs'),
      );
    const grantStatement = this.database
      .prepare(
        `INSERT INTO capability_grants (
          namespace, tenant_id, grant_id, principal_id, binding_id, evidence_set_id,
          evidence_set_digest, capability_id, operation_id, capability_kind,
          operation_kind, lane_digest, intent_digest, display_digest, authority_kind,
          wallet_session_id, quota_id, remaining_uses, lifecycle_kind,
          created_at_ms, expires_at_ms, consumed_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL
          FROM verified_grant_evidence_sets AS evidence
         WHERE evidence.namespace = ? AND evidence.tenant_id = ?
           AND evidence.evidence_set_id = ? AND evidence.principal_id = ?
           AND evidence.evidence_set_digest = ? AND evidence.capability_kind = ?
           AND evidence.operation_kind = ? AND evidence.lane_digest = ?
           AND evidence.intent_digest = ? AND evidence.display_digest = ?
           AND evidence.expires_at_ms >= ?
           AND (? = 'operation_step_up' OR EXISTS (
             SELECT 1 FROM reusable_wallet_sessions AS wallet_session
              WHERE wallet_session.namespace = ? AND wallet_session.tenant_id = ?
                AND wallet_session.wallet_session_id = ?
                AND wallet_session.wallet_id = ?
                AND wallet_session.principal_id = ? AND wallet_session.quota_id = ?
                AND wallet_session.lifecycle_kind = 'active'
                AND wallet_session.expires_at_ms >= ?
           )) AND ${ECDSA_SIGNER_MATCH}`,
      )
      .bind(
        this.namespace,
        input.grant.tenantId,
        input.grant.grantId,
        input.grant.principalId,
        input.grant.bindingId,
        input.grant.evidenceSetId,
        input.grant.evidenceSetDigest,
        input.grant.capabilityId,
        input.grant.operationId,
        input.grant.operation.capabilityKind,
        input.grant.operation.operationKind,
        input.grant.laneDigest,
        input.grant.intentDigest,
        input.grant.displayDigest,
        authority.kind,
        authority.walletSessionId,
        authority.quotaId,
        requirePositiveInteger(input.grant.remainingUses, 'grant.remainingUses'),
        requirePositiveInteger(input.grant.createdAtMs, 'grant.createdAtMs'),
        requirePositiveInteger(input.grant.expiresAtMs, 'grant.expiresAtMs'),
        this.namespace,
        input.grant.tenantId,
        input.grant.evidenceSetId,
        input.grant.principalId,
        input.grant.evidenceSetDigest,
        input.grant.operation.capabilityKind,
        input.grant.operation.operationKind,
        input.grant.laneDigest,
        input.grant.intentDigest,
        input.grant.displayDigest,
        input.grant.expiresAtMs,
        authority.kind,
        this.namespace,
        input.grant.tenantId,
        authority.walletSessionId,
        input.material.walletId,
        input.grant.principalId,
        authority.quotaId,
        input.grant.expiresAtMs,
        ...signerBindings,
      );
    const grantCheck = this.database
      .prepare(
        `SELECT 1 AS matched
           FROM capability_grants
          WHERE namespace = ? AND tenant_id = ? AND grant_id = ?
            AND principal_id = ? AND binding_id = ? AND evidence_set_id = ?
            AND evidence_set_digest = ? AND capability_id = ? AND operation_id = ?
            AND capability_kind = ? AND operation_kind = ?
            AND lane_digest = ? AND intent_digest = ? AND display_digest = ?
            AND authority_kind = ? AND COALESCE(wallet_session_id, '') = COALESCE(?, '')
            AND COALESCE(quota_id, '') = COALESCE(?, '')
            AND remaining_uses = ? AND lifecycle_kind = 'active'
            AND created_at_ms = ? AND expires_at_ms = ? AND consumed_at_ms IS NULL`,
      )
      .bind(
        this.namespace,
        input.grant.tenantId,
        input.grant.grantId,
        input.grant.principalId,
        input.grant.bindingId,
        input.grant.evidenceSetId,
        input.grant.evidenceSetDigest,
        input.grant.capabilityId,
        input.grant.operationId,
        input.grant.operation.capabilityKind,
        input.grant.operation.operationKind,
        input.grant.laneDigest,
        input.grant.intentDigest,
        input.grant.displayDigest,
        authority.kind,
        authority.walletSessionId ?? null,
        authority.quotaId ?? null,
        requirePositiveInteger(input.grant.remainingUses, 'grant.remainingUses'),
        requirePositiveInteger(input.grant.createdAtMs, 'grant.createdAtMs'),
        requirePositiveInteger(input.grant.expiresAtMs, 'grant.expiresAtMs'),
      );
    const [atomicGuard, clearAtomicGuard] = this.ecdsaAtomicGuard({
      tenantId: input.grant.tenantId,
      checkId: `evidence-grant:${input.grant.grantId}`,
      exactMatchSql: `${ECDSA_SIGNER_MATCH}
        AND EXISTS (
          SELECT 1 FROM verified_grant_evidence_sets AS evidence
           WHERE evidence.namespace = ? AND evidence.tenant_id = ?
             AND evidence.evidence_set_id = ? AND evidence.evidence_set_digest = ?
        )
        AND EXISTS (
          SELECT 1 FROM capability_grants AS grant
           WHERE grant.namespace = ? AND grant.tenant_id = ?
             AND grant.grant_id = ? AND grant.evidence_set_digest = ?
             AND grant.capability_id = ? AND grant.operation_id = ?
        )`,
      bindings: [
        ...signerBindings,
        this.namespace,
        input.evidenceSet.tenantId,
        input.evidenceSet.evidenceSetId,
        input.evidenceSet.evidenceSetDigest,
        this.namespace,
        input.grant.tenantId,
        input.grant.grantId,
        input.grant.evidenceSetDigest,
        input.grant.capabilityId,
        input.grant.operationId,
      ],
    });
    let results: readonly AtomicD1Result[];
    try {
      results = await this.database.batch<AtomicD1Result>([
        signerCheck,
        evidenceStatement,
        evidenceCheck,
        grantStatement,
        grantCheck,
        atomicGuard,
        clearAtomicGuard,
      ]);
    } catch (error: unknown) {
      if (
        (await this.readEcdsaMaterialMatch(input.material)) &&
        (await this.readExactEcdsaEvidence(input.evidenceSet)) &&
        (await this.readExactEcdsaGrant(input.grant))
      ) {
        return { kind: 'committed' };
      }
      if (!isD1ConstraintFailure(error)) throw error;
      return { kind: 'material_mismatch' };
    }
    if (results.length !== 7) {
      throw new Error('ECDSA evidence/grant transaction returned incomplete results');
    }
    if (
      (results[0]?.results?.length || 0) === 0 ||
      (results[2]?.results?.length || 0) === 0 ||
      (results[4]?.results?.length || 0) === 0
    ) {
      return { kind: 'material_mismatch' };
    }
    return { kind: 'committed' };
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

  async putWalletSessionAuthorization(input: {
    readonly session: WalletSessionAuthorization;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void> {
    requireExactReusableWalletSessionQuota(input);
    const retireQuotaStatement = this.database
      .prepare(
        `UPDATE authorization_wallet_session_quotas
            SET remaining_uses = 0,
                lifecycle_kind = 'exhausted'
          WHERE namespace = ?
            AND tenant_id = ?
            AND NOT EXISTS (
              SELECT 1
                FROM reusable_wallet_sessions
               WHERE namespace = ?
                 AND tenant_id = ?
                 AND mint_id = ?
            )
            AND quota_id IN (
              SELECT quota_id
                FROM reusable_wallet_sessions
               WHERE namespace = ?
                 AND tenant_id = ?
                 AND wallet_id = ?
                 AND authority_digest = ?
                 AND mint_id != ?
                 AND lifecycle_kind = 'active'
            )`,
      )
      .bind(
        this.namespace,
        input.session.tenantId,
        this.namespace,
        input.session.tenantId,
        input.session.mintId,
        this.namespace,
        input.session.tenantId,
        input.session.walletId,
        input.session.authority.authorityDigest,
        input.session.mintId,
      );
    const retireSessionStatement = this.database
      .prepare(
        `UPDATE reusable_wallet_sessions
            SET lifecycle_kind = 'superseded'
          WHERE namespace = ?
            AND tenant_id = ?
            AND NOT EXISTS (
              SELECT 1
                FROM reusable_wallet_sessions
               WHERE namespace = ?
                 AND tenant_id = ?
                 AND mint_id = ?
            )
            AND wallet_id = ?
            AND authority_digest = ?
            AND mint_id != ?
            AND lifecycle_kind = 'active'`,
      )
      .bind(
        this.namespace,
        input.session.tenantId,
        this.namespace,
        input.session.tenantId,
        input.session.mintId,
        input.session.walletId,
        input.session.authority.authorityDigest,
        input.session.mintId,
      );
    const quotaStatement = this.database
      .prepare(
        `INSERT OR IGNORE INTO authorization_wallet_session_quotas (
          namespace,
          tenant_id,
          quota_id,
          wallet_session_id,
          principal_id,
          remaining_uses,
          lifecycle_kind,
          expires_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, 'active', ?
         WHERE NOT EXISTS (
           SELECT 1
             FROM reusable_wallet_sessions
            WHERE namespace = ?
              AND tenant_id = ?
              AND mint_id = ?
         )`,
      )
      .bind(
        this.namespace,
        input.quota.tenantId,
        input.quota.quotaId,
        input.quota.walletSessionId,
        input.quota.principalId,
        requirePositiveInteger(input.quota.remainingUses, 'quota.remainingUses'),
        requirePositiveInteger(input.quota.expiresAtMs, 'quota.expiresAtMs'),
        this.namespace,
        input.session.tenantId,
        input.session.mintId,
      );
    const sessionStatement = this.database
      .prepare(
        `INSERT OR IGNORE INTO reusable_wallet_sessions (
          namespace,
          tenant_id,
          wallet_session_id,
          principal_id,
          wallet_id,
          authority_digest,
          mint_id,
          quota_id,
          lifecycle_kind,
          created_at_ms,
          expires_at_ms
        )
        VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?
        )`,
      )
      .bind(
        this.namespace,
        input.session.tenantId,
        input.session.walletSessionId,
        input.session.principalId,
        input.session.walletId,
        input.session.authority.authorityDigest,
        input.session.mintId,
        input.session.quotaId,
        requirePositiveInteger(input.session.createdAtMs, 'session.createdAtMs'),
        requirePositiveInteger(input.session.expiresAtMs, 'session.expiresAtMs'),
      );
    const results = await this.database.batch<{
      readonly meta?: { readonly changes?: number };
    }>([retireQuotaStatement, retireSessionStatement, quotaStatement, sessionStatement]);
    if (results.length !== 4) {
      throw new Error('reusable Wallet Session transaction returned incomplete results');
    }
    await this.requireExactReusableWalletSessionReadback(input);
  }

  private async requireExactReusableWalletSessionReadback(input: {
    readonly session: WalletSessionAuthorization;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void> {
    const session = await this.database
      .prepare(
        `SELECT *
           FROM reusable_wallet_sessions
          WHERE namespace = ?
            AND tenant_id = ?
            AND mint_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.session.tenantId, input.session.mintId)
      .first<D1Row>();
    const quota = await this.database
      .prepare(
        `SELECT *
           FROM authorization_wallet_session_quotas
          WHERE namespace = ?
            AND tenant_id = ?
            AND quota_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.quota.tenantId, input.quota.quotaId)
      .first<D1Row>();
    if (!reusableWalletSessionReadbackMatches(session, quota, input)) {
      throw new Error('reusable Wallet Session issuance replay does not match');
    }
  }

  async readGrantClaimSource(input: {
    readonly tenantId: CapabilityGrantClaimSource['tenantId'];
    readonly grantId: CapabilityGrantClaimSource['grantId'];
  }): Promise<CapabilityGrantClaimSource | null> {
    const row = await this.database
      .prepare(
        `SELECT grant.*, evidence.session_id AS authorization_session_id
           FROM capability_grants AS grant
           JOIN verified_grant_evidence_sets AS evidence
             ON evidence.namespace = grant.namespace
            AND evidence.tenant_id = grant.tenant_id
            AND evidence.evidence_set_id = grant.evidence_set_id
          WHERE grant.namespace = ?
            AND grant.tenant_id = ?
            AND grant.grant_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.grantId)
      .first<D1Row>();
    return row ? parseCapabilityGrantClaimSourceRow(row) : null;
  }

  async claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult> {
    const existing = await this.readOperationUse({
      tenantId: claim.tenantId,
      operationFingerprintDigest: claim.operationFingerprintDigest,
    });
    if (existing) return replayResult(existing, claim);

    if (isReusableWalletSessionClaim(claim)) {
      const result = await this.claimReusableWalletSessionOperation(claim);
      return result.kind === 'material_mismatch' ? { kind: 'grant_mismatch' } : result;
    }

    const result = await this.claimGrantOperation(claim);
    return result.kind === 'material_mismatch' ? { kind: 'grant_mismatch' } : result;
  }

  async claimEcdsaOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<import('../../authorization/service').EcdsaAtomicClaimResult> {
    if (
      input.material.runtimePolicyScope.orgId !== input.claim.tenantId ||
      input.claim.operation.operation.capabilityKind !== CAPABILITY_KINDS.evmEcdsaMpcSigning ||
      input.material.materialActivation.capability !== input.claim.operation.capabilityId
    ) {
      return { kind: 'material_mismatch' };
    }
    if (!(await this.readEcdsaMaterialMatch(input.material))) {
      return { kind: 'material_mismatch' };
    }
    const existing = await this.readEcdsaOperationUse({
      tenantId: input.claim.tenantId,
      operationFingerprintDigest: input.claim.operationFingerprintDigest,
      materialActivationId: input.material.materialActivation.activation_id,
    });
    if (existing.kind === 'material_mismatch') return { kind: 'material_mismatch' };
    if (existing.kind === 'matching') return replayResult(existing.use, input.claim);
    if (isReusableWalletSessionClaim(input.claim)) {
      return await this.claimReusableWalletSessionOperation(input.claim, input.material);
    }
    return await this.claimGrantOperation(input.claim, input.material);
  }

  async claimEcdsaReusableWalletSessionOperation(input: {
    readonly evidenceSet: VerifiedGrantEvidenceSet;
    readonly grant: ActiveCapabilityGrant;
    readonly claim: CapabilityOperationClaim;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<import('../../authorization/service').EcdsaReusableWalletSessionClaimOutcome> {
    if (
      input.material.runtimePolicyScope.orgId !== input.evidenceSet.tenantId ||
      input.material.runtimePolicyScope.orgId !== input.grant.tenantId ||
      input.material.runtimePolicyScope.orgId !== input.claim.tenantId ||
      input.evidenceSet.tenantId !== input.grant.tenantId ||
      input.evidenceSet.tenantId !== input.claim.tenantId ||
      input.grant.operation.capabilityKind !== CAPABILITY_KINDS.evmEcdsaMpcSigning ||
      input.claim.operation.operation.capabilityKind !== CAPABILITY_KINDS.evmEcdsaMpcSigning ||
      input.material.materialActivation.capability !== input.grant.capabilityId ||
      input.material.materialActivation.capability !== input.claim.operation.capabilityId
    ) {
      return { claim: null, result: { kind: 'material_mismatch' } };
    }
    if (!(await this.readEcdsaMaterialMatch(input.material))) {
      return { claim: null, result: { kind: 'material_mismatch' } };
    }
    const existing = await this.readEcdsaOperationUse({
      tenantId: input.claim.tenantId,
      operationFingerprintDigest: input.claim.operationFingerprintDigest,
      materialActivationId: input.material.materialActivation.activation_id,
    });
    if (existing.kind === 'material_mismatch') {
      return { claim: null, result: { kind: 'material_mismatch' } };
    }
    if (existing.kind === 'matching') {
      return { claim: null, result: replayResult(existing.use, input.claim) };
    }
    if (!isReusableWalletSessionClaim(input.claim)) {
      return { claim: input.claim, result: { kind: 'grant_mismatch' } };
    }
    const authority = grantAuthorityColumns(input.grant);
    const signerBindings = ecdsaSignerMatchBindings(this.namespace, input.material);
    const signerCheck = this.database
      .prepare(`SELECT 1 AS matched WHERE ${ECDSA_SIGNER_MATCH}`)
      .bind(...signerBindings);
    const evidenceStatement = this.database
      .prepare(
        `INSERT INTO verified_grant_evidence_sets (
          namespace, tenant_id, evidence_set_id, principal_id, session_id, device_id,
          evidence_set_digest, evidence_json, capability_kind, operation_kind,
          lane_digest, intent_digest, display_digest, assurance, expires_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          FROM authorization_sessions AS session
         WHERE session.namespace = ? AND session.tenant_id = ?
           AND session.session_id = ? AND session.principal_id = ?
           AND session.device_id = ? AND session.lifecycle_kind = 'active'
           AND session.expires_at_ms >= ? AND ${ECDSA_SIGNER_MATCH}`,
      )
      .bind(
        this.namespace,
        input.evidenceSet.tenantId,
        input.evidenceSet.evidenceSetId,
        input.evidenceSet.principalId,
        input.evidenceSet.sessionId,
        input.evidenceSet.deviceId,
        input.evidenceSet.evidenceSetDigest,
        JSON.stringify(input.evidenceSet.evidence),
        input.evidenceSet.operation.capabilityKind,
        input.evidenceSet.operation.operationKind,
        input.evidenceSet.laneDigest,
        input.evidenceSet.intentDigest,
        input.evidenceSet.displayDigest,
        input.evidenceSet.assurance,
        requirePositiveInteger(input.evidenceSet.expiresAtMs, 'evidenceSet.expiresAtMs'),
        this.namespace,
        input.evidenceSet.tenantId,
        input.evidenceSet.sessionId,
        input.evidenceSet.principalId,
        input.evidenceSet.deviceId,
        input.evidenceSet.expiresAtMs,
        ...signerBindings,
      );
    const grantStatement = this.database
      .prepare(
        `INSERT INTO capability_grants (
          namespace, tenant_id, grant_id, principal_id, binding_id, evidence_set_id,
          evidence_set_digest, capability_id, operation_id, capability_kind,
          operation_kind, lane_digest, intent_digest, display_digest, authority_kind,
          wallet_session_id, quota_id, remaining_uses, lifecycle_kind,
          created_at_ms, expires_at_ms, consumed_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL
          FROM verified_grant_evidence_sets AS evidence
         WHERE evidence.namespace = ? AND evidence.tenant_id = ?
           AND evidence.evidence_set_id = ? AND evidence.principal_id = ?
           AND evidence.evidence_set_digest = ? AND evidence.capability_kind = ?
           AND evidence.operation_kind = ? AND evidence.lane_digest = ?
           AND evidence.intent_digest = ? AND evidence.display_digest = ?
           AND evidence.expires_at_ms >= ?
           AND (? = 'operation_step_up' OR EXISTS (
             SELECT 1 FROM reusable_wallet_sessions AS wallet_session
              WHERE wallet_session.namespace = ? AND wallet_session.tenant_id = ?
                AND wallet_session.wallet_session_id = ?
                AND wallet_session.wallet_id = ?
                AND wallet_session.principal_id = ? AND wallet_session.quota_id = ?
                AND wallet_session.lifecycle_kind = 'active'
                AND wallet_session.expires_at_ms >= ?
           )) AND ${ECDSA_SIGNER_MATCH}`,
      )
      .bind(
        this.namespace,
        input.grant.tenantId,
        input.grant.grantId,
        input.grant.principalId,
        input.grant.bindingId,
        input.grant.evidenceSetId,
        input.grant.evidenceSetDigest,
        input.grant.capabilityId,
        input.grant.operationId,
        input.grant.operation.capabilityKind,
        input.grant.operation.operationKind,
        input.grant.laneDigest,
        input.grant.intentDigest,
        input.grant.displayDigest,
        authority.kind,
        authority.walletSessionId,
        authority.quotaId,
        requirePositiveInteger(input.grant.remainingUses, 'grant.remainingUses'),
        requirePositiveInteger(input.grant.createdAtMs, 'grant.createdAtMs'),
        requirePositiveInteger(input.grant.expiresAtMs, 'grant.expiresAtMs'),
        this.namespace,
        input.grant.tenantId,
        input.grant.evidenceSetId,
        input.grant.principalId,
        input.grant.evidenceSetDigest,
        input.grant.operation.capabilityKind,
        input.grant.operation.operationKind,
        input.grant.laneDigest,
        input.grant.intentDigest,
        input.grant.displayDigest,
        input.grant.expiresAtMs,
        authority.kind,
        this.namespace,
        input.grant.tenantId,
        authority.walletSessionId,
        input.material.walletId,
        input.grant.principalId,
        authority.quotaId,
        input.grant.expiresAtMs,
        ...signerBindings,
      );
    const claimStatement = this.database
      .prepare(
        `INSERT INTO reusable_wallet_session_operation_uses (
          namespace, tenant_id, use_id, audit_event_id, grant_id, principal_id,
          capability_id, capability_kind, operation_kind, operation_id,
          operation_fingerprint_digest, evidence_set_digest, lane_digest,
          intent_digest, display_digest, wallet_session_id, quota_id, quota_kind,
          material_activation_id, lifecycle_kind, result_kind, result_digest, result_storage_ref,
          claimed_at_ms, completed_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          'claimed', 'pending', NULL, NULL, ?, NULL
         WHERE ${ECDSA_SIGNER_MATCH}
           AND EXISTS (
             SELECT 1 FROM capability_grants AS grant
              WHERE grant.namespace = ? AND grant.tenant_id = ?
                AND grant.grant_id = ?
                AND grant.principal_id = ?
                AND grant.evidence_set_digest = ?
                AND grant.capability_id = ? AND grant.operation_id = ?
                AND grant.capability_kind = ? AND grant.operation_kind = ?
                AND grant.lane_digest = ? AND grant.intent_digest = ?
                AND grant.display_digest = ?
                AND grant.authority_kind = ?
                AND COALESCE(grant.wallet_session_id, '') = COALESCE(?, '')
                AND COALESCE(grant.quota_id, '') = COALESCE(?, '')
                AND grant.lifecycle_kind = 'active'
                AND grant.remaining_uses > 0
                AND grant.expires_at_ms > ?
           )
           AND EXISTS (
             SELECT 1 FROM verified_grant_evidence_sets AS evidence
              WHERE evidence.namespace = ? AND evidence.tenant_id = ?
                AND evidence.evidence_set_digest = ?
                AND evidence.capability_kind = ? AND evidence.operation_kind = ?
                AND evidence.lane_digest = ? AND evidence.intent_digest = ?
                AND evidence.display_digest = ?
                AND evidence.expires_at_ms >= ?
           )`,
      )
      .bind(
        this.namespace,
        input.claim.tenantId,
        input.claim.useId,
        input.claim.auditEventId,
        input.claim.grantId,
        input.claim.operation.principalId,
        input.claim.operation.capabilityId,
        input.claim.operation.operation.capabilityKind,
        input.claim.operation.operation.operationKind,
        input.claim.operation.operationId,
        input.claim.operationFingerprintDigest,
        input.claim.evidenceSetDigest,
        input.claim.operation.digests.laneDigest,
        input.claim.operation.digests.intentDigest,
        input.claim.operation.digests.displayDigest,
        input.claim.authorization.walletSessionId,
        input.claim.authorization.quotaId,
        input.claim.quota.kind,
        input.material.materialActivation.activation_id,
        requirePositiveInteger(input.claim.claimedAtMs, 'claim.claimedAtMs'),
        ...signerBindings,
        this.namespace,
        input.claim.tenantId,
        input.claim.grantId,
        input.claim.operation.principalId,
        input.claim.evidenceSetDigest,
        input.claim.operation.capabilityId,
        input.claim.operation.operationId,
        input.claim.operation.operation.capabilityKind,
        input.claim.operation.operation.operationKind,
        input.claim.operation.digests.laneDigest,
        input.claim.operation.digests.intentDigest,
        input.claim.operation.digests.displayDigest,
        authority.kind,
        authority.walletSessionId ?? null,
        authority.quotaId ?? null,
        requirePositiveInteger(input.claim.claimedAtMs, 'claim.claimedAtMs'),
        this.namespace,
        input.claim.tenantId,
        input.claim.evidenceSetDigest,
        input.claim.operation.operation.capabilityKind,
        input.claim.operation.operation.operationKind,
        input.claim.operation.digests.laneDigest,
        input.claim.operation.digests.intentDigest,
        input.claim.operation.digests.displayDigest,
        requirePositiveInteger(input.claim.claimedAtMs, 'claim.claimedAtMs'),
      );
    const [atomicGuard, clearAtomicGuard] = this.ecdsaAtomicGuard({
      tenantId: input.claim.tenantId,
      checkId: `reusable-claim:${input.claim.useId}`,
      exactMatchSql: `${ECDSA_SIGNER_MATCH}
        AND EXISTS (
          SELECT 1 FROM verified_grant_evidence_sets AS evidence
           WHERE evidence.namespace = ? AND evidence.tenant_id = ?
             AND evidence.evidence_set_id = ? AND evidence.evidence_set_digest = ?
        )
        AND EXISTS (
          SELECT 1 FROM capability_grants AS grant
           WHERE grant.namespace = ? AND grant.tenant_id = ?
             AND grant.grant_id = ? AND grant.evidence_set_digest = ?
             AND grant.capability_id = ? AND grant.operation_id = ?
        )
        AND EXISTS (
          SELECT 1 FROM reusable_wallet_session_operation_uses AS use
           WHERE use.namespace = ? AND use.tenant_id = ?
             AND use.use_id = ? AND use.operation_fingerprint_digest = ?
             AND use.material_activation_id = ?
        )`,
      bindings: [
        ...signerBindings,
        this.namespace,
        input.evidenceSet.tenantId,
        input.evidenceSet.evidenceSetId,
        input.evidenceSet.evidenceSetDigest,
        this.namespace,
        input.grant.tenantId,
        input.grant.grantId,
        input.grant.evidenceSetDigest,
        input.grant.capabilityId,
        input.grant.operationId,
        this.namespace,
        input.claim.tenantId,
        input.claim.useId,
        input.claim.operationFingerprintDigest,
        input.material.materialActivation.activation_id,
      ],
    });
    let results: readonly AtomicD1Result[];
    try {
      results = await this.database.batch<AtomicD1Result>([
        signerCheck,
        evidenceStatement,
        grantStatement,
        claimStatement,
        atomicGuard,
        clearAtomicGuard,
      ]);
    } catch (error: unknown) {
      if (
        (await this.readEcdsaMaterialMatch(input.material)) &&
        (await this.readExactEcdsaEvidence(input.evidenceSet)) &&
        (await this.readExactEcdsaGrant(input.grant))
      ) {
        const result = await this.claimReusableWalletSessionOperationEcdsa(
          input.claim,
          input.material,
        );
        return {
          claim: result.kind === 'claimed' ? input.claim : null,
          result,
        };
      }
      const raced = await this.readEcdsaOperationUse({
        tenantId: input.claim.tenantId,
        operationFingerprintDigest: input.claim.operationFingerprintDigest,
        materialActivationId: input.material.materialActivation.activation_id,
      });
      if (raced.kind === 'material_mismatch') {
        return { claim: null, result: { kind: 'material_mismatch' } };
      }
      if (raced.kind === 'matching') {
        return { claim: null, result: replayResult(raced.use, input.claim) };
      }
      if (!isD1ConstraintFailure(error)) throw error;
      if (isReusableWalletSessionClaim(input.claim)) {
        return {
          claim: null,
          result: await this.classifyRejectedReusableWalletSessionClaim(input.claim),
        };
      }
      return { claim: null, result: { kind: 'grant_mismatch' } };
    }
    if (results.length !== 6) throw new Error('ECDSA operation transaction returned incomplete results');
    if ((results[0]?.results?.length || 0) === 0) {
      return { claim: null, result: { kind: 'material_mismatch' } };
    }
    const inserted = d1ChangedRows(results[3] || { success: false });
    if (inserted !== 1) {
      return { claim: null, result: await this.classifyRejectedReusableWalletSessionClaim(input.claim) };
    }
    const committed = await this.readEcdsaOperationUse({
      tenantId: input.claim.tenantId,
      operationFingerprintDigest: input.claim.operationFingerprintDigest,
      materialActivationId: input.material.materialActivation.activation_id,
    });
    if (committed.kind !== 'matching' || committed.use.kind !== 'claimed') {
      throw new Error('committed ECDSA reusable operation claim could not be read back');
    }
    return { claim: input.claim, result: { kind: 'claimed', use: committed.use } };
  }

  private async claimGrantOperation(
    claim: CapabilityOperationClaim,
    material?: EcdsaMaterialActivationScope,
  ): Promise<import('../../authorization/service').EcdsaAtomicClaimResult> {
    if (material) return await this.claimGrantOperationEcdsa(claim, material);
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
      const raced = await this.readOperationUse({
        tenantId: claim.tenantId,
        operationFingerprintDigest: claim.operationFingerprintDigest,
      });
      if (raced) return replayResult(raced, claim);
      return await this.classifyRejectedClaim(claim);
    }

    const use = await this.readOperationUse({
      tenantId: claim.tenantId,
      operationFingerprintDigest: claim.operationFingerprintDigest,
    });
    if (!use || use.kind !== 'claimed') {
      throw new Error('committed capability operation claim could not be read back');
    }
    return { kind: 'claimed', use };
  }

  private async claimGrantOperationEcdsa(
    claim: CapabilityOperationClaim,
    material: EcdsaMaterialActivationScope,
  ): Promise<import('../../authorization/service').EcdsaAtomicClaimResult> {
    const authorization = claimAuthorizationColumns(claim);
    const signerBindings = ecdsaSignerMatchBindings(this.namespace, material);
    const signerCheck = this.database
      .prepare(`SELECT 1 AS matched WHERE ${ECDSA_SIGNER_MATCH}`)
      .bind(...signerBindings);
    const claimStatement = this.database
      .prepare(
        `INSERT INTO capability_grant_uses (
          namespace, tenant_id, use_id, audit_event_id, grant_id, principal_id,
          capability_id, capability_kind, operation_kind, operation_id,
          operation_fingerprint_digest, evidence_set_digest, lane_digest,
          intent_digest, display_digest, authorization_kind, wallet_session_id,
          quota_id, quota_kind, material_activation_id, lifecycle_kind, result_kind, result_digest,
          result_storage_ref, claimed_at_ms, completed_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          'claimed', 'pending', NULL, NULL, ?, NULL
         WHERE ${ECDSA_SIGNER_MATCH}
           AND EXISTS (
             SELECT 1 FROM capability_grants AS grant
              WHERE grant.namespace = ? AND grant.tenant_id = ?
                AND grant.grant_id = ? AND grant.principal_id = ?
                AND grant.evidence_set_digest = ?
                AND grant.capability_id = ? AND grant.operation_id = ?
                AND grant.capability_kind = ? AND grant.operation_kind = ?
                AND grant.lane_digest = ? AND grant.intent_digest = ?
                AND grant.display_digest = ? AND grant.authority_kind = ?
                AND COALESCE(grant.wallet_session_id, '') = COALESCE(?, '')
                AND COALESCE(grant.quota_id, '') = COALESCE(?, '')
                AND grant.lifecycle_kind = 'active'
                AND grant.remaining_uses > 0 AND grant.expires_at_ms > ?
           )
           AND EXISTS (
             SELECT 1 FROM verified_grant_evidence_sets AS evidence
              WHERE evidence.namespace = ? AND evidence.tenant_id = ?
                AND evidence.evidence_set_digest = ?
                AND evidence.capability_kind = ? AND evidence.operation_kind = ?
                AND evidence.lane_digest = ? AND evidence.intent_digest = ?
                AND evidence.display_digest = ?
                AND evidence.expires_at_ms >= ?
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
        material.materialActivation.activation_id,
        requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
        ...signerBindings,
        this.namespace,
        claim.tenantId,
        claim.grantId,
        claim.operation.principalId,
        claim.evidenceSetDigest,
        claim.operation.capabilityId,
        claim.operation.operationId,
        claim.operation.operation.capabilityKind,
        claim.operation.operation.operationKind,
        claim.operation.digests.laneDigest,
        claim.operation.digests.intentDigest,
        claim.operation.digests.displayDigest,
        claim.authorization.kind,
        claim.authorization.walletSessionId,
        claim.authorization.quotaId,
        requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
        this.namespace,
        claim.tenantId,
        claim.evidenceSetDigest,
        claim.operation.operation.capabilityKind,
        claim.operation.operation.operationKind,
        claim.operation.digests.laneDigest,
        claim.operation.digests.intentDigest,
        claim.operation.digests.displayDigest,
        requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
      );
    try {
      const results = await this.database.batch<AtomicD1Result>([signerCheck, claimStatement]);
      if (results.length !== 2) {
        throw new Error('ECDSA operation transaction returned incomplete results');
      }
      if ((results[0]?.results?.length || 0) === 0) {
        return { kind: 'material_mismatch' };
      }
      if (d1ChangedRows(results[1] || { success: false }) !== 1) {
        return await this.classifyRejectedClaim(claim);
      }
    } catch (error: unknown) {
      const raced = await this.readEcdsaOperationUse({
        tenantId: claim.tenantId,
        operationFingerprintDigest: claim.operationFingerprintDigest,
        materialActivationId: material.materialActivation.activation_id,
      });
      if (raced.kind === 'material_mismatch') return { kind: 'material_mismatch' };
      if (raced.kind === 'matching') return replayResult(raced.use, claim);
      if (!isD1ConstraintFailure(error)) throw error;
      return await this.classifyRejectedClaim(claim);
    }
    const committed = await this.readEcdsaOperationUse({
      tenantId: claim.tenantId,
      operationFingerprintDigest: claim.operationFingerprintDigest,
      materialActivationId: material.materialActivation.activation_id,
    });
    if (committed.kind !== 'matching' || committed.use.kind !== 'claimed') {
      throw new Error('committed ECDSA capability operation claim could not be read back');
    }
    return { kind: 'claimed', use: committed.use };
  }

  private async claimReusableWalletSessionOperation(
    claim: Extract<
      CapabilityOperationClaim,
      { readonly authorization: { readonly kind: 'reusable_wallet_session' } }
    >,
    material?: EcdsaMaterialActivationScope,
  ): Promise<import('../../authorization/service').EcdsaAtomicClaimResult> {
    if (material) return await this.claimReusableWalletSessionOperationEcdsa(claim, material);
    try {
      const result = await this.database
        .prepare(
          `INSERT INTO reusable_wallet_session_operation_uses (
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
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
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
          claim.authorization.walletSessionId,
          claim.authorization.quotaId,
          claim.quota.kind,
          requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
        )
        .run();
      requireOneChangedRow(result, 'reusable Wallet Session operation claim');
    } catch {
      const raced = await this.readOperationUse({
        tenantId: claim.tenantId,
        operationFingerprintDigest: claim.operationFingerprintDigest,
      });
      if (raced) return replayResult(raced, claim);
      return await this.classifyRejectedReusableWalletSessionClaim(claim);
    }

    const use = await this.readReusableWalletSessionOperationUse({
      tenantId: claim.tenantId,
      operationFingerprintDigest: claim.operationFingerprintDigest,
    });
    if (!use || use.kind !== 'claimed') {
      throw new Error('committed reusable Wallet Session operation claim could not be read back');
    }
    return { kind: 'claimed', use };
  }

  private async claimReusableWalletSessionOperationEcdsa(
    claim: Extract<
      CapabilityOperationClaim,
      { readonly authorization: { readonly kind: 'reusable_wallet_session' } }
    >,
    material: EcdsaMaterialActivationScope,
  ): Promise<import('../../authorization/service').EcdsaAtomicClaimResult> {
    const signerBindings = ecdsaSignerMatchBindings(this.namespace, material);
    const signerCheck = this.database
      .prepare(`SELECT 1 AS matched WHERE ${ECDSA_SIGNER_MATCH}`)
      .bind(...signerBindings);
    const claimStatement = this.database
      .prepare(
        `INSERT INTO reusable_wallet_session_operation_uses (
          namespace, tenant_id, use_id, audit_event_id, grant_id, principal_id,
          capability_id, capability_kind, operation_kind, operation_id,
          operation_fingerprint_digest, evidence_set_digest, lane_digest,
          intent_digest, display_digest, wallet_session_id, quota_id, quota_kind,
          material_activation_id, lifecycle_kind, result_kind, result_digest, result_storage_ref,
          claimed_at_ms, completed_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          'claimed', 'pending', NULL, NULL, ?, NULL
         WHERE ${ECDSA_SIGNER_MATCH}
           AND EXISTS (
             SELECT 1 FROM capability_grants AS grant
              WHERE grant.namespace = ? AND grant.tenant_id = ?
                AND grant.grant_id = ? AND grant.principal_id = ?
                AND grant.evidence_set_digest = ?
                AND grant.capability_id = ? AND grant.operation_id = ?
                AND grant.capability_kind = ? AND grant.operation_kind = ?
                AND grant.lane_digest = ? AND grant.intent_digest = ?
                AND grant.display_digest = ? AND grant.authority_kind = ?
                AND COALESCE(grant.wallet_session_id, '') = COALESCE(?, '')
                AND COALESCE(grant.quota_id, '') = COALESCE(?, '')
                AND grant.lifecycle_kind = 'active'
                AND grant.remaining_uses > 0 AND grant.expires_at_ms > ?
           )
           AND EXISTS (
             SELECT 1 FROM reusable_wallet_sessions AS wallet_session
              WHERE wallet_session.namespace = ? AND wallet_session.tenant_id = ?
                AND wallet_session.wallet_session_id = ? AND wallet_session.wallet_id = ?
                AND wallet_session.principal_id = ? AND wallet_session.quota_id = ?
                AND wallet_session.lifecycle_kind = 'active'
                AND wallet_session.expires_at_ms > ?
           )
           AND EXISTS (
             SELECT 1 FROM verified_grant_evidence_sets AS evidence
              WHERE evidence.namespace = ? AND evidence.tenant_id = ?
                AND evidence.evidence_set_digest = ?
                AND evidence.capability_kind = ? AND evidence.operation_kind = ?
                AND evidence.lane_digest = ? AND evidence.intent_digest = ?
                AND evidence.display_digest = ?
                AND evidence.expires_at_ms >= ?
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
        claim.authorization.walletSessionId,
        claim.authorization.quotaId,
        claim.quota.kind,
        material.materialActivation.activation_id,
        requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
        ...signerBindings,
        this.namespace,
        claim.tenantId,
        claim.grantId,
        claim.operation.principalId,
        claim.evidenceSetDigest,
        claim.operation.capabilityId,
        claim.operation.operationId,
        claim.operation.operation.capabilityKind,
        claim.operation.operation.operationKind,
        claim.operation.digests.laneDigest,
        claim.operation.digests.intentDigest,
        claim.operation.digests.displayDigest,
        claim.authorization.kind,
        claim.authorization.walletSessionId,
        claim.authorization.quotaId,
        requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
        this.namespace,
        claim.tenantId,
        claim.authorization.walletSessionId,
        material.walletId,
        claim.operation.principalId,
        claim.authorization.quotaId,
        requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
        this.namespace,
        claim.tenantId,
        claim.evidenceSetDigest,
        claim.operation.operation.capabilityKind,
        claim.operation.operation.operationKind,
        claim.operation.digests.laneDigest,
        claim.operation.digests.intentDigest,
        claim.operation.digests.displayDigest,
        requirePositiveInteger(claim.claimedAtMs, 'claim.claimedAtMs'),
      );
    try {
      const results = await this.database.batch<AtomicD1Result>([signerCheck, claimStatement]);
      if (results.length !== 2) {
        throw new Error('ECDSA reusable operation transaction returned incomplete results');
      }
      if ((results[0]?.results?.length || 0) === 0) {
        return { kind: 'material_mismatch' };
      }
      if (d1ChangedRows(results[1] || { success: false }) !== 1) {
        return await this.classifyRejectedReusableWalletSessionClaim(claim);
      }
    } catch (error: unknown) {
      const raced = await this.readEcdsaOperationUse({
        tenantId: claim.tenantId,
        operationFingerprintDigest: claim.operationFingerprintDigest,
        materialActivationId: material.materialActivation.activation_id,
      });
      if (raced.kind === 'material_mismatch') return { kind: 'material_mismatch' };
      if (raced.kind === 'matching') return replayResult(raced.use, claim);
      if (!isD1ConstraintFailure(error)) throw error;
      return await this.classifyRejectedReusableWalletSessionClaim(claim);
    }
    const committed = await this.readEcdsaOperationUse({
      tenantId: claim.tenantId,
      operationFingerprintDigest: claim.operationFingerprintDigest,
      materialActivationId: material.materialActivation.activation_id,
    });
    if (committed.kind !== 'matching' || committed.use.kind !== 'claimed') {
      throw new Error('committed ECDSA reusable operation claim could not be read back');
    }
    return { kind: 'claimed', use: committed.use };
  }

  async completeOperation(input: {
    readonly claim: CapabilityOperationClaim | CapabilityOperationCompletionClaimRef;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult> {
    const current = await this.readOperationUse({
      tenantId: input.claim.tenantId,
      operationFingerprintDigest: input.claim.operationFingerprintDigest,
    });
    if (!current) return { kind: 'claim_missing' };
    if (current.useId !== input.claim.useId || current.grantId !== input.claim.grantId) {
      return { kind: 'claim_mismatch' };
    }
    if (current.kind === 'completed') return { kind: 'already_completed', use: current };

    const reusableUse = await this.readReusableWalletSessionOperationUse({
      tenantId: input.claim.tenantId,
      operationFingerprintDigest: input.claim.operationFingerprintDigest,
    });
    const useTable = reusableUse
      ? 'reusable_wallet_session_operation_uses'
      : 'capability_grant_uses';
    const update = await this.database
      .prepare(
        `UPDATE ${useTable}
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
      const raced = await this.readOperationUse({
        tenantId: input.claim.tenantId,
        operationFingerprintDigest: input.claim.operationFingerprintDigest,
      });
      if (raced?.kind === 'completed') return { kind: 'already_completed', use: raced };
      return raced ? { kind: 'claim_mismatch' } : { kind: 'claim_missing' };
    }
    const completed = await this.readOperationUse({
      tenantId: input.claim.tenantId,
      operationFingerprintDigest: input.claim.operationFingerprintDigest,
    });
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
    if (row) return parseGrantAuditEventRow(row);
    const reusableRow = await this.database
      .prepare(
        `SELECT *
           FROM reusable_wallet_session_operation_audit_events
          WHERE namespace = ?
            AND tenant_id = ?
            AND event_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.eventId)
      .first<D1Row>();
    return reusableRow ? parseReusableWalletSessionAuditEventRow(reusableRow) : null;
  }

  async readOperationUse(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<CapabilityGrantUse | null> {
    const row = await this.database
      .prepare(
        `SELECT *
           FROM capability_grant_uses
          WHERE namespace = ?
            AND tenant_id = ?
            AND operation_fingerprint_digest = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.operationFingerprintDigest)
      .first<D1Row>();
    if (row) return parseCapabilityGrantUseRow(row);
    return await this.readReusableWalletSessionOperationUse(input);
  }

  private async readEcdsaOperationUse(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
    readonly materialActivationId: string;
  }): Promise<
    | { readonly kind: 'missing' }
    | { readonly kind: 'material_mismatch' }
    | { readonly kind: 'matching'; readonly use: CapabilityGrantUse }
  > {
    const grantUse = await this.database
      .prepare(
        `SELECT *
           FROM capability_grant_uses
          WHERE namespace = ?
            AND tenant_id = ?
            AND operation_fingerprint_digest = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.operationFingerprintDigest)
      .first<D1Row>();
    if (grantUse) {
      return grantUse.material_activation_id === input.materialActivationId
        ? { kind: 'matching', use: parseCapabilityGrantUseRow(grantUse) }
        : { kind: 'material_mismatch' };
    }
    const reusableUse = await this.database
      .prepare(
        `SELECT *
           FROM reusable_wallet_session_operation_uses
          WHERE namespace = ?
            AND tenant_id = ?
            AND operation_fingerprint_digest = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.operationFingerprintDigest)
      .first<D1Row>();
    if (!reusableUse) return { kind: 'missing' };
    return reusableUse.material_activation_id === input.materialActivationId
      ? { kind: 'matching', use: parseCapabilityGrantUseRow(reusableUse) }
      : { kind: 'material_mismatch' };
  }

  private async readReusableWalletSessionOperationUse(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<CapabilityGrantUse | null> {
    const row = await this.database
      .prepare(
        `SELECT *
           FROM reusable_wallet_session_operation_uses
          WHERE namespace = ?
            AND tenant_id = ?
            AND operation_fingerprint_digest = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.operationFingerprintDigest)
      .first<D1Row>();
    return row ? parseCapabilityGrantUseRow(row) : null;
  }

  private async readHostedWalletExchange(
    codeHash: RedeemHostedWalletSeamsSessionExchangeInput['codeHash'],
  ): Promise<HostedWalletExchangeRow | null> {
    return await this.database
      .prepare(
        `SELECT *
           FROM hosted_wallet_session_exchange_codes
          WHERE namespace = ?
            AND code_hash = ?
          LIMIT 1`,
      )
      .bind(this.namespace, codeHash)
      .first<HostedWalletExchangeRow>();
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

  private async classifyRejectedReusableWalletSessionClaim(
    claim: Extract<
      CapabilityOperationClaim,
      { readonly authorization: { readonly kind: 'reusable_wallet_session' } }
    >,
  ): Promise<ClaimCapabilityOperationResult> {
    const session = await this.database
      .prepare(
        `SELECT *
           FROM reusable_wallet_sessions
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, claim.tenantId, claim.authorization.walletSessionId)
      .first<D1Row>();
    if (!session || !reusableWalletSessionMatchesClaim(session, claim)) {
      return { kind: 'wallet_session_mismatch' };
    }
    if (integerColumn(session.expires_at_ms, 'session.expires_at_ms') <= claim.claimedAtMs) {
      return { kind: 'wallet_session_expired' };
    }
    if (session.lifecycle_kind !== 'active') return { kind: 'wallet_session_mismatch' };

    const quota = await this.database
      .prepare(
        `SELECT *
           FROM authorization_wallet_session_quotas
          WHERE namespace = ?
            AND tenant_id = ?
            AND quota_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, claim.tenantId, claim.authorization.quotaId)
      .first<QuotaClassificationRow>();
    if (!quota || !quotaMatchesClaim(quota, claim)) return { kind: 'wallet_session_mismatch' };
    if (integerColumn(quota.expires_at_ms, 'quota.expires_at_ms') <= claim.claimedAtMs) {
      return { kind: 'wallet_session_expired' };
    }
    if (
      claim.quota.kind === 'consume_reusable_wallet_session' &&
      (quota.lifecycle_kind !== 'active' ||
        integerColumn(quota.remaining_uses, 'quota.remaining_uses') <= 0)
    ) {
      return { kind: 'wallet_session_quota_exhausted' };
    }
    throw new Error('authorization claim failed despite eligible reusable Wallet Session');
  }
}

function authSourcePayload(source: ActiveAuthorizationSession['authSource']) {
  switch (source.kind) {
    case 'oidc_provider':
      return { providerId: source.providerId, providerSubject: source.providerSubject };
    case 'passkey':
      return { credentialIdB64u: source.credentialIdB64u };
  }
}

function audiencePayload(audience: ActiveAuthorizationSession['audience']) {
  switch (audience.kind) {
    case 'first_party_web':
      return { origin: audience.origin };
    case 'hosted_wallet_iframe':
      return { appOrigin: audience.appOrigin, walletOrigin: audience.walletOrigin };
  }
}

function parseAuthorizationSessionRow(row: D1Row): ActiveAuthorizationSession {
  const authSourcePayload = parseJsonRecord(row.auth_source_json, 'session.authSource');
  const audiencePayload = parseJsonRecord(row.audience_json, 'session.audience');
  const providerId = parseAuthorizationProviderId(authSourcePayload.providerId);
  const authSource =
    row.auth_source_kind === 'oidc_provider' && providerId
      ? {
          kind: 'oidc_provider' as const,
          providerId,
          providerSubject: requireDomainId(
            authSourcePayload.providerSubject,
            parseProviderSubject,
            'session.authSource.providerSubject',
          ),
        }
      : row.auth_source_kind === 'passkey'
        ? {
            kind: 'passkey' as const,
            credentialIdB64u: requireDomainId(
              authSourcePayload.credentialIdB64u,
              parseWebAuthnCredentialIdB64u,
              'session.authSource.credentialIdB64u',
            ),
          }
        : (() => {
            throw new Error('session auth source kind is invalid');
          })();
  const audience =
    row.audience_kind === 'first_party_web'
      ? {
          kind: 'first_party_web' as const,
          origin: parseSessionOrigin(audiencePayload.origin),
        }
      : row.audience_kind === 'hosted_wallet_iframe'
        ? {
            kind: 'hosted_wallet_iframe' as const,
            appOrigin: parseSessionOrigin(audiencePayload.appOrigin),
            walletOrigin: parseSessionOrigin(audiencePayload.walletOrigin),
          }
        : (() => {
            throw new Error('session audience kind is invalid');
          })();
  return buildActiveAuthorizationSession({
    tenantId: requireParsed(row.tenant_id, parseTenantId, 'session.tenantId'),
    principalId: requireParsed(row.principal_id, parsePrincipalId, 'session.principalId'),
    sessionId: requireParsed(row.session_id, parseSeamsSessionId, 'session.sessionId'),
    authSource,
    deviceId: requireParsed(row.device_id, parseDeviceId, 'session.deviceId'),
    audience,
    appSessionVersion: requireDomainId(
      row.app_session_version,
      parseAppSessionVersion,
      'session.appSessionVersion',
    ),
    assurance:
      row.assurance === 'session' || row.assurance === 'step_up'
        ? row.assurance
        : (() => {
            throw new Error('session assurance is invalid');
          })(),
    createdAtMs: integerColumn(row.created_at_ms, 'session.createdAtMs'),
    lifecycle: {
      kind: 'active',
      expiresAtMs: integerColumn(row.expires_at_ms, 'session.expiresAtMs'),
    },
  });
}

function parseAuthorizationProviderId(value: unknown): 'google_oidc' | 'oidc' | null {
  return value === 'google_oidc' || value === 'oidc' ? value : null;
}

function parseCapabilityGrantClaimSourceRow(row: D1Row): CapabilityGrantClaimSource {
  const tenantId = requireParsed(row.tenant_id, parseTenantId, 'grant.tenantId');
  const principalId = requireParsed(row.principal_id, parsePrincipalId, 'grant.principalId');
  const authorizationSessionId = requireParsed(
    row.authorization_session_id,
    parseSeamsSessionId,
    'grant.authorizationSessionId',
  );
  const grantId = requireParsed(row.grant_id, parseCapabilityGrantId, 'grant.grantId');
  const evidenceSetDigest = parseDigestB64u(row.evidence_set_digest);
  const capabilityId = requireParsed(row.capability_id, parseCapabilityId, 'grant.capabilityId');
  const operationId = requireParsed(
    row.operation_id,
    parseCapabilityOperationId,
    'grant.operationId',
  );
  const operation = requireParsed(
    {
      capabilityKind: row.capability_kind,
      operationKind: row.operation_kind,
    },
    parseCapabilityOperationRef,
    'grant.operation',
  );
  const laneDigest = parseDigestB64u(row.lane_digest);
  const intentDigest = parseDigestB64u(row.intent_digest);
  const displayDigest = parseDigestB64u(row.display_digest);
  switch (row.authority_kind) {
    case 'reusable_wallet_session':
      return {
        tenantId,
        principalId,
        authorizationSessionId,
        grantId,
        evidenceSetDigest,
        capabilityId,
        operationId,
        operation,
        laneDigest,
        intentDigest,
        displayDigest,
        authority: {
          kind: 'reusable_wallet_session',
          walletSessionId: requireParsed(
            row.wallet_session_id,
            parseWalletSessionId,
            'grant.walletSessionId',
          ),
          quotaId: requireParsed(row.quota_id, parseMpcWalletSigningQuotaId, 'grant.quotaId'),
        },
      };
    case 'operation_step_up':
      return {
        tenantId,
        principalId,
        authorizationSessionId,
        grantId,
        evidenceSetDigest,
        capabilityId,
        operationId,
        operation,
        laneDigest,
        intentDigest,
        displayDigest,
        authority: { kind: 'operation_step_up' },
      };
    default:
      throw new Error('grant authority kind is invalid');
  }
}

function classifyHostedWalletExchange(
  row: HostedWalletExchangeRow | null,
  input: RedeemHostedWalletSeamsSessionExchangeInput,
): RedeemHostedWalletSeamsSessionExchangeResult | null {
  if (!row) return { kind: 'invalid_code' };
  if (row.lifecycle_kind === 'consumed') return { kind: 'already_consumed' };
  if (row.lifecycle_kind !== 'issued') return { kind: 'invalid_code' };
  if (integerColumn(row.expires_at_ms, 'exchange.expiresAtMs') <= input.redeemedAtMs) {
    return { kind: 'expired' };
  }
  if (row.nonce_digest !== input.nonceDigest) return { kind: 'nonce_mismatch' };
  if (row.wallet_origin !== input.walletOrigin) return { kind: 'wallet_origin_mismatch' };
  return null;
}

function parseJsonRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'string') throw new Error(`${label} must be JSON`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${label} must be valid JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return parsed as Record<string, unknown>;
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

function isReusableWalletSessionClaim(
  claim: CapabilityOperationClaim,
): claim is Extract<
  CapabilityOperationClaim,
  { readonly authorization: { readonly kind: 'reusable_wallet_session' } }
> {
  return claim.authorization.kind === 'reusable_wallet_session';
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

function reusableWalletSessionMatchesClaim(
  row: D1Row,
  claim: Extract<
    CapabilityOperationClaim,
    { readonly authorization: { readonly kind: 'reusable_wallet_session' } }
  >,
): boolean {
  return (
    row.wallet_session_id === claim.authorization.walletSessionId &&
    row.quota_id === claim.authorization.quotaId &&
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
    operationId: requireParsed(
      row.operation_id,
      parseCapabilityOperationId,
      'use.operationId',
    ),
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
      operationId: base.operationId,
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
    operationId: base.operationId,
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

function parseGrantAuditEventRow(row: D1Row): AuthorizationAuditEvent {
  if (!isAuditResult(row.result_kind)) {
    throw new Error('authorization audit row has an invalid result');
  }
  return {
    kind: 'authorization_audit_event',
    tenantId: requireParsed(row.tenant_id, parseTenantId, 'audit.tenantId'),
    eventId: requireParsed(row.event_id, parseAuthorizationAuditEventId, 'audit.eventId'),
    principalId: requireParsed(row.principal_id, parsePrincipalId, 'audit.principalId'),
    authorization: {
      kind: 'operation_step_up',
      sessionId: requireParsed(row.session_id, parseSeamsSessionId, 'audit.sessionId'),
      deviceId: requireParsed(row.device_id, parseDeviceId, 'audit.deviceId'),
    },
    grantId: requireParsed(row.grant_id, parseCapabilityGrantId, 'audit.grantId'),
    useId: requireParsed(row.use_id, parseCapabilityGrantUseId, 'audit.useId'),
    capabilityId: requireParsed(row.capability_id, parseCapabilityId, 'audit.capabilityId'),
    operationId: requireParsed(row.operation_id, parseCapabilityOperationId, 'audit.operationId'),
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

function parseReusableWalletSessionAuditEventRow(row: D1Row): AuthorizationAuditEvent {
  if (!isAuditResult(row.result_kind)) {
    throw new Error('authorization audit row has an invalid result');
  }
  return {
    kind: 'authorization_audit_event',
    tenantId: requireParsed(row.tenant_id, parseTenantId, 'audit.tenantId'),
    eventId: requireParsed(row.event_id, parseAuthorizationAuditEventId, 'audit.eventId'),
    principalId: requireParsed(row.principal_id, parsePrincipalId, 'audit.principalId'),
    authorization: {
      kind: 'reusable_wallet_session',
      walletSessionId: requireParsed(
        row.wallet_session_id,
        parseWalletSessionId,
        'audit.walletSessionId',
      ),
    },
    grantId: requireParsed(row.grant_id, parseCapabilityGrantId, 'audit.grantId'),
    useId: requireParsed(row.use_id, parseCapabilityGrantUseId, 'audit.useId'),
    capabilityId: requireParsed(row.capability_id, parseCapabilityId, 'audit.capabilityId'),
    operationId: requireParsed(row.operation_id, parseCapabilityOperationId, 'audit.operationId'),
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

function requireDomainId<T>(
  value: unknown,
  parser: (
    raw: unknown,
  ) =>
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
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
    // eslint-disable-next-line no-control-regex
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

function requireExactReusableWalletSessionQuota(input: {
  readonly session: WalletSessionAuthorization;
  readonly quota: ActiveWalletSessionQuota;
}): void {
  if (
    input.session.tenantId !== input.quota.tenantId ||
    input.session.principalId !== input.quota.principalId ||
    input.session.walletSessionId !== input.quota.walletSessionId ||
    input.session.quotaId !== input.quota.quotaId ||
    input.session.expiresAtMs !== input.quota.expiresAtMs
  ) {
    throw new Error('reusable Wallet Session and quota must have one exact identity');
  }
}

function reusableWalletSessionReadbackMatches(
  session: D1Row | null,
  quota: D1Row | null,
  input: {
    readonly session: WalletSessionAuthorization;
    readonly quota: ActiveWalletSessionQuota;
  },
): boolean {
  return (
    session !== null &&
    quota !== null &&
    session.wallet_session_id === input.session.walletSessionId &&
    session.principal_id === input.session.principalId &&
    session.wallet_id === input.session.walletId &&
    session.authority_digest === input.session.authority.authorityDigest &&
    session.mint_id === input.session.mintId &&
    session.quota_id === input.session.quotaId &&
    session.lifecycle_kind === 'active' &&
    integerColumn(session.created_at_ms, 'session.createdAtMs') === input.session.createdAtMs &&
    integerColumn(session.expires_at_ms, 'session.expiresAtMs') === input.session.expiresAtMs &&
    quota.wallet_session_id === input.quota.walletSessionId &&
    quota.principal_id === input.quota.principalId &&
    quota.lifecycle_kind === 'active' &&
    integerColumn(quota.remaining_uses, 'quota.remainingUses') === input.quota.remainingUses &&
    integerColumn(quota.expires_at_ms, 'quota.expiresAtMs') === input.quota.expiresAtMs
  );
}
