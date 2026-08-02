import {
  CAPABILITY_KINDS,
  parseAuthorizationAuditEventId,
  parseAuthorizationGrantRef,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationRef,
  parseCapabilityOperationResultStorageRef,
  parseDeviceId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  type AuthorizationParseResult,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  ActiveAuthorizationSession,
  AuthorizedOperation,
  AuthorizedOperationInput,
  WalletSessionAuthorization,
  ActiveWalletSessionQuota,
  CapabilityOperationResultRef,
  CompletedCapabilityOperationResult,
  IssuedHostedWalletSeamsSessionExchange,
  RedeemHostedWalletSeamsSessionExchangeInput,
  RedeemHostedWalletSeamsSessionExchangeResult,
  ReusableWalletSessionStatus,
  VerifiedGrantEvidenceSet,
  WalletSessionId,
} from '../../authorization/domain';
import {
  buildActiveAuthorizationSession,
  parseMpcWalletSigningQuotaId,
  parseSessionOrigin,
  parseWalletSessionId,
} from '../../authorization/domain';
import { buildAuthorizedOperation } from '../../authorization/domain';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
  parseCapabilityOperationFingerprintDigest,
  type CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import type {
  AuthorizationClaimPort,
  AuthorizationEvidencePort,
  AuthorizationGrantPort,
  AuthorizationSessionPort,
  EcdsaMaterialActivationScope,
} from '../../authorization/service';
import { d1ChangedRows, type D1Row } from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
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
    AuthorizationClaimPort
{
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
        walletSessionIdForAuthorization(input.session),
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

  async readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null> {
    const row = await this.database
      .prepare(
        `SELECT * FROM authorized_operations
          WHERE namespace = ? AND tenant_id = ? AND operation_fingerprint_digest = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.operationFingerprintDigest)
      .first<D1Row>();
    return row ? await parseAuthorizedOperationRow(row) : null;
  }

  async claimAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: EcdsaMaterialActivationScope;
  }): Promise<
    | { readonly kind: 'claimed'; readonly operation: AuthorizedOperation }
    | { readonly kind: 'replayed'; readonly operation: AuthorizedOperation }
    | { readonly kind: 'operation_in_progress'; readonly operation: AuthorizedOperation }
    | {
        readonly kind:
          | 'authorization_grant_rejected'
          | 'verified_step_up_rejected'
          | 'wallet_session_quota_exhausted'
          | 'material_mismatch';
      }
  > {
    const operation = await buildAuthorizedOperation(input.operation);
    const existing = await this.readAuthorizedOperation({
      tenantId: operation.tenantId,
      operationFingerprintDigest: operation.operationFingerprintDigest,
    });
    if (existing) {
      return existing.lifecycle === 'completed'
        ? { kind: 'replayed', operation: existing }
        : { kind: 'operation_in_progress', operation: existing };
    }
    const source = operation.authorization;
    const quota = operation.quota;
    const materialActivationId = input.material?.materialActivation.activation_id ?? null;
    const requiresEcdsaMaterial =
      operation.operation.operation.capabilityKind === CAPABILITY_KINDS.evmEcdsaMpcSigning;
    if (requiresEcdsaMaterial && !input.material) return { kind: 'material_mismatch' };
    if (
      input.material &&
      (operation.operation.operation.capabilityKind !== CAPABILITY_KINDS.evmEcdsaMpcSigning ||
        input.material.runtimePolicyScope.orgId !== operation.tenantId ||
        input.material.materialActivation.capability !== operation.operation.capabilityId ||
        input.material.materialActivation.material_owner !== input.material.walletId)
    ) {
      return { kind: 'material_mismatch' };
    }
    try {
      const values = [
        this.namespace,
        operation.tenantId,
        operation.authorizedOperationId,
        operation.auditEventId,
        operation.operation.principalId,
        operation.operation.capabilityId,
        operation.operation.operation.capabilityKind,
        operation.operation.operation.operationKind,
        operation.operation.operationId,
        operation.operationFingerprintDigest,
        operation.operation.digests.laneDigest,
        operation.operation.digests.intentDigest,
        operation.operation.digests.displayDigest,
        source.kind,
        source.kind === 'authorization_grant' ? source.authorizationGrantRef.authorizationId : null,
        source.kind === 'verified_step_up' ? source.evidenceSetDigest : null,
        quota.kind === 'consume_reusable_wallet_session' ? quota.quotaId : null,
        quota.kind,
        requirePositiveInteger(input.operation.claimedAtMs, 'operation.claimedAtMs'),
        materialActivationId,
      ] as const;
      const statement = input.material
        ? this.database
            .prepare(
              `INSERT INTO authorized_operations (
                namespace, tenant_id, authorized_operation_id, audit_event_id,
                principal_id, capability_id, capability_kind, operation_kind, operation_id,
                operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
                authorization_source_kind, authorization_id, evidence_set_digest,
                quota_id, quota_kind, lifecycle_kind, result_kind,
                result_digest, result_storage_ref, claimed_at_ms, completed_at_ms,
                material_activation_id
              ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'claimed', 'pending', NULL, NULL, ?, NULL, ?
                 WHERE ${ECDSA_SIGNER_MATCH}`,
            )
            .bind(...values, ...ecdsaSignerMatchBindings(this.namespace, input.material))
        : this.database
            .prepare(
              `INSERT INTO authorized_operations (
                namespace, tenant_id, authorized_operation_id, audit_event_id,
                principal_id, capability_id, capability_kind, operation_kind, operation_id,
                operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
                authorization_source_kind, authorization_id, evidence_set_digest,
                quota_id, quota_kind, lifecycle_kind, result_kind,
                result_digest, result_storage_ref, claimed_at_ms, completed_at_ms,
                material_activation_id
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'claimed', 'pending', NULL, NULL, ?, NULL, ?)`,
            )
            .bind(...values);
      const result = await statement.run();
      if (input.material && d1ChangedRows(result) === 0) return { kind: 'material_mismatch' };
      requireOneChangedRow(result, 'authorized operation claim');
    } catch {
      const raced = await this.readAuthorizedOperation({
        tenantId: operation.tenantId,
        operationFingerprintDigest: operation.operationFingerprintDigest,
      });
      if (raced) {
        return raced.lifecycle === 'completed'
          ? { kind: 'replayed', operation: raced }
          : { kind: 'operation_in_progress', operation: raced };
      }
      return source.kind === 'verified_step_up'
        ? { kind: 'verified_step_up_rejected' }
        : quota.kind === 'consume_reusable_wallet_session'
          ? { kind: 'wallet_session_quota_exhausted' }
          : { kind: 'authorization_grant_rejected' };
    }
    const committed = await this.readAuthorizedOperation({
      tenantId: operation.tenantId,
      operationFingerprintDigest: operation.operationFingerprintDigest,
    });
    if (!committed) throw new Error('authorized operation claim could not be read back');
    return { kind: 'claimed', operation: committed };
  }

  async completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<AuthorizedOperation> {
    const operation = input.operation;
    const update = await this.database
      .prepare(
        `UPDATE authorized_operations
            SET lifecycle_kind = 'completed', result_kind = ?, result_digest = ?,
                result_storage_ref = ?, completed_at_ms = ?
          WHERE namespace = ? AND tenant_id = ?
            AND authorized_operation_id = ? AND operation_fingerprint_digest = ?
            AND lifecycle_kind = 'claimed'`,
      )
      .bind(
        input.result,
        input.resultRef.resultDigest,
        input.resultRef.resultStorageRef,
        requirePositiveInteger(input.completedAtMs, 'operation.completedAtMs'),
        this.namespace,
        operation.tenantId,
        operation.authorizedOperationId,
        operation.operationFingerprintDigest,
      )
      .run();
    if (d1ChangedRows(update) === 0) {
      const existing = await this.readAuthorizedOperation({
        tenantId: operation.tenantId,
        operationFingerprintDigest: operation.operationFingerprintDigest,
      });
      if (!existing) throw new Error('authorized operation completion claim is missing');
      return existing;
    }
    const completed = await this.readAuthorizedOperation({
      tenantId: operation.tenantId,
      operationFingerprintDigest: operation.operationFingerprintDigest,
    });
    if (!completed) throw new Error('authorized operation completion could not be read back');
    return completed;
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

async function parseAuthorizedOperationRow(row: D1Row): Promise<AuthorizedOperation> {
  const tenantId = requireParsed(row.tenant_id, parseTenantId, 'operation.tenantId');
  const operation = buildCapabilityOperationEnvelope({
    tenantId,
    principalId: requireParsed(row.principal_id, parsePrincipalId, 'operation.principalId'),
    capabilityId: requireParsed(row.capability_id, parseCapabilityId, 'operation.capabilityId'),
    operationId: requireParsed(row.operation_id, parseCapabilityOperationId, 'operation.operationId'),
    operation: requireParsed(
      { capabilityKind: row.capability_kind, operationKind: row.operation_kind },
      parseCapabilityOperationRef,
      'operation.operation',
    ),
    digests: {
      laneDigest: parseDigestB64u(requireString(row.lane_digest, 'operation.laneDigest')),
      intentDigest: parseDigestB64u(requireString(row.intent_digest, 'operation.intentDigest')),
      displayDigest: parseDigestB64u(requireString(row.display_digest, 'operation.displayDigest')),
    },
  });
  const sourceKind = requireString(row.authorization_source_kind, 'operation.authorization.kind');
  let authorization: AuthorizedOperation['authorization'];
  if (sourceKind === 'authorization_grant') {
    if (row.evidence_set_digest != null) {
      throw new Error('operation.authorization grant row cannot contain evidenceSetDigest');
    }
    authorization = {
      kind: 'authorization_grant',
      authorizationGrantRef: requireParsed(
        {
          kind: 'wallet_session_authorization',
          authorizationId: row.authorization_id,
        },
        parseAuthorizationGrantRef,
        'operation.authorization.authorizationGrantRef',
      ),
    };
  } else if (sourceKind === 'verified_step_up') {
    if (row.authorization_id != null) {
      throw new Error('operation.authorization step-up row cannot contain authorizationId');
    }
    authorization = {
          kind: 'verified_step_up' as const,
          evidenceSetDigest: parseDigestB64u(
            requireString(row.evidence_set_digest, 'operation.authorization.evidenceSetDigest'),
          ),
      };
  } else {
    throw new Error('operation.authorization.kind is invalid');
  }
  const lifecycle = requireString(row.lifecycle_kind, 'operation.lifecycle');
  const base = {
    kind: 'authorized_operation' as const,
    tenantId,
    authorizedOperationId: requireParsed(
      row.authorized_operation_id,
      parseAuthorizedOperationId,
      'operation.authorizedOperationId',
    ),
    auditEventId: requireParsed(
      row.audit_event_id,
      parseAuthorizationAuditEventId,
      'operation.auditEventId',
    ),
    operation,
    operationFingerprintDigest: parseOperationFingerprint(row.operation_fingerprint_digest),
    authorization,
    claimedAtMs: requirePositiveInteger(row.claimed_at_ms, 'operation.claimedAtMs'),
    quota: (() => {
      const quotaKind = requireString(row.quota_kind, 'operation.quota.kind');
      if (quotaKind === 'consume_reusable_wallet_session') {
        return {
          kind: 'consume_reusable_wallet_session' as const,
          quotaId: requireParsed(row.quota_id, parseMpcWalletSigningQuotaId, 'operation.quotaId'),
        };
      }
      if (quotaKind === 'quota_neutral') {
        if (row.quota_id != null) throw new Error('operation.quota-neutral row cannot contain quotaId');
        return { kind: 'quota_neutral' as const };
      }
      throw new Error('operation.quota.kind is invalid');
    })(),
  };
  const expectedFingerprint = await computeCapabilityOperationFingerprintDigest(operation);
  if (expectedFingerprint !== base.operationFingerprintDigest) {
    throw new Error('operation.operationFingerprintDigest does not match operation envelope');
  }
  if (lifecycle === 'claimed') return { ...base, lifecycle: 'claimed' };
  if (lifecycle !== 'completed') throw new Error('operation.lifecycle is invalid');
  const result = requireString(row.result_kind, 'operation.result');
  if (
    result !== 'succeeded' &&
    result !== 'failed_before_side_effect' &&
    result !== 'failed_after_side_effect'
  ) {
    throw new Error('operation.result is invalid');
  }
  return {
    ...base,
    lifecycle: 'completed',
    result,
    resultRef: {
      resultDigest: parseDigestB64u(requireString(row.result_digest, 'operation.resultDigest')),
      resultStorageRef: requireParsed(
        row.result_storage_ref,
        parseCapabilityOperationResultStorageRef,
        'operation.resultStorageRef',
      ),
    },
    completedAtMs: requirePositiveInteger(row.completed_at_ms, 'operation.completedAtMs'),
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
  try {
    return parseCapabilityOperationFingerprintDigest(value);
  } catch (error) {
    throw new Error(
      `operation.operationFingerprintDigest: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
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

function requireString(value: unknown, label: string): string {
  return requireOpaqueString(value, label);
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
    walletSessionIdForAuthorization(input.session) !== input.quota.walletSessionId ||
    input.session.quotaId !== input.quota.quotaId ||
    input.session.expiresAtMs !== input.quota.expiresAtMs
  ) {
    throw new Error('reusable Wallet Session and quota must have one exact identity');
  }
}

function walletSessionIdForAuthorization(session: WalletSessionAuthorization): WalletSessionId {
  return requireParsed(session.authorizationId, parseWalletSessionId, 'session.authorizationId');
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
    session.wallet_session_id === walletSessionIdForAuthorization(input.session) &&
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
