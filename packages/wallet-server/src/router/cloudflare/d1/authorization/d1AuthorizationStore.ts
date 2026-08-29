import { parseWalletAuthMethodId, type WalletAuthMethodId } from '@shared/utils/domainIds';
import {
  CAPABILITY_KINDS,
  parseAuthorizationAuditEventId,
  parseAuthorizationGrantRef,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationRef,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseTenantId,
  parseWalletSessionClientCapabilityV1,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type AuthorizationParseResult,
  type AuthorizedOperationId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  AuthorizedOperation,
  AuthorizedOperationInput,
  WalletSessionAuthorization,
  IssuedWalletSessionAuthorizationV2,
  WalletSessionAuthorizationV2,
  ActiveWalletSessionQuota,
  PersistedActiveWalletSessionAuthorizationV2,
  DirectV2CommitResult,
  WalletSessionAuthorizationV2MintLookup,
  WalletSessionAuthorizationV2MintRead,
  AuthorizedOperationReplayResponse,
  CompletedCapabilityOperationResult,
  IssuedHostedWalletSeamsSessionExchange,
  RedeemHostedWalletSeamsSessionExchangeInput,
  PersistedHostedWalletSeamsSessionExchangeResult,
  ReusableWalletSessionStatus,
  VerifiedAuthorizationEvidenceSet,
  VerifiedOwnerProof,
  WalletSessionId,
} from '../../../../authorization/domain';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorization,
  parseWalletSessionAuthorizationV2,
  walletSessionAuthorizationV2RecordsEqual,
  computeAuthorizedOperationResultDigest,
  parseAuthorizedOperationReplayResponse,
} from '../../../../authorization/domain';
import { buildAuthorizedOperation } from '../../../../authorization/domain';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
  parseCapabilityOperationFingerprintDigest,
  type CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import type {
  AuthorizedOperationPort,
  AuthorizationEvidencePort,
  AuthorizationGrantPort,
  AuthorizationSessionPort,
  EcdsaMaterialActivationScope,
  AuthorizedOperationMaterialScope,
  IssuedReusableWalletSession,
  OpaqueWalletSessionCurve,
  OpaqueOwnerWalletSessionBinding,
  ResolvedOpaqueWalletSessionToken,
} from '../../../../authorization/service';
import { parseOpaqueOwnerWalletSessionBinding } from '../../../../authorization/service';
import type { D1WalletStoreScope } from '../../../../core/d1WalletStore';
import { d1ChangedRows, parseD1JsonColumn, type D1Row } from '../../../../storage/d1Sql';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import { parseWalletId } from '@shared/utils/domainIds';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

export type D1AuthorizationStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly walletSignerScope: D1WalletStoreScope;
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
  walletSignerScope: D1WalletStoreScope,
  material: EcdsaMaterialActivationScope,
): readonly unknown[] {
  const activation = material.materialActivation;
  return [
    walletSignerScope.namespace,
    walletSignerScope.orgId,
    walletSignerScope.projectId,
    walletSignerScope.envId,
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
  readonly wallet_session_id?: unknown;
  readonly nonce_digest?: unknown;
  readonly app_origin?: unknown;
  readonly wallet_origin?: unknown;
  readonly curve?: unknown;
  readonly binding_json?: unknown;
  readonly lifecycle_kind?: unknown;
  readonly expires_at_ms?: unknown;
};

/**
 * The issuing auth method recorded on a stored session row, if any.
 *
 * The column is nullable because sessions minted before provenance existed have
 * no issuer to record. Absence means unattributed, not "matches anything" — the
 * comparison helper below is what decides whether that is acceptable.
 */
function storedAuthMethodId(raw: unknown): WalletAuthMethodId | null {
  if (raw === null || raw === undefined) return null;
  const parsed = parseWalletAuthMethodId(raw);
  if (!parsed.ok) throw new Error('stored Wallet Session auth-method identity is invalid');
  return parsed.value;
}

/**
 * Whether a stored session may be read back under this authority.
 *
 * A recorded issuer must match exactly: persisting provenance is only worth
 * anything if a mismatch is refused, so a session issued by one credential can
 * never be replayed under another. A row with no recorded issuer predates the
 * column and is allowed through — it simply cannot be fenced by binding.
 */
function storedAuthMethodMatches(raw: unknown, authority: WalletAuthAuthorityRef): boolean {
  const stored = storedAuthMethodId(raw);
  return stored === null || stored === authority.walletAuthMethodId;
}

const ACTIVE_WALLET_AUTH_METHOD_EXISTS_SQL = `
  EXISTS (
    SELECT 1
      FROM wallet_auth_methods AS auth_method
     WHERE auth_method.namespace = ?
       AND auth_method.org_id = ?
       AND auth_method.project_id = ?
       AND auth_method.env_id = ?
       AND auth_method.wallet_auth_method_id = ?
       AND auth_method.wallet_id = ?
       AND auth_method.status = 'active'
  )`;

function activeWalletAuthMethodBindings(
  scope: D1WalletStoreScope,
  authority: WalletAuthAuthorityRef,
): readonly string[] {
  return [
    scope.namespace,
    scope.orgId,
    scope.projectId,
    scope.envId,
    authority.walletAuthMethodId,
    String(authority.walletId),
  ];
}

const ACTIVE_V2_AUTHORITY_METHOD_EXISTS_SQL = `
  EXISTS (
    SELECT 1
      FROM wallet_authorities AS authority
      JOIN wallet_auth_methods AS auth_method
        ON auth_method.namespace = authority.namespace
       AND auth_method.org_id = authority.org_id
       AND auth_method.project_id = authority.project_id
       AND auth_method.env_id = authority.env_id
       AND auth_method.wallet_authority_id = authority.authority_id
       AND auth_method.wallet_id = authority.wallet_id
       AND auth_method.wallet_auth_method_id = ?
       AND auth_method.status = 'active'
     WHERE authority.namespace = ?
       AND authority.org_id = ?
       AND authority.project_id = ?
       AND authority.env_id = ?
       AND authority.authority_id = ?
       AND authority.wallet_id = ?
       AND authority.lifecycle_state = 'active'
       AND authority.authority_digest_b64u = ?
       AND authority.revocation_epoch = ?
  )`;

function activeV2AuthorityMethodBindings(
  scope: D1WalletStoreScope,
  session: WalletSessionAuthorizationV2,
): readonly unknown[] {
  return [
    String(session.walletAuthMethodId),
    scope.namespace,
    scope.orgId,
    scope.projectId,
    scope.envId,
    String(session.authorityId),
    String(session.walletId),
    String(session.authorityDigestB64u),
    session.authorityRevocationEpoch,
  ];
}

export class CloudflareD1AuthorizationStore
  implements
    AuthorizationSessionPort,
    AuthorizationEvidencePort,
    AuthorizationGrantPort,
    AuthorizedOperationPort
{
  private readonly database: D1DatabaseLike;
  private readonly namespace: string;
  private readonly walletSignerScope: D1WalletStoreScope;

  constructor(options: D1AuthorizationStoreOptions) {
    this.database = options.database;
    this.namespace = requireOpaqueString(options.namespace, 'namespace');
    this.walletSignerScope = {
      namespace: requireOpaqueString(
        options.walletSignerScope.namespace,
        'walletSignerScope.namespace',
      ),
      orgId: requireOpaqueString(options.walletSignerScope.orgId, 'walletSignerScope.orgId'),
      projectId: requireOpaqueString(
        options.walletSignerScope.projectId,
        'walletSignerScope.projectId',
      ),
      envId: requireOpaqueString(options.walletSignerScope.envId, 'walletSignerScope.envId'),
    };
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

  async revokeReusableWalletSessionsForAuthMethod(input: {
    readonly tenantId: TenantId;
    readonly walletId: import('@shared/utils/domainIds').WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly nowMs: number;
  }): Promise<void> {
    await this.database.batch(this.prepareRevokeReusableWalletSessionsForAuthMethod(input));
  }

  prepareRevokeReusableWalletSessionsForAuthMethod(input: {
    readonly tenantId: TenantId;
    readonly walletId: import('@shared/utils/domainIds').WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly nowMs: number;
  }): readonly D1PreparedStatementLike[] {
    requirePositiveInteger(input.nowMs, 'auth-method session revocation time');
    const sessionFilter = `
      FROM reusable_wallet_sessions AS session
      WHERE session.namespace = ?
        AND session.tenant_id = ?
        AND session.wallet_id = ?
        AND session.wallet_auth_method_id = ?`;
    const deleteTokens = this.database
      .prepare(
        `DELETE FROM opaque_wallet_session_tokens
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})`,
      )
      .bind(
        this.namespace,
        input.tenantId,
        this.namespace,
        input.tenantId,
        input.walletId,
        input.walletAuthMethodId,
      );
    const deleteRegistrationReplayTokens = this.database
      .prepare(
        `DELETE FROM registration_replay_opaque_wallet_session_tokens_v1
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})`,
      )
      .bind(
        this.namespace,
        input.tenantId,
        this.namespace,
        input.tenantId,
        input.walletId,
        input.walletAuthMethodId,
      );
    const exhaustQuotas = this.database
      .prepare(
        `UPDATE authorization_wallet_session_quotas
            SET remaining_uses = 0,
                lifecycle_kind = 'exhausted'
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id IN (SELECT session.wallet_session_id ${sessionFilter})
            AND lifecycle_kind = 'active'`,
      )
      .bind(
        this.namespace,
        input.tenantId,
        this.namespace,
        input.tenantId,
        input.walletId,
        input.walletAuthMethodId,
      );
    const supersedeSessions = this.database
      .prepare(
        `UPDATE reusable_wallet_sessions
            SET lifecycle_kind = 'superseded'
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_id = ?
            AND wallet_auth_method_id = ?
            AND lifecycle_kind = 'active'`,
      )
      .bind(this.namespace, input.tenantId, input.walletId, input.walletAuthMethodId);
    return [deleteTokens, deleteRegistrationReplayTokens, exhaustQuotas, supersedeSessions];
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
          wallet_session_id,
          code_hash,
          nonce_digest,
          app_origin,
          wallet_origin,
          curve,
          binding_json,
          lifecycle_kind,
          issued_at_ms,
          expires_at_ms,
          token_hash,
          consumed_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued', ?, ?, NULL, NULL
          FROM reusable_wallet_sessions AS wallet_session
         WHERE wallet_session.namespace = ?
           AND wallet_session.tenant_id = ?
           AND wallet_session.wallet_session_id = ?
           AND wallet_session.lifecycle_kind = 'active'
           AND wallet_session.expires_at_ms >= ?`,
      )
      .bind(
        this.namespace,
        exchange.tenantId,
        exchange.exchangeCodeId,
        exchange.walletSessionId,
        exchange.codeHash,
        exchange.nonceDigest,
        exchange.appOrigin,
        exchange.walletOrigin,
        exchange.curve,
        exchange.bindingJson,
        requirePositiveInteger(exchange.issuedAtMs, 'exchange.issuedAtMs'),
        requirePositiveInteger(exchange.expiresAtMs, 'exchange.expiresAtMs'),
        this.namespace,
        exchange.tenantId,
        exchange.walletSessionId,
        exchange.expiresAtMs,
      )
      .run();
    requireOneChangedRow(result, 'hosted-wallet Seams session exchange code');
  }

  async redeemHostedWalletSeamsSessionExchange(
    input: RedeemHostedWalletSeamsSessionExchangeInput,
  ): Promise<PersistedHostedWalletSeamsSessionExchangeResult> {
    const current = await this.readHostedWalletExchange(input.codeHash);
    const rejected = classifyHostedWalletExchange(current, input);
    if (rejected) return rejected;
    try {
      const revokeExistingToken = this.database
        .prepare(
          `DELETE FROM opaque_wallet_session_tokens
            WHERE namespace = ?
              AND tenant_id = (
                SELECT tenant_id
                  FROM hosted_wallet_session_exchange_codes
                 WHERE namespace = ? AND code_hash = ?
              )
              AND wallet_session_id = (
                SELECT wallet_session_id
                  FROM hosted_wallet_session_exchange_codes
                 WHERE namespace = ? AND code_hash = ?
              )
              AND curve = ?`,
        )
        .bind(
          this.namespace,
          this.namespace,
          input.codeHash,
          this.namespace,
          input.codeHash,
          input.curve,
        );
      const revokeExistingRegistrationReplayToken = this.database
        .prepare(
          `DELETE FROM registration_replay_opaque_wallet_session_tokens_v1
            WHERE namespace = ?
              AND tenant_id = (
                SELECT tenant_id
                  FROM hosted_wallet_session_exchange_codes
                 WHERE namespace = ? AND code_hash = ?
              )
              AND wallet_session_id = (
                SELECT wallet_session_id
                  FROM hosted_wallet_session_exchange_codes
                 WHERE namespace = ? AND code_hash = ?
              )
              AND curve = ?`,
        )
        .bind(
          this.namespace,
          this.namespace,
          input.codeHash,
          this.namespace,
          input.codeHash,
          input.curve,
        );
      const updateStatement = this.database
        .prepare(
          `UPDATE hosted_wallet_session_exchange_codes
              SET lifecycle_kind = 'consumed',
                  token_hash = ?,
                  consumed_at_ms = ?
            WHERE namespace = ?
              AND code_hash = ?
              AND nonce_digest = ?
              AND app_origin = ?
              AND wallet_origin = ?
              AND lifecycle_kind = 'issued'
              AND expires_at_ms > ?
              AND EXISTS (
                SELECT 1
                  FROM reusable_wallet_sessions AS wallet_session
                 WHERE wallet_session.namespace = hosted_wallet_session_exchange_codes.namespace
                   AND wallet_session.tenant_id = hosted_wallet_session_exchange_codes.tenant_id
                   AND wallet_session.wallet_session_id = hosted_wallet_session_exchange_codes.wallet_session_id
                   AND wallet_session.lifecycle_kind = 'active'
                   AND wallet_session.expires_at_ms > ?
              )`,
        )
        .bind(
          input.tokenHash,
          requirePositiveInteger(input.redeemedAtMs, 'exchange.redeemedAtMs'),
          this.namespace,
          input.codeHash,
          input.nonceDigest,
          input.appOrigin,
          input.walletOrigin,
          input.redeemedAtMs,
          input.redeemedAtMs,
        );
      const results = await this.database.batch([
        revokeExistingToken,
        revokeExistingRegistrationReplayToken,
        updateStatement,
      ]);
      const update = results[2] as D1ResultLike;
      if (d1ChangedRows(update) !== 1) {
        return (
          classifyHostedWalletExchange(
            await this.readHostedWalletExchange(input.codeHash),
            input,
          ) ?? { kind: 'wallet_session_unavailable' }
        );
      }
    } catch {
      return { kind: 'wallet_session_unavailable' };
    }
    if (!current) throw new Error('hosted-wallet Seams session exchange disappeared');
    return {
      kind: 'redeemed',
      tenantId: requireParsed(current.tenant_id, parseTenantId, 'exchange.tenantId'),
      walletSessionId: requireParsed(
        current.wallet_session_id,
        parseWalletSessionId,
        'exchange.walletSessionId',
      ),
      curve: input.curve,
      expiresAtMs: integerColumn(current.expires_at_ms, 'exchange.expiresAtMs'),
    };
  }

  async putVerifiedEvidenceSet(evidenceSet: VerifiedAuthorizationEvidenceSet): Promise<void> {
    const result = await this.database
      .prepare(
        `INSERT OR IGNORE INTO verified_wallet_operation_evidence_sets (
          namespace,
          tenant_id,
          evidence_set_id,
          principal_id,
          wallet_id,
          authority_digest,
          request_origin,
          audience,
          evidence_set_digest,
          evidence_json,
          capability_kind,
          operation_kind,
          lane_digest,
          intent_digest,
          display_digest,
          assurance,
          verified_at_ms,
          expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        this.namespace,
        evidenceSet.tenantId,
        evidenceSet.evidenceSetId,
        evidenceSet.principalId,
        evidenceSet.walletId,
        evidenceSet.authorityRef.authorityDigest,
        evidenceSet.requestOrigin,
        evidenceSet.audience,
        evidenceSet.evidenceSetDigest,
        JSON.stringify(evidenceSet.evidence),
        evidenceSet.operation.capabilityKind,
        evidenceSet.operation.operationKind,
        evidenceSet.laneDigest,
        evidenceSet.intentDigest,
        evidenceSet.displayDigest,
        evidenceSet.assurance,
        requirePositiveInteger(evidenceSet.verifiedAtMs, 'evidenceSet.verifiedAtMs'),
        requirePositiveInteger(evidenceSet.expiresAtMs, 'evidenceSet.expiresAtMs'),
      )
      .run();
    if (d1ChangedRows(result) > 1) {
      throw new Error('verified wallet operation evidence set changed more than one row');
    }
  }

  async consumeVerifiedOwnerProof(
    proof: VerifiedOwnerProof,
    consumedAtMs: number,
    consumptionScopeId: string,
  ): Promise<boolean> {
    const consumedAt = requirePositiveInteger(consumedAtMs, 'owner proof consumedAtMs');
    const scopeId = consumptionScopeId.trim();
    if (!scopeId) throw new Error('owner proof consumption scope is required');
    if (proof.verifiedAtMs > consumedAt || proof.expiresAtMs <= consumedAt) {
      throw new Error('owner proof is outside its verification window');
    }
    const result = await this.database
      .prepare(
        `INSERT OR IGNORE INTO verified_owner_proof_consumptions (
          namespace,
          tenant_id,
          proof_id,
          purpose,
          method,
          principal_id,
          wallet_id,
          authority_digest,
          replay_identity,
          consumption_scope_id,
          consumed_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        this.namespace,
        proof.tenantId,
        proof.proofId,
        proof.purpose,
        proof.method,
        proof.principalId,
        proof.walletId,
        proof.authority.authorityDigest,
        proof.replayIdentity,
        scopeId,
        consumedAt,
      )
      .run();
    if (d1ChangedRows(result) === 1) return true;
    const existing = await this.database
      .prepare(
        `SELECT
           purpose,
           method,
           principal_id,
           wallet_id,
           authority_digest,
           replay_identity,
           consumption_scope_id
           FROM verified_owner_proof_consumptions
          WHERE namespace = ?
            AND tenant_id = ?
            AND proof_id = ?
            AND replay_identity = ?`,
      )
      .bind(this.namespace, proof.tenantId, proof.proofId, proof.replayIdentity)
      .first<{
        purpose: string;
        method: string;
        principal_id: string;
        wallet_id: string;
        authority_digest: string;
        replay_identity: string;
        consumption_scope_id: string;
      }>();
    return (
      existing?.purpose === proof.purpose &&
      existing.method === proof.method &&
      existing.principal_id === proof.principalId &&
      existing.wallet_id === proof.walletId &&
      existing.authority_digest === proof.authority.authorityDigest &&
      existing.replay_identity === proof.replayIdentity &&
      existing.consumption_scope_id === scopeId
    );
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
         )
           AND ${ACTIVE_WALLET_AUTH_METHOD_EXISTS_SQL}`,
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
        ...activeWalletAuthMethodBindings(this.walletSignerScope, input.session.authority),
      );
    const sessionStatement = this.database
      .prepare(
        `INSERT OR IGNORE INTO reusable_wallet_sessions (
          namespace,
          tenant_id,
          authorization_id,
          wallet_session_id,
          principal_id,
          wallet_id,
          authority_digest,
          wallet_auth_method_id,
          mint_id,
          quota_id,
          lifecycle_kind,
          created_at_ms,
          expires_at_ms
        )
        SELECT
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?
         WHERE ${ACTIVE_WALLET_AUTH_METHOD_EXISTS_SQL}`,
      )
      .bind(
        this.namespace,
        input.session.tenantId,
        input.session.authorizationId,
        input.session.walletSessionId,
        input.session.principalId,
        input.session.walletId,
        input.session.authority.authorityDigest,
        // Recorded so pausing or revoking this credential can select every
        // session it issued, rather than recomputing a digest per candidate.
        input.session.authority.walletAuthMethodId,
        input.session.mintId,
        input.session.quotaId,
        requirePositiveInteger(input.session.createdAtMs, 'session.createdAtMs'),
        requirePositiveInteger(input.session.expiresAtMs, 'session.expiresAtMs'),
        ...activeWalletAuthMethodBindings(this.walletSignerScope, input.session.authority),
      );
    const results = await this.database.batch<D1ResultLike>([
      retireQuotaStatement,
      retireSessionStatement,
      quotaStatement,
      sessionStatement,
    ]);
    if (results.length !== 4) {
      throw new Error('reusable Wallet Session transaction returned incomplete results');
    }
    const quotaResult = results[2];
    const sessionResult = results[3];
    if (!quotaResult || !sessionResult) {
      throw new Error('reusable Wallet Session transaction returned incomplete results');
    }
    const quotaInserted = d1ChangedRows(quotaResult) === 1;
    const sessionInserted = d1ChangedRows(sessionResult) === 1;
    if (quotaInserted !== sessionInserted) {
      throw new Error('reusable Wallet Session transaction persisted an incomplete identity');
    }
    if (sessionInserted) {
      await this.requireExactReusableWalletSessionReadback(input);
      return;
    }
    await this.requireExactReusableWalletSessionReplayReadback(input);
  }

  async readWalletSessionAuthorizationByMint(input: {
    readonly tenantId: TenantId;
    readonly principalId: WalletSessionAuthorization['principalId'];
    readonly walletId: WalletSessionAuthorization['walletId'];
    readonly authority: WalletAuthAuthorityRef;
    readonly mintId: WalletSessionAuthorization['mintId'];
    readonly nowMs: number;
  }): Promise<IssuedReusableWalletSession | null> {
    if (input.authority.walletId !== input.walletId) {
      throw new Error('Wallet Session authorization authority does not identify the wallet');
    }
    const row = await this.database
      .prepare(
        `SELECT
           session.tenant_id AS session_tenant_id,
           session.principal_id AS session_principal_id,
           session.wallet_id AS session_wallet_id,
           session.authority_digest AS session_authority_digest,
           session.wallet_auth_method_id AS session_wallet_auth_method_id,
           session.mint_id AS session_mint_id,
           session.authorization_id AS session_authorization_id,
           session.wallet_session_id AS session_wallet_session_id,
           session.quota_id AS session_quota_id,
           session.lifecycle_kind AS session_lifecycle_kind,
           session.created_at_ms AS session_created_at_ms,
           session.expires_at_ms AS session_expires_at_ms,
           quota.tenant_id AS quota_tenant_id,
           quota.principal_id AS quota_principal_id,
           quota.wallet_session_id AS quota_wallet_session_id,
           quota.quota_id AS quota_quota_id,
           quota.lifecycle_kind AS quota_lifecycle_kind,
           quota.remaining_uses AS quota_remaining_uses,
           quota.expires_at_ms AS quota_expires_at_ms
         FROM reusable_wallet_sessions AS session
         LEFT JOIN authorization_wallet_session_quotas AS quota
           ON quota.namespace = session.namespace
          AND quota.tenant_id = session.tenant_id
          AND quota.quota_id = session.quota_id
        WHERE session.namespace = ?
          AND session.tenant_id = ?
          AND session.mint_id = ?
        LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.mintId)
      .first<D1Row>();
    if (!row) return null;

    const sessionTenantId = requireParsed(row.session_tenant_id, parseTenantId, 'session.tenantId');
    const sessionPrincipalId = requireParsed(
      row.session_principal_id,
      parsePrincipalId,
      'session.principalId',
    );
    const sessionWalletId = requireParsed(row.session_wallet_id, parseWalletId, 'session.walletId');
    const sessionMintId = requireParsed(
      row.session_mint_id,
      parseReusableWalletSessionMintId,
      'session.mintId',
    );
    const sessionAuthorizationId = requireParsed(
      row.session_authorization_id,
      parseWalletSessionAuthorizationId,
      'session.authorizationId',
    );
    const sessionWalletSessionId = requireParsed(
      row.session_wallet_session_id,
      parseWalletSessionId,
      'session.walletSessionId',
    );
    const sessionQuotaId = requireParsed(
      row.session_quota_id,
      parseMpcWalletSigningQuotaId,
      'session.quotaId',
    );
    const sessionCreatedAtMs = requirePositiveInteger(
      row.session_created_at_ms,
      'session.createdAtMs',
    );
    const sessionExpiresAtMs = requirePositiveInteger(
      row.session_expires_at_ms,
      'session.expiresAtMs',
    );
    const quotaTenantId = requireParsed(row.quota_tenant_id, parseTenantId, 'quota.tenantId');
    const quotaPrincipalId = requireParsed(
      row.quota_principal_id,
      parsePrincipalId,
      'quota.principalId',
    );
    const quotaWalletSessionId = requireParsed(
      row.quota_wallet_session_id,
      parseWalletSessionId,
      'quota.walletSessionId',
    );
    const quotaId = requireParsed(
      row.quota_quota_id,
      parseMpcWalletSigningQuotaId,
      'quota.quotaId',
    );
    const quotaRemainingUses = requirePositiveInteger(
      row.quota_remaining_uses,
      'quota.remainingUses',
    );
    const quotaExpiresAtMs = requirePositiveInteger(row.quota_expires_at_ms, 'quota.expiresAtMs');
    if (
      sessionTenantId !== input.tenantId ||
      sessionPrincipalId !== input.principalId ||
      sessionWalletId !== input.walletId ||
      row.session_authority_digest !== input.authority.authorityDigest ||
      // Provenance is only worth persisting if a mismatch is refused. A stored
      // session issued by one credential must never be replayed under another.
      !storedAuthMethodMatches(row.session_wallet_auth_method_id, input.authority) ||
      sessionMintId !== input.mintId ||
      quotaTenantId !== sessionTenantId ||
      quotaPrincipalId !== sessionPrincipalId ||
      quotaWalletSessionId !== sessionWalletSessionId ||
      quotaId !== sessionQuotaId ||
      quotaExpiresAtMs !== sessionExpiresAtMs
    ) {
      throw new Error('Stored Wallet Session authorization identity does not match the request');
    }
    if (row.session_lifecycle_kind !== 'active' || row.quota_lifecycle_kind !== 'active') {
      throw new Error('Stored Wallet Session authorization is no longer active');
    }
    if (sessionExpiresAtMs <= requirePositiveInteger(input.nowMs, 'authorization read time')) {
      throw new Error('Stored Wallet Session authorization has expired');
    }
    const session = buildWalletSessionAuthorization({
      tenantId: sessionTenantId,
      principalId: sessionPrincipalId,
      walletId: sessionWalletId,
      authority: input.authority,
      mintId: sessionMintId,
      authorizationId: sessionAuthorizationId,
      walletSessionId: sessionWalletSessionId,
      quotaId: sessionQuotaId,
      createdAtMs: sessionCreatedAtMs,
      expiresAtMs: sessionExpiresAtMs,
    });
    const quota = buildActiveWalletSessionQuota({
      tenantId: quotaTenantId,
      principalId: quotaPrincipalId,
      walletSessionId: quotaWalletSessionId,
      quotaId,
      remainingUses: quotaRemainingUses,
      expiresAtMs: quotaExpiresAtMs,
    });
    return { session, quota };
  }

  async putWalletSessionAuthorizationV2(input: {
    readonly session: WalletSessionAuthorizationV2;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void> {
    const statements = this.prepareWalletSessionAuthorizationV2Statements(input);
    const results = await this.database.batch<D1ResultLike>(statements);
    if (results.length !== 2) {
      throw new Error('V2 Wallet Session transaction returned incomplete results');
    }
    const quotaResult = results[0];
    const sessionResult = results[1];
    if (!quotaResult || !sessionResult) {
      throw new Error('V2 Wallet Session transaction returned incomplete results');
    }
    const quotaChanges = d1ChangedRows(quotaResult);
    const sessionChanges = d1ChangedRows(sessionResult);
    if (quotaChanges !== sessionChanges) {
      const reusedExactQuota =
        quotaChanges === 0 &&
        sessionChanges === 1 &&
        (await this.existingWalletSessionAuthorizationV2QuotaMatches(input.quota));
      if (!reusedExactQuota) {
        throw new Error('V2 Wallet Session transaction persisted an incomplete identity');
      }
    }
    const persisted = await this.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: input.session,
      nowMs: input.session.createdAtMs,
    });
    if (!persisted) {
      throw new Error('V2 Wallet Session authorization was not persisted');
    }
    if (persisted.quota.remainingUses !== input.quota.remainingUses) {
      throw new Error('V2 Wallet Session issuance replay does not match');
    }
  }

  async commitDirectWalletSessionAuthorizationV2(input: {
    readonly persisted: PersistedActiveWalletSessionAuthorizationV2;
  }): Promise<DirectV2CommitResult> {
    const { persisted } = input;
    requireExactPersistedActiveWalletSessionAuthorizationV2(persisted);
    const statements = this.prepareDirectWalletSessionAuthorizationV2Statements(persisted);
    const results = await this.database.batch<D1ResultLike>(statements);
    if (results.length !== 4) {
      throw new Error('Direct V2 Wallet Session transaction returned incomplete results');
    }
    const quotaResult = results[2];
    const sessionResult = results[3];
    if (!quotaResult || !sessionResult) {
      throw new Error('Direct V2 Wallet Session transaction returned incomplete results');
    }
    const quotaChanges = d1ChangedRows(quotaResult);
    const sessionChanges = d1ChangedRows(sessionResult);
    if (quotaChanges !== sessionChanges) {
      throw new Error('Direct V2 Wallet Session transaction persisted an incomplete identity');
    }
    const lookup: WalletSessionAuthorizationV2MintLookup = {
      tenantId: persisted.session.tenantId,
      principalId: persisted.session.principalId,
      walletId: persisted.session.walletId,
      authorityId: persisted.session.authorityId,
      walletAuthMethodId: persisted.session.walletAuthMethodId,
      mintId: persisted.session.mintId,
    };
    const committed = await this.readWalletSessionAuthorizationV2ByMint(lookup);
    if (!committed) {
      throw new Error('Direct V2 Wallet Session authorization commit was not readable');
    }
    if (committed.session.walletSessionId !== persisted.session.walletSessionId) {
      throw new Error('Direct V2 Wallet Session commit returned a different session identity');
    }
    if (sessionChanges === 0) {
      return { kind: 'already_committed', committed };
    }
    if (
      committed.primaryOperationCredentialDigestB64u !==
      persisted.primaryOperationCredentialDigestB64u
    ) {
      throw new Error('Direct V2 Wallet Session commit returned a different credential digest');
    }
    if (sessionChanges !== 1) {
      throw new Error('Direct V2 Wallet Session transaction changed more than one session');
    }
    return { kind: 'inserted' };
  }

  /**
   * Builds the one batch used by direct issuance. Every predecessor mutation
   * is gated by the candidate identity check, so a same-mint replay leaves
   * the committed session and its predecessor state untouched.
   */
  prepareDirectWalletSessionAuthorizationV2Statements(
    persisted: PersistedActiveWalletSessionAuthorizationV2,
  ): readonly [
    D1PreparedStatementLike,
    D1PreparedStatementLike,
    D1PreparedStatementLike,
    D1PreparedStatementLike,
  ] {
    requireExactPersistedActiveWalletSessionAuthorizationV2(persisted);
    const {
      session,
      quota,
      primaryOperationCredentialDigestB64u,
      walletSessionClientCapability,
      responseFamily,
    } = persisted;
    const capabilitySubjectsJson = JSON.stringify(session.capabilitySubjects);
    const recordJson = JSON.stringify(session);
    if (!capabilitySubjectsJson || !recordJson) {
      throw new Error('Direct V2 Wallet Session authorization serialization is required');
    }
    const availabilitySql = directV2IdentityAvailabilitySql();
    const availabilityBindings = directV2IdentityAvailabilityBindings(
      this.namespace,
      this.walletSignerScope,
      session,
    );
    const sessionIdentityAvailabilitySql = directV2SessionIdentityAvailabilitySql();
    const sessionIdentityAvailabilityBindings = directV2SessionIdentityAvailabilityBindings(
      this.namespace,
      this.walletSignerScope,
      session,
    );
    const retirePredecessorSessions = this.database
      .prepare(
        `UPDATE wallet_session_authorizations_v2
            SET retired_at_ms = MAX(issued_at_ms, ?)
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND tenant_id = ?
            AND wallet_id = ?
            AND authority_id = ?
            AND wallet_auth_method_id = ?
            AND retired_at_ms IS NULL
            AND mint_id != ?
            AND ${availabilitySql}`,
      )
      .bind(
        requirePositiveInteger(session.createdAtMs, 'Direct V2 issuance time'),
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        session.tenantId,
        String(session.walletId),
        String(session.authorityId),
        String(session.walletAuthMethodId),
        String(session.mintId),
        ...availabilityBindings,
      );
    const exhaustPredecessorQuotas = this.database
      .prepare(
        `UPDATE authorization_wallet_session_quotas
            SET remaining_uses = 0,
                lifecycle_kind = 'exhausted'
          WHERE namespace = ?
            AND tenant_id = ?
            AND quota_id IN (
              SELECT predecessor.quota_id
                FROM wallet_session_authorizations_v2 AS predecessor
               WHERE predecessor.namespace = ?
                 AND predecessor.org_id = ?
                 AND predecessor.project_id = ?
                 AND predecessor.env_id = ?
                 AND predecessor.tenant_id = ?
                 AND predecessor.wallet_id = ?
                 AND predecessor.authority_id = ?
                 AND predecessor.wallet_auth_method_id = ?
                 AND predecessor.mint_id != ?
                 AND predecessor.retired_at_ms IS NULL
            )
            AND ${availabilitySql}`,
      )
      .bind(
        this.namespace,
        session.tenantId,
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        session.tenantId,
        String(session.walletId),
        String(session.authorityId),
        String(session.walletAuthMethodId),
        String(session.mintId),
        ...availabilityBindings,
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
         WHERE ${availabilitySql}
           AND ${ACTIVE_V2_AUTHORITY_METHOD_EXISTS_SQL}`,
      )
      .bind(
        this.namespace,
        quota.tenantId,
        String(quota.quotaId),
        String(quota.walletSessionId),
        String(quota.principalId),
        requirePositiveInteger(quota.remainingUses, 'Direct V2 quota.remainingUses'),
        requirePositiveInteger(quota.expiresAtMs, 'Direct V2 quota.expiresAtMs'),
        ...availabilityBindings,
        ...activeV2AuthorityMethodBindings(this.walletSignerScope, session),
      );
    const sessionStatement = this.database
      .prepare(
        `INSERT OR IGNORE INTO wallet_session_authorizations_v2 (
          namespace,
          org_id,
          project_id,
          env_id,
          tenant_id,
          authorization_id,
          mint_id,
          wallet_session_id,
          quota_id,
          principal_id,
          wallet_id,
          authority_id,
          wallet_auth_method_id,
          authority_digest_b64u,
          authority_revocation_epoch,
          capability_subjects_json,
          issued_at_ms,
          expires_at_ms,
          retired_at_ms,
          record_json,
          operation_credential_hash,
          wallet_session_client_capability,
          response_family
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?
         WHERE ${sessionIdentityAvailabilitySql}
           AND ${ACTIVE_V2_AUTHORITY_METHOD_EXISTS_SQL}
           AND EXISTS (
             SELECT 1
               FROM authorization_wallet_session_quotas AS quota
              WHERE quota.namespace = ?
                AND quota.tenant_id = ?
                AND quota.quota_id = ?
                AND quota.wallet_session_id = ?
                AND quota.principal_id = ?
                AND quota.remaining_uses = ?
                AND quota.lifecycle_kind = 'active'
                AND quota.expires_at_ms = ?
           )`,
      )
      .bind(
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        session.tenantId,
        String(session.authorizationId),
        String(session.mintId),
        String(session.walletSessionId),
        String(session.quotaId),
        String(session.principalId),
        String(session.walletId),
        String(session.authorityId),
        String(session.walletAuthMethodId),
        String(session.authorityDigestB64u),
        session.authorityRevocationEpoch,
        capabilitySubjectsJson,
        requirePositiveInteger(session.createdAtMs, 'Direct V2 session.createdAtMs'),
        requirePositiveInteger(session.expiresAtMs, 'Direct V2 session.expiresAtMs'),
        recordJson,
        String(primaryOperationCredentialDigestB64u),
        String(walletSessionClientCapability),
        responseFamily,
        ...sessionIdentityAvailabilityBindings,
        ...activeV2AuthorityMethodBindings(this.walletSignerScope, session),
        this.namespace,
        quota.tenantId,
        String(quota.quotaId),
        String(quota.walletSessionId),
        String(quota.principalId),
        requirePositiveInteger(quota.remainingUses, 'Direct V2 quota.remainingUses'),
        requirePositiveInteger(quota.expiresAtMs, 'Direct V2 quota.expiresAtMs'),
      );
    return [exhaustPredecessorQuotas, retirePredecessorSessions, quotaStatement, sessionStatement];
  }

  async replaceWalletSessionAuthorizationV2AuthorityProjection(input: {
    readonly session: WalletSessionAuthorizationV2;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void> {
    requireExactWalletSessionAuthorizationV2Quota(input);
    const capabilitySubjectsJson = JSON.stringify(input.session.capabilitySubjects);
    const recordJson = JSON.stringify(input.session);
    const result = await this.database
      .prepare(
        `UPDATE wallet_session_authorizations_v2
            SET authority_digest_b64u = ?,
                capability_subjects_json = ?,
                record_json = ?
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND tenant_id = ?
            AND authorization_id = ?
            AND mint_id = ?
            AND wallet_session_id = ?
            AND quota_id = ?
            AND principal_id = ?
            AND wallet_id = ?
            AND authority_id = ?
            AND wallet_auth_method_id = ?
            AND authority_revocation_epoch = ?
            AND issued_at_ms = ?
            AND expires_at_ms = ?
            AND retired_at_ms IS NULL
            AND ${ACTIVE_V2_AUTHORITY_METHOD_EXISTS_SQL}
            AND EXISTS (
              SELECT 1
                FROM authorization_wallet_session_quotas AS quota
               WHERE quota.namespace = ?
                 AND quota.tenant_id = ?
                 AND quota.quota_id = ?
                 AND quota.wallet_session_id = ?
                 AND quota.principal_id = ?
                 AND quota.remaining_uses = ?
                 AND quota.lifecycle_kind = 'active'
                 AND quota.expires_at_ms = ?
            )`,
      )
      .bind(
        String(input.session.authorityDigestB64u),
        capabilitySubjectsJson,
        recordJson,
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.session.tenantId,
        String(input.session.authorizationId),
        String(input.session.mintId),
        String(input.session.walletSessionId),
        String(input.session.quotaId),
        String(input.session.principalId),
        String(input.session.walletId),
        String(input.session.authorityId),
        String(input.session.walletAuthMethodId),
        input.session.authorityRevocationEpoch,
        requirePositiveInteger(input.session.createdAtMs, 'V2 session.createdAtMs'),
        requirePositiveInteger(input.session.expiresAtMs, 'V2 session.expiresAtMs'),
        ...activeV2AuthorityMethodBindings(this.walletSignerScope, input.session),
        this.namespace,
        input.quota.tenantId,
        String(input.quota.quotaId),
        String(input.quota.walletSessionId),
        String(input.quota.principalId),
        requirePositiveInteger(input.quota.remainingUses, 'V2 quota.remainingUses'),
        requirePositiveInteger(input.quota.expiresAtMs, 'V2 quota.expiresAtMs'),
      )
      .run();
    if (d1ChangedRows(result) > 1) {
      throw new Error('V2 Wallet Session authority projection changed more than one row');
    }
    const persisted = await this.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: input.session,
      nowMs: input.session.createdAtMs,
    });
    if (!persisted || persisted.quota.remainingUses !== input.quota.remainingUses) {
      throw new Error('V2 Wallet Session authority projection was not replaced');
    }
  }

  async putWalletSessionAuthorizationV2OperationCredential(input: {
    readonly session: WalletSessionAuthorizationV2;
    readonly tokenHash: import('@shared/utils/canonicalPrimitives').DigestB64u;
  }): Promise<void> {
    const result = await this.database
      .prepare(
        `UPDATE wallet_session_authorizations_v2
            SET operation_credential_hash = ?
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND tenant_id = ?
            AND authorization_id = ?
            AND mint_id = ?
            AND wallet_session_id = ?
            AND quota_id = ?
            AND principal_id = ?
            AND wallet_id = ?
            AND authority_id = ?
            AND wallet_auth_method_id = ?
            AND authority_digest_b64u = ?
            AND authority_revocation_epoch = ?
            AND issued_at_ms = ?
            AND expires_at_ms = ?
            AND retired_at_ms IS NULL`,
      )
      .bind(
        input.tokenHash,
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.session.tenantId,
        String(input.session.authorizationId),
        String(input.session.mintId),
        String(input.session.walletSessionId),
        String(input.session.quotaId),
        String(input.session.principalId),
        String(input.session.walletId),
        String(input.session.authorityId),
        String(input.session.walletAuthMethodId),
        String(input.session.authorityDigestB64u),
        input.session.authorityRevocationEpoch,
        requirePositiveInteger(input.session.createdAtMs, 'V2 session.createdAtMs'),
        requirePositiveInteger(input.session.expiresAtMs, 'V2 session.expiresAtMs'),
      )
      .run();
    if (d1ChangedRows(result) !== 1) {
      throw new Error('V2 Wallet Session operation credential binding was not persisted');
    }
  }

  private async existingWalletSessionAuthorizationV2QuotaMatches(
    quota: ActiveWalletSessionQuota,
  ): Promise<boolean> {
    const row = await this.database
      .prepare(
        `SELECT
           tenant_id,
           principal_id,
           wallet_session_id,
           quota_id,
           remaining_uses,
           lifecycle_kind,
           expires_at_ms
         FROM authorization_wallet_session_quotas
        WHERE namespace = ?
          AND tenant_id = ?
          AND quota_id = ?
        LIMIT 1`,
      )
      .bind(this.namespace, quota.tenantId, String(quota.quotaId))
      .first<D1Row>();
    return (
      row !== null &&
      row.tenant_id === String(quota.tenantId) &&
      row.principal_id === String(quota.principalId) &&
      row.wallet_session_id === String(quota.walletSessionId) &&
      row.quota_id === String(quota.quotaId) &&
      row.lifecycle_kind === 'active' &&
      integerColumn(row.remaining_uses, 'V2 quota.remainingUses') === quota.remainingUses &&
      integerColumn(row.expires_at_ms, 'V2 quota.expiresAtMs') === quota.expiresAtMs
    );
  }

  /**
   * Builds the two statements used to persist one V2 Wallet Session. Callers
   * that activate an authority may append these statements to that CAS batch
   * so an active authority is never visible without its durable session.
   */
  prepareWalletSessionAuthorizationV2Statements(input: {
    readonly session: WalletSessionAuthorizationV2;
    readonly quota: ActiveWalletSessionQuota;
  }): readonly [D1PreparedStatementLike, D1PreparedStatementLike] {
    requireExactWalletSessionAuthorizationV2Quota(input);
    const capabilitySubjectsJson = JSON.stringify(input.session.capabilitySubjects);
    const recordJson = JSON.stringify(input.session);
    if (!capabilitySubjectsJson || !recordJson) {
      throw new Error('V2 Wallet Session authorization serialization is required');
    }
    const identityAvailabilitySql = `
      NOT EXISTS (
        SELECT 1
          FROM wallet_session_authorizations_v2 AS existing
         WHERE existing.namespace = ?
           AND existing.org_id = ?
           AND existing.project_id = ?
           AND existing.env_id = ?
           AND existing.tenant_id = ?
           AND (
             existing.authorization_id = ?
             OR existing.mint_id = ?
             OR existing.wallet_session_id = ?
             OR existing.quota_id = ?
           )
      )`;
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
         WHERE ${identityAvailabilitySql}
           AND ${ACTIVE_V2_AUTHORITY_METHOD_EXISTS_SQL}`,
      )
      .bind(
        this.namespace,
        input.quota.tenantId,
        String(input.quota.quotaId),
        String(input.quota.walletSessionId),
        String(input.quota.principalId),
        requirePositiveInteger(input.quota.remainingUses, 'V2 quota.remainingUses'),
        requirePositiveInteger(input.quota.expiresAtMs, 'V2 quota.expiresAtMs'),
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.session.tenantId,
        String(input.session.authorizationId),
        String(input.session.mintId),
        String(input.session.walletSessionId),
        String(input.session.quotaId),
        ...activeV2AuthorityMethodBindings(this.walletSignerScope, input.session),
      );
    const sessionStatement = this.database
      .prepare(
        `INSERT OR IGNORE INTO wallet_session_authorizations_v2 (
          namespace,
          org_id,
          project_id,
          env_id,
          tenant_id,
          authorization_id,
          mint_id,
          wallet_session_id,
          quota_id,
          principal_id,
          wallet_id,
          authority_id,
          wallet_auth_method_id,
          authority_digest_b64u,
          authority_revocation_epoch,
          capability_subjects_json,
          issued_at_ms,
          expires_at_ms,
          retired_at_ms,
          record_json
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?
         WHERE ${identityAvailabilitySql}
           AND ${ACTIVE_V2_AUTHORITY_METHOD_EXISTS_SQL}
           AND EXISTS (
             SELECT 1
               FROM authorization_wallet_session_quotas AS quota
              WHERE quota.namespace = ?
                AND quota.tenant_id = ?
                AND quota.quota_id = ?
                AND quota.wallet_session_id = ?
                AND quota.principal_id = ?
                AND quota.remaining_uses = ?
                AND quota.lifecycle_kind = 'active'
                AND quota.expires_at_ms = ?
           )`,
      )
      .bind(
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.session.tenantId,
        String(input.session.authorizationId),
        String(input.session.mintId),
        String(input.session.walletSessionId),
        String(input.session.quotaId),
        String(input.session.principalId),
        String(input.session.walletId),
        String(input.session.authorityId),
        String(input.session.walletAuthMethodId),
        String(input.session.authorityDigestB64u),
        input.session.authorityRevocationEpoch,
        capabilitySubjectsJson,
        requirePositiveInteger(input.session.createdAtMs, 'V2 session.createdAtMs'),
        requirePositiveInteger(input.session.expiresAtMs, 'V2 session.expiresAtMs'),
        recordJson,
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.session.tenantId,
        String(input.session.authorizationId),
        String(input.session.mintId),
        String(input.session.walletSessionId),
        String(input.session.quotaId),
        ...activeV2AuthorityMethodBindings(this.walletSignerScope, input.session),
        this.namespace,
        input.quota.tenantId,
        String(input.quota.quotaId),
        String(input.quota.walletSessionId),
        String(input.quota.principalId),
        requirePositiveInteger(input.quota.remainingUses, 'V2 quota.remainingUses'),
        requirePositiveInteger(input.quota.expiresAtMs, 'V2 quota.expiresAtMs'),
      );
    return [quotaStatement, sessionStatement];
  }

  async readWalletSessionAuthorizationV2ByMint(
    input: WalletSessionAuthorizationV2MintLookup,
  ): Promise<WalletSessionAuthorizationV2MintRead | null> {
    const row = await this.database
      .prepare(
        `SELECT
           record_json,
           capability_subjects_json,
           tenant_id,
           authorization_id,
           mint_id,
           wallet_session_id,
           quota_id,
           principal_id,
           wallet_id,
           authority_id,
           wallet_auth_method_id,
           authority_digest_b64u,
           authority_revocation_epoch,
           issued_at_ms,
           expires_at_ms,
           retired_at_ms,
           operation_credential_hash,
           wallet_session_client_capability,
           response_family
         FROM wallet_session_authorizations_v2
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND tenant_id = ?
          AND principal_id = ?
          AND wallet_id = ?
          AND authority_id = ?
          AND wallet_auth_method_id = ?
          AND mint_id = ?
        LIMIT 1`,
      )
      .bind(
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.tenantId,
        String(input.principalId),
        String(input.walletId),
        String(input.authorityId),
        String(input.walletAuthMethodId),
        String(input.mintId),
      )
      .first<D1Row>();
    if (!row) return null;
    const session = parseWalletSessionAuthorizationV2(parseD1JsonColumn(row.record_json));
    if (
      !walletSessionAuthorizationV2RowMatches(
        {
          session_tenant_id: row.tenant_id,
          session_authorization_id: row.authorization_id,
          session_mint_id: row.mint_id,
          session_wallet_session_id: row.wallet_session_id,
          session_quota_id: row.quota_id,
          session_principal_id: row.principal_id,
          session_wallet_id: row.wallet_id,
          session_authority_id: row.authority_id,
          session_wallet_auth_method_id: row.wallet_auth_method_id,
          session_authority_digest_b64u: row.authority_digest_b64u,
          session_authority_revocation_epoch: row.authority_revocation_epoch,
          session_issued_at_ms: row.issued_at_ms,
          session_expires_at_ms: row.expires_at_ms,
        },
        session,
      )
    ) {
      throw new Error('Stored V2 Wallet Session mint columns disagree with record');
    }
    const subjectsRecord = parseWalletSessionAuthorizationV2WithSubjects(
      {
        session_tenant_id: row.tenant_id,
        session_authorization_id: row.authorization_id,
        session_mint_id: row.mint_id,
        session_wallet_session_id: row.wallet_session_id,
        session_quota_id: row.quota_id,
        session_principal_id: row.principal_id,
        session_wallet_id: row.wallet_id,
        session_authority_id: row.authority_id,
        session_wallet_auth_method_id: row.wallet_auth_method_id,
        session_authority_digest_b64u: row.authority_digest_b64u,
        session_authority_revocation_epoch: row.authority_revocation_epoch,
        session_issued_at_ms: row.issued_at_ms,
        session_expires_at_ms: row.expires_at_ms,
      },
      parseD1JsonColumn(row.capability_subjects_json),
    );
    if (!walletSessionAuthorizationV2RecordsEqual(subjectsRecord, session)) {
      throw new Error('Stored V2 Wallet Session mint subjects disagree with record');
    }
    if (
      session.tenantId !== input.tenantId ||
      session.principalId !== input.principalId ||
      session.walletId !== input.walletId ||
      session.authorityId !== input.authorityId ||
      session.walletAuthMethodId !== input.walletAuthMethodId ||
      session.mintId !== input.mintId
    ) {
      throw new Error('Stored V2 Wallet Session mint identity does not match the request');
    }
    const primaryOperationCredentialDigestB64u = parseDigestB64u(row.operation_credential_hash);
    const parsedWalletSessionClientCapability = parseWalletSessionClientCapabilityV1(
      row.wallet_session_client_capability,
    );
    const walletSessionClientCapability = parsedWalletSessionClientCapability.ok
      ? parsedWalletSessionClientCapability.value
      : null;
    const responseFamily =
      typeof row.response_family === 'string' ? row.response_family : null;
    const retiredAtMs =
      row.retired_at_ms === null || row.retired_at_ms === undefined
        ? null
        : requirePositiveInteger(row.retired_at_ms, 'V2 session.retiredAtMs');
    return {
      kind: 'committed',
      session,
      primaryOperationCredentialDigestB64u,
      walletSessionClientCapability,
      responseFamily,
      retiredAtMs,
    };
  }

  async readWalletSessionAuthorizationV2ByAuthorizationId(input: {
    readonly expected: WalletSessionAuthorizationV2;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.readWalletSessionAuthorizationV2(input, 'authorization_id');
  }

  async readWalletSessionAuthorizationV2ByIdentity(input: {
    readonly tenantId: WalletSessionAuthorizationV2['tenantId'];
    readonly walletId: WalletSessionAuthorizationV2['walletId'];
    readonly walletSessionId: WalletSessionAuthorizationV2['walletSessionId'];
    readonly authorizationId: WalletSessionAuthorizationV2['authorizationId'];
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.readWalletSessionAuthorizationV2(
      {
        identity: {
          tenantId: input.tenantId,
          walletId: input.walletId,
          walletSessionId: input.walletSessionId,
          authorizationId: input.authorizationId,
        },
        nowMs: input.nowMs,
      },
      'authorization_id',
    );
  }

  async readActiveWalletSessionAuthorizationV2ByIdentity(input: {
    readonly tenantId: WalletSessionAuthorizationV2['tenantId'];
    readonly walletId: WalletSessionAuthorizationV2['walletId'];
    readonly walletSessionId: WalletSessionAuthorizationV2['walletSessionId'];
    readonly authorizationId: WalletSessionAuthorizationV2['authorizationId'];
    readonly nowMs: number;
  }): Promise<WalletSessionAuthorizationV2 | null> {
    const row = await this.database
      .prepare(
        `SELECT record_json, retired_at_ms
           FROM wallet_session_authorizations_v2
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND tenant_id = ?
            AND wallet_id = ?
            AND wallet_session_id = ?
            AND authorization_id = ?
          LIMIT 1`,
      )
      .bind(
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.tenantId,
        input.walletId,
        input.walletSessionId,
        input.authorizationId,
      )
      .first<D1Row>();
    if (!row) return null;
    if (row.retired_at_ms !== null && row.retired_at_ms !== undefined) return null;
    const session = parseWalletSessionAuthorizationV2(parseD1JsonColumn(row.record_json));
    if (
      session.tenantId !== input.tenantId ||
      session.walletId !== input.walletId ||
      session.walletSessionId !== input.walletSessionId ||
      session.authorizationId !== input.authorizationId
    ) {
      throw new Error('Stored V2 Wallet Session identity does not match the request');
    }
    const nowMs = requirePositiveInteger(input.nowMs, 'V2 authorization read time');
    return session.expiresAtMs > nowMs ? session : null;
  }

  async readWalletSessionAuthorizationV2ByOperationCredential(input: {
    readonly tenantId: WalletSessionAuthorizationV2['tenantId'];
    readonly tokenHash: import('@shared/utils/canonicalPrimitives').DigestB64u;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.readWalletSessionAuthorizationV2(
      {
        operationCredentialHash: input.tokenHash,
        tenantId: input.tenantId,
        nowMs: input.nowMs,
      },
      'operation_credential_hash',
    );
  }

  private async readWalletSessionAuthorizationV2(
    input:
      | {
          readonly expected: WalletSessionAuthorizationV2;
          readonly nowMs: number;
        }
      | {
          readonly identity: {
            readonly tenantId: WalletSessionAuthorizationV2['tenantId'];
            readonly walletId: WalletSessionAuthorizationV2['walletId'];
            readonly walletSessionId: WalletSessionAuthorizationV2['walletSessionId'];
            readonly authorizationId: WalletSessionAuthorizationV2['authorizationId'];
          };
          readonly nowMs: number;
        }
      | {
          readonly operationCredentialHash: import('@shared/utils/canonicalPrimitives').DigestB64u;
          readonly tenantId: WalletSessionAuthorizationV2['tenantId'];
          readonly nowMs: number;
        },
    lookupColumn: 'mint_id' | 'authorization_id' | 'operation_credential_hash',
  ): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    const lookup =
      'expected' in input ? input.expected : 'identity' in input ? input.identity : null;
    const operationCredentialHash =
      'operationCredentialHash' in input ? input.operationCredentialHash : null;
    const row = await this.database
      .prepare(
        `SELECT
           session.record_json AS session_record_json,
           session.capability_subjects_json AS session_capability_subjects_json,
           session.tenant_id AS session_tenant_id,
           session.authorization_id AS session_authorization_id,
           session.mint_id AS session_mint_id,
           session.wallet_session_id AS session_wallet_session_id,
           session.quota_id AS session_quota_id,
           session.principal_id AS session_principal_id,
           session.wallet_id AS session_wallet_id,
           session.authority_id AS session_authority_id,
           session.wallet_auth_method_id AS session_wallet_auth_method_id,
           session.authority_digest_b64u AS session_authority_digest_b64u,
           session.authority_revocation_epoch AS session_authority_revocation_epoch,
           session.issued_at_ms AS session_issued_at_ms,
           session.expires_at_ms AS session_expires_at_ms,
           session.retired_at_ms AS session_retired_at_ms,
           authority.authority_id AS authority_id,
           authority.wallet_id AS authority_wallet_id,
           authority.lifecycle_state AS authority_lifecycle_state,
           authority.authority_digest_b64u AS authority_digest_b64u,
           authority.revocation_epoch AS authority_revocation_epoch,
           auth_method.wallet_auth_method_id AS auth_method_id,
           auth_method.wallet_id AS auth_method_wallet_id,
           auth_method.wallet_authority_id AS auth_method_authority_id,
           auth_method.status AS auth_method_status,
           quota.tenant_id AS quota_tenant_id,
           quota.principal_id AS quota_principal_id,
           quota.wallet_session_id AS quota_wallet_session_id,
           quota.quota_id AS quota_id,
           quota.remaining_uses AS quota_remaining_uses,
           quota.lifecycle_kind AS quota_lifecycle_kind,
           quota.expires_at_ms AS quota_expires_at_ms
         FROM wallet_session_authorizations_v2 AS session
         LEFT JOIN wallet_authorities AS authority
           ON authority.namespace = session.namespace
          AND authority.org_id = ?
          AND authority.project_id = ?
          AND authority.env_id = ?
          AND authority.authority_id = session.authority_id
          AND authority.wallet_id = session.wallet_id
         LEFT JOIN wallet_auth_methods AS auth_method
           ON auth_method.namespace = session.namespace
          AND auth_method.org_id = ?
          AND auth_method.project_id = ?
          AND auth_method.env_id = ?
          AND auth_method.wallet_auth_method_id = session.wallet_auth_method_id
          AND auth_method.wallet_id = session.wallet_id
          AND auth_method.wallet_authority_id = session.authority_id
         LEFT JOIN authorization_wallet_session_quotas AS quota
           ON quota.namespace = session.namespace
          AND quota.tenant_id = session.tenant_id
          AND quota.quota_id = session.quota_id
        WHERE session.namespace = ?
          AND session.org_id = ?
          AND session.project_id = ?
          AND session.env_id = ?
          AND session.tenant_id = ?
          AND session.${lookupColumn} = ?
        LIMIT 1`,
      )
      .bind(
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        this.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        'operationCredentialHash' in input ? input.tenantId : lookup?.tenantId,
        lookupColumn === 'mint_id'
          ? String('expected' in input ? input.expected.mintId : lookup?.authorizationId)
          : lookupColumn === 'authorization_id'
            ? String(lookup?.authorizationId)
            : operationCredentialHash,
      )
      .first<D1Row>();
    if (!row) return null;
    if (row.session_retired_at_ms !== null && row.session_retired_at_ms !== undefined) {
      throw new Error('Stored V2 Wallet Session authorization is retired');
    }
    const session = parseWalletSessionAuthorizationV2(parseD1JsonColumn(row.session_record_json));
    if (!walletSessionAuthorizationV2RowMatches(row, session)) {
      throw new Error('Stored V2 Wallet Session authorization columns disagree with record');
    }
    const subjectsRecord = parseWalletSessionAuthorizationV2WithSubjects(
      row,
      parseD1JsonColumn(row.session_capability_subjects_json),
    );
    if (!walletSessionAuthorizationV2RecordsEqual(subjectsRecord, session)) {
      throw new Error('Stored V2 Wallet Session capability subjects disagree with record');
    }
    if (
      row.authority_id !== String(session.authorityId) ||
      row.authority_wallet_id !== String(session.walletId) ||
      row.authority_lifecycle_state !== 'active' ||
      row.authority_digest_b64u !== String(session.authorityDigestB64u) ||
      integerColumn(row.authority_revocation_epoch, 'authority.revocationEpoch') !==
        session.authorityRevocationEpoch ||
      row.auth_method_id !== String(session.walletAuthMethodId) ||
      row.auth_method_wallet_id !== String(session.walletId) ||
      row.auth_method_authority_id !== String(session.authorityId) ||
      row.auth_method_status !== 'active'
    ) {
      throw new Error('Stored V2 Wallet Session authority provenance is no longer active');
    }
    if (
      'identity' in input &&
      (session.walletId !== input.identity.walletId ||
        session.walletSessionId !== input.identity.walletSessionId ||
        session.authorizationId !== input.identity.authorizationId)
    ) {
      throw new Error('Stored V2 Wallet Session identity does not match the request');
    }
    if ('expected' in input && !walletSessionAuthorizationV2RecordsEqual(session, input.expected)) {
      throw new Error('Stored V2 Wallet Session authorization replay does not match');
    }
    const nowMs = requirePositiveInteger(input.nowMs, 'V2 authorization read time');
    if (session.expiresAtMs <= nowMs) {
      throw new Error('Stored V2 Wallet Session authorization has expired');
    }
    const quota = parseWalletSessionAuthorizationV2QuotaRow(row, session);
    return { session, quota };
  }

  async putOpaqueWalletSessionToken(input: {
    readonly tokenHash: import('@shared/utils/canonicalPrimitives').DigestB64u;
    readonly curve: OpaqueWalletSessionCurve;
    readonly binding: OpaqueOwnerWalletSessionBinding;
    readonly tenantId: TenantId;
    readonly walletSessionId: import('@shared/authorization/capabilityKinds').WalletSessionId;
  }): Promise<void> {
    const bindingJson = JSON.stringify(input.binding);
    const binding = parseOpaqueOwnerWalletSessionBinding(input.binding);
    if (
      !bindingJson ||
      !binding ||
      binding.curve !== input.curve ||
      binding.walletSessionId !== input.walletSessionId
    ) {
      throw new Error('opaque Wallet Session binding is invalid');
    }
    const result = await this.database
      .prepare(
        `INSERT INTO opaque_wallet_session_tokens (
          namespace,
          tenant_id,
          token_hash,
          curve,
          wallet_session_id,
          binding_json
        )
        SELECT ?, ?, ?, ?, ?, ?
          FROM reusable_wallet_sessions AS session
         WHERE session.namespace = ?
           AND session.tenant_id = ?
           AND session.wallet_session_id = ?
           AND session.lifecycle_kind = 'active'`,
      )
      .bind(
        this.namespace,
        input.tenantId,
        input.tokenHash,
        input.curve,
        input.walletSessionId,
        bindingJson,
        this.namespace,
        input.tenantId,
        input.walletSessionId,
      )
      .run();
    requireOneChangedRow(result, 'opaque Wallet Session token');
  }

  async putRegistrationReplayOpaqueWalletSessionToken(
    input: Parameters<AuthorizationGrantPort['putRegistrationReplayOpaqueWalletSessionToken']>[0],
  ): Promise<void> {
    const bindingJson = JSON.stringify(input.binding);
    const binding = parseOpaqueOwnerWalletSessionBinding(input.binding);
    const authorityRef =
      binding?.curve === 'ecdsa'
        ? binding.walletAuthAuthorityRef
        : binding?.curve === 'ed25519'
          ? await walletAuthAuthorityRef({ authority: binding.authority })
          : null;
    const issuedAtMs = requirePositiveInteger(input.issuedAtMs, 'registration replay issuedAtMs');
    const sessionExpiresAtMs = requirePositiveInteger(
      input.sessionExpiresAtMs,
      'registration replay sessionExpiresAtMs',
    );
    const tokenExpiresAtMs = requirePositiveInteger(
      input.tokenExpiresAtMs,
      'registration replay tokenExpiresAtMs',
    );
    if (
      !bindingJson ||
      !binding ||
      !authorityRef ||
      binding.curve !== input.curve ||
      binding.authorizationId !== input.authorizationId ||
      binding.walletSessionId !== input.walletSessionId ||
      binding.quotaId !== input.quotaId ||
      binding.walletId !== input.walletId ||
      binding.thresholdExpiresAtMs !== sessionExpiresAtMs ||
      sessionExpiresAtMs <= issuedAtMs ||
      tokenExpiresAtMs <= issuedAtMs ||
      tokenExpiresAtMs > sessionExpiresAtMs
    ) {
      throw new Error('registration replay Wallet Session binding is invalid');
    }
    const insertReplayToken = this.database
      .prepare(
        `INSERT INTO registration_replay_opaque_wallet_session_tokens_v1 (
          namespace,
          tenant_id,
          token_hash,
          curve,
          registration_ceremony_id,
          operation,
          operation_fingerprint,
          authorization_id,
          wallet_session_id,
          quota_id,
          principal_id,
          wallet_id,
          authority_digest,
          wallet_auth_method_id,
          binding_json,
          issued_at_ms,
          session_expires_at_ms,
          token_expires_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          FROM reusable_wallet_sessions AS session
          JOIN authorization_wallet_session_quotas AS quota
            ON quota.namespace = session.namespace
           AND quota.tenant_id = session.tenant_id
           AND quota.quota_id = session.quota_id
         WHERE session.namespace = ?
           AND session.tenant_id = ?
           AND session.wallet_session_id = ?
           AND session.authorization_id = ?
           AND session.quota_id = ?
           AND session.principal_id = ?
           AND session.wallet_id = ?
           AND session.authority_digest = ?
           AND session.wallet_auth_method_id = ?
           AND session.lifecycle_kind = 'active'
           AND session.expires_at_ms = ?
           AND quota.namespace = session.namespace
           AND quota.tenant_id = session.tenant_id
           AND quota.wallet_session_id = session.wallet_session_id
           AND quota.principal_id = session.principal_id
           AND quota.quota_id = session.quota_id
           AND quota.expires_at_ms = ?
           AND quota.lifecycle_kind = 'active'
           AND quota.remaining_uses > 0`,
      )
      .bind(
        this.namespace,
        input.tenantId,
        input.tokenHash,
        input.curve,
        input.registrationCeremonyId,
        input.operation,
        input.operationFingerprint,
        input.authorizationId,
        input.walletSessionId,
        input.quotaId,
        input.principalId,
        input.walletId,
        authorityRef.authorityDigest,
        authorityRef.walletAuthMethodId,
        bindingJson,
        issuedAtMs,
        sessionExpiresAtMs,
        tokenExpiresAtMs,
        this.namespace,
        input.tenantId,
        input.walletSessionId,
        input.authorizationId,
        input.quotaId,
        input.principalId,
        input.walletId,
        authorityRef.authorityDigest,
        authorityRef.walletAuthMethodId,
        sessionExpiresAtMs,
        sessionExpiresAtMs,
      );
    const pruneExpired = this.database
      .prepare(
        `DELETE FROM registration_replay_opaque_wallet_session_tokens_v1
          WHERE namespace = ?
            AND tenant_id = ?
            AND token_expires_at_ms <= ?`,
      )
      .bind(this.namespace, input.tenantId, issuedAtMs);
    const results = await this.database.batch([pruneExpired, insertReplayToken]);
    requireOneChangedRow(
      results[1] as D1ResultLike,
      'registration replay opaque Wallet Session token',
    );
  }

  async readOpaqueWalletSessionToken(input: {
    readonly tenantId: TenantId;
    readonly tokenHash: import('@shared/utils/canonicalPrimitives').DigestB64u;
    readonly curve: OpaqueWalletSessionCurve;
    readonly nowMs: number;
  }): Promise<ResolvedOpaqueWalletSessionToken | null> {
    const row = await this.database
      .prepare(
        `SELECT
           token.curve AS token_curve,
           token.binding_json AS token_binding_json,
           session.tenant_id AS session_tenant_id,
           session.principal_id AS session_principal_id,
           session.wallet_id AS session_wallet_id,
           session.authority_digest AS session_authority_digest,
           session.wallet_auth_method_id AS session_wallet_auth_method_id,
           session.authorization_id AS session_authorization_id,
           session.wallet_session_id AS session_wallet_session_id,
           session.quota_id AS session_quota_id,
           session.lifecycle_kind AS session_lifecycle_kind,
           session.expires_at_ms AS session_expires_at_ms,
           quota.tenant_id AS quota_tenant_id,
           quota.principal_id AS quota_principal_id,
           quota.wallet_session_id AS quota_wallet_session_id,
           quota.quota_id AS quota_quota_id,
           quota.remaining_uses AS quota_remaining_uses,
           quota.lifecycle_kind AS quota_lifecycle_kind,
           quota.expires_at_ms AS quota_expires_at_ms,
           token.token_expires_at_ms AS token_expires_at_ms,
           token.token_authority_digest AS token_authority_digest,
           token.token_wallet_auth_method_id AS token_wallet_auth_method_id
         FROM (
           SELECT namespace, tenant_id, token_hash, curve, wallet_session_id, binding_json,
                  NULL AS token_expires_at_ms,
                  NULL AS token_authority_digest,
                  NULL AS token_wallet_auth_method_id
             FROM opaque_wallet_session_tokens
           UNION ALL
           SELECT namespace, tenant_id, token_hash, curve, wallet_session_id, binding_json,
                  token_expires_at_ms,
                  authority_digest AS token_authority_digest,
                  wallet_auth_method_id AS token_wallet_auth_method_id
             FROM registration_replay_opaque_wallet_session_tokens_v1
         ) AS token
         JOIN reusable_wallet_sessions AS session
           ON session.namespace = token.namespace
          AND session.tenant_id = token.tenant_id
          AND session.wallet_session_id = token.wallet_session_id
         JOIN authorization_wallet_session_quotas AS quota
           ON quota.namespace = session.namespace
          AND quota.tenant_id = session.tenant_id
          AND quota.quota_id = session.quota_id
        WHERE token.namespace = ?
          AND token.tenant_id = ?
          AND token.token_hash = ?
          AND token.curve = ?
        LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.tokenHash, input.curve)
      .first<D1Row>();
    if (!row) return null;

    const nowMs = requirePositiveInteger(input.nowMs, 'opaque token read time');
    const sessionExpiresAtMs = requirePositiveInteger(
      row.session_expires_at_ms,
      'session.expiresAtMs',
    );
    const quotaExpiresAtMs = requirePositiveInteger(row.quota_expires_at_ms, 'quota.expiresAtMs');
    const tokenExpiresAtMs =
      row.token_expires_at_ms === null || row.token_expires_at_ms === undefined
        ? sessionExpiresAtMs
        : requirePositiveInteger(row.token_expires_at_ms, 'token.expiresAtMs');
    if (
      row.token_curve !== input.curve ||
      row.session_lifecycle_kind !== 'active' ||
      tokenExpiresAtMs <= nowMs ||
      sessionExpiresAtMs <= nowMs ||
      quotaExpiresAtMs <= nowMs
    ) {
      return null;
    }

    const tenantId = requireParsed(row.session_tenant_id, parseTenantId, 'session.tenantId');
    const principalId = requireParsed(
      row.session_principal_id,
      parsePrincipalId,
      'session.principalId',
    );
    const walletId = requireParsed(row.session_wallet_id, parseWalletId, 'session.walletId');
    const authorityDigest = requireParsed(
      row.session_authority_digest,
      parseDigestResult,
      'session.authorityDigest',
    );
    const authorizationId = requireParsed(
      row.session_authorization_id,
      parseWalletSessionAuthorizationId,
      'session.authorizationId',
    );
    const walletSessionId = requireParsed(
      row.session_wallet_session_id,
      parseWalletSessionId,
      'session.walletSessionId',
    );
    const quotaId = requireParsed(
      row.session_quota_id,
      parseMpcWalletSigningQuotaId,
      'session.quotaId',
    );
    const quotaTenantId = requireParsed(row.quota_tenant_id, parseTenantId, 'quota.tenantId');
    const quotaPrincipalId = requireParsed(
      row.quota_principal_id,
      parsePrincipalId,
      'quota.principalId',
    );
    const quotaWalletSessionId = requireParsed(
      row.quota_wallet_session_id,
      parseWalletSessionId,
      'quota.walletSessionId',
    );
    const persistedQuotaId = requireParsed(
      row.quota_quota_id,
      parseMpcWalletSigningQuotaId,
      'quota.quotaId',
    );
    const quotaLifecycle = String(row.quota_lifecycle_kind || '');
    const quotaRemainingUses = Number(row.quota_remaining_uses);
    if (
      tenantId !== input.tenantId ||
      quotaTenantId !== tenantId ||
      quotaPrincipalId !== principalId ||
      quotaWalletSessionId !== walletSessionId ||
      persistedQuotaId !== quotaId ||
      quotaExpiresAtMs !== sessionExpiresAtMs ||
      !Number.isSafeInteger(quotaRemainingUses) ||
      quotaRemainingUses < 0 ||
      (quotaLifecycle !== 'active' && quotaLifecycle !== 'exhausted') ||
      (quotaLifecycle === 'active' && quotaRemainingUses === 0) ||
      (quotaLifecycle === 'exhausted' && quotaRemainingUses !== 0)
    ) {
      throw new Error('opaque Wallet Session persisted identity is inconsistent');
    }
    const binding = parseOpaqueOwnerWalletSessionBinding(String(row.token_binding_json || ''));
    if (!binding) throw new Error('opaque Wallet Session binding is invalid');
    if (row.token_authority_digest !== null && row.token_authority_digest !== undefined) {
      const authorityRef =
        binding.curve === 'ecdsa'
          ? binding.walletAuthAuthorityRef
          : await walletAuthAuthorityRef({ authority: binding.authority });
      if (
        String(row.token_authority_digest) !== String(authorityRef.authorityDigest) ||
        String(row.token_wallet_auth_method_id) !== String(authorityRef.walletAuthMethodId) ||
        String(row.token_authority_digest) !== String(row.session_authority_digest) ||
        String(row.token_wallet_auth_method_id) !== String(row.session_wallet_auth_method_id)
      ) {
        throw new Error('registration replay Wallet Session identity is inconsistent');
      }
    }
    return {
      kind: 'resolved_opaque_wallet_session_token',
      curve: input.curve,
      binding,
      authorization: {
        tenantId,
        principalId,
        walletId,
        authorityDigest,
        walletAuthMethodId: storedAuthMethodId(row.session_wallet_auth_method_id),
        authorizationId,
        walletSessionId,
        quotaId,
        expiresAtMs: sessionExpiresAtMs,
      },
    };
  }

  async readOpaqueWalletSessionTokenByIdentity(input: {
    readonly tenantId: TenantId;
    readonly walletSessionId: WalletSessionId;
    readonly curve: OpaqueWalletSessionCurve;
    readonly nowMs: number;
  }): Promise<ResolvedOpaqueWalletSessionToken | null> {
    const replayRow = await this.database
      .prepare(
        `SELECT token_hash
           FROM registration_replay_opaque_wallet_session_tokens_v1
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id = ?
            AND curve = ?
          ORDER BY token_expires_at_ms DESC, issued_at_ms DESC, token_hash DESC
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.walletSessionId, input.curve)
      .first<{ readonly token_hash?: unknown }>();
    if (replayRow) {
      const tokenHash = parseDigestB64u(replayRow.token_hash);
      const resolved = await this.readOpaqueWalletSessionToken({
        tenantId: input.tenantId,
        tokenHash,
        curve: input.curve,
        nowMs: input.nowMs,
      });
      if (resolved) return resolved;
    }
    const row = await this.database
      .prepare(
        `SELECT token_hash
           FROM opaque_wallet_session_tokens
          WHERE namespace = ?
            AND tenant_id = ?
            AND wallet_session_id = ?
            AND curve = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.walletSessionId, input.curve)
      .first<{ readonly token_hash?: unknown }>();
    if (!row) return null;
    const tokenHash = parseDigestB64u(row.token_hash);
    return await this.readOpaqueWalletSessionToken({
      tenantId: input.tenantId,
      tokenHash,
      curve: input.curve,
      nowMs: input.nowMs,
    });
  }

  async readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null> {
    const record = await this.readAuthorizedOperationRecord(input);
    return record?.operation ?? null;
  }

  async readAuthorizedOperationById(input: {
    readonly tenantId: TenantId;
    readonly authorizedOperationId: AuthorizedOperationId;
  }): Promise<AuthorizedOperation | null> {
    const row = await this.database
      .prepare(
        `SELECT * FROM authorized_operations
          WHERE namespace = ? AND tenant_id = ? AND authorized_operation_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.authorizedOperationId)
      .first<D1Row>();
    return row ? await parseAuthorizedOperationRow(row) : null;
  }

  private async readAuthorizedOperationRecord(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperationPersistenceRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT * FROM authorized_operations
          WHERE namespace = ? AND tenant_id = ? AND operation_fingerprint_digest = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.operationFingerprintDigest)
      .first<D1Row>();
    return row
      ? {
          row,
          operation: await parseAuthorizedOperationRow(row),
        }
      : null;
  }

  async admitAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: AuthorizedOperationMaterialScope;
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
    const requiresEcdsaMaterial =
      operation.operation.operation.capabilityKind === CAPABILITY_KINDS.evmEcdsaMpcSigning;
    if (requiresEcdsaMaterial && !input.material) return { kind: 'material_mismatch' };
    if (
      input.material &&
      input.material.kind === 'ecdsa_material_activation' &&
      (operation.operation.operation.capabilityKind !== CAPABILITY_KINDS.evmEcdsaMpcSigning ||
        input.material.runtimePolicyScope.orgId !== operation.tenantId ||
        input.material.materialActivation.capability !== operation.operation.capabilityId ||
        input.material.materialActivation.material_owner !== input.material.walletId)
    ) {
      return { kind: 'material_mismatch' };
    }
    const existing = await this.readAuthorizedOperationRecord({
      tenantId: operation.tenantId,
      operationFingerprintDigest: operation.operationFingerprintDigest,
    });
    if (existing) {
      const replayMismatch = authorizedOperationReplayMismatch({
        existing: existing.row,
        incoming: operation,
        material: input.material,
      });
      if (replayMismatch) return replayMismatch;
      if (existing.operation.lifecycle === 'completed') {
        return { kind: 'replayed', operation: existing.operation };
      }
      if (!(await this.isAuthorizedOperationSourceActive(existing.row, operation.claimedAtMs))) {
        return authorizationSourceRejected(operation.authorization);
      }
      return { kind: 'operation_in_progress', operation: existing.operation };
    }
    const source = operation.authorization;
    const quota = operation.quota;
    const materialActivationId = input.material?.materialActivation.activation_id ?? null;
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
        source.kind === 'authorization_grant' ? source.authorizationGrantRef.kind : null,
        requirePositiveInteger(input.operation.claimedAtMs, 'operation.claimedAtMs'),
        materialActivationId,
        input.material?.materialActivation.capability ?? null,
        input.material?.materialActivation.material_owner ?? null,
        input.material?.materialActivation.key_binding ?? null,
        input.material?.materialActivation.lifecycle_binding ?? null,
        input.material?.materialActivation.signing_worker ?? null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        source.kind === 'authorization_grant' ? this.walletSignerScope.orgId : null,
        source.kind === 'authorization_grant' ? this.walletSignerScope.projectId : null,
        source.kind === 'authorization_grant' ? this.walletSignerScope.envId : null,
      ] as const;
      const statement =
        input.material?.kind === 'ecdsa_material_activation'
          ? this.database
              .prepare(
                `INSERT INTO authorized_operations (
                namespace, tenant_id, authorized_operation_id, audit_event_id,
                principal_id, capability_id, capability_kind, operation_kind, operation_id,
                operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
                authorization_source_kind, authorization_id, evidence_set_digest,
                quota_id, quota_kind, authorization_grant_kind, lifecycle_kind, result_kind,
                result_digest, result_status, result_content_type, result_body_text,
                claimed_at_ms, completed_at_ms,
                material_activation_id, material_activation_capability,
                material_activation_owner, material_activation_key_binding,
                material_activation_lifecycle_binding, material_activation_signing_worker,
                linked_wallet_id, linked_enrollment_id, linked_device_id,
                linked_wallet_key_id, linked_lane_id, linked_lane_share_epoch,
                linked_revocation_epoch, linked_scope_org_id, linked_scope_project_id,
                linked_scope_env_id
              ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'claimed', 'pending', NULL, NULL, NULL, NULL, ?, NULL, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                 WHERE ${ECDSA_SIGNER_MATCH}`,
              )
              .bind(...values, ...ecdsaSignerMatchBindings(this.walletSignerScope, input.material))
          : this.database
              .prepare(
                `INSERT INTO authorized_operations (
                namespace, tenant_id, authorized_operation_id, audit_event_id,
                principal_id, capability_id, capability_kind, operation_kind, operation_id,
                operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
                authorization_source_kind, authorization_id, evidence_set_digest,
                quota_id, quota_kind, authorization_grant_kind, lifecycle_kind, result_kind,
                result_digest, result_status, result_content_type, result_body_text,
                claimed_at_ms, completed_at_ms,
                material_activation_id, material_activation_capability,
                material_activation_owner, material_activation_key_binding,
                material_activation_lifecycle_binding, material_activation_signing_worker,
                linked_wallet_id, linked_enrollment_id, linked_device_id,
                linked_wallet_key_id, linked_lane_id, linked_lane_share_epoch,
                linked_revocation_epoch, linked_scope_org_id, linked_scope_project_id,
                linked_scope_env_id
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'claimed', 'pending', NULL, NULL, NULL, NULL, ?, NULL, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              )
              .bind(...values);
      const result = await statement.run();
      if (input.material && d1ChangedRows(result) === 0) return { kind: 'material_mismatch' };
    } catch (error: unknown) {
      const raced = await this.readAuthorizedOperationRecord({
        tenantId: operation.tenantId,
        operationFingerprintDigest: operation.operationFingerprintDigest,
      });
      if (raced) {
        const replayMismatch = authorizedOperationReplayMismatch({
          existing: raced.row,
          incoming: operation,
          material: input.material,
        });
        if (replayMismatch) return replayMismatch;
        if (raced.operation.lifecycle === 'completed') {
          return { kind: 'replayed', operation: raced.operation };
        }
        if (!(await this.isAuthorizedOperationSourceActive(raced.row, operation.claimedAtMs))) {
          return authorizationSourceRejected(operation.authorization);
        }
        return { kind: 'operation_in_progress', operation: raced.operation };
      }
      const triggerFailure = classifyAuthorizedOperationAdmissionError(error);
      if (triggerFailure) return triggerFailure;
      throw error;
    }
    const committed = await this.readAuthorizedOperationRecord({
      tenantId: operation.tenantId,
      operationFingerprintDigest: operation.operationFingerprintDigest,
    });
    if (!committed) throw new Error('authorized operation admission could not be read back');
    return { kind: 'claimed', operation: committed.operation };
  }

  private async isAuthorizedOperationSourceActive(row: D1Row, nowMs: number): Promise<boolean> {
    const sourceKind = requireString(row.authorization_source_kind, 'operation.authorization.kind');
    if (sourceKind === 'authorization_grant') {
      const scope = [row.linked_scope_org_id, row.linked_scope_project_id, row.linked_scope_env_id];
      if (scope.some((value) => typeof value !== 'string' || value.length === 0)) return false;
      if (
        scope[0] !== this.walletSignerScope.orgId ||
        scope[1] !== this.walletSignerScope.projectId ||
        scope[2] !== this.walletSignerScope.envId
      ) {
        return false;
      }
      const session = await this.database
        .prepare(
          `SELECT 1 AS active
             FROM wallet_session_authorizations_v2 AS session
             JOIN wallet_authorities AS authority
               ON authority.namespace = session.namespace
              AND authority.org_id = session.org_id
              AND authority.project_id = session.project_id
              AND authority.env_id = session.env_id
              AND authority.authority_id = session.authority_id
              AND authority.wallet_id = session.wallet_id
             JOIN wallet_auth_methods AS auth_method
               ON auth_method.namespace = session.namespace
              AND auth_method.org_id = session.org_id
              AND auth_method.project_id = session.project_id
              AND auth_method.env_id = session.env_id
              AND auth_method.wallet_auth_method_id = session.wallet_auth_method_id
              AND auth_method.wallet_id = session.wallet_id
              AND auth_method.wallet_authority_id = session.authority_id
            WHERE session.namespace = ?
              AND session.org_id = ?
              AND session.project_id = ?
              AND session.env_id = ?
              AND session.tenant_id = ?
              AND session.authorization_id = ?
              AND session.principal_id = ?
              AND session.retired_at_ms IS NULL
              AND session.expires_at_ms > ?
              AND authority.lifecycle_state = 'active'
              AND authority.authority_digest_b64u = session.authority_digest_b64u
              AND authority.revocation_epoch = session.authority_revocation_epoch
              AND auth_method.status = 'active'
            LIMIT 1`,
        )
        .bind(
          this.namespace,
          ...scope,
          requireString(row.tenant_id, 'operation.tenantId'),
          requireString(row.authorization_id, 'operation.authorizationId'),
          requireString(row.principal_id, 'operation.principalId'),
          requirePositiveInteger(nowMs, 'operation replay time'),
        )
        .first<D1Row>();
      return session !== null;
    }
    if (sourceKind !== 'verified_step_up') return false;
    const capabilityKind = requireString(row.capability_kind, 'operation.capabilityKind');
    const evidence = await this.database
      .prepare(
        `SELECT 1 AS active
           FROM verified_wallet_operation_evidence_sets AS evidence
          WHERE evidence.namespace = ?
            AND evidence.tenant_id = ?
            AND evidence.evidence_set_digest = ?
            AND evidence.principal_id = ?
            AND evidence.capability_kind = ?
            AND evidence.operation_kind = ?
            AND evidence.lane_digest = ?
            AND evidence.intent_digest = ?
            AND evidence.display_digest = ?
            AND evidence.assurance = 'step_up'
            AND evidence.expires_at_ms > ?
          LIMIT 1`,
      )
      .bind(
        this.namespace,
        requireString(row.tenant_id, 'operation.tenantId'),
        requireString(row.evidence_set_digest, 'operation.evidenceSetDigest'),
        requireString(row.principal_id, 'operation.principalId'),
        capabilityKind,
        requireString(row.operation_kind, 'operation.operationKind'),
        requireString(row.lane_digest, 'operation.laneDigest'),
        requireString(row.intent_digest, 'operation.intentDigest'),
        requireString(row.display_digest, 'operation.displayDigest'),
        requirePositiveInteger(nowMs, 'operation replay time'),
      )
      .first<D1Row>();
    return evidence !== null;
  }

  async completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: CompletedCapabilityOperationResult;
    readonly response: AuthorizedOperationReplayResponse;
    readonly completedAtMs: number;
  }): Promise<AuthorizedOperation> {
    const operation = input.operation;
    const response = parseAuthorizedOperationReplayResponse(input.response);
    const resultDigest = await computeAuthorizedOperationResultDigest(response);
    const update = await this.database
      .prepare(
        `UPDATE authorized_operations
            SET lifecycle_kind = 'completed', result_kind = ?, result_digest = ?,
                result_status = ?, result_content_type = ?, result_body_text = ?,
                completed_at_ms = ?
          WHERE namespace = ? AND tenant_id = ?
            AND authorized_operation_id = ? AND operation_fingerprint_digest = ?
            AND lifecycle_kind = 'claimed'`,
      )
      .bind(
        input.result,
        resultDigest,
        response.status,
        response.contentType,
        response.bodyText,
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

  private async requireExactReusableWalletSessionReplayReadback(input: {
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
    if (!reusableWalletSessionReplayReadbackMatches(session, quota, input)) {
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

type AuthorizedOperationPersistenceRecord = {
  readonly row: D1Row;
  readonly operation: AuthorizedOperation;
};

type AuthorizedOperationReplayMismatch =
  | { readonly kind: 'authorization_grant_rejected' }
  | { readonly kind: 'verified_step_up_rejected' }
  | { readonly kind: 'material_mismatch' };

function classifyAuthorizedOperationAdmissionError(
  error: unknown,
):
  | { readonly kind: 'authorization_grant_rejected' }
  | { readonly kind: 'verified_step_up_rejected' }
  | { readonly kind: 'wallet_session_quota_exhausted' }
  | null {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes('authorization_wallet_session_quota_rejected')) {
    return { kind: 'wallet_session_quota_exhausted' };
  }
  if (message.includes('authorization_wallet_session_rejected')) {
    return { kind: 'authorization_grant_rejected' };
  }
  if (message.includes('authorization_evidence_claim_rejected')) {
    return { kind: 'verified_step_up_rejected' };
  }
  return null;
}

function authorizedOperationReplayMismatch(input: {
  readonly existing: D1Row;
  readonly incoming: AuthorizedOperation;
  readonly material?: AuthorizedOperationMaterialScope;
}): AuthorizedOperationReplayMismatch | null {
  const sourceKind = requireString(
    input.existing.authorization_source_kind,
    'operation.authorization.kind',
  );
  if (sourceKind !== input.incoming.authorization.kind) {
    return authorizationSourceRejected(input.incoming.authorization);
  }
  if (input.incoming.authorization.kind === 'authorization_grant') {
    const expectedGrantKind = input.incoming.authorization.authorizationGrantRef.kind;
    if (input.existing.authorization_grant_kind !== expectedGrantKind) {
      return { kind: 'authorization_grant_rejected' };
    }
    if (
      input.existing.authorization_id !==
      input.incoming.authorization.authorizationGrantRef.authorizationId
    ) {
      return { kind: 'authorization_grant_rejected' };
    }
  } else if (
    input.existing.evidence_set_digest !== input.incoming.authorization.evidenceSetDigest
  ) {
    return { kind: 'verified_step_up_rejected' };
  }

  const existingQuotaKind = requireString(input.existing.quota_kind, 'operation.quota.kind');
  if (existingQuotaKind !== input.incoming.quota.kind) {
    return authorizationSourceRejected(input.incoming.authorization);
  }
  if (
    existingQuotaKind === 'consume_reusable_wallet_session' &&
    input.existing.quota_id !== input.incoming.quota.quotaId
  ) {
    return { kind: 'authorization_grant_rejected' };
  }
  if (existingQuotaKind === 'quota_neutral' && input.existing.quota_id !== null) {
    return { kind: 'authorization_grant_rejected' };
  }

  const existingMaterialActivationId = input.existing.material_activation_id;
  const incomingMaterialActivationId = input.material?.materialActivation.activation_id ?? null;
  if (existingMaterialActivationId !== incomingMaterialActivationId) {
    return { kind: 'material_mismatch' };
  }
  return null;
}

function authorizationSourceRejected(
  source: AuthorizedOperation['authorization'],
): AuthorizedOperationReplayMismatch {
  return source.kind === 'verified_step_up'
    ? { kind: 'verified_step_up_rejected' }
    : { kind: 'authorization_grant_rejected' };
}

function classifyHostedWalletExchange(
  row: HostedWalletExchangeRow | null,
  input: RedeemHostedWalletSeamsSessionExchangeInput,
): PersistedHostedWalletSeamsSessionExchangeResult | null {
  if (!row) return { kind: 'invalid_code' };
  if (row.lifecycle_kind === 'consumed') return { kind: 'already_consumed' };
  if (row.lifecycle_kind !== 'issued') return { kind: 'invalid_code' };
  if (integerColumn(row.expires_at_ms, 'exchange.expiresAtMs') <= input.redeemedAtMs) {
    return { kind: 'expired' };
  }
  if (row.nonce_digest !== input.nonceDigest) return { kind: 'nonce_mismatch' };
  if (row.app_origin !== input.appOrigin) return { kind: 'app_origin_mismatch' };
  if (row.wallet_origin !== input.walletOrigin) return { kind: 'app_origin_mismatch' };
  if (row.curve !== input.curve) return { kind: 'app_origin_mismatch' };
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
    operationId: requireParsed(
      row.operation_id,
      parseCapabilityOperationId,
      'operation.operationId',
    ),
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
    if (row.authorization_grant_kind !== 'wallet_session_authorization') {
      throw new Error('operation.authorization grant kind is invalid');
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
        if (row.quota_id != null)
          throw new Error('operation.quota-neutral row cannot contain quotaId');
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
  const response = parseAuthorizedOperationReplayResponse({
    status: integerColumn(row.result_status, 'operation.response.status'),
    contentType: requiredText(row.result_content_type, 'operation.response.contentType'),
    bodyText: requiredText(row.result_body_text, 'operation.response.bodyText'),
  });
  const resultDigest = parseDigestB64u(requireString(row.result_digest, 'operation.resultDigest'));
  const expectedResultDigest = await computeAuthorizedOperationResultDigest(response);
  if (expectedResultDigest !== resultDigest) {
    throw new Error('operation.resultDigest does not match replay response');
  }
  return {
    ...base,
    lifecycle: 'completed',
    result,
    response,
    resultDigest,
    completedAtMs: requirePositiveInteger(row.completed_at_ms, 'operation.completedAtMs'),
  };
}

function requiredText(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be text`);
  return value;
}

function parseOpaqueBindingJson(value: string, label: string): Readonly<Record<string, unknown>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${label} is invalid JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${label} must be an object`);
  }
  return Object.fromEntries(Object.entries(parsed));
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

function parseDigestResult(
  value: unknown,
): AuthorizationParseResult<import('@shared/utils/canonicalPrimitives').DigestB64u> {
  try {
    return { ok: true, value: parseDigestB64u(value) };
  } catch (error) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: error instanceof Error ? error.message : String(error),
      },
    };
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

function requireNonnegativeInteger(value: unknown, label: string): number {
  const parsed = integerColumn(value, label);
  if (parsed < 0) throw new Error(`${label} must be nonnegative`);
  return parsed;
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

function requireExactWalletSessionAuthorizationV2Quota(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly quota: ActiveWalletSessionQuota;
}): void {
  if (
    input.session.tenantId !== input.quota.tenantId ||
    input.session.principalId !== input.quota.principalId ||
    input.session.walletSessionId !== input.quota.walletSessionId ||
    input.session.quotaId !== input.quota.quotaId ||
    input.session.expiresAtMs !== input.quota.expiresAtMs
  ) {
    throw new Error('V2 Wallet Session authorization and quota must have one exact identity');
  }
}

function requireExactPersistedActiveWalletSessionAuthorizationV2(
  input: PersistedActiveWalletSessionAuthorizationV2,
): void {
  if (input.kind !== 'persisted_active_wallet_session_authorization_v2') {
    throw new Error('Direct V2 Wallet Session aggregate kind is invalid');
  }
  requireExactWalletSessionAuthorizationV2Quota(input);
  parseDigestB64u(input.primaryOperationCredentialDigestB64u);
  const parsedWalletSessionClientCapability = parseWalletSessionClientCapabilityV1(
    input.walletSessionClientCapability,
  );
  if (!parsedWalletSessionClientCapability.ok) {
    throw new Error(
      `Direct V2 Wallet Session client capability is invalid: ${parsedWalletSessionClientCapability.error.message}`,
    );
  }
  if (input.responseFamily.length === 0) {
    throw new Error('Direct V2 Wallet Session response family is required');
  }
  if (input.retiredAtMs !== undefined) {
    throw new Error('Direct V2 Wallet Session aggregate cannot be retired');
  }
}

function directV2IdentityAvailabilitySql(): string {
  return `${directV2SessionIdentityAvailabilitySql()}
      AND NOT EXISTS (
        SELECT 1
          FROM authorization_wallet_session_quotas AS existing_quota
         WHERE existing_quota.namespace = ?
           AND existing_quota.tenant_id = ?
           AND existing_quota.quota_id = ?
      )`;
}

function directV2IdentityAvailabilityBindings(
  namespace: string,
  scope: D1WalletStoreScope,
  session: WalletSessionAuthorizationV2,
): readonly string[] {
  return [
    ...directV2SessionIdentityAvailabilityBindings(namespace, scope, session),
    namespace,
    String(session.tenantId),
    String(session.quotaId),
  ];
}

function directV2SessionIdentityAvailabilitySql(): string {
  return `
      NOT EXISTS (
        SELECT 1
          FROM wallet_session_authorizations_v2 AS existing
         WHERE existing.namespace = ?
           AND existing.org_id = ?
           AND existing.project_id = ?
           AND existing.env_id = ?
           AND existing.tenant_id = ?
           AND (
             existing.authorization_id = ?
             OR existing.mint_id = ?
             OR existing.wallet_session_id = ?
             OR existing.quota_id = ?
           )
      )`;
}

function directV2SessionIdentityAvailabilityBindings(
  namespace: string,
  scope: D1WalletStoreScope,
  session: WalletSessionAuthorizationV2,
): readonly string[] {
  return [
    namespace,
    scope.orgId,
    scope.projectId,
    scope.envId,
    String(session.tenantId),
    String(session.authorizationId),
    String(session.mintId),
    String(session.walletSessionId),
    String(session.quotaId),
  ];
}

function walletSessionAuthorizationV2RowMatches(
  row: D1Row,
  session: WalletSessionAuthorizationV2,
): boolean {
  return (
    row.session_tenant_id === String(session.tenantId) &&
    row.session_authorization_id === String(session.authorizationId) &&
    row.session_mint_id === String(session.mintId) &&
    row.session_wallet_session_id === String(session.walletSessionId) &&
    row.session_quota_id === String(session.quotaId) &&
    row.session_principal_id === String(session.principalId) &&
    row.session_wallet_id === String(session.walletId) &&
    row.session_authority_id === String(session.authorityId) &&
    row.session_wallet_auth_method_id === String(session.walletAuthMethodId) &&
    row.session_authority_digest_b64u === String(session.authorityDigestB64u) &&
    integerColumn(row.session_authority_revocation_epoch, 'session.authorityRevocationEpoch') ===
      session.authorityRevocationEpoch &&
    integerColumn(row.session_issued_at_ms, 'session.createdAtMs') === session.createdAtMs &&
    integerColumn(row.session_expires_at_ms, 'session.expiresAtMs') === session.expiresAtMs
  );
}

function parseWalletSessionAuthorizationV2WithSubjects(
  row: D1Row,
  capabilitySubjects: unknown,
): WalletSessionAuthorizationV2 {
  return parseWalletSessionAuthorizationV2({
    kind: 'wallet_session_authorization_v2',
    tenantId: row.session_tenant_id,
    principalId: row.session_principal_id,
    walletId: row.session_wallet_id,
    authorityId: row.session_authority_id,
    walletAuthMethodId: row.session_wallet_auth_method_id,
    authorityDigestB64u: row.session_authority_digest_b64u,
    authorityRevocationEpoch: row.session_authority_revocation_epoch,
    mintId: row.session_mint_id,
    authorizationId: row.session_authorization_id,
    walletSessionId: row.session_wallet_session_id,
    quotaId: row.session_quota_id,
    capabilitySubjects,
    createdAtMs: row.session_issued_at_ms,
    expiresAtMs: row.session_expires_at_ms,
  });
}

function parseWalletSessionAuthorizationV2QuotaRow(
  row: D1Row,
  session: WalletSessionAuthorizationV2,
): ActiveWalletSessionQuota {
  if (row.quota_lifecycle_kind !== 'active') {
    throw new Error('Stored V2 Wallet Session quota is no longer active');
  }
  const quotaTenantId = requireParsed(row.quota_tenant_id, parseTenantId, 'V2 quota.tenantId');
  const quotaPrincipalId = requireParsed(
    row.quota_principal_id,
    parsePrincipalId,
    'V2 quota.principalId',
  );
  const quotaWalletSessionId = requireParsed(
    row.quota_wallet_session_id,
    parseWalletSessionId,
    'V2 quota.walletSessionId',
  );
  const quotaId = requireParsed(row.quota_id, parseMpcWalletSigningQuotaId, 'V2 quota.quotaId');
  const remainingUses = requirePositiveInteger(row.quota_remaining_uses, 'V2 quota.remainingUses');
  const expiresAtMs = requirePositiveInteger(row.quota_expires_at_ms, 'V2 quota.expiresAtMs');
  if (
    quotaTenantId !== session.tenantId ||
    quotaPrincipalId !== session.principalId ||
    quotaWalletSessionId !== session.walletSessionId ||
    quotaId !== session.quotaId ||
    expiresAtMs !== session.expiresAtMs
  ) {
    throw new Error('Stored V2 Wallet Session quota identity does not match');
  }
  return buildActiveWalletSessionQuota({
    tenantId: quotaTenantId,
    principalId: quotaPrincipalId,
    walletSessionId: quotaWalletSessionId,
    quotaId,
    remainingUses,
    expiresAtMs,
  });
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
    session.authorization_id === input.session.authorizationId &&
    session.wallet_session_id === input.session.walletSessionId &&
    session.principal_id === input.session.principalId &&
    session.wallet_id === input.session.walletId &&
    session.authority_digest === input.session.authority.authorityDigest &&
    storedAuthMethodMatches(session.wallet_auth_method_id, input.session.authority) &&
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

function reusableWalletSessionReplayReadbackMatches(
  session: D1Row | null,
  quota: D1Row | null,
  input: {
    readonly session: WalletSessionAuthorization;
    readonly quota: ActiveWalletSessionQuota;
  },
): boolean {
  if (
    session === null ||
    quota === null ||
    session.authorization_id !== input.session.authorizationId ||
    session.wallet_session_id !== input.session.walletSessionId ||
    session.principal_id !== input.session.principalId ||
    session.wallet_id !== input.session.walletId ||
    session.authority_digest !== input.session.authority.authorityDigest ||
    !storedAuthMethodMatches(session.wallet_auth_method_id, input.session.authority) ||
    session.mint_id !== input.session.mintId ||
    session.quota_id !== input.session.quotaId ||
    session.lifecycle_kind !== 'active' ||
    quota.wallet_session_id !== input.quota.walletSessionId ||
    quota.quota_id !== input.quota.quotaId ||
    quota.principal_id !== input.quota.principalId ||
    quota.lifecycle_kind !== 'active' ||
    integerColumn(quota.remaining_uses, 'quota.remainingUses') !== input.quota.remainingUses
  ) {
    return false;
  }
  const sessionCreatedAtMs = requirePositiveInteger(session.created_at_ms, 'session.createdAtMs');
  const sessionExpiresAtMs = requirePositiveInteger(session.expires_at_ms, 'session.expiresAtMs');
  const quotaExpiresAtMs = requirePositiveInteger(quota.expires_at_ms, 'quota.expiresAtMs');
  return sessionExpiresAtMs > sessionCreatedAtMs && quotaExpiresAtMs === sessionExpiresAtMs;
}
