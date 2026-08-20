import { parseWalletAuthMethodId, type WalletAuthMethodId } from '@shared/utils/domainIds';
import {
  CAPABILITY_KINDS,
  parseAuthorizationAuditEventId,
  parseAuthorizationGrantRef,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationRef,
  parseLinkedDeviceWalletSessionAuthorizationId,
  buildLinkedDeviceWalletSessionAuthorizationRef,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseTenantId,
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
  ActiveWalletSessionQuota,
  AuthorizedOperationReplayResponse,
  CompletedCapabilityOperationResult,
  IssuedHostedWalletSeamsSessionExchange,
  RedeemHostedWalletSeamsSessionExchangeInput,
  PersistedHostedWalletSeamsSessionExchangeResult,
  ReusableWalletSessionStatus,
  VerifiedAuthorizationEvidenceSet,
  VerifiedOwnerProof,
  WalletSessionId,
  LinkedDeviceWalletSessionAuthorization,
  LinkedDeviceWalletSessionStatus,
} from '../../../../authorization/domain';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorization,
  parseLinkedDeviceWalletSessionAuthorization,
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
  LinkedDeviceMaterialActivationScopeV1,
  AuthorizedOperationMaterialScope,
  IssuedReusableWalletSession,
  IssuedLinkedDeviceWalletSession,
  OpaqueWalletSessionCurve,
  OpaqueOwnerWalletSessionBinding,
  ResolvedOpaqueWalletSessionToken,
} from '../../../../authorization/service';
import { parseOpaqueOwnerWalletSessionBinding } from '../../../../authorization/service';
import type { D1WalletStoreScope } from '../../../../core/d1WalletStore';
import { d1ChangedRows, type D1Row } from '../../../../storage/d1Sql';
import type { D1DatabaseLike, D1ResultLike } from '../../../../storage/tenantRoute';
import { parseLinkedDeviceEnrollmentId, parseLinkedDeviceId } from '@shared/utils/domainIds';
import { parseWalletId } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { CloudflareD1LaneLifecycleStore } from '../signingLanes/d1LaneLifecycleStore';
import type { LaneLifecycleStore } from '../../../../core/signingLanes/LaneLifecycleStore';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { parseLaneEnrollmentId } from '@shared/signing-lanes';
import { hasDelegatedWalletPermissionV1 } from '@shared/authorization/delegatedAuthority';

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

type LinkedDeviceAuthorizationPersistenceRows = {
  readonly authorization: LinkedDeviceWalletSessionAuthorization;
  readonly lifecycleKind: 'active' | 'revoked';
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly revokedAtMs: number | null;
  readonly quotaTenantId: TenantId;
  readonly quotaPrincipalId: LinkedDeviceWalletSessionAuthorization['principalId'];
  readonly quotaWalletSessionId: WalletSessionId;
  readonly quotaId: ActiveWalletSessionQuota['quotaId'];
  readonly remainingUses: number;
  readonly quotaLifecycleKind: 'active' | 'exhausted' | 'revoked';
  readonly quotaExpiresAtMs: number;
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
  private readonly laneLifecycle: Pick<
    LaneLifecycleStore,
    'getEnrollment' | 'getProtocol' | 'listEnrollmentProductEpochs'
  >;

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
    this.laneLifecycle = new CloudflareD1LaneLifecycleStore({
      database: this.database,
      scope: this.walletSignerScope,
    });
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
    await this.database.batch([deleteTokens, exhaustQuotas, supersedeSessions]);
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
      const results = await this.database.batch([revokeExistingToken, updateStatement]);
      const update = results[1] as D1ResultLike;
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
           quota.expires_at_ms AS quota_expires_at_ms
         FROM opaque_wallet_session_tokens AS token
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
    if (
      row.token_curve !== input.curve ||
      row.session_lifecycle_kind !== 'active' ||
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

  async putLinkedDeviceWalletSessionAuthorization(input: {
    readonly authorization: LinkedDeviceWalletSessionAuthorization;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void> {
    requireExactLinkedDeviceWalletSessionQuota(input);
    const authorization = parseLinkedDeviceWalletSessionAuthorization(input.authorization);
    if (authorization.principalId !== input.quota.principalId) {
      throw new Error('linked-device authorization and quota principal identities differ');
    }
    await this.requireActiveLinkedDeviceEnrollment(authorization);

    const existing = await this.readLinkedDeviceAuthorizationRows({
      tenantId: authorization.tenantId,
      authorizationId: authorization.authorizationGrantRef.authorizationId,
    });
    if (existing) {
      if (linkedDeviceAuthorizationReadbackMatches(existing, input)) return;
      throw new Error('linked-device Wallet Session authorization replay does not match');
    }

    const scope = this.walletSignerScope;
    const authStatement = this.database
      .prepare(
        `INSERT INTO linked_device_wallet_session_authorizations (
           namespace, org_id, project_id, env_id, tenant_id, authorization_id,
           principal_id, wallet_id, enrollment_id, device_id, wallet_session_id,
           quota_id, key_manifest_digest_b64u, permission_json, revocation_epoch,
           lifecycle_kind, issued_at_ms, expires_at_ms, revoked_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL)`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        authorization.tenantId,
        authorization.authorizationGrantRef.authorizationId,
        authorization.principalId,
        authorization.walletId,
        authorization.enrollmentId,
        authorization.deviceId,
        authorization.walletSessionId,
        authorization.quotaId,
        authorization.keyManifestDigestB64u,
        JSON.stringify(authorization.permission),
        authorization.revocationEpoch,
        requirePositiveInteger(authorization.issuedAtMs, 'linked authorization.issuedAtMs'),
        requirePositiveInteger(authorization.expiresAtMs, 'linked authorization.expiresAtMs'),
      );
    const quotaStatement = this.database
      .prepare(
        `INSERT INTO linked_device_wallet_session_quotas (
           namespace, org_id, project_id, env_id, tenant_id, quota_id,
           authorization_id, wallet_session_id, principal_id, remaining_uses,
           lifecycle_kind, expires_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        input.quota.tenantId,
        input.quota.quotaId,
        authorization.authorizationGrantRef.authorizationId,
        input.quota.walletSessionId,
        input.quota.principalId,
        requirePositiveInteger(input.quota.remainingUses, 'linked quota.remainingUses'),
        requirePositiveInteger(input.quota.expiresAtMs, 'linked quota.expiresAtMs'),
      );
    const results = await this.database.batch<D1ResultLike>([authStatement, quotaStatement]);
    if (results.length !== 2)
      throw new Error('linked authorization transaction returned incomplete results');
    const authResult = results[0];
    const quotaResult = results[1];
    if (!authResult || !quotaResult) {
      throw new Error('linked authorization transaction returned incomplete results');
    }
    const authInserted = d1ChangedRows(authResult) === 1;
    const quotaInserted = d1ChangedRows(quotaResult) === 1;
    if (authInserted !== quotaInserted) {
      throw new Error('linked authorization transaction persisted an incomplete identity');
    }
    const readback = await this.readLinkedDeviceAuthorizationRows({
      tenantId: authorization.tenantId,
      authorizationId: authorization.authorizationGrantRef.authorizationId,
    });
    if (!readback || !linkedDeviceAuthorizationReadbackMatches(readback, input)) {
      throw new Error('linked-device Wallet Session authorization could not be read back');
    }
  }

  async readLinkedDeviceWalletSessionAuthorization(input: {
    readonly tenantId: TenantId;
    readonly deviceId: LinkedDeviceWalletSessionAuthorization['deviceId'];
    readonly authorizationId: LinkedDeviceWalletSessionAuthorization['authorizationGrantRef']['authorizationId'];
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: ActiveWalletSessionQuota['quotaId'];
    readonly nowMs: number;
  }): Promise<IssuedLinkedDeviceWalletSession | null> {
    const rows = await this.readLinkedDeviceAuthorizationRows({
      tenantId: input.tenantId,
      authorizationId: input.authorizationId,
    });
    if (!rows) return null;
    const authorization = rows.authorization;
    if (
      authorization.deviceId !== input.deviceId ||
      authorization.walletSessionId !== input.walletSessionId ||
      authorization.quotaId !== input.quotaId
    ) {
      throw new Error(
        'linked-device Wallet Session authorization identity does not match the request',
      );
    }
    const nowMs = requirePositiveInteger(input.nowMs, 'linked authorization read time');
    if (rows.lifecycleKind !== 'active' || rows.quotaLifecycleKind !== 'active') {
      throw new Error('linked-device Wallet Session authorization is no longer active');
    }
    if (rows.expiresAtMs <= nowMs) {
      throw new Error('linked-device Wallet Session authorization has expired');
    }
    const quota = buildActiveWalletSessionQuota({
      tenantId: rows.quotaTenantId,
      principalId: rows.quotaPrincipalId,
      walletSessionId: rows.quotaWalletSessionId,
      quotaId: rows.quotaId,
      remainingUses: rows.remainingUses,
      expiresAtMs: rows.quotaExpiresAtMs,
    });
    return { authorization, quota };
  }

  async readClaimedLinkedDeviceWalletSessionAuthorization(input: {
    readonly tenantId: TenantId;
    readonly deviceId: LinkedDeviceWalletSessionAuthorization['deviceId'];
    readonly authorizationId: LinkedDeviceWalletSessionAuthorization['authorizationGrantRef']['authorizationId'];
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: ActiveWalletSessionQuota['quotaId'];
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionAuthorization | null> {
    const rows = await this.readLinkedDeviceAuthorizationRows({
      tenantId: input.tenantId,
      authorizationId: input.authorizationId,
    });
    if (!rows) return null;
    const authorization = rows.authorization;
    if (
      authorization.deviceId !== input.deviceId ||
      authorization.walletSessionId !== input.walletSessionId ||
      authorization.quotaId !== input.quotaId
    ) {
      throw new Error(
        'claimed linked-device Wallet Session authorization identity does not match the request',
      );
    }
    const nowMs = requirePositiveInteger(input.nowMs, 'claimed linked authorization read time');
    if (
      rows.lifecycleKind !== 'active' ||
      (rows.quotaLifecycleKind !== 'active' && rows.quotaLifecycleKind !== 'exhausted')
    ) {
      throw new Error('claimed linked-device Wallet Session authorization is unavailable');
    }
    if (rows.expiresAtMs <= nowMs || rows.quotaExpiresAtMs <= nowMs) {
      throw new Error('claimed linked-device Wallet Session authorization has expired');
    }
    if (
      rows.quotaTenantId !== authorization.tenantId ||
      rows.quotaPrincipalId !== authorization.principalId ||
      rows.quotaWalletSessionId !== authorization.walletSessionId ||
      rows.quotaId !== authorization.quotaId ||
      rows.quotaExpiresAtMs !== authorization.expiresAtMs
    ) {
      throw new Error('claimed linked-device Wallet Session quota identity does not match');
    }
    return authorization;
  }

  async getLinkedDeviceWalletSessionStatus(input: {
    readonly tenantId: TenantId;
    readonly principalId: LinkedDeviceWalletSessionAuthorization['principalId'];
    readonly deviceId: LinkedDeviceWalletSessionAuthorization['deviceId'];
    readonly authorizationId: LinkedDeviceWalletSessionAuthorization['authorizationGrantRef']['authorizationId'];
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: ActiveWalletSessionQuota['quotaId'];
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionStatus> {
    const rows = await this.readLinkedDeviceAuthorizationRows({
      tenantId: input.tenantId,
      authorizationId: input.authorizationId,
    });
    const missing = {
      kind: 'missing' as const,
      tenantId: input.tenantId,
      principalId: input.principalId,
      deviceId: input.deviceId,
      authorizationId: input.authorizationId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
    };
    if (!rows) return missing;
    const authorization = rows.authorization;
    const identityMatches =
      authorization.principalId === input.principalId &&
      authorization.deviceId === input.deviceId &&
      authorization.walletSessionId === input.walletSessionId &&
      authorization.quotaId === input.quotaId;
    if (!identityMatches || rows.quotaPrincipalId !== authorization.principalId) {
      return { ...missing, kind: 'invalid' };
    }
    const identity = {
      tenantId: authorization.tenantId,
      principalId: authorization.principalId,
      deviceId: authorization.deviceId,
      authorizationId: authorization.authorizationGrantRef.authorizationId,
      walletId: authorization.walletId,
      enrollmentId: authorization.enrollmentId,
      walletSessionId: authorization.walletSessionId,
      quotaId: authorization.quotaId,
      keyManifestDigestB64u: authorization.keyManifestDigestB64u,
      revocationEpoch: authorization.revocationEpoch,
    };
    if (rows.lifecycleKind === 'revoked' || rows.quotaLifecycleKind === 'revoked') {
      return {
        ...identity,
        kind: 'revoked',
        revokedAtMs: rows.revokedAtMs ?? rows.issuedAtMs,
        expiresAtMs: rows.expiresAtMs,
      };
    }
    const nowMs = requirePositiveInteger(input.nowMs, 'linked authorization status time');
    if (rows.expiresAtMs <= nowMs || rows.quotaExpiresAtMs <= nowMs) {
      return { ...identity, kind: 'expired', expiresAtMs: rows.expiresAtMs };
    }
    if (rows.remainingUses === 0 || rows.quotaLifecycleKind === 'exhausted') {
      return { ...identity, kind: 'exhausted', remainingUses: 0, expiresAtMs: rows.expiresAtMs };
    }
    if (rows.lifecycleKind !== 'active' || rows.quotaLifecycleKind !== 'active') {
      return { ...missing, kind: 'invalid' };
    }
    return {
      ...identity,
      kind: 'active',
      remainingUses: rows.remainingUses,
      expiresAtMs: rows.expiresAtMs,
    };
  }

  async renewLinkedDeviceWalletSessionAuthorization(input: {
    readonly tenantId: TenantId;
    readonly principalId: LinkedDeviceWalletSessionAuthorization['principalId'];
    readonly deviceId: LinkedDeviceWalletSessionAuthorization['deviceId'];
    readonly enrollmentId: LinkedDeviceWalletSessionAuthorization['enrollmentId'];
    readonly authorizationId: LinkedDeviceWalletSessionAuthorization['authorizationGrantRef']['authorizationId'];
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: ActiveWalletSessionQuota['quotaId'];
    readonly revocationEpoch: number;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
  }): Promise<void> {
    const issuedAtMs = requirePositiveInteger(input.issuedAtMs, 'linked renewal issuedAtMs');
    const expiresAtMs = requirePositiveInteger(input.expiresAtMs, 'linked renewal expiresAtMs');
    const remainingUses = requirePositiveInteger(
      input.remainingUses,
      'linked renewal remainingUses',
    );
    if (expiresAtMs <= issuedAtMs) throw new Error('linked renewal expiry is invalid');
    if (!Number.isSafeInteger(input.revocationEpoch) || input.revocationEpoch < 0) {
      throw new Error('linked renewal revocationEpoch is invalid');
    }
    const scope = this.walletSignerScope;
    const authorizationStatement = this.database
      .prepare(
        `UPDATE linked_device_wallet_session_authorizations
            SET issued_at_ms = ?, expires_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND tenant_id = ? AND authorization_id = ?
            AND principal_id = ? AND device_id = ? AND enrollment_id = ?
            AND wallet_session_id = ? AND quota_id = ?
            AND revocation_epoch = ? AND lifecycle_kind = 'active'
            AND EXISTS (
              SELECT 1 FROM lane_enrollments AS enrollment
               WHERE enrollment.namespace = linked_device_wallet_session_authorizations.namespace
                 AND enrollment.org_id = linked_device_wallet_session_authorizations.org_id
                 AND enrollment.project_id = linked_device_wallet_session_authorizations.project_id
                 AND enrollment.env_id = linked_device_wallet_session_authorizations.env_id
                 AND enrollment.enrollment_id = linked_device_wallet_session_authorizations.enrollment_id
                 AND enrollment.enrollment_id = ?
                 AND enrollment.wallet_id = linked_device_wallet_session_authorizations.wallet_id
                 AND json_extract(enrollment.lifecycle_json, '$.state') = 'active'
                 AND json_extract(enrollment.lifecycle_json, '$.manifestDigestB64u') = linked_device_wallet_session_authorizations.key_manifest_digest_b64u
            )`,
      )
      .bind(
        issuedAtMs,
        expiresAtMs,
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        input.tenantId,
        input.authorizationId,
        input.principalId,
        input.deviceId,
        input.enrollmentId,
        input.walletSessionId,
        input.quotaId,
        input.revocationEpoch,
        input.enrollmentId,
      );
    const quotaStatement = this.database
      .prepare(
        `UPDATE linked_device_wallet_session_quotas
            SET remaining_uses = ?, lifecycle_kind = 'active', expires_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND tenant_id = ? AND authorization_id = ?
            AND quota_id = ? AND wallet_session_id = ? AND principal_id = ?
            AND lifecycle_kind IN ('active', 'exhausted')
            AND EXISTS (
              SELECT 1
                FROM linked_device_wallet_session_authorizations AS authorization
                JOIN lane_enrollments AS enrollment
                  ON enrollment.namespace = authorization.namespace
                 AND enrollment.org_id = authorization.org_id
                 AND enrollment.project_id = authorization.project_id
                 AND enrollment.env_id = authorization.env_id
                 AND enrollment.enrollment_id = authorization.enrollment_id
                 AND enrollment.wallet_id = authorization.wallet_id
                 AND json_extract(enrollment.lifecycle_json, '$.state') = 'active'
                 AND json_extract(enrollment.lifecycle_json, '$.manifestDigestB64u') = authorization.key_manifest_digest_b64u
               WHERE authorization.namespace = linked_device_wallet_session_quotas.namespace
                 AND authorization.org_id = linked_device_wallet_session_quotas.org_id
                 AND authorization.project_id = linked_device_wallet_session_quotas.project_id
                 AND authorization.env_id = linked_device_wallet_session_quotas.env_id
                 AND authorization.tenant_id = linked_device_wallet_session_quotas.tenant_id
                 AND authorization.authorization_id = linked_device_wallet_session_quotas.authorization_id
                 AND authorization.enrollment_id = ?
                 AND authorization.revocation_epoch = ?
                 AND authorization.lifecycle_kind = 'active'
            )`,
      )
      .bind(
        remainingUses,
        expiresAtMs,
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        input.tenantId,
        input.authorizationId,
        input.quotaId,
        input.walletSessionId,
        input.principalId,
        input.enrollmentId,
        input.revocationEpoch,
      );
    const results = await this.database.batch<D1ResultLike>([
      authorizationStatement,
      quotaStatement,
    ]);
    if (results.length !== 2 || !results[0] || !results[1]) {
      throw new Error('linked authorization renewal transaction returned incomplete results');
    }
    if (d1ChangedRows(results[0]) === 1 && d1ChangedRows(results[1]) === 1) return;
    const status = await this.getLinkedDeviceWalletSessionStatus({
      tenantId: input.tenantId,
      principalId: input.principalId,
      deviceId: input.deviceId,
      authorizationId: input.authorizationId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
      nowMs: issuedAtMs,
    });
    if (status.kind === 'revoked')
      throw new Error('linked-device Wallet Session authorization is revoked');
    throw new Error('linked-device Wallet Session authorization could not be renewed');
  }

  async revokeLinkedDeviceWalletSession(input: {
    readonly tenantId: TenantId;
    readonly principalId: LinkedDeviceWalletSessionAuthorization['principalId'];
    readonly deviceId: LinkedDeviceWalletSessionAuthorization['deviceId'];
    readonly authorizationId: LinkedDeviceWalletSessionAuthorization['authorizationGrantRef']['authorizationId'];
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: ActiveWalletSessionQuota['quotaId'];
    readonly nowMs: number;
  }): Promise<void> {
    const nowMs = requirePositiveInteger(input.nowMs, 'linked authorization revocation time');
    const authorizationStatement = this.database
      .prepare(
        `UPDATE linked_device_wallet_session_authorizations
            SET lifecycle_kind = 'revoked', revoked_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND tenant_id = ? AND authorization_id = ?
            AND principal_id = ? AND device_id = ? AND wallet_session_id = ?
            AND quota_id = ? AND lifecycle_kind = 'active'`,
      )
      .bind(
        nowMs,
        this.walletSignerScope.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.tenantId,
        input.authorizationId,
        input.principalId,
        input.deviceId,
        input.walletSessionId,
        input.quotaId,
      );
    const quotaStatement = this.database
      .prepare(
        `UPDATE linked_device_wallet_session_quotas
            SET remaining_uses = 0, lifecycle_kind = 'revoked'
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND tenant_id = ? AND authorization_id = ?
            AND quota_id = ? AND wallet_session_id = ?
            AND principal_id = ? AND lifecycle_kind != 'revoked'`,
      )
      .bind(
        this.walletSignerScope.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.tenantId,
        input.authorizationId,
        input.quotaId,
        input.walletSessionId,
        input.principalId,
      );
    const results = await this.database.batch<D1ResultLike>([
      authorizationStatement,
      quotaStatement,
    ]);
    if (results.length !== 2 || !results[0] || !results[1]) {
      throw new Error('linked authorization revocation transaction returned incomplete results');
    }
    const changed = d1ChangedRows(results[0]);
    if (changed === 1) return;
    const status = await this.getLinkedDeviceWalletSessionStatus(input);
    if (status.kind === 'revoked') return;
    throw new Error('linked-device Wallet Session authorization could not be revoked');
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
    const linkedGrant =
      operation.authorization.kind === 'authorization_grant' &&
      operation.authorization.authorizationGrantRef.kind ===
        'linked_device_wallet_session_authorization_v1';
    if (linkedGrant !== (input.material?.kind === 'linked_device_lane')) {
      return { kind: 'material_mismatch' };
    }
    if (input.material?.kind === 'linked_device_lane') {
      if (
        operation.operation.operation.capabilityKind !== CAPABILITY_KINDS.nearEd25519MpcSigning &&
        operation.operation.operation.capabilityKind !== CAPABILITY_KINDS.evmEcdsaMpcSigning
      ) {
        return { kind: 'material_mismatch' };
      }
      const permission = await this.readLinkedDeviceOperationPermission(operation);
      if (!permission) {
        return { kind: 'authorization_grant_rejected' };
      }
      const requiredPermission =
        operation.operation.operation.operationKind === 'near.export_key' ||
        operation.operation.operation.operationKind === 'evm.export_key'
          ? 'export_keys'
          : 'sign';
      if (!hasDelegatedWalletPermissionV1(permission, requiredPermission)) {
        return { kind: 'authorization_grant_rejected' };
      }
      if (!(await this.isActiveLinkedDeviceMaterial(input.material))) {
        return { kind: 'material_mismatch' };
      }
    } else if (
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
        linkedScope: linkedMaterialScope(input.material, this.walletSignerScope),
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
        input.material?.kind === 'linked_device_lane' ? input.material.walletId : null,
        input.material?.kind === 'linked_device_lane' ? input.material.enrollmentId : null,
        input.material?.kind === 'linked_device_lane' ? input.material.deviceId : null,
        input.material?.kind === 'linked_device_lane' ? input.material.walletKeyId : null,
        input.material?.kind === 'linked_device_lane' ? input.material.laneId : null,
        input.material?.kind === 'linked_device_lane' ? input.material.laneShareEpoch : null,
        input.material?.kind === 'linked_device_lane' ? input.material.revocationEpoch : null,
        input.material?.kind === 'linked_device_lane' ? this.walletSignerScope.orgId : null,
        input.material?.kind === 'linked_device_lane' ? this.walletSignerScope.projectId : null,
        input.material?.kind === 'linked_device_lane' ? this.walletSignerScope.envId : null,
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
          linkedScope: linkedMaterialScope(input.material, this.walletSignerScope),
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

  private async requireActiveLinkedDeviceEnrollment(
    authorization: LinkedDeviceWalletSessionAuthorization,
  ): Promise<void> {
    const enrollmentId = requireDomainId(
      authorization.enrollmentId,
      parseLaneEnrollmentId,
      'linked authorization.enrollmentId',
    );
    const enrollment = await this.laneLifecycle.getEnrollment(enrollmentId);
    if (!enrollment || enrollment.value.lifecycle.state !== 'active') {
      throw new Error('linked-device enrollment is not active');
    }
    if (String(enrollment.value.manifest.walletId) !== String(authorization.walletId)) {
      throw new Error('linked-device authorization wallet differs from enrollment');
    }
    const manifestDigest = await computeLaneEnrollmentManifestDigestV1(enrollment.value.manifest);
    if (manifestDigest !== authorization.keyManifestDigestB64u) {
      throw new Error('linked-device authorization manifest digest differs from enrollment');
    }
  }

  private async isActiveLinkedDeviceMaterial(
    material: LinkedDeviceMaterialActivationScopeV1,
  ): Promise<boolean> {
    try {
      const enrollmentId = requireDomainId(
        material.enrollmentId,
        parseLaneEnrollmentId,
        'linked material.enrollmentId',
      );
      const enrollment = await this.laneLifecycle.getEnrollment(enrollmentId);
      if (!enrollment || enrollment.value.lifecycle.state !== 'active') return false;
      if (String(enrollment.value.manifest.walletId) !== String(material.walletId)) return false;
      const products = await this.laneLifecycle.listEnrollmentProductEpochs(enrollmentId);
      const activation = routerAbMpcMaterialActivationRefFromWire(material.materialActivation);
      const product = products.find(
        (candidate) =>
          candidate.state === 'active' &&
          candidate.laneKind === 'linked_device' &&
          String(candidate.walletId) === String(material.walletId) &&
          String(candidate.walletKeyId) === String(material.walletKeyId) &&
          String(candidate.laneId) === String(material.laneId) &&
          String(candidate.laneShareEpoch) === String(material.laneShareEpoch) &&
          candidate.revocationEpoch === material.revocationEpoch &&
          mpcMaterialActivationRefsEqual(candidate.materialActivation, activation),
      );
      if (!product) return false;
      const protocol = await this.laneLifecycle.getProtocol(product.operationId);
      if (!protocol || protocol.value.lifecycle.state !== 'active') return false;
      return (
        String(protocol.value.job.enrollmentId) === String(material.enrollmentId) &&
        String(protocol.value.job.walletId) === String(material.walletId) &&
        String(protocol.value.job.walletKeyId) === String(material.walletKeyId) &&
        String(protocol.value.job.target.laneId) === String(material.laneId) &&
        String(protocol.value.job.target.laneShareEpoch) === String(material.laneShareEpoch) &&
        String(protocol.value.job.targetMaterialActivationId) ===
          String(material.materialActivation.activation_id)
      );
    } catch {
      return false;
    }
  }

  private async readLinkedDeviceOperationPermission(
    operation: AuthorizedOperation,
  ): Promise<LinkedDeviceWalletSessionAuthorization['permission'] | null> {
    if (
      operation.authorization.kind !== 'authorization_grant' ||
      operation.authorization.authorizationGrantRef.kind !==
        'linked_device_wallet_session_authorization_v1'
    ) {
      return null;
    }
    const rows = await this.readLinkedDeviceAuthorizationRows({
      tenantId: operation.tenantId,
      authorizationId: operation.authorization.authorizationGrantRef.authorizationId,
    });
    if (!rows || rows.authorization.principalId !== operation.operation.principalId) return null;
    return rows.authorization.permission;
  }

  private async readLinkedDeviceAuthorizationRows(input: {
    readonly tenantId: TenantId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorization['authorizationGrantRef']['authorizationId'];
  }): Promise<LinkedDeviceAuthorizationPersistenceRows | null> {
    const row = await this.database
      .prepare(
        `SELECT
           authorization.tenant_id AS authorization_tenant_id,
           authorization.authorization_id AS authorization_id,
           authorization.principal_id AS authorization_principal_id,
           authorization.wallet_id AS authorization_wallet_id,
           authorization.enrollment_id AS authorization_enrollment_id,
           authorization.device_id AS authorization_device_id,
           authorization.wallet_session_id AS authorization_wallet_session_id,
           authorization.quota_id AS authorization_quota_id,
           authorization.key_manifest_digest_b64u AS authorization_key_manifest_digest_b64u,
           authorization.permission_json AS authorization_permission_json,
           authorization.revocation_epoch AS authorization_revocation_epoch,
           authorization.lifecycle_kind AS authorization_lifecycle_kind,
           authorization.issued_at_ms AS authorization_issued_at_ms,
           authorization.expires_at_ms AS authorization_expires_at_ms,
           authorization.revoked_at_ms AS authorization_revoked_at_ms,
           quota.tenant_id AS quota_tenant_id,
           quota.principal_id AS quota_principal_id,
           quota.wallet_session_id AS quota_wallet_session_id,
           quota.quota_id AS quota_quota_id,
           quota.remaining_uses AS quota_remaining_uses,
           quota.lifecycle_kind AS quota_lifecycle_kind,
           quota.expires_at_ms AS quota_expires_at_ms
         FROM linked_device_wallet_session_authorizations AS authorization
         LEFT JOIN linked_device_wallet_session_quotas AS quota
           ON quota.namespace = authorization.namespace
          AND quota.org_id = authorization.org_id
          AND quota.project_id = authorization.project_id
          AND quota.env_id = authorization.env_id
          AND quota.tenant_id = authorization.tenant_id
          AND quota.authorization_id = authorization.authorization_id
          AND quota.quota_id = authorization.quota_id
         WHERE authorization.namespace = ?
           AND authorization.org_id = ?
           AND authorization.project_id = ?
           AND authorization.env_id = ?
           AND authorization.tenant_id = ?
           AND authorization.authorization_id = ?
         LIMIT 1`,
      )
      .bind(
        this.walletSignerScope.namespace,
        this.walletSignerScope.orgId,
        this.walletSignerScope.projectId,
        this.walletSignerScope.envId,
        input.tenantId,
        input.authorizationId,
      )
      .first<D1Row>();
    return row ? parseLinkedDeviceAuthorizationPersistenceRows(row) : null;
  }

  private async isAuthorizedOperationSourceActive(row: D1Row, nowMs: number): Promise<boolean> {
    const sourceKind = requireString(row.authorization_source_kind, 'operation.authorization.kind');
    if (sourceKind === 'authorization_grant') {
      if (row.authorization_grant_kind === 'linked_device_wallet_session_authorization_v1') {
        const linked = await this.database
          .prepare(
            `SELECT 1 AS active
               FROM linked_device_wallet_session_authorizations AS authorization
               JOIN linked_device_wallet_session_quotas AS quota
                 ON quota.namespace = authorization.namespace
                AND quota.org_id = authorization.org_id
                AND quota.project_id = authorization.project_id
                AND quota.env_id = authorization.env_id
                AND quota.tenant_id = authorization.tenant_id
                AND quota.authorization_id = authorization.authorization_id
                AND quota.quota_id = authorization.quota_id
              WHERE authorization.namespace = ?
                AND authorization.org_id = ?
                AND authorization.project_id = ?
                AND authorization.env_id = ?
                AND authorization.tenant_id = ?
                AND authorization.authorization_id = ?
                AND authorization.principal_id = ?
                AND authorization.lifecycle_kind = 'active'
                AND authorization.expires_at_ms > ?
                AND quota.lifecycle_kind IN ('active', 'exhausted')
                AND quota.expires_at_ms > ?
              LIMIT 1`,
          )
          .bind(
            this.walletSignerScope.namespace,
            this.walletSignerScope.orgId,
            this.walletSignerScope.projectId,
            this.walletSignerScope.envId,
            requireString(row.tenant_id, 'operation.tenantId'),
            requireString(row.authorization_id, 'operation.authorizationId'),
            requireString(row.principal_id, 'operation.principalId'),
            requirePositiveInteger(nowMs, 'operation replay time'),
            requirePositiveInteger(nowMs, 'operation replay time'),
          )
          .first<D1Row>();
        return linked !== null;
      }
      const session = await this.database
        .prepare(
          `SELECT 1 AS active
             FROM reusable_wallet_sessions
            WHERE namespace = ?
              AND tenant_id = ?
              AND authorization_id = ?
              AND principal_id = ?
              AND lifecycle_kind = 'active'
              AND expires_at_ms > ?
            LIMIT 1`,
        )
        .bind(
          this.namespace,
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

function linkedMaterialScope(
  material: AuthorizedOperationMaterialScope | undefined,
  scope: D1WalletStoreScope,
): { readonly orgId: string; readonly projectId: string; readonly envId: string } | undefined {
  return material?.kind === 'linked_device_lane'
    ? { orgId: scope.orgId, projectId: scope.projectId, envId: scope.envId }
    : undefined;
}

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
  if (message.includes('authorization_linked_device_rejected')) {
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
  readonly linkedScope?: {
    readonly orgId: string;
    readonly projectId: string;
    readonly envId: string;
  };
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
  if (input.material?.kind === 'linked_device_lane') {
    if (
      !input.linkedScope ||
      input.existing.linked_scope_org_id !== input.linkedScope.orgId ||
      input.existing.linked_scope_project_id !== input.linkedScope.projectId ||
      input.existing.linked_scope_env_id !== input.linkedScope.envId
    ) {
      return { kind: 'authorization_grant_rejected' };
    }
    const linkedFields: readonly [unknown, unknown][] = [
      [input.existing.linked_wallet_id, input.material.walletId],
      [input.existing.linked_enrollment_id, input.material.enrollmentId],
      [input.existing.linked_device_id, input.material.deviceId],
      [input.existing.linked_wallet_key_id, input.material.walletKeyId],
      [input.existing.linked_lane_id, input.material.laneId],
      [input.existing.linked_lane_share_epoch, input.material.laneShareEpoch],
      [input.existing.linked_revocation_epoch, input.material.revocationEpoch],
    ];
    if (linkedFields.some(([existing, incoming]) => String(existing) !== String(incoming))) {
      return { kind: 'material_mismatch' };
    }
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
    const grantKind =
      row.authorization_grant_kind === 'linked_device_wallet_session_authorization_v1'
        ? 'linked_device_wallet_session_authorization_v1'
        : row.authorization_grant_kind === 'wallet_session_authorization'
          ? 'wallet_session_authorization'
          : (() => {
              throw new Error('operation.authorization grant kind is invalid');
            })();
    if (grantKind === 'linked_device_wallet_session_authorization_v1') {
      requireString(row.linked_scope_org_id, 'operation.linkedScope.orgId');
      requireString(row.linked_scope_project_id, 'operation.linkedScope.projectId');
      requireString(row.linked_scope_env_id, 'operation.linkedScope.envId');
    }
    authorization = {
      kind: 'authorization_grant',
      authorizationGrantRef: requireParsed(
        {
          kind: grantKind,
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

function parseLinkedDeviceAuthorizationPersistenceRows(
  row: D1Row,
): LinkedDeviceAuthorizationPersistenceRows {
  const tenantId = requireParsed(
    row.authorization_tenant_id,
    parseTenantId,
    'linked authorization.tenantId',
  );
  const authorizationId = requireParsed(
    row.authorization_id,
    parseLinkedDeviceWalletSessionAuthorizationId,
    'linked authorization.authorizationId',
  );
  const permission = parseJsonRecord(
    row.authorization_permission_json,
    'linked authorization.permission',
  );
  const authorization = parseLinkedDeviceWalletSessionAuthorization({
    kind: 'linked_device_wallet_session_authorization_v1',
    tenantId,
    principalId: requireParsed(
      row.authorization_principal_id,
      parsePrincipalId,
      'linked authorization.principalId',
    ),
    authorizationGrantRef: buildLinkedDeviceWalletSessionAuthorizationRef(authorizationId),
    walletId: requireDomainId(
      row.authorization_wallet_id,
      parseWalletId,
      'linked authorization.walletId',
    ),
    enrollmentId: requireDomainId(
      row.authorization_enrollment_id,
      parseLinkedDeviceEnrollmentId,
      'linked authorization.enrollmentId',
    ),
    deviceId: requireDomainId(
      row.authorization_device_id,
      parseLinkedDeviceId,
      'linked authorization.deviceId',
    ),
    walletSessionId: requireParsed(
      row.authorization_wallet_session_id,
      parseWalletSessionId,
      'linked authorization.walletSessionId',
    ),
    quotaId: requireParsed(
      row.authorization_quota_id,
      parseMpcWalletSigningQuotaId,
      'linked authorization.quotaId',
    ),
    keyManifestDigestB64u: parseDigestB64u(
      requireString(
        row.authorization_key_manifest_digest_b64u,
        'linked authorization.keyManifestDigestB64u',
      ),
    ),
    permission,
    revocationEpoch: requireNonnegativeInteger(
      row.authorization_revocation_epoch,
      'linked authorization.revocationEpoch',
    ),
    issuedAtMs: requirePositiveInteger(
      row.authorization_issued_at_ms,
      'linked authorization.issuedAtMs',
    ),
    expiresAtMs: requirePositiveInteger(
      row.authorization_expires_at_ms,
      'linked authorization.expiresAtMs',
    ),
  });
  const lifecycleKind = requireLinkedAuthorizationLifecycleKind(row.authorization_lifecycle_kind);
  const quotaTenantId = requireParsed(row.quota_tenant_id, parseTenantId, 'linked quota.tenantId');
  const quotaPrincipalId = requireParsed(
    row.quota_principal_id,
    parsePrincipalId,
    'linked quota.principalId',
  );
  const quotaWalletSessionId = requireParsed(
    row.quota_wallet_session_id,
    parseWalletSessionId,
    'linked quota.walletSessionId',
  );
  const quotaId = requireParsed(
    row.quota_quota_id,
    parseMpcWalletSigningQuotaId,
    'linked quota.quotaId',
  );
  const remainingUses = requireNonnegativeInteger(
    row.quota_remaining_uses,
    'linked quota.remainingUses',
  );
  const quotaLifecycleKind = requireLinkedQuotaLifecycleKind(row.quota_lifecycle_kind);
  const quotaExpiresAtMs = requirePositiveInteger(
    row.quota_expires_at_ms,
    'linked quota.expiresAtMs',
  );
  if (
    authorization.tenantId !== quotaTenantId ||
    authorization.principalId !== quotaPrincipalId ||
    authorization.walletSessionId !== quotaWalletSessionId ||
    authorization.quotaId !== quotaId ||
    authorization.expiresAtMs !== quotaExpiresAtMs
  ) {
    throw new Error('linked authorization and quota rows do not share one exact identity');
  }
  return {
    authorization,
    lifecycleKind,
    issuedAtMs: authorization.issuedAtMs,
    expiresAtMs: authorization.expiresAtMs,
    revokedAtMs:
      row.authorization_revoked_at_ms == null
        ? null
        : requirePositiveInteger(
            row.authorization_revoked_at_ms,
            'linked authorization.revokedAtMs',
          ),
    quotaTenantId,
    quotaPrincipalId,
    quotaWalletSessionId,
    quotaId,
    remainingUses,
    quotaLifecycleKind,
    quotaExpiresAtMs,
  };
}

function requireLinkedAuthorizationLifecycleKind(value: unknown): 'active' | 'revoked' {
  if (value === 'active' || value === 'revoked') return value;
  throw new Error('linked authorization lifecycle kind is invalid');
}

function requireLinkedQuotaLifecycleKind(value: unknown): 'active' | 'exhausted' | 'revoked' {
  if (value === 'active' || value === 'exhausted' || value === 'revoked') return value;
  throw new Error('linked quota lifecycle kind is invalid');
}

function requireNonnegativeInteger(value: unknown, label: string): number {
  const parsed = integerColumn(value, label);
  if (parsed < 0) throw new Error(`${label} must be nonnegative`);
  return parsed;
}

function requireExactLinkedDeviceWalletSessionQuota(input: {
  readonly authorization: LinkedDeviceWalletSessionAuthorization;
  readonly quota: ActiveWalletSessionQuota;
}): void {
  if (
    input.authorization.tenantId !== input.quota.tenantId ||
    input.authorization.principalId !== input.quota.principalId ||
    input.authorization.walletSessionId !== input.quota.walletSessionId ||
    input.authorization.quotaId !== input.quota.quotaId ||
    input.authorization.expiresAtMs !== input.quota.expiresAtMs
  ) {
    throw new Error('linked-device authorization and quota must have one exact identity');
  }
}

function linkedDeviceAuthorizationReadbackMatches(
  rows: LinkedDeviceAuthorizationPersistenceRows,
  input: {
    readonly authorization: LinkedDeviceWalletSessionAuthorization;
    readonly quota: ActiveWalletSessionQuota;
  },
): boolean {
  return (
    rows.authorization.tenantId === input.authorization.tenantId &&
    rows.authorization.principalId === input.authorization.principalId &&
    rows.authorization.authorizationGrantRef.authorizationId ===
      input.authorization.authorizationGrantRef.authorizationId &&
    rows.authorization.walletId === input.authorization.walletId &&
    rows.authorization.enrollmentId === input.authorization.enrollmentId &&
    rows.authorization.deviceId === input.authorization.deviceId &&
    rows.authorization.walletSessionId === input.authorization.walletSessionId &&
    rows.authorization.quotaId === input.authorization.quotaId &&
    rows.authorization.keyManifestDigestB64u === input.authorization.keyManifestDigestB64u &&
    JSON.stringify(rows.authorization.permission) ===
      JSON.stringify(input.authorization.permission) &&
    rows.authorization.revocationEpoch === input.authorization.revocationEpoch &&
    rows.authorization.issuedAtMs === input.authorization.issuedAtMs &&
    rows.authorization.expiresAtMs === input.authorization.expiresAtMs &&
    rows.lifecycleKind === 'active' &&
    rows.quotaTenantId === input.quota.tenantId &&
    rows.quotaPrincipalId === input.quota.principalId &&
    rows.quotaWalletSessionId === input.quota.walletSessionId &&
    rows.quotaId === input.quota.quotaId &&
    rows.remainingUses === input.quota.remainingUses &&
    rows.quotaLifecycleKind === 'active' &&
    rows.quotaExpiresAtMs === input.quota.expiresAtMs
  );
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
