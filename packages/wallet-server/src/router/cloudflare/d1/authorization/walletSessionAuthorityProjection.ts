import type { WalletCapabilitySubjectV1 } from '@shared/device-linking/contracts';
import type { WalletAuthorityId, WalletId } from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { D1WalletStoreScope } from '../../../../core/d1WalletStore';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';

export type WalletSessionAuthorityProjectionInput = {
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
  readonly capabilitySubjects: readonly [WalletCapabilitySubjectV1, ...WalletCapabilitySubjectV1[]];
  readonly promotionAtMs: number;
};

/**
 * Builds the statements that promote every non-retired V2 snapshot belonging
 * to an authority. The row identities and operation-credential hashes remain
 * untouched; only the authority projection is replaced.
 */
export function prepareD1WalletSessionAuthorityProjectionStatements(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletStoreScope;
  readonly projection: WalletSessionAuthorityProjectionInput;
}): readonly [D1PreparedStatementLike, D1PreparedStatementLike, D1PreparedStatementLike] {
  requirePositiveInteger(input.projection.promotionAtMs, 'Wallet Session authority promotion time');
  const capabilitySubjectsJson = JSON.stringify(input.projection.capabilitySubjects);
  if (!capabilitySubjectsJson) {
    throw new Error('Wallet Session authority capability subjects serialization is required');
  }
  const scope = [
    input.scope.namespace,
    input.scope.orgId,
    input.scope.projectId,
    input.scope.envId,
  ] as const;
  const parentScope = [
    String(input.projection.walletId),
    String(input.projection.authorityId),
  ] as const;
  const parentIdentityJoin = `
      predecessor.namespace = hosted.namespace
      AND predecessor.org_id = hosted.org_id
      AND predecessor.project_id = hosted.project_id
      AND predecessor.env_id = hosted.env_id
      AND predecessor.tenant_id = hosted.tenant_id
      AND predecessor.authorization_id = hosted.authorization_id
      AND predecessor.wallet_session_id = hosted.wallet_session_id
      AND predecessor.quota_id = hosted.quota_id
      AND predecessor.principal_id = hosted.principal_id
      AND predecessor.wallet_id = hosted.wallet_id
      AND predecessor.authority_id = hosted.authority_id
      AND predecessor.wallet_auth_method_id = hosted.wallet_auth_method_id`;
  const parentSelectionSql = `
      predecessor.wallet_id = ?
      AND predecessor.authority_id = ?
      AND predecessor.retired_at_ms IS NULL
      AND ${activeWalletSessionAuthorityProjectionExistsSql('predecessor')}`;
  const deleteHostedExchanges = input.database
    .prepare(
      `DELETE FROM wallet_session_hosted_exchange_codes_v2 AS hosted
        WHERE hosted.namespace = ?
          AND hosted.org_id = ?
          AND hosted.project_id = ?
          AND hosted.env_id = ?
          AND hosted.lifecycle_kind = 'issued'
          AND EXISTS (
            SELECT 1
              FROM wallet_session_authorizations_v2 AS predecessor
             WHERE ${parentIdentityJoin}
               AND ${parentSelectionSql}
          )`,
    )
    .bind(...scope, ...parentScope, ...authorityProjectionBindings(input.projection));
  const retireHostedCredentials = input.database
    .prepare(
      `UPDATE wallet_session_hosted_credentials_v2 AS hosted
          SET lifecycle_kind = 'retired',
              retired_at_ms = MAX(hosted.issued_at_ms, ?)
        WHERE hosted.namespace = ?
          AND hosted.org_id = ?
          AND hosted.project_id = ?
          AND hosted.env_id = ?
          AND hosted.lifecycle_kind = 'active'
          AND hosted.retired_at_ms IS NULL
          AND EXISTS (
            SELECT 1
              FROM wallet_session_authorizations_v2 AS predecessor
             WHERE ${parentIdentityJoin}
               AND ${parentSelectionSql}
          )`,
    )
    .bind(
      input.projection.promotionAtMs,
      ...scope,
      ...parentScope,
      ...authorityProjectionBindings(input.projection),
    );
  const updateProjection = input.database
    .prepare(
      `UPDATE wallet_session_authorizations_v2
          SET authority_digest_b64u = ?,
              authority_revocation_epoch = ?,
              capability_subjects_json = ?,
              record_json = json_set(
                record_json,
                '$.authorityDigestB64u', ?,
                '$.authorityRevocationEpoch', json(?),
                '$.capabilitySubjects', json(?)
              )
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND authority_id = ?
          AND retired_at_ms IS NULL
          AND ${activeWalletSessionAuthorityProjectionExistsSql('wallet_session_authorizations_v2')}`,
    )
    .bind(
      String(input.projection.authorityDigestB64u),
      input.projection.authorityRevocationEpoch,
      capabilitySubjectsJson,
      String(input.projection.authorityDigestB64u),
      /* D1 binds JS numbers as REAL and json_set would render the epoch as a
         float literal inside record_json; json(?) over the decimal string
         keeps the stored JSON integer-typed. */
      String(input.projection.authorityRevocationEpoch),
      capabilitySubjectsJson,
      ...scope,
      ...parentScope,
      ...authorityProjectionBindings(input.projection),
    );
  return [deleteHostedExchanges, retireHostedCredentials, updateProjection];
}

function activeWalletSessionAuthorityProjectionExistsSql(rowAlias: string): string {
  return `
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
       AND auth_method.wallet_auth_method_id = ${rowAlias}.wallet_auth_method_id
       AND auth_method.status = 'active'
     WHERE authority.namespace = ${rowAlias}.namespace
       AND authority.org_id = ${rowAlias}.org_id
       AND authority.project_id = ${rowAlias}.project_id
       AND authority.env_id = ${rowAlias}.env_id
       AND authority.authority_id = ${rowAlias}.authority_id
       AND authority.wallet_id = ${rowAlias}.wallet_id
       AND authority.lifecycle_state = 'active'
       AND authority.authority_digest_b64u = ?
       AND authority.revocation_epoch = ?
  )`;
}

function authorityProjectionBindings(
  projection: WalletSessionAuthorityProjectionInput,
): readonly unknown[] {
  return [String(projection.authorityDigestB64u), projection.authorityRevocationEpoch];
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}
