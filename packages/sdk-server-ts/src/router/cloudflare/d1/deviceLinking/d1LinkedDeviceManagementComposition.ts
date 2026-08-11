import { buildLinkedDevicePrincipalId } from '../../../../authorization/domain';
import type { D1WalletStoreScope } from '../../../../core/d1WalletStore';
import type {
  LinkedDeviceId,
  LinkedDeviceEnrollmentId,
  LaneEnrollmentId,
} from '@shared/signing-lanes/ids';
import {
  parseLaneEnrollmentId,
  type LaneOperationId,
} from '@shared/signing-lanes/ids';
import {
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type LinkedDeviceWalletSessionAuthorizationId,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type TenantId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type {
  LaneProductEpochRecordV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import {
  buildRevokeLaneEnrollmentV1,
  buildRevokeSigningLaneV1,
} from '@shared/signing-lanes/rotationParsers';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { parseCorrelationId, parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  LinkedDeviceLocalStateInvalidationPortV1,
  LinkedDeviceManagementAuthorizationPortV1,
  LinkedDeviceManagementTargetV1,
  LinkedDeviceRevocationPlanV1,
  LinkedDeviceRevocationPreparationPortV1,
  LinkedDeviceWalletSessionRevocationPortV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';
import type { DeviceLinkingRouteServiceV1 } from '../../../transport/fetch/routes/deviceLinking';
import type { DeviceManagementRouteServiceV1 } from '../../../transport/fetch/routes/deviceManagement';
import type { LaneAggregateRevocationRequestV1 } from '../../../../core/signingLanes/LaneAggregateRevocationApplicationService';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import {
  createD1LinkedDeviceManagementRouteServiceV1,
  type D1LinkedDeviceManagementRouteServiceOptionsV1,
} from './d1LinkedDeviceManagementRouteService';

const AUTHORIZATION_TABLE = 'linked_device_wallet_session_authorizations';
const QUOTA_TABLE = 'linked_device_wallet_session_quotas';

type AuthorizationMetadataRowV1 = {
  readonly tenant_id?: unknown;
  readonly authorization_id?: unknown;
  readonly wallet_session_id?: unknown;
  readonly quota_id?: unknown;
  readonly principal_id?: unknown;
  readonly lifecycle_kind?: unknown;
};

export type D1LinkedDeviceWalletSessionAuthorizationMetadataV1 = {
  readonly tenantId: TenantId;
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly principalId: PrincipalId;
  readonly lifecycleKind: 'active' | 'revoked';
};

export type D1LinkedDeviceWalletSessionAuthorizationMetadataSourcePortV1 = {
  readLinkedDeviceWalletSessionAuthorizationMetadataV1(input: {
    readonly walletId: LinkedDeviceManagementTargetV1['summary']['walletId'];
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<D1LinkedDeviceWalletSessionAuthorizationMetadataV1 | null>;
};

/** Read-only source for the exact linked grant/quota identity. */
export class D1LinkedDeviceWalletSessionAuthorizationMetadataSourceV1
  implements D1LinkedDeviceWalletSessionAuthorizationMetadataSourcePortV1
{
  private readonly database: D1DatabaseLike;
  private readonly scope: D1WalletStoreScope;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
  }) {
    this.database = input.database;
    this.scope = normalizeScope(input.scope);
  }

  async readLinkedDeviceWalletSessionAuthorizationMetadataV1(input: {
    readonly walletId: LinkedDeviceManagementTargetV1['summary']['walletId'];
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<D1LinkedDeviceWalletSessionAuthorizationMetadataV1 | null> {
    const result = await this.database
      .prepare(
        `SELECT authorization.tenant_id, authorization.authorization_id,
                authorization.wallet_session_id, authorization.quota_id,
                authorization.principal_id, authorization.lifecycle_kind
           FROM ${AUTHORIZATION_TABLE} AS authorization
           JOIN ${QUOTA_TABLE} AS quota
             ON quota.namespace = authorization.namespace
            AND quota.org_id = authorization.org_id
            AND quota.project_id = authorization.project_id
            AND quota.env_id = authorization.env_id
            AND quota.tenant_id = authorization.tenant_id
            AND quota.authorization_id = authorization.authorization_id
            AND quota.wallet_session_id = authorization.wallet_session_id
            AND quota.quota_id = authorization.quota_id
          WHERE authorization.namespace = ?
            AND authorization.org_id = ?
            AND authorization.project_id = ?
            AND authorization.env_id = ?
            AND authorization.wallet_id = ?
            AND authorization.enrollment_id = ?
            AND authorization.device_id = ?
          ORDER BY authorization.issued_at_ms DESC
          LIMIT 2`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(input.walletId),
        String(input.enrollmentId),
        String(input.deviceId),
      )
      .all<AuthorizationMetadataRowV1>();
    const rows = result.results ?? [];
    if (rows.length === 0) return null;
    if (rows.length !== 1) throw new Error('linked-device authorization metadata is duplicated');
    return parseAuthorizationMetadataRow(rows[0], input.deviceId);
  }
}

/** Builds the exact manifest-ordered child commands used by an approved revoker. */
export class D1LinkedDeviceRevocationPreparationV1
  implements LinkedDeviceRevocationPreparationPortV1
{
  constructor(
    private readonly metadata: D1LinkedDeviceWalletSessionAuthorizationMetadataSourceV1,
  ) {}

  async prepareLinkedDeviceRevocationV1(input: {
    readonly target: LinkedDeviceManagementTargetV1;
    readonly requestedAtMs: number;
  }): Promise<Awaited<ReturnType<LinkedDeviceRevocationPreparationPortV1['prepareLinkedDeviceRevocationV1']>>> {
    const metadata = await this.metadata.readLinkedDeviceWalletSessionAuthorizationMetadataV1({
      walletId: input.target.summary.walletId,
      enrollmentId: input.target.summary.enrollmentId,
      deviceId: input.target.summary.deviceId,
    });
    if (!metadata) return { kind: 'not_found' };
    const parsedEnrollmentId = parseLaneEnrollmentId(String(input.target.summary.enrollmentId));
    if (!parsedEnrollmentId.ok) return { kind: 'conflict' };
    const manifest = input.target.enrollment.value.manifest;
    if (
      String(manifest.enrollmentId) !== String(parsedEnrollmentId.value) ||
      manifest.walletId !== input.target.summary.walletId
    ) {
      return { kind: 'conflict' };
    }
    const manifestDigestB64u = parseDigestB64u(
      await computeLaneEnrollmentManifestDigestV1(manifest),
    );
    const products = indexProducts(input.target.products);
    const expectedEpochs: number[] = [];
    const commands: RevokeSigningLaneV1[] = [];
    for (const child of manifest.orderedChildren) {
      const product = products.get(String(child.operationId));
      if (!product) return { kind: 'conflict' };
      const expectedRevocationEpoch = expectedSourceRevocationEpoch(product);
      expectedEpochs.push(expectedRevocationEpoch);
      commands.push(
        buildRevokeSigningLaneV1({
          walletId: input.target.summary.walletId,
          walletKeyId: child.walletKeyId,
          laneId: child.targetLaneId,
          laneShareEpoch: child.targetLaneShareEpoch,
          expectedRevocationEpoch,
          reason: 'user_revoked',
          retirementCorrelationId: parseCorrelationId(String(child.operationId)),
          retirementRequestDigestB64u: await digestRevocationBindingV1({
            kind: 'request',
            enrollmentId: parsedEnrollmentId.value,
            operationId: child.operationId,
            requestedAtMs: input.requestedAtMs,
          }),
          retirementEffectBindingDigestB64u: await digestRevocationBindingV1({
            kind: 'effect',
            enrollmentId: parsedEnrollmentId.value,
            operationId: child.operationId,
            requestedAtMs: input.requestedAtMs,
          }),
          requestedAtMs: input.requestedAtMs,
        }),
      );
    }
    const expectedEpoch = expectedEpochs[0];
    const firstCommand = commands[0];
    const firstChild = manifest.orderedChildren[0];
    if (expectedEpoch === undefined || !firstCommand || !firstChild) {
      return { kind: 'conflict' };
    }
    if (expectedEpochs.some((value) => value !== expectedEpoch)) return { kind: 'conflict' };
    const command = buildRevokeLaneEnrollmentV1({
      enrollmentId: parsedEnrollmentId.value,
      walletId: input.target.summary.walletId,
      manifestDigestB64u,
      reason: 'user_revoked',
      requestedAtMs: input.requestedAtMs,
    });
    const orderedChildren = commands.map((childCommand, index) => {
      const manifestChild = manifest.orderedChildren[index];
      if (!manifestChild) throw new Error('linked-device manifest child order is incomplete');
      return {
        curve: curveForKeyFamily(manifestChild.keyFamily),
        command: childCommand,
      };
    });
    const firstOrderedChild = orderedChildren[0];
    if (!firstOrderedChild) return { kind: 'conflict' };
    const aggregate: LaneAggregateRevocationRequestV1 = {
      command,
      orderedChildren: [firstOrderedChild, ...orderedChildren.slice(1)],
    };
    const authorizationId = parseWalletSessionAuthorizationId(String(metadata.authorizationId));
    if (!authorizationId.ok) return { kind: 'conflict' };
    return {
      kind: 'prepared',
      plan: {
        target: input.target,
        aggregate,
        walletSession: {
          tenantId: metadata.tenantId,
          deviceId: input.target.summary.deviceId,
          authorizationId: authorizationId.value,
          walletSessionId: metadata.walletSessionId,
          quotaId: metadata.quotaId,
        },
        revocationEpoch: expectedEpoch + 1,
      },
    } satisfies { kind: 'prepared'; plan: LinkedDeviceRevocationPlanV1 };
  }
}

/**
 * Safe composition boundary: all mutation ports are supplied by the caller
 * after its owner-auth and platform policy checks. This factory owns only the
 * D1 projection and the route-service assembly.
 */
export type CloudflareD1LinkedDeviceManagementCompositionOptionsV1 =
  D1LinkedDeviceManagementRouteServiceOptionsV1 & {
    readonly authorization: LinkedDeviceManagementAuthorizationPortV1;
    readonly preparation: LinkedDeviceRevocationPreparationPortV1;
    readonly localStateInvalidation: LinkedDeviceLocalStateInvalidationPortV1;
    readonly walletSessionRevocation: LinkedDeviceWalletSessionRevocationPortV1;
  };

export function createCloudflareD1LinkedDeviceManagementCompositionV1(
  options: CloudflareD1LinkedDeviceManagementCompositionOptionsV1,
): DeviceManagementRouteServiceV1 {
  return createD1LinkedDeviceManagementRouteServiceV1(options);
}

function parseAuthorizationMetadataRow(
  row: AuthorizationMetadataRowV1 | undefined,
  deviceId: LinkedDeviceId,
): D1LinkedDeviceWalletSessionAuthorizationMetadataV1 {
  if (!row) throw new Error('linked-device authorization metadata row is missing');
  const tenantId = parseTenantId(requiredString(row.tenant_id, 'tenant_id'));
  const authorizationId = parseLinkedDeviceWalletSessionAuthorizationId(
    requiredString(row.authorization_id, 'authorization_id'),
  );
  const walletSessionId = parseWalletSessionId(requiredString(row.wallet_session_id, 'wallet_session_id'));
  const quotaId = parseMpcWalletSigningQuotaId(requiredString(row.quota_id, 'quota_id'));
  const principalId = parsePrincipalId(requiredString(row.principal_id, 'principal_id'));
  if (!tenantId.ok || !authorizationId.ok || !walletSessionId.ok || !quotaId.ok || !principalId.ok) {
    throw new Error('linked-device authorization metadata identity is invalid');
  }
  if (principalId.value !== buildLinkedDevicePrincipalId(deviceId)) {
    throw new Error('linked-device authorization metadata principal differs from its device');
  }
  if (row.lifecycle_kind !== 'active' && row.lifecycle_kind !== 'revoked') {
    throw new Error('linked-device authorization metadata lifecycle is invalid');
  }
  return {
    tenantId: tenantId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    principalId: principalId.value,
    lifecycleKind: row.lifecycle_kind,
  };
}

function indexProducts(
  products: readonly LaneProductEpochRecordV1[],
): ReadonlyMap<string, LaneProductEpochRecordV1> {
  const indexed = new Map<string, LaneProductEpochRecordV1>();
  for (const product of products) {
    const key = String(product.operationId);
    if (indexed.has(key)) throw new Error('linked-device products contain duplicate operations');
    indexed.set(key, product);
  }
  return indexed;
}

function expectedSourceRevocationEpoch(product: LaneProductEpochRecordV1): number {
  switch (product.state) {
    case 'pending_visibility':
    case 'active':
      return product.revocationEpoch;
    case 'revocation_pending':
    case 'revoked':
      if (product.revocationEpoch < 1) throw new Error('linked-device revocation epoch is invalid');
      return product.revocationEpoch - 1;
    case 'retired':
      throw new Error('retired linked-device product cannot be revoked');
  }
}

function curveForKeyFamily(
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
): 'ed25519_yao' | 'ecdsa_additive' {
  switch (keyFamily) {
    case 'ed25519':
      return 'ed25519_yao';
    case 'ecdsa_secp256k1':
      return 'ecdsa_additive';
  }
}

async function digestRevocationBindingV1(input: {
  readonly kind: 'request' | 'effect';
  readonly enrollmentId: LaneEnrollmentId;
  readonly operationId: LaneOperationId;
  readonly requestedAtMs: number;
}): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        [
          'seams/r103/linked-device-revocation/v1',
          input.kind,
          String(input.enrollmentId),
          String(input.operationId),
          String(input.requestedAtMs),
        ].join('\u0000'),
      ),
    ),
  );
}

function normalizeScope(scope: D1LinkedDeviceSessionScopeV1): D1WalletStoreScope {
  return {
    namespace: requiredScope(scope.namespace, 'namespace'),
    orgId: requiredScope(scope.orgId, 'orgId'),
    projectId: requiredScope(scope.projectId, 'projectId'),
    envId: requiredScope(scope.envId, 'envId'),
  };
}

function scopeValues(scope: D1WalletStoreScope): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function requiredScope(value: string, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`linked-device management ${label} is invalid`);
  }
  return value;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`linked-device ${label} is invalid`);
  }
  return value;
}
