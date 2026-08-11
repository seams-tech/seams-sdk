import { expect, test } from '@playwright/test';
import { buildLinkedDevicePrincipalId } from '../../packages/sdk-server-ts/src/authorization/domain';
import {
  AuthorizationServiceLinkedDeviceWalletSessionRevocationV1,
  createCloudflareD1LinkedDeviceManagementCompositionV1,
  D1LinkedDeviceWalletSessionAuthorizationMetadataSourceV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceManagementComposition';
import type { AuthorizationService } from '../../packages/sdk-server-ts/src/authorization/service';
import type { LinkedDeviceWalletSessionStatus } from '../../packages/sdk-server-ts/src/authorization/domain';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseMpcWalletSigningQuotaId,
  parseTenantId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';

type LinkedDeviceStatusInput = Parameters<
  AuthorizationService['getLinkedDeviceWalletSessionStatus']
>[0];
type LinkedDeviceRevokeInput = Parameters<
  AuthorizationService['revokeLinkedDeviceWalletSession']
>[0];

class FakeLinkedDeviceAuthorizationServiceV1 {
  readonly statusInputs: LinkedDeviceStatusInput[] = [];
  readonly revokeInputs: LinkedDeviceRevokeInput[] = [];

  constructor(public status: LinkedDeviceWalletSessionStatus) {}

  async getLinkedDeviceWalletSessionStatus(
    input: LinkedDeviceStatusInput,
  ): Promise<LinkedDeviceWalletSessionStatus> {
    this.statusInputs.push(input);
    return this.status;
  }

  async revokeLinkedDeviceWalletSession(input: LinkedDeviceRevokeInput): Promise<void> {
    this.revokeInputs.push(input);
  }
}

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('reads one exact linked authorization and quota identity from D1', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const scope = {
    namespace: 'signer',
    orgId: 'org_management_composition',
    projectId: 'project_management_composition',
    envId: 'env_management_composition',
  } as const;
  const tenantId = 'tenant:management-composition';
  const authorizationId = 'authorization:management-composition';
  const walletSessionId = 'wallet-session:management-composition';
  const quotaId = 'wallet-quota:management-composition';
  const principalId = buildLinkedDevicePrincipalId(fixture.approval.deviceId);
  await temporary.database
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
      tenantId,
      authorizationId,
      principalId,
      fixture.approval.walletId,
      fixture.approval.enrollmentId,
      fixture.approval.deviceId,
      walletSessionId,
      quotaId,
      base64UrlEncode(new Uint8Array(32).fill(7)),
      JSON.stringify({
        kind: 'owner_equivalent_signing',
        administrationScope: 'signing_only',
        localUserPresence: 'required',
      }),
      0,
      1_000,
      100_000,
    )
    .run();
  await temporary.database
    .prepare(
      `INSERT INTO linked_device_wallet_session_quotas (
         namespace, org_id, project_id, env_id, tenant_id, quota_id,
         authorization_id, wallet_session_id, principal_id, remaining_uses,
         lifecycle_kind, expires_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'active', ?)`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      tenantId,
      quotaId,
      authorizationId,
      walletSessionId,
      principalId,
      100_000,
    )
    .run();

  const source = new D1LinkedDeviceWalletSessionAuthorizationMetadataSourceV1({
    database: temporary.database,
    scope,
  });
  await expect(
    source.readLinkedDeviceWalletSessionAuthorizationMetadataV1({
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
    }),
  ).resolves.toMatchObject({
    tenantId,
    authorizationId,
    walletSessionId,
    quotaId,
    principalId,
    lifecycleKind: 'active',
  });
});

test('authorization-service revocation adapter fences active sessions and replays revoked ones', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const tenantId = parseTenantId('tenant:management-revocation');
  const authorizationId = parseLinkedDeviceWalletSessionAuthorizationId(
    'authorization:management-revocation',
  );
  const walletSessionId = parseWalletSessionId('wallet-session:management-revocation');
  const quotaId = parseMpcWalletSigningQuotaId('quota:management-revocation');
  if (!tenantId.ok || !authorizationId.ok || !walletSessionId.ok || !quotaId.ok) {
    throw new Error('linked-device revocation fixture identity is invalid');
  }
  const target = {
    tenantId: tenantId.value,
    deviceId: fixture.approval.deviceId,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
  };
  const statusIdentity = {
    ...target,
    principalId: buildLinkedDevicePrincipalId(target.deviceId),
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    keyManifestDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9))),
    revocationEpoch: 0,
  };
  const authorization = new FakeLinkedDeviceAuthorizationServiceV1({
    ...statusIdentity,
    kind: 'active',
    remainingUses: 3,
    expiresAtMs: 10_000,
  });
  const adapter = new AuthorizationServiceLinkedDeviceWalletSessionRevocationV1(authorization);

  await expect(
    adapter.revokeLinkedDeviceWalletSessionV1({ target, requestedAtMs: 2_000 }),
  ).resolves.toEqual({ kind: 'applied' });
  expect(authorization.revokeInputs).toEqual([{ ...target, nowMs: 2_000 }]);

  authorization.status = {
    ...statusIdentity,
    kind: 'revoked',
    revokedAtMs: 2_000,
    expiresAtMs: 10_000,
  };
  await expect(
    adapter.revokeLinkedDeviceWalletSessionV1({ target, requestedAtMs: 2_001 }),
  ).resolves.toEqual({ kind: 'replayed' });
  expect(authorization.revokeInputs).toHaveLength(1);
});

test('management composition keeps owner auth and mutation ports explicit', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const scope = {
    namespace: 'signer',
    orgId: 'org_management_composition_route',
    projectId: 'project_management_composition_route',
    envId: 'env_management_composition_route',
  } as const;
  const service = createCloudflareD1LinkedDeviceManagementCompositionV1({
    database: temporary.database,
    scope,
    sessionService: { getSessionV1: async () => null },
    metadata: {
      readLinkedDeviceMetadataV1: async () => ({ label: 'Device', platform: 'test' }),
    },
    authorization: {
      authorizeLinkedDeviceManagementV1: async () => ({ kind: 'unauthorized' as const }),
    },
    preparation: {
      prepareLinkedDeviceRevocationV1: async () => ({ kind: 'conflict' as const }),
    },
    aggregateRevocation: {
      revokeLaneEnrollmentV1: async () => {
        throw new Error('aggregate mutation should not run');
      },
    },
    walletSessionRevocation: {
      revokeLinkedDeviceWalletSessionV1: async () => ({ kind: 'conflict' as const }),
    },
    localStateInvalidation: {
      invalidateLinkedDeviceStateV1: async () => ({ kind: 'conflict' as const }),
    },
    nowV1: () => 2_000,
    authenticateOwnerRequestV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'owner auth is required',
    }),
  });
  const result = await service.management.listLinkedDevicesV1(
    { kind: 'linked_device_list_request_v1', walletId: fixture.approval.walletId },
    2_000,
  );
  expect(result).toEqual({ kind: 'unauthorized' });
});
