import { expect, test } from '@playwright/test';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import type { EcdsaMaterialActivationScope } from '../../packages/wallet-server/src/authorization/service';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import {
  D1WalletStore,
  type D1WalletStoreScope,
} from '../../packages/wallet-server/src/core/d1WalletStore';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildReusableAuthorizationCoreFixture,
  buildWalletOperationPasskeyVerifiedFactorFixture,
} from './helpers/authorizationCore.fixtures';
import type { AuthorizedOperationInput } from '../../packages/wallet-server/src/authorization/domain';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';

const signerMigrations = listD1MigrationFiles('d1-signer');

test.describe('D1 authorization core', () => {
  test('admits wallet step-up evidence without an app session and rejects substitution', async () => {
    const temporary = createTemporaryD1Database();
    const namespace = 'authorized-operation-step-up-binding';
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const fixture = await buildWalletOperationPasskeyVerifiedFactorFixture();
      const walletSignerScope = signerPersistenceScope(
        namespace,
        fixture.authorization.authorizedOperation.tenantId,
        'env-a',
      );
      const store = new CloudflareD1AuthorizationStore({
        database: temporary.database,
        namespace,
        walletSignerScope,
      });
      const service = new AuthorizationService({
        policy: capabilityPolicyPort,
        sessions: store,
        evidence: store,
        grants: store,
        authorizedOperations: store,
        audit: store,
      });
      const evidenceSet = await service.recordVerifiedWalletOperationFactorEvidenceSet({
        operation: fixture.authorization.authorizedOperation.operation,
        evidenceId: fixture.evidenceId,
        evidenceSetId: fixture.evidenceSetId,
        factor: fixture.factor,
      });
      const material = await seedEcdsaMaterial(
        temporary.database,
        walletSignerScope,
        fixture.authorization,
        'env-a',
      );

      const operation = fixture.authorization.authorizedOperation;
      const claimInput: AuthorizedOperationInput = {
        tenantId: operation.tenantId,
        authorizedOperationId: operation.authorizedOperationId,
        auditEventId: operation.auditEventId,
        operation: operation.operation,
        authorization: {
          kind: 'verified_step_up',
          evidenceSetDigest: testDigest(99),
        },
        quota: { kind: 'quota_neutral' },
        claimedAtMs: operation.claimedAtMs,
      };
      await expect(
        service.admitAuthorizedOperation({ operation: claimInput, material }),
      ).resolves.toEqual({ kind: 'verified_step_up_rejected' });
      await expect(rowCount(temporary.database, 'authorized_operations')).resolves.toBe(0);

      await expect(
        service.admitAuthorizedOperation({
          operation: {
            ...claimInput,
            authorization: {
              kind: 'verified_step_up',
              evidenceSetDigest: evidenceSet.evidenceSetDigest,
            },
          },
          material,
        }),
      ).resolves.toMatchObject({ kind: 'claimed' });
      await expect(
        rowCount(temporary.database, 'verified_wallet_operation_evidence_sets'),
      ).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });
});

function signerPersistenceScope(
  namespace: string,
  orgId: string,
  envId: string,
): D1WalletStoreScope {
  return {
    namespace,
    orgId,
    projectId: 'project-a',
    envId,
  };
}

async function seedEcdsaMaterial(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  walletSignerScope: D1WalletStoreScope,
  authorization: Awaited<ReturnType<typeof buildReusableAuthorizationCoreFixture>>,
  policyEnvId: string,
): Promise<EcdsaMaterialActivationScope> {
  const signer = createWalletEcdsaSignerRecord({
    walletId: authorization.walletSessionIdentity.walletId,
    now: authorization.session.createdAtMs,
    materialActivationCapability: String(authorization.authorizedOperation.operation.capabilityId),
  });
  const runtimePolicyScope = {
    orgId: authorization.session.tenantId,
    projectId: 'project-a',
    envId: policyEnvId,
    signingRootVersion: signer.walletKey.signingRootVersion,
  } as const;
  const walletStore = new D1WalletStore({
    database,
    ...walletSignerScope,
  });
  await walletStore.putSigner(signer);
  return {
    walletId: signer.walletId,
    keyHandle: signer.walletKey.keyHandle,
    runtimePolicyScope,
    materialActivation: signer.walletKey.publicCapability.material_activation,
  };
}

async function rowCount(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  table: 'verified_wallet_operation_evidence_sets' | 'authorized_operations',
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}

function testDigest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}
