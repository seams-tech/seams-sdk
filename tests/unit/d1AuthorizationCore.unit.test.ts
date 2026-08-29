import { expect, test } from '@playwright/test';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import type { EcdsaMaterialActivationScope } from '../../packages/wallet-server/src/authorization/service';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import {
  D1WalletStore,
  type D1WalletStoreScope,
} from '../../packages/wallet-server/src/core/d1WalletStore';
import { D1WalletAuthMethodStore } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildPasskeyWalletSessionIssuanceFixture,
  buildReusableAuthorizationCoreFixture,
  buildWalletOperationPasskeyVerifiedFactorFixture,
} from './helpers/authorizationCore.fixtures';
import type { AuthorizedOperationInput } from '../../packages/wallet-server/src/authorization/domain';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import {
  parseReusableWalletSessionMintId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';

const signerMigrations = listD1MigrationFiles('d1-signer');

test.describe('D1 authorization core', () => {
  test('issues one exact Wallet Session authorization and quota atomically', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'wallet-session-issuance');
      const fixture = await buildPasskeyWalletSessionIssuanceFixture({
        tenantId: 'tenant-wallet-session',
        principalId: 'principal-wallet-session',
        walletId: 'wallet-session-wallet',
        walletAuthMethodId: 'wallet-auth-method:wallet-session',
        credentialIdB64u: 'credential-wallet-session',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });
      await seedActiveWalletAuthMethod(temporary.database, 'wallet-session-issuance', fixture);
      const mintId = requiredMintId('registration:wallet-session');
      const issued = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId,
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.expiresAtMs,
      });
      expect(issued.session.authorizationId).not.toBe(issued.quota.quotaId);
      await expect(
        service.issueReusableWalletSession({
          tenantId: fixture.session.tenantId,
          principalId: fixture.session.principalId,
          walletId: fixture.authority.walletId,
          authority: fixture.authorityRef,
          mintId,
          remainingUses: 3,
          issuedAtMs: fixture.session.createdAtMs + 1,
          expiresAtMs: fixture.session.expiresAtMs,
        }),
      ).resolves.toEqual(issued);
      await expect(rowCount(temporary.database, 'reusable_wallet_sessions')).resolves.toBe(1);
      await expect(
        rowCount(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('replays one Wallet Session mint when only server-issued timestamps differ', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'wallet-session-timestamp-replay');
      const fixture = await buildPasskeyWalletSessionIssuanceFixture({
        tenantId: 'tenant-wallet-session-timestamp-replay',
        principalId: 'principal-wallet-session-timestamp-replay',
        walletId: 'wallet-session-timestamp-replay-wallet',
        walletAuthMethodId: 'wallet-auth-method:wallet-session-timestamp-replay',
        credentialIdB64u: 'credential-wallet-session-timestamp-replay',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });
      await seedActiveWalletAuthMethod(
        temporary.database,
        'wallet-session-timestamp-replay',
        fixture,
      );
      const mintId = requiredMintId('unlock:wallet-session-timestamp-replay');
      const issued = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId,
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.expiresAtMs,
      });
      await expect(
        service.issueReusableWalletSession({
          tenantId: fixture.session.tenantId,
          principalId: fixture.session.principalId,
          walletId: fixture.authority.walletId,
          authority: fixture.authorityRef,
          mintId,
          remainingUses: 3,
          issuedAtMs: fixture.session.createdAtMs + 2,
          expiresAtMs: fixture.session.expiresAtMs + 1_000,
        }),
      ).resolves.toEqual(issued);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('supersedes the prior Wallet Session authorization generation atomically', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'wallet-session-rollback');
      const fixture = await buildPasskeyWalletSessionIssuanceFixture({
        tenantId: 'tenant-wallet-session',
        principalId: 'principal-wallet-session',
        walletId: 'wallet-session-wallet',
        walletAuthMethodId: 'wallet-auth-method:wallet-session-second',
        credentialIdB64u: 'credential-wallet-session',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });
      await seedActiveWalletAuthMethod(temporary.database, 'wallet-session-rollback', fixture);
      const issued = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId: requiredMintId('unlock:wallet-session'),
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.expiresAtMs,
      });
      const replacement = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId: requiredMintId('unlock:replacement-wallet-session'),
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 2,
        expiresAtMs: fixture.session.expiresAtMs,
      });
      expect(replacement.session.authorizationId).not.toBe(issued.session.authorizationId);
      await expect(
        rowCountWhere(temporary.database, 'reusable_wallet_sessions', "lifecycle_kind = 'active'"),
      ).resolves.toBe(1);
      await expect(
        rowCountWhere(
          temporary.database,
          'authorization_wallet_session_quotas',
          "lifecycle_kind = 'active'",
        ),
      ).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('reads exact Wallet Session authorization lifecycle from session and quota rows', async () => {
    const temporary = createTemporaryD1Database();
    const namespace = 'wallet-session-status';
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, namespace);
      const fixture = await buildPasskeyWalletSessionIssuanceFixture({
        tenantId: 'tenant-wallet-session-status',
        principalId: 'principal-wallet-session-status',
        walletId: 'wallet-session-status-wallet',
        walletAuthMethodId: 'wallet-auth-method:wallet-session-status',
        credentialIdB64u: 'credential-wallet-session-status',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });
      await seedActiveWalletAuthMethod(temporary.database, namespace, fixture);
      const issued = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId: requiredMintId('unlock:wallet-session-status'),
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.expiresAtMs,
      });
      const statusInput = {
        tenantId: issued.session.tenantId,
        principalId: issued.session.principalId,
        walletSessionId: issued.quota.walletSessionId,
        quotaId: issued.quota.quotaId,
        nowMs: fixture.session.createdAtMs + 2,
      } as const;
      await expect(service.readReusableWalletSessionStatus(statusInput)).resolves.toMatchObject({
        kind: 'active',
        remainingUses: 3,
      });
      await temporary.database
        .prepare(
          `UPDATE authorization_wallet_session_quotas
              SET lifecycle_kind = 'exhausted',
                  remaining_uses = 0
            WHERE namespace = ?
              AND tenant_id = ?
              AND quota_id = ?`,
        )
        .bind(namespace, issued.session.tenantId, issued.quota.quotaId)
        .run();
      await expect(service.readReusableWalletSessionStatus(statusInput)).resolves.toMatchObject({
        kind: 'exhausted',
        remainingUses: 0,
      });
      const replacement = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId: requiredMintId('unlock:wallet-session-status-replacement'),
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 2,
        expiresAtMs: fixture.session.expiresAtMs,
      });
      await expect(service.readReusableWalletSessionStatus(statusInput)).resolves.toMatchObject({
        kind: 'superseded',
      });
      await expect(
        service.readReusableWalletSessionStatus({
          tenantId: replacement.session.tenantId,
          principalId: replacement.session.principalId,
          walletSessionId: replacement.quota.walletSessionId,
          quotaId: replacement.quota.quotaId,
          nowMs: replacement.session.expiresAtMs,
        }),
      ).resolves.toMatchObject({ kind: 'expired' });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('rejects a conflicting Wallet Session authorization replay', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'wallet-session-conflicting-replay');
      const fixture = await buildPasskeyWalletSessionIssuanceFixture({
        tenantId: 'tenant-wallet-session-conflict',
        principalId: 'principal-wallet-session-conflict',
        walletId: 'wallet-session-conflict-wallet',
        walletAuthMethodId: 'wallet-auth-method:wallet-session-conflict',
        credentialIdB64u: 'credential-wallet-session-conflict',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });
      await seedActiveWalletAuthMethod(
        temporary.database,
        'wallet-session-conflicting-replay',
        fixture,
      );
      const mintId = requiredMintId('unlock:wallet-session-conflict');
      await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId,
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.expiresAtMs,
      });
      await expect(
        service.issueReusableWalletSession({
          tenantId: fixture.session.tenantId,
          principalId: fixture.session.principalId,
          walletId: fixture.authority.walletId,
          authority: fixture.authorityRef,
          mintId,
          remainingUses: 2,
          issuedAtMs: fixture.session.createdAtMs + 1,
          expiresAtMs: fixture.session.expiresAtMs,
        }),
      ).rejects.toThrow('issuance replay does not match');
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

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

function createService(
  database: Parameters<typeof rowCount>[0],
  namespace: string,
): AuthorizationService {
  const store = new CloudflareD1AuthorizationStore({
    database,
    namespace,
    walletSignerScope: {
      namespace,
      orgId: 'test-org',
      projectId: 'test-project',
      envId: 'test-env',
    },
  });
  return new AuthorizationService({
    policy: capabilityPolicyPort,
    sessions: store,
    evidence: store,
    grants: store,
    authorizedOperations: store,
    audit: store,
  });
}

async function seedActiveWalletAuthMethod(
  database: Parameters<typeof rowCount>[0],
  namespace: string,
  fixture: Awaited<ReturnType<typeof buildPasskeyWalletSessionIssuanceFixture>>,
): Promise<void> {
  const store = new D1WalletAuthMethodStore({
    database,
    namespace,
    orgId: 'test-org',
    projectId: 'test-project',
    envId: 'test-env',
    ensureSchema: false,
  });
  await store.putV2(fixture.authMethod);
}

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
    walletId: authorization.reusableWalletSession.walletId,
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

function requiredMintId(value: string) {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function rowCount(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  table:
    | 'authorization_wallet_session_quotas'
    | 'reusable_wallet_sessions'
    | 'opaque_wallet_session_tokens'
    | 'verified_wallet_operation_evidence_sets'
    | 'authorized_operations',
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}

async function rowCountWhere(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  table: 'reusable_wallet_sessions' | 'authorization_wallet_session_quotas',
  predicate: string,
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE ${predicate}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}

function testDigest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}
