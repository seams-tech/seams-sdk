import { expect, test } from '@playwright/test';
import { AuthorizationService } from '../../packages/sdk-server-ts/src/authorization/service';
import { CloudflareD1AuthorizationStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1AuthorizationStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildAdditionalAuthorizationClaim,
  buildReusableAuthorizationCoreFixture,
  buildStepUpAuthorizationCoreFixture,
} from './helpers/authorizationCore.fixtures';

const signerMigrations = listD1MigrationFiles('d1-signer');

test.describe('D1 authorization core', () => {
  test('persists session, evidence, grant, claim, completion, replay, and audit', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = new AuthorizationService(
        new CloudflareD1AuthorizationStore({
          database: temporary.database,
          namespace: 'authorization-test',
        }),
      );
      const fixture = await buildReusableAuthorizationCoreFixture();
      await service.recordActiveSession(fixture.session);
      await service.recordVerifiedEvidenceSet(fixture.evidenceSet);
      await service.recordWalletSessionQuota(fixture.quota);
      await service.issueGrant(fixture.grant);

      await expect(service.claimOperation(fixture.claim)).resolves.toMatchObject({
        kind: 'claimed',
      });
      await expect(service.claimOperation(fixture.claim)).resolves.toMatchObject({
        kind: 'operation_in_progress',
      });
      await expect(
        service.completeOperation({
          claim: fixture.claim,
          result: 'succeeded',
          resultRef: fixture.resultRef,
          completedAtMs: fixture.claim.claimedAtMs + 10,
        }),
      ).resolves.toMatchObject({ kind: 'completed' });
      await expect(service.claimOperation(fixture.claim)).resolves.toMatchObject({
        kind: 'replayed',
        use: { result: 'succeeded' },
      });

      await expect(readRemainingUses(temporary.database, 'capability_grants')).resolves.toBe(1);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(1);
      await expect(
        service.readAuditEvent({
          tenantId: fixture.claim.tenantId,
          eventId: fixture.claim.auditEventId,
        }),
      ).resolves.toMatchObject({
        result: 'succeeded',
        useId: fixture.claim.useId,
        createdAtMs: fixture.claim.claimedAtMs,
      });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('keeps exports quota-neutral and makes step-up single-operation', async () => {
    const exportDatabase = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(exportDatabase.database, signerMigrations);
      const exportService = createService(exportDatabase.database, 'export-test');
      const exportFixture = await buildReusableAuthorizationCoreFixture({
        operationKind: 'evm.export_key',
      });
      await seedReusable(exportService, exportFixture);
      await expect(exportService.claimOperation(exportFixture.claim)).resolves.toMatchObject({
        kind: 'claimed',
      });
      await expect(
        readRemainingUses(exportDatabase.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(2);
    } finally {
      cleanupTemporaryD1Database(exportDatabase.tempDir);
    }

    const stepUpDatabase = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(stepUpDatabase.database, signerMigrations);
      const stepUpService = createService(stepUpDatabase.database, 'step-up-test');
      const stepUpFixture = await buildStepUpAuthorizationCoreFixture();
      await stepUpService.recordActiveSession(stepUpFixture.session);
      await stepUpService.recordVerifiedEvidenceSet(stepUpFixture.evidenceSet);
      await stepUpService.issueGrant(stepUpFixture.grant);
      await expect(stepUpService.claimOperation(stepUpFixture.claim)).resolves.toMatchObject({
        kind: 'claimed',
      });
      await expect(readRemainingUses(stepUpDatabase.database, 'capability_grants')).resolves.toBe(
        0,
      );
      await expect(
        rowCount(stepUpDatabase.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(stepUpDatabase.tempDir);
    }
  });

  test('rolls back the grant claim when reusable quota is expired', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'rollback-test');
      const baseline = await buildReusableAuthorizationCoreFixture();
      const fixture = await buildReusableAuthorizationCoreFixture({
        quotaExpiresAtMs: baseline.claim.claimedAtMs - 1,
      });
      await seedReusable(service, fixture);

      await expect(service.claimOperation(fixture.claim)).resolves.toEqual({
        kind: 'wallet_session_expired',
      });
      await expect(readRemainingUses(temporary.database, 'capability_grants')).resolves.toBe(2);
      await expect(rowCount(temporary.database, 'capability_grant_uses')).resolves.toBe(0);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('serializes concurrent fingerprints through one grant and quota use', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'concurrent-test');
      const fixture = await buildReusableAuthorizationCoreFixture({
        grantRemainingUses: 1,
        quotaRemainingUses: 1,
      });
      const competingClaim = await buildAdditionalAuthorizationClaim(fixture, 'competing');
      await seedReusable(service, fixture);

      const outcomes = await Promise.all([
        service.claimOperation(fixture.claim),
        service.claimOperation(competingClaim),
      ]);
      expect(outcomes.map((outcome) => outcome.kind).sort()).toEqual([
        'claimed',
        'grant_exhausted',
      ]);
      await expect(rowCount(temporary.database, 'capability_grant_uses')).resolves.toBe(1);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(1);
      await expect(readRemainingUses(temporary.database, 'capability_grants')).resolves.toBe(0);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });
});

function createService(
  database: Parameters<typeof readRemainingUses>[0],
  namespace: string,
): AuthorizationService {
  return new AuthorizationService(new CloudflareD1AuthorizationStore({ database, namespace }));
}

async function seedReusable(
  service: AuthorizationService,
  fixture: Awaited<ReturnType<typeof buildReusableAuthorizationCoreFixture>>,
): Promise<void> {
  await service.recordActiveSession(fixture.session);
  await service.recordVerifiedEvidenceSet(fixture.evidenceSet);
  await service.recordWalletSessionQuota(fixture.quota);
  await service.issueGrant(fixture.grant);
}

async function readRemainingUses(
  database: import('../../packages/sdk-server-ts/src/storage/tenantRoute').D1DatabaseLike,
  table: 'capability_grants' | 'authorization_wallet_session_quotas',
): Promise<number> {
  const row = await database
    .prepare(`SELECT remaining_uses FROM ${table} LIMIT 1`)
    .first<{ readonly remaining_uses?: unknown }>();
  return Number(row?.remaining_uses);
}

async function rowCount(
  database: import('../../packages/sdk-server-ts/src/storage/tenantRoute').D1DatabaseLike,
  table:
    | 'authorization_wallet_session_quotas'
    | 'capability_grant_uses'
    | 'authorization_audit_events',
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}
