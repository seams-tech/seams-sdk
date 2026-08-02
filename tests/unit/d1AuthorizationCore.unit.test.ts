import { expect, test } from '@playwright/test';
import {
  AuthorizationService,
  type ReusableWalletSessionClaimInput,
} from '../../packages/sdk-server-ts/src/authorization/service';
import { CloudflareD1AuthorizationStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1AuthorizationStore';
import { D1WalletStore } from '../../packages/sdk-server-ts/src/core/d1WalletStore';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildAdditionalAuthorizationClaim,
  buildEmailOtpVerifiedFactorFixture,
  buildPasskeyVerifiedFactorFixture,
  buildPasskeyAuthorizationSessionFixture,
  buildReusableAuthorizationCoreFixture,
  buildStepUpAuthorizationCoreFixture,
} from './helpers/authorizationCore.fixtures';
import {
  buildActiveCapabilityGrant,
  buildCapabilityOperationCompletionClaimRef,
  buildCapabilityOperationClaim,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseSessionOrigin,
} from '../../packages/sdk-server-ts/src/authorization/domain';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
} from '../../packages/shared-ts/src/authorization/operationFingerprint';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseVerifiedGrantEvidenceSetFromPersistence } from '../../packages/sdk-server-ts/src/authorization/factorEvidence';
import { capabilityPolicyPort } from '../../packages/sdk-server-ts/src/authorization/capabilityPolicy';
import {
  parseReusableWalletSessionMintId,
  parseAuthorizedOperationId,
  parseCapabilityBindingId,
  parseCapabilityGrantUseId,
  parseAuthorizationAuditEventId,
  parseMpcWalletSigningQuotaId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseRouterAbMpcMaterialActivationRef } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import type { EcdsaMaterialActivationScope } from '../../packages/sdk-server-ts/src/authorization/service';

const signerMigrations = listD1MigrationFiles('d1-signer');

test.describe('D1 authorization core', () => {
  test('issues one exact reusable Wallet Session and quota atomically', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'wallet-session-issuance');
      const fixture = await buildPasskeyAuthorizationSessionFixture({
        tenantId: 'tenant-wallet-session',
        principalId: 'principal-wallet-session',
        sessionId: 'session-wallet-session',
        deviceId: 'device-wallet-session',
        walletId: 'wallet-session-wallet',
        credentialIdB64u: 'credential-wallet-session',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });
      await service.recordActiveSession(fixture.session);
      const mintId = requiredMintId('registration:wallet-session');
      const issued = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId,
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
      });

      expect(issued.session.walletSessionId).not.toBe(issued.quota.quotaId);
      const replayed = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId,
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
      });
      expect(replayed).toEqual(issued);
      expect(issued.session).toMatchObject({
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        walletSessionId: issued.quota.walletSessionId,
        quotaId: issued.quota.quotaId,
      });
      await expect(rowCount(temporary.database, 'reusable_wallet_sessions')).resolves.toBe(1);
      await expect(
        rowCount(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('supersedes the prior wallet-authority generation atomically', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'wallet-session-rollback');
      const fixture = await buildPasskeyAuthorizationSessionFixture({
        tenantId: 'tenant-wallet-session',
        principalId: 'principal-wallet-session',
        sessionId: 'missing-session-wallet-session',
        deviceId: 'device-wallet-session',
        walletId: 'wallet-session-wallet',
        credentialIdB64u: 'credential-wallet-session',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });

      const issued = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId: requiredMintId('unlock:wallet-session'),
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
      });
      const replacement = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId: requiredMintId('unlock:replacement-wallet-session'),
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 2,
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
      });
      expect(replacement.session.walletSessionId).not.toBe(issued.session.walletSessionId);
      await expect(rowCount(temporary.database, 'reusable_wallet_sessions')).resolves.toBe(2);
      await expect(
        rowCount(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(2);
      await expect(
        rowCountWhere(
          temporary.database,
          'reusable_wallet_sessions',
          "lifecycle_kind = 'active'",
        ),
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

  test('reads exact reusable Wallet Session lifecycle from the session and quota rows', async () => {
    const temporary = createTemporaryD1Database();
    const namespace = 'wallet-session-status';
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, namespace);
      const fixture = await buildPasskeyAuthorizationSessionFixture({
        tenantId: 'tenant-wallet-session-status',
        principalId: 'principal-wallet-session-status',
        sessionId: 'session-wallet-session-status',
        deviceId: 'device-wallet-session-status',
        walletId: 'wallet-session-status-wallet',
        credentialIdB64u: 'credential-wallet-session-status',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });
      const issued = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId: requiredMintId('unlock:wallet-session-status'),
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
      });
      const statusInput = {
        tenantId: issued.session.tenantId,
        principalId: issued.session.principalId,
        walletSessionId: issued.session.walletSessionId,
        quotaId: issued.quota.quotaId,
        nowMs: fixture.session.createdAtMs + 2,
      } as const;

      await expect(service.readReusableWalletSessionStatus(statusInput)).resolves.toEqual({
        kind: 'active',
        tenantId: issued.session.tenantId,
        principalId: issued.session.principalId,
        walletSessionId: issued.session.walletSessionId,
        quotaId: issued.quota.quotaId,
        remainingUses: 3,
        expiresAtMs: issued.session.expiresAtMs,
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
        walletSessionId: issued.session.walletSessionId,
        quotaId: issued.quota.quotaId,
      });

      const replacement = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId: requiredMintId('unlock:wallet-session-status-replacement'),
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 2,
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
      });
      await expect(service.readReusableWalletSessionStatus(statusInput)).resolves.toMatchObject({
        kind: 'superseded',
        walletSessionId: issued.session.walletSessionId,
        quotaId: issued.quota.quotaId,
      });
      await expect(
        service.readReusableWalletSessionStatus({
          tenantId: replacement.session.tenantId,
          principalId: replacement.session.principalId,
          walletSessionId: replacement.session.walletSessionId,
          quotaId: replacement.quota.quotaId,
          nowMs: replacement.session.expiresAtMs,
        }),
      ).resolves.toMatchObject({
        kind: 'expired',
        walletSessionId: replacement.session.walletSessionId,
        quotaId: replacement.quota.quotaId,
        expiresAtMs: replacement.session.expiresAtMs,
      });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('rejects a conflicting mint replay without retiring the active generation', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'wallet-session-conflicting-replay');
      const fixture = await buildPasskeyAuthorizationSessionFixture({
        tenantId: 'tenant-wallet-session-conflict',
        principalId: 'principal-wallet-session-conflict',
        sessionId: 'session-wallet-session-conflict',
        deviceId: 'device-wallet-session-conflict',
        walletId: 'wallet-session-conflict-wallet',
        credentialIdB64u: 'credential-wallet-session-conflict',
        rpId: 'example.test',
        origin: 'https://app.example.test',
        expiresAtMs: 1_900_000_100_000,
      });
      const mintId = requiredMintId('unlock:wallet-session-conflict');
      await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId,
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
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
          expiresAtMs: fixture.session.lifecycle.expiresAtMs,
        }),
      ).rejects.toThrow('issuance replay does not match');
      await expect(
        rowCountWhere(
          temporary.database,
          'reusable_wallet_sessions',
          "lifecycle_kind = 'active'",
        ),
      ).resolves.toBe(1);
      await expect(
        rowCountWhere(
          temporary.database,
          'authorization_wallet_session_quotas',
          "lifecycle_kind = 'active' AND remaining_uses = 3",
        ),
      ).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('persists, completes, and replays a reusable Wallet Session claim', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'authorization-test');
      const fixture = await buildReusableAuthorizationCoreFixture();
      expect(fixture.evidenceSet.assurance).toBe('session');
      expect(
        parseVerifiedGrantEvidenceSetFromPersistence(
          JSON.parse(JSON.stringify(fixture.evidenceSet)),
        ),
      ).toMatchObject({
        kind: fixture.evidenceSet.kind,
        tenantId: fixture.evidenceSet.tenantId,
        principalId: fixture.evidenceSet.principalId,
        sessionId: fixture.evidenceSet.sessionId,
        evidenceSetId: fixture.evidenceSet.evidenceSetId,
        evidenceSetDigest: fixture.evidenceSet.evidenceSetDigest,
      });
      await seedReusable(service, fixture);

      await expect(service.claimOperation(fixture.claim)).resolves.toMatchObject({
        kind: 'claimed',
      });
      await expect(service.claimOperation(fixture.claim)).resolves.toMatchObject({
        kind: 'operation_in_progress',
      });
      await expect(
        service.completeOperation({
          claim: buildCapabilityOperationCompletionClaimRef(fixture.claim),
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
        authorization: {
          kind: 'reusable_wallet_session',
          walletSessionId: fixture.reusableWalletSession.walletSessionId,
        },
        result: 'succeeded',
        useId: fixture.claim.useId,
        operationId: fixture.claim.operation.operationId,
        createdAtMs: fixture.claim.claimedAtMs,
      });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('returns an exact replay before reading current grant or quota state', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'authorization-replay-first');
      const fixture = await buildReusableAuthorizationCoreFixture();
      await seedReusable(service, fixture);
      await expect(service.claimOperation(fixture.claim)).resolves.toMatchObject({
        kind: 'claimed',
      });
      await expect(
        service.completeOperation({
          claim: fixture.claim,
          result: 'succeeded',
          resultRef: fixture.resultRef,
          completedAtMs: fixture.claim.claimedAtMs + 10,
        }),
      ).resolves.toMatchObject({ kind: 'completed' });

      await temporary.database
        .prepare(
          `UPDATE capability_grants
              SET principal_id = 'superseded-principal'
            WHERE namespace = ?
              AND tenant_id = ?
              AND grant_id = ?`,
        )
        .bind('authorization-replay-first', fixture.claim.tenantId, fixture.claim.grantId)
        .run();

      await expect(
        service.claimReusableWalletSessionOperation(
          reusableWalletSessionClaimInput(fixture.claim),
        ),
      ).resolves.toMatchObject({
        claim: null,
        result: {
          kind: 'replayed',
          use: {
            useId: fixture.claim.useId,
            result: 'succeeded',
            resultRef: fixture.resultRef,
          },
        },
      });
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(1);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(1);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('claims a reusable Wallet Session operation without a capability grant record', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'wallet-session-direct-operation');
      const fixture = await buildReusableAuthorizationCoreFixture();
      await service.seedStore.putActiveReusableWalletSession({
        session: fixture.reusableWalletSession,
        quota: fixture.quota,
      });

      const outcome = await service.claimReusableWalletSessionOperation(
        reusableWalletSessionClaimInput(fixture.claim),
      );
      expect(outcome).toMatchObject({
        claim: {
          authorization: {
            kind: 'reusable_wallet_session',
            walletSessionId: fixture.reusableWalletSession.walletSessionId,
            quotaId: fixture.reusableWalletSession.quotaId,
          },
        },
        result: { kind: 'claimed' },
      });
      if (!outcome.claim) throw new Error('expected a new reusable Wallet Session claim');
      await expect(
        service.completeOperation({
          claim: buildCapabilityOperationCompletionClaimRef(outcome.claim),
          result: 'succeeded',
          resultRef: fixture.resultRef,
          completedAtMs: fixture.claim.claimedAtMs + 10,
        }),
      ).resolves.toMatchObject({ kind: 'completed' });
      await expect(rowCount(temporary.database, 'capability_grants')).resolves.toBe(0);
      await expect(rowCount(temporary.database, 'verified_grant_evidence_sets')).resolves.toBe(0);
      await expect(rowCount(temporary.database, 'capability_grant_uses')).resolves.toBe(0);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(0);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(1);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(1);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(fixture.quota.remainingUses - 1);
      await expect(
        service.readAuditEvent({
          tenantId: fixture.claim.tenantId,
          eventId: fixture.claim.auditEventId,
        }),
      ).resolves.toMatchObject({
        authorization: {
          kind: 'reusable_wallet_session',
          walletSessionId: fixture.reusableWalletSession.walletSessionId,
        },
        result: 'succeeded',
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
      await stepUpService.recordVerifiedSessionEvidenceSet(stepUpFixture.sessionEvidenceInput);
      await stepUpService.issueGrant({
        operation: stepUpFixture.claim.operation,
        evidenceSet: stepUpFixture.evidenceSet,
        grant: stepUpFixture.grant,
      });
      const stepUpClaimInput = {
        tenantId: stepUpFixture.claim.tenantId,
        grantId: stepUpFixture.claim.grantId,
        useId: stepUpFixture.claim.useId,
        auditEventId: stepUpFixture.claim.auditEventId,
        authorizationSessionId: stepUpFixture.session.sessionId,
        principalId: stepUpFixture.claim.operation.principalId,
        capabilityId: stepUpFixture.claim.operation.capabilityId,
        operationId: stepUpFixture.claim.operation.operationId,
        operation: stepUpFixture.claim.operation.operation,
        laneDigest: stepUpFixture.claim.operation.digests.laneDigest,
        intentDigest: stepUpFixture.claim.operation.digests.intentDigest,
        displayDigest: stepUpFixture.claim.operation.digests.displayDigest,
        claimedAtMs: stepUpFixture.claim.claimedAtMs,
      };
      await expect(
        stepUpService.claimOperationStepUpFromGrant({
          ...stepUpClaimInput,
          intentDigest: testDigest(99),
        }),
      ).resolves.toEqual({ kind: 'grant_mismatch' });
      await expect(
        stepUpService.claimOperationStepUpFromGrant(stepUpClaimInput),
      ).resolves.toMatchObject({ kind: 'claimed' });
      await expect(
        stepUpService.claimOperationStepUpFromGrant(stepUpClaimInput),
      ).resolves.toMatchObject({ kind: 'operation_in_progress' });
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

  test('rejects an expired reusable authorization without consuming its quota', async () => {
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
      await expect(readRemainingUses(temporary.database, 'capability_grants')).resolves.toBe(1);
      await expect(rowCount(temporary.database, 'capability_grant_uses')).resolves.toBe(0);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('serializes concurrent fingerprints through one Wallet Session quota use', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'concurrent-test');
      const fixture = await buildReusableAuthorizationCoreFixture({
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
        'wallet_session_quota_exhausted',
      ]);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(1);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(1);
      await expect(readRemainingUses(temporary.database, 'capability_grants')).resolves.toBe(1);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('redeems a hashed hosted-wallet exchange code once and creates its target session atomically', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'hosted-wallet-exchange-test');
      const fixture = await buildReusableAuthorizationCoreFixture();
      await service.recordActiveSession(fixture.session);
      const issuedAtMs = fixture.session.createdAtMs + 1_000;
      const walletOrigin = parseSessionOrigin('https://wallet.example.test');
      if (fixture.session.audience.kind !== 'first_party_web') {
        throw new Error('fixture must use a first-party audience');
      }
      const appOrigin = fixture.session.audience.origin;
      const delivery = await service.mintHostedWalletSeamsSessionExchange({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        sourceSessionId: fixture.session.sessionId,
        appOrigin,
        walletOrigin,
        issuedAtMs,
        expiresAtMs: issuedAtMs + 60_000,
      });

      const persisted = await temporary.database
        .prepare(
          `SELECT code_hash, nonce_digest
             FROM hosted_wallet_session_exchange_codes
            LIMIT 1`,
        )
        .first<{ readonly code_hash?: unknown; readonly nonce_digest?: unknown }>();
      expect(persisted?.code_hash).not.toBe(delivery.exchangeCode);
      expect(persisted?.nonce_digest).not.toBe(delivery.nonce);

      await expect(
        service.redeemHostedWalletSeamsSessionExchange({
          exchangeCode: delivery.exchangeCode,
          nonce: parseHostedWalletSeamsSessionExchangeNonce('incorrect-nonce'),
          walletOrigin,
          redeemedAtMs: issuedAtMs + 1,
        }),
      ).resolves.toEqual({ kind: 'nonce_mismatch' });
      await expect(
        service.redeemHostedWalletSeamsSessionExchange({
          exchangeCode: delivery.exchangeCode,
          nonce: delivery.nonce,
          walletOrigin,
          redeemedAtMs: issuedAtMs + 2,
        }),
      ).resolves.toMatchObject({
        kind: 'redeemed',
        session: {
          principalId: fixture.session.principalId,
          authSource: fixture.session.authSource,
          audience: {
            kind: 'hosted_wallet_iframe',
            appOrigin,
            walletOrigin,
          },
        },
      });
      await expect(
        service.redeemHostedWalletSeamsSessionExchange({
          exchangeCode: delivery.exchangeCode,
          nonce: delivery.nonce,
          walletOrigin,
          redeemedAtMs: issuedAtMs + 3,
        }),
      ).resolves.toEqual({ kind: 'already_consumed' });
      await expect(rowCount(temporary.database, 'authorization_sessions')).resolves.toBe(2);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('normalizes Passkey and Email OTP verification into one evidence-set shape', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'factor-evidence-conformance');
      const passkey = await buildPasskeyVerifiedFactorFixture();
      const emailOtp = await buildEmailOtpVerifiedFactorFixture();
      await service.recordActiveSession(passkey.authorization.session);

      const passkeyEvidence = await service.recordVerifiedFactorEvidenceSet({
        session: passkey.authorization.session,
        operation: passkey.authorization.claim.operation,
        evidenceId: passkey.evidenceId,
        evidenceSetId: passkey.evidenceSetId,
        factor: passkey.factor,
      });
      const emailOtpEvidence = await service.recordVerifiedFactorEvidenceSet({
        session: emailOtp.authorization.session,
        operation: emailOtp.authorization.claim.operation,
        evidenceId: emailOtp.evidenceId,
        evidenceSetId: emailOtp.evidenceSetId,
        factor: emailOtp.factor,
      });

      expect(Object.keys(passkeyEvidence).sort()).toEqual(Object.keys(emailOtpEvidence).sort());
      expect(passkeyEvidence).toMatchObject({
        tenantId: emailOtpEvidence.tenantId,
        principalId: emailOtpEvidence.principalId,
        sessionId: emailOtpEvidence.sessionId,
        deviceId: emailOtpEvidence.deviceId,
        operation: emailOtpEvidence.operation,
        laneDigest: emailOtpEvidence.laneDigest,
        intentDigest: emailOtpEvidence.intentDigest,
        displayDigest: emailOtpEvidence.displayDigest,
      });
      expect(passkeyEvidence.evidence[0].evidenceKind).toBe('passkey_assertion');
      expect(emailOtpEvidence.evidence[0].evidenceKind).toBe('email_otp');
      expect(passkeyEvidence.assurance).toBe('step_up');
      expect(emailOtpEvidence.assurance).toBe('step_up');
      await expect(rowCount(temporary.database, 'verified_grant_evidence_sets')).resolves.toBe(2);

      const grant = buildGrantForEvidence(passkey.authorization.grant, passkeyEvidence);
      await service.seedStore.putActiveReusableWalletSession({
        session: passkey.authorization.reusableWalletSession,
        quota: passkey.authorization.quota,
      });
      await service.issueGrant({
        operation: passkey.authorization.claim.operation,
        evidenceSet: passkeyEvidence,
        grant,
      });
      await expect(rowCount(temporary.database, 'capability_grants')).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('rejects mismatched verified operations and grant digests before issuance', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'factor-evidence-mismatch');
      const fixture = await buildPasskeyVerifiedFactorFixture();
      await service.recordActiveSession(fixture.authorization.session);
      const mismatchedOperation = operationWithIntentDigest(
        fixture.authorization.claim.operation,
        testDigest(31),
      );

      await expect(
        service.recordVerifiedFactorEvidenceSet({
          session: fixture.authorization.session,
          operation: mismatchedOperation,
          evidenceId: fixture.evidenceId,
          evidenceSetId: fixture.evidenceSetId,
          factor: fixture.factor,
        }),
      ).rejects.toThrow('verified factor does not match the capability operation');
      await expect(rowCount(temporary.database, 'verified_grant_evidence_sets')).resolves.toBe(0);

      const evidenceSet = await service.recordVerifiedFactorEvidenceSet({
        session: fixture.authorization.session,
        operation: fixture.authorization.claim.operation,
        evidenceId: fixture.evidenceId,
        evidenceSetId: fixture.evidenceSetId,
        factor: fixture.factor,
      });
      const mismatchedGrant = buildGrantForEvidence(
        fixture.authorization.grant,
        evidenceSet,
        testDigest(32),
      );
      await expect(
        service.issueGrant({
          operation: fixture.authorization.claim.operation,
          evidenceSet,
          grant: mismatchedGrant,
        }),
      ).rejects.toThrow('capability grant digests do not match verified evidence');
      await expect(rowCount(temporary.database, 'capability_grants')).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('commits ECDSA evidence and grants exactly once, then claims idempotently', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const namespace = 'ecdsa-atomic-success';
      const service = createService(temporary.database, namespace);
      const { authorization, material } = await buildEcdsaAtomicFixture(
        temporary.database,
        service,
        namespace,
      );

      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material,
        }),
      ).resolves.toEqual({ kind: 'committed' });
      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material,
        }),
      ).resolves.toEqual({ kind: 'committed' });
      await expect(rowCount(temporary.database, 'verified_grant_evidence_sets')).resolves.toBe(1);
      await expect(rowCount(temporary.database, 'capability_grants')).resolves.toBe(1);

      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material,
        }),
      ).resolves.toMatchObject({
        claim: authorization.claim,
        result: { kind: 'claimed' },
      });
      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material,
        }),
      ).resolves.toMatchObject({
        claim: null,
        result: { kind: 'operation_in_progress' },
      });
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(1);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(1);
      await expect(
        readStoredMaterialActivationId(
          temporary.database,
          'reusable_wallet_session_operation_uses',
        ),
      ).resolves.toBe(material.materialActivation.activation_id);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(1);
      await expect(
        rowCount(temporary.database, 'ecdsa_authorization_atomic_guards'),
      ).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('rejects hostile ECDSA activation and tenant scopes before any writes', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const namespace = 'ecdsa-atomic-boundary';
      const service = createService(temporary.database, namespace);
      const { authorization, material } = await buildEcdsaAtomicFixture(
        temporary.database,
        service,
        namespace,
      );
      const hostileActivation = parseRouterAbMpcMaterialActivationRef({
        ...material.materialActivation,
        activation_id: 'hostile-activation',
      });
      const hostileMaterial = { ...material, materialActivation: hostileActivation };
      const hostileCapability = parseRouterAbMpcMaterialActivationRef({
        ...material.materialActivation,
        capability: 'hostile-capability',
      });
      const hostileCapabilityMaterial = { ...material, materialActivation: hostileCapability };
      const hostileKeyHandleMaterial = { ...material, keyHandle: 'hostile-key-handle' };
      const hostileOwnerMaterial = {
        ...material,
        walletId: requiredWalletId('hostile-wallet-owner'),
      };
      const hostileTenantMaterial = {
        ...material,
        runtimePolicyScope: {
          ...material.runtimePolicyScope,
          orgId: 'tenant-hostile',
        },
      };

      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material: hostileMaterial,
        }),
      ).resolves.toEqual({ kind: 'material_mismatch' });
      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material: hostileMaterial,
        }),
      ).resolves.toMatchObject({ claim: null, result: { kind: 'material_mismatch' } });
      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material: hostileOwnerMaterial,
        }),
      ).resolves.toEqual({ kind: 'material_mismatch' });
      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material: hostileOwnerMaterial,
        }),
      ).resolves.toMatchObject({ claim: null, result: { kind: 'material_mismatch' } });

      for (const field of [
        'material_owner',
        'key_binding',
        'lifecycle_binding',
        'signing_worker',
      ] as const) {
        const materialActivation = parseRouterAbMpcMaterialActivationRef({
          ...material.materialActivation,
          [field]: `hostile-${field}`,
        });
        await expect(
          service.seedStore.putEcdsaEvidenceAndGrant({
            evidenceSet: authorization.evidenceSet,
            grant: authorization.grant,
            material: { ...material, materialActivation },
          }),
          `${field} must be rejected by the D1 signer fence`,
        ).resolves.toEqual({ kind: 'material_mismatch' });
      }
      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material: hostileCapabilityMaterial,
        }),
      ).resolves.toEqual({ kind: 'material_mismatch' });
      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material: hostileCapabilityMaterial,
        }),
      ).resolves.toMatchObject({ claim: null, result: { kind: 'material_mismatch' } });
      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material: hostileKeyHandleMaterial,
        }),
      ).resolves.toEqual({ kind: 'material_mismatch' });
      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material: hostileKeyHandleMaterial,
        }),
      ).resolves.toMatchObject({ claim: null, result: { kind: 'material_mismatch' } });
      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material: hostileTenantMaterial,
        }),
      ).resolves.toEqual({ kind: 'material_mismatch' });
      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material: hostileTenantMaterial,
        }),
      ).resolves.toMatchObject({ claim: null, result: { kind: 'material_mismatch' } });

      await expect(rowCount(temporary.database, 'verified_grant_evidence_sets')).resolves.toBe(0);
      await expect(rowCount(temporary.database, 'capability_grants')).resolves.toBe(0);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(2);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(0);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(0);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(0);
      await expect(
        rowCount(temporary.database, 'ecdsa_authorization_atomic_guards'),
      ).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('does not replay an ECDSA operation after signer activation rotates', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const namespace = 'ecdsa-atomic-activation-rotation';
      const service = createService(temporary.database, namespace);
      const { authorization, material } = await buildEcdsaAtomicFixture(
        temporary.database,
        service,
        namespace,
      );
      await service.putEcdsaEvidenceAndGrant({
        evidenceSet: authorization.evidenceSet,
        grant: authorization.grant,
        material,
      });
      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material,
        }),
      ).resolves.toMatchObject({ claim: authorization.claim, result: { kind: 'claimed' } });

      const rotatedSigner = createWalletEcdsaSignerRecord({
        walletId: authorization.reusableWalletSession.walletId,
        now: authorization.session.createdAtMs + 1,
        materialActivationId: 'rotated-activation-ref',
        materialActivationCapability: String(authorization.claim.operation.capabilityId),
      });
      const walletStore = new D1WalletStore({
        database: temporary.database,
        namespace,
        orgId: material.runtimePolicyScope.orgId,
        projectId: material.runtimePolicyScope.projectId,
        envId: material.runtimePolicyScope.envId,
      });
      await walletStore.putSigner(rotatedSigner);
      const rotatedMaterial = {
        ...material,
        keyHandle: rotatedSigner.walletKey.keyHandle,
        materialActivation: rotatedSigner.walletKey.publicCapability.material_activation,
      };

      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: authorization.claim,
          material: rotatedMaterial,
        }),
      ).resolves.toMatchObject({ claim: null, result: { kind: 'material_mismatch' } });
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(1);
      await expect(
        readStoredMaterialActivationId(
          temporary.database,
          'reusable_wallet_session_operation_uses',
        ),
      ).resolves.toBe(material.materialActivation.activation_id);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(1);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(1);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(0);
      await expect(
        rowCount(temporary.database, 'ecdsa_authorization_atomic_guards'),
      ).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('claims ECDSA operation-step-up grants with activation-bound replay', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const namespace = 'ecdsa-atomic-step-up';
      const service = createService(temporary.database, namespace);
      const authorization = await buildStepUpAuthorizationCoreFixture();
      const walletId = requiredWalletId('wallet-authorization');
      const signer = createWalletEcdsaSignerRecord({
        walletId,
        now: authorization.session.createdAtMs,
        materialActivationCapability: String(authorization.claim.operation.capabilityId),
      });
      const runtimePolicyScope = {
        orgId: authorization.session.tenantId,
        projectId: 'project-a',
        envId: 'env-a',
        signingRootVersion: signer.walletKey.signingRootVersion,
      } as const;
      const walletStore = new D1WalletStore({
        database: temporary.database,
        namespace,
        orgId: runtimePolicyScope.orgId,
        projectId: runtimePolicyScope.projectId,
        envId: runtimePolicyScope.envId,
      });
      await walletStore.putSigner(signer);
      await service.recordActiveSession(authorization.session);
      await service.recordVerifiedSessionEvidenceSet(authorization.sessionEvidenceInput);
      await service.seedStore.putActiveGrant(authorization.grant);
      const material: EcdsaMaterialActivationScope = {
        walletId,
        keyHandle: signer.walletKey.keyHandle,
        runtimePolicyScope,
        materialActivation: signer.walletKey.publicCapability.material_activation,
      };

      await expect(
        service.claimEcdsaOperation({ claim: authorization.claim, material }),
      ).resolves.toMatchObject({ kind: 'claimed' });
      await expect(
        service.claimEcdsaOperation({ claim: authorization.claim, material }),
      ).resolves.toMatchObject({ kind: 'operation_in_progress' });
      await expect(rowCount(temporary.database, 'capability_grant_uses')).resolves.toBe(1);
      await expect(
        readStoredMaterialActivationId(temporary.database, 'capability_grant_uses'),
      ).resolves.toBe(material.materialActivation.activation_id);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(1);

      const rotatedSigner = createWalletEcdsaSignerRecord({
        walletId,
        now: authorization.session.createdAtMs + 1,
        materialActivationId: 'step-up-rotated-activation-ref',
        materialActivationCapability: String(authorization.claim.operation.capabilityId),
      });
      await walletStore.putSigner(rotatedSigner);
      await expect(
        service.claimEcdsaOperation({
          claim: authorization.claim,
          material: {
            ...material,
            keyHandle: rotatedSigner.walletKey.keyHandle,
            materialActivation: rotatedSigner.walletKey.publicCapability.material_activation,
          },
        }),
      ).resolves.toEqual({ kind: 'material_mismatch' });
      await expect(rowCount(temporary.database, 'capability_grant_uses')).resolves.toBe(1);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('rolls back ECDSA evidence and grant writes on conflicting persisted rows', async () => {
    const evidenceConflict = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(evidenceConflict.database, signerMigrations);
      const namespace = 'ecdsa-atomic-evidence-conflict';
      const service = createService(evidenceConflict.database, namespace);
      const { authorization, material } = await buildEcdsaAtomicFixture(
        evidenceConflict.database,
        service,
        namespace,
      );
      await service.recordVerifiedSessionEvidenceSet({
        ...authorization.sessionEvidenceInput,
        operation: operationWithIntentDigest(authorization.claim.operation, testDigest(91)),
      });

      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material,
        }),
      ).resolves.toEqual({ kind: 'material_mismatch' });
      await expect(
        rowCount(evidenceConflict.database, 'verified_grant_evidence_sets'),
      ).resolves.toBe(1);
      await expect(rowCount(evidenceConflict.database, 'capability_grants')).resolves.toBe(0);
      await expect(
        readRemainingUses(evidenceConflict.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(2);
      await expect(
        rowCount(evidenceConflict.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(0);
      await expect(
        rowCount(evidenceConflict.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(evidenceConflict.tempDir);
    }

    const grantConflict = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(grantConflict.database, signerMigrations);
      const namespace = 'ecdsa-atomic-grant-conflict';
      const service = createService(grantConflict.database, namespace);
      const { authorization, material } = await buildEcdsaAtomicFixture(
        grantConflict.database,
        service,
        namespace,
      );
      await service.recordVerifiedSessionEvidenceSet(authorization.sessionEvidenceInput);
      if (authorization.grant.authority.kind !== 'reusable_wallet_session') {
        throw new Error('ECDSA atomic fixture must use reusable Wallet Session authority');
      }
      const conflictingGrant = buildActiveCapabilityGrant({
        tenantId: authorization.grant.tenantId,
        principalId: authorization.grant.principalId,
        grantId: authorization.grant.grantId,
        bindingId: requiredBindingId('binding-conflict'),
        evidenceSetId: authorization.grant.evidenceSetId,
        evidenceSetDigest: authorization.grant.evidenceSetDigest,
        capabilityId: authorization.grant.capabilityId,
        operationId: authorization.grant.operationId,
        operation: authorization.grant.operation,
        laneDigest: authorization.grant.laneDigest,
        intentDigest: authorization.grant.intentDigest,
        displayDigest: authorization.grant.displayDigest,
        authority: authorization.grant.authority,
        remainingUses: authorization.grant.remainingUses,
        createdAtMs: authorization.grant.createdAtMs,
        expiresAtMs: authorization.grant.expiresAtMs,
      });
      await service.seedStore.putActiveGrant(conflictingGrant);

      await expect(
        service.putEcdsaEvidenceAndGrant({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          material,
        }),
      ).resolves.toEqual({ kind: 'material_mismatch' });
      await expect(rowCount(grantConflict.database, 'verified_grant_evidence_sets')).resolves.toBe(
        1,
      );
      await expect(rowCount(grantConflict.database, 'capability_grants')).resolves.toBe(1);
      await expect(
        readRemainingUses(grantConflict.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(2);
      await expect(
        rowCount(grantConflict.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(0);
      await expect(
        rowCount(grantConflict.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(grantConflict.tempDir);
    }
  });

  test('rolls back evidence and grant inserts when the combined ECDSA claim predicate fails', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const namespace = 'ecdsa-atomic-claim-predicate';
      const service = createService(temporary.database, namespace);
      const { authorization, material } = await buildEcdsaAtomicFixture(
        temporary.database,
        service,
        namespace,
      );
      if (authorization.claim.authorization.kind !== 'reusable_wallet_session') {
        throw new Error('ECDSA atomic fixture must use reusable Wallet Session authorization');
      }
      const conflictingClaim = await buildCapabilityOperationClaim({
        tenantId: authorization.claim.tenantId,
        useId: requiredGrantUseId('grant-use-conflicting-claim'),
        auditEventId: requiredAuditEventId('audit-event-conflicting-claim'),
        grantId: authorization.claim.grantId,
        operation: authorization.claim.operation,
        evidenceSetDigest: testDigest(92),
        claimedAtMs: authorization.claim.claimedAtMs,
        authorization: {
          kind: 'reusable_wallet_session',
          walletSessionId: authorization.claim.authorization.walletSessionId,
          quotaId: requiredQuotaId('quota-conflicting-claim'),
        },
      });

      await expect(
        service.claimEcdsaReusableWalletSessionOperation({
          evidenceSet: authorization.evidenceSet,
          grant: authorization.grant,
          claim: conflictingClaim,
          material,
        }),
      ).resolves.toMatchObject({ claim: null, result: { kind: 'wallet_session_mismatch' } });
      await expect(rowCount(temporary.database, 'verified_grant_evidence_sets')).resolves.toBe(0);
      await expect(rowCount(temporary.database, 'capability_grants')).resolves.toBe(0);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_uses'),
      ).resolves.toBe(0);
      await expect(
        rowCount(temporary.database, 'reusable_wallet_session_operation_audit_events'),
      ).resolves.toBe(0);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(2);
      await expect(rowCount(temporary.database, 'authorization_audit_events')).resolves.toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('claims direct Wallet Session operations and replays without a synthetic grant', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'direct-wallet-session-operation');
      const fixture = await buildReusableAuthorizationCoreFixture();
      await service.recordActiveSession(fixture.session);
      const issued = await service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.reusableWalletSession.walletId,
        authority: fixture.reusableWalletSession.authority,
        mintId: fixture.reusableWalletSession.mintId,
        remainingUses: 2,
        issuedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
      });
      const operation = {
        authorizedOperationId: requiredAuthorizedOperationId('authorized-operation-1'),
        tenantId: fixture.claim.operation.tenantId,
        operation: fixture.claim.operation,
        auditEventId: requiredAuditEventId('authorized-audit-1'),
        claimedAtMs: fixture.claim.claimedAtMs,
        authorization: {
          kind: 'authorization_grant' as const,
          authorizationGrantRef: issued.authorization.authorizationGrantRef,
        },
        authorizationGrantRevocationEpoch: issued.authorization.revocationEpoch,
        walletSessionId: issued.session.walletSessionId,
        quotaId: issued.quota.quotaId,
        quota: {
          kind: 'consume_reusable_wallet_session' as const,
          quotaId: issued.quota.quotaId,
        },
      };

      const claimed = await service.claimAuthorizedOperation({ operation });
      expect(claimed.kind).toBe('claimed');
      if (claimed.kind !== 'claimed') throw new Error('direct operation was not claimed');
      expect(claimed.operation.authorization.kind).toBe('authorization_grant');
      await expect(
        rowCount(temporary.database, 'capability_grants'),
      ).resolves.toBe(0);
      await expect(
        readRemainingUses(temporary.database, 'authorization_wallet_session_quotas'),
      ).resolves.toBe(1);

      const inProgress = await service.claimAuthorizedOperation({ operation });
      expect(inProgress).toMatchObject({ kind: 'operation_in_progress' });
      const completed = await service.completeAuthorizedOperation({
        operation: claimed.operation,
        result: 'succeeded',
        resultRef: fixture.resultRef,
        completedAtMs: fixture.claim.claimedAtMs + 1,
      });
      expect(completed.lifecycle).toBe('completed');
      await expect(service.claimAuthorizedOperation({ operation })).resolves.toMatchObject({
        kind: 'replayed',
      });
      await expect(
        rowCount(temporary.database, 'authorized_operations'),
      ).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('claims a step-up operation directly from verified evidence without a grant row', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'direct-step-up-operation');
      const fixture = await buildReusableAuthorizationCoreFixture();
      await service.recordActiveSession(fixture.session);
      await service.recordVerifiedSessionEvidenceSet(fixture.sessionEvidenceInput);
      const operation = {
        authorizedOperationId: requiredAuthorizedOperationId('authorized-step-up-1'),
        tenantId: fixture.claim.operation.tenantId,
        operation: fixture.claim.operation,
        auditEventId: requiredAuditEventId('authorized-step-up-audit-1'),
        claimedAtMs: fixture.claim.claimedAtMs,
        authorization: {
          kind: 'verified_step_up' as const,
          evidenceSetDigest: fixture.evidenceSet.evidenceSetDigest,
        },
        quota: { kind: 'quota_neutral' as const },
      };

      const claimed = await service.claimAuthorizedOperation({ operation });
      expect(claimed).toMatchObject({ kind: 'claimed' });
      await expect(rowCount(temporary.database, 'capability_grants')).resolves.toBe(0);
      await expect(
        service.claimAuthorizedOperation({ operation }),
      ).resolves.toMatchObject({ kind: 'operation_in_progress' });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });
});

function createService(
  database: Parameters<typeof readRemainingUses>[0],
  namespace: string,
): AuthorizationService & {
  readonly seedStore: CloudflareD1AuthorizationStore;
} {
  const store = new CloudflareD1AuthorizationStore({ database, namespace });
  const service = new AuthorizationService({
    policy: capabilityPolicyPort,
    sessions: store,
    evidence: store,
    grants: store,
    claims: store,
    audit: store,
  });
  return Object.assign(service, { seedStore: store });
}

type EcdsaAtomicFixture = {
  readonly authorization: Awaited<ReturnType<typeof buildReusableAuthorizationCoreFixture>>;
  readonly material: EcdsaMaterialActivationScope;
};

async function buildEcdsaAtomicFixture(
  database: Parameters<typeof readRemainingUses>[0],
  service: AuthorizationService & { readonly seedStore: CloudflareD1AuthorizationStore },
  namespace: string,
): Promise<EcdsaAtomicFixture> {
  const authorization = await buildReusableAuthorizationCoreFixture();
  const signer = createWalletEcdsaSignerRecord({
    walletId: authorization.reusableWalletSession.walletId,
    now: authorization.session.createdAtMs,
    materialActivationCapability: String(authorization.claim.operation.capabilityId),
  });
  const runtimePolicyScope = {
    orgId: authorization.session.tenantId,
    projectId: 'project-a',
    envId: 'env-a',
    signingRootVersion: signer.walletKey.signingRootVersion,
  } as const;
  const walletStore = new D1WalletStore({
    database,
    namespace,
    orgId: runtimePolicyScope.orgId,
    projectId: runtimePolicyScope.projectId,
    envId: runtimePolicyScope.envId,
  });
  await walletStore.putSigner(signer);
  await service.recordActiveSession(authorization.session);
  await service.seedStore.putActiveReusableWalletSession({
    session: authorization.reusableWalletSession,
    quota: authorization.quota,
  });
  return {
    authorization,
    material: {
      walletId: signer.walletId,
      keyHandle: signer.walletKey.keyHandle,
      runtimePolicyScope,
      materialActivation: signer.walletKey.publicCapability.material_activation,
    },
  };
}

function reusableWalletSessionClaimInput(
  claim: Awaited<ReturnType<typeof buildReusableAuthorizationCoreFixture>>['claim'],
): ReusableWalletSessionClaimInput {
  if (claim.authorization.kind !== 'reusable_wallet_session') {
    throw new Error('reusable Wallet Session claim fixture is required');
  }
  return {
    tenantId: claim.tenantId,
    grantId: claim.grantId,
    useId: claim.useId,
    auditEventId: claim.auditEventId,
    walletSessionId: claim.authorization.walletSessionId,
    quotaId: claim.authorization.quotaId,
    principalId: claim.operation.principalId,
    capabilityId: claim.operation.capabilityId,
    operationId: claim.operation.operationId,
    operation: claim.operation.operation,
    laneDigest: claim.operation.digests.laneDigest,
    intentDigest: claim.operation.digests.intentDigest,
    displayDigest: claim.operation.digests.displayDigest,
    claimedAtMs: claim.claimedAtMs + 100,
  };
}

async function seedReusable(
  service: AuthorizationService & {
    readonly seedStore: CloudflareD1AuthorizationStore;
  },
  fixture: Awaited<ReturnType<typeof buildReusableAuthorizationCoreFixture>>,
): Promise<void> {
  await service.recordActiveSession(fixture.session);
  await service.recordVerifiedSessionEvidenceSet(fixture.sessionEvidenceInput);
  await service.seedStore.putActiveReusableWalletSession({
    session: fixture.reusableWalletSession,
    quota: fixture.quota,
  });
  await service.issueGrant({
    operation: fixture.claim.operation,
    evidenceSet: fixture.evidenceSet,
    grant: fixture.grant,
  });
}

function buildGrantForEvidence(
  baseline: Awaited<ReturnType<typeof buildReusableAuthorizationCoreFixture>>['grant'],
  evidenceSet: Awaited<ReturnType<AuthorizationService['recordVerifiedFactorEvidenceSet']>>,
  intentDigest = evidenceSet.intentDigest,
) {
  switch (baseline.authority.kind) {
    case 'reusable_wallet_session':
      return buildActiveCapabilityGrant({
        tenantId: baseline.tenantId,
        principalId: baseline.principalId,
        grantId: baseline.grantId,
        bindingId: baseline.bindingId,
        evidenceSetId: evidenceSet.evidenceSetId,
        evidenceSetDigest: evidenceSet.evidenceSetDigest,
        capabilityId: baseline.capabilityId,
        operationId: baseline.operationId,
        operation: evidenceSet.operation,
        laneDigest: evidenceSet.laneDigest,
        intentDigest,
        displayDigest: evidenceSet.displayDigest,
        authority: baseline.authority,
        remainingUses: baseline.remainingUses,
        createdAtMs: baseline.createdAtMs,
        expiresAtMs: Math.min(baseline.expiresAtMs, evidenceSet.expiresAtMs),
      });
    case 'operation_step_up':
      return buildActiveCapabilityGrant({
        tenantId: baseline.tenantId,
        principalId: baseline.principalId,
        grantId: baseline.grantId,
        bindingId: baseline.bindingId,
        evidenceSetId: evidenceSet.evidenceSetId,
        evidenceSetDigest: evidenceSet.evidenceSetDigest,
        capabilityId: baseline.capabilityId,
        operationId: baseline.operationId,
        operation: evidenceSet.operation,
        laneDigest: evidenceSet.laneDigest,
        intentDigest,
        displayDigest: evidenceSet.displayDigest,
        authority: baseline.authority,
        remainingUses: 1,
        createdAtMs: baseline.createdAtMs,
        expiresAtMs: Math.min(baseline.expiresAtMs, evidenceSet.expiresAtMs),
      });
  }
}

function operationWithIntentDigest(
  baseline: CapabilityOperationEnvelope,
  intentDigest: ReturnType<typeof testDigest>,
): CapabilityOperationEnvelope {
  return buildCapabilityOperationEnvelope({
    tenantId: baseline.tenantId,
    principalId: baseline.principalId,
    capabilityId: baseline.capabilityId,
    operationId: baseline.operationId,
    operation: baseline.operation,
    digests: {
      laneDigest: baseline.digests.laneDigest,
      intentDigest,
      displayDigest: baseline.digests.displayDigest,
    },
  });
}

function testDigest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}

function requiredMintId(value: string) {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredBindingId(value: string) {
  const parsed = parseCapabilityBindingId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredGrantUseId(value: string) {
  const parsed = parseCapabilityGrantUseId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredAuditEventId(value: string) {
  const parsed = parseAuthorizationAuditEventId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredQuotaId(value: string) {
  const parsed = parseMpcWalletSigningQuotaId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredAuthorizedOperationId(value: string) {
  const parsed = parseAuthorizedOperationId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredWalletId(value: string) {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
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

async function readStoredMaterialActivationId(
  database: import('../../packages/sdk-server-ts/src/storage/tenantRoute').D1DatabaseLike,
  table: 'capability_grant_uses' | 'reusable_wallet_session_operation_uses',
): Promise<string | null> {
  const row = await database
    .prepare(`SELECT material_activation_id FROM ${table} LIMIT 1`)
    .first<{ readonly material_activation_id?: unknown }>();
  return typeof row?.material_activation_id === 'string' ? row.material_activation_id : null;
}

async function rowCount(
  database: import('../../packages/sdk-server-ts/src/storage/tenantRoute').D1DatabaseLike,
  table:
    | 'authorization_wallet_session_quotas'
    | 'reusable_wallet_sessions'
    | 'authorization_sessions'
    | 'verified_grant_evidence_sets'
    | 'capability_grants'
    | 'capability_grant_uses'
    | 'ecdsa_authorization_atomic_guards'
    | 'authorization_audit_events'
    | 'reusable_wallet_session_operation_uses'
    | 'reusable_wallet_session_operation_audit_events'
    | 'authorized_operations'
    | 'authorized_operation_audit_events',
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}

async function rowCountWhere(
  database: import('../../packages/sdk-server-ts/src/storage/tenantRoute').D1DatabaseLike,
  table: 'reusable_wallet_sessions' | 'authorization_wallet_session_quotas',
  predicate: string,
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE ${predicate}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}
