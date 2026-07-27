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
  buildEmailOtpVerifiedFactorFixture,
  buildPasskeyVerifiedFactorFixture,
  buildReusableAuthorizationCoreFixture,
  buildStepUpAuthorizationCoreFixture,
} from './helpers/authorizationCore.fixtures';
import {
  buildActiveCapabilityGrant,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseSessionOrigin,
} from '../../packages/sdk-server-ts/src/authorization/domain';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
} from '../../packages/shared-ts/src/authorization/operationFingerprint';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';

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
      await service.issueGrant({
        operation: fixture.claim.operation,
        evidenceSet: fixture.evidenceSet,
        grant: fixture.grant,
      });

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
      await stepUpService.issueGrant({
        operation: stepUpFixture.claim.operation,
        evidenceSet: stepUpFixture.evidenceSet,
        grant: stepUpFixture.grant,
      });
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
      await expect(rowCount(temporary.database, 'verified_grant_evidence_sets')).resolves.toBe(2);

      const grant = buildGrantForEvidence(passkey.authorization.grant, passkeyEvidence);
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
    | 'authorization_sessions'
    | 'verified_grant_evidence_sets'
    | 'capability_grants'
    | 'capability_grant_uses'
    | 'authorization_audit_events',
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}
