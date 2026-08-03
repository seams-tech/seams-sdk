import { expect, test } from '@playwright/test';
import { AuthorizationService } from '../../packages/sdk-server-ts/src/authorization/service';
import type { EcdsaMaterialActivationScope } from '../../packages/sdk-server-ts/src/authorization/service';
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
  buildEmailOtpVerifiedFactorFixture,
  buildPasskeyAuthorizationSessionFixture,
  buildPasskeyVerifiedFactorFixture,
  buildReusableAuthorizationCoreFixture,
} from './helpers/authorizationCore.fixtures';
import {
  parseHostedWalletSeamsSessionExchangeNonce,
  parseSessionOrigin,
} from '../../packages/sdk-server-ts/src/authorization/domain';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
} from '../../packages/shared-ts/src/authorization/operationFingerprint';
import type {
  AuthorizedOperation,
  AuthorizedOperationInput,
} from '../../packages/sdk-server-ts/src/authorization/domain';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseVerifiedAuthorizationEvidenceSetFromPersistence } from '../../packages/sdk-server-ts/src/authorization/factorEvidence';
import { capabilityPolicyPort } from '../../packages/sdk-server-ts/src/authorization/capabilityPolicy';
import {
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseMpcWalletSigningQuotaId,
  parseReusableWalletSessionMintId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';

const signerMigrations = listD1MigrationFiles('d1-signer');

test.describe('D1 authorization core', () => {
  test('issues one exact Wallet Session authorization and quota atomically', async () => {
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
          expiresAtMs: fixture.session.lifecycle.expiresAtMs,
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

  test('supersedes the prior Wallet Session authorization generation atomically', async () => {
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
        expiresAtMs: fixture.session.lifecycle.expiresAtMs,
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
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('admits one stable operation fingerprint across transport retries and consumes quota once', async () => {
    const temporary = createTemporaryD1Database();
    const namespace = 'authorized-operation-admission';
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const store = new CloudflareD1AuthorizationStore({
        database: temporary.database,
        namespace,
      });
      const service = new AuthorizationService({
        policy: capabilityPolicyPort,
        sessions: store,
        evidence: store,
        grants: store,
        authorizedOperations: store,
        audit: store,
      });
      const fixture = await buildReusableAuthorizationCoreFixture({
        quotaRemainingUses: 2,
      });
      await store.putWalletSessionAuthorization({
        session: fixture.reusableWalletSession,
        quota: fixture.quota,
      });

      const claimInput = authorizedOperationInput(fixture.authorizedOperation);
      const material = await seedEcdsaMaterial(temporary.database, namespace, fixture);
      const claimed = await service.admitAuthorizedOperation({ operation: claimInput, material });
      expect(claimed.kind).toBe('claimed');
      if (claimed.kind !== 'claimed') throw new Error('expected a newly admitted operation');
      await expect(
        readQuotaRemainingUses(
          temporary.database,
          fixture.authorizedOperation.tenantId,
          fixture.quota.quotaId,
        ),
      ).resolves.toBe(1);
      await expect(rowCount(temporary.database, 'authorized_operations')).resolves.toBe(1);

      const retryInput: AuthorizedOperationInput = {
        ...claimInput,
        authorizedOperationId: requiredAuthorizedOperationId(
          'authorized-operation-transport-retry',
        ),
        auditEventId: requiredAuthorizationAuditEventId('audit-event-transport-retry'),
        claimedAtMs: claimInput.claimedAtMs + 1,
      };

      await expect(
        service.admitAuthorizedOperation({ operation: retryInput, material }),
      ).resolves.toMatchObject({
        kind: 'operation_in_progress',
        operation: {
          authorizedOperationId: claimInput.authorizedOperationId,
          auditEventId: claimInput.auditEventId,
          lifecycle: 'claimed',
        },
      });

      await expect(
        service.completeAuthorizedOperation({
          operation: claimed.operation,
          result: 'succeeded',
          response: fixture.response,
          completedAtMs: claimInput.claimedAtMs + 1,
        }),
      ).resolves.toMatchObject({
        lifecycle: 'completed',
        response: fixture.response,
      });

      await expect(
        service.admitAuthorizedOperation({ operation: retryInput, material }),
      ).resolves.toMatchObject({
        kind: 'replayed',
        operation: {
          authorizedOperationId: fixture.authorizedOperation.authorizedOperationId,
          lifecycle: 'completed',
          response: fixture.response,
        },
      });
      await expect(
        readQuotaRemainingUses(
          temporary.database,
          fixture.authorizedOperation.tenantId,
          fixture.quota.quotaId,
        ),
      ).resolves.toBe(1);
      await expect(rowCount(temporary.database, 'authorized_operations')).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('rejects replay source, quota, and material substitutions and persists audit linkage', async () => {
    const temporary = createTemporaryD1Database();
    const namespace = 'authorized-operation-replay-binding';
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const store = new CloudflareD1AuthorizationStore({
        database: temporary.database,
        namespace,
      });
      const service = new AuthorizationService({
        policy: capabilityPolicyPort,
        sessions: store,
        evidence: store,
        grants: store,
        authorizedOperations: store,
        audit: store,
      });
      const fixture = await buildReusableAuthorizationCoreFixture({
        quotaRemainingUses: 2,
      });
      await store.putWalletSessionAuthorization({
        session: fixture.reusableWalletSession,
        quota: fixture.quota,
      });
      const material = await seedEcdsaMaterial(temporary.database, namespace, fixture);
      const claimInput = authorizedOperationInput(fixture.authorizedOperation);
      await expect(
        service.admitAuthorizedOperation({ operation: claimInput, material }),
      ).resolves.toMatchObject({
        kind: 'claimed',
      });
      const audit = await temporary.database
        .prepare(
          `SELECT authorization_id, result_kind
             FROM authorized_operation_audit_events
            WHERE tenant_id = ? AND authorized_operation_id = ?`,
        )
        .bind(
          fixture.authorizedOperation.tenantId,
          fixture.authorizedOperation.authorizedOperationId,
        )
        .first<{ readonly authorization_id?: unknown; readonly result_kind?: unknown }>();
      expect(audit).toMatchObject({
        authorization_id: fixture.reusableWalletSession.authorizationId,
        result_kind: 'pending',
      });

      const stepUpReplay: AuthorizedOperationInput = {
        ...claimInput,
        authorization: {
          kind: 'verified_step_up',
          evidenceSetDigest: testDigest(99),
        },
        quota: { kind: 'quota_neutral' },
      };
      await expect(
        service.admitAuthorizedOperation({ operation: stepUpReplay, material }),
      ).resolves.toEqual({ kind: 'verified_step_up_rejected' });

      const wrongQuota = parseMpcWalletSigningQuotaId('quota-replay-mismatch');
      if (!wrongQuota.ok) throw new Error(wrongQuota.error.message);
      const quotaReplay: AuthorizedOperationInput = {
        ...claimInput,
        quota: {
          kind: 'consume_reusable_wallet_session',
          quotaId: wrongQuota.value,
        },
      };
      await expect(
        service.admitAuthorizedOperation({ operation: quotaReplay, material }),
      ).resolves.toEqual({ kind: 'authorization_grant_rejected' });

      const materialReplay: EcdsaMaterialActivationScope = {
        ...material,
        materialActivation: {
          ...material.materialActivation,
          activation_id: `${material.materialActivation.activation_id}-substituted`,
        },
      };
      await expect(
        service.admitAuthorizedOperation({ operation: claimInput, material: materialReplay }),
      ).resolves.toEqual({ kind: 'material_mismatch' });

      await temporary.database
        .prepare(
          `UPDATE reusable_wallet_sessions
              SET lifecycle_kind = 'superseded'
            WHERE namespace = ? AND tenant_id = ? AND authorization_id = ?`,
        )
        .bind(
          namespace,
          fixture.reusableWalletSession.tenantId,
          fixture.reusableWalletSession.authorizationId,
        )
        .run();
      await expect(
        service.admitAuthorizedOperation({ operation: claimInput, material }),
      ).resolves.toEqual({ kind: 'authorization_grant_rejected' });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('rejects step-up admission when evidence is substituted for the operation', async () => {
    const temporary = createTemporaryD1Database();
    const namespace = 'authorized-operation-step-up-binding';
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const store = new CloudflareD1AuthorizationStore({
        database: temporary.database,
        namespace,
      });
      const service = new AuthorizationService({
        policy: capabilityPolicyPort,
        sessions: store,
        evidence: store,
        grants: store,
        authorizedOperations: store,
        audit: store,
      });
      const fixture = await buildPasskeyVerifiedFactorFixture();
      await service.recordActiveSession(fixture.authorization.session);
      await service.recordVerifiedFactorEvidenceSet({
        session: fixture.authorization.session,
        operation: fixture.authorization.authorizedOperation.operation,
        evidenceId: fixture.evidenceId,
        evidenceSetId: fixture.evidenceSetId,
        factor: fixture.factor,
      });
      const material = await seedEcdsaMaterial(
        temporary.database,
        namespace,
        fixture.authorization,
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
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('redeems a hashed hosted-wallet exchange code once', async () => {
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
      const delivery = await service.mintHostedWalletSeamsSessionExchange({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        sourceSessionId: fixture.session.sessionId,
        appOrigin: fixture.session.audience.origin,
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
        operation: passkey.authorization.authorizedOperation.operation,
        evidenceId: passkey.evidenceId,
        evidenceSetId: passkey.evidenceSetId,
        factor: passkey.factor,
      });
      const emailOtpEvidence = await service.recordVerifiedFactorEvidenceSet({
        session: emailOtp.authorization.session,
        operation: emailOtp.authorization.authorizedOperation.operation,
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
      expect(
        parseVerifiedAuthorizationEvidenceSetFromPersistence(
          JSON.parse(JSON.stringify(passkeyEvidence)),
        ),
      ).toMatchObject({
        evidenceSetId: passkeyEvidence.evidenceSetId,
        evidenceSetDigest: passkeyEvidence.evidenceSetDigest,
      });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('rejects a verified factor bound to a different operation digest', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const service = createService(temporary.database, 'factor-evidence-mismatch');
      const fixture = await buildPasskeyVerifiedFactorFixture();
      await service.recordActiveSession(fixture.authorization.session);
      const mismatchedOperation = operationWithIntentDigest(
        fixture.authorization.authorizedOperation.operation,
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
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });
});

function createService(
  database: Parameters<typeof rowCount>[0],
  namespace: string,
): AuthorizationService {
  const store = new CloudflareD1AuthorizationStore({ database, namespace });
  return new AuthorizationService({
    policy: capabilityPolicyPort,
    sessions: store,
    evidence: store,
    grants: store,
    authorizedOperations: store,
    audit: store,
  });
}

async function seedEcdsaMaterial(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  namespace: string,
  authorization: Awaited<ReturnType<typeof buildReusableAuthorizationCoreFixture>>,
): Promise<EcdsaMaterialActivationScope> {
  const signer = createWalletEcdsaSignerRecord({
    walletId: authorization.reusableWalletSession.walletId,
    now: authorization.session.createdAtMs,
    materialActivationCapability: String(authorization.authorizedOperation.operation.capabilityId),
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

function requiredAuthorizedOperationId(value: string) {
  const parsed = parseAuthorizedOperationId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredAuthorizationAuditEventId(value: string) {
  const parsed = parseAuthorizationAuditEventId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function rowCount(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  table:
    | 'authorization_wallet_session_quotas'
    | 'reusable_wallet_sessions'
    | 'authorization_sessions'
    | 'verified_grant_evidence_sets'
    | 'authorized_operations',
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}

async function readQuotaRemainingUses(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  tenantId: string,
  quotaId: string,
): Promise<number> {
  const row = await database
    .prepare(
      `SELECT remaining_uses
         FROM authorization_wallet_session_quotas
        WHERE tenant_id = ? AND quota_id = ?
        LIMIT 1`,
    )
    .bind(tenantId, quotaId)
    .first<{ readonly remaining_uses?: unknown }>();
  return Number(row?.remaining_uses);
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

function authorizedOperationInput(operation: AuthorizedOperation): AuthorizedOperationInput {
  if (operation.lifecycle !== 'claimed') {
    throw new Error('authorized operation fixture must start claimed');
  }
  return {
    tenantId: operation.tenantId,
    authorizedOperationId: operation.authorizedOperationId,
    auditEventId: operation.auditEventId,
    operation: operation.operation,
    authorization: operation.authorization,
    quota: operation.quota,
    claimedAtMs: operation.claimedAtMs,
  };
}
